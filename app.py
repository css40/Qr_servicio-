from flask import Flask, request, jsonify, redirect, render_template, session, url_for, abort
import sqlite3, os, time, hashlib, json, string, random
from functools import wraps
from urllib.parse import urlparse

# ---------- Configuración ----------
# Base de datos (usa variable si existe, si no local)
DB = os.environ.get("DB_PATH", "qrpro.db")

# URL pública (en Render la definimos como variable de entorno)
APP_URL = os.environ.get("APP_URL")

# Clave secreta obligatoria en producción
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ---------- DB helpers ----------
def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )
    """)

    # links:
    # kind: 'url', 'wifi', 'whatsapp', 'text', 'vcard'
    # target_url: solo aplica para kind=url (o whatsapp si lo tratamos como url)
    # payload_json: para wifi/text/vcard guardamos datos
    # viewer_enabled: si kind != url, usamos /v/<code>
    c.execute("""
    CREATE TABLE IF NOT EXISTS links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      code TEXT UNIQUE NOT NULL,
      kind TEXT NOT NULL,
      title TEXT,
      target_url TEXT,
      payload_json TEXT,
      viewer_enabled INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      expires_at INTEGER,
      max_scans INTEGER
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      link_id INTEGER NOT NULL,
      ts INTEGER NOT NULL,
      ua TEXT,
      ref TEXT,
      ip_hash TEXT,
      FOREIGN KEY(link_id) REFERENCES links(id)
    )
    """)

    conn.commit()
    conn.close()


@app.before_request
def ensure_db():
    if not os.path.exists(DB):
        init_db()


# ---------- auth helpers ----------
def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def is_logged_in() -> bool:
    return bool(session.get("uid"))

def require_login(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrap


# ---------- misc helpers ----------
def make_code(n=7):
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

def normalize_url(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    # si parece dominio sin protocolo, agregamos https://
    if "://" not in s and "." in s.split("/")[0]:
        s = "https://" + s
    return s

def is_http_url(s: str) -> bool:
    try:
        u = urlparse(s)
        return u.scheme in ("http", "https") and bool(u.netloc)
    except:
        return False

def hash_ip(ip: str) -> str:
    if not ip:
        return ""
    return sha256(ip)[:16]


# ---------- pages ----------
@app.get("/")
def home():
    if not is_logged_in():
        return redirect(url_for("simple"))
    return render_template("home.html", logged=True, username=session.get("username"))

@app.get("/dashboard")
@require_login
def dashboard():
    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM links WHERE user_id=? ORDER BY created_at DESC", (session["uid"],))
    links = c.fetchall()
    conn.close()
    return render_template("dashboard.html", links=links, app_url=APP_URL, username=session.get("username"))

@app.get("/login")
def login():
    return render_template("login.html")

@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    u = c.fetchone()
    conn.close()

    if not u or u["password_hash"] != sha256(password):
        return render_template("login.html", error="Usuario o contraseña incorrectos")

    session["uid"] = u["id"]
    session["username"] = u["username"]
    # después de login: se queda en home para crear
    return redirect(url_for("home"))

@app.get("/register")
def register():
    return render_template("register.html")

@app.post("/register")
def register_post():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    if len(username) < 3 or len(password) < 4:
        return render_template("register.html", error="Usuario mínimo 3 chars y contraseña mínimo 4")

    conn = db()
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users(username, password_hash, created_at) VALUES(?,?,?)",
            (username, sha256(password), int(time.time()))
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return render_template("register.html", error="Ese usuario ya existe")

    conn.close()
    # al registrar, que vaya a login (más claro)
    return redirect(url_for("login"))

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------- API: create link ----------
@app.post("/api/create")
def api_create():
    data = request.get_json(force=True)

    kind = (data.get("kind") or "url").strip().lower()
    title = (data.get("title") or "").strip() or None
    target_url = normalize_url(data.get("target_url") or "")
    payload = data.get("payload")  # dict o string dependiendo
    expires_at = data.get("expires_at")
    max_scans = data.get("max_scans")

    # Reglas invitado: SOLO URL http/https y sin extras
    if not is_logged_in():
        if kind != "url":
            return jsonify({"ok": False, "need_login": True, "error": "Para más opciones tenés que iniciar sesión."}), 403
        if not target_url or not is_http_url(target_url):
            return jsonify({"ok": False, "need_login": False, "error": "Solo se permiten links http/https."}), 400
        if title or expires_at or max_scans:
            return jsonify({"ok": False, "need_login": True, "error": "Título/expira/límite requieren iniciar sesión."}), 403

    # Reglas logueado
    if is_logged_in():
        # URL
        if kind == "url":
            if not target_url or not is_http_url(target_url):
                return jsonify({"ok": False, "error": "URL inválida (http/https)."}), 400
        # WhatsApp lo convertimos a URL si viene un número
        elif kind == "whatsapp":
            # payload puede ser {phone:"505...", msg:"hola"}
            if not isinstance(payload, dict):
                return jsonify({"ok": False, "error": "Payload inválido para whatsapp."}), 400
            phone = "".join(ch for ch in (payload.get("phone") or "") if ch.isdigit())
            msg = (payload.get("msg") or "").strip()
            if not phone:
                return jsonify({"ok": False, "error": "Falta número (con código país)."}), 400
            wa = f"https://wa.me/{phone}"
            if msg:
                # dejamos que el frontend encodee, aquí lo simple:
                from urllib.parse import quote
                wa += f"?text={quote(msg)}"
            target_url = wa
            kind = "url"  # whatsapp termina como URL
        # wifi/text/vcard -> se abre en viewer /v/<code>
        elif kind in ("wifi", "text", "vcard"):
            if payload is None:
                return jsonify({"ok": False, "error": "Falta payload."}), 400
        else:
            return jsonify({"ok": False, "error": "Tipo no soportado."}), 400

    # Sanitizar expires/max
    if expires_at is not None:
        try:
            expires_at = int(expires_at)
        except:
            return jsonify({"ok": False, "error": "expires_at debe ser epoch int."}), 400
    if max_scans is not None:
        try:
            max_scans = int(max_scans)
            if max_scans < 1:
                raise ValueError()
        except:
            return jsonify({"ok": False, "error": "max_scans inválido."}), 400

    # Insert
    conn = db()
    c = conn.cursor()

    code = make_code()
    for _ in range(10):
        c.execute("SELECT 1 FROM links WHERE code=?", (code,))
        if not c.fetchone():
            break
        code = make_code()

    now = int(time.time())
    uid = session.get("uid") or 0

    viewer_enabled = 1 if kind in ("wifi", "text", "vcard") else 0
    payload_json = json.dumps(payload, ensure_ascii=False) if payload is not None else None

    c.execute("""
      INSERT INTO links(user_id, code, kind, title, target_url, payload_json, viewer_enabled,
                        created_at, updated_at, expires_at, max_scans)
      VALUES(?,?,?,?,?,?,?,?,?,?,?)
    """, (uid, code, kind, title, target_url, payload_json, viewer_enabled,
          now, now, expires_at, max_scans))
    conn.commit()
    conn.close()

    short_url = f"{APP_URL}/r/{code}"
    return jsonify({"ok": True, "code": code, "short_url": short_url, "guest": (uid == 0)})

@app.get("/simple")
def simple():
    # Página simple solo para invitados
    if is_logged_in():
        return redirect(url_for("home"))  # o url_for("pro") si querés separar
    return render_template("simple.html")
# ---------- API: update destination (solo dueño, solo links url) ----------
@app.post("/api/update")
@require_login
def api_update():
    data = request.get_json(force=True)
    code = (data.get("code") or "").strip()
    new_url = normalize_url(data.get("target_url") or "")

    if not code:
        return jsonify({"ok": False, "error": "Falta code"}), 400
    if not is_http_url(new_url):
        return jsonify({"ok": False, "error": "URL inválida (http/https)."}), 400

    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM links WHERE code=? AND user_id=?", (code, session["uid"]))
    link = c.fetchone()
    if not link:
        conn.close()
        return jsonify({"ok": False, "error": "No encontrado"}), 404

    # Si es viewer payload, no se actualiza como URL (para evitar lío)
    if link["viewer_enabled"] == 1:
        conn.close()
        return jsonify({"ok": False, "error": "Este QR es de tipo payload (WiFi/Text/vCard)."}), 400

    now = int(time.time())
    c.execute("UPDATE links SET target_url=?, updated_at=? WHERE code=? AND user_id=?",
              (new_url, now, code, session["uid"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ---------- API: stats (solo dueño) ----------
@app.get("/api/stats/<code>")
@require_login
def api_stats(code):
    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM links WHERE code=? AND user_id=?", (code, session["uid"]))
    link = c.fetchone()
    if not link:
        conn.close()
        return jsonify({"ok": False, "error": "No encontrado"}), 404

    c.execute("SELECT COUNT(*) AS n FROM scans WHERE link_id=?", (link["id"],))
    total = c.fetchone()["n"]

    c.execute("""
      SELECT ts, ua, ref
      FROM scans
      WHERE link_id=?
      ORDER BY ts DESC
      LIMIT 30
    """, (link["id"],))
    recent = [dict(r) for r in c.fetchall()]
    conn.close()

    return jsonify({
        "ok": True,
        "code": code,
        "kind": link["kind"],
        "title": link["title"],
        "viewer_enabled": bool(link["viewer_enabled"]),
        "target_url": link["target_url"],
        "expires_at": link["expires_at"],
        "max_scans": link["max_scans"],
        "total_scans": total,
        "recent": recent
    })


# ---------- Redirect dynamic + tracking ----------
@app.get("/r/<code>")
def redirect_code(code):
    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM links WHERE code=?", (code,))
    link = c.fetchone()
    if not link:
        conn.close()
        return "Link no encontrado", 404

    now = int(time.time())

    # Expiración
    if link["expires_at"] is not None and now > int(link["expires_at"]):
        conn.close()
        return "Este QR expiró", 410

    # Límite scans
    c.execute("SELECT COUNT(*) AS n FROM scans WHERE link_id=?", (link["id"],))
    total = c.fetchone()["n"]
    if link["max_scans"] is not None and total >= int(link["max_scans"]):
        conn.close()
        return "Este QR alcanzó el límite de escaneos", 429

    # Track scan
    ua = (request.headers.get("User-Agent") or "")[:300]
    ref = (request.headers.get("Referer") or "")[:300]
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    ip = (ip.split(",")[0].strip() if ip else "")
    ip_hash = hash_ip(ip)

    c.execute("INSERT INTO scans(link_id, ts, ua, ref, ip_hash) VALUES(?,?,?,?,?)",
              (link["id"], now, ua, ref, ip_hash))
    conn.commit()

    # Redirect:
    if link["viewer_enabled"] == 1:
        conn.close()
        return redirect(url_for("view_payload", code=code), code=302)

    # normal URL
    target = link["target_url"]
    conn.close()
    if not target:
        return "Destino inválido", 400
    return redirect(target, code=302)


# ---------- Viewer for payload types ----------
@app.get("/v/<code>")
def view_payload(code):
    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM links WHERE code=?", (code,))
    link = c.fetchone()
    conn.close()

    if not link:
        abort(404)

    # Si no es tipo payload, redirige normal
    if link["viewer_enabled"] != 1:
        return redirect(url_for("redirect_code", code=code))

    payload = None
    pretty_payload = ""

    if link["payload_json"]:
        try:
            payload = json.loads(link["payload_json"])
            # 🔥 Formateamos bonito aquí (SIN romper Jinja)
            pretty_payload = json.dumps(
                payload,
                indent=2,
                ensure_ascii=False
            )
        except Exception:
            pretty_payload = link["payload_json"]

    return render_template(
        "view_payload.html",
        link=link,
        payload_pretty=pretty_payload,
        app_url=APP_URL
    )
if __name__ == "__main__":
    init_db()
    app.run(debug=True)