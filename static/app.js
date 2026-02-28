/* global QRCode */
const logged = window.__LOGGED__ === true;

const $ = (id) => document.getElementById(id);

const kind = $("kind");
const title = $("title");
const expiresIn = $("expires_in");
const maxScans = $("max_scans");
const fields = $("fields");

const btnCreate = $("btnCreate");
const btnCopy = $("btnCopy");
const btnDownload = $("btnDownload");

const statusEl = $("status");
const qrEl = $("qr");
const shortUrlEl = $("shortUrl");
const modeHint = $("modeHint");

let lastShortUrl = "";
let lastCode = "";

function setStatus(msg, ok = true){
  statusEl.textContent = msg;
  statusEl.className = ok ? "status" : "status bad";
}

function normalizeUrl(s){
  let t = (s || "").trim();
  if(!t) return "";
  if(!t.includes("://") && /^[a-z0-9.-]+\.[a-z]{2,}([/:?].*)?$/i.test(t)){
    t = "https://" + t;
  }
  return t;
}

function renderFields(){
  const k = kind.value;

  // Invitado: solo URL. Mostrar hint.
  if(!logged){
    modeHint.innerHTML = `✅ Invitado: solo <b>URL</b>. 🔒 Más opciones: <a href="/login">login</a>.`;
  } else {
    modeHint.innerHTML = `🔓 Logueado: tenés URL + WhatsApp + WiFi + Texto + vCard.`;
  }

  // Si invitado, forzamos selector a url (y deshabilitamos otros)
  if(!logged){
    // dejamos ver opciones pero si elige otra, lo regresamos
    if(k !== "url"){
      kind.value = "url";
    }
  }

  if(kind.value === "url"){
    fields.innerHTML = `
      <label class="label">URL</label>
      <input id="f_url" class="input" placeholder="https://..." />
      <div class="tiny">Ej: https://youtube.com, https://tusitio.com</div>
    `;
  } else if(kind.value === "whatsapp"){
    fields.innerHTML = `
      <label class="label">WhatsApp</label>
      <input id="f_phone" class="input" placeholder="505XXXXXXXX (con código país)" />
      <input id="f_msg" class="input" placeholder="Mensaje (opcional)" />
    `;
  } else if(kind.value === "wifi"){
    fields.innerHTML = `
      <label class="label">WiFi</label>
      <input id="f_ssid" class="input" placeholder="SSID / Nombre de red" />
      <input id="f_pass" class="input" placeholder="Contraseña" />
      <select id="f_sec" class="input">
        <option value="WPA" selected>WPA/WPA2</option>
        <option value="WEP">WEP</option>
        <option value="nopass">Sin contraseña</option>
      </select>
      <div class="tiny">Esto abre un viewer /v/ para copiar los datos.</div>
    `;
  } else if(kind.value === "text"){
    fields.innerHTML = `
      <label class="label">Texto</label>
      <textarea id="f_text" class="input" rows="4" placeholder="Escribí algo..."></textarea>
      <div class="tiny">Esto abre un viewer /v/.</div>
    `;
  } else if(kind.value === "vcard"){
    fields.innerHTML = `
      <label class="label">Contacto (vCard)</label>
      <input id="f_name" class="input" placeholder="Nombre completo" />
      <input id="f_tel" class="input" placeholder="Teléfono (opcional)" />
      <input id="f_email" class="input" placeholder="Email (opcional)" />
      <input id="f_org" class="input" placeholder="Empresa (opcional)" />
      <div class="tiny">Esto abre un viewer /v/.</div>
    `;
  }

  // Invitado: bloquear extras visualmente
  const locked = !logged;
  title.disabled = locked;
  expiresIn.disabled = locked;
  maxScans.disabled = locked;
}

function buildCreatePayload(){
  const k = kind.value;

  if(!logged && k !== "url"){
    // seguridad extra
    return { error: "Para más opciones, iniciá sesión." };
  }

  const common = {
    kind: k,
    title: (title.value || "").trim() || null,
    expires_at: null,
    max_scans: null
  };

  if(logged){
    const expMin = parseInt(expiresIn.value || "", 10);
    if(Number.isFinite(expMin) && expMin > 0){
      common.expires_at = Math.floor(Date.now()/1000) + expMin * 60;
    }
    const mx = parseInt(maxScans.value || "", 10);
    if(Number.isFinite(mx) && mx > 0){
      common.max_scans = mx;
    }
  }

  if(k === "url"){
    const u = normalizeUrl($("f_url").value);
    return { ...common, target_url: u };
  }

  if(k === "whatsapp"){
    const phone = ($("f_phone").value || "").trim();
    const msg = ($("f_msg").value || "").trim();
    return { ...common, payload: { phone, msg } };
  }

  if(k === "wifi"){
    const ssid = ($("f_ssid").value || "").trim();
    const pass = ($("f_pass").value || "").trim();
    const sec = $("f_sec").value;
    return { ...common, payload: { ssid, pass, sec } };
  }

  if(k === "text"){
    const text = ($("f_text").value || "").trim();
    return { ...common, payload: text };
  }

  if(k === "vcard"){
    const name = ($("f_name").value || "").trim();
    const tel = ($("f_tel").value || "").trim();
    const email = ($("f_email").value || "").trim();
    const org = ($("f_org").value || "").trim();
    return { ...common, payload: { name, tel, email, org } };
  }

  return { error: "Tipo no soportado" };
}

async function createLink(){
  const payload = buildCreatePayload();
  if(payload.error){
    setStatus(payload.error, false);
    return;
  }

  // Validaciones rápidas en frontend
  if(payload.kind === "url"){
    if(!payload.target_url){
      setStatus("Pegá una URL primero.", false); return;
    }
  }
  if(!logged && (payload.title || payload.expires_at || payload.max_scans)){
    setStatus("Esas opciones requieren login.", false); return;
  }

  const r = await fetch("/api/create", {
    method: "POST",
    headers: { "Content-Type":"application/json" },
    body: JSON.stringify(payload)
  });
  const j = await r.json();

  if(!j.ok){
    if(j.need_login){
      setStatus("🔒 Para más opciones: iniciá sesión.", false);
      return;
    }
    setStatus(j.error || "Error creando QR", false);
    return;
  }

  lastShortUrl = j.short_url;
  lastCode = j.code;

  // Render QR
  qrEl.innerHTML = "";
  new QRCode(qrEl, { text: lastShortUrl, width: 260, height: 260 });

  shortUrlEl.textContent = lastShortUrl;

  btnCopy.disabled = false;
  btnDownload.disabled = false;

  setStatus(j.guest ? "QR creado ✅ (modo invitado)" : "QR creado ✅ (logueado)");
}

async function copyLink(){
  try{
    await navigator.clipboard.writeText(lastShortUrl);
    setStatus("Link copiado ✅");
  } catch {
    setStatus("No pude copiar 😵", false);
  }
}

function downloadQR(){
  const img = qrEl.querySelector("img");
  const canvas = qrEl.querySelector("canvas");
  let dataUrl = "";
  if(img?.src) dataUrl = img.src;
  else if(canvas) dataUrl = canvas.toDataURL("image/png");
  else { setStatus("No encontré el QR para descargar.", false); return; }

  const a = document.createElement("a");
  a.href = dataUrl;
  a.download = `qr-${(lastCode||"code")}.png`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setStatus("Descargado ✅");
}

kind.addEventListener("change", () => {
  // invitado: forzar URL
  if(!logged && kind.value !== "url"){
    kind.value = "url";
    setStatus("🔒 Invitado solo URL. Logueate para más opciones.", false);
  } else {
    setStatus("");
  }
  renderFields();
});

btnCreate.addEventListener("click", createLink);
btnCopy.addEventListener("click", copyLink);
btnDownload.addEventListener("click", downloadQR);

// init
renderFields();
setStatus("Pegá un link y generá tu QR ✅");