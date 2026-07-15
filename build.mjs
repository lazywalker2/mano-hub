// Mano Hub — šifruoto puslapio generatorius.
// Naudojimas: node build.mjs "slaptažodis"
// Iš src.html (tikroji programa) sukuria index.html — AES-256-GCM šifruotą
// puslapį su slaptažodžio langu. Į GitHub keliauja tik index.html.
import { webcrypto as crypto } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const pass = process.argv[2];
if (!pass) { console.error('Naudojimas: node build.mjs "slaptažodis"'); process.exit(1); }

const html = readFileSync(new URL('./src.html', import.meta.url), 'utf8');
const enc = new TextEncoder();
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const keyMat = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' },
  keyMat, { name: 'AES-GCM', length: 256 }, true, ['encrypt']
);
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(html));
const b64 = b => Buffer.from(b).toString('base64');

const loader = `<!DOCTYPE html>
<html lang="lt">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mano Hub</title>
<style>
  :root { --bg:#f5f5f7; --surface:#fff; --text:#1d1d1f; --muted:#6e6e73; --accent:#0071e3; --border:#e5e5ea; --danger:#ff3b30; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#161617; --surface:#1f1f21; --text:#f5f5f7; --muted:#98989d; --accent:#0a84ff; --border:#38383c; --danger:#ff453a; }
  }
  * { box-sizing:border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    background:var(--bg); color:var(--text); padding:20px; }
  .card { background:var(--surface); border:1px solid var(--border); border-radius:18px;
    padding:30px 26px; width:100%; max-width:340px; text-align:center;
    box-shadow:0 1px 3px rgba(0,0,0,.06),0 8px 30px rgba(0,0,0,.08); }
  h1 { margin:0 0 18px; font-size:1.2rem; letter-spacing:-.01em; }
  input[type=password] { width:100%; font:inherit; color:var(--text); background:var(--bg);
    border:1px solid var(--border); border-radius:10px; padding:10px 12px; text-align:center; }
  input:focus { outline:2px solid var(--accent); outline-offset:-1px; }
  .rem { display:flex; gap:7px; align-items:center; justify-content:center;
    font-size:.82rem; color:var(--muted); margin-top:12px; cursor:pointer; }
  .err { color:var(--danger); font-size:.8rem; min-height:1em; margin:10px 0 0; }
  button { width:100%; margin-top:12px; border:none; font:inherit; font-weight:500;
    background:var(--accent); color:#fff; padding:10px; border-radius:980px; cursor:pointer; }
  button:active { opacity:.75; }
</style>
</head>
<body>
<div class="card" id="card" hidden>
  <h1>🔒 Mano Hub</h1>
  <input type="password" id="p" placeholder="Slaptažodis" autocomplete="current-password">
  <label class="rem"><input type="checkbox" id="rem" checked> Prisiminti šiame įrenginyje</label>
  <p class="err" id="err"></p>
  <button id="go">Atrakinti</button>
</div>
<script>
const DATA = { salt: '__SALT__', iv: '__IV__', ct: '__CT__' };
const b2u = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function keyFromPass(p) {
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(p), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b2u(DATA.salt), iterations: 310000, hash: 'SHA-256' },
    km, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
}
async function decryptWith(key) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b2u(DATA.iv) }, key, b2u(DATA.ct));
  return new TextDecoder().decode(pt);
}
function boot(html) { document.open(); document.write(html); document.close(); }
async function unlock() {
  const err = document.getElementById('err');
  err.textContent = '';
  try {
    const key = await keyFromPass(document.getElementById('p').value);
    const html = await decryptWith(key);
    if (document.getElementById('rem').checked) {
      const raw = await crypto.subtle.exportKey('raw', key);
      try { localStorage.setItem('hub.pageKey', btoa(String.fromCharCode(...new Uint8Array(raw)))) } catch {}
    }
    boot(html);
  } catch { err.textContent = 'Neteisingas slaptažodis'; }
}
(async () => {
  let k = null;
  try { k = localStorage.getItem('hub.pageKey'); } catch {}
  if (k) {
    try {
      const key = await crypto.subtle.importKey('raw', b2u(k), { name: 'AES-GCM' }, false, ['decrypt']);
      return boot(await decryptWith(key));
    } catch { try { localStorage.removeItem('hub.pageKey'); } catch {} }
  }
  document.getElementById('card').hidden = false;
  document.getElementById('p').focus();
})();
document.getElementById('go').addEventListener('click', unlock);
document.getElementById('p').addEventListener('keydown', e => { if (e.key === 'Enter') unlock(); });
</script>
</body>
</html>`;

writeFileSync(new URL('./index.html', import.meta.url),
  loader.replace('__SALT__', b64(salt)).replace('__IV__', b64(iv)).replace('__CT__', b64(ct)));
console.log('index.html sugeneruotas (' + Math.round(Buffer.byteLength(loader) / 1024) + ' KB be duomenų, šifras ' + Math.round(ct.byteLength / 1024) + ' KB).');
