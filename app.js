// ShieldKit: defensive security tools that run in the browser. No build step.
const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

/* ---------------- UI helpers ---------------- */
function toast(msg = "Copied") {
  $("toast").textContent = msg;
  $("toast").classList.add("show");
  setTimeout(() => $("toast").classList.remove("show"), 1100);
}
function copy(text) { navigator.clipboard.writeText(text).then(() => toast()); }
function esc(s) { return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

// Typing effect in the hero
(() => {
  const cmds = ["./audit --password", "./analyze --url suspicious.link", "./hash --identify", "./jwt --inspect", "./codec --base64"];
  let i = 0, j = 0, del = false;
  (function tick() {
    const c = cmds[i];
    $("typed").textContent = c.slice(0, j);
    if (!del && j < c.length) j++;
    else if (!del) { del = true; return setTimeout(tick, 1400); }
    else if (j > 0) j--;
    else { del = false; i = (i + 1) % cmds.length; }
    setTimeout(tick, del ? 30 : 70);
  })();
})();

// Tabs
$("tabs").addEventListener("click", (e) => {
  const t = e.target.closest(".tab");
  if (!t) return;
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("on", x === t));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("on", p.id === "p-" + t.dataset.t));
});

/* ---------------- 1. Password audit ---------------- */
const COMMON = ["password", "123456", "123456789", "qwerty", "abc123", "111111", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon", "football", "baseball", "sunshine", "princess", "master", "shadow", "superman", "trustno1", "passw0rd", "p@ssw0rd", "password1", "qwerty123", "1q2w3e4r", "zaq12wsx", "000000", "654321", "india", "india123"];

function analyzePassword(pw) {
  const checks = {
    "12+ characters": pw.length >= 12,
    "Lowercase letter": /[a-z]/.test(pw),
    "Uppercase letter": /[A-Z]/.test(pw),
    "Number": /\d/.test(pw),
    "Symbol": /[^A-Za-z0-9]/.test(pw),
    "No repeated runs (aaa)": !/(.)\1\1/.test(pw),
    "No sequences (abc, 123)": !hasSequence(pw),
    "Not a common password": !COMMON.includes(pw.toLowerCase()),
  };
  let pool = 0;
  if (checks["Lowercase letter"]) pool += 26;
  if (checks["Uppercase letter"]) pool += 26;
  if (checks["Number"]) pool += 10;
  if (checks["Symbol"]) pool += 33;
  let entropy = pw.length ? pw.length * Math.log2(Math.max(pool, 1)) : 0;
  if (!checks["Not a common password"]) entropy = Math.min(entropy, 10);
  if (!checks["No repeated runs (aaa)"]) entropy *= 0.8;
  if (!checks["No sequences (abc, 123)"]) entropy *= 0.85;
  const seconds = Math.pow(2, entropy) / 2 / 1e10;
  return { checks, entropy, seconds };
}
function hasSequence(s) {
  const t = s.toLowerCase();
  for (let i = 0; i < t.length - 2; i++) {
    const a = t.charCodeAt(i), b = t.charCodeAt(i + 1), c = t.charCodeAt(i + 2);
    if ((b - a === 1 && c - b === 1) || (a - b === 1 && b - c === 1)) return true;
  }
  return /qwer|asdf|zxcv/.test(t);
}
function humanTime(s) {
  if (s < 1) return "instantly";
  const u = [["centuries", 3.15e9], ["years", 3.15e7], ["days", 86400], ["hours", 3600], ["minutes", 60], ["seconds", 1]];
  for (const [n, v] of u) if (s >= v) {
    const x = s / v;
    return x > 1e6 ? "∞ (heat death)" : `${x < 10 ? x.toFixed(1) : Math.round(x).toLocaleString()} ${n}`;
  }
}
function renderPassword() {
  const pw = $("pw").value;
  $("pwBreach").textContent = "—";
  $("pwBreach").className = "";
  const { checks, entropy, seconds } = analyzePassword(pw);
  $("pwChecks").innerHTML = Object.entries(checks).map(([k, v]) => `<li class="${pw && v ? "ok" : "no"}">${k}</li>`).join("");
  if (!pw) {
    ["pwLabel", "pwEntropy", "pwCrack"].forEach((id) => ($(id).textContent = "—"));
    $("pwBar").style.width = "0";
    return;
  }
  const levels = [[28, "Very weak", "var(--bad)"], [36, "Weak", "var(--bad)"], [60, "Fair", "var(--warn)"], [80, "Strong", "var(--g2)"], [Infinity, "Very strong", "var(--g)"]];
  const [, label, color] = levels.find(([max]) => entropy < max);
  $("pwLabel").textContent = label;
  $("pwLabel").style.color = color;
  $("pwEntropy").textContent = `${Math.round(entropy)} bits`;
  $("pwCrack").textContent = humanTime(seconds);
  $("pwBar").style.width = Math.min(100, (entropy / 100) * 100) + "%";
  $("pwBar").style.background = color;
}
$("pw").addEventListener("input", renderPassword);
$("pwShow").onclick = () => {
  const show = $("pw").type === "password";
  $("pw").type = show ? "text" : "password";
  $("pwShow").textContent = show ? "Hide" : "Show";
};
$("pwGen").onclick = () => {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+?";
  const rnd = crypto.getRandomValues(new Uint32Array(20));
  const pw = [...rnd].map((n) => chars[n % chars.length]).join("");
  $("pw").value = pw;
  $("pw").type = "text";
  $("pwShow").textContent = "Hide";
  renderPassword();
  copy(pw);
  toast("Generated & copied");
};
$("pwBreachBtn").onclick = async () => {
  const pw = $("pw").value;
  if (!pw) return toast("Type a password first");
  const btn = $("pwBreachBtn");
  btn.disabled = true;
  $("pwBreach").textContent = "checking…";
  try {
    const hash = toHex(await crypto.subtle.digest("SHA-1", enc.encode(pw))).toUpperCase();
    const prefix = hash.slice(0, 5), suffix = hash.slice(5);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { "Add-Padding": "true" } });
    if (!res.ok) throw new Error();
    const line = (await res.text()).split("\n").find((l) => l.startsWith(suffix));
    const count = line ? parseInt(line.split(":")[1], 10) : 0;
    $("pwBreach").textContent = count ? `YES · ${count.toLocaleString()}×` : "Not found";
    $("pwBreach").className = count ? "bad-t" : "ok-t";
  } catch {
    $("pwBreach").textContent = "API error";
    $("pwBreach").className = "warn-t";
  } finally {
    btn.disabled = false;
  }
};
renderPassword();

/* ---------------- 2. Phishing URL analyzer ---------------- */
const BRANDS = {
  paypal: "paypal.com", apple: "apple.com", microsoft: "microsoft.com", google: "google.com", amazon: "amazon.com",
  netflix: "netflix.com", facebook: "facebook.com", instagram: "instagram.com", whatsapp: "whatsapp.com",
  github: "github.com", linkedin: "linkedin.com", outlook: "outlook.com", icloud: "icloud.com", dropbox: "dropbox.com",
  sbi: "onlinesbi.sbi", hdfc: "hdfcbank.com", icici: "icicibank.com", paytm: "paytm.com", flipkart: "flipkart.com",
};
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly"];
const RISKY_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "click", "link", "work", "rest", "country", "kim", "loan", "support", "live", "icu", "buzz"];
const BAIT = ["login", "signin", "verify", "verification", "secure", "update", "account", "confirm", "wallet", "password", "unlock", "suspend", "billing", "reward", "free", "gift", "bonus", "kyc"];
const TWO_PART = ["co.uk", "co.in", "com.au", "co.jp", "org.uk", "net.in", "gov.in", "ac.in"];

function registeredDomain(host) {
  const parts = host.split(".");
  const last2 = parts.slice(-2).join(".");
  return TWO_PART.includes(last2) ? parts.slice(-3).join(".") : last2;
}
const deLeet = (s) => s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/[0]/g, "o").replace(/[1l|]/g, "l").replace(/3/g, "e").replace(/5/g, "s").replace(/4/g, "a").replace(/7/g, "t");

function analyzeUrl(raw) {
  const flags = [];
  let risk = 0;
  const add = (lvl, msg, why, pts) => { flags.push({ lvl, msg, why }); risk += pts; };
  let input = raw.trim();
  if (/^(javascript|data|vbscript):/i.test(input)) {
    add("bad", "Dangerous URL scheme", "javascript:/data: links can run code or render fake pages.", 60);
    return { risk: 100, flags, host: input.slice(0, 40) };
  }
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) input = "http://" + input;
  let u;
  try { u = new URL(input); } catch { return { error: "That doesn't look like a valid URL." }; }
  const host = u.hostname.toLowerCase();
  const reg = registeredDomain(host);
  const labels = host.split(".");
  const tld = labels[labels.length - 1];
  const full = u.href.toLowerCase();

  if (u.protocol !== "https:") add("warn", "Not using HTTPS", "Data sent to this page isn't encrypted. Real login pages always use HTTPS.", 15);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) add("bad", "Raw IP address instead of a domain", "Legitimate sites use domain names; IP links hide who owns the server.", 35);
  if (u.username || raw.includes("@")) add("bad", "Contains '@' in the URL", "Browsers ignore everything before '@', a classic trick to disguise the real destination.", 30);
  if (host.includes("xn--")) add("bad", "Punycode / homograph domain", "Uses look-alike Unicode characters to imitate a real domain (e.g. аpple.com with a Cyrillic а).", 35);
  if (SHORTENERS.includes(reg) || SHORTENERS.includes(host)) add("warn", "Link shortener", "Hides the real destination. Expand it with a preview service before clicking.", 20);
  if (RISKY_TLDS.includes(tld)) add("warn", `High-abuse TLD (.${tld})`, "Cheap domains like this are heavily used in phishing campaigns.", 15);
  if (labels.length > 4) add("warn", `Many subdomains (${labels.length - 2})`, "Attackers stack subdomains so the brand name appears first, e.g. paypal.com.evil.xyz.", 15);
  if ((reg.match(/-/g) || []).length >= 2) add("warn", "Multiple hyphens in domain", "Names like secure-login-verify.com are a common phishing pattern.", 10);
  if (u.port && !["80", "443"].includes(u.port)) add("warn", `Unusual port :${u.port}`, "Normal websites don't need a custom port.", 10);
  if (u.href.length > 100) add("warn", `Very long URL (${u.href.length} chars)`, "Long URLs can push the real domain out of view.", 8);
  if ((u.href.match(/%[0-9a-f]{2}/gi) || []).length > 3) add("warn", "Heavy URL encoding", "Encoded characters can hide what the link really contains.", 8);

  const bait = BAIT.filter((w) => full.includes(w));
  if (bait.length) add("warn", `Bait keywords: ${bait.slice(0, 4).join(", ")}`, "Urgent account/security words are used to rush you into entering details.", Math.min(20, bait.length * 7));

  let brandHit = false;
  for (const [brand, real] of Object.entries(BRANDS)) {
    const official = reg === real || reg === registeredDomain(real);
    if (official) { brandHit = true; add("ok", `Official ${brand} domain`, `The registered domain is ${reg}.`, -25); break; }
    if (host.includes(brand)) { brandHit = true; add("bad", `Uses "${brand}" but isn't ${real}`, `The real owner of this link is ${reg}, not ${brand}.`, 40); break; }
    const fake = labels.find((l) => deLeet(l).includes(brand));
    if (fake) { brandHit = true; add("bad", `Look-alike of ${brand}`, `"${fake}" imitates "${brand}" using swapped characters (1→l, 0→o, rn→m). The real owner is ${reg}.`, 45); break; }
  }
  // A login page on the brand's real domain is expected, so drop the bait-keyword warning
  if (flags.some((f) => f.msg.startsWith("Official"))) {
    const i = flags.findIndex((f) => f.msg.startsWith("Bait"));
    if (i > -1) { risk -= Math.min(20, bait.length * 7); flags.splice(i, 1); }
  }
  if (!brandHit && u.protocol === "https:" && !flags.some((f) => f.lvl === "bad")) add("ok", "No impersonation detected", "No known brand is being imitated in this domain.", 0);

  return { risk: Math.max(0, Math.min(100, risk)), flags, host, reg };
}

function renderUrl() {
  const raw = $("url").value;
  if (!raw.trim()) return ($("urlOut").innerHTML = "");
  const r = analyzeUrl(raw);
  if (r.error) return ($("urlOut").innerHTML = `<div class="alert warn">${esc(r.error)}</div>`);
  const [label, cls] = r.risk >= 50 ? ["HIGH RISK: likely phishing", "bad-t"] : r.risk >= 20 ? ["SUSPICIOUS: be careful", "warn-t"] : ["LOW RISK", "ok-t"];
  const order = { bad: 0, warn: 1, ok: 2 };
  $("urlOut").innerHTML = `
    <div class="verdict">
      <div class="verdict-top">
        <div class="score ${cls}">${r.risk}</div>
        <div><h3 class="${cls}">${label}</h3><div class="host">Real domain: ${esc(r.reg || r.host)}</div></div>
      </div>
      <ul class="flags">${r.flags.sort((a, b) => order[a.lvl] - order[b.lvl]).map((f) => `<li class="${f.lvl}">${esc(f.msg)}<small>${esc(f.why)}</small></li>`).join("") || '<li class="ok">No red flags found<small>Still verify the sender before entering any details.</small></li>'}</ul>
    </div>`;
}
$("urlGo").onclick = renderUrl;
$("url").addEventListener("keydown", (e) => e.key === "Enter" && renderUrl());
document.querySelectorAll("[data-u]").forEach((b) => (b.onclick = () => { $("url").value = b.dataset.u; renderUrl(); }));

/* ---------------- 3. Hash tools ---------------- */
// Compact MD5 (RFC 1321). SubtleCrypto doesn't support MD5, so it's implemented here.
function md5(bytes) {
  const K = [], S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0;
  const len = bytes.length, nBlocks = ((len + 8) >> 6) + 1, w = new Uint32Array(nBlocks * 16);
  for (let i = 0; i < len; i++) w[i >> 2] |= bytes[i] << ((i % 4) * 8);
  w[len >> 2] |= 0x80 << ((len % 4) * 8);
  w[nBlocks * 16 - 2] = (len * 8) >>> 0;
  w[nBlocks * 16 - 1] = Math.floor(len / 0x20000000);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let blk = 0; blk < nBlocks; blk++) {
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      const tmp = D; D = C; C = B;
      const x = (A + F + K[i] + w[blk * 16 + g]) >>> 0;
      const s = S[(i >> 4) * 4 + (i % 4)];
      B = (B + ((x << s) | (x >>> (32 - s)))) >>> 0;
      A = tmp;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  return [a0, b0, c0, d0].map((v) => [0, 8, 16, 24].map((s) => ((v >>> s) & 255).toString(16).padStart(2, "0")).join("")).join("");
}

function kvItem(k, v) { return `<div class="item" data-copy="${esc(v)}"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`; }
document.addEventListener("click", (e) => { const it = e.target.closest("[data-copy]"); if (it) copy(it.dataset.copy); });

async function renderHashes() {
  const text = $("hashIn").value;
  if (!text) return ($("hashOut").innerHTML = "");
  const bytes = enc.encode(text);
  const out = [["MD5 (insecure)", md5(bytes)]];
  for (const alg of ["SHA-1", "SHA-256", "SHA-384", "SHA-512"]) out.push([alg + (alg === "SHA-1" ? " (insecure)" : ""), toHex(await crypto.subtle.digest(alg, bytes))]);
  $("hashOut").innerHTML = out.map(([k, v]) => kvItem(k, v)).join("") + '<p class="note">Click any hash to copy. Never store passwords with fast hashes; use bcrypt, scrypt or Argon2.</p>';
}
$("hashIn").addEventListener("input", renderHashes);

function identifyHash(h) {
  h = h.trim();
  if (!h) return [];
  const prefixed = [
    [/^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/, "bcrypt", "Slow, salted password hash: good choice ✓"],
    [/^\$argon2(id|i|d)\$/, "Argon2", "Modern memory-hard password hash: best choice ✓"],
    [/^\$scrypt\$|^\$7\$/, "scrypt", "Memory-hard password hash ✓"],
    [/^\$6\$/, "SHA-512 crypt", "Linux /etc/shadow format"],
    [/^\$5\$/, "SHA-256 crypt", "Linux /etc/shadow format"],
    [/^\$1\$/, "MD5 crypt", "Legacy Unix format: weak"],
    [/^\$apr1\$/, "Apache APR1 MD5", "Used in .htpasswd: weak"],
    [/^pbkdf2_sha256\$/, "PBKDF2-SHA256 (Django)", "Salted & iterated ✓"],
    [/^\*[0-9A-F]{40}$/i, "MySQL 4.1+ (SHA1(SHA1()))", "Unsalted: weak"],
  ];
  for (const [re, name, note] of prefixed) if (re.test(h)) return [[name, note]];
  if (/^[0-9a-f]+$/i.test(h)) {
    const map = {
      8: [["CRC32 / Adler-32", "Checksum, not a security hash"]],
      16: [["MySQL 3.x (OLD_PASSWORD)", "Very weak"], ["Half MD5", ""]],
      32: [["MD5", "Most likely. Broken, crackable in seconds"], ["NTLM", "Windows password hash: unsalted"], ["MD4", "Legacy"]],
      40: [["SHA-1", "Most likely. Deprecated"], ["RIPEMD-160", ""]],
      56: [["SHA-224", ""], ["SHA3-224", ""]],
      64: [["SHA-256", "Most likely"], ["SHA3-256", ""], ["BLAKE2s", ""]],
      96: [["SHA-384", ""], ["SHA3-384", ""]],
      128: [["SHA-512", "Most likely"], ["SHA3-512", ""], ["Whirlpool", ""], ["BLAKE2b", ""]],
    };
    return map[h.length] || [["Unknown hex string", `${h.length} hex chars doesn't match a common hash length`]];
  }
  if (/^[A-Za-z0-9+/]+=*$/.test(h) && h.length % 4 === 0) return [["Base64 data", "Possibly an encoded hash or key. Try decoding it in the Encode tab"]];
  return [["Not recognized", "Doesn't match common hash formats"]];
}
$("hashId").addEventListener("input", () => {
  const r = identifyHash($("hashId").value);
  $("hashIdOut").innerHTML = r.map(([n, note], i) => `<div class="item"><div class="k">${i === 0 ? "Best match" : "Also possible"}</div><div class="v">${esc(n)}${note ? ` <span style="color:var(--muted)">· ${esc(note)}</span>` : ""}</div></div>`).join("");
});

/* ---------------- 4. JWT inspector ---------------- */
const b64urlDecode = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return dec.decode(Uint8Array.from(atob(s), (c) => c.charCodeAt(0)));
};
const b64urlEncode = (s) => btoa(String.fromCharCode(...enc.encode(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function renderJwt() {
  const t = $("jwtIn").value.trim();
  const warn = [];
  $("jwtHead").textContent = $("jwtBody").textContent = "—";
  if (!t) return ($("jwtWarn").innerHTML = "");
  const parts = t.split(".");
  if (parts.length !== 3) return ($("jwtWarn").innerHTML = `<div class="alert bad">A JWT must have 3 parts separated by dots (header.payload.signature). Found ${parts.length}.</div>`);
  let head, body;
  try { head = JSON.parse(b64urlDecode(parts[0])); body = JSON.parse(b64urlDecode(parts[1])); }
  catch { return ($("jwtWarn").innerHTML = '<div class="alert bad">Could not decode. The header or payload isn\'t valid Base64URL JSON.</div>'); }
  $("jwtHead").textContent = JSON.stringify(head, null, 2);
  const fmt = (v) => (typeof v === "number" ? `${v}  // ${new Date(v * 1000).toLocaleString()}` : JSON.stringify(v));
  $("jwtBody").textContent = "{\n" + Object.entries(body).map(([k, v]) => `  "${k}": ${["exp", "iat", "nbf", "auth_time"].includes(k) ? fmt(v) : JSON.stringify(v)}`).join(",\n") + "\n}";

  const now = Date.now() / 1000;
  const alg = String(head.alg || "").toLowerCase();
  if (alg === "none") warn.push(["bad", '"alg": "none": the token is unsigned. Servers must reject it, or anyone can forge tokens.']);
  if (!parts[2] && alg !== "none") warn.push(["bad", "Signature is empty."]);
  if (alg.startsWith("hs")) warn.push(["warn", `${head.alg} uses a shared secret. Make sure it's long and random, since weak secrets can be brute-forced offline.`]);
  if (body.exp === undefined) warn.push(["warn", "No exp (expiry) claim: this token never expires."]);
  else if (body.exp < now) warn.push(["bad", `Expired ${humanTime(now - body.exp)} ago.`]);
  else warn.push(["ok", `Valid for another ${humanTime(body.exp - now)}.`]);
  if (body.nbf && body.nbf > now) warn.push(["warn", "Not valid yet (nbf is in the future)."]);
  const sensitive = Object.keys(body).filter((k) => /pass|secret|ssn|card|cvv|pin/i.test(k));
  if (sensitive.length) warn.push(["bad", `Sensitive-looking fields in payload: ${sensitive.join(", ")}. JWT payloads are only encoded, not encrypted.`]);
  warn.push(["warn", "Signature is not verified here. Decoding ≠ trusting. Always verify on the server."]);
  $("jwtWarn").innerHTML = warn.map(([c, m]) => `<div class="alert ${c}">${esc(m)}</div>`).join("");
}
$("jwtIn").addEventListener("input", renderJwt);
$("jwtSample").onclick = () => {
  const now = Math.floor(Date.now() / 1000);
  const h = b64urlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const p = b64urlEncode(JSON.stringify({ sub: "1024", name: "Demo User", role: "admin", iat: now - 7200, exp: now - 3600 }));
  $("jwtIn").value = `${h}.${p}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`;
  renderJwt();
};

/* ---------------- 5. Encoders ---------------- */
const codecs = {
  b64: { e: (s) => btoa(String.fromCharCode(...enc.encode(s))), d: (s) => dec.decode(Uint8Array.from(atob(s.trim()), (c) => c.charCodeAt(0))) },
  url: { e: encodeURIComponent, d: decodeURIComponent },
  hex: { e: (s) => toHex(enc.encode(s)), d: (s) => { const h = s.replace(/[^0-9a-f]/gi, ""); if (h.length % 2) throw new Error("Odd number of hex digits"); return dec.decode(new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)))); } },
  bin: { e: (s) => [...enc.encode(s)].map((b) => b.toString(2).padStart(8, "0")).join(" "), d: (s) => dec.decode(new Uint8Array(s.trim().split(/\s+/).map((b) => { if (!/^[01]{1,8}$/.test(b)) throw new Error("Binary must be groups of 0/1"); return parseInt(b, 2); }))) },
  rot13: { e: (s) => s.replace(/[a-z]/gi, (c) => String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)), d: null },
  html: { e: (s) => s.replace(/[&<>"'\/]/g, (c) => `&#${c.charCodeAt(0)};`), d: (s) => { const t = document.createElement("textarea"); t.innerHTML = s; return t.value; } },
};
codecs.rot13.d = codecs.rot13.e;
function runCodec(dir) {
  $("encErr").textContent = "";
  try { $("encOut").value = codecs[$("encMode").value][dir]($("encIn").value); }
  catch (err) { $("encOut").value = ""; $("encErr").textContent = "✗ " + (err.message.includes("atob") || err.name === "InvalidCharacterError" ? "Input isn't valid for this format" : err.message); }
}
$("encDo").onclick = () => runCodec("e");
$("decDo").onclick = () => runCodec("d");
$("encSwap").onclick = () => { [$("encIn").value, $("encOut").value] = [$("encOut").value, $("encIn").value]; };
$("encOut").addEventListener("click", () => $("encOut").value && copy($("encOut").value));
