// ShieldKit core logic: pure functions with no DOM access, so they can be unit-tested in Node.
(function (root) {
  "use strict";
  const enc = new TextEncoder();
  const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

  /* ================= Domain helpers ================= */
  // Second-level public suffixes (subset of the Public Suffix List)
  const MULTI_SUFFIX = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "org.in", "net.in", "gov.in", "ac.in", "edu.in", "res.in",
    "co.jp", "ne.jp", "or.jp", "com.au", "net.au", "org.au", "com.br", "com.cn", "com.sg", "com.my", "co.za", "co.nz", "com.mx",
    "com.tr", "com.sa", "com.pk", "com.bd", "co.id", "com.ng", "co.kr", "com.hk", "com.tw", "com.ar", "com.vn", "com.ph"]);
  // Platforms where anyone can register a subdomain, so the "owner" is the subdomain, not the platform
  const SHARED_HOSTS = ["github.io", "gitlab.io", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "web.app",
    "firebaseapp.com", "herokuapp.com", "onrender.com", "glitch.me", "repl.co", "replit.app", "replit.dev", "blogspot.com",
    "wordpress.com", "wixsite.com", "weebly.com", "000webhostapp.com", "azurewebsites.net", "appspot.com", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com", "duckdns.org", "r2.dev", "surge.sh", "framer.app", "webflow.io", "square.site",
    "godaddysites.com", "myshopify.com", "carrd.co", "notion.site", "translate.goog"];

  function registeredDomain(host) {
    const labels = host.split(".");
    for (const s of SHARED_HOSTS) {
      if (host === s) return { reg: s, shared: null };
      if (host.endsWith("." + s)) return { reg: labels.slice(-(s.split(".").length + 1)).join("."), shared: s };
    }
    const n = MULTI_SUFFIX.has(labels.slice(-2).join(".")) ? 3 : 2;
    return { reg: labels.slice(-n).join("."), shared: null };
  }

  // Each brand maps to ALL of its official registered domains (avoids false positives like login.microsoftonline.com)
  const MS = ["microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com", "msn.com", "bing.com", "azure.com", "sharepoint.com", "onedrive.com", "skype.com", "xbox.com", "windows.net", "msft.net"];
  const GOOGLE = ["google.com", "google.co.in", "google.co.uk", "googleapis.com", "googleusercontent.com", "gstatic.com", "youtube.com", "youtu.be", "gmail.com", "withgoogle.com", "goo.gl", "g.co", "googlemail.com"];
  const APPLE = ["apple.com", "icloud.com", "apple.co", "me.com", "mzstatic.com"];
  const AMAZON = ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazonaws.com", "amzn.to", "amzn.in", "media-amazon.com", "a2z.com", "primevideo.com"];
  const BRANDS = {
    paypal: ["paypal.com", "paypal.me", "paypalobjects.com"],
    apple: APPLE, icloud: APPLE,
    microsoft: MS, outlook: MS, office365: MS, onedrive: MS, hotmail: MS,
    google: GOOGLE, gmail: GOOGLE, youtube: GOOGLE,
    amazon: AMAZON,
    netflix: ["netflix.com", "nflxext.com", "nflximg.net", "nflxvideo.net"],
    facebook: ["facebook.com", "fb.com", "fb.me", "fbcdn.net", "meta.com", "messenger.com"],
    instagram: ["instagram.com", "cdninstagram.com"],
    whatsapp: ["whatsapp.com", "whatsapp.net", "wa.me"],
    github: ["github.com", "githubusercontent.com", "githubassets.com", "github.dev", "github.blog"],
    linkedin: ["linkedin.com", "licdn.com", "lnkd.in"],
    dropbox: ["dropbox.com", "dropboxusercontent.com", "db.tt"],
    sbi: ["onlinesbi.sbi", "sbi.co.in", "sbicard.com", "onlinesbi.com", "sbi"],
    hdfc: ["hdfcbank.com", "hdfc.com", "hdfcbank.net"],
    icici: ["icicibank.com", "icicidirect.com", "icicilombard.com"],
    paytm: ["paytm.com", "paytm.in", "paytmbank.com"],
    flipkart: ["flipkart.com"],
    binance: ["binance.com"], coinbase: ["coinbase.com"], metamask: ["metamask.io"],
    steam: ["steampowered.com", "steamcommunity.com"],
    adobe: ["adobe.com"], docusign: ["docusign.com", "docusign.net"],
    dhl: ["dhl.com", "dhl.de"], fedex: ["fedex.com"], indiapost: ["indiapost.gov.in"],
    chase: ["chase.com"], wellsfargo: ["wellsfargo.com"], bankofamerica: ["bankofamerica.com"],
  };

  // Optimal-string-alignment distance (Levenshtein + adjacent swaps), used to catch typosquats like "gogle" / "googel"
  function editDistance(a, b) {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++)
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    return d[a.length][b.length];
  }
  // Homoglyph normalisation; "1" can stand for l or i, so both variants are produced
  function deLeet(s) {
    const base = s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/\$/g, "s").replace(/@/g, "a");
    return [...new Set([base.replace(/1/g, "l"), base.replace(/1/g, "i")])];
  }

  // Does a single token impersonate a brand? Returns {brand, how} or null.
  function matchBrand(token) {
    if (token.length < 3) return null;
    for (const brand of Object.keys(BRANDS)) {
      if (token === brand) return { brand, how: "exact" };
      // Partial match only for longer brands, to avoid "pineapple" → apple style false positives
      if (brand.length >= 6 && token.includes(brand)) return { brand, how: "contains" };
    }
    for (const brand of Object.keys(BRANDS)) {
      const variants = deLeet(token).filter((v) => v !== token);
      if (variants.some((v) => v === brand || (brand.length >= 6 && v.includes(brand)))) return { brand, how: "homoglyph" };
      if (brand.length >= 5 && Math.abs(token.length - brand.length) <= 1 && editDistance(token, brand) === 1) return { brand, how: "typo" };
    }
    return null;
  }

  const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "t.ly", "s.id", "v.gd", "bl.ink", "shorte.st", "adf.ly"]);
  const RISKY_TLDS = new Set(["xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "click", "link", "work", "rest", "country", "kim", "loan", "support", "icu", "buzz", "cam", "monster", "quest", "sbs", "cfd", "bond", "lol", "mom"]);
  const BAIT = ["login", "logon", "signin", "verify", "verification", "validate", "secure", "security", "update", "account", "confirm", "wallet", "password", "unlock", "suspended", "suspend", "billing", "invoice", "refund", "reward", "gift", "bonus", "kyc", "recover", "support", "helpdesk", "authenticate", "auth"];
  const RISKY_EXT = /\.(exe|scr|msi|bat|cmd|ps1|vbs|js|jar|apk|dmg|iso|img|hta|lnk|zip|rar|7z)$/i;

  function analyzeUrl(raw) {
    const flags = [];
    let risk = 0;
    const add = (lvl, msg, why, pts = 0) => { flags.push({ lvl, msg, why }); risk += pts; };
    let input = String(raw || "").trim();
    if (!input) return { error: "Paste a link to analyze." };
    if (/^(javascript|data|vbscript|file):/i.test(input)) {
      add("bad", "Dangerous URL scheme", "javascript:, data: and file: links can run code or render fake pages without a real website.", 100);
      return { risk: 100, flags, host: input.split(":")[0] + ":", reg: null };
    }
    let assumed = false;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) { input = "https://" + input; assumed = true; }
    let u;
    try { u = new URL(input); } catch { return { error: "That doesn't look like a valid URL." }; }
    if (!/^https?:$/.test(u.protocol)) add("warn", `Unusual scheme (${u.protocol})`, "Web links normally use http or https.", 15);

    const host = u.hostname.toLowerCase().replace(/\.$/, "");
    const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[");
    const { reg, shared } = isIP ? { reg: host, shared: null } : registeredDomain(host);
    const regLabels = reg.split(".").length;
    const subLabels = host.split(".").slice(0, -regLabels).filter((l) => l !== "www");
    const tld = host.split(".").pop();
    const hostTokens = host.split(/[.-]/).filter(Boolean);
    const pathTokens = decodeSafe(u.pathname + " " + u.search).toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

    if (assumed) add("info", "No scheme given, assumed https://", "Analysis is based on the domain only.");
    if (u.protocol === "http:") add("warn", "Not using HTTPS", "Anything typed on this page travels unencrypted. Real login pages always use HTTPS.", 15);
    if (isIP) add("bad", "Raw IP address instead of a domain", "Legitimate services use domain names; IP links hide who runs the server.", 35);
    if (u.username || u.password) add("bad", "Credentials/'@' trick before the host", `Everything before '@' is ignored. This link really goes to ${host}.`, 35);
    if (host.split(".").some((l) => l.startsWith("xn--"))) add("bad", "Punycode / homograph domain", "Uses look-alike Unicode letters (e.g. a Cyrillic 'а') to imitate a real domain.", 35);
    if (SHORTENERS.has(reg)) add("warn", "Link shortener", "Hides the real destination. Expand it with a link-preview service before opening.", 25);
    if (shared) add("warn", `Free hosting subdomain (*.${shared})`, `Anyone can create a site on ${shared}. The owner is "${reg}", not ${shared}.`, 15);
    if (RISKY_TLDS.has(tld)) add("warn", `High-abuse TLD (.${tld})`, "Cheap domains like this are heavily used in phishing campaigns.", 15);
    if (subLabels.length >= 3) add("warn", `Deep subdomain chain (${subLabels.length} levels)`, "Attackers stack subdomains so a trusted name appears first, e.g. paypal.com.account.evil.xyz.", 15);
    if ((reg.split(".")[0].match(/-/g) || []).length >= 2) add("warn", "Multiple hyphens in domain", "Names like secure-login-verify.com are a common phishing pattern.", 10);
    if (u.port && !["80", "443"].includes(u.port)) add("warn", `Unusual port :${u.port}`, "Normal websites don't need a custom port.", 10);
    if (u.href.length > 120) add("warn", `Very long URL (${u.href.length} chars)`, "Long links push the real domain out of view on phones.", 8);
    if (RISKY_EXT.test(u.pathname)) add("warn", "Links directly to a file download", `The link ends in ${u.pathname.match(RISKY_EXT)[0]}, which could be malware.`, 20);

    // Brand impersonation
    const officialFor = Object.entries(BRANDS).find(([, doms]) => doms.includes(reg));
    let impersonation = null;
    if (officialFor) {
      add("ok", `Official ${officialFor[0]} domain`, `${reg} is a registered domain of ${officialFor[0]}.`, -30);
    } else if (!isIP) {
      const ownerTokens = shared ? reg.split(".")[0].split("-") : hostTokens;
      for (const t of ownerTokens) { impersonation = matchBrand(t); if (impersonation) { impersonation.token = t; break; } }
      if (impersonation) {
        const { brand, how, token } = impersonation;
        const real = BRANDS[brand][0];
        const why = { exact: `"${brand}" appears in the address, but the site is owned by ${reg}, not ${real}.`,
          contains: `"${token}" contains "${brand}", but the site is owned by ${reg}, not ${real}.`,
          homoglyph: `"${token}" imitates "${brand}" using swapped characters (0→o, 1→l/i, rn→m). Owner: ${reg}.`,
          typo: `"${token}" is one letter away from "${brand}" (typosquatting). Owner: ${reg}.` }[how];
        add("bad", how === "exact" || how === "contains" ? `Uses the ${brand} name but isn't ${real}` : `Look-alike of ${brand}`, why, how === "exact" || how === "contains" ? 40 : 45);
      } else {
        const inPath = Object.keys(BRANDS).find((b) => b.length >= 5 && pathTokens.includes(b));
        if (inPath) add("warn", `Brand name "${inPath}" in the path`, `Mentions ${inPath} but the site is ${reg}. Brand names in the path are a common decoy.`, 15);
      }
    }

    const tokens = [...hostTokens, ...pathTokens];
    const bait = BAIT.filter((w) => tokens.some((t) => t === w || (w.length >= 5 && t.startsWith(w))));
    if (bait.length && !officialFor) add("warn", `Bait keywords: ${bait.slice(0, 4).join(", ")}`, "Urgent account/security words are used to rush you into entering details.", Math.min(20, bait.length * 6));

    if (!flags.some((f) => f.lvl === "bad" || f.lvl === "warn") && !officialFor) add("ok", "No red flags found", "Still verify the sender before entering personal details.");
    risk = Math.max(0, Math.min(100, risk));
    const verdict = risk >= 50 ? "high" : risk >= 20 ? "suspicious" : "low";
    return { risk, verdict, flags, host, reg };
  }
  function decodeSafe(s) { try { return decodeURIComponent(s); } catch { return s; } }

  /* ================= Hashes ================= */
  // MD5 (RFC 1321). Web Crypto has no MD5, so it's implemented here. Verified against RFC test vectors in tests/.
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
  async function hashAll(text) {
    const bytes = enc.encode(text);
    const out = [["MD5", md5(bytes), "broken: never use for passwords or signatures"]];
    for (const alg of ["SHA-1", "SHA-256", "SHA-384", "SHA-512"])
      out.push([alg, toHex(await crypto.subtle.digest(alg, bytes)), alg === "SHA-1" ? "deprecated: collisions are practical" : ""]);
    return out;
  }

  function identifyHash(input) {
    const h = String(input || "").trim();
    if (!h) return [];
    const prefixed = [
      [/^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/, "bcrypt", "Slow, salted password hash ✓"],
      [/^\$argon2(id|i|d)\$/, "Argon2", "Modern memory-hard password hash ✓ (best choice)"],
      [/^\$y\$/, "yescrypt", "Default on modern Linux /etc/shadow ✓"],
      [/^\$7\$|^\$scrypt\$/, "scrypt", "Memory-hard password hash ✓"],
      [/^\$6\$/, "SHA-512 crypt", "Linux /etc/shadow, salted and iterated"],
      [/^\$5\$/, "SHA-256 crypt", "Linux /etc/shadow, salted and iterated"],
      [/^\$1\$/, "MD5 crypt", "Legacy Unix format: weak"],
      [/^\$apr1\$/, "Apache APR1 MD5", ".htpasswd: weak"],
      [/^pbkdf2_sha256\$\d+\$/, "PBKDF2-SHA256 (Django)", "Salted and iterated ✓"],
      [/^\{SSHA\}/i, "LDAP Salted SHA-1", "Fast hash: weak"],
      [/^\*[0-9A-F]{40}$/i, "MySQL 4.1+ PASSWORD()", "Unsalted SHA1(SHA1()): weak"],
    ];
    for (const [re, name, note] of prefixed) if (re.test(h)) return [{ name, note, confidence: "high" }];
    if (/^[0-9a-f]+$/i.test(h)) {
      const map = {
        8: [["CRC32", "checksum, not a security hash"]],
        16: [["MySQL 3.x OLD_PASSWORD", "very weak"], ["Half MD5 / 64-bit hash", ""]],
        32: [["MD5", "most common"], ["NTLM", "Windows password hash; identical format to MD5"], ["MD4", ""]],
        40: [["SHA-1", "most common"], ["RIPEMD-160", ""]],
        56: [["SHA-224", ""], ["SHA3-224", ""]],
        64: [["SHA-256", "most common"], ["SHA3-256", ""], ["BLAKE2s-256", ""]],
        96: [["SHA-384", ""], ["SHA3-384", ""]],
        128: [["SHA-512", "most common"], ["SHA3-512", ""], ["BLAKE2b-512", ""], ["Whirlpool", ""]],
      };
      const m = map[h.length];
      if (!m) return [{ name: "Unknown hex string", note: `${h.length} hex characters doesn't match a standard hash length`, confidence: "none" }];
      return m.map(([name, note], i) => ({ name, note, confidence: i === 0 ? "likely" : "possible" }));
    }
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(h) && h.length % 4 === 0 && h.length >= 16) {
      const bytes = (h.length / 4) * 3 - (h.match(/=*$/)[0].length);
      const byLen = { 16: "MD5", 20: "SHA-1", 32: "SHA-256", 48: "SHA-384", 64: "SHA-512" }[bytes];
      return [{ name: byLen ? `Base64-encoded ${byLen}` : "Base64 data", note: `${bytes} bytes once decoded`, confidence: byLen ? "likely" : "possible" }];
    }
    return [{ name: "Not recognized", note: "Doesn't match common hash formats", confidence: "none" }];
  }

  /* ================= JWT ================= */
  function b64urlToBytes(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  }
  function inspectJwt(raw, nowSec = Date.now() / 1000) {
    const t = String(raw || "").trim().replace(/^bearer\s+/i, "");
    if (!t) return null;
    const parts = t.split(".");
    if (parts.length === 5) return { error: "This is a JWE (encrypted token, 5 parts). Its payload can't be read without the key." };
    if (parts.length !== 3) return { error: `A JWT has 3 dot-separated parts (header.payload.signature); found ${parts.length}.` };
    let header, payload;
    try {
      const td = new TextDecoder("utf-8", { fatal: true });
      header = JSON.parse(td.decode(b64urlToBytes(parts[0])));
      payload = JSON.parse(td.decode(b64urlToBytes(parts[1])));
    } catch { return { error: "Header or payload isn't valid Base64URL-encoded JSON." }; }
    if (typeof header !== "object" || !header || typeof payload !== "object" || !payload) return { error: "Header and payload must be JSON objects." };
    const findings = [];
    const alg = String(header.alg ?? "");
    if (!alg) findings.push(["bad", "Missing \"alg\" in header."]);
    else if (alg.toLowerCase() === "none") findings.push(["bad", "\"alg\": \"none\" means the token is unsigned. A server that accepts it lets anyone forge tokens."]);
    else if (/^HS/i.test(alg)) findings.push(["info", `${alg} uses a shared secret. It must be long and random, since weak secrets can be cracked offline from any captured token.`]);
    if (alg.toLowerCase() !== "none" && !parts[2]) findings.push(["bad", "Signature part is empty."]);
    for (const k of ["jku", "x5u"]) if (header[k]) findings.push(["warn", `Header "${k}" points to a remote key URL (${String(header[k]).slice(0, 60)}). The server must only trust an allowlist, or attackers can supply their own key.`]);
    if (header.jwk) findings.push(["warn", "Header embeds its own public key (\"jwk\"). Servers must never trust a key supplied inside the token."]);
    if (typeof header.kid === "string" && /[\/\\'";]|\.\./.test(header.kid)) findings.push(["warn", "\"kid\" contains path or SQL characters. If the server uses it in a file path or query, it may be injectable."]);
    const num = (k) => payload[k] !== undefined && typeof payload[k] !== "number";
    for (const k of ["exp", "nbf", "iat"]) if (num(k)) findings.push(["warn", `"${k}" should be a number (seconds since epoch), got ${typeof payload[k]}.`]);
    if (payload.exp === undefined) findings.push(["warn", "No \"exp\" claim: this token never expires."]);
    else if (typeof payload.exp === "number") {
      if (payload.exp < nowSec) findings.push(["bad", `Expired ${duration(nowSec - payload.exp)} ago.`]);
      else findings.push(["ok", `Expires in ${duration(payload.exp - nowSec)}.`]);
      if (typeof payload.iat === "number" && payload.exp - payload.iat > 30 * 86400) findings.push(["warn", `Lifetime is ${duration(payload.exp - payload.iat)}. Long-lived tokens are risky if stolen.`]);
    }
    if (typeof payload.nbf === "number" && payload.nbf > nowSec) findings.push(["warn", "Not valid yet (\"nbf\" is in the future)."]);
    if (typeof payload.iat === "number" && payload.iat > nowSec + 300) findings.push(["warn", "\"iat\" (issued-at) is in the future. Check for clock skew or tampering."]);
    const sensitiveKey = /^(pass(word)?|pwd|secret|client_secret|ssn|aadhaar|pan|card(_?num(ber)?)?|cc|cvv|cvc|pin|otp|api_?key|private_?key)$/i;
    const sensitive = Object.keys(payload).filter((k) => sensitiveKey.test(k));
    if (sensitive.length) findings.push(["bad", `Sensitive fields in payload: ${sensitive.join(", ")}. JWT payloads are only Base64-encoded, so anyone holding the token can read them.`]);
    findings.push(["info", "The signature isn't verified here: decoding a token doesn't mean you can trust it. Always verify on the server with a pinned algorithm."]);
    return { header, payload, findings };
  }
  function duration(s) {
    s = Math.abs(s);
    const units = [["year", 31557600], ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]];
    for (const [n, v] of units) if (s >= v) { const x = Math.floor(s / v); return `${x} ${n}${x === 1 ? "" : "s"}`; }
    return "0 seconds";
  }

  /* ================= Encoders ================= */
  const bytesToBin = (bytes) => { let s = ""; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000)); return s; };
  const strictUtf8 = (bytes) => {
    try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
    catch { throw new Error("Decoded bytes aren't valid UTF-8 text (binary data?). Hex: " + toHex(bytes).slice(0, 64) + (bytes.length > 32 ? "…" : "")); }
  };
  const codecs = {
    b64: {
      e: (s) => btoa(bytesToBin(enc.encode(s))),
      d: (s) => {
        let t = s.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(t)) throw new Error("Not valid Base64");
        while (t.length % 4) t += "=";
        return strictUtf8(Uint8Array.from(atob(t), (c) => c.charCodeAt(0)));
      },
    },
    url: { e: encodeURIComponent, d: (s) => { try { return decodeURIComponent(s.replace(/\+/g, " ")); } catch { throw new Error("Malformed percent-encoding"); } } },
    hex: {
      e: (s) => toHex(enc.encode(s)),
      d: (s) => {
        const h = s.trim().replace(/0x|\\x|[\s:,-]/gi, "");
        if (!/^[0-9a-f]*$/i.test(h)) throw new Error("Contains non-hex characters");
        if (h.length % 2) throw new Error("Odd number of hex digits");
        return strictUtf8(new Uint8Array((h.match(/../g) || []).map((x) => parseInt(x, 16))));
      },
    },
    bin: {
      e: (s) => [...enc.encode(s)].map((b) => b.toString(2).padStart(8, "0")).join(" "),
      d: (s) => {
        const bits = s.replace(/\s+/g, "");
        if (!/^[01]*$/.test(bits) || bits.length % 8) throw new Error("Binary must be 0/1 in groups of 8");
        return strictUtf8(new Uint8Array((bits.match(/.{8}/g) || []).map((b) => parseInt(b, 2))));
      },
    },
    rot13: { e: (s) => s.replace(/[a-z]/gi, (c) => { const b = c <= "Z" ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b); }) },
    html: {
      e: (s) => s.replace(/[&<>"'`=\/]/g, (c) => `&#${c.charCodeAt(0)};`),
      d: (s) => s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos|nbsp);/gi, (m, e) => {
        const named = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " }[e.toLowerCase()];
        if (named) return named;
        const cp = e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
      }),
    },
  };
  codecs.rot13.d = codecs.rot13.e;

  /* ================= Passwords ================= */
  // Unbiased random password (rejection sampling avoids modulo bias)
  function generatePassword(length = 20) {
    const sets = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!@#$%^&*-_=+?"];
    const all = sets.join("");
    const pick = (chars) => {
      const limit = Math.floor(0x100000000 / chars.length) * chars.length;
      const buf = new Uint32Array(1);
      do crypto.getRandomValues(buf); while (buf[0] >= limit);
      return chars[buf[0] % chars.length];
    };
    let pw;
    do { pw = Array.from({ length }, () => pick(all)).join(""); } while (!sets.every((s) => [...pw].some((c) => s.includes(c))));
    return pw;
  }
  // SHA-1 for the HIBP k-anonymity range API
  async function hibpParts(password) {
    const h = toHex(await crypto.subtle.digest("SHA-1", enc.encode(password))).toUpperCase();
    return { prefix: h.slice(0, 5), suffix: h.slice(5) };
  }
  function hibpCount(rangeText, suffix) {
    for (const line of rangeText.split(/\r?\n/)) {
      const [suf, count] = line.trim().split(":");
      if (suf === suffix) return parseInt(count, 10) || 0;
    }
    return 0;
  }

  const API = { registeredDomain, editDistance, matchBrand, analyzeUrl, md5, hashAll, identifyHash, inspectJwt, duration, codecs, generatePassword, hibpParts, hibpCount, toHex, BRANDS };
  if (typeof module !== "undefined" && module.exports) module.exports = API;
  else root.SK = API;
})(typeof globalThis !== "undefined" ? globalThis : this);
