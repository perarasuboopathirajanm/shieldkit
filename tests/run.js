// Run with: node tests/run.js   (Node 18+, no dependencies)
const SK = require("../lib.js");
let pass = 0, fail = 0;
const ok = (cond, name, extra = "") => { if (cond) pass++; else { fail++; console.log("  ✗", name, extra); } };
const section = (s) => console.log("\n▸ " + s);

(async () => {
  section("Phishing analyzer: legitimate links must score LOW (< 20)");
  const legit = [
    "https://github.com/login", "https://accounts.google.com/signin", "https://login.microsoftonline.com/common/oauth2",
    "https://outlook.office.com/mail", "https://www.amazon.in/gp/cart", "https://www.paypal.com/signin",
    "https://raw.githubusercontent.com/user/repo/main/README.md", "https://pineapple.com", "https://www.onlinesbi.sbi/",
    "https://netbanking.hdfcbank.com/netbanking/", "https://example.com/contact?email=me@example.com",
    "https://en.wikipedia.org/wiki/Phishing", "https://www.bbc.co.uk/news", "github.com", "https://www.icloud.com",
  ];
  for (const u of legit) { const r = SK.analyzeUrl(u); ok(r.risk < 20, u, `→ ${r.risk} ${r.flags.map((f) => f.msg).join(" | ")}`); }

  section("Phishing analyzer: malicious links must score HIGH (≥ 50)");
  const bad = [
    "http://paypa1-account-verify.secure-login.xyz/update", "https://g00gle-security.top/login", "https://micros0ft-support.com/verify",
    "https://paypal.com.account-secure.xyz/signin", "https://gooogle.com/accounts/login", "https://paypai.com/signin",
    "http://192.168.4.20/bank/login.php", "https://user@evil-site.com/paypal", "https://xn--pple-43d.com/login",
    "https://amazon-gift-reward.com/claim", "https://perarasu-paypal-login.github.io/", "https://netfIix-billing.com/update",
    "https://secure.hdfc-kyc-update.in/verify", "javascript:alert(document.cookie)", "https://faceb00k.com/login",
  ];
  for (const u of bad) { const r = SK.analyzeUrl(u); ok(r.risk >= 50, u, `→ ${r.risk} ${r.flags.map((f) => f.msg).join(" | ")}`); }

  section("Phishing analyzer: suspicious-but-not-certain → SUSPICIOUS (20–49)");
  for (const u of ["https://bit.ly/3xYz9Ab", "https://evil-example.com/paypal/login", "https://docs-share.vercel.app/login"]) {
    const r = SK.analyzeUrl(u); ok(r.risk >= 20 && r.risk < 50, u, `→ ${r.risk} ${r.flags.map((f) => f.msg).join(" | ")}`);
  }

  section("Phishing analyzer: specific detections");
  ok(SK.analyzeUrl("https://a.com/?e=x@y.com").flags.every((f) => !f.msg.includes("@")), "email in query is not flagged as '@' trick");
  ok(SK.analyzeUrl("https://x.github.io").reg === "x.github.io", "github.io subdomain is its own owner");
  ok(SK.analyzeUrl("https://random-blog.vercel.app/").flags.some((f) => f.msg.includes("Free hosting")), "free hosting noted (but not alone suspicious)");
  ok(SK.analyzeUrl("https://shop.example.co.uk").reg === "example.co.uk", "co.uk handled as public suffix");
  ok(SK.analyzeUrl("https://evil.com/setup.exe").flags.some((f) => f.msg.includes("download")), "executable download flagged");
  ok(SK.matchBrand("pineapple") === null, "'pineapple' is not an Apple impersonation");
  ok(SK.matchBrand("googel")?.how === "typo", "'googel' detected as typo of google");
  ok(SK.matchBrand("rnicrosoft")?.how === "homoglyph", "'rnicrosoft' detected as homoglyph");

  section("MD5: RFC 1321 test vectors");
  const md5v = { "": "d41d8cd98f00b204e9800998ecf8427e", a: "0cc175b9c0f1b6a831c399e269772661", abc: "900150983cd24fb0d6963f7d28e17f72",
    "message digest": "f96b697d7cb7938d525a2f31aaf161d0", "abcdefghijklmnopqrstuvwxyz": "c3fcd3d76192e4007dfb496cca67e13b",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890": "57edf4a22be3c955ac49da2e2107b67a" };
  for (const [k, v] of Object.entries(md5v)) ok(SK.md5(new TextEncoder().encode(k)) === v, `md5("${k.slice(0, 20)}")`);

  section("SHA via Web Crypto");
  const h = Object.fromEntries((await SK.hashAll("abc")).map(([k, v]) => [k, v]));
  ok(h["SHA-1"] === "a9993e364706816aba3e25717850c26c9cd0d89d", "sha1(abc)");
  ok(h["SHA-256"] === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256(abc)");

  section("Hash identifier");
  const id = (x) => SK.identifyHash(x)[0].name;
  ok(id("5f4dcc3b5aa765d61d8327deb882cf99") === "MD5", "MD5 hex");
  ok(id("$2b$12$KIXQJ2Q1nY7V9bWfK6kZ8uQe0m3J9Hk1Zr5aWb3cD9eF7gH1iJ2kO") === "bcrypt", "bcrypt");
  ok(id("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA") === "Argon2", "argon2id");
  ok(id("$y$j9T$abc$def") === "yescrypt", "yescrypt");
  ok(id("X03MO1qnZdYdgyfeuILPmQ==") === "Base64-encoded MD5", "base64 md5");
  ok(id("hello world!") === "Not recognized", "garbage");
  ok(id("abc123") === "Unknown hex string", "short hex");

  section("JWT inspector");
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const now = 1_700_000_000;
  const j1 = SK.inspectJwt(`${b64u({ alg: "none" })}.${b64u({ sub: 1 })}.`, now);
  ok(j1.findings.some(([l, m]) => l === "bad" && m.includes("none")), "alg none flagged");
  ok(j1.findings.some(([, m]) => m.includes("never expires")), "missing exp flagged");
  const j2 = SK.inspectJwt(`Bearer ${b64u({ alg: "HS256" })}.${b64u({ exp: now - 60, password: "x" })}.sig`, now);
  ok(j2.findings.some(([l, m]) => l === "bad" && m.startsWith("Expired 1 minute")), "expired + Bearer prefix");
  ok(j2.findings.some(([, m]) => m.includes("password")), "sensitive field flagged");
  const j3 = SK.inspectJwt(`${b64u({ alg: "RS256", jku: "https://evil/keys" })}.${b64u({ exp: now + 3600, shipping: 1, pinned: 1 })}.sig`, now);
  ok(j3.findings.some(([, m]) => m.includes("jku")), "jku flagged");
  ok(!j3.findings.some(([, m]) => m.includes("Sensitive")), "'shipping'/'pinned' not false-positive sensitive");
  ok(SK.inspectJwt("a.b.c.d.e").error.includes("JWE"), "JWE detected");
  ok(SK.inspectJwt("x.y.z").error, "invalid JWT errors cleanly");

  section("Encoders: round-trips incl. Unicode");
  const sample = "Hëllo <வணக்கம்> 😀 & \"q\" 'a' /x";
  for (const m of Object.keys(SK.codecs)) ok(SK.codecs[m].d(SK.codecs[m].e(sample)) === sample, `${m} round-trip`);
  ok(SK.codecs.b64.d("SGVsbG8_") === "Hello?", "base64url accepted");
  ok(SK.codecs.hex.d("0x48 0x69") === "Hi", "hex with 0x prefixes");
  ok(SK.codecs.html.d("&lt;b&gt; &#x1F600; &amp;amp;") === "<b> 😀 &amp;", "html decode (no double-decoding)");
  ok(SK.codecs.b64.e("x".repeat(500000)).length > 0, "large input does not overflow the stack");
  let threw = false; try { SK.codecs.b64.d("/w=="); } catch { threw = true; } ok(threw, "invalid UTF-8 reported instead of garbage");
  ok(SK.codecs.rot13.e("Hello, World!") === "Uryyb, Jbeyq!", "rot13");

  section("Password generator & HIBP helpers");
  const pws = Array.from({ length: 200 }, () => SK.generatePassword(20));
  ok(pws.every((p) => p.length === 20 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p)), "always 20 chars with all 4 classes");
  ok(new Set(pws).size === 200, "no duplicates in 200 generations");
  const { prefix, suffix } = await SK.hibpParts("password");
  ok(prefix === "5BAA6" && suffix === "1E4C9B93F3F0682250B6CF8331B7EE68FD8", "SHA-1 k-anonymity split");
  ok(SK.hibpCount("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n", suffix) === 9545824, "range response parsed (CRLF)");

  console.log(`\n${fail ? "❌" : "✅"} ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
