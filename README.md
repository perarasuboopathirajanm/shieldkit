# ⛨ ShieldKit: Browser Security Toolkit

**Defensive security tools that run entirely in your browser.** No account, no server, no tracking.

**[▶ Live demo](https://perarasuboopathirajanm.github.io/shieldkit/)** · ✅ 95 automated tests · 🔒 strict Content-Security-Policy

## Tools

| Tool | What it does | How it stays accurate |
|---|---|---|
| 🔑 **Password strength** | Strength grade, offline crack time (fast hash vs bcrypt-like), detected weaknesses, secure generator | Uses **[zxcvbn](https://github.com/dropbox/zxcvbn)** pattern matching (dictionaries, names, l33t-speak, keyboard walks, dates, repeats). Grades are based on **offline** attack cost, so `Tr0ub4dor&3` is *Fair*, not "strong" |
| 🛡️ **Breach check** | Has this password appeared in a data breach? | [HIBP Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords) **k-anonymity**: only the first 5 hex chars of the SHA-1 are sent, with response padding |
| 🎣 **Phishing URL analyzer** | Risk score 0–100 with explained red flags | Finds the **real owner** (public suffixes like `co.uk`, free-hosting platforms like `*.github.io`). Detects brand impersonation and known IP-logger links (Grabify, IPLogger…), temporary tunnel links used by Telegram phishing bots (ngrok, Cloudflare tunnels, serveo, loca.lt…), exact, homoglyph `paypa1`/`rn→m`, one-letter typosquats `gooogle`) across 30+ brands with full official-domain allowlists (e.g. `microsoftonline.com` is Microsoft). Also flags `user@host` tricks, punycode, IPs, shorteners, risky TLDs and executable downloads |
| #️⃣ **Hash generator** | MD5, SHA-1, SHA-256/384/512 | Web Crypto API; MD5 verified against RFC 1321 vectors |
| 🔍 **Hash identifier** | bcrypt, Argon2, yescrypt, scrypt, shadow `$1$/$5$/$6$`, PBKDF2, LDAP, MySQL, raw hex and Base64 digests | Shows confidence and warns that same-length hashes (MD5/NTLM) can't be told apart by format |
| 🪪 **JWT inspector** | Decodes header and payload, human-readable times | Flags `alg:none`, expiry problems, missing `exp`, long lifetimes, `jku`/`x5u`/`jwk` key-injection headers, suspicious `kid`, sensitive claims, and JWE tokens |
| 🔁 **Encoder / decoder** | Base64/Base64URL, URL, Hex, Binary, ROT13, HTML entities | UTF-8 safe, strict validation (no silent garbage), handles large input |

## Security design

- **Strict CSP** (`default-src 'none'`): no inline scripts or styles; network access only to the HIBP range API.
- **Subresource Integrity** on the only third-party script (zxcvbn from cdnjs), loaded lazily when you use the password tool.
- **No third-party fonts or analytics**, and `referrer` is set to `no-referrer`.
- **All untrusted input is escaped** before rendering (tested with XSS payloads).
- The password generator uses `crypto.getRandomValues` with **rejection sampling**, so there's no modulo bias.
- The phishing analyzer is **static only**: it never opens the link.

## Project structure

```
index.html    UI markup + CSP
style.css     styling
lib.js        all analysis logic (pure functions, no DOM)
app.js        UI wiring
tests/run.js  95 tests: phishing (legit vs malicious), RFC vectors, JWT, codecs, generator
```

## Run & test

```bash
git clone https://github.com/perarasuboopathirajanm/shieldkit.git
cd shieldkit
node tests/run.js        # run the test suite (Node 18+, no dependencies)
npx serve .              # open http://localhost:3000
```

## Limitations

The phishing score is heuristic and the brand list is finite, so a clean result isn't proof a site is safe. JWT signatures aren't verified, because that needs the server's key.

## License

MIT © 2026 Perarasu Boopathirajan
