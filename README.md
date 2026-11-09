# ⛨ ShieldKit: Browser Security Toolkit

A set of **defensive security tools** with a hacker-terminal look, running **100% in your browser**. No server, no tracking, no data leaves your device.

**[▶ Live demo](https://perarasuboopathirajanm.github.io/shieldkit/)**

## Tools

| Tool | What it does |
|---|---|
| 🔑 **Password Auditor** | Entropy, strength meter, estimated offline crack time, 8-point checklist, and a secure random password generator |
| 🛡️ **Breach Check** | Checks a password against 900M+ leaked passwords via [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) using **k-anonymity**: only the first 5 chars of the SHA-1 hash are sent |
| 🎣 **Phishing URL Analyzer** | Risk score 0–100 with explained red flags: look-alike brands (`paypa1`), brand-in-subdomain tricks, raw IPs, `@` tricks, punycode homographs, shorteners, high-abuse TLDs, bait words |
| #️⃣ **Hash Generator** | MD5, SHA-1, SHA-256, SHA-384, SHA-512 (Web Crypto API, plus an RFC 1321 MD5 implementation) |
| 🔍 **Hash Identifier** | Recognises MD5/NTLM, SHA family, bcrypt, Argon2, scrypt, Linux shadow (`$1$ $5$ $6$`), MySQL, PBKDF2 and more |
| 🪪 **JWT Inspector** | Decodes header and payload, converts timestamps, and flags `alg: none`, expired tokens, missing `exp`, weak HS secrets and sensitive data in payloads |
| 🔁 **Encoder / Decoder** | Base64 (UTF-8 safe), URL, Hex, Binary, ROT13, HTML entities |

## Run locally

```bash
git clone https://github.com/perarasuboopathirajanm/shieldkit.git
cd shieldkit
npx serve .   # or just open index.html
```

## Security & privacy design

- Everything runs client-side with the **Web Crypto API**.
- The breach check uses the **k-anonymity** range API, so your password and its full hash never leave the browser.
- The phishing analyzer is **static analysis only** and never opens the URL.
- Untrusted input is HTML-escaped before rendering (no XSS from analyzed URLs or tokens).

## Tech

`HTML` · `CSS` · `Vanilla JavaScript` · `Web Crypto API` · `HIBP Pwned Passwords API`

## Roadmap

- [ ] Security headers checker (with a small serverless proxy)
- [ ] Email header analyzer (SPF / DKIM / DMARC)
- [ ] TOTP (2FA) code generator & QR
- [ ] Offline PWA mode

## Disclaimer

Built for **learning and defensive use**. The phishing score is heuristic, so always verify links through official channels.

## License

MIT © 2026 Perarasu Boopathirajan
