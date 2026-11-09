// ShieldKit UI. All analysis logic lives in lib.js (window.SK) and is covered by tests/run.js.
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function toast(msg = "Copied") {
    $("toast").textContent = msg;
    $("toast").classList.add("show");
    clearTimeout(toast.t);
    toast.t = setTimeout(() => $("toast").classList.remove("show"), 1200);
  }
  function copy(text) {
    if (!navigator.clipboard) return toast("Clipboard not available");
    navigator.clipboard.writeText(text).then(() => toast(), () => toast("Copy blocked by browser"));
  }

  // Hero typing effect (skipped for reduced-motion users)
  (() => {
    const el = $("typed");
    const cmds = ["./audit --password", "./analyze --url suspicious.link", "./hash --identify", "./jwt --inspect", "./codec --base64"];
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) { el.textContent = cmds[0]; return; }
    let i = 0, j = 0, del = false;
    (function tick() {
      const c = cmds[i];
      el.textContent = c.slice(0, j);
      if (!del && j < c.length) j++;
      else if (!del) { del = true; return setTimeout(tick, 1400); }
      else if (j > 0) j--;
      else { del = false; i = (i + 1) % cmds.length; }
      setTimeout(tick, del ? 30 : 70);
    })();
  })();

  // Tabs (with keyboard arrows)
  const tabs = [...document.querySelectorAll(".tab")];
  function selectTab(t) {
    tabs.forEach((x) => { x.classList.toggle("on", x === t); x.setAttribute("aria-selected", x === t); x.tabIndex = x === t ? 0 : -1; });
    document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("on", p.id === "p-" + t.dataset.t));
  }
  $("tabs").addEventListener("click", (e) => { const t = e.target.closest(".tab"); if (t) selectTab(t); });
  $("tabs").addEventListener("keydown", (e) => {
    const i = tabs.indexOf(document.activeElement);
    if (i < 0 || !["ArrowRight", "ArrowLeft"].includes(e.key)) return;
    const n = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    n.focus(); selectTab(n);
  });

  /* ---------------- 1. Password ---------------- */
  // zxcvbn (Dropbox) detects dictionary words, names, l33t-speak, keyboard patterns, dates and repeats.
  // Loaded lazily from cdnjs with Subresource Integrity, so a tampered file is refused by the browser.
  const ZXCVBN = { src: "https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/4.4.2/zxcvbn.js", integrity: "sha384-jhGcGHNZytnBnH1wbEM3KxJYyRDy9Q0QLKjE65xk+aMqXFCdvFuYIjzMWAAWBBtR" };
  let zxState = "idle";
  function loadZxcvbn() {
    if (zxState !== "idle") return;
    zxState = "loading";
    $("pwEngine").textContent = "loading pattern engine…";
    const s = document.createElement("script");
    s.src = ZXCVBN.src; s.integrity = ZXCVBN.integrity; s.crossOrigin = "anonymous"; s.referrerPolicy = "no-referrer";
    s.onload = () => { zxState = "ready"; renderPassword(); };
    s.onerror = () => { zxState = "failed"; renderPassword(); };
    document.head.appendChild(s);
  }
  const LEVELS = [["Very weak", "var(--bad)"], ["Weak", "var(--bad)"], ["Fair", "var(--warn)"], ["Strong", "var(--g2)"], ["Very strong", "var(--g)"]];

  // Fallback if zxcvbn can't load: character-pool estimate, clearly labelled as rough
  function roughScore(pw) {
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26; if (/[A-Z]/.test(pw)) pool += 26; if (/\d/.test(pw)) pool += 10; if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
    return { log10: pw.length * Math.log10(Math.max(pool, 1)) };
  }
  // Grade against an OFFLINE attack on a leaked fast hash (10^10 guesses/s), the realistic worst case.
  // ~10^14 guesses ≈ 3 hours at that speed; 10^16 ≈ 2 weeks.
  const gradeFromGuesses = (log10) => (log10 < 8 ? 0 : log10 < 10 ? 1 : log10 < 12 ? 2 : log10 < 15 ? 3 : 4);
  function crackTime(log10guesses, perSec) {
    const s = Math.pow(10, log10guesses - Math.log10(perSec)) / 2; // on average, half the space is searched
    if (s < 1) return "instantly";
    if (s > 31557600 * 1000) return "1000+ years";
    return SK.duration(s);
  }
  function renderPassword() {
    const pw = $("pw").value.slice(0, 128);
    $("pwBreach").textContent = "—"; $("pwBreach").className = "";
    const fb = $("pwFeedback");
    if (!pw) {
      ["pwLabel", "pwFast", "pwSlow"].forEach((id) => ($(id).textContent = "—"));
      $("pwBar").style.width = "0"; fb.innerHTML = ""; $("pwEngine").textContent = ""; return;
    }
    let score, log10, warning = "", suggestions = [], patterns = [];
    if (zxState === "ready") {
      const r = window.zxcvbn(pw);
      log10 = r.guesses_log10; score = Math.min(gradeFromGuesses(log10), r.score === 4 ? 4 : r.score + 1);
      warning = r.feedback.warning; suggestions = r.feedback.suggestions;
      patterns = r.sequence.filter((m) => m.pattern !== "bruteforce").map((m) => `${m.pattern}${m.dictionary_name ? ` (${m.dictionary_name.replace(/_/g, " ")})` : ""}: "${m.token}"`);
      $("pwEngine").textContent = "engine: zxcvbn pattern matching";
    } else {
      // Without pattern matching we can't see dictionary words or substitutions, so never rate above "Fair"
      ({ log10 } = roughScore(pw)); score = Math.min(gradeFromGuesses(log10), 2);
      if (zxState === "failed") warning = "Pattern engine didn't load, so dictionary words and substitutions can't be detected. Rating is capped at Fair.";
      $("pwEngine").textContent = zxState === "failed" ? "⚠ pattern engine unavailable: showing a rough character-set estimate" : "loading pattern engine…";
    }
    const [label, color] = LEVELS[score];
    $("pwLabel").textContent = label; $("pwLabel").style.color = color;
    const known = zxState === "ready";
    $("pwFast").textContent = known ? crackTime(log10, 1e10) : "—";
    $("pwSlow").textContent = known ? crackTime(log10, 1e4) : "—";
    $("pwBar").style.width = (score + 1) * 20 + "%"; $("pwBar").style.background = color;
    $("pwBar").parentElement.setAttribute("aria-valuenow", score);
    const items = [];
    if (warning) items.push(`<li class="bad">${esc(warning)}</li>`);
    patterns.slice(0, 4).forEach((p) => items.push(`<li class="warn">Found ${esc(p)}</li>`));
    suggestions.forEach((s) => items.push(`<li class="info">${esc(s)}</li>`));
    if (zxState === "ready" && score <= 2 && !warning && !suggestions.length) items.push('<li class="info">Too short or simple to resist an offline attack. Use 4+ random words or 16+ random characters.</li>');
    if (zxState === "ready" && score >= 3 && !warning && !patterns.length) items.push('<li class="ok">No common patterns found.</li>');
    fb.innerHTML = items.join("");
  }
  $("pw").addEventListener("focus", loadZxcvbn);
  $("pw").addEventListener("input", () => { loadZxcvbn(); renderPassword(); });
  $("pwShow").onclick = () => {
    const show = $("pw").type === "password";
    $("pw").type = show ? "text" : "password";
    $("pwShow").textContent = show ? "Hide" : "Show";
    $("pwShow").setAttribute("aria-pressed", show);
  };
  $("pwGen").onclick = () => {
    const pw = SK.generatePassword(20);
    $("pw").value = pw; $("pw").type = "text"; $("pwShow").textContent = "Hide";
    loadZxcvbn(); renderPassword(); copy(pw); toast("Generated & copied");
  };
  $("pwBreachBtn").onclick = async () => {
    const pw = $("pw").value;
    if (!pw) return toast("Type a password first");
    const btn = $("pwBreachBtn");
    btn.disabled = true; $("pwBreach").textContent = "checking…"; $("pwBreach").className = "";
    try {
      const { prefix, suffix } = await SK.hibpParts(pw);
      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { "Add-Padding": "true" }, referrerPolicy: "no-referrer", cache: "no-store" });
      if (!res.ok) throw new Error(res.status);
      const count = SK.hibpCount(await res.text(), suffix);
      $("pwBreach").textContent = count ? `Yes, seen ${count.toLocaleString()}×` : "Not found";
      $("pwBreach").className = count ? "bad-t" : "ok-t";
    } catch {
      $("pwBreach").textContent = "Check failed (offline?)"; $("pwBreach").className = "warn-t";
    } finally { btn.disabled = false; }
  };

  /* ---------------- 2. Phishing ---------------- */
  function renderUrl() {
    const raw = $("url").value;
    if (!raw.trim()) return ($("urlOut").innerHTML = "");
    const r = SK.analyzeUrl(raw);
    if (r.error) return ($("urlOut").innerHTML = `<div class="alert warn">${esc(r.error)}</div>`);
    const [label, cls] = { high: ["HIGH RISK: likely phishing", "bad-t"], suspicious: ["SUSPICIOUS: be careful", "warn-t"], low: ["LOW RISK", "ok-t"] }[r.verdict];
    const order = { bad: 0, warn: 1, info: 2, ok: 3 };
    const flags = [...r.flags].sort((a, b) => order[a.lvl] - order[b.lvl]);
    $("urlOut").innerHTML = `
      <div class="verdict" role="status">
        <div class="verdict-top">
          <div class="score ${cls}">${r.risk}<small>/100</small></div>
          <div><h3 class="${cls}">${label}</h3><div class="host">Actual owner: <b>${esc(r.reg || r.host)}</b></div></div>
        </div>
        <ul class="flags">${flags.map((f) => `<li class="${f.lvl}">${esc(f.msg)}<small>${esc(f.why)}</small></li>`).join("")}</ul>
      </div>`;
  }
  $("urlGo").onclick = renderUrl;
  $("url").addEventListener("keydown", (e) => e.key === "Enter" && renderUrl());
  document.querySelectorAll("[data-u]").forEach((b) => (b.onclick = () => { $("url").value = b.dataset.u; renderUrl(); }));

  /* ---------------- 3. Hash ---------------- */
  let hashSeq = 0;
  async function renderHashes() {
    const text = $("hashIn").value, seq = ++hashSeq;
    if (!text) return ($("hashOut").innerHTML = "");
    const rows = await SK.hashAll(text);
    if (seq !== hashSeq) return; // a newer keystroke already started; drop stale result
    $("hashOut").innerHTML = rows.map(([k, v, note]) =>
      `<button type="button" class="item" data-copy="${esc(v)}"><span class="k">${esc(k)}${note ? ` <em>· ${esc(note)}</em>` : ""}</span><span class="v">${esc(v)}</span></button>`).join("") +
      '<p class="note">Click a hash to copy. For storing passwords use a slow, salted hash: Argon2id, bcrypt or scrypt.</p>';
  }
  $("hashIn").addEventListener("input", renderHashes);
  $("hashId").addEventListener("input", () => {
    const r = SK.identifyHash($("hashId").value);
    const lbl = { high: "Match", likely: "Most likely", possible: "Also possible", none: "Result" };
    $("hashIdOut").innerHTML = r.map((x) => `<div class="item static"><span class="k">${lbl[x.confidence]}</span><span class="v">${esc(x.name)}${x.note ? ` <em>· ${esc(x.note)}</em>` : ""}</span></div>`).join("") +
      (r.length > 1 ? '<p class="note">Hashes of the same length can\'t be told apart by format alone (e.g. MD5 and NTLM).</p>' : "");
  });
  document.addEventListener("click", (e) => { const it = e.target.closest("[data-copy]"); if (it) copy(it.dataset.copy); });

  /* ---------------- 4. JWT ---------------- */
  function renderJwt() {
    const r = SK.inspectJwt($("jwtIn").value);
    $("jwtHead").textContent = $("jwtBody").textContent = "—";
    if (!r) return ($("jwtWarn").innerHTML = "");
    if (r.error) return ($("jwtWarn").innerHTML = `<div class="alert bad">${esc(r.error)}</div>`);
    $("jwtHead").textContent = JSON.stringify(r.header, null, 2);
    const fmt = (k, v) => (["exp", "iat", "nbf", "auth_time"].includes(k) && typeof v === "number" ? `${v}  // ${new Date(v * 1000).toISOString()}` : JSON.stringify(v));
    $("jwtBody").textContent = "{\n" + Object.entries(r.payload).map(([k, v]) => `  ${JSON.stringify(k)}: ${fmt(k, v)}`).join(",\n") + "\n}";
    $("jwtWarn").innerHTML = r.findings.map(([c, m]) => `<div class="alert ${c}">${esc(m)}</div>`).join("");
  }
  $("jwtIn").addEventListener("input", renderJwt);
  $("jwtSample").onclick = () => {
    const now = Math.floor(Date.now() / 1000);
    const b64u = (o) => btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    $("jwtIn").value = `${b64u({ alg: "HS256", typ: "JWT" })}.${b64u({ sub: "1024", name: "Demo User", role: "admin", iat: now - 7200, exp: now - 3600 })}.c2lnbmF0dXJlLW5vdC12ZXJpZmllZA`;
    renderJwt();
  };

  /* ---------------- 5. Encode ---------------- */
  function runCodec(dir) {
    $("encErr").textContent = "";
    try { $("encOut").value = SK.codecs[$("encMode").value][dir]($("encIn").value); }
    catch (err) { $("encOut").value = ""; $("encErr").textContent = "✗ " + err.message; }
  }
  $("encDo").onclick = () => runCodec("e");
  $("decDo").onclick = () => runCodec("d");
  $("encSwap").onclick = () => { [$("encIn").value, $("encOut").value] = [$("encOut").value, $("encIn").value]; };
  $("encCopy").onclick = () => $("encOut").value && copy($("encOut").value);
})();
