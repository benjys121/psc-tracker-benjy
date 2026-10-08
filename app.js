const view = document.getElementById("view");
const PW_KEY = "psc-tracker-pw";
const SEEN_KEY = "psc-tracker-seen";
const PENDING_KEY = "psc-tracker-pending";
const MARKER = "requested from the dashboard"; // the Slack bot looks for this (psc/slackbot.py)
let DATA = null; // decrypted bundle: { cases: [...], briefings: [...], webhook }
let BUILT_AT = null;
let PASSWORD = null;

/* ---------- helpers ---------- */

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const parseDay = (iso) => (iso ? new Date(iso.slice(0, 10) + "T12:00:00") : null);
const shortDate = (iso) => {
  const d = parseDay(iso);
  if (!d) return "—";
  const sameYear = d.getFullYear() === new Date().getFullYear();
  return `${MONTHS[d.getMonth()]} ${d.getDate()}${sameYear ? "" : ` ’${String(d.getFullYear()).slice(2)}`}`;
};
const longDate = (iso) =>
  parseDay(iso)?.toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric", year: "numeric" }) ?? "";
const relDay = (iso) => {
  const d = parseDay(iso);
  if (!d) return "";
  const today = new Date();
  today.setHours(12, 0, 0, 0);
  const days = Math.round((today - d) / 864e5);
  return days === 0 ? "Today" : days === 1 ? "Yesterday" : days < 7 ? `${days} days ago` : "";
};

// Browser storage can be missing or blocked (private windows); everything still works without it.
const storage = {
  get(key, fallback) {
    try {
      const v = localStorage.getItem(key);
      return v == null ? fallback : JSON.parse(v);
    } catch {
      return fallback;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {}
  },
  remove(key) {
    try {
      localStorage.removeItem(key);
    } catch {}
  },
};

function setNav(which) {
  document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("on", a.dataset.nav === which));
}

/* ---------- unlocking ---------- */

const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function decrypt(blob, password) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64(blob.salt), iterations: blob.iter, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  const gz = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(blob.iv) }, key, b64(blob.ct)); // throws on a wrong password
  const text = await new Response(new Blob([gz]).stream().pipeThrough(new DecompressionStream("gzip"))).text();
  return JSON.parse(text);
}

async function fetchBlob() {
  const res = await fetch(`data.enc.json?t=${Date.now()}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Couldn't load the data (${res.status})`);
  return res.json();
}

function showLock(message = "") {
  document.body.classList.add("locked");
  view.innerHTML = `
    <form class="track lock" id="lock">
      <label for="pw">Password</label>
      <div class="track-row">
        <input id="pw" type="password" autocomplete="current-password" required autofocus>
        <button class="btn" type="submit">Unlock</button>
      </div>
      <label class="remember"><input type="checkbox" id="remember" checked> Remember me on this device</label>
      <div class="problems" id="problems">${esc(message)}</div>
    </form>`;
  document.getElementById("lock").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector("button");
    const pw = document.getElementById("pw").value;
    const remember = document.getElementById("remember").checked; // the form is gone once unlocked
    btn.disabled = true;
    btn.textContent = "Unlocking…";
    try {
      await unlock(pw);
      if (remember) storage.set(PW_KEY, pw);
    } catch (err) {
      showLock(err.name === "OperationError" ? "That password didn't work." : err.message);
    }
  });
}

async function unlock(pw) {
  const blob = await fetchBlob();
  DATA = await decrypt(blob, pw);
  PASSWORD = pw;
  BUILT_AT = blob.built_at;
  document.body.classList.remove("locked");
  document.getElementById("updated").textContent = BUILT_AT
    ? `Updated ${shortDate(BUILT_AT)}, ${new Date(BUILT_AT).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" })}`
    : "";
  route();
}

/* ---------- "new since your last visit" (per browser) ---------- */

const seenMap = () => storage.get(SEEN_KEY, {});
function lastSeen(c) {
  const seen = seenMap()[c.case];
  if (seen != null) return seen;
  // Never opened on this device: treat the last two days of filings as new.
  const cutoff = new Date(Date.now() - 2 * 864e5).toISOString().slice(0, 10);
  const older = c.filings.filter((f) => (f.date || "") < cutoff);
  return older.length ? Math.max(...older.map((f) => f.filing_seq)) : 0;
}
function markSeen(c) {
  const map = seenMap();
  map[c.case] = Math.max(0, ...c.filings.map((f) => f.filing_seq));
  storage.set(SEEN_KEY, map);
}

/* ---------- track / untrack (sent through Slack; the bot on the Mac applies them) ---------- */

function normalizeCase(raw) {
  const s = (raw || "").replace(/\s+/g, "").toUpperCase();
  let m = s.match(/^(\d{2})-([A-Z]{1,2})-(\d{1,4})$/);
  if (m) return `${m[1]}-${m[2]}-${m[3].padStart(4, "0")}`;
  m = s.match(/^(\d{2})-(\d{1,5})$/);
  return m ? `${m[1]}-${m[2].padStart(5, "0")}` : null;
}

const isTracked = (caseNo) => DATA.cases.some((c) => c.case === caseNo);
const caseObj = (caseNo) => DATA.cases.find((c) => c.case === caseNo);
const lc = (s) => (s || "").toLowerCase();
const cleanCategory = (s) => (s || "").replace(/^[\s"'`#.,;:—–-]+|[\s"'`#.,;:—–-]+$/g, "").replace(/\s+/g, " ").slice(0, 40);

// Requests sent to Slack but not yet reflected in the published data. Stars and categories are
// shown optimistically from these; each is dropped once the data matches (or after an hour).
const opKey = (p) =>
  p.action.endsWith("search") ? `search:${lc(p.name)}` :
  p.action.endsWith("track") ? `track:${p.case}` :
  p.action.endsWith("star") ? `star:${p.case}` :
  p.action.endsWith("tag") ? `tag:${p.case}:${lc(p.name)}` : `cat:${lc(p.name)}`;

function resolved(p) {
  const c = p.case && caseObj(p.case);
  switch (p.action) {
    case "track": return !!c;
    case "untrack": return !c;
    case "star": return !c || c.starred;
    case "unstar": return !c || !c.starred;
    case "tag": return !c || (c.categories || []).some((x) => lc(x) === lc(p.name));
    case "untag": return !c || !(c.categories || []).some((x) => lc(x) === lc(p.name));
    case "search": return findSearch(p.name) != null;
    case "unsearch": return findSearch(p.name) == null;
    case "newcat": return (DATA.categories || []).some((x) => lc(x) === lc(p.name));
    case "delcat": return !(DATA.categories || []).some((x) => lc(x) === lc(p.name));
  }
  return true;
}

function pending() {
  const now = Date.now();
  const list = storage.get(PENDING_KEY, []).filter((p) => p.action && now - p.at < 36e5 && !resolved(p));
  storage.set(PENDING_KEY, list);
  return list;
}
// A saved search by "#4172" or by the words it was saved under / the organization's name.
const findSearch = (q) =>
  (DATA.searches || []).find((x) => `#${x.seq}` === q || lc(x.query) === lc(q) || lc(x.name) === lc(q));
const pendingFor = (caseNo) => pending().find((p) => p.case === caseNo && p.action.endsWith("track"));

// Effective (optimistic) state
function isStarred(c) {
  const p = pending().find((p) => p.case === c.case && p.action.endsWith("star"));
  return p ? p.action === "star" : !!c.starred;
}
function categoriesOf(c) {
  const deleted = pending().filter((p) => p.action === "delcat").map((p) => lc(p.name));
  let cats = (c.categories || []).filter((x) => !deleted.includes(lc(x)));
  for (const p of pending().filter((p) => p.case === c.case)) {
    if (p.action === "tag" && !cats.some((x) => lc(x) === lc(p.name))) cats = [...cats, p.name];
    if (p.action === "untag") cats = cats.filter((x) => lc(x) !== lc(p.name));
  }
  return cats;
}
function allCategories() {
  const seen = new Map();
  const add = (n) => n && !seen.has(lc(n)) && seen.set(lc(n), n);
  (DATA.categories || []).forEach(add);
  pending().filter((p) => p.action === "newcat" || p.action === "tag").forEach((p) => add(p.name));
  pending().filter((p) => p.action === "delcat").forEach((p) => seen.delete(lc(p.name)));
  return [...seen.values()].sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
}

const COMMAND_TEXT = { newcat: "category add", delcat: "category delete" };

async function sendCommand(action, cases = [], names = []) {
  if (!DATA.webhook) throw new Error("Changes from the dashboard aren't set up (no Slack webhook).");
  const text = [COMMAND_TEXT[action] || action, cases.join(", "), names.join(", ")].filter(Boolean).join(" ");
  // Slack's webhook sends no CORS headers, so post a form-encoded payload in no-cors mode.
  // The response is unreadable; the bot applies it (and replies in Slack only when needed).
  await fetch(DATA.webhook, {
    method: "POST",
    mode: "no-cors",
    // Posted as a reply in the bot's "Dashboard requests" thread, so it stays out of the channel.
    body: new URLSearchParams({
      payload: JSON.stringify({ text: `${text} — ${DATA.marker || MARKER}`, ...(DATA.thread_ts ? { thread_ts: DATA.thread_ts } : {}) }),
    }),
  });
  const ops = [];
  if (cases.length && names.length) cases.forEach((c) => names.forEach((n) => ops.push({ action, case: c, name: n })));
  else if (cases.length) cases.forEach((c) => ops.push({ action, case: c }));
  else names.forEach((n) => ops.push({ action, name: n }));
  const keys = new Set(ops.map(opKey));
  const list = storage.get(PENDING_KEY, []).filter((p) => p.action && !keys.has(opKey(p)));
  ops.forEach((o) => list.push({ ...o, at: Date.now() }));
  storage.set(PENDING_KEY, list);
  watchForUpdates();
}

async function act(action, cases, names) {
  try {
    await sendCommand(action, cases, names);
  } catch (err) {
    alert(err.message);
  }
  route(false);
}

// While requests are pending, re-download the published data and re-render when it changes.
let refreshTimer = null;
function watchForUpdates() {
  if (refreshTimer) return;
  refreshTimer = setInterval(async () => {
    if (!pending().length) {
      clearInterval(refreshTimer);
      refreshTimer = null;
      return;
    }
    try {
      const blob = await fetchBlob();
      if (blob.built_at === BUILT_AT) return;
      DATA = await decrypt(blob, PASSWORD);
      BUILT_AT = blob.built_at;
      route(false);
    } catch {}
  }, 30000);
}

async function onTrack(e) {
  e.preventDefault();
  const form = e.target;
  const problems = document.getElementById("problems");
  const tokens = form.cases.value.split(/[\s,]+/).filter(Boolean);
  const bad = tokens.filter((t) => !normalizeCase(t));
  const cases = [...new Set(tokens.map(normalizeCase).filter(Boolean))];
  const already = cases.filter(isTracked);
  const toAdd = cases.filter((c) => !isTracked(c));
  const notes = [
    ...bad.map((t) => `“${t}” doesn't look like a case number (try 25-E-0375).`),
    ...already.map((c) => `${c} is already tracked.`),
  ];
  if (!toAdd.length) {
    problems.innerHTML = notes.map(esc).join("<br>") || "Enter a case number.";
    return;
  }
  const btn = form.querySelector("button");
  btn.disabled = true;
  try {
    await sendCommand("track", toAdd);
    renderWatchlist();
    document.getElementById("problems").innerHTML = notes.map(esc).join("<br>");
  } catch (err) {
    problems.textContent = err.message;
    btn.disabled = false;
  }
}

/* ---------- stars and categories (shared by the watchlist and case pages) ---------- */

function starButton(c) {
  const on = isStarred(c);
  return `<button class="star${on ? " on" : ""}" data-act="${on ? "unstar" : "star"}" data-case="${esc(c.case)}"
    aria-pressed="${on}" title="${on ? "Unstar" : "Star"} ${esc(c.case)}">${on ? "★" : "☆"}</button>`;
}

function categoryPills(c) {
  return `<div class="pills">${categoriesOf(c)
    .map((n) => `<span class="pill">${esc(n)}<button data-act="untag" data-case="${esc(c.case)}" data-name="${esc(n)}" aria-label="Remove ${esc(n)} from ${esc(c.case)}">×</button></span>`)
    .join("")}<button class="pill add" data-act="addcat" data-case="${esc(c.case)}">+ Category</button></div>`;
}

function categoryInput(caseNo) {
  const id = `cat-${caseNo}`;
  return `<form class="catform" data-case="${esc(caseNo)}">
    <input name="name" list="${id}" placeholder="rate case, transmission…" autocomplete="off" aria-label="Category for ${esc(caseNo)}" required>
    <datalist id="${id}">${allCategories().map((n) => `<option value="${esc(n)}">`).join("")}</datalist>
    <button class="btn small" type="submit">Add</button>
    <button class="textbtn quiet" type="button" data-act="cancelcat">Cancel</button>
  </form>`;
}

// One delegated handler for star / category / filter clicks anywhere in the view.
view.addEventListener("click", (e) => {
  const el = e.target.closest("[data-act]");
  if (!el || !DATA) return;
  const { act: a, case: caseNo, name } = el.dataset;
  if (a === "star" || a === "unstar") act(a, [caseNo]);
  else if (a === "untag") act("untag", [caseNo], [name]);
  else if (a === "addcat") {
    el.closest(".pills").outerHTML = categoryInput(caseNo);
    view.querySelector(`.catform[data-case="${caseNo}"] input`).focus();
  } else if (a === "cancelcat") route(false);
  else if (a === "untrack") {
    if (confirm(`Stop tracking ${caseNo}?`)) act("untrack", [caseNo]);
  } else if (a === "filter") {
    setPrefs({ filter: el.dataset.filter });
    renderWatchlist();
  } else if (a === "newcat") {
    const n = cleanCategory(prompt("New category name (e.g. rate case, transmission):") || "");
    if (n) act("newcat", [], [n]);
  } else if (a === "delcat") {
    if (confirm(`Delete the category “${name}”? It's removed from every case, but the cases stay tracked.`)) {
      if (lc(getPrefs().filter) === lc(`cat:${name}`)) setPrefs({ filter: "all" });
      act("delcat", [], [name]);
    }
  } else if (a === "tracksearchcase") {
    act("track", [caseNo]);
  } else if (a === "searchother") {
    const existing = findSearch(`#${el.dataset.seq}`);
    if (existing) location.hash = `#/search/${existing.seq}`;
    else act("search", [], [`#${el.dataset.seq}`]);
  } else if (a === "unsearch") {
    if (confirm("Remove this saved search?")) act("unsearch", [], [`#${el.dataset.seq}`]);
  } else if (a === "editcats") {
    editingCategories = !editingCategories;
    renderWatchlist();
  }
});
view.addEventListener("submit", (e) => {
  const form = e.target.closest(".catform");
  if (!form) return;
  e.preventDefault();
  const names = form.name.value.split(",").map(cleanCategory).filter(Boolean);
  // Reuse an existing category's spelling when it only differs by case.
  const canon = (n) => allCategories().find((x) => lc(x) === lc(n)) || n;
  if (names.length) act("tag", [form.dataset.case], names.map(canon));
});

/* ---------- watchlist ---------- */

const PREFS_KEY = "psc-tracker-view";
const getPrefs = () => ({ sort: "starred", filter: "all", group: false, ...storage.get(PREFS_KEY, {}) });
let editingCategories = false; // per visit, not remembered
const setPrefs = (patch) => storage.set(PREFS_KEY, { ...getPrefs(), ...patch });

const newCountOf = (c) => {
  const seen = lastSeen(c);
  return c.filings.filter((f) => f.filing_seq > seen).length;
};
const latestOf = (c) => c.filings[0]?.date || "";
const SORTS = {
  starred: { label: "Starred first", cmp: (a, b) => isStarred(b) - isStarred(a) || latestOf(b).localeCompare(latestOf(a)) },
  latest: { label: "Latest filing", cmp: (a, b) => latestOf(b).localeCompare(latestOf(a)) },
  new: { label: "Most new filings", cmp: (a, b) => newCountOf(b) - newCountOf(a) || latestOf(b).localeCompare(latestOf(a)) },
  added: { label: "Recently added", cmp: (a, b) => (b.added_at || "").localeCompare(a.added_at || "") },
  case: { label: "Case number", cmp: (a, b) => a.case.localeCompare(b.case) },
};

function filingRow(f, seen) {
  const doc = f.documents[0] || {};
  const extra = f.documents.length > 1 ? ` <span class="meta">+${f.documents.length - 1} more</span>` : "";
  return `<li class="${f.filing_seq > seen ? "new" : ""}">
    <span class="when">${shortDate(f.date)}</span>
    <div>
      <div class="what"><span class="type">${esc(f.doc_type)}</span><a class="doc" href="${esc(doc.url)}" target="_blank" rel="noopener">${esc(doc.title)}</a>${extra}</div>
      ${f.summary ? `<div class="sum">${esc(f.summary)}</div>` : ""}
      <div class="meta">${esc(f.filer_short || f.filer)}</div>
    </div></li>`;
}

function watchCard(c) {
  const m = c.meta || {};
  const seen = lastSeen(c);
  const newCount = newCountOf(c);
  const kind = [m.industry, m.subtype || m.type].filter(Boolean).join(" · ");
  const latest = c.filings[0]?.date;
  const rel = relDay(latest);
  return `<article class="watch${isStarred(c) ? " starred" : ""}" data-case="${esc(c.case)}">
    <div class="watch-side">
      <div class="caseline">${starButton(c)}<a class="caseno" href="#/case/${esc(c.case)}">${esc(c.case)}</a></div>
      <div class="kicker">${esc(kind)}</div>
      ${
        pendingFor(c.case)
          ? `<span class="tag ink">Removing…</span>`
          : newCount
          ? `<span class="tag gold">${newCount} new</span>`
          : `<span class="tag">Up to date</span>`
      }
      <div class="count">${c.filings.length.toLocaleString()} filings${latest ? ` · last ${rel ? rel.toLowerCase() : shortDate(latest)}` : ""}</div>
    </div>
    <div class="watch-main">
      <h2><a href="#/case/${esc(c.case)}">${esc(m.title || c.case)}</a></h2>
      <div class="who">${esc(m.companies || "")}</div>
      ${c.summary ? `<p class="case-sum">${esc(c.summary)}</p>` : ""}
      ${categoryPills(c)}
      <ul class="filings">${c.filings.slice(0, 6).map((f) => filingRow(f, seen)).join("")}</ul>
      <div class="actions">
        <a class="textbtn" href="#/case/${esc(c.case)}">All ${c.filings.length.toLocaleString()} filings</a>
        ${newCount ? `<button class="textbtn" data-act="seen">Mark as read</button>` : ""}
        <a class="textbtn quiet" href="${esc(m.url)}" target="_blank" rel="noopener">Open on DPS ↗</a>
        ${pendingFor(c.case) ? "" : `<button class="textbtn quiet" data-act="untrack" data-case="${esc(c.case)}">Stop tracking</button>`}
      </div>
    </div>
  </article>`;
}

function toolbar(cases) {
  const prefs = getPrefs();
  const cats = allCategories();
  const count = (pred) => cases.filter(pred).length;
  const chip = (filter, label, n, extra = "") =>
    `<button class="chip${lc(prefs.filter) === lc(filter) ? " on" : ""}" data-act="filter" data-filter="${esc(filter)}">${label}<span class="n">${n}</span></button>${extra}`;
  return `<div class="toolbar">
    <div class="chips">
      ${chip("all", "All", cases.length)}
      ${chip("starred", "★ Starred", count(isStarred))}
      ${cats
        .map((n) =>
          chip(`cat:${n}`, esc(n), count((c) => categoriesOf(c).some((x) => lc(x) === lc(n))),
            editingCategories ? `<button class="chip-x" data-act="delcat" data-name="${esc(n)}" aria-label="Delete category ${esc(n)}">×</button>` : "")
        )
        .join("")}
      ${cats.length ? chip("none", "Uncategorized", count((c) => !categoriesOf(c).length)) : ""}
      <button class="chip ghost" data-act="newcat">+ New category</button>
      ${cats.length ? `<button class="textbtn quiet" data-act="editcats">${editingCategories ? "Done" : "Edit categories"}</button>` : ""}
    </div>
    <div class="sorts">
      <label>Sort <select id="sort">${Object.entries(SORTS)
        .map(([k, v]) => `<option value="${k}"${prefs.sort === k ? " selected" : ""}>${v.label}</option>`)
        .join("")}</select></label>
      <label class="check"><input type="checkbox" id="group"${prefs.group ? " checked" : ""}> Group by category</label>
    </div>
  </div>`;
}

function renderWatchlist() {
  setNav("watch");
  const prefs = getPrefs();
  const all = DATA.cases;
  const cats = allCategories();
  let filter = prefs.filter;
  if (filter.startsWith("cat:") && !cats.some((n) => lc(`cat:${n}`) === lc(filter))) filter = "all";
  const matches = (c) =>
    filter === "starred" ? isStarred(c) :
    filter === "none" ? !categoriesOf(c).length :
    filter.startsWith("cat:") ? categoriesOf(c).some((x) => lc(x) === lc(filter.slice(4))) : true;
  const cases = all.filter(matches).sort((SORTS[prefs.sort] || SORTS.starred).cmp);
  const totalNew = all.reduce((n, c) => n + newCountOf(c), 0);
  const adding = pending().filter((p) => p.action === "track");

  let body;
  if (!all.length && !adding.length) {
    body = `<div class="empty"><p><strong>Nothing tracked yet.</strong> Add a case number above.</p></div>`;
  } else if (!cases.length) {
    body = `<div class="empty"><p>No tracked cases match this filter.</p></div>`;
  } else if (prefs.group && cats.length) {
    const groups = cats
      .map((n) => ({ name: n, items: cases.filter((c) => categoriesOf(c).some((x) => lc(x) === lc(n))) }))
      .concat([{ name: "Uncategorized", items: cases.filter((c) => !categoriesOf(c).length) }])
      .filter((g) => g.items.length);
    body = groups.map((g) => `<h3 class="group-head">${esc(g.name)} <span>${g.items.length}</span></h3>${g.items.map(watchCard).join("")}`).join("");
  } else {
    body = cases.map(watchCard).join("");
  }

  view.innerHTML = `
    <form class="track" id="track">
      <label for="cases">Track a proceeding</label>
      <div class="track-row">
        <input id="cases" name="cases" autocomplete="off" placeholder="25-E-0375" required>
        <button class="btn" type="submit">Track</button>
      </div>
      <p class="hint">One or more PSC case numbers, separated by commas. The request goes to your Slack channel, the bot confirms there, and the case appears here in a few minutes. You can also post <code>track 25-E-0375</code> in Slack.</p>
      <div class="problems" id="problems"></div>
    </form>
    <h2 class="section-head">Tracked cases</h2>
    ${all.length ? toolbar(all) : ""}
    ${adding
      .map(
        (p) => `<article class="watch pending"><div class="watch-side"><span class="caseno">${esc(p.case)}</span><span class="tag ink">Adding…</span></div>
        <div class="watch-main"><p class="who">Requested ${Math.max(1, Math.round((Date.now() - p.at) / 6e4))} min ago. The bot confirms in Slack (or says if the case doesn't exist), and the full history appears here once the dashboard rebuilds, usually within five minutes. This page checks automatically.</p></div></article>`
      )
      .join("")}
    ${all.length ? (totalNew
      ? `<p class="dek"><strong>${totalNew} new filing${totalNew === 1 ? "" : "s"}</strong> since your last visit.</p>`
      : `<p class="dek">No new filings in the ${all.length} tracked case${all.length === 1 ? "" : "s"} since your last visit.</p>`) : ""}
    ${body}`;

  document.getElementById("track").addEventListener("submit", onTrack);
  document.getElementById("sort")?.addEventListener("change", (e) => {
    setPrefs({ sort: e.target.value });
    renderWatchlist();
  });
  document.getElementById("group")?.addEventListener("change", (e) => {
    setPrefs({ group: e.target.checked });
    renderWatchlist();
  });
  view.querySelectorAll('[data-act="seen"]').forEach((btn) =>
    btn.addEventListener("click", () => {
      markSeen(caseObj(btn.closest(".watch").dataset.case));
      renderWatchlist();
    })
  );
}

/* ---------- case page ---------- */

const PAGE = 60;

function renderCase(caseNo) {
  setNav("watch");
  const c = DATA.cases.find((x) => x.case === caseNo);
  if (!c) {
    view.innerHTML = `<a class="textbtn back" href="#/">← Tracked cases</a>
      <div class="empty"><p><strong>${esc(caseNo)} isn't tracked${pendingFor(caseNo) ? " yet. It's been requested and will appear here in a few minutes" : ""}.</strong>
      <a class="doc" href="https://documents.dps.ny.gov/public/MatterManagement/CaseMaster.aspx?MatterCaseNo=${encodeURIComponent(caseNo)}" target="_blank" rel="noopener">Open it on the DPS site</a>.</p>
      ${pendingFor(caseNo) ? "" : `<button class="btn" id="trackbtn">Track ${esc(caseNo)}</button>`}</div>`;
    document.getElementById("trackbtn")?.addEventListener("click", async () => {
      await sendCommand("track", [caseNo]).catch((err) => alert(err.message));
      renderCase(caseNo);
    });
    return;
  }
  const m = c.meta || {};
  const seen = lastSeen(c);
  const types = {};
  c.filings.forEach((f) => (types[f.doc_type] = (types[f.doc_type] || 0) + 1));
  const topTypes = Object.entries(types).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const state = { type: null, q: "", shown: PAGE };

  view.innerHTML = `
    <a class="textbtn back" href="#/">← Tracked cases</a>
    <header class="case-head">
      <div class="kicker">${esc([m.industry, m.type, m.subtype].filter(Boolean).join(" · "))}</div>
      <div class="title-row">${starButton(c)}<h1>${esc(m.title)}</h1></div>
      ${c.summary ? `<p class="case-sum lead">${esc(c.summary)}</p>` : ""}
      ${categoryPills(c)}
      <dl class="facts">
        <div><dt>Case</dt><dd class="caseno">${esc(c.case)}</dd></div>
        <div><dt>Parties</dt><dd>${esc(m.companies || "—")}</dd></div>
        <div><dt>Opened</dt><dd>${esc(longDate(m.opened) || "—")}</dd></div>
        <div><dt>Filings</dt><dd>${c.filings.length.toLocaleString()} · latest ${esc(shortDate(c.filings[0]?.date))}</dd></div>
      </dl>
      <div class="case-actions">
        <a class="btn ghost" href="${esc(m.url)}" target="_blank" rel="noopener">Open on DPS ↗</a>
        <span class="kicker">Tracked since ${esc(shortDate(c.added_at))}</span>
        ${pendingFor(c.case) ? `<span class="tag ink">Removing…</span>` : `<button class="textbtn quiet" data-act="untrack" data-case="${esc(c.case)}">Stop tracking</button>`}
      </div>
    </header>
    <div class="filters">
      <input id="q" type="search" placeholder="Search titles and filers" aria-label="Search filings">
      <button class="chip on" data-type="">All<span class="n">${c.filings.length}</span></button>
      ${topTypes.map(([t, n]) => `<button class="chip" data-type="${esc(t)}">${esc(t)}<span class="n">${n}</span></button>`).join("")}
    </div>
    <div id="timeline"></div>`;

  const timeline = document.getElementById("timeline");
  const draw = () => {
    const q = state.q.toLowerCase();
    const rows = c.filings.filter(
      (f) =>
        (!state.type || f.doc_type === state.type) &&
        (!q || f.filer.toLowerCase().includes(q) || f.documents.some((d) => d.title.toLowerCase().includes(q)))
    );
    const byDay = [];
    rows.slice(0, state.shown).forEach((f) => {
      const last = byDay[byDay.length - 1];
      if (last && last.date === f.date) last.items.push(f);
      else byDay.push({ date: f.date, items: [f] });
    });
    timeline.innerHTML =
      (rows.length ? "" : `<p class="empty">No filings match.</p>`) +
      byDay
        .map(
          (d) => `<section class="day">
        <div class="day-label">${shortDate(d.date)}<small>${esc(relDay(d.date) || parseDay(d.date)?.toLocaleDateString("en-US", { weekday: "long" }) || "")}</small></div>
        <div>${d.items
          .map((f) => {
            const isNew = f.filing_seq > seen;
            return `<div class="filing${isNew ? " new" : ""}">
              <div class="head">${isNew ? '<span class="tag gold">New</span> ' : ""}<span class="type">${esc(f.doc_type)}</span> · <b>${esc(f.filer_short || f.filer)}</b> · item ${esc(f.item_no)}</div>
              ${f.summary ? `<p class="sum">${esc(f.summary)}</p>` : ""}
              <ul>${f.documents
                .map(
                  (doc) =>
                    `<li><a class="doc" href="${esc(doc.url)}" target="_blank" rel="noopener">${esc(doc.title)}</a><span class="size">${esc(doc.ext)}${doc.size ? ` · ${esc(doc.size)}` : ""}</span></li>`
                )
                .join("")}</ul></div>`;
          })
          .join("")}</div></section>`
        )
        .join("") +
      (rows.length > state.shown
        ? `<div class="more"><button class="btn ghost" id="more">Show ${Math.min(PAGE, rows.length - state.shown)} more of ${(rows.length - state.shown).toLocaleString()}</button></div>`
        : "");
    document.getElementById("more")?.addEventListener("click", () => {
      state.shown += PAGE;
      draw();
    });
  };
  draw();
  markSeen(c); // opening the full case counts as reading it

  document.getElementById("q").addEventListener("input", (e) => {
    state.q = e.target.value;
    state.shown = PAGE;
    draw();
  });
  view.querySelectorAll(".chip").forEach((chip) =>
    chip.addEventListener("click", () => {
      view.querySelectorAll(".chip").forEach((x) => x.classList.toggle("on", x === chip));
      state.type = chip.dataset.type || null;
      state.shown = PAGE;
      draw();
    })
  );
}

/* ---------- search: every filing by a company or organization ---------- */

function searchFilingRow(f, s) {
  const tracked = isTracked(f.case);
  const title = s.titles?.[f.case];
  const caseLink = tracked
    ? `<a class="caseno-sm" href="#/case/${esc(f.case)}">${esc(f.case)}</a>`
    : `<a class="caseno-sm" href="https://documents.dps.ny.gov/public/MatterManagement/CaseMaster.aspx?MatterCaseNo=${encodeURIComponent(f.case || "")}" target="_blank" rel="noopener">${esc(f.case)}</a>`;
  const trackBtn = !f.case || tracked ? "" : pendingFor(f.case)
    ? `<span class="tag ink">Adding…</span>`
    : `<button class="textbtn quiet" data-act="tracksearchcase" data-case="${esc(f.case)}">+ Track</button>`;
  return `<div class="filing">
    <div class="head"><span class="type">${esc(f.doc_type)}</span> · ${caseLink} ${trackBtn}</div>
    ${title ? `<div class="case-title">${esc(title)}</div>` : ""}
    <ul>${f.documents.map((doc) => `<li><a class="doc" href="${esc(doc.url)}" target="_blank" rel="noopener">${esc(doc.title)}</a><span class="size">${esc(doc.ext)}${doc.size ? ` · ${esc(doc.size)}` : ""}</span></li>`).join("")}</ul>
  </div>`;
}

// "#8516" -> the organization's name, when an earlier search listed it as another match
function searchLabel(q) {
  const seq = Number((q.match(/^#(\d+)$/) || [])[1]);
  if (!seq) return q;
  for (const x of DATA.searches || []) for (const o of x.others || []) if (o.seq === seq) return o.name;
  return q;
}

function renderSearch(arg) {
  setNav("search");
  const saved = DATA.searches || [];
  const waiting = pending().filter((p) => p.action === "search");
  const current = saved.find((x) => String(x.seq) === arg) || (arg ? null : saved[saved.length - 1]);

  view.innerHTML = `
    <form class="track" id="searchform">
      <label for="q">Search filings by company or organization</label>
      <div class="track-row">
        <input id="q" name="q" autocomplete="off" placeholder="City of New York, Sierra Club, NYPA…" required>
        <button class="btn" type="submit">Search</button>
      </div>
      <p class="hint">Finds every filing an organization has made, across all PSC cases. The search runs on the tracker, so results appear here in a few minutes (this page checks automatically), and saved searches refresh every few hours.</p>
      <div class="problems" id="problems"></div>
    </form>
    <h2 class="section-head">Saved searches</h2>
    <div class="chips search-chips">
      ${saved.map((x) => `<a class="chip${current && x.seq === current.seq ? " on" : ""}" href="#/search/${x.seq}" style="text-decoration:none">${esc(x.name)}<span class="n">${x.filings.length.toLocaleString()}</span></a>`).join("")}
      ${waiting.map((p) => `<span class="chip ghost">Searching “${esc(searchLabel(p.name))}”…</span>`).join("")}
      ${!saved.length && !waiting.length ? `<p class="empty">No saved searches yet. Search for an organization above.</p>` : ""}
    </div>
    <div id="results"></div>`;

  document.getElementById("searchform").addEventListener("submit", async (e) => {
    e.preventDefault();
    const q = e.target.q.value.trim().replace(/\s+/g, " ");
    const problems = document.getElementById("problems");
    if (q.length < 2) return (problems.textContent = "Type at least two letters.");
    const existing = findSearch(q);
    if (existing) return (location.hash = `#/search/${existing.seq}`);
    try {
      await sendCommand("search", [], [q]);
      renderSearch(arg);
    } catch (err) {
      problems.textContent = err.message;
    }
  });
  if (!current) return;

  const cases = new Set(current.filings.map((f) => f.case));
  const years = [...new Set(current.filings.map((f) => (f.date || "").slice(0, 4)).filter(Boolean))].sort().reverse();
  const types = {};
  current.filings.forEach((f) => (types[f.doc_type] = (types[f.doc_type] || 0) + 1));
  const topTypes = Object.entries(types).sort((a, b) => b[1] - a[1]).slice(0, 7);
  const state = { type: null, year: "", q: "", shown: PAGE };
  const removing = pending().some((p) => p.action === "unsearch" && p.name === `#${current.seq}`);

  document.getElementById("results").innerHTML = `
    <header class="case-head search-head">
      <div class="kicker">Filings by</div>
      <h1>${esc(current.name)}</h1>
      <p class="case-sum">${current.filings.length.toLocaleString()} filings in ${cases.size.toLocaleString()} cases${years.length ? `, ${years[years.length - 1]}–${years[0]}` : ""}. Searched as “${esc(current.query)}”.</p>
      ${current.others?.length ? `<p class="others">Also matched: ${current.others.map((o) => `<button class="pill add" data-act="searchother" data-seq="${o.seq}" data-name="${esc(o.name)}">${esc(o.name)}</button>`).join(" ")}</p>` : ""}
      <div class="case-actions">${removing ? `<span class="tag ink">Removing…</span>` : `<button class="textbtn quiet" data-act="unsearch" data-seq="${current.seq}">Remove this search</button>`}</div>
    </header>
    <div class="filters">
      <input id="fq" type="search" placeholder="Search titles and case numbers" aria-label="Filter results">
      <select id="fyear" aria-label="Year"><option value="">All years</option>${years.map((y) => `<option>${y}</option>`).join("")}</select>
      <button class="chip on" data-type="">All<span class="n">${current.filings.length}</span></button>
      ${topTypes.map(([t, n]) => `<button class="chip" data-type="${esc(t)}">${esc(t)}<span class="n">${n}</span></button>`).join("")}
    </div>
    <div id="timeline"></div>`;

  const timeline = document.getElementById("timeline");
  const draw = () => {
    const q = state.q.toLowerCase();
    const rows = current.filings.filter(
      (f) =>
        (!state.type || f.doc_type === state.type) &&
        (!state.year || (f.date || "").startsWith(state.year)) &&
        (!q || lc(f.case).includes(q) || lc(current.titles?.[f.case]).includes(q) || f.documents.some((d) => lc(d.title).includes(q)))
    );
    const byDay = [];
    rows.slice(0, state.shown).forEach((f) => {
      const last = byDay[byDay.length - 1];
      if (last && last.date === f.date) last.items.push(f);
      else byDay.push({ date: f.date, items: [f] });
    });
    timeline.innerHTML =
      (rows.length ? "" : `<p class="empty">No filings match.</p>`) +
      byDay.map((d) => `<section class="day">
        <div class="day-label">${shortDate(d.date)}<small>${esc(relDay(d.date) || (d.date || "").slice(0, 4))}</small></div>
        <div>${d.items.map((f) => searchFilingRow(f, current)).join("")}</div></section>`).join("") +
      (rows.length > state.shown
        ? `<div class="more"><button class="btn ghost" id="more">Show ${Math.min(PAGE, rows.length - state.shown)} more of ${(rows.length - state.shown).toLocaleString()}</button></div>`
        : "");
    document.getElementById("more")?.addEventListener("click", () => {
      state.shown += PAGE;
      draw();
    });
  };
  draw();
  document.getElementById("fq").addEventListener("input", (e) => ((state.q = e.target.value), (state.shown = PAGE), draw()));
  document.getElementById("fyear").addEventListener("change", (e) => ((state.year = e.target.value), (state.shown = PAGE), draw()));
  view.querySelectorAll(".filters .chip").forEach((chip) =>
    chip.addEventListener("click", () => {
      view.querySelectorAll(".filters .chip").forEach((x) => x.classList.toggle("on", x === chip));
      state.type = chip.dataset.type || null;
      state.shown = PAGE;
      draw();
    })
  );
}

/* ---------- briefing archive ---------- */

function renderBriefing(day) {
  setNav("briefing");
  const all = DATA.briefings.filter((b) => b.items.length || b.watchlist?.length);
  if (!all.length) {
    view.innerHTML = `<h2 class="section-head">PSC Updates</h2><div class="empty"><p><strong>No briefings yet.</strong> They appear here after each morning post.</p></div>`;
    return;
  }
  const b = all.find((x) => x.date === day) || all[0];
  view.innerHTML = `
    <h2 class="section-head">PSC Updates <span class="tools kicker">${esc(longDate(b.date))}</span></h2>
    <div class="brief-dates">${all
      .slice(0, 20)
      .map((x) => `<a class="chip${x === b ? " on" : ""}" href="#/briefing/${x.date}" style="text-decoration:none">${shortDate(x.date)}</a>`)
      .join("")}</div>
    ${b.items.length ? `<p class="topline">${esc(b.top_line)}</p>` : `<p class="topline">No major PSC news; new filings in tracked cases only.</p>`}
    <p class="kicker">${(b.filing_count || 0).toLocaleString()} filings reviewed</p>
    ${b.items
      .map(
        (it) => `<article class="item">
      <div class="side"><a class="caseno" href="${esc(it.url)}" target="_blank" rel="noopener">${esc(it.case)}</a></div>
      <div>
        <h2><a href="${esc(it.url)}" target="_blank" rel="noopener">${esc(it.headline)}</a></h2>
        <div class="who">${esc([it.companies, it.kind].filter(Boolean).join(" · "))}${it.comments ? ` · <strong>${it.comments.toLocaleString()} new public comments</strong>` : ""}</div>
        <p class="summary">${esc(it.summary)}</p>
        <ul>${it.filings.map((f) => `<li><a class="doc" href="${esc(f.url || it.url)}" target="_blank" rel="noopener">${esc(f.title)}</a> <span>— ${esc(f.doc_type)}</span></li>`).join("")}</ul>
      </div></article>`
      )
      .join("")}
    ${
      b.watchlist?.length
        ? `<h2 class="section-head">Tracked cases that day</h2>${b.watchlist
            .map(
              (w) => `<article class="item"><div class="side"><a class="caseno" href="#/case/${esc(w.case)}">${esc(w.case)}</a></div>
            <div><div class="who">${esc(w.title || "")}</div><ul>${w.filings
              .map((f) => `<li><a class="doc" href="${esc(f.url || w.url)}" target="_blank" rel="noopener">${esc(f.title)}</a> <span>— ${esc(f.doc_type)}</span>${f.summary ? `<div class="sum">${esc(f.summary)}</div>` : ""}</li>`)
              .join("")}</ul></div></article>`
            )
            .join("")}`
        : ""
    }`;
}

/* ---------- router ---------- */

function route(scroll = true) {
  if (!DATA) return;
  const [, page, arg] = location.hash.split("/");
  if (scroll) window.scrollTo(0, 0);
  if (pending().length) watchForUpdates();
  if (page === "case" && arg) renderCase(decodeURIComponent(arg));
  else if (page === "briefing") renderBriefing(arg);
  else if (page === "search") renderSearch(arg);
  else renderWatchlist();
}
window.addEventListener("hashchange", () => route());

(async () => {
  const saved = storage.get(PW_KEY, null);
  if (!saved) return showLock();
  view.innerHTML = `<div class="loading"><div class="kicker">Unlocking</div><div class="bar"></div></div>`;
  try {
    await unlock(saved);
  } catch (err) {
    storage.remove(PW_KEY); // password changed since it was saved
    showLock(err.name === "OperationError" ? "The password has changed. Enter the new one." : err.message);
  }
})();
