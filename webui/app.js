/* Nutiscan Web UI controller. */

const el = (id) => document.getElementById(id);
const state = { jobId: null, timer: null, snapshot: null, fixes: {}, filter: 'all',
                query: '', selected: null, fixTab: {} };

const CHECKS = [
  ['headers','Turvapeadised'],['cookies','Küpsised'],['cors','CORS'],['cache','Vahemälu'],
  ['banner','Versioonileke'],['tls','TLS'],['methods','HTTP-meetodid'],['exposed','Avalikud failid'],
  ['xss','XSS'],['sqli','SQLi'],['traversal','Traversal'],['redirect','Ümbersuunamine'],
  ['command','Käsu süüst'],['ssti','SSTI'],['crlf','CRLF'],['domxss','DOM-XSS']
];

function toast(msg) {
  const box = el('toast');
  box.textContent = msg;
  box.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => box.classList.remove('show'), 2600);
}

function buildChecks() {
  const root = el('checkBoxes');
  CHECKS.forEach(([name, label]) => {
    const wrap = document.createElement('label');
    const box = document.createElement('input');
    box.type = 'checkbox'; box.checked = true; box.dataset.check = name;
    wrap.append(box, document.createTextNode(label));
    root.append(wrap);
  });
}

function switchView(name) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === name));
  document.querySelectorAll('.view').forEach(v => { v.hidden = v.id !== 'view-' + name; });
}

document.querySelectorAll('.nav-item').forEach(n => n.addEventListener('click', () => switchView(n.dataset.view)));
document.querySelectorAll('[data-goto]').forEach(n => n.addEventListener('click', () => switchView(n.dataset.goto)));

/* ---------- boot ---------- */

fetch('/api/fixes').then(r => r.json()).then(d => { state.fixes = d.fixes || {}; renderFixLibrary(); }).catch(() => {});
fetch('/api/health').then(r => r.json()).then(d => {
  document.querySelector('.engine b').textContent = 'v' + d.version;
}).catch(() => {});
loadHistory();
buildChecks();

/* ---------- form ---------- */

el('scanForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const raw = el('url').value.trim().replace(/^https?:\/\//i, '');
  if (!raw) return;
  const payload = {
    url: raw,
    maxPages: Number(el('maxPages').value) || 60,
    maxDepth: Number(el('maxDepth').value) || 0,
    rateLimit: Number(el('rateLimit').value) || 8,
    allowPrivate: el('allowPrivate').checked,
    idor: el('idor').checked,
    checks: Array.from(document.querySelectorAll('[data-check]')).filter(x => x.checked).map(x => x.dataset.check),
  };
  const authText = el('auth').value.trim();
  if (authText) {
    try { payload.auth = JSON.parse(authText); }
    catch (err) { toast('Vigane autentimise JSON: ' + err.message); return; }
  }
  const headerText = el('headers').value.trim();
  if (headerText) {
    try {
      payload.headers = JSON.parse(headerText);
    } catch (err) {
      toast('Vigane päiste JSON: ' + err.message);
      return;
    }
  }
  resetScan();
  el('startBtn').disabled = true;
  el('stopBtn').disabled = false;
  setLive(true, 'skannib');
  try {
    const response = await fetch('/api/scan', { method: 'POST',
      headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'käivitamine ebaõnnestus');
    state.jobId = data.id;
    el('progressCard').hidden = false;
    state.timer = setInterval(poll, 700);
    poll();
  } catch (err) {
    el('startBtn').disabled = false;
    el('stopBtn').disabled = true;
    setLive(false, 'viga');
    toast(String(err.message || err));
  }
});

el('stopBtn').addEventListener('click', async () => {
  if (!state.jobId) return;
  await fetch(`/api/scan/${state.jobId}/stop`, {method:'POST'}).catch(() => {});
  toast('Peatamislähetus saadetud');
});

function setLive(busy, text) {
  const pill = el('livePill');
  pill.classList.toggle('busy', busy);
  pill.innerHTML = `<span></span> ${text}`;
}

function resetScan() {
  if (state.timer) clearInterval(state.timer);
  state.timer = null;
  state.snapshot = null;
  state.selected = null;
  el('statGrid').hidden = true;
  el('triageCard').hidden = true;
  el('miniFindings').hidden = true;
  el('progressCard').hidden = false;
  el('barFill').style.width = '0%';
}

/* ---------- polling ---------- */

async function poll() {
  if (!state.jobId) return;
  let data;
  try {
    const r = await fetch(`/api/scan/${state.jobId}`);
    data = await r.json();
  } catch { return; }
  state.snapshot = data;
  el('stage').textContent = data.stage;
  el('progressPct').textContent = data.progress + '%';
  el('barFill').style.width = data.progress + '%';
  el('timer').textContent = data.duration + 's';
  el('progressMeta').textContent =
    `lehti ${data.pages} · sisendeid ${data.endpoints} · leide ${data.findings.length}`;
  el('navFindings').textContent = String(data.findings.length);

  if (data.findings.length) {
    renderMini(data.findings);
    renderFindings();
  }
  const done = data.status === 'done' || data.status === 'error';
  if (done) {
    clearInterval(state.timer); state.timer = null;
    el('startBtn').disabled = false;
    el('stopBtn').disabled = true;
    setLive(false, data.status === 'error' ? 'viga' : 'valmis');
    el('statGrid').hidden = false;
    const c = data.counts;
    el('cCritical').textContent = c.critical;
    el('cHigh').textContent = c.high;
    el('cMedium').textContent = c.medium;
    el('cLow').textContent = c.low;
    el('cInfo').textContent = c.info;
    el('cRisk').textContent = (data.triageSummary || {}).riskScore ?? 0;
    if (data.triage) {
      el('triageCard').hidden = false;
      renderMarkdown(el('triage'), data.triage);
      const risk = (data.triageSummary || {}).riskScore ?? 0;
      const chip = el('riskChip');
      chip.textContent = `risk ${risk}/100`;
      chip.classList.toggle('risky', risk >= 60);
    }
    if (data.error) toast('Viga: ' + data.error);
    loadHistory();
  }
}

function renderMini(findings) {
  el('miniFindings').hidden = false;
  const list = el('miniList');
  list.textContent = '';
  findings.slice(0, 6).forEach(f => {
    const row = document.createElement('div');
    row.className = 'mini-item';
    const tag = document.createElement('span');
    tag.className = 'sev ' + f.severity; tag.textContent = f.severity;
    const title = document.createElement('span');
    title.textContent = f.title; title.style.flex = '1';
    row.append(tag, title);
    list.append(row);
  });
}

/* ---------- findings ---------- */

el('search').addEventListener('input', e => { state.query = e.target.value.toLowerCase(); renderFindings(); });
document.querySelectorAll('#filters .chip').forEach(chip => chip.addEventListener('click', () => {
  state.filter = chip.dataset.sev;
  document.querySelectorAll('#filters .chip').forEach(c => c.classList.remove('active'));
  chip.classList.add('active');
  renderFindings();
}));

function renderFindings() {
  const root = el('findingsList');
  root.textContent = '';
  const findings = (state.snapshot?.findings || []).filter(f =>
    (state.filter === 'all' || f.severity === state.filter) &&
    (!state.query || (f.title + f.detail + f.url + f.check).toLowerCase().includes(state.query))
  );
  if (!findings.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-detail';
    empty.textContent = 'Leide ei ole või otsing ei täpsustanud midagi.';
    root.append(empty);
    return;
  }
  findings.forEach(f => {
    const item = document.createElement('div');
    item.className = 'finding ' + f.severity + (state.selected === f.id ? ' selected' : '');
    const head = document.createElement('div');
    head.className = 'finding-head';
    const tag = document.createElement('span');
    tag.className = 'sev ' + f.severity; tag.textContent = f.severity;
    const title = document.createElement('span');
    title.className = 'finding-title'; title.textContent = f.title;
    const cat = document.createElement('span');
    cat.className = 'finding-cat'; cat.textContent = f.check;
    head.append(tag, title, cat);
    head.addEventListener('click', () => {
      state.selected = f.id;
      renderFindings();
      renderDetail(f);
    });
    item.append(head);
    root.append(item);
  });
}

function renderDetail(f) {
  const root = el('detailPane');
  root.textContent = '';
  const wrap = document.createElement('div');
  wrap.className = 'detail-content';
  const h = document.createElement('h2'); h.textContent = f.title;
  const meta = document.createElement('div');
  meta.className = 'detail-meta';
  const tag = document.createElement('span');
  tag.className = 'sev ' + f.severity; tag.textContent = `${f.severity} · ${f.score}/10 · ${f.confidence}`;
  const chk = document.createElement('span'); chk.className = 'chip'; chk.textContent = 'kontroll: ' + f.check;
  meta.append(tag, chk);
  wrap.append(h, meta);
  wrap.append(section('Asukoht', f.url, true));
  wrap.append(section('Kirjeldus', f.detail));
  if (f.request && Object.keys(f.request).length) {
    wrap.append(section('Taasesitus', Object.entries(f.request).map(([k,v]) => `${k}: ${v}`).join('\n'), true));
  }
  if (f.evidence) wrap.append(section('Tõend', f.evidence, true));

  const fix = state.fixes[f.check] || { title: 'Parandusjuhend', summary: f.remediation || '', steps: [], code: {} };
  const box = document.createElement('div');
  box.className = 'fix-box';
  const fh = document.createElement('h3'); fh.textContent = '✦ ' + fix.title;
  const fs = document.createElement('div'); fs.className = 'summary'; fs.textContent = fix.summary || f.remediation;
  box.append(fh, fs);
  if (fix.steps && fix.steps.length) {
    const ol = document.createElement('ol');
    fix.steps.forEach(s => { const li = document.createElement('li'); li.textContent = s; ol.append(li); });
    box.append(ol);
  }
  if (fix.code && Object.keys(fix.code).length) {
    const tabs = document.createElement('div'); tabs.className = 'tabs';
    const pre = document.createElement('pre');
    const langs = Object.keys(fix.code);
    const active = state.fixTab[f.check] || langs[0];
    const show = (lang) => {
      state.fixTab[f.check] = lang;
      pre.textContent = fix.code[lang];
      tabs.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.lang === lang));
    };
    langs.forEach(lang => {
      const b = document.createElement('button');
      b.className = 'tab' + (lang === active ? ' active' : '');
      b.textContent = lang; b.dataset.lang = lang;
      b.addEventListener('click', () => show(lang));
      tabs.append(b);
    });
    box.append(tabs, pre);
    show(active);
  }
  wrap.append(box);
  root.append(wrap);
}

function section(title, text, code) {
  const box = document.createElement('div'); box.className = 'detail-sec';
  const h = document.createElement('h4'); h.textContent = title;
  const body = code ? document.createElement('pre') : document.createElement('p');
  body.textContent = text;
  box.append(h, body);
  return box;
}

/* ---------- fixes library ---------- */

function renderFixLibrary() {
  const root = el('fixGrid');
  root.textContent = '';
  Object.entries(state.fixes).forEach(([key, fix]) => {
    const card = document.createElement('div'); card.className = 'fix-card';
    const h = document.createElement('h3'); h.textContent = fix.title;
    const p = document.createElement('p'); p.textContent = fix.summary;
    const count = document.createElement('div');
    count.className = 'count';
    count.textContent = `${fix.steps?.length || 0} sammud · ${Object.keys(fix.code || {}).length} koodinäited`;
    card.append(h, p, count);
    card.addEventListener('click', () => {
      const fake = { title: fix.title, severity: 'info', score: 0, confidence: 'firm',
                     check: key, url: '—', detail: fix.summary, remediation: '', request: {}, evidence: '' };
      switchView('findings');
      renderDetail(fake);
      toast('Avatud: ' + fix.title);
    });
    root.append(card);
  });
}

/* ---------- history ---------- */

async function loadHistory() {
  const root = el('historyList');
  try {
    const data = await (await fetch('/api/history')).json();
    root.textContent = '';
    if (!data.items.length) {
      root.textContent = 'Ajalugu on tühi.';
      return;
    }
    data.items.forEach(item => {
      const row = document.createElement('div'); row.className = 'history-item';
      const u = document.createElement('span'); u.className = 'url'; u.textContent = item.url;
      const m = document.createElement('span'); m.className = 'meta';
      m.textContent = `${item.findings} leidu · risk ${item.risk}/100 · ${item.duration}s`;
      row.append(u, m);
      row.addEventListener('click', async () => {
        const snap = await (await fetch(`/api/scan/${item.id}`)).json();
        state.snapshot = snap; state.jobId = item.id; state.selected = null;
        switchView('findings');
        renderFindings();
        toast('Avatud: ' + item.url);
      });
      root.append(row);
    });
  } catch {}
}
el('refreshHistory').addEventListener('click', loadHistory);

/* ---------- export ---------- */

document.querySelectorAll('[data-export]').forEach(b => b.addEventListener('click', () => {
  if (!state.jobId) { toast('Esiteks skanni sihtmärk'); return; }
  const fmt = b.dataset.export;
  window.location.href = `/api/scan/${encodeURIComponent(state.jobId)}/export?format=${fmt}`;
}));

/* ---------- tiny markdown renderer ---------- */

function renderMarkdown(root, text) {
  root.textContent = '';
  let list = null;
  const flush = () => { list = null; };
  text.split('\n').forEach(raw => {
    const line = raw.trimEnd();
    if (!line.trim()) { flush(); return; }
    if (line.startsWith('## ') || line.startsWith('# ')) {
      flush();
      const h = document.createElement('h3');
      h.textContent = line.replace(/^#+\s*/, '');
      root.append(h); return;
    }
    const ordered = /^(\d+)\.\s+(.*)$/.exec(line);
    const bullet = /^[-*]\s+(.*)$/.exec(line);
    if (ordered || bullet) {
      const tag = ordered ? 'OL' : 'UL';
      if (!list || list.tagName !== tag) { list = document.createElement(tag); root.append(list); }
      const li = document.createElement('li');
      li.textContent = ordered ? ordered[2] : bullet[1];
      list.append(li); return;
    }
    flush();
    const p = document.createElement('p');
    p.textContent = line;
    root.append(p);
  });
}
