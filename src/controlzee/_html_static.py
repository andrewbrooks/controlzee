"""The stylesheet and script of the HTML report. Fixed text: nothing from the logs is ever put into either of them.

The page's Content Security Policy allows exactly these two (by their hashes), so even if some log text were ever left
unescaped it could not run a script or load anything. The script only enhances (copy buttons, folding, filtering, a
checklist, the theme); the report reads fine without it.
"""
from __future__ import annotations

CSS = """
:root{color-scheme:light dark;--bg:#fff;--bg2:#f6f8fa;--fg:#1f2328;--mut:#59636e;--line:#d1d9e0;--accent:#0969da;--danger:#cf222e;--warn:#9a6700;--ok:#1a7f37;
--seed-fill:#fde2e2;--seed-stroke:#c0392b;--fol-fill:#e3edff;--fol-stroke:#3b6fd4;--un-fill:#f4f4f4;--un-stroke:#888;--shadow:0 1px 2px rgba(31,35,40,.08);
--c-initial-access:#0b7285;--c-execution:#d9480f;--c-persistence:#7048e8;--c-privilege-escalation:#c2255c;--c-defense-evasion:#862e9c;--c-credential-access:#e67700;
--c-discovery:#1c7ed6;--c-lateral-movement:#2b8a3e;--c-collection:#0c8599;--c-exfiltration:#a61e4d;--c-impact:#c92a2a;--c-other:#868e96}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0d1117;--bg2:#161b22;--fg:#e6edf3;--mut:#9198a1;--line:#30363d;--accent:#4493f8;--danger:#f85149;--warn:#d29922;--ok:#3fb950;
--seed-fill:#4a1f24;--seed-stroke:#f85149;--fol-fill:#14305a;--fol-stroke:#4493f8;--un-fill:#21262d;--un-stroke:#8b949e;--shadow:none;
--c-initial-access:#3bc9db;--c-execution:#ff922b;--c-persistence:#9775fa;--c-privilege-escalation:#f06595;--c-defense-evasion:#da77f2;--c-credential-access:#fcc419;
--c-discovery:#4dabf7;--c-lateral-movement:#69db7c;--c-collection:#66d9e8;--c-exfiltration:#ff8787;--c-impact:#ff6b6b;--c-other:#868e96}}
:root[data-theme=dark]{--bg:#0d1117;--bg2:#161b22;--fg:#e6edf3;--mut:#9198a1;--line:#30363d;--accent:#4493f8;--danger:#f85149;--warn:#d29922;--ok:#3fb950;
--seed-fill:#4a1f24;--seed-stroke:#f85149;--fol-fill:#14305a;--fol-stroke:#4493f8;--un-fill:#21262d;--un-stroke:#8b949e;--shadow:none;
--c-initial-access:#3bc9db;--c-execution:#ff922b;--c-persistence:#9775fa;--c-privilege-escalation:#f06595;--c-defense-evasion:#da77f2;--c-credential-access:#fcc419;
--c-discovery:#4dabf7;--c-lateral-movement:#69db7c;--c-collection:#66d9e8;--c-exfiltration:#ff8787;--c-impact:#ff6b6b;--c-other:#868e96}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
header.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:16px;padding:8px 20px;background:var(--bg);border-bottom:1px solid var(--line)}
.brand{font-weight:700;letter-spacing:.2px}.brand span{color:var(--accent)}
header.top nav{flex:1;display:flex;gap:2px;overflow-x:auto;white-space:nowrap}
header.top nav a{padding:4px 10px;border-radius:6px;color:var(--mut);font-size:13px}header.top nav a:hover{background:var(--bg2);color:var(--fg);text-decoration:none}
.tools{display:flex;gap:6px}
button,.btn{font:inherit;font-size:12.5px;padding:4px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg2);color:var(--fg);cursor:pointer}
button:hover{border-color:var(--accent)}button:focus-visible,summary:focus-visible,.node:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
main{max-width:1120px;margin:0 auto;padding:8px 20px 80px}
section{margin-top:40px;scroll-margin-top:56px}
h1{font-size:30px;margin:28px 0 4px}h2{font-size:20px;margin:0 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}h3{font-size:16px;margin:0}
.meta{color:var(--mut);font-size:13px;margin:0 0 20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.card{background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:12px 14px;box-shadow:var(--shadow)}
.card .n{font-size:26px;font-weight:700;line-height:1.15}.card .l{color:var(--mut);font-size:12.5px}
.callout{border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;background:var(--bg2);padding:14px 18px}
.callout .lead{font-size:16px;margin:0 0 8px}.points{margin:8px 0;padding:0;list-style:none}
.points li{padding:5px 0 5px 22px;position:relative}.points li::before{content:"";position:absolute;left:4px;top:13px;width:9px;height:9px;border-radius:50%;background:var(--danger)}
.points li.info::before{background:var(--accent)}.points strong{font-weight:650}
.first{margin-top:10px;padding-top:10px;border-top:1px dashed var(--line)}.first ol{margin:6px 0 0;padding-left:22px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}
.chip{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;color:#fff;background:var(--c,var(--c-other))}
.chip.t-credential-access,.chip.t-persistence-x{color:#1f2328}
button.chip{border:0;font:inherit;font-size:12px;cursor:pointer}button.chip.off{opacity:.35;text-decoration:line-through}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:5px 10px;text-align:left;vertical-align:top}
th{background:var(--bg2);position:sticky;top:0;font-weight:600;white-space:nowrap}td.nowrap{white-space:nowrap}
tr.gap td{background:repeating-linear-gradient(45deg,transparent,transparent 6px,var(--bg2) 6px,var(--bg2) 12px);color:var(--mut)}
details{border:1px solid var(--line);border-radius:8px;margin:8px 0;background:var(--bg)}
details>summary{cursor:pointer;padding:8px 14px;font-weight:500;list-style:none}details>summary::before{content:"▸";display:inline-block;width:1.1em;color:var(--mut)}
details[open]>summary::before{content:"▾"}details>div.body{padding:2px 16px 12px}details[open]>summary{border-bottom:1px solid var(--line)}
.kv{width:auto;margin:8px 0}.kv th{position:static;background:none;font-weight:500;color:var(--mut);white-space:nowrap}
pre{margin:6px 0;padding:10px 12px;background:var(--bg2);border:1px solid var(--line);border-radius:6px;overflow-x:auto}
.cmd{position:relative}.cmd button{position:absolute;right:8px;top:12px}
code.id{cursor:pointer;border-bottom:1px dotted var(--mut)}code.id:hover{background:var(--bg2)}code.copied,button.copied{color:var(--ok)}
.progress{display:flex;align-items:center;gap:12px;margin:0 0 12px}.progress progress{flex:1;height:10px;accent-color:var(--ok)}
.step{border:1px solid var(--line);border-radius:10px;padding:12px 16px;margin:10px 0;background:var(--bg);box-shadow:var(--shadow)}
.step.done{opacity:.65}.step.done h3{text-decoration:line-through}
.step-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.step-head input{width:18px;height:18px;accent-color:var(--ok)}
.sid{font-family:ui-monospace,monospace;font-weight:700;color:var(--mut)}
.badge{display:inline-block;padding:1px 8px;border-radius:5px;font-size:11.5px;border:1px solid var(--line);color:var(--mut)}
.badge.run{border-color:var(--ok);color:var(--ok)}.badge.danger{border-color:var(--danger);color:var(--danger)}.badge.phase{text-transform:capitalize}
.target{margin:6px 0 2px;font-weight:500}.why{margin:2px 0 6px;color:var(--mut)}
.caution{margin:8px 0;padding:8px 12px;border-left:3px solid var(--warn);background:var(--bg2);border-radius:4px;font-size:13.5px}
.toolbar{display:flex;gap:10px;align-items:center;margin:8px 0}.toolbar input[type=search]{flex:1;max-width:340px;padding:5px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
.legend{display:flex;flex-wrap:wrap;gap:14px;color:var(--mut);font-size:12.5px;margin:6px 0}.legend i{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;background:var(--c,var(--c-other))}
.note{color:var(--mut);font-size:13px}
svg{display:block;max-width:100%;height:auto}
svg.graph,svg.timeline{background:var(--bg2);border:1px solid var(--line);border-radius:10px}
svg text{font-family:system-ui,sans-serif;fill:var(--fg)}
.node .box{stroke-width:1.5}.node.seed .box{fill:var(--seed-fill);stroke:var(--seed-stroke)}.node.followed .box{fill:var(--fol-fill);stroke:var(--fol-stroke)}
.node.unused .box{fill:var(--un-fill);stroke:var(--un-stroke);stroke-dasharray:5 4}.node .name{font-size:13px;font-weight:600}.node .sub{font-size:11px;fill:var(--mut)}
.node.link{cursor:pointer}.node.link:hover .box{stroke-width:3}
.edge{fill:none;stroke:var(--mut);stroke-width:1.6}.edge.dashed{stroke-dasharray:5 4}.arrowhead{fill:var(--mut)}
.edge-label-bg{fill:var(--bg);stroke:var(--line)}.edge-label{font-size:11px}
.lane{fill:transparent}.lane.alt{fill:color-mix(in srgb,var(--fg) 4%,transparent)}.lane-label{font-size:12px}
.gap rect{fill:var(--warn);opacity:.18}.axis,.tick{stroke:var(--mut);stroke-width:1}.tick-label,.axis-note{font-size:11px;fill:var(--mut)}
.tamper path{fill:var(--danger)}
circle.dot{fill:var(--c,var(--c-other))}circle.dot.prop{stroke:var(--fg);stroke-width:1.6}
.dot.fail path{stroke:var(--c,var(--danger));stroke-width:2;fill:none}
.t-initial-access{--c:var(--c-initial-access)}.t-execution{--c:var(--c-execution)}.t-persistence{--c:var(--c-persistence)}
.t-privilege-escalation{--c:var(--c-privilege-escalation)}.t-defense-evasion{--c:var(--c-defense-evasion)}.t-credential-access{--c:var(--c-credential-access)}
.t-discovery{--c:var(--c-discovery)}.t-lateral-movement{--c:var(--c-lateral-movement)}.t-collection{--c:var(--c-collection)}
.t-exfiltration{--c:var(--c-exfiltration)}.t-impact{--c:var(--c-impact)}.t-other{--c:var(--c-other)}
svg.tactic-bar rect{fill:var(--c,var(--c-other))}svg.tactic-bar{height:18px;border-radius:4px}
footer{margin-top:60px;padding-top:14px;border-top:1px solid var(--line);color:var(--mut);font-size:12px}
@media print{header.top,.tools,.toolbar,.cmd button{display:none}main{max-width:none;padding:0}details{break-inside:avoid}svg{break-inside:avoid}.step{break-inside:avoid}}
"""

JS = """
(function () {
  'use strict';
  var root = document.documentElement;
  function $(s, c) { return (c || document).querySelector(s); }
  function $$(s, c) { return Array.prototype.slice.call((c || document).querySelectorAll(s)); }
  function store(k, v) { try { if (v === undefined) { return localStorage.getItem(k); } localStorage.setItem(k, v); } catch (e) { return null; } }

  var saved = store('czee-theme');
  if (saved) { root.setAttribute('data-theme', saved); }
  var theme = $('#theme');
  if (theme) { theme.addEventListener('click', function () {
    var cur = root.getAttribute('data-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    var next = cur === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next); store('czee-theme', next);
  }); }

  function setAll(open) { $$('details').forEach(function (d) { d.open = open; }); }
  var ex = $('#expand'), co = $('#collapse');
  if (ex) { ex.addEventListener('click', function () { setAll(true); }); }
  if (co) { co.addEventListener('click', function () { setAll(false); }); }

  function copy(text, el) {
    function done() { el.classList.add('copied'); var old = el.getAttribute('data-label') || el.textContent;
      el.setAttribute('data-label', old); el.textContent = 'copied'; setTimeout(function () { el.classList.remove('copied'); el.textContent = old; }, 900); }
    if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text).then(done, done); return; }
    var t = document.createElement('textarea'); t.value = text; document.body.appendChild(t); t.select();
    try { document.execCommand('copy'); } catch (e) { /* nothing to do */ } t.remove(); done();
  }
  $$('[data-copy]').forEach(function (el) {
    function go() { copy(el.getAttribute('data-copy'), el); }
    el.addEventListener('click', go);
    el.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
  });

  $$('.node[data-target]').forEach(function (n) {
    function go() { var t = document.getElementById(n.getAttribute('data-target'));
      if (t) { if (t.tagName === 'DETAILS') { t.open = true; } t.scrollIntoView({ behavior: 'smooth', block: 'start' }); } }
    n.addEventListener('click', go);
    n.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
  });

  var rows = $$('#call-table tbody tr[data-tactic]'), q = $('#filter'), off = {};
  function apply() {
    var term = q ? q.value.toLowerCase() : '', shown = 0;
    rows.forEach(function (r) { var ok = !off[r.getAttribute('data-tactic')] && (!term || r.textContent.toLowerCase().indexOf(term) >= 0);
      r.hidden = !ok; if (ok) { shown++; } });
    var c = $('#count'); if (c) { c.textContent = shown + ' of ' + rows.length + ' calls'; }
  }
  if (q) { q.addEventListener('input', apply); }
  $$('button.chip[data-tactic]').forEach(function (b) { b.addEventListener('click', function () {
    var t = b.getAttribute('data-tactic'); off[t] = !off[t]; b.classList.toggle('off', !!off[t]); apply(); }); });

  var boxes = $$('.step input[type=checkbox]'), bar = $('#progress'), lab = $('#progress-label');
  var key = 'czee-steps-' + (document.body.getAttribute('data-scope') || ''), state = {};
  try { state = JSON.parse(store(key) || '{}') || {}; } catch (e) { state = {}; }
  function refresh() { var n = 0; boxes.forEach(function (b) { var s = b.closest('.step'); if (b.checked) { n++; } s.classList.toggle('done', b.checked); });
    if (bar) { bar.max = boxes.length; bar.value = n; } if (lab) { lab.textContent = n + ' of ' + boxes.length + ' steps done'; } }
  boxes.forEach(function (b) { b.checked = !!state[b.getAttribute('data-step')];
    b.addEventListener('change', function () { state[b.getAttribute('data-step')] = b.checked; store(key, JSON.stringify(state)); refresh(); }); });
  refresh(); apply();

  var was = [];
  window.addEventListener('beforeprint', function () { was = $$('details').map(function (d) { return d.open; }); setAll(true); });
  window.addEventListener('afterprint', function () { $$('details').forEach(function (d, i) { d.open = was[i]; }); });
}());
"""
