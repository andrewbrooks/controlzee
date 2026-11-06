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
a.card{display:block;color:inherit;text-decoration:none}a.card:hover{border-color:var(--accent);text-decoration:none}a.card:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.card.alert{border-color:var(--danger);border-left-width:5px}.card.alert .n{color:var(--danger)}.card.alert .n::before{content:"\\25B2";font-size:15px;margin-right:6px;vertical-align:3px}
.callout{border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;background:var(--bg2);padding:14px 18px}
.callout .lead{font-size:16px;margin:0 0 8px}.points{margin:8px 0;padding:0;list-style:none}
.points li{padding:5px 0 5px 22px;position:relative}.points li::before{content:"";position:absolute;left:4px;top:13px;width:9px;height:9px;border-radius:50%;background:var(--danger)}
.points li.info::before{background:var(--accent)}.points strong{font-weight:650}
.first{margin-top:10px;padding-top:10px;border-top:1px dashed var(--line)}.first ol{margin:6px 0 0;padding-left:22px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}
svg.tactic-bar{margin-top:14px}
h3.sub{margin:26px 0 4px}
.chip{display:inline-block;white-space:nowrap;padding:2px 9px;border-radius:999px;font-size:12px;color:#fff;background:var(--c,var(--c-other))}
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
.dot .body{fill:var(--c,var(--c-other))}.dot.prop .body{stroke:var(--fg);stroke-width:1.6}
.dot.fail path{stroke:var(--c,var(--danger));stroke-width:2;fill:none}.dot .hit{fill:transparent}.dot.link{cursor:pointer}
.dot.link:hover .body{stroke:var(--fg);stroke-width:2}.dot.link:hover path{stroke-width:3}
.tl-wrap{position:relative}.tl-zoom{position:absolute;top:6px;left:8px;display:flex;gap:4px;z-index:1}
.tl-zoom button{font:inherit;font-size:12px;line-height:1;padding:3px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);cursor:pointer}
.sb-track{fill:var(--line)}.sb-thumb{fill:var(--mut);opacity:.75;cursor:grab}.sb-thumb:hover{opacity:1}
svg.timeline{user-select:none;-webkit-user-select:none}svg.timeline:not(.zoomed) .sb{visibility:hidden}svg.timeline.zoomed{cursor:grab;touch-action:pan-y}svg.timeline.panning{cursor:grabbing}
.ribbon{list-style:none;margin:10px 0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px}
.m{border:1px solid var(--line);border-left:4px solid var(--c,var(--mut));border-radius:8px;background:var(--bg2)}.m.hot{border-width:2px;border-left-width:6px;border-color:var(--danger)}
.m>a,.m>span{display:grid;grid-template-columns:auto 1fr;column-gap:8px;padding:8px 12px;color:inherit;text-decoration:none;height:100%;align-content:start}
.m>a:hover{background:var(--bg);text-decoration:none}.m>a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.m .mk{grid-row:1;color:var(--c,var(--mut));font-size:13px;line-height:1.5}.m.hot .mk{color:var(--danger)}
.m .mt{font-weight:650;line-height:1.35}.m .mn{color:var(--mut);font-weight:500}
.m .md,.m .mw,.m .mg{grid-column:2;font-size:12.5px;color:var(--mut);overflow-wrap:anywhere}.m .mg{font-style:italic}.m.more{border-left-width:1px;align-self:stretch}
.m-start{--c:var(--accent)}.m-issued{--c:var(--c-persistence)}.m-privilege{--c:var(--c-privilege-escalation)}.m-tamper{--c:var(--c-defense-evasion)}.m-secrets{--c:var(--c-credential-access)}.m-instance{--c:var(--c-initial-access)}
tr.hit td{background:color-mix(in srgb,var(--warn) 30%,transparent)}
.t-initial-access{--c:var(--c-initial-access)}.t-execution{--c:var(--c-execution)}.t-persistence{--c:var(--c-persistence)}
.t-privilege-escalation{--c:var(--c-privilege-escalation)}.t-defense-evasion{--c:var(--c-defense-evasion)}.t-credential-access{--c:var(--c-credential-access)}
.t-discovery{--c:var(--c-discovery)}.t-lateral-movement{--c:var(--c-lateral-movement)}.t-collection{--c:var(--c-collection)}
.t-exfiltration{--c:var(--c-exfiltration)}.t-impact{--c:var(--c-impact)}.t-other{--c:var(--c-other)}
svg.tactic-bar rect{fill:var(--c,var(--c-other))}svg.tactic-bar{width:100%;height:18px;border-radius:4px}
footer{margin-top:60px;padding-top:14px;border-top:1px solid var(--line);color:var(--mut);font-size:12px}
@media print{.ribbon{grid-template-columns:repeat(3,1fr)}.m{break-inside:avoid}header.top,.tools,.toolbar,.tl-zoom,.cmd button{display:none}main{max-width:none;padding:0}details{break-inside:avoid}svg{break-inside:avoid}.step{break-inside:avoid}}
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

  function goRow(id) {
    var r = id && document.getElementById(id); if (!r) { return; }
    var d = r.closest('details'); if (d) { d.open = true; }
    if (r.hidden) { if (q) { q.value = ''; } Object.keys(off).forEach(function (k) { off[k] = false; });
      $$('button.chip[data-tactic]').forEach(function (b) { b.classList.remove('off'); }); apply(); }
    r.scrollIntoView({ behavior: 'smooth', block: 'center' }); r.classList.add('hit');
    setTimeout(function () { r.classList.remove('hit'); }, 2500);
  }

  $$('.ribbon a[href^="#call-"]').forEach(function (a) { a.addEventListener('click', function (e) { e.preventDefault(); goRow(a.getAttribute('href').slice(1)); }); });

  var tl = $('svg.timeline'), moved = false;
  if (tl) {
    tl.addEventListener('click', function (e) {
      if (moved) { moved = false; e.stopPropagation(); return; }
      var d = e.target.closest && e.target.closest('.dot'); if (d) { goRow(d.getAttribute('data-target')); }
    });
    var T0 = +tl.getAttribute('data-t0'), SPAN = +tl.getAttribute('data-span'), G = +tl.getAttribute('data-gutter'), W = +tl.getAttribute('data-plot');
    if (SPAN > 0) { (function () {
      var NS = 'http://www.w3.org/2000/svg', marks = $$('[data-t]', tl), ticks = $('.ticks', tl), note = $('.axis-note', tl), thumb = $('.sb-thumb', tl), track = $('.sb-track', tl);
      var base = +$('.axis', tl).getAttribute('y1'), day = 86400e6, v0 = 0, v1 = 1, MIN = Math.min(1, 1e6 / SPAN), date0 = note.textContent;
      function pad(n) { return (n < 10 ? '0' : '') + n; }
      function fmt(us, view) {
        var d = new Date(us / 1000), hm = pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()), hms = hm + ':' + pad(d.getUTCSeconds());
        return view > 2 * day ? pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + ' ' + hm : view < day ? hms : hm;
      }
      function dur(us) { var s = Math.round(us / 1e6); return s < 120 ? s + 's' : s < 7200 ? Math.floor(s / 60) + 'm ' + (s % 60) + 's' :
        s < 172800 ? Math.floor(s / 3600) + 'h ' + Math.floor(s % 3600 / 60) + 'm' : Math.floor(s / 86400) + 'd'; }
      function X(t) { return G + (t / SPAN - v0) / (v1 - v0) * W; }
      function el(name, attrs, text) { var n = document.createElementNS(NS, name); Object.keys(attrs).forEach(function (k) { n.setAttribute(k, attrs[k]); });
        if (text) { n.textContent = text; } return n; }
      function draw() {
        marks.forEach(function (m) {
          if (m.hasAttribute('data-t2')) { var a = X(+m.getAttribute('data-t')), b = X(+m.getAttribute('data-t2'));
            m.setAttribute('x', a.toFixed(1)); m.setAttribute('width', Math.max(b - a, 2).toFixed(1)); }
          else { m.setAttribute('transform', 'translate(' + X(+m.getAttribute('data-t')).toFixed(1) + ' ' + m.getAttribute('data-y') + ')'); }
        });
        while (ticks.firstChild) { ticks.removeChild(ticks.firstChild); }
        for (var k = 0; k < 6; k++) {
          var tx = (G + W * k / 5).toFixed(1), us = T0 + (v0 + (v1 - v0) * k / 5) * SPAN;
          ticks.appendChild(el('line', { 'class': 'tick', x1: tx, y1: base, x2: tx, y2: base + 5 }));
          ticks.appendChild(el('text', { 'class': 'tick-label', x: tx, y: base + 20, 'text-anchor': k === 0 ? 'start' : k === 5 ? 'end' : 'middle' }, fmt(us, (v1 - v0) * SPAN)));
        }
        var zoomed = v1 - v0 < 0.9999; tl.classList.toggle('zoomed', zoomed);
        thumb.setAttribute('x', (G + v0 * W).toFixed(1)); thumb.setAttribute('width', Math.max((v1 - v0) * W, 14).toFixed(1));
        note.textContent = date0 + (zoomed ? ' \u00b7 showing ' + dur((v1 - v0) * SPAN) + ' of ' + dur(SPAN) : '');
      }
      function zoom(factor, c) {
        var w = Math.min(1, Math.max(MIN, (v1 - v0) / factor)), at = v0 + c * (v1 - v0);
        v0 = Math.min(Math.max(at - c * w, 0), 1 - w); v1 = v0 + w; draw();
      }
      function frac(e) { var p = tl.createSVGPoint(); p.x = e.clientX; p.y = e.clientY; var m = tl.getScreenCTM();
        return m ? Math.min(1, Math.max(0, (p.matrixTransform(m.inverse()).x - G) / W)) : 0.5; }
      $$('[data-zoom]').forEach(function (b) { b.addEventListener('click', function () {
        var z = b.getAttribute('data-zoom'); if (z === 'reset') { v0 = 0; v1 = 1; draw(); } else { zoom(z === 'in' ? 2 : 0.5, 0.5); } }); });
      tl.addEventListener('wheel', function (e) { if (!(e.ctrlKey || e.metaKey)) { return; } e.preventDefault();
        zoom(Math.exp(-Math.max(-60, Math.min(60, e.deltaY)) * 0.01), frac(e)); }, { passive: false });
      tl.addEventListener('dblclick', function (e) { if (!(e.target.closest && e.target.closest('.dot'))) { zoom(2, frac(e)); } });
      var drag = null;
      tl.addEventListener('pointerdown', function (e) { moved = false; drag = e.button === 0 && v1 - v0 < 0.9999 ? { x: e.clientX, v0: v0, w: v1 - v0, id: e.pointerId } : null; });
      tl.addEventListener('pointermove', function (e) {
        if (!drag) { return; } var dx = e.clientX - drag.x, m = tl.getScreenCTM(); if (!m) { return; }
        if (!moved && Math.abs(dx) < 5) { return; }
        if (!moved) { moved = true; tl.classList.add('panning'); try { tl.setPointerCapture(drag.id); } catch (x) { /* no capture: still pans */ } }
        v0 = Math.min(Math.max(drag.v0 - dx / (m.a * W) * drag.w, 0), 1 - drag.w); v1 = v0 + drag.w; draw();
      });
      var sb = null;  // the scroll bar: drag the thumb, or press the track to centre the view there
      thumb.addEventListener('pointerdown', function (e) { e.stopPropagation(); e.preventDefault(); sb = { x: e.clientX, v0: v0, w: v1 - v0 };
        try { thumb.setPointerCapture(e.pointerId); } catch (x) { /* no capture: the track still works */ } });
      thumb.addEventListener('pointermove', function (e) { var m = tl.getScreenCTM(); if (!sb || !m) { return; }
        v0 = Math.min(Math.max(sb.v0 + (e.clientX - sb.x) / (m.a * W), 0), 1 - sb.w); v1 = v0 + sb.w; draw(); });
      thumb.addEventListener('pointerup', function () { sb = null; }); thumb.addEventListener('pointercancel', function () { sb = null; });
      track.addEventListener('pointerdown', function (e) { e.stopPropagation(); e.preventDefault(); var w = v1 - v0;
        v0 = Math.min(Math.max(frac(e) - w / 2, 0), 1 - w); v1 = v0 + w; draw(); });
      function end() { drag = null; tl.classList.remove('panning'); }
      tl.addEventListener('pointerup', end); tl.addEventListener('pointercancel', end);
    }()); }
  }

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
