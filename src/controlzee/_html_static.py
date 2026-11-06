"""The stylesheet and script of the HTML report. Fixed text: nothing from the logs is ever put into either of them.

The page's Content Security Policy allows exactly these two (by their hashes), so even if some log text were ever left
unescaped it could not run a script or load anything. The script only enhances (copy buttons, folding, filtering, a
checklist); the report reads fine without it.
"""
from __future__ import annotations

CSS = """
/* controlzee report: a case file. Light only; paper, ink and one accent. Every colour is a variable here. Red means "needs attention" and nothing else. */
:root{color-scheme:light;
--paper:#FAF8F4;--paper-2:#F2EEE6;--card:#fff;--ink:#1B1A17;--mut:#57524A;--line:#DDD6C8;--line-2:#C4BBA8;
--accent:#0F5C63;--accent-soft:#E2EEEE;--accent-ink:#fff;
--attn:#B3261E;--attn-soft:#FCEDEB;--warn:#8A5A00;--warn-soft:#FFF4D9;--ok:#2F6B3A;
--shadow:0 1px 2px rgba(27,26,23,.07);
--serif:Charter,"Bitstream Charter","Sitka Text",Cambria,Georgia,serif;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
--c-initial-access:#3A86B4;--c-execution:#C0651A;--c-persistence:#4C5FA8;--c-privilege-escalation:#7A5C3E;--c-defense-evasion:#8E4A9E;--c-credential-access:#C99700;
--c-discovery:#7C8FA3;--c-lateral-movement:#2F8F4E;--c-collection:#5A9E8F;--c-exfiltration:#2E4057;--c-impact:#3D3D3D;--c-other:#9A948A}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 var(--sans)}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
code,pre,.mono,.m-id{font-family:var(--mono);font-size:12.5px}
code.ident{background:none;padding:0;overflow-wrap:anywhere}
h1,h2,h3,.brand{font-family:var(--serif)}
header.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:16px;padding:8px 20px;background:var(--paper);border-bottom:1px solid var(--line-2)}
.brand{display:flex;align-items:center;gap:8px;font-weight:700;font-size:17px;letter-spacing:.2px}.brand .word span{color:var(--accent)}
svg.logo{width:30px;height:25px;flex:none;background:none;border:0}svg.logo .key{fill:var(--card);stroke:var(--ink);stroke-width:1.6}svg.logo .glyph{fill:none;stroke:var(--accent);stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}
header.top nav{flex:1;display:flex;gap:2px;overflow-x:auto;white-space:nowrap}
header.top nav a{padding:4px 10px;border-radius:6px;color:var(--mut);font-size:13px}header.top nav a:hover{background:var(--paper-2);color:var(--ink);text-decoration:none}
.tools{display:flex;gap:6px}
button,.btn{font:inherit;font-size:12.5px;padding:4px 10px;border:1px solid var(--line-2);border-radius:6px;background:var(--card);color:var(--ink);cursor:pointer}
button:hover{border-color:var(--accent)}button:focus-visible,summary:focus-visible,.node:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
main{max-width:1120px;margin:0 auto;padding:8px 20px 80px}
section{margin-top:40px;scroll-margin-top:56px}
h1{font-size:32px;margin:28px 0 4px;letter-spacing:-.2px}h2{font-size:22px;margin:0 0 12px;padding-bottom:6px;border-bottom:2px solid var(--ink)}h3{font-size:17px;margin:0}
.meta{color:var(--mut);font-size:13px;margin:0 0 20px}
.callout{border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:6px;background:var(--card);padding:14px 18px}
.callout .lead{font-size:16px;margin:0 0 8px}.points{margin:8px 0;padding:0;list-style:none}
.points li{padding:5px 0 5px 22px;position:relative}.points li::before{content:"\\25B2";position:absolute;left:2px;top:6px;font-size:11px;color:var(--attn)}
.points li.info::before{content:"\\25CF";color:var(--accent)}.points strong{font-weight:650}
.first{margin-top:10px;padding-top:10px;border-top:1px dashed var(--line-2)}.first ol{margin:6px 0 0;padding-left:22px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}
.chip{display:inline-flex;align-items:center;gap:6px;white-space:nowrap;padding:1px 9px;border-radius:999px;font-size:12px;color:var(--ink);background:var(--card);border:1.5px solid var(--c,var(--c-other))}
.chip::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--c,var(--c-other))}
button.chip{font:inherit;font-size:12px;cursor:pointer}button.chip.off{opacity:.45;text-decoration:line-through}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px;background:var(--card)}th,td{border-bottom:1px solid var(--line);padding:5px 10px;text-align:left;vertical-align:top}
th{background:var(--paper-2);position:sticky;top:0;font-weight:600;white-space:nowrap}td.nowrap{white-space:nowrap}td.mono,td.mono code{font-family:var(--mono);font-size:12.5px}
tr.gap td{background:repeating-linear-gradient(45deg,var(--card),var(--card) 6px,var(--paper-2) 6px,var(--paper-2) 12px);color:var(--mut)}
details{border:1px solid var(--line);border-radius:6px;margin:8px 0;background:var(--card)}
details>summary{cursor:pointer;padding:8px 14px;font-weight:500;list-style:none}details>summary::before{content:"\\25B8";display:inline-block;width:1.1em;color:var(--mut)}
details[open]>summary::before{content:"\\25BE"}details>div.body{padding:2px 16px 12px}details[open]>summary{border-bottom:1px solid var(--line)}
.kv{width:auto;margin:8px 0;background:none}.kv th{position:static;background:none;font-weight:500;color:var(--mut);white-space:nowrap}.kv td{font-family:var(--mono);font-size:12.5px}
pre{margin:6px 0;padding:10px 12px;background:var(--card);border:1px solid var(--line-2);border-radius:4px;overflow-x:auto}
.cmd{position:relative}.cmd button{position:absolute;right:8px;top:12px}
code.id{cursor:pointer;border-bottom:1px dotted var(--mut)}code.id:hover{background:var(--paper-2)}code.copied,button.copied{color:var(--ok)}
.progress{display:flex;align-items:center;gap:12px;margin:0 0 12px}.progress progress{flex:1;height:10px;accent-color:var(--accent)}
.step{border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:6px;padding:12px 16px;margin:10px 0;background:var(--card);box-shadow:var(--shadow)}
.step.done{opacity:.65}.step.done h3{text-decoration:line-through}
.step-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.step-head input{width:18px;height:18px;accent-color:var(--accent)}
.sid{font-family:var(--mono);font-weight:700;color:var(--accent)}
.badge{display:inline-block;padding:1px 8px;border-radius:5px;font-size:11.5px;border:1px solid var(--line-2);color:var(--mut);background:var(--card)}
.badge.run{border-color:var(--accent);color:var(--accent)}.badge.danger{border-color:var(--attn);color:var(--attn)}.badge.phase{text-transform:capitalize}
h3.phase-title{color:var(--accent);margin:22px 0 4px}
.target{margin:6px 0 2px;font-weight:500;font-family:var(--mono);font-size:12.5px;overflow-wrap:anywhere}.why{margin:2px 0 6px;color:var(--mut)}
.caution{margin:8px 0;padding:8px 12px;border-left:3px solid var(--warn);background:var(--warn-soft);border-radius:4px;font-size:13.5px}
.toolbar{display:flex;gap:10px;align-items:center;margin:8px 0}.toolbar input[type=search]{flex:1;max-width:340px;padding:5px 10px;border:1px solid var(--line-2);border-radius:6px;background:var(--card);color:var(--ink);font:inherit}
.legend{display:flex;flex-wrap:wrap;gap:14px;color:var(--mut);font-size:12.5px;margin:6px 0}.legend span{display:inline-flex;align-items:center;gap:5px}svg.mk{display:inline-block;background:none;border:0;flex:none}svg.mk path{fill:var(--c,var(--c-other))}
.note{color:var(--mut);font-size:13px}
svg{display:block;max-width:100%;height:auto}
svg.graph,svg.timeline{background:var(--card);border:1px solid var(--line);border-radius:6px}
svg text{font-family:var(--sans);fill:var(--ink)}
.node .box{stroke-width:1.5;fill:var(--card)}
.node.seed .box{stroke:var(--accent);stroke-width:2.5}.node.seed .rim{fill:none;stroke:var(--accent);stroke-width:1.2}
.node.followed .box{fill:var(--paper-2);stroke:var(--mut)}
.node.unused .box{fill:var(--paper);stroke:var(--mut);stroke-dasharray:5 4}
.node.ghost .box{fill:var(--warn-soft);stroke:var(--warn);stroke-dasharray:2 4;stroke-width:2}
.node .name{font-family:var(--mono);font-size:12.5px;font-weight:600}.node .sub{font-size:11px;fill:var(--mut)}
.rc rect{fill:var(--card);stroke:var(--line-2)}.rc text{font-family:var(--mono);font-size:10.5px}.rc.hot rect{stroke:var(--attn);stroke-width:2}.rc.hot text{font-weight:650}.rc-more{font-size:11px;fill:var(--mut)}
.node.link{cursor:pointer}.node.link:hover .box{stroke-width:3}
.edge{fill:none;stroke:var(--mut);stroke-width:1.6}.edge.dashed{stroke-dasharray:5 4}.arrowhead{fill:var(--mut)}
.edge-label-bg{fill:var(--card);stroke:var(--line-2)}.edge-label{font-family:var(--mono);font-size:11px}
.lane{fill:transparent}.lane.alt{fill:var(--paper-2)}.lane-label{font-family:var(--mono);font-size:12px}
.gap rect{fill:var(--warn);opacity:.18}.axis,.tick{stroke:var(--mut);stroke-width:1}.tick-label,.axis-note{font-size:11px;fill:var(--mut)}
.tamper path{fill:var(--attn)}
.dot .body{fill:var(--c,var(--c-other))}.dot.prop .body{stroke:var(--ink);stroke-width:1.8}
.dot.fail .body{fill:var(--card);stroke:var(--c,var(--ink));stroke-width:1.8}.dot.fail.prop .body{stroke:var(--ink)}.dot .hit{fill:transparent}.dot.link{cursor:pointer}
.dot.link:hover .body{stroke:var(--ink);stroke-width:2.4}
.tl-wrap{position:relative}.tl-zoom{position:absolute;top:6px;left:8px;gap:4px;z-index:1}
.tl-zoom button{font:inherit;font-size:12px;line-height:1;padding:3px 8px;border:1px solid var(--line-2);border-radius:6px;background:var(--card);color:var(--ink);cursor:pointer}
.sb-track{fill:var(--line)}.sb-thumb{fill:var(--mut);opacity:.75;cursor:grab}.sb-thumb:hover{opacity:1}
svg.timeline{user-select:none;-webkit-user-select:none}svg.timeline:not(.zoomed) .sb{visibility:hidden}svg.timeline.zoomed{cursor:grab;touch-action:pan-y}svg.timeline.panning{cursor:grabbing}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.flag{color:var(--attn);font-weight:650;white-space:nowrap}a.flag:hover{text-decoration:underline}
dl.case{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));margin:14px 0;background:var(--card);border:1px solid var(--line);border-radius:6px;box-shadow:var(--shadow)}
dl.case>div{padding:10px 16px;border-right:1px solid var(--line);border-bottom:1px solid var(--line);margin:0 -1px -1px 0}
dl.case dt{font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut)}
dl.case dd{margin:2px 0 0;font:500 14.5px/1.45 var(--sans)}dl.case dd code{font-size:13px}dl.case dd>a:first-child:not(.flag){font:700 24px/1.2 var(--serif);color:var(--accent)}
dl.case dd a.flag{display:block;font:600 13px/1.4 var(--sans);color:var(--attn)}
dl.case .sub{display:block;font:400 12.5px/1.4 var(--sans);color:var(--mut)}
h3.sub{margin:26px 0 4px}
svg.killchain{width:100%;height:auto;background:none;border:0;margin:4px 0 8px}
.kc-band{fill:none;stroke:var(--line-2);stroke-dasharray:3 3}.kc-hit .kc-band{fill:var(--c);stroke:var(--c);stroke-dasharray:none}
.kc-name{font-size:12.5px;fill:var(--ink)}.kc-miss .kc-name{fill:var(--mut)}.kc-n{font-size:17px;font-weight:700;fill:var(--ink)}.kc-miss .kc-n{fill:var(--line-2);font-weight:400}
ol.log{list-style:none;margin:10px 0;padding:0;background:var(--card);border:1px solid var(--line);border-radius:6px}
.ev{border-bottom:1px solid var(--line)}.ev:last-child{border-bottom:0}
.ev>a,.ev>.row{display:grid;grid-template-columns:5.2rem 1.6rem 1fr auto;gap:0 10px;align-items:baseline;padding:7px 14px;color:inherit;text-decoration:none}
.ev>a:hover{background:var(--paper-2);text-decoration:none}
.ev-t{font-family:var(--mono);font-size:12.5px;color:var(--mut)}.ev-n{font:700 13px var(--serif);color:var(--accent);text-align:right}
.ev-i{display:inline-block;width:1.2em;color:var(--mut)}.ev-r{font-size:12.5px;font-style:italic;color:var(--mut);white-space:nowrap}
.ev .mn,.ev .mg{color:var(--mut);font-size:12.5px}.ev.hot{background:var(--attn-soft)}.ev.hot>a:hover{background:var(--attn-soft)}
.ev.more>a{display:block}
.gbox{margin:6px 0}.g-zoom{display:none}.js .g-zoom{display:flex;gap:4px;margin:0 0 6px}
.g-zoom button{font:inherit;font-size:12px;line-height:1;padding:3px 8px}
.gwrap{overflow:auto;resize:vertical;min-height:180px;border:1px solid var(--line);border-radius:6px;background:var(--card);text-align:center}
.gwrap svg.graph{display:block;margin:0 auto;border:0;border-radius:0}svg.graph.zoomed{max-width:none}
.tl-zoom{display:none}.js .tl-zoom{display:flex}
.brk rect{fill:var(--paper-2);stroke:var(--mut);stroke-dasharray:3 3}.brk-lab text{font-size:11.5px;font-style:italic;fill:var(--mut)}
tr.hit td{background:var(--warn-soft)}
.t-initial-access{--c:var(--c-initial-access)}.t-execution{--c:var(--c-execution)}.t-persistence{--c:var(--c-persistence)}
.t-privilege-escalation{--c:var(--c-privilege-escalation)}.t-defense-evasion{--c:var(--c-defense-evasion)}.t-credential-access{--c:var(--c-credential-access)}
.t-discovery{--c:var(--c-discovery)}.t-lateral-movement{--c:var(--c-lateral-movement)}.t-collection{--c:var(--c-collection)}
.t-exfiltration{--c:var(--c-exfiltration)}.t-impact{--c:var(--c-impact)}.t-other{--c:var(--c-other)}
footer{margin-top:60px;padding-top:14px;border-top:1px solid var(--line-2);color:var(--mut);font-size:12px;font-family:var(--mono)}
@media print{
:root{--paper:#fff}
body{font-size:11pt;background:var(--card);-webkit-print-color-adjust:exact;print-color-adjust:exact}
header.top,.tools,.toolbar,.tl-zoom,.cmd button,.progress,.step-head input{display:none}
main{max-width:none;padding:0}section{margin-top:22pt}
details{border-color:var(--line-2)}details::details-content{content-visibility:visible;display:block}
details>summary::before{content:""}
h1,h2,h3{break-after:avoid}h2{break-before:auto}
tr,.step,.m,.card,svg,pre,details>summary{break-inside:avoid}thead{display:table-header-group}
.scroll{overflow:visible}th{position:static;white-space:nowrap}td{overflow-wrap:anywhere}td.mono:first-child,td.nowrap{white-space:nowrap}pre{white-space:pre-wrap;overflow-wrap:anywhere}table{font-size:9pt}
a{color:var(--ink)}svg.timeline{user-select:auto}
}
"""

JS = """
(function () {
  'use strict';
  document.documentElement.className += ' js';
  function $(s, c) { return (c || document).querySelector(s); }
  function $$(s, c) { return Array.prototype.slice.call((c || document).querySelectorAll(s)); }
  function store(k, v) { try { if (v === undefined) { return localStorage.getItem(k); } localStorage.setItem(k, v); } catch (e) { return null; } }

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

  $$('.log a[href^="#call-"]').forEach(function (a) { a.addEventListener('click', function (e) { e.preventDefault(); goRow(a.getAttribute('href').slice(1)); }); });

  var gw = $('.gwrap');
  if (gw) { (function () {
    var svg = $('svg.graph', gw), base = +svg.getAttribute('viewBox').split(' ')[2], z = 1;
    function apply() { svg.setAttribute('width', Math.round(Math.min(base, gw.clientWidth) * z)); svg.classList.toggle('zoomed', z !== 1); }
    function set(k) { z = Math.min(3, Math.max(0.5, k)); apply(); }
    $$('[data-gzoom]').forEach(function (b) { b.addEventListener('click', function () {
      var k = b.getAttribute('data-gzoom'); set(k === 'reset' ? 1 : z * (k === 'in' ? 1.25 : 0.8)); }); });
    gw.addEventListener('wheel', function (e) { if (!(e.ctrlKey || e.metaKey)) { return; } e.preventDefault();
      set(z * Math.exp(-Math.max(-60, Math.min(60, e.deltaY)) * 0.01)); }, { passive: false });
    window.addEventListener('resize', apply);
  }()); }

  var tl = $('svg.timeline'), moved = false;
  if (tl) {
    tl.addEventListener('click', function (e) {
      if (moved) { moved = false; e.stopPropagation(); return; }
      var d = e.target.closest && e.target.closest('.dot'); if (d) { goRow(d.getAttribute('data-target')); }
    });
    var T0 = +tl.getAttribute('data-t0'), SPAN = +tl.getAttribute('data-span'), G = +tl.getAttribute('data-gutter'), W = +tl.getAttribute('data-plot');
    var REAL = +(tl.getAttribute('data-real') || SPAN), CUTS = (tl.getAttribute('data-breaks') || '').split(';').filter(Boolean).map(function (c) {
      var q = c.split(','); return { at: +q[0], w: +q[1], gap: +q[2] }; });
    function realAt(v) { var off = 0; for (var i = 0; i < CUTS.length; i++) { var c = CUTS[i]; if (v < c.at) { break; } if (v <= c.at + c.w) { return null; } off += c.gap - c.w; } return v + off; }
    function realLen(a, b) { var n = b - a; CUTS.forEach(function (c) { var ov = Math.max(0, Math.min(b, c.at + c.w) - Math.max(a, c.at)); n += ov / c.w * (c.gap - c.w); }); return n; }
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
          var tx = (G + W * k / 5).toFixed(1), rr = realAt((v0 + (v1 - v0) * k / 5) * SPAN);
          if (rr === null) { continue; }
          var us = T0 + rr;
          ticks.appendChild(el('line', { 'class': 'tick', x1: tx, y1: base, x2: tx, y2: base + 5 }));
          ticks.appendChild(el('text', { 'class': 'tick-label', x: tx, y: base + 20, 'text-anchor': k === 0 ? 'start' : k === 5 ? 'end' : 'middle' }, fmt(us, realLen(v0 * SPAN, v1 * SPAN))));
        }
        var zoomed = v1 - v0 < 0.9999; tl.classList.toggle('zoomed', zoomed);
        thumb.setAttribute('x', (G + v0 * W).toFixed(1)); thumb.setAttribute('width', Math.max((v1 - v0) * W, 14).toFixed(1));
        note.textContent = date0 + (zoomed ? ' \u00b7 showing ' + dur(realLen(v0 * SPAN, v1 * SPAN)) + ' of ' + dur(REAL) : '');
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
