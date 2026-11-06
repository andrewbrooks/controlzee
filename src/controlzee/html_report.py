"""`report.html`: the same report as `report.md`, as one self-contained page: no network, no library, one file.

What it adds to the Markdown: a diagram of how the attacker moved and a swimlane timeline (both plain SVG), click to
copy event ids and commands, a filter on the call table, a checklist that remembers what was done, expand all, and a
light or dark theme. It reads fine without its script.

Logs are hostile input. Every value from them goes through `visual.h` (control characters replaced, length capped, every
markup character an entity), class names come from fixed lists, ids from counters, and the page carries a Content
Security Policy that allows only its own stylesheet and script, by hash: if some text were ever left unescaped it still
could not run anything or load anything. The output is byte-identical for the same scope: no clocks, everything sorted.
"""
from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterable

from controlzee import __version__
from controlzee._html_static import CSS, JS
from controlzee.classify import TACTIC_ORDER
from controlzee.diagrams import attack_svg, tactic_bar_svg, tactic_class, timeline_svg
from controlzee.facts import MAX_NODES, Issued, collect_identities, evidence_rows
from controlzee.model.plan import Plan, PlanAction
from controlzee.model.scope import Scope
from controlzee.model.timeline import Timeline
from controlzee.plan import PHASES, build_plan
from controlzee.story import MAX_MOMENTS, Moment, build_moments
from controlzee.timeline import build_timeline
from controlzee.timeutil import parse_time_us
from controlzee.visual import build_graph, glance_points, h, headline

_PHASE_TITLES = {"contain": "Contain", "investigate": "Investigate", "eradicate": "Eradicate", "recover": "Recover"}
_NAV = {"glance": "At a glance", "path": "Attack path", "swimlanes": "Timeline", "identities": "Identities", "coverage": "Coverage",
        "calls": "Calls", "exposure": "Exposure", "plan": "Plan", "appendix": "Appendix"}


def _n(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _hash(text: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def _table(header: list[str], rows: Iterable[list[str]], *, cls: str = "", head: bool = True) -> str:
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    thead = "<thead><tr>" + "".join(f"<th>{c}</th>" for c in header) + "</tr></thead>" if head else ""
    attr = f' class="{cls}"' if cls else ""
    return f'<div class="scroll"><table{attr}>{thead}<tbody>{body}</tbody></table></div>'


def _kv(pairs: list[tuple[str, str]]) -> str:
    return '<div class="scroll"><table class="kv"><tbody>' + "".join(
        f"<tr><th>{h(k, 80)}</th><td>{h(v, 300)}</td></tr>" for k, v in pairs) + "</tbody></table></div>"


def _fold(title_html: str, body: str, *, open_: bool, id_: str = "") -> str:
    ident = f' id="{id_}"' if id_ else ""
    return f'<details{ident}{" open" if open_ else ""}><summary>{title_html}</summary><div class="body">{body}</div></details>'


def _chip(tactic: str, text: str) -> str:
    return f'<span class="chip {tactic_class(tactic)}">{h(text)}</span>'


def _tactic_key(tactic: str) -> str:
    return tactic if tactic in TACTIC_ORDER else "other"


# ---- sections

def _cards(scope: Scope, tl: Timeline, plan: Plan, lanes: bool) -> str:
    """The figures at the top, each a link to the section that backs it. A tile that needs attention (full control granted, secrets
    read, logging changed, accounts without logs) exists only when its count is not zero, and says so in words as well as colour."""
    s = scope.summary
    first, last = s.first_event_time, s.last_event_time
    minutes = (parse_time_us(last) - parse_time_us(first)) // 60_000_000 if first and last else 0
    x, cov = tl.exposure, scope.coverage
    # (number, label, detail, section it links to, needs attention)
    cards = [(str(s.events_in_scope), "events in scope", f"{s.by_confidence.get('strong', 0)} strong, {s.by_confidence.get('weak', 0)} weak", "calls", False),
             (str(len(tl.actors)), "identities", f"{len(scope.taint.identities)} credentials followed", "identities", False),
             ("<1" if minutes < 1 else str(minutes), "minute" if minutes == 1 else "minutes", f"{h(first or '')[:10]}", "swimlanes" if lanes else "calls", False),
             (str(len(x.accounts)), "account" if len(x.accounts) == 1 else "accounts", "", "exposure", False),
             (str(len(plan.actions)), "plan steps", f"{sum(1 for a in plan.actions if a.operations)} can be run by respond", "plan", False)]
    if x.admin_granted:
        cards.append((str(sum(1 for p in x.privilege_changes if p.admin)), "full control granted", "permission changes", "exposure", True))
    if x.credentials_read:
        cards.append((str(len(x.credentials_read)), "secrets read", "treat as known", "exposure", True))
    if (tampered := sum(1 for t in cov.tampering if t.in_scope)):
        cards.append((str(tampered), "logging changes", "by the attacker", "coverage", True))
    if cov.unlogged_accounts:
        cards.append((str(len(cov.unlogged_accounts)), "accounts without logs", "reached, unseen", "coverage", True))
    return '<div class="cards">' + "".join(
        f'<a class="card{" alert" if alert else ""}" href="#{target}"><div class="n">{h(n)}</div><div class="l">{h(label)}</div>'
        + (f'<div class="l">{d}</div>' if d else "") + "</a>"
        for n, label, d, target, alert in cards) + "</div>"


def _glance(scope: Scope, tl: Timeline, plan: Plan) -> str:
    accounts = ", ".join(h(a) for a in tl.exposure.accounts)
    out = [f'<div class="callout"><p class="lead">{headline(scope, tl, accounts)}</p>']
    points = glance_points(scope, tl)
    out.append('<ul class="points">' + "".join(f'<li class="{sev}"><strong>{h(strong)}</strong>{h(rest)}</li>' for strong, rest, sev in points)
               + "</ul>" if points else '<p class="note">Nothing in the exposure stands out beyond the timeline.</p>')
    contain = [a for a in plan.actions if a.phase == "contain"]
    if contain:
        items = "".join(f'<li><a href="#step-{h(a.id)}">{h(a.id)}</a> {h(a.title)}</li>' for a in contain[:5])
        more = f'<p class="note">and {len(contain) - 5} more containment steps</p>' if len(contain) > 5 else ""
        out.append(f'<div class="first"><strong>Do first</strong> ({_n(len(contain), "containment step", "containment steps")})<ol>{items}</ol>{more}</div>')
    weak = sum(1 for e in scope.events if e.confidence.value == "weak")
    if weak:
        out.append(f'<p class="note">{_n(weak, "event is", "events are")} in scope on weak evidence only: confirm them before acting on them.</p>')
    out.append("</div>")
    chips = "".join(_chip(_tactic_key(t.tactic), f"{t.tactic} ×{t.events}") for t in tl.tactics)
    return "".join(out) + tactic_bar_svg(tl) + f'<div class="chips">{chips}</div>'


_MARKS = {"start": "\u25cf", "issued": "\u25c6", "privilege": "\u25b2", "tamper": "\u25a0", "secrets": "\u2605", "instance": "\u2726"}


def _after(seconds: int) -> str:
    if seconds < 1:
        return "in the same second"
    if seconds < 60:
        return f"{seconds} s later"
    if seconds < 3600:
        return f"{seconds // 60} min later"
    return f"{seconds // 3600} h {seconds % 3600 // 60} min later"


def _story(moments: list[Moment], call_ids: dict[str, str]) -> str:
    """"How it unfolded": the key moments in time order as plain links to their rows in Calls, with the time since the previous one.
    Each has a shape and a word as well as a colour, and the ones that need attention say so in a border. Empty when there is no story."""
    if not moments:
        return ""
    shown = moments[:MAX_MOMENTS]
    items = []
    for i, m in enumerate(shown):
        prev = shown[i - 1] if i else None
        title = h(m.title, 80) + (f' <span class="mn">&times;{m.count}</span>' if m.count > 1 else "")
        body = (f'<span class="mk" aria-hidden="true">{_MARKS[m.kind]}</span><span class="mt">{title}</span>'
                f'<span class="md">{h(m.detail, 140)}</span><span class="mw">{h(m.time[11:19])} UTC &middot; {h(m.actor, 60)}</span>')
        body += f'<span class="mg">{_after((m.t_us - prev.end_us) // 1_000_000)}</span>' if prev else '<span class="mg">start</span>'
        if m.first:
            body += '<span class="mg">first call that matched an indicator</span>'
        row = call_ids.get(m.event_id)
        inner = f'<a href="#{row}">{body}</a>' if row else f"<span>{body}</span>"
        items.append(f'<li class="m m-{m.kind}{" hot" if m.hot else ""}">{inner}</li>')
    if len(moments) > len(shown):
        items.append(f'<li class="m more"><a href="#calls">+{len(moments) - len(shown)} more moments: see Calls</a></li>')
    return ('<h3 class="sub">How it unfolded</h3><p class="note">The key moments in time order. Click one to see its call. '
            'A heavy border: something that needs attention.</p>'
            f'<ol class="ribbon" aria-label="Key moments in time order">{"".join(items)}</ol>')


def _identity_anchor(i: int) -> str:
    return f"identity-{i}"


def _issued(i: Issued) -> str:
    when = f"The call <code>{h(i.rule)}</code>, made by <strong>{h(i.by)}</strong> at {h(i.time)}" + (f" from {h(i.ip)}" if i.ip else "") + "."
    return f"<p><strong>How it came about.</strong> {when}</p>" + (_kv(i.params) if i.params else '<p class="note">No parameters were logged for it.</p>')


def _identities(scope: Scope, tl: Timeline) -> str:
    identities, unused = collect_identities(scope, tl)
    out = ['<p class="note">Open one to see who it is, how it came about (the call that created or handed it over, with the parameters that '
           "were logged) and what it did. Secrets are never shown, and environment variables show their names only.</p>"]
    for i, f in enumerate(identities):
        kind = "matched an indicator" if f.matched else "followed"
        title = (f'<strong>{h(f.label)}</strong> <span class="badge">{_n(f.calls, "call", "calls")}</span> <span class="badge">{kind}</span>'
                 + (f' <span class="badge">{h(f.what)}</span>' if f.what else ""))
        body = _kv(f.who)
        if f.matched:
            body += f'<p><strong>Matched</strong> the indicator{"s" if len(f.matched) != 1 else ""} ' + ", ".join(f"<code>{h(m)}</code>" for m in f.matched) + ".</p>"
        body += "".join(_issued(x) for x in f.issued)
        body += f"<p><strong>What it did</strong> ({_n(f.calls, 'call', 'calls')})</p>" + _table(
            ["Time", "Call", "Target", "Result", "Parameters (writes)"],
            [[h(d.time), h(d.call), h(d.target, 200), h(d.result), h(d.params, 240)] for d in f.did])
        if f.more:
            body += f'<p class="note">{f.more} more calls are in the call table.</p>'
        out.append(_fold(title, body, open_=False, id_=_identity_anchor(i)))
    for k, u in enumerate(unused):
        out.append(_fold(f'<strong>{h(u.what)}</strong> <span class="badge">never used in these logs</span>', _issued(u.issued), open_=False, id_=f"unused-{k}"))
    return "".join(out)


def _coverage(scope: Scope) -> str:
    cov = scope.coverage
    if not (cov.notes or cov.tampering):
        return '<p class="note">Nothing found: the logs cover the incident period without unusual silences or logging changes.</p>'
    out = ["<ul>" + "".join(f"<li>{h(n, 400)}</li>" for n in cov.notes) + "</ul>"] if cov.notes else []
    if cov.gaps:
        out.append(_fold(f"Silences during the incident ({len(cov.gaps)})", _table(
            ["Account", "Region", "From", "To", "Minutes", "Possible cause"],
            [[h(g.account), h(g.region), h(g.start), h(g.end), str(g.minutes), h(g.possible_cause or "")] for g in cov.gaps]), open_=len(cov.gaps) <= 5))
    if cov.tampering:
        body = _table(["Time", "Call", "Effect", "By", "Result", "Attacker"],
                      [[h(t.event_time), h(f"{t.event_source.split('.', 1)[0]}:{t.event_name}"), h(t.effect), h(t.principal or ""),
                        h(t.error_code or "ok"), "yes" if t.in_scope else "no"] for t in cov.tampering])
        if cov.tampering_total > len(cov.tampering):
            body += f'<p class="note">{cov.tampering_total - len(cov.tampering)} more are counted in scope.json but not listed.</p>'
        out.append(_fold(f"Logging and detection changes, all actors ({len(cov.tampering)})", body, open_=len(cov.tampering) <= 5))
    return "".join(out)


def _call_ids(tl: Timeline) -> dict[str, str]:
    """Event id to the id of its row in the call table, numbered in order (the timeline's marks link to them)."""
    ids = [e.event_id for e in tl.entries if e.kind != "gap" and e.event_id]
    return {event_id: f"call-{n}" for n, event_id in enumerate(ids, 1)}


def _calls(tl: Timeline) -> str:
    ids = _call_ids(tl)
    toolbar = ('<div class="toolbar"><input type="search" id="filter" placeholder="Filter the calls (actor, call, target...)" aria-label="Filter the calls">'
               '<span class="note" id="count"></span></div><div class="chips">'
               + "".join(f'<button class="chip {tactic_class(t.tactic)}" data-tactic="{_tactic_key(t.tactic)}">{h(t.tactic)}</button>' for t in tl.tactics)
               + "</div>")
    rows = []
    for e in tl.entries:
        if e.kind == "gap":
            rows.append(f'<tr class="gap"><td class="nowrap">{h(e.time)}</td><td colspan="6">gap until {h(e.end)}: {h(e.note or "", 400)}</td></tr>')
            continue
        found = "seed" if e.origin == "seed" and not e.via else ("followed" if e.origin == "propagated" else "seed, followed")
        tactic = e.tactic or "other"
        tk = _tactic_key(tactic)
        rid = f' id="{ids[e.event_id]}"' if e.event_id in ids else ""
        rows.append(f'<tr{rid} data-tactic="{tk}"><td class="nowrap">{h(e.time)}</td><td>{h(e.actor, 80)}</td><td>{h(e.action)}</td>'
                    f'<td>{h("; ".join(e.targets), 300)}</td><td>{h(e.outcome)}</td><td>{_chip(tk, tactic)}</td>'
                    f'<td>{h(found)} ({h(e.confidence.value if e.confidence else "")})</td></tr>')
    table = ('<div class="scroll"><table id="call-table"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>Tactic</th>'
             "<th>Found by</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>")
    return toolbar + _fold(f"Every in-scope call, in order ({len(tl.entries)})", table, open_=len(tl.entries) <= 25)


def _exposure(tl: Timeline) -> str:
    x = tl.exposure
    out = ["<ul>" + "".join(f"<li>{h(n, 400)}</li>" for n in x.notes) + "</ul>"] if x.notes else []
    if x.privilege_changes:
        out.append(_fold(f"Permission changes ({len(x.privilege_changes)})", _table(
            ["Time", "Change", "Principal", "Policy", "Full control", "Result"],
            [[h(p.time), h(p.action), h(p.principal), h(p.policy or ""), "<strong>yes</strong>" if p.admin else "no", h(p.outcome)]
             for p in x.privilege_changes]), open_=len(x.privilege_changes) <= 8))
    if x.instance_role_use:
        out.append("<p><strong>Instance role credentials used from more than one address</strong> (an instance calls from its own address):</p>" + _table(
            ["Instance", "Region", "Address", "Calls", "First seen", "Actions"],
            [[h(u.instance), h(u.region), h(a.address), str(a.events), h(a.first_event_time), h(", ".join(a.actions), 300)]
             for u in x.instance_role_use for a in u.addresses]))
    if x.resources:
        out.append(_fold(f"Resources touched ({len(x.resources)})", _table(
            ["Service", "Type", "Name", "Access", "Calls", "Refused", "Actions"],
            [[h(r.service), h(r.type), h(r.name, 300), h(r.access), str(r.events), str(r.failed), h(", ".join(r.actions), 300)]
             for r in x.resources]), open_=len(x.resources) <= 8))
    return "".join(out) or '<p class="note">No resources were named in the in-scope calls.</p>'


def _evidence(ids: list[str], scope: Scope) -> str:
    rows, _shown = evidence_rows(ids, scope)
    if not rows:
        return ""
    cells = []
    for r in rows:
        code = f'<code class="id" data-copy="{h(r.ids[0], 200)}" title="Click to copy the full event ID" tabindex="0">{h(r.ids[0][:8])}</code>'
        if len(r.ids) > 1:
            code += f' <code class="id" data-copy="{"&#10;".join(h(i, 200) for i in r.ids)}" title="Click to copy all {len(r.ids)} event IDs">+{len(r.ids) - 1}</code>'
        cells.append([h(r.when), h(r.who, 80), h(r.call) + (f" ×{r.count}" if r.count > 1 else ""), h(r.target, 160), h(r.result), code])
    return _fold(f"Evidence from {_n(sum(len(r.ids) for r in rows), 'call', 'calls')}",
                 _table(["When (UTC)", "Who", "Call", "Target", "Result", "Event (click to copy)"], cells), open_=False)


def _step(a: PlanAction, scope: Scope) -> str:
    runs = ('<span class="badge run">respond can do this</span>' if a.operations and not a.on_request and not a.disruptive else
            '<span class="badge run">respond can do this, when named with --steps</span>' if a.operations and a.on_request else
            '<span class="badge danger">respond can do this, with --allow-disruptive</span>' if a.operations else '<span class="badge">manual</span>')
    weak = ' <span class="badge">weak evidence: confirm first</span>' if a.confidence.value == "weak" else ""
    out = [f'<article class="step" id="step-{h(a.id)}"><div class="step-head"><input type="checkbox" data-step="{h(a.id)}" aria-label="Done: {h(a.id)}">'
           f'<span class="sid">{h(a.id)}</span><h3>{h(a.title)}</h3>{runs}{weak}</div>',
           f'<p class="target">{h(a.target, 300)}</p><p class="why">{h(a.why, 600)}</p>']
    if a.caution:
        out.append(f'<p class="caution"><strong>Caution:</strong> {h(a.caution, 600)}</p>')
    if a.commands:
        text = "\n".join(h(c, 4000) for c in a.commands)
        out.append(f'<div class="cmd"><pre><code>{text}</code></pre><button data-copy="{"&#10;".join(h(c, 4000) for c in a.commands)}">Copy</button></div>')
    out.append(_evidence(a.evidence, scope) if a.evidence else "")
    out.append("</article>")
    return "".join(out)


def _plan(plan: Plan, scope: Scope) -> str:
    out = ['<div class="progress"><progress id="progress" value="0" max="1"></progress><span class="note" id="progress-label"></span></div>',
           '<ul class="note">' + "".join(f"<li>{h(n, 400)}</li>" for n in plan.notes) + "</ul>"]
    for phase in PHASES:
        steps = [a for a in plan.actions if a.phase == phase]
        if steps:
            out.append(f'<h3 class="phase-title">{_PHASE_TITLES[phase]}</h3>' + "".join(_step(a, scope) for a in steps))
    return "".join(out)


def _appendix(scope: Scope) -> str:
    i = scope.inputs
    body = ["<p><strong>Indicators</strong></p>" + _table(["Name", "Kind", "Value", "Match"],
            [[h(x.name), h(x.kind.value), h(x.value, 300), h(x.match)] for x in scope.seeds.indicators]),
            f"<p>Expression: <code>{h(scope.seeds.expression, 600)}</code></p>"]
    if scope.seeds.window:
        body.append(f"<p>Window: {h(scope.seeds.window.start or 'open')} to {h(scope.seeds.window.end or 'open')}</p>")
    if scope.taint.identities:
        body.append("<p><strong>Followed identities</strong></p>" + _table(["Kind", "Value", "Issued by", "At", "Events", "Confidence"],
                    [[h(t.kind), h(t.value), h(t.rule), h(t.issued_at), str(t.events), h(t.confidence.value)] for t in scope.taint.identities]))
    body.append(f'<p class="note">Inputs: {i.event_count} events from {i.ingested_files} files ({i.error_files} unreadable, {i.skipped_files} skipped), '
                f'{h(i.first_event_time or "")} to {h(i.last_event_time or "")}; accounts {", ".join(h(a) for a in i.accounts)}; '
                f'manifest sha256 <code>{h(i.manifest_sha256)}</code>.</p>')
    return _fold("Indicators, followed identities and inputs", "".join(body), open_=False)


# ---- the page

def build_html(scope: Scope) -> bytes:
    tl = Timeline.model_validate(build_timeline(scope))
    plan = Plan.model_validate(build_plan(scope))
    sections: list[tuple[str, str, str]] = []
    if scope.summary.events_in_scope:
        lanes = timeline_svg(scope, tl, _call_ids(tl))
        sections.append(("glance", "At a glance", _cards(scope, tl, plan, bool(lanes)) + _glance(scope, tl, plan)
                         + _story(build_moments(scope, tl), _call_ids(tl))))
        graph = build_graph(scope)
        if graph is not None:
            anchors = {a.label: _identity_anchor(i) for i, a in enumerate(tl.actors[:MAX_NODES])}
            note = ("Each arrow is a credential or principal one identity created or obtained for another, labelled with the call that issued it. "
                    "Click an identity to jump to its details. Red: matched an indicator. Blue: found only by following the attacker. Dashed: "
                    "handed over but never used in these logs. The lines inside an identity are what it changed, deleted or read, by kind "
                    "(a triangle: it was given full control; a star: it read secrets). Dotted: an account that was reached but sent no logs, "
                    "so what happened there is unknown.")
            sections.append(("path", "How the attacker moved", f'<p class="note">{note}</p><div class="scroll">{attack_svg(graph, anchors)}</div>'
                             + (f'<p class="note">{graph.hidden} more identities acted and are not drawn.</p>' if graph.hidden else "")))
        if lanes:
            legend = "".join(f'<span><i class="{tactic_class(_tactic_key(t.tactic))}"></i>{h(t.tactic)}</span>' for t in tl.tactics)
            sections.append(("swimlanes", "Timeline", '<p class="note">One lane per identity, one dot per call, coloured by tactic. A ring: found by following the attacker. '
                             "A cross: the call failed. A shaded band: the logs were silent. A red diamond: the attacker changed logging or detection. "
                             "Click a dot to jump to its row in Calls; zoom with the buttons, Ctrl+wheel or a double click, and drag to pan."
                             f'</p><div class="scroll tl-wrap"><div class="tl-zoom"><button type="button" data-zoom="in" aria-label="Zoom in">+</button>'
                             '<button type="button" data-zoom="out" aria-label="Zoom out">&minus;</button>'
                             f'<button type="button" data-zoom="reset">Reset</button></div>{lanes}</div><div class="legend">{legend}</div>'))
        sections.append(("identities", "Identities", _identities(scope, tl)))
    else:
        sections.append(("glance", "At a glance", '<p class="note">No events matched the indicators.</p>'))
    sections += [("coverage", "What the logs cannot show", _coverage(scope))]
    if scope.summary.events_in_scope:
        sections += [("calls", "Calls", _calls(tl)), ("exposure", "Exposure", _exposure(tl)), ("plan", "Response plan", _plan(plan, scope))]
    sections.append(("appendix", "Appendix", _appendix(scope)))
    nav = "".join(f'<a href="#{i}">{_NAV[i]}</a>' for i, _, _ in sections)
    body = "".join(f'<section id="{i}"><h2>{h(t)}</h2>{content}</section>' for i, t, content in sections)
    csp = (f"default-src 'none'; style-src '{_hash(CSS)}'; script-src '{_hash(JS)}'; img-src data:; base-uri 'none'; form-action 'none'")
    page = (
        f'<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{csp}">\n<title>Incident report · controlzee</title>\n<style>{CSS}</style></head>\n'
        f'<body data-scope="{h(scope.scope_sha256[:16])}">\n'
        f'<header class="top"><div class="brand">control<span>zee</span></div><nav>{nav}</nav><div class="tools">'
        '<button id="expand">Expand all</button><button id="collapse">Collapse all</button><button id="theme">Theme</button></div></header>\n'
        f'<main><h1>Incident report</h1><p class="meta">Generated by controlzee {h(__version__)} from scope {h(scope.scope_sha256[:12])}. All times UTC. '
        f'Everything here is derived from that scope.json; regenerate it rather than editing it.</p>\n{body}\n'
        f'<footer><div>scope {h(scope.scope_sha256)}</div><div>timeline {h(tl.timeline_sha256)}</div><div>plan {h(plan.plan_sha256)}</div></footer></main>\n'
        f'<script>{JS}</script></body></html>\n')
    return page.encode("utf-8")
