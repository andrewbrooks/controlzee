"""`report.html`: the same report as `report.md`, as one self-contained page: no network, no library, one file.

What it adds to the Markdown: a diagram of how the attacker moved and a swimlane timeline (both plain SVG), click to
copy event ids and commands, a filter on the call table, a checklist that remembers what was done, expand all, and a
light, printable styling. It reads fine without its script.

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
from controlzee.diagrams import attack_svg, killchain_svg, marker_svg, tactic_class, timeline_svg
from controlzee.facts import MAX_NODES, Issued, collect_identities, evidence_rows
from controlzee.model.plan import Plan, PlanAction
from controlzee.model.scope import Scope
from controlzee.model.timeline import Timeline
from controlzee.plan import PHASES, build_plan
from controlzee.planlink import steps_by_actor
from controlzee.shellwrap import wrap
from controlzee.story import MAX_MOMENTS, Moment, build_moments
from controlzee.timeline import build_timeline
from controlzee.timeutil import parse_time_us
from controlzee.visual import Graph, build_graph, glance_points, h, headline

_LOGO = ('<svg class="logo" viewBox="0 0 26 22" role="img" aria-label="Ctrl+Z keycap"><rect class="key" x="1" y="1" width="24" height="20" rx="4"/>'
         '<path class="glyph" d="M5.5 11 L8.5 7.5 L11.5 11"/><path class="glyph" d="M14.5 7 H20.5 L14.5 15 H20.5"/></svg>')
_PHASE_TITLES = {"contain": "Contain", "investigate": "Investigate", "eradicate": "Eradicate", "recover": "Recover"}
_NAV = {"glance": "At a glance", "path": "Attack path", "swimlanes": "Timeline", "identities": "Identities", "coverage": "Coverage",
        "sequence": "Sequence of events", "calls": "Calls", "exposure": "Exposure", "plan": "Plan", "appendix": "Appendix"}


def _n(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _hash(text: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def _m(text: object, limit: int = 120) -> str:
    """An identifier (ARN, key id, account, API call) in monospace."""
    return f'<code class="ident">{h(text, limit)}</code>'


def _table(header: list[str], rows: Iterable[list[str]], *, cls: str = "", head: bool = True, mono: tuple[int, ...] = ()) -> str:
    """`mono` lists the columns that hold identifiers, set in monospace."""
    body = "".join("<tr>" + "".join(f'<td class="mono">{c}</td>' if i in mono else f"<td>{c}</td>" for i, c in enumerate(r)) + "</tr>" for r in rows)
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

def _took(seconds: int) -> str:
    if seconds < 60:
        return "under a minute"
    if seconds < 3600:
        return f"{seconds // 60} min"
    return f"{seconds // 3600} h {seconds % 3600 // 60:02d} min"


def _case_header(scope: Scope, tl: Timeline, plan: Plan) -> str:
    """The facts of the case as a definition list: when, where, who, how much, what to do. An account that was reached and sent no
    logs is flagged where the account is named."""
    s = scope.summary
    first, last = s.first_event_time or "", s.last_event_time or ""
    unlogged = {u.account for u in scope.coverage.unlogged_accounts}
    if first and last:
        same_day = first[:10] == last[:10]
        window = (f"{_m(first[:10])}, {_m(first[11:19])} to {_m(last[11:19])} UTC" if same_day
                  else f"{_m(first[:10] + ' ' + first[11:19])} to {_m(last[:10] + ' ' + last[11:19])} UTC")
        took = _took((parse_time_us(last) - parse_time_us(first)) // 1_000_000)
    else:
        window, took = "not known", ""
    accounts = ", ".join(_m(a) + (' <a class="flag" href="#coverage"><span aria-hidden="true">\u25b2</span> no logs from it</a>' if a in unlogged else "")
                         for a in tl.exposure.accounts)
    runnable = sum(1 for a in plan.actions if a.operations)
    rows = [("Incident window", window, took),
            ("Accounts", accounts or "none named", ""),
            ("Identities", f'<a href="#identities">{len(tl.actors)}</a>', f"{len(scope.taint.identities)} credentials followed"),
            ("Events in scope", f'<a href="#calls">{s.events_in_scope}</a>', f"{s.by_confidence.get('strong', 0)} strong, {s.by_confidence.get('weak', 0)} weak"),
            ("Plan steps", f'<a href="#plan">{len(plan.actions)}</a>', f"{runnable} can be run by respond")]
    return '<dl class="case">' + "".join(f'<div><dt>{h(k)}</dt><dd>{v}' + (f'<span class="sub">{h(d)}</span>' if d else "") + "</dd></div>" for k, v, d in rows) + "</dl>"


def _do_first(plan: Plan) -> str:
    contain = [a for a in plan.actions if a.phase == "contain"]
    if not contain:
        return ""
    items = "".join(f'<li><a href="#step-{h(a.id)}">{h(a.id)}</a> {h(a.title)}</li>' for a in contain[:5])
    more = f'<p class="note">and {len(contain) - 5} more containment steps, in <a href="#plan">the response plan</a></p>' if len(contain) > 5 else ""
    return (f'<div class="dofirst"><h3>Do first <span class="note">({_n(len(contain), "containment step", "containment steps")})</span></h3>'
            f'<ol>{items}</ol>{more}</div>')


def _glance(scope: Scope, tl: Timeline, plan: Plan) -> str:
    accounts = ", ".join(_m(a) for a in tl.exposure.accounts)
    out = [_do_first(plan), f'<div class="callout"><p class="lead">{headline(scope, tl, accounts)}</p>']
    points = glance_points(scope, tl)
    out.append('<ul class="points">' + "".join(f'<li class="{sev}"><strong>{h(strong)}</strong>{h(rest)}</li>' for strong, rest, sev in points)
               + "</ul>" if points else '<p class="note">Nothing in the exposure stands out beyond the timeline.</p>')
    weak = sum(1 for e in scope.events if e.confidence.value == "weak")
    if weak:
        out.append(f'<p class="note">{_n(weak, "event is", "events are")} in scope on weak evidence only: confirm them before acting on them.</p>')
    out.append("</div>")
    return "".join(out) + _kill_chain(tl)


def _kill_chain(tl: Timeline) -> str:
    strip = killchain_svg(tl)
    if not strip:
        return ""
    other = next((t for t in tl.tactics if t.tactic == "other"), None)
    extra = f' {_n(other.events + other.failed, "call is", "calls are")} not in any of these tactics.' if other else ""
    return (f'<h3 class="sub">Tactics used</h3><p class="note">The ATT&amp;CK tactics controlzee can tell apart, in the framework\'s order, with the number of '
            f'calls under each. Filled: used. Hollow: not seen.{extra}</p>{strip}')


_MARKS = {"start": "\u25cf", "issued": "\u25c6", "privilege": "\u2191", "tamper": "\u2298", "secrets": "\u2605", "instance": "\u2726"}


def _after(seconds: int) -> str:
    if seconds < 1:
        return "in the same second"
    if seconds < 60:
        return f"{seconds} s later"
    if seconds < 3600:
        return f"{seconds // 60} min later"
    return f"{seconds // 3600} h {seconds % 3600 // 60} min later"


def _sequence(moments: list[Moment], call_ids: dict[str, str]) -> str:
    """"Sequence of events": the key moments as a numbered log, time in the left gutter, then what happened, the call and who made it,
    then the time since the previous one. Each is a plain link to its row in Calls. A moment that needs attention has an icon and the
    attention colour, and the icon comes with words for those who cannot see it. Empty when there is no story."""
    if not moments:
        return ""
    shown = moments[:MAX_MOMENTS]
    many_days = shown[0].time[:10] != shown[-1].time[:10]
    items = []
    for i, m in enumerate(shown):
        prev = shown[i - 1] if i else None
        flag = '<span class="flag"><span aria-hidden="true">\u25b2</span><span class="vh">Needs attention: </span></span> ' if m.hot else ""
        count = f' <span class="mn">&times;{m.count}</span>' if m.count > 1 else ""
        first = ' <span class="mg">(the first call that matched an indicator)</span>' if m.first else ""
        when = f"{m.time[5:10]} {m.time[11:19]}" if many_days else m.time[11:19]
        body = (f'<span class="ev-t">{h(when)}</span><span class="ev-n" aria-hidden="true">{i + 1}</span>'
                f'<span class="ev-m"><span class="ev-i" aria-hidden="true">{_MARKS[m.kind]}</span>{flag}<strong>{h(m.title, 80)}</strong>{count}{first} '
                f'{_m(m.detail, 140)} <span class="mg">by</span> {_m(m.actor, 60)}</span>'
                f'<span class="ev-r">{_after((m.t_us - prev.end_us) // 1_000_000) if prev else "start"}</span>')
        row = call_ids.get(m.event_id)
        inner = f'<a href="#{row}">{body}</a>' if row else f'<span class="row">{body}</span>'
        items.append(f'<li class="ev{" hot" if m.hot else ""}">{inner}</li>')
    if len(moments) > len(shown):
        items.append(f'<li class="ev more"><a href="#calls">+{len(moments) - len(shown)} more moments: see Calls</a></li>')
    return ('<p class="note">The key moments in time order, times in UTC. Click one to see its call. '
            'A triangle: something that needs attention.</p>'
            f'<ol class="log" aria-label="Key moments in time order">{"".join(items)}</ol>')


def _arrows(g: Graph, numbers: dict[str, int]) -> str:
    """What each arrow of the graph is, as a list under it: the number of the step in the sequence of events that issued it (a dash when it
    is not one of the steps shown), the call, who made it and what it handed over. The same facts as the picture, in text."""
    rows: list[tuple[int | None, str, str, str]] = []
    for k, (a, b, call) in enumerate(g.edges):
        rows.append((numbers.get(g.edge_ids[k]) if k < len(g.edge_ids) else None, call, g.nodes[a].label, g.nodes[b].label))
    for k, (src, what, call) in enumerate(g.unused):
        rows.append((numbers.get(g.unused_ids[k]) if k < len(g.unused_ids) else None, call, g.nodes[src].label, what))
    for k, (src, acct, call) in enumerate(g.ghosts):
        rows.append((numbers.get(g.ghost_ids[k]) if k < len(g.ghost_ids) else None, call, g.nodes[src].label, f"{acct} (no logs)"))
    rows.sort(key=lambda r: (r[0] is None, r[0] or 0))
    return ('<ul class="arrows" aria-label="The arrows of the picture">' + "".join(
        f'<li><span class="no">{n if n is not None else "&ndash;"}</span> {_m(call, 60)} <span class="mg">from</span> {_m(src, 60)} '
        f'<span class="mg">to</span> {_m(dst, 60)}</li>' for n, call, src, dst in rows) + "</ul>")


def _identity_anchor(i: int) -> str:
    return f"identity-{i}"


def _issued(i: Issued) -> str:
    when = f"The call <code>{h(i.rule)}</code>, made by <strong class='m-id'>{h(i.by)}</strong> at {h(i.time)}" + (f" from {_m(i.ip)}" if i.ip else "") + "."
    return f"<p><strong>How it came about.</strong> {when}</p>" + (_kv(i.params) if i.params else '<p class="note">No parameters were logged for it.</p>')


def _identities(scope: Scope, tl: Timeline) -> str:
    identities, unused = collect_identities(scope, tl)
    out = ['<p class="note">Open one to see who it is, how it came about (the call that created or handed it over, with the parameters that '
           "were logged) and what it did. Secrets are never shown, and environment variables show their names only.</p>"]
    for i, f in enumerate(identities):
        kind = "matched an indicator" if f.matched else "followed"
        title = (f'<strong class="m-id">{h(f.label)}</strong> <span class="badge">{_n(f.calls, "call", "calls")}</span> <span class="badge">{kind}</span>'
                 + (f' <span class="badge">{h(f.what)}</span>' if f.what else ""))
        body = _kv(f.who)
        if f.matched:
            body += f'<p><strong>Matched</strong> the indicator{"s" if len(f.matched) != 1 else ""} ' + ", ".join(f"<code>{h(m)}</code>" for m in f.matched) + ".</p>"
        body += "".join(_issued(x) for x in f.issued)
        body += f"<p><strong>What it did</strong> ({_n(f.calls, 'call', 'calls')})</p>" + _table(
            ["Time", "Call", "Target", "Result", "Parameters (writes)"],
            [[h(d.time), h(d.call), h(d.target, 200), h(d.result), h(d.params, 240)] for d in f.did], mono=(0, 1, 2, 4))
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
            [[h(g.account), h(g.region), h(g.start), h(g.end), str(g.minutes), h(g.possible_cause or "")] for g in cov.gaps], mono=(0, 1, 2, 3, 5)), open_=len(cov.gaps) <= 5))
    if cov.tampering:
        body = _table(["Time", "Call", "Effect", "By", "Result", "Attacker"],
                      [[h(t.event_time), h(f"{t.event_source.split('.', 1)[0]}:{t.event_name}"), h(t.effect), h(t.principal or ""),
                        h(t.error_code or "ok"), "yes" if t.in_scope else "no"] for t in cov.tampering], mono=(0, 1, 3))
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
        rows.append(f'<tr{rid} data-tactic="{tk}"><td class="nowrap mono">{h(e.time)}</td><td class="mono">{h(e.actor, 80)}</td><td class="mono">{h(e.action)}</td>'
                    f'<td class="mono">{h("; ".join(e.targets), 300)}</td><td>{h(e.outcome)}</td><td>{_chip(tk, tactic)}</td>'
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
             for p in x.privilege_changes], mono=(0, 1, 2, 3)), open_=len(x.privilege_changes) <= 8))
    if x.instance_role_use:
        out.append("<p><strong>Instance role credentials used from more than one address</strong> (an instance calls from its own address):</p>" + _table(
            ["Instance", "Region", "Address", "Calls", "First seen", "Actions"],
            [[h(u.instance), h(u.region), h(a.address), str(a.events), h(a.first_event_time), h(", ".join(a.actions), 300)]
             for u in x.instance_role_use for a in u.addresses], mono=(0, 1, 2, 4, 5)))
    if x.resources:
        out.append(_fold(f"Resources touched ({len(x.resources)})", _table(
            ["Service", "Type", "Name", "Access", "Calls", "Refused", "Actions"],
            [[h(r.service), h(r.type), h(r.name, 300), h(r.access), str(r.events), str(r.failed), h(", ".join(r.actions), 300)]
             for r in x.resources], mono=(2, 6)), open_=len(x.resources) <= 8))
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
                 _table(["When (UTC)", "Who", "Call", "Target", "Result", "Event (click to copy)"], cells, mono=(0, 1, 2, 3)), open_=False)


def _command(c: str) -> tuple[str, str]:
    """A command for the page and for the Copy button: laid out over lines (see shellwrap), escaped line by line."""
    lines = wrap(c).split("\n")
    return "\n".join(h(x, 4000) for x in lines), "&#10;".join(h(x, 4000) for x in lines)


def _step(a: PlanAction, scope: Scope, identities: dict[str, str]) -> str:
    """`identities` maps the labels of the identities this step is about to the ids of their blocks."""
    runs = ('<span class="badge run"><span aria-hidden="true">\u25b6</span> respond can do this</span>' if a.operations and not a.on_request and not a.disruptive else
            '<span class="badge run"><span aria-hidden="true">\u25b6</span> respond can do this, when named with --steps</span>' if a.operations and a.on_request else
            '<span class="badge danger"><span aria-hidden="true">\u25b2</span> respond can do this, with --allow-disruptive</span>' if a.operations else
            '<span class="badge"><span aria-hidden="true">\u270b</span> manual</span>')
    weak = ' <span class="badge">weak evidence: confirm first</span>' if a.confidence.value == "weak" else ""
    nodes = f' data-nodes="{h(" ".join(identities.values()), 300)}"' if identities else ""
    out = [f'<article class="step" id="step-{h(a.id)}" data-phase="{h(a.phase)}"{nodes}><div class="step-head"><input type="checkbox" data-step="{h(a.id)}" aria-label="Done: {h(a.id)}">'
           f'<span class="sid">{h(a.id)}</span><h3>{h(a.title)}</h3>{runs}{weak}</div>',
           f'<p class="target">{h(a.target, 300)}</p><p class="why">{h(a.why, 600)}</p>']
    if identities:
        out.append('<p class="concerns">About the identity ' + ", ".join(f'<a href="#{h(i)}">{_m(label, 80)}</a>' for label, i in identities.items())
                   + " in the picture above.</p>")
    if a.caution:
        out.append(f'<p class="caution"><strong>Caution:</strong> {h(a.caution, 600)}</p>')
    if a.commands:
        shown = [_command(c) for c in a.commands]
        out.append(f'<div class="cmd"><pre><code>{chr(10).join(t for t, _ in shown)}</code></pre>'
                   f'<button data-copy="{"&#10;".join(c for _, c in shown)}">Copy</button></div>')
    out.append(_evidence(a.evidence, scope) if a.evidence else "")
    out.append("</article>")
    return "".join(out)


def _plan(plan: Plan, scope: Scope, identities: dict[str, dict[str, str]]) -> str:
    """The response plan: a phase bar that stays in view and shows how far each phase is, then the steps by phase."""
    phases = [(phase, [a for a in plan.actions if a.phase == phase]) for phase in PHASES]
    phases = [(phase, steps) for phase, steps in phases if steps]
    bar = ('<nav class="phasebar" aria-label="Plan phases">' + '<span class="arr" aria-hidden="true">\u2192</span>'.join(
        f'<a href="#phase-{phase}" data-phase="{phase}"><span class="pt">{_PHASE_TITLES[phase]}</span> '
        f'<span class="pc">{_n(len(steps), "step", "steps")}</span><progress class="pbar" value="0" max="{len(steps)}"></progress></a>'
        for phase, steps in phases) + "</nav>")
    out = ['<div class="progress"><progress id="progress" value="0" max="1"></progress><span class="note" id="progress-label"></span></div>', bar,
           '<ul class="note">' + "".join(f"<li>{h(n, 400)}</li>" for n in plan.notes) + "</ul>"]
    if any(identities.values()):
        out.append('<p class="note">Hover over or tab to a step that is about an identity in the picture of how the attacker moved, and that identity '
                   "is outlined there; hover over an identity to see the steps about it.</p>")
    for phase, steps in phases:
        out.append(f'<h3 class="phase-title" id="phase-{phase}">{_PHASE_TITLES[phase]}</h3>' + "".join(_step(a, scope, identities.get(a.id, {})) for a in steps))
    return "".join(out)


def _appendix(scope: Scope) -> str:
    i = scope.inputs
    body = ["<p><strong>Indicators</strong></p>" + _table(["Name", "Kind", "Value", "Match"],
            [[h(x.name), h(x.kind.value), h(x.value, 300), h(x.match)] for x in scope.seeds.indicators], mono=(2,)),
            f"<p>Expression: <code>{h(scope.seeds.expression, 600)}</code></p>"]
    if scope.seeds.window:
        body.append(f"<p>Window: {h(scope.seeds.window.start or 'open')} to {h(scope.seeds.window.end or 'open')}</p>")
    if scope.taint.identities:
        body.append("<p><strong>Followed identities</strong></p>" + _table(["Kind", "Value", "Issued by", "At", "Events", "Confidence"],
                    [[h(t.kind), h(t.value), h(t.rule), h(t.issued_at), str(t.events), h(t.confidence.value)] for t in scope.taint.identities], mono=(1, 2, 3)))
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
        moments = build_moments(scope, tl)
        numbers = {eid: i + 1 for i, m in enumerate(moments[:MAX_MOMENTS]) for eid in m.event_ids}  # arrows and the sequence share their numbers
        anchors = {a.label: _identity_anchor(i) for i, a in enumerate(tl.actors[:MAX_NODES])}
        by_step = steps_by_actor(plan, tl.actors[:MAX_NODES])
        about = {sid: {label: anchors[label] for label in labels if label in anchors} for sid, labels in by_step.items()}
        steps_of: dict[str, list[str]] = {}
        for sid, labels in by_step.items():
            for label in labels:
                steps_of.setdefault(label, []).append(sid)
        sections.append(("glance", "At a glance", _case_header(scope, tl, plan) + _glance(scope, tl, plan)))
        graph = build_graph(scope)
        if graph is not None:
            note = ("Each arrow is a credential or principal one identity created or obtained for another. Its number is the step of the "
                    "sequence of events that issued it, and the list under the picture says what it is. "
                    "Click an identity to jump to its details. A double outline: matched an indicator. A single grey outline: found only by following the attacker. Dashed: "
                    "handed over but never used in these logs. The lines inside an identity are what it changed, deleted or read, by kind "
                    "(a triangle: it was given full control; a star: it read secrets). Dotted: an account that was reached but sent no logs, "
                    "so what happened there is unknown. Drag the lower edge of the picture to make it taller; with scripts on, zoom with the "
                    "buttons or Ctrl+wheel.")
            drawn = attack_svg(graph, anchors, numbers, {label: " ".join(ids) for label, ids in steps_of.items()})
            sections.append(("path", "How the attacker moved", f'<p class="note">{note}</p><div class="gbox"><div class="g-zoom">'
                             '<button type="button" data-gzoom="in" aria-label="Zoom in">+</button>'
                             '<button type="button" data-gzoom="out" aria-label="Zoom out">&minus;</button>'
                             f'<button type="button" data-gzoom="reset">Reset</button></div><div class="gwrap">{drawn}</div></div>'
                             + _arrows(graph, numbers)
                             + (f'<p class="note">{graph.hidden} more identities acted and are not drawn.</p>' if graph.hidden else "")))
        story = _sequence(moments, _call_ids(tl))
        if story:
            sections.append(("sequence", "Sequence of events", story))
        if lanes:
            legend = "".join(f'<span>{marker_svg(_tactic_key(t.tactic))}{h(t.tactic)}</span>' for t in tl.tactics)
            sections.append(("swimlanes", "Timeline", '<p class="note">One lane per identity, one mark per call; the shape and colour say which tactic. '
                             "A dark outline: found by following the attacker. A hollow mark: the call failed. A shaded band: the logs were silent. "
                             "A red diamond: the attacker changed logging or detection. A narrow break in the axis: a long stretch with no activity, "
                             "cut short and labelled with its length. "
                             "Click a mark to jump to its row in Calls; zoom with the buttons, Ctrl+wheel or a double click, and drag to pan."
                             f'</p><div class="scroll tl-wrap"><div class="tl-zoom"><button type="button" data-zoom="in" aria-label="Zoom in">+</button>'
                             '<button type="button" data-zoom="out" aria-label="Zoom out">&minus;</button>'
                             f'<button type="button" data-zoom="reset">Reset</button></div>{lanes}</div><div class="legend">{legend}</div>'))
        sections += [("plan", "Response plan", _plan(plan, scope, about)), ("identities", "Identities", _identities(scope, tl))]
    else:
        sections.append(("glance", "At a glance", '<p class="note">No events matched the indicators.</p>'))
    sections.append(("coverage", "What the logs cannot show", _coverage(scope)))
    if scope.summary.events_in_scope:
        sections += [("exposure", "Exposure", _exposure(tl)), ("calls", "Calls", _calls(tl))]
    sections.append(("appendix", "Appendix", _appendix(scope)))
    nav = "".join(f'<a href="#{i}">{_NAV[i]}</a>' for i, _, _ in sections)
    body = "".join(f'<section id="{i}"><h2>{h(t)}</h2>{content}</section>' for i, t, content in sections)
    csp = (f"default-src 'none'; style-src '{_hash(CSS)}'; script-src '{_hash(JS)}'; img-src data:; base-uri 'none'; form-action 'none'")
    page = (
        f'<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{csp}">\n<title>Incident report · controlzee</title>\n<style>{CSS}</style></head>\n'
        f'<body data-scope="{h(scope.scope_sha256[:16])}">\n'
        f'<header class="top"><div class="brand">{_LOGO}<span class="word">control<span>zee</span></span></div><nav>{nav}</nav><div class="tools">'
        '<button id="expand">Expand all</button><button id="collapse">Collapse all</button></div></header>\n'
        f'<main><h1>Incident report</h1><p class="meta">Generated by controlzee {h(__version__)} from scope {h(scope.scope_sha256[:12])}. All times UTC. '
        f'Everything here is derived from that scope.json; regenerate it rather than editing it.</p>\n{body}\n'
        f'<footer><div>scope {h(scope.scope_sha256)}</div><div>timeline {h(tl.timeline_sha256)}</div><div>plan {h(plan.plan_sha256)}</div></footer></main>\n'
        f'<script>{JS}</script></body></html>\n')
    return page.encode("utf-8")
