"""SVG pictures for the HTML report: how the attacker moved, who did what when, and the tactic mix.

Drawn here, in plain SVG with CSS classes (the page's stylesheet colours them, in light and dark), so the report needs no
library and no network. The numbers are computed, rounded to one decimal and always printed the same way, so the same
scope gives the same bytes. Every piece of text from the logs goes through `visual.h`, and nothing from the logs is ever
used as an element name, a class or an id: classes come from fixed lists, ids from counters.
"""
from __future__ import annotations

from typing import Final

from controlzee.classify import TACTIC_ORDER, action, resources, tactic
from controlzee.facts import MAX_NODES
from controlzee.model.scope import Scope
from controlzee.model.timeline import Timeline
from controlzee.timeline import actor_label
from controlzee.timeutil import format_time_us, parse_time_us
from controlzee.visual import Graph, h

_TACTICS: Final = frozenset(TACTIC_ORDER)


def _f(x: float) -> str:
    return f"{x:.1f}"


def _cut(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def tactic_class(tactic: str) -> str:
    return f"t-{tactic}" if tactic in _TACTICS else "t-other"


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


# ---- how the attacker moved

NODE_W, NODE_H, COL_GAP, ROW_GAP, PAD = 240, 54, 120, 20, 24


def attack_svg(g: Graph, anchors: dict[str, str]) -> str:
    """The graph, left to right: seeds first, then what they handed over. `anchors` maps an identity's label to the id of its
    block further down the page, so a node can take the reader there."""
    n = len(g.nodes)
    layer = [0] * n
    for _ in range(n):  # longest path from a seed; bounded, so a cycle cannot loop
        changed = False
        for a, b, _call in g.edges:
            if not g.nodes[b].seed and layer[b] < layer[a] + 1 <= n:
                layer[b] = layer[a] + 1
                changed = True
        if not changed:
            break
    columns: dict[int, list[tuple[str, int]]] = {}
    for i in range(n):
        columns.setdefault(layer[i], []).append(("n", i))
    for k, (src, _what, _call) in enumerate(g.unused):
        columns.setdefault(layer[src] + 1, []).append(("u", k))
    rows = max(len(c) for c in columns.values())
    width = PAD * 2 + (max(columns) + 1) * NODE_W + max(columns) * COL_GAP
    height = PAD * 2 + rows * NODE_H + (rows - 1) * ROW_GAP
    pos: dict[tuple[str, int], tuple[float, float]] = {}
    for col, items in columns.items():
        top = PAD + (rows - len(items)) * (NODE_H + ROW_GAP) / 2
        for r, item in enumerate(items):
            pos[item] = (PAD + col * (NODE_W + COL_GAP), top + r * (NODE_H + ROW_GAP))
    label = f"How the attacker moved: {_plural(n, 'identity', 'identities')}"
    out = [f'<svg class="graph" viewBox="0 0 {int(width)} {int(height)}" role="img" aria-label="{h(label)}">',
           '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
           '<path class="arrowhead" d="M0 0 L10 5 L0 10 z"/></marker></defs>']

    def edge(src: tuple[str, int], dst: tuple[str, int], call: str, dashed: bool) -> None:
        (x1, y1), (x2, y2) = pos[src], pos[dst]
        if x2 > x1:
            sx, sy, ex, ey = x1 + NODE_W, y1 + NODE_H / 2, x2, y2 + NODE_H / 2
            mid = (sx + ex) / 2
            d = f"M{_f(sx)} {_f(sy)} C{_f(mid)} {_f(sy)} {_f(mid)} {_f(ey)} {_f(ex)} {_f(ey)}"
        else:  # same column or backwards: leave the bottom, arrive at the top
            sx, sy, ex, ey = x1 + NODE_W / 2, y1 + NODE_H, x2 + NODE_W / 2, y2
            d = f"M{_f(sx)} {_f(sy)} C{_f(sx)} {_f(sy + 40)} {_f(ex)} {_f(ey - 40)} {_f(ex)} {_f(ey)}"
        mx, my = (sx + ex) / 2, (sy + ey) / 2
        text = _cut(call, 26)
        w = len(text) * 6.6 + 12
        out.append(f'<path class="edge{" dashed" if dashed else ""}" d="{d}" marker-end="url(#arrow)"/>')
        out.append(f'<rect class="edge-label-bg" x="{_f(mx - w / 2)}" y="{_f(my - 10)}" width="{_f(w)}" height="20" rx="5"/>')
        out.append(f'<text class="edge-label" x="{_f(mx)}" y="{_f(my + 4)}" text-anchor="middle">{h(text)}</text>')

    for a, b, call in g.edges:
        edge(("n", a), ("n", b), call, False)
    for k, (src, _what, call) in enumerate(g.unused):
        edge(("n", src), ("u", k), call, True)

    def node(key: tuple[str, int], css: str, title: str, name: str, sub: str, target: str | None) -> None:
        x, y = pos[key]
        link = f' data-target="{h(target)}" tabindex="0" role="link"' if target else ""
        out.append(f'<g class="node {css}{" link" if target else ""}"{link}><title>{h(title, 200)}</title>'
                   f'<rect class="box" x="{_f(x)}" y="{_f(y)}" width="{NODE_W}" height="{NODE_H}" rx="10"/>'
                   f'<text class="name" x="{_f(x + 14)}" y="{_f(y + 22)}">{h(_cut(name, 30))}</text>'
                   f'<text class="sub" x="{_f(x + 14)}" y="{_f(y + 40)}">{h(sub)}</text></g>')

    for i, nd in enumerate(g.nodes):
        node(("n", i), "seed" if nd.seed else "followed", f"{nd.label} · {_plural(nd.calls, 'call', 'calls')}", nd.label,
             f"{_plural(nd.calls, 'call', 'calls')} · {'matched an indicator' if nd.seed else 'followed'}", anchors.get(nd.label))
    for k, (_src, what, _call) in enumerate(g.unused):
        node(("u", k), "unused", what, what, "handed over, never used", None)
    out.append("</svg>")
    return "".join(out)


# ---- who did what when

GUTTER, PLOT_W, PAD_R, TOP, LANE_H, AXIS_H = 220, 860, 24, 30, 38, 46
_DODGE: Final = (0, -7, 7, -14, 14)


def _tick(us: int, span_us: int) -> str:
    iso = format_time_us(us)  # 2026-10-20T14:30:00Z
    if span_us > 2 * 86_400_000_000:
        return f"{iso[5:10]} {iso[11:16]}"
    return iso[11:19] if span_us < 86_400_000_000 else iso[11:16]


def timeline_svg(scope: Scope, tl: Timeline) -> str:
    """A lane for each identity, time left to right, a dot for each call (a cross if it failed, a ring if it was found by
    following the attacker), the log silences shaded and the attacker's logging changes marked."""
    actors = tl.actors[:MAX_NODES]
    lane = {a.label: i for i, a in enumerate(actors)}
    events = [(parse_time_us(s.event.event_time), s) for s in scope.events if actor_label(s.event.user_identity) in lane]
    if not events:
        return ""
    t0 = min(t for t, _ in events)
    t1 = max(t for t, _ in events)
    span = max(t1 - t0, 1)
    width, height = GUTTER + PLOT_W + PAD_R, TOP + len(actors) * LANE_H + AXIS_H

    def x(t: int) -> float:
        return GUTTER + (t - t0) / span * PLOT_W if t1 > t0 else GUTTER + PLOT_W / 2

    label = f"Timeline: {_plural(len(events), 'call', 'calls')} by {_plural(len(actors), 'identity', 'identities')}"
    out = [f'<svg class="timeline" viewBox="0 0 {width} {height}" role="img" aria-label="{h(label)}">']
    for i, a in enumerate(actors):
        y = TOP + i * LANE_H
        out.append(f'<rect class="lane{" alt" if i % 2 else ""}" x="0" y="{y}" width="{width}" height="{LANE_H}"/>')
        out.append(f'<text class="lane-label" x="12" y="{_f(y + LANE_H / 2 + 4)}"><title>{h(a.label, 200)}</title>{h(_cut(a.label, 30))}</text>')
    for g in scope.coverage.gaps:  # silences in the logs
        gs, ge = parse_time_us(g.start), parse_time_us(g.end)
        if ge < t0 or gs > t1:
            continue
        gx1, gx2 = x(max(gs, t0)), x(min(ge, t1))
        out.append(f'<g class="gap"><title>{h(f"No events for {g.minutes} minutes ({g.region})", 120)}</title>'
                   f'<rect x="{_f(gx1)}" y="{TOP}" width="{_f(max(gx2 - gx1, 2))}" height="{len(actors) * LANE_H}"/></g>')
    placed: dict[int, list[tuple[float, int]]] = {}
    for t, s in sorted(events, key=lambda e: (e[0], e[1].event.event_id)):
        ev = s.event
        i = lane[actor_label(ev.user_identity)]
        cx = x(t)
        taken = placed.setdefault(i, [])
        off = next((o for o in _DODGE if not any(abs(px - cx) < 8 and po == o for px, po in taken)), _DODGE[-1])
        taken.append((cx, off))
        cy = TOP + i * LANE_H + LANE_H / 2 + off
        targets = "; ".join(f"{k} {v}" for k, v in resources(ev))
        what = " · ".join(part for part in (ev.event_time, action(ev), targets, ev.error_code or "ok") if part)
        cls = f"{tactic_class(tactic(ev))}{' prop' if s.origin == 'propagated' else ''}"
        if ev.error_code:
            out.append(f'<g class="dot fail {tactic_class(tactic(ev))}"><title>{h(what, 240)}</title>'
                       f'<path d="M{_f(cx - 4)} {_f(cy - 4)} L{_f(cx + 4)} {_f(cy + 4)} M{_f(cx - 4)} {_f(cy + 4)} L{_f(cx + 4)} {_f(cy - 4)}"/></g>')
        else:
            out.append(f'<circle class="dot {cls}" cx="{_f(cx)}" cy="{_f(cy)}" r="4.5"><title>{h(what, 240)}</title></circle>')
    for tm in (t for t in scope.coverage.tampering if t.in_scope):  # the attacker changed logging or detection
        tx = x(max(min(parse_time_us(tm.event_time), t1), t0))
        out.append(f'<g class="tamper"><title>{h(f"{tm.event_time} · {tm.event_name}: {tm.effect}", 200)}</title>'
                   f'<path d="M{_f(tx)} {TOP - 16} l5 8 l-5 8 l-5 -8 z"/></g>')
    base = TOP + len(actors) * LANE_H
    out.append(f'<line class="axis" x1="{GUTTER}" y1="{base}" x2="{GUTTER + PLOT_W}" y2="{base}"/>')
    for k in range(6):
        tt = t0 + span * k // 5
        tx = x(tt) if t1 > t0 else GUTTER + PLOT_W / 2
        anchor = "start" if k == 0 else "end" if k == 5 else "middle"
        out.append(f'<line class="tick" x1="{_f(tx)}" y1="{base}" x2="{_f(tx)}" y2="{base + 5}"/>'
                   f'<text class="tick-label" x="{_f(tx)}" y="{base + 20}" text-anchor="{anchor}">{h(_tick(tt, span))}</text>')
        if t1 == t0:
            break
    out.append(f'<text class="axis-note" x="{GUTTER}" y="{base + 38}">UTC · {h(format_time_us(t0)[:10])}</text>')
    out.append("</svg>")
    return "".join(out)


# ---- the tactic mix

def tactic_bar_svg(tl: Timeline) -> str:
    """One bar split by tactic, each part as wide as its share of the calls."""
    total = sum(t.events for t in tl.tactics)
    if not total:
        return ""
    out = ['<svg class="tactic-bar" viewBox="0 0 1000 18" role="img" aria-label="Calls by tactic" preserveAspectRatio="none">']
    left = 0.0
    for t in tl.tactics:
        w = 1000 * t.events / total
        out.append(f'<rect class="{tactic_class(t.tactic)}" x="{_f(left)}" y="0" width="{_f(max(w - 2, 1))}" height="18" rx="3">'
                   f'<title>{h(t.tactic + ": " + _plural(t.events, "call", "calls"))}</title></rect>')
        left += w
    out.append("</svg>")
    return "".join(out)
