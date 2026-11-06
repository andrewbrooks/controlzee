"""SVG pictures for the HTML report: how the attacker moved, who did what when, and the tactic mix.

Drawn here, in plain SVG with CSS classes (the page's stylesheet colours them, in light and dark), so the report needs no
library and no network. The numbers are computed, rounded to one decimal and always printed the same way, so the same
scope gives the same bytes. Every piece of text from the logs goes through `visual.h`, and nothing from the logs is ever
used as an element name, a class or an id: classes come from fixed lists, ids from counters.
"""
from __future__ import annotations

from typing import Final

from controlzee.classify import TACTIC_ORDER, action, resources, tactic
from controlzee.facts import MAX_NODES, MAX_TOUCHED, Touch
from controlzee.model.scope import Scope
from controlzee.model.timeline import Timeline
from controlzee.timeline import actor_label
from controlzee.timeutil import format_time_us, parse_time_us
from controlzee.visual import Graph, Node, h
from controlzee.visual import mid as _mid

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

# Sizes are in the picture's own units, and the page shows it at about that size (never much smaller), so 13 is about 13 pixels.
NODE_W, NODE_H, COL_GAP, ROW_GAP, PAD = 240, 54, 96, 22, 24
MIN_W: Final = 1000  # a small graph is drawn on a canvas this wide, centred, so that it is not blown up to fill the page
WIDE: Final = 1320  # a graph wider than this is shown at its own size and scrolls, rather than shrunk until its text is small
CHIP_H, CHIP_GAP = 20, 4
NAME_CHARS: Final = 26
CHIP_CHARS: Final = 28
_VERB: Final = {"write": "changed", "delete": "deleted", "read": "read"}
_MARK: Final = {"admin": "\u25b2 ", "secret": "\u2605 "}  # a shape as well as a colour: the reader may not see red
BADGE_R: Final = 12


def _short(name: str) -> str:
    """An ARN by its last part ("ReadOnlyAccess" for a policy's ARN): the whole of it is in the tooltip and the tables."""
    parts = name.split(":", 5)
    if not name.startswith("arn:") or len(parts) < 6:
        return name
    last = parts[5].split("/")[-1].removeprefix("function:")  # "function:billing-report:$LATEST" is the function and a version
    return last.split(":")[0] or name


def touch_text(t: Touch) -> str:
    """"changed role support-audit", "read secret x40", with a shape in front when it needs attention."""
    what = ", ".join(_short(n) for n in t.names) if t.count <= len(t.names) else f"\u00d7{t.count}"
    return f"{_MARK.get(t.flag, '')}{_VERB.get(t.access, t.access)} {t.kind} {what}"


def _chips(nd: Node) -> tuple[list[Touch], int]:
    """The resource chips drawn on an identity and how many kinds are left out."""
    return list(nd.touched[:MAX_TOUCHED]), max(len(nd.touched) - MAX_TOUCHED, 0)


def _name_lines(name: str) -> list[str]:
    """An identity's name on one line, or on two when it is long and has a path in it ("assumed-role/" then "ops-admin/maint")."""
    if len(name) <= NAME_CHARS or "/" not in name:
        return [_mid(name, NAME_CHARS)]
    head, rest = name.split("/", 1)
    return [head + "/", _mid(rest, NAME_CHARS)]


def _header(name: str) -> int:
    return NODE_H + 18 * (len(_name_lines(name)) - 1)


def _node_height(name: str, nd: Node | None) -> int:
    head = _header(name)
    if nd is None or not nd.touched:
        return head
    shown, more = _chips(nd)
    return head + 4 + (len(shown) + (1 if more else 0)) * (CHIP_H + CHIP_GAP)


def _plural_arrow(n: int) -> str:
    return f"{n} arrow" if n == 1 else f"{n} arrows"


def attack_svg(g: Graph, anchors: dict[str, str], numbers: dict[str, int] | None = None, steps: dict[str, str] | None = None) -> str:
    """The graph, left to right: seeds first, then what they handed over. Each identity lists what it changed or read (by kind, the
    ones that need attention first), and an account that was reached but sent no logs is drawn dashed, so the chain does not seem to
    end where the logs do. Each arrow carries the number of the step in the sequence of events that issued what it hands over
    (`numbers`, event id to number); the call is named in the list under the picture and in the arrow's tooltip.

    `anchors` maps an identity's label to the id of its block further down the page; `steps` maps it to the ids of the plan steps that
    are about it, so the page script can light them together."""
    numbers = numbers or {}
    steps = steps or {}
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
    for k, (src, _what, _call) in enumerate(g.ghosts):
        columns.setdefault(layer[src] + 1, []).append(("g", k))

    def name_of(key: tuple[str, int]) -> str:
        kind, i = key
        return g.nodes[i].label if kind == "n" else g.unused[i][1].removesuffix(" (unused)") if kind == "u" else g.ghosts[i][1]

    def height(key: tuple[str, int]) -> int:
        return _node_height(name_of(key), g.nodes[key[1]] if key[0] == "n" else None)

    def col_height(items: list[tuple[str, int]]) -> int:
        return sum(height(k) for k in items) + (len(items) - 1) * ROW_GAP

    tallest = max(col_height(c) for c in columns.values())
    content = PAD * 2 + (max(columns) + 1) * NODE_W + max(columns) * COL_GAP
    width = max(MIN_W, content)
    left = (width - content) / 2
    total = PAD * 2 + tallest
    pos: dict[tuple[str, int], tuple[float, float]] = {}
    for col, items in columns.items():
        y = PAD + (tallest - col_height(items)) / 2
        for item in items:
            pos[item] = (left + PAD + col * (NODE_W + COL_GAP), y)
            y += height(item) + ROW_GAP
    groups = sum(len(nd.touched) for nd in g.nodes)
    label = f"How the attacker moved: {_plural(n, 'identity', 'identities')}, {_plural_arrow(len(g.edges) + len(g.unused) + len(g.ghosts))}" \
        + (f", {_plural(groups, 'kind', 'kinds')} of resource touched" if groups else "") \
        + (f", {_plural(len(g.ghosts), 'account', 'accounts')} reached without logs" if g.ghosts else "")
    out = [f'<svg class="graph{" wide" if width > WIDE else ""}" width="{int(width)}" viewBox="0 0 {int(width)} {int(total)}" role="img" aria-label="{h(label)}">',
           '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
           '<path class="arrowhead" d="M0 0 L10 5 L0 10 z"/></marker></defs>']

    def edge(src: tuple[str, int], dst: tuple[str, int], call: str, dashed: bool, event_id: str) -> None:
        (x1, y1), (x2, y2) = pos[src], pos[dst]
        if x2 > x1:  # arrows meet the header of a node, not the middle of its chips
            sx, sy, ex, ey = x1 + NODE_W, y1 + _header(name_of(src)) / 2, x2, y2 + _header(name_of(dst)) / 2
            mid = (sx + ex) / 2
            d = f"M{_f(sx)} {_f(sy)} C{_f(mid)} {_f(sy)} {_f(mid)} {_f(ey)} {_f(ex)} {_f(ey)}"
        else:  # same column or backwards: leave the bottom, arrive at the top
            sx, sy, ex, ey = x1 + NODE_W / 2, y1 + height(src), x2 + NODE_W / 2, y2
            d = f"M{_f(sx)} {_f(sy)} C{_f(sx)} {_f(sy + 40)} {_f(ex)} {_f(ey - 40)} {_f(ex)} {_f(ey)}"
        out.append(f'<path class="edge{" dashed" if dashed else ""}" d="{d}" marker-end="url(#arrow)"/>')
        mx, my = (sx + ex) / 2, (sy + ey) / 2
        number = numbers.get(event_id)
        if number is None:  # not a step of the sequence: a dot, and the call in its tooltip
            out.append(f'<g class="eb none"><title>{h(call, 80)}</title><circle cx="{_f(mx)}" cy="{_f(my)}" r="4.5"/></g>')
        else:
            out.append(f'<g class="eb"><title>{h(f"Step {number}: {call}", 100)}</title><circle cx="{_f(mx)}" cy="{_f(my)}" r="{BADGE_R}"/>'
                       f'<text x="{_f(mx)}" y="{_f(my + 4.7)}" text-anchor="middle">{number}</text></g>')

    for k, (a, b, call) in enumerate(g.edges):
        edge(("n", a), ("n", b), call, False, g.edge_ids[k] if k < len(g.edge_ids) else "")
    for k, (src, _what, call) in enumerate(g.unused):
        edge(("n", src), ("u", k), call, True, g.unused_ids[k] if k < len(g.unused_ids) else "")
    for k, (src, _acct, call) in enumerate(g.ghosts):
        edge(("n", src), ("g", k), call, True, g.ghost_ids[k] if k < len(g.ghost_ids) else "")

    def node(key: tuple[str, int], css: str, title: str, sub: str, target: str | None, nd: Node | None = None) -> None:
        x, y = pos[key]
        name = name_of(key)
        lines = _name_lines(name)
        head = _header(name)
        link = f' data-target="{h(target)}" data-node="{h(target)}" tabindex="0" role="link"' if target else ""
        if nd is not None and nd.label in steps:
            link += f' data-steps="{h(steps[nd.label], 200)}"'
        chips, more = _chips(nd) if nd is not None else ([], 0)
        every = "; ".join(touch_text(t) for t in nd.touched) if nd is not None else ""
        full = f"{title}. Touched: {every}" if every else title
        out.append(f'<g class="node {css}{" link" if target else ""}"{link}><title>{h(full, 600)}</title>'
                   f'<rect class="box" x="{_f(x)}" y="{_f(y)}" width="{NODE_W}" height="{height(key)}" rx="10"/>'
                   + "".join(f'<text class="name" x="{_f(x + 14)}" y="{_f(y + 22 + 18 * i)}">{h(line)}</text>' for i, line in enumerate(lines))
                   + f'<text class="sub" x="{_f(x + 14)}" y="{_f(y + head - 14)}">{h(sub)}</text>')
        if css == "seed":  # a second outline: "matched an indicator" is a shape, not a colour
            out.append(f'<rect class="rim" x="{_f(x - 4)}" y="{_f(y - 4)}" width="{NODE_W + 8}" height="{height(key) + 8}" rx="13"/>')
        cy = y + head + 2
        for t in chips:
            out.append(f'<g class="rc{" hot" if t.flag else ""}"><rect x="{_f(x + 10)}" y="{_f(cy)}" width="{NODE_W - 20}" height="{CHIP_H}" rx="5"/>'
                       f'<text x="{_f(x + 17)}" y="{_f(cy + 14)}">{h(_mid(touch_text(t), CHIP_CHARS))}</text></g>')
            cy += CHIP_H + CHIP_GAP
        if more:
            out.append(f'<text class="rc-more" x="{_f(x + 17)}" y="{_f(cy + 14)}">{h(f"+{more} more kinds of resource")}</text>')
        out.append("</g>")

    for i, nd in enumerate(g.nodes):
        node(("n", i), "seed" if nd.seed else "followed", f"{nd.label} \u00b7 {_plural(nd.calls, 'call', 'calls')}",
             f"{_plural(nd.calls, 'call', 'calls')} \u00b7 {'matched an indicator' if nd.seed else 'followed'}", anchors.get(nd.label), nd)
    for k, (_src, what, _call) in enumerate(g.unused):
        node(("u", k), "unused", what, "handed over, never used", None)
    for k, (_src, acct, _call) in enumerate(g.ghosts):
        node(("g", k), "ghost", f"{acct}: reached, no logs came from it, so what happened there is unknown", "reached, but no logs: unknown", None)
    out.append("</svg>")
    return "".join(out)


# ---- who did what when

GUTTER, PLOT_W, PAD_R, TOP, LANE_H, AXIS_H = 220, 860, 24, 30, 38, 46
_DODGE: Final = (0, -7, 7, -14, 14)
PAD_L: Final = 8  # room left of the plot, so a mark on the first tick is not cut in half by the plot's clip

# A stretch with no activity is cut short on the axis when it is at least this long AND at least this share of the whole incident:
# the floor keeps a 5-minute pause in a 10-minute incident (50 % of it) from being cut, the share keeps a short pause in a
# week-long incident from being cut. Of the 16 test inputs, exactly the three with a pause of 1 to 3 hours qualify.
BREAK_MIN_US: Final = 15 * 60_000_000
BREAK_SHARE: Final = 0.20
BREAK_FRAC: Final = 0.04  # the width of a cut, as a share of the axis

# One silhouette for each tactic, so that colour is not the only way to tell them apart. Centred on 0 0, about 10 units across.
_SHAPES: Final = {
    "circle": "M-4.5 0a4.5 4.5 0 1 0 9 0a4.5 4.5 0 1 0 -9 0z",
    "square": "M-4 -4h8v8h-8z",
    "diamond": "M0 -5.6L5.6 0L0 5.6L-5.6 0z",
    "up": "M0 -5L5 4L-5 4z",
    "down": "M0 5L5 -4L-5 -4z",
    "hexagon": "M-5 0L-2.5 -4.3L2.5 -4.3L5 0L2.5 4.3L-2.5 4.3z",
    "plus": "M-1.8 -5h3.6v3.2h3.2v3.6h-3.2v3.2h-3.6v-3.2h-3.2v-3.6h3.2z",
    "star": "M0 -6L1.6 -1.6L6 0L1.6 1.6L0 6L-1.6 1.6L-6 0L-1.6 -1.6z",
    "pentagon": "M0 -5L4.8 -1.5L3 4.2L-3 4.2L-4.8 -1.5z",
    "pennant": "M-4 -5L5 0L-4 5z",
    "bar": "M-5.5 -2.4h11v4.8h-11z",
    "cross": "M-4 -4L-2 -4L0 -1.5L2 -4L4 -4L4 -2L1.5 0L4 2L4 4L2 4L0 1.5L-2 4L-4 4L-4 2L-1.5 0L-4 -2z",
}
_TACTIC_SHAPE: Final = {"initial-access": "down", "execution": "up", "persistence": "square", "privilege-escalation": "diamond",
                        "defense-evasion": "hexagon", "credential-access": "plus", "discovery": "circle", "lateral-movement": "pennant",
                        "collection": "pentagon", "exfiltration": "bar", "impact": "star", "other": "cross"}


def marker_path(tactic: str) -> str:
    return _SHAPES[_TACTIC_SHAPE[tactic if tactic in _TACTICS else "other"]]


def marker_svg(tactic: str) -> str:
    """The tactic's mark, small, for a legend."""
    return (f'<svg class="mk {tactic_class(tactic)}" viewBox="-7 -7 14 14" width="14" height="14" role="img" aria-label="{h(tactic)} marker">'
            f'<path d="{marker_path(tactic)}"/></svg>')


def _tick(us: int, span_us: int) -> str:
    iso = format_time_us(us)  # 2026-10-20T14:30:00Z
    if span_us > 2 * 86_400_000_000:
        return f"{iso[5:10]} {iso[11:16]}"
    return iso[11:19] if span_us < 86_400_000_000 else iso[11:16]


def _length(us: int) -> str:
    minutes = us // 60_000_000
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours} h {minutes:02d} min"
    return f"{hours // 24} d {hours % 24} h"


def _breaks(offsets: list[int], span: int) -> list[tuple[int, int]]:
    """The stretches (start, end, as microseconds after the first call) between two calls of any identity that are long enough to cut."""
    return [(a, b) for a, b in zip(offsets, offsets[1:], strict=False) if b - a >= BREAK_MIN_US and b - a >= BREAK_SHARE * span]


def timeline_svg(scope: Scope, tl: Timeline, rows: dict[str, str] | None = None) -> str:
    """A lane for each identity, time left to right, a mark for each call (a shape for its tactic; hollow if it failed; outlined if it was
    found by following the attacker), the log silences shaded and the attacker's logging changes marked. A long stretch with no
    activity is cut short and labelled with its length.

    The plot is a nested <svg>, which clips what is zoomed out of view. Every mark carries its place on the axis (`data-t`, in
    microseconds of the axis as drawn, cuts included) so the page script can move it when the reader zooms or pans, and
    `data-target`, the id of its row in the call table (from `rows`, event id to row id), so a click can take the reader there."""
    rows = rows or {}
    actors = tl.actors[:MAX_NODES]
    lane = {a.label: i for i, a in enumerate(actors)}
    events = [(parse_time_us(s.event.event_time), s) for s in scope.events if actor_label(s.event.user_identity) in lane]
    if not events:
        return ""
    t0 = min(t for t, _ in events)
    t1 = max(t for t, _ in events)
    span = max(t1 - t0, 1)
    cuts = _breaks(sorted({t - t0 for t, _ in events}), t1 - t0)
    kept = (t1 - t0) - sum(e - s for s, e in cuts)
    axis = round(kept / (1 - len(cuts) * BREAK_FRAC)) if cuts else (t1 - t0)  # length of the axis as drawn
    cut_w = round(axis * BREAK_FRAC) if cuts else 0
    starts: list[int] = []  # where each cut begins on the axis as drawn
    removed = 0
    for cs, ce in cuts:
        starts.append(cs - removed)
        removed += (ce - cs) - cut_w

    def v(off: int) -> int:
        """A time (microseconds after the first call) to its place on the axis as drawn."""
        gone = 0
        for (cs, ce), vs in zip(cuts, starts, strict=True):
            if off <= cs:
                break
            if off < ce:
                return vs + round((off - cs) / (ce - cs) * cut_w)
            gone += (ce - cs) - cut_w
        return off - gone


    def x(vt: float) -> float:
        return GUTTER + vt / axis * PLOT_W if axis > 0 else GUTTER + PLOT_W / 2

    lab_row: list[int] = []  # labels of cuts that sit close together go on a second row, so they do not overprint
    reach = [-1e9, -1e9]
    for vs in starts:
        cx = x(vs + cut_w / 2)
        lr = 0 if cx - reach[0] >= 175 else 1
        reach[lr] = cx
        lab_row.append(lr)
    width, height = GUTTER + PLOT_W + PAD_R, TOP + len(actors) * LANE_H + AXIS_H + (14 if 1 in lab_row else 0)

    label = f"Timeline: {_plural(len(events), 'call', 'calls')} by {_plural(len(actors), 'identity', 'identities')}" \
        + (f", {_plural(len(cuts), 'long stretch', 'long stretches')} with no activity cut short" if cuts else "")
    breaks_attr = f' data-breaks="{";".join(f"{vs},{cut_w},{ce - cs}" for (cs, ce), vs in zip(cuts, starts, strict=True))}"' if cuts else ""
    out = [f'<svg class="timeline" viewBox="0 0 {width} {height}" data-t0="{t0}" data-span="{max(axis, 1)}" data-real="{t1 - t0}"{breaks_attr} '
           f'data-gutter="{GUTTER}" data-plot="{PLOT_W}" role="img" aria-label="{h(label)}">']
    for i, a in enumerate(actors):
        y = TOP + i * LANE_H
        out.append(f'<rect class="lane{" alt" if i % 2 else ""}" x="0" y="{y}" width="{width}" height="{LANE_H}"/>')
        out.append(f'<text class="lane-label" x="12" y="{_f(y + LANE_H / 2 + 4)}"><title>{h(a.label, 200)}</title>{h(_mid(a.label, 28))}</text>')
    base = TOP + len(actors) * LANE_H
    out.append(f'<line class="axis" x1="{GUTTER}" y1="{base}" x2="{GUTTER + PLOT_W}" y2="{base}"/>')
    out.append(f'<g class="sb"><rect class="sb-track" x="{GUTTER}" y="3" width="{PLOT_W}" height="8" rx="4"/>'
               f'<rect class="sb-thumb" x="{GUTTER}" y="3" width="{PLOT_W}" height="8" rx="4"/></g>')  # the scroll bar, shown once zoomed
    out.append(f'<svg class="plot" x="{GUTTER - PAD_L}" y="0" width="{PLOT_W + PAD_R + PAD_L}" height="{height}" '
               f'viewBox="{GUTTER - PAD_L} 0 {PLOT_W + PAD_R + PAD_L} {height}">')
    for g in scope.coverage.gaps:  # silences in the logs
        gs, ge = parse_time_us(g.start), parse_time_us(g.end)
        if ge < t0 or gs > t1:
            continue
        va, vb = v(max(gs, t0) - t0), v(min(ge, t1) - t0)
        gx1, gx2 = x(va), x(vb)
        out.append(f'<g class="gap"><title>{h(f"No events for {g.minutes} minutes ({g.region})", 120)}</title>'
                   f'<rect data-t="{va}" data-t2="{vb}" x="{_f(gx1)}" y="{TOP}" width="{_f(max(gx2 - gx1, 2))}" '
                   f'height="{len(actors) * LANE_H}"/></g>')
    labels: list[str] = []
    for (cs, ce), vs, lrow in zip(cuts, starts, lab_row, strict=True):  # a long stretch with no activity, cut short
        silent = sum(max(0, min(parse_time_us(g.end) - t0, ce) - max(parse_time_us(g.start) - t0, cs)) for g in scope.coverage.gaps)
        text = f"{_length(ce - cs)}, " + ("logs silent" if silent * 2 >= ce - cs else "no activity")
        out.append(f'<g class="brk"><title>{h(f"{text}: {format_time_us(t0 + cs)} to {format_time_us(t0 + ce)}", 160)}</title>'
                   f'<rect data-t="{vs + cut_w // 6}" data-t2="{vs + cut_w - cut_w // 6}" x="{_f(x(vs + cut_w // 6))}" y="{TOP}" width="{_f(x(vs + cut_w - cut_w // 6) - x(vs + cut_w // 6))}" '
                   f'height="{len(actors) * LANE_H}"/></g>')
        ly = base + 34 + 14 * lrow
        anchor = "end" if x(vs + cut_w / 2) + len(text) * 3.2 > width - 4 else "middle"  # a label that would run off the edge ends at the break
        labels.append(f'<g class="brk-lab" data-t="{vs + cut_w // 2}" data-y="{ly}" transform="translate({_f(x(vs + cut_w / 2))} {ly})">'
                      f'<text text-anchor="{anchor}">{h(text)}</text></g>')
    placed: dict[int, list[tuple[float, int]]] = {}
    for t, s in sorted(events, key=lambda e: (e[0], e[1].event.event_id)):
        ev = s.event
        i = lane[actor_label(ev.user_identity)]
        vt = v(t - t0)
        cx = x(vt)
        taken = placed.setdefault(i, [])
        off = next((o for o in _DODGE if not any(abs(px - cx) < 8 and po == o for px, po in taken)), _DODGE[-1])
        taken.append((cx, off))
        cy = TOP + i * LANE_H + LANE_H / 2 + off
        targets = "; ".join(f"{k} {val}" for k, val in resources(ev))
        what = " \u00b7 ".join(part for part in (ev.event_time, action(ev), targets, ev.error_code or "ok") if part)
        row = f' data-target="{h(rows[ev.event_id])}"' if ev.event_id in rows else ""
        cls = f"{tactic_class(tactic(ev))}{' prop' if s.origin == 'propagated' else ''}{' fail' if ev.error_code else ''}{' link' if row else ''}"
        out.append(f'<g class="dot {cls}" data-t="{vt}" data-y="{_f(cy)}"{row} transform="translate({_f(cx)} {_f(cy)})">'
                   f'<title>{h(what, 240)}</title><circle class="hit" r="8"/><path class="body" d="{marker_path(tactic(ev))}"/></g>')
    for tm in (t for t in scope.coverage.tampering if t.in_scope):  # the attacker changed logging or detection
        tt = max(min(parse_time_us(tm.event_time), t1), t0)
        out.append(f'<g class="tamper" data-t="{v(tt - t0)}" data-y="0" transform="translate({_f(x(v(tt - t0)))} 0)">'
                   f'<title>{h(f"{tm.event_time} \u00b7 {tm.event_name}: {tm.effect}", 200)}</title>'
                   f'<path d="M0 {TOP - 16} l5 8 l-5 8 l-5 -8 z"/></g>')
    out.extend(labels)
    out.append('<g class="ticks">')
    for k in range(6):
        vt = axis * k // 5
        if any(vs < vt < vs + cut_w for vs in starts):  # inside a cut: no time to name
            continue
        real = vt + sum((ce - cs) - cut_w for (cs, ce), vs in zip(cuts, starts, strict=True) if vs + cut_w <= vt)
        tx = x(vt) if t1 > t0 else GUTTER + PLOT_W / 2
        anchor = "start" if k == 0 else "end" if k == 5 else "middle"
        out.append(f'<line class="tick" x1="{_f(tx)}" y1="{base}" x2="{_f(tx)}" y2="{base + 5}"/>'
                   f'<text class="tick-label" x="{_f(tx)}" y="{base + 20}" text-anchor="{anchor}">{h(_tick(t0 + real, span))}</text>')
        if t1 == t0:
            break
    out.append("</g></svg>")
    out.append(f'<text class="axis-note" x="{GUTTER}" y="{base + 38}">UTC \u00b7 {h(format_time_us(t0)[:10])}</text>')
    out.append("</svg>")
    return "".join(out)


# ---- the kill chain

_KILL_CHAIN: Final = tuple(t for t in TACTIC_ORDER if t != "other")


def killchain_svg(tl: Timeline) -> str:
    """The ATT&CK tactics controlzee can tell apart, in the framework's order, with the number of calls under each: the ones the attacker
    used are filled, the rest hollow. Empty when no call falls under any of them."""
    seen = {t.tactic: t for t in tl.tactics}
    if not any(t in seen for t in _KILL_CHAIN):
        return ""
    cell = 100
    parts = [f"{t} {seen[t].events + seen[t].failed}" for t in _KILL_CHAIN if t in seen]
    out = [f'<svg class="killchain" viewBox="0 0 {cell * len(_KILL_CHAIN)} 92" role="img" aria-label="{h("Tactics used, in ATT&CK order: " + ", ".join(parts))}">']
    for i, t in enumerate(_KILL_CHAIN):
        hit = seen.get(t)
        x0 = i * cell
        words = t.split("-")
        count = hit.events + hit.failed if hit else 0
        tip = f"{t}: {_plural(count, 'call', 'calls')}" + (f", {hit.failed} failed" if hit and hit.failed else "") if hit else f"{t}: not seen"
        out.append(f'<g class="kc {"kc-hit " + tactic_class(t) if hit else "kc-miss"}"><title>{h(tip)}</title>'
                   f'<rect class="kc-band" x="{x0 + 3}" y="4" width="{cell - 6}" height="14" rx="3"/>'
                   f'<text class="kc-name" x="{x0 + cell / 2}" y="38" text-anchor="middle">{h(words[0].capitalize())}</text>'
                   f'<text class="kc-name" x="{x0 + cell / 2}" y="53" text-anchor="middle">{h(" ".join(words[1:]))}</text>'
                   f'<text class="kc-n" x="{x0 + cell / 2}" y="78" text-anchor="middle">{count}</text></g>')
    out.append("</svg>")
    return "".join(out)
