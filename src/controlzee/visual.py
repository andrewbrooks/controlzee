"""The pictures and quick-read text of `report.md`: an at-a-glance block and a diagram of how the attacker moved.

Everything here is derived from the scope (and the timeline and plan built from it), so it is as reproducible as they are:
no clocks, no random ids, everything sorted. Logs are hostile input. The diagram is Mermaid, which GitHub draws from a
fenced block, so a label must not be able to close its quotes or add markup: labels are cut to a whitelist of
characters (`_label`) and node ids are numbered by this module, never taken from the logs.
"""
from __future__ import annotations

import html
import re
from collections.abc import Callable
from dataclasses import dataclass

from controlzee.facts import KIND_NAMES, MAX_NODES, Issued, collect_identities
from controlzee.model.common import Confidence
from controlzee.model.plan import Plan
from controlzee.model.scope import Scope
from controlzee.model.timeline import Timeline
from controlzee.safety import clean
from controlzee.timeline import actor_label
from controlzee.timeutil import parse_time_us

_UNSAFE = re.compile(r"[^A-Za-z0-9 _/.@:+=,()-]")


def _label(value: object, limit: int = 48) -> str:
    """Untrusted text as a Mermaid label: cut to a whitelist, so it cannot close the quotes or add markup."""
    return _UNSAFE.sub("·", clean(value, limit))


def _calls(n: int) -> str:
    return f"{n} call" if n == 1 else f"{n} calls"


@dataclass(frozen=True)
class Node:
    label: str  # as the logs name the identity
    calls: int
    seed: bool  # matched an indicator, as opposed to being found by following the attacker


@dataclass(frozen=True)
class Graph:
    """Who acted, and which credential or principal one identity created or obtained for another."""

    nodes: list[Node]  # in order of first appearance
    edges: list[tuple[int, int, str]]  # (from node, to node, the call that issued what was handed over)
    unused: list[tuple[int, str, str]]  # (from node, what, call): handed over and never used in these logs
    hidden: int  # identities that acted but are not drawn


def build_graph(scope: Scope) -> Graph | None:
    """The graph of the scope, or None when no identity handed anything to another (a single identity has nothing to draw)."""
    by_id = {s.event.event_id: s for s in scope.events}
    label_of = {s.event.event_id: actor_label(s.event.user_identity) for s in scope.events}
    order: list[str] = []  # actors in order of first appearance
    calls: dict[str, int] = {}
    seeds: set[str] = set()
    for s in scope.events:
        a = label_of[s.event.event_id]
        if a not in calls:
            order.append(a)
            calls[a] = 0
        calls[a] += 1
        if s.origin == "seed":
            seeds.add(a)
    edges: list[tuple[str, str, str]] = []  # (from, to, call), first appearance order
    unused: list[tuple[str, str, str]] = []  # (issuer, what, call)
    for t in scope.taint.identities:
        if t.issued_by not in by_id:
            continue
        issuer = label_of[t.issued_by]
        users: list[str] = []
        for s in scope.events:
            if s.via == f"{t.kind}:{t.value}" and (a := label_of[s.event.event_id]) not in users:
                users.append(a)
        call = t.rule.split(":", 1)[-1]
        for u in users:
            if u != issuer and (issuer, u, call) not in edges:
                edges.append((issuer, u, call))
        if not users:
            what = f"new {KIND_NAMES.get(t.kind, 'credential')} ...{t.value[-4:]} (unused)"
            if (issuer, what, call) not in unused:
                unused.append((issuer, what, call))
    shown = order[:MAX_NODES]
    index = {a: i for i, a in enumerate(shown)}
    kept_edges = [(index[a], index[b], c) for a, b, c in edges if a in index and b in index]
    kept_unused = [(index[a], what, c) for a, what, c in unused if a in index]
    if not kept_edges and not kept_unused:
        return None
    return Graph(nodes=[Node(a, calls[a], a in seeds) for a in shown], edges=kept_edges, unused=kept_unused,
                 hidden=len(order) - len(shown))


def attack_path(scope: Scope) -> list[str]:
    """The graph as a Mermaid flowchart. Empty when there is nothing to draw."""
    g = build_graph(scope)
    if g is None:
        return []
    out = ["## How the attacker moved", "",
           "Each arrow is a credential or principal one identity created or obtained for another, labelled with the call that "
           "issued it. Red: matched an indicator. Blue: found only by following the attacker. Dashed: handed over but never "
           "used in these logs.", "", "```mermaid", "flowchart LR"]
    for i, n in enumerate(g.nodes):
        out.append(f'    n{i}["{_label(n.label)} · {_calls(n.calls)}"]:::{"seed" if n.seed else "followed"}')
    for src, dst, call in g.edges:
        out.append(f'    n{src} -->|"{_label(call, 30)}"| n{dst}')
    for i, (src, what, call) in enumerate(g.unused):
        out += [f'    u{i}["{_label(what)}"]:::unused', f'    n{src} -.->|"{_label(call, 30)}"| u{i}']
    out += ["    classDef seed fill:#fde2e2,stroke:#c0392b,color:#222",
            "    classDef followed fill:#e3edff,stroke:#3b6fd4,color:#222",
            "    classDef unused fill:#f4f4f4,stroke:#888,stroke-dasharray:4 3,color:#222", "```", ""]
    if g.hidden:
        out += [f"{g.hidden} more identities acted and are not drawn; see the timeline.", ""]
    return out


def _minutes(scope: Scope) -> str:
    s = scope.summary
    if not (s.first_event_time and s.last_event_time):
        return ""
    minutes = (parse_time_us(s.last_event_time) - parse_time_us(s.first_event_time)) // 60_000_000
    return "in under a minute" if minutes < 1 else f"over {minutes} minute{'s' if minutes != 1 else ''}"


def _n(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def glance_points(scope: Scope, tl: Timeline) -> list[tuple[str, str, str]]:
    """What stands out in the exposure, as (the part to stress, the rest, "danger" or "info"): the same facts for the Markdown and
    the HTML report."""
    x, cov = tl.exposure, scope.coverage
    points: list[tuple[str, str, str]] = []
    if x.admin_granted:
        points.append(("Full administrative access was granted", ": assume anything in the account(s) could be read or changed.", "danger"))
    if x.credentials_read:
        points.append((f"{_n(len(x.credentials_read), 'secret or parameter was', 'secrets or parameters were')} read",
                       ": treat the values as known to the attacker.", "danger"))
    if x.instance_role_use:
        points.append((f"The role credentials of {_n(len(x.instance_role_use), 'instance', 'instances')} were used from another address",
                       ": a sign they were taken from the instance.", "danger"))
    in_scope_tampering = sum(1 for t in cov.tampering if t.in_scope)
    if in_scope_tampering:
        points.append(("The attacker changed logging or detection", f" ({_n(in_scope_tampering, 'call', 'calls')}).", "danger"))
    if cov.unlogged_accounts:
        points.append((f"{_n(len(cov.unlogged_accounts), 'account', 'accounts')} reached without logs", ": what happened there is unknown.", "info"))
    if cov.gaps:
        points.append((f"{_n(len(cov.gaps), 'silence', 'silences')} in the logs", " during the incident.", "info"))
    return points


def headline(scope: Scope, tl: Timeline, accounts: str) -> str:
    """"11 events by 2 identities over 10 minutes, in account 111122223333." with `accounts` already escaped by the caller."""
    s = scope.summary
    return (f"{_n(s.events_in_scope, 'event', 'events')} by {_n(len(tl.actors), 'identity', 'identities')} {_minutes(scope)}, "
            f"in {'account' if len(tl.exposure.accounts) == 1 else 'accounts'} {accounts}.")


def at_a_glance(scope: Scope, tl: Timeline, plan: Plan, md: Callable[..., str]) -> list[str]:
    """A short block above the summary: how big, what stands out, and what to do first. `md` is the report's escaper."""
    if not scope.summary.events_in_scope:
        return []
    contain = [a for a in plan.actions if a.phase == "contain"]
    runnable = sum(1 for a in plan.actions if a.operations)
    out = [f"> **At a glance.** {headline(scope, tl, ', '.join(md(a) for a in tl.exposure.accounts))}", ">"]
    out += [f"> - **{strong}**{rest}" for strong, rest, _ in glance_points(scope, tl)] or ["> - Nothing in the exposure stands out beyond the timeline."]
    out += ["> - Tactics: " + " · ".join(f"{t.tactic} ×{t.events}" for t in tl.tactics) + "."]
    if contain:
        first = ", ".join(f"{a.id} {a.title.lower()}" for a in contain[:3])
        more = f", and {len(contain) - 3} more" if len(contain) > 3 else ""
        out += [">", f"> **Do first** ({_n(len(contain), 'containment step', 'containment steps')}): {first}{more}.",
                f"> Of {_n(len(plan.actions), 'plan step', 'plan steps')}, {runnable} can be carried out by `controlzee respond`; "
                "the rest are for a person."]
    weak = sum(1 for e in scope.events if e.confidence is Confidence.WEAK)
    if weak:
        out += [">", f"> {_n(weak, 'event is', 'events are')} in scope on weak evidence only: confirm them before acting on them."]
    return [*out, ""]


# ---- what each identity was: a collapsible block per identity


def h(value: object, limit: int = 120) -> str:
    """Untrusted text for HTML (the summary line of a <details>, where Markdown is not read): control characters replaced,
    length capped, every markup character turned into an entity."""
    return html.escape(clean(value, limit), quote=True)


def details(summary_html: str, body: list[str], *, open_: bool = False) -> list[str]:
    """A collapsible block. `summary_html` must already be safe HTML; `body` is Markdown (GitHub reads it after the blank line)."""
    return ["<details open>" if open_ else "<details>", f"<summary>{summary_html}</summary>", "", *body, "", "</details>", ""]


def _kv_table(pairs: list[tuple[str, str]], md: Callable[..., str], header: tuple[str, str] = ("Parameter", "Value")) -> list[str]:
    return [f"| {header[0]} | {header[1]} |", "|---|---|", *(f"| {md(k, 80)} | {md(v, 300)} |" for k, v in pairs)]


def _issued_md(i: Issued, md: Callable[..., str]) -> list[str]:
    out = [f"**How it came about.** The call `{md(i.rule)}`, made by **{md(i.by)}** at {md(i.time)}"
           + (f" from {md(i.ip)}" if i.ip else "") + ".", ""]
    return out + (_kv_table(i.params, md) + [""] if i.params else ["No parameters were logged for it.", ""])


def identities_section(scope: Scope, tl: Timeline, md: Callable[..., str]) -> list[str]:
    """One collapsible block per identity that acted (and per credential handed over and never used): who it is, how it
    came about (the issuing call and its parameters), and what it did."""
    if not scope.events:
        return []
    identities, unused = collect_identities(scope, tl)
    out = ["## Identities", "",
           "Open one to see who it is, how it came about (the call that created or handed it over, with the parameters that were "
           "logged) and what it did. Secrets are never shown, and environment variables show their names only.", ""]
    for f in identities:
        body = _kv_table(f.who, md, ("Who it is", "Detail")) + [""]
        if f.matched:
            body += [f"**Matched** the indicator{'s' if len(f.matched) != 1 else ''} {', '.join(f'`{md(m)}`' for m in f.matched)}.", ""]
        for i in f.issued:
            body += _issued_md(i, md)
        rows = [f"| {md(d.time)} | {md(d.call)} | {md(d.target, 200)} | {md(d.result)} | {md(d.params, 240)} |" for d in f.did]
        body += [f"**What it did** ({_n(f.calls, 'call', 'calls')})", "", "| Time | Call | Target | Result | Parameters (writes) |",
                 "|---|---|---|---|---|", *rows]
        if f.more:
            body += ["", f"{f.more} more calls are in the timeline."]
        body.append("")
        what = f" · {h(f.what)}" if f.what else ""
        out += details(f"<b>{h(f.label)}</b> · {_calls(f.calls)} · {'matched an indicator' if f.matched else 'followed'}{what}", body)
    for u in unused:
        out += details(f"<b>{h(u.what)}</b> · never used in these logs", _issued_md(u.issued, md))
    return out
