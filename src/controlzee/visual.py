"""The pictures and quick-read text of `report.md`: an at-a-glance block and a diagram of how the attacker moved.

Everything here is derived from the scope (and the timeline and plan built from it), so it is as reproducible as they are:
no clocks, no random ids, everything sorted. Logs are hostile input. The diagram is Mermaid, which GitHub draws from a
fenced block, so a label must not be able to close its quotes or add markup: labels are cut to a whitelist of
characters (`_label`) and node ids are numbered by this module, never taken from the logs.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Final

from controlzee.model.common import Confidence
from controlzee.model.plan import Plan
from controlzee.model.scope import Scope
from controlzee.model.timeline import Timeline
from controlzee.safety import clean
from controlzee.timeline import actor_label
from controlzee.timeutil import parse_time_us

MAX_NODES: Final = 30  # a picture of more than this is not a picture
_UNSAFE = re.compile(r"[^A-Za-z0-9 _/.@:+=,()-]")
_KIND_NAMES: Final = {"access_key_id": "access key", "principal_id": "user", "role_id": "role", "instance_id": "instance",
                      "function_name": "function"}


def _label(value: object, limit: int = 48) -> str:
    """Untrusted text as a Mermaid label: cut to a whitelist, so it cannot close the quotes or add markup."""
    return _UNSAFE.sub("·", clean(value, limit))


def _calls(n: int) -> str:
    return f"{n} call" if n == 1 else f"{n} calls"


def attack_path(scope: Scope) -> list[str]:
    """A flowchart: who acted, and which credential or principal one identity created or obtained for another.
    Empty when no identity handed anything to another (a single identity has nothing to draw)."""
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
    unused: list[tuple[str, str, str]] = []  # (issuer, what, call): handed over and never used
    for t in scope.taint.identities:
        issuer_event = by_id.get(t.issued_by)
        if issuer_event is None:
            continue
        issuer = label_of[t.issued_by]
        users = []
        for s in scope.events:
            if s.via == f"{t.kind}:{t.value}" and (a := label_of[s.event.event_id]) not in users:
                users.append(a)
        call = t.rule.split(":", 1)[-1]
        for u in users:
            if u != issuer and (issuer, u, call) not in edges:
                edges.append((issuer, u, call))
        if not users:
            what = f"new {_KIND_NAMES.get(t.kind, 'credential')} ...{t.value[-4:]} (unused)"
            if (issuer, what, call) not in unused:
                unused.append((issuer, what, call))
    if not edges and not unused:
        return []
    shown = order[:MAX_NODES]
    ids = {a: f"n{i}" for i, a in enumerate(shown)}
    out = ["## How the attacker moved", "",
           "Each arrow is a credential or principal one identity created or obtained for another, labelled with the call that "
           "issued it. Red: matched an indicator. Blue: found only by following the attacker. Dashed: handed over but never "
           "used in these logs.", "", "```mermaid", "flowchart LR"]
    for a in shown:
        out.append(f'    {ids[a]}["{_label(a)} · {_calls(calls[a])}"]:::{"seed" if a in seeds else "followed"}')
    drawn = 0
    for src, dst, call in edges:
        if src in ids and dst in ids:
            out.append(f'    {ids[src]} -->|"{_label(call, 30)}"| {ids[dst]}')
            drawn += 1
    for i, (src, what, call) in enumerate(unused):
        if src in ids:
            out += [f'    u{i}["{_label(what)}"]:::unused', f'    {ids[src]} -.->|"{_label(call, 30)}"| u{i}']
            drawn += 1
    out += ["    classDef seed fill:#fde2e2,stroke:#c0392b,color:#222",
            "    classDef followed fill:#e3edff,stroke:#3b6fd4,color:#222",
            "    classDef unused fill:#f4f4f4,stroke:#888,stroke-dasharray:4 3,color:#222", "```", ""]
    if len(order) > len(shown):
        out += [f"{len(order) - len(shown)} more identities acted and are not drawn; see the timeline.", ""]
    return out if drawn else []


def _minutes(scope: Scope) -> str:
    s = scope.summary
    if not (s.first_event_time and s.last_event_time):
        return ""
    minutes = (parse_time_us(s.last_event_time) - parse_time_us(s.first_event_time)) // 60_000_000
    return "in under a minute" if minutes < 1 else f"over {minutes} minute{'s' if minutes != 1 else ''}"


def _n(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def at_a_glance(scope: Scope, tl: Timeline, plan: Plan, md: Callable[..., str]) -> list[str]:
    """A short block above the summary: how big, what stands out, and what to do first. `md` is the report's escaper."""
    s, x, cov = scope.summary, tl.exposure, scope.coverage
    if not s.events_in_scope:
        return []
    accounts = ", ".join(md(a) for a in x.accounts)
    stands_out = []
    if x.admin_granted:
        stands_out.append("**Full administrative access was granted**: assume anything in the account(s) could be read or changed.")
    if x.credentials_read:
        stands_out.append(f"**{_n(len(x.credentials_read), 'secret or parameter was', 'secrets or parameters were')} read**: "
                          "treat the values as known to the attacker.")
    if x.instance_role_use:
        stands_out.append(f"**The role credentials of {_n(len(x.instance_role_use), 'instance', 'instances')} were used from another "
                          "address**: a sign they were taken from the instance.")
    in_scope_tampering = sum(1 for t in cov.tampering if t.in_scope)
    if in_scope_tampering:
        stands_out.append(f"**The attacker changed logging or detection** ({_n(in_scope_tampering, 'call', 'calls')}).")
    if cov.unlogged_accounts:
        stands_out.append(f"**{_n(len(cov.unlogged_accounts), 'account', 'accounts')} reached without logs**: what happened there is unknown.")
    if cov.gaps:
        stands_out.append(f"**{_n(len(cov.gaps), 'silence', 'silences')} in the logs** during the incident.")
    contain = [a for a in plan.actions if a.phase == "contain"]
    runnable = sum(1 for a in plan.actions if a.operations)
    out = ["> **At a glance.** "
           f"{_n(s.events_in_scope, 'event', 'events')} by {_n(len(tl.actors), 'identity', 'identities')} {_minutes(scope)}, "
           f"in {'account' if len(x.accounts) == 1 else 'accounts'} {accounts}.", ">"]
    out += [f"> - {line}" for line in stands_out] or ["> - Nothing in the exposure stands out beyond the timeline."]
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

