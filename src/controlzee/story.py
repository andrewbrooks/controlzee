"""The key moments of an incident in time order, for the report's "How it unfolded" ribbon.

Pure data derived from the scope and its timeline: the first call that matched an indicator, credentials issued, permissions
changed (full control stressed), logging or detection changed, secrets read, and instance role credentials used from another
address. A burst of the same call by the same identity (sixty `GetSecretValue`) is one moment with a count. Nothing here is
escaped: the renderer does that. Everything is sorted by `(time, kind, event id)`, so the same scope gives the same list.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from controlzee.classify import action
from controlzee.facts import KIND_NAMES, reads_secret
from controlzee.model.scope import Scope
from controlzee.model.timeline import Timeline
from controlzee.timeline import actor_label, privilege_change
from controlzee.timeutil import parse_time_us

MIN_MOMENTS: Final = 3  # fewer than this is not a story: the calls table says it as well (the shortest inputs have 2)
MAX_MOMENTS: Final = 12  # more than this is not a ribbon any more
GROUP_SECONDS: Final = 30  # repeats this close are one moment (bursts in the captures are at most 6 s apart; the next gap is 105 s)

Kind = Literal["tamper", "privilege", "instance", "secrets", "issued", "start"]
_RANK: Final = {k: i for i, k in enumerate(("tamper", "privilege", "instance", "secrets", "issued", "start"))}


@dataclass(frozen=True)
class Moment:
    kind: Kind
    title: str  # "New access key", "Admin access granted"
    detail: str  # the call, for the line under the title
    actor: str
    time: str  # of the first call
    t_us: int  # first call
    end_us: int  # last call of the group
    count: int  # calls in the group
    event_id: str  # of the first call: where the ribbon links to
    hot: bool  # something that needs attention: full control, logging changed, secrets read, instance credentials used elsewhere
    first: bool = False  # also the first call that matched an indicator
    event_ids: tuple[str, ...] = ()  # every call of the group, so an arrow of the graph can name the step that issued it


def _issued_title(scope: Scope) -> dict[str, str]:
    out: dict[str, str] = {}
    for t in sorted(scope.taint.identities, key=lambda t: (t.issued_at, t.kind, t.value)):
        out.setdefault(t.issued_by, f"New {KIND_NAMES.get(t.kind, 'credential')}")
    return out


def _raw(scope: Scope, tl: Timeline) -> list[Moment]:
    issued = _issued_title(scope)
    by_id = {s.event.event_id: s.event for s in scope.events}
    found: dict[str, Moment] = {}  # one moment per call: the most telling kind wins

    def add(kind: Kind, title: str, detail: str, ev_id: str, hot: bool) -> None:
        ev = by_id[ev_id]
        t = parse_time_us(ev.event_time)
        m = Moment(kind, title, detail, actor_label(ev.user_identity), ev.event_time, t, t, 1, ev_id, hot, event_ids=(ev_id,))
        if ev_id not in found or _RANK[kind] < _RANK[found[ev_id].kind]:
            found[ev_id] = m

    for tm in scope.coverage.tampering:
        if tm.in_scope and tm.event_id in by_id:
            add("tamper", "Logging or detection changed", f"{tm.event_source.split('.', 1)[0]}:{tm.event_name}: {tm.effect}", tm.event_id, True)
    for s in scope.events:
        ev = s.event
        if (pc := privilege_change(ev)) is not None and pc.outcome == "ok":
            add("privilege", "Full control granted" if pc.admin else "Permissions changed", f"{pc.action} on {pc.principal}", ev.event_id, pc.admin)
        elif reads_secret(ev):
            add("secrets", "Secrets read", action(ev), ev.event_id, True)
        elif ev.event_id in issued:
            add("issued", issued[ev.event_id], action(ev), ev.event_id, False)
    for u in tl.exposure.instance_role_use:
        evs = [by_id[i] for i in u.event_ids if i in by_id]
        if evs:
            home = evs[0].source_ip
            other = next((e for e in evs if e.source_ip != home), None)
            if other is not None:
                add("instance", "Instance role used from another address", f"{u.instance} from {other.source_ip}", other.event_id, True)
    seed = next((s.event for s in scope.events if s.origin == "seed"), None)
    if seed is not None:
        if seed.event_id in found:
            found[seed.event_id] = Moment(**{**found[seed.event_id].__dict__, "first": True})
        else:
            add("start", "First call that matched an indicator", action(seed), seed.event_id, False)
    return sorted(found.values(), key=lambda m: (m.t_us, _RANK[m.kind], m.event_id))


def _group(raw: list[Moment]) -> list[Moment]:
    """Bursts of the same call by the same identity (`GROUP_SECONDS` apart at most) as one moment with a count. A group keeps every call it
    stands for, and the marker of the first call that matched an indicator if any of them has it."""
    grouped: list[Moment] = []
    last_of: dict[tuple[str, str, str], int] = {}  # (kind, actor, detail) to the index of its latest group
    for m in raw:
        key = (m.kind, m.actor, m.detail)
        i = last_of.get(key)
        if i is not None and m.t_us - grouped[i].end_us <= GROUP_SECONDS * 1_000_000 and m.kind != "start":
            g = grouped[i]
            grouped[i] = Moment(**{**g.__dict__, "end_us": m.t_us, "count": g.count + 1, "event_ids": (*g.event_ids, *m.event_ids), "first": g.first or m.first})
        else:
            last_of[key] = len(grouped)
            grouped.append(m)
    return grouped


def build_moments(scope: Scope, tl: Timeline) -> list[Moment]:
    """The moments in time order with bursts grouped, or [] when there are fewer than `MIN_MOMENTS` (not enough to be a story).
    All of them are returned; the renderer shows `MAX_MOMENTS` and counts the rest."""
    grouped = _group(_raw(scope, tl))
    return grouped if len(grouped) >= MIN_MOMENTS else []
