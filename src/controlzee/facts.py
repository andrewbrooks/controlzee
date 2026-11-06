"""The facts behind the report's blocks, as data, so the Markdown and the HTML report show the same things.

An identity (who it is, how it came about, what it did) and the evidence behind a plan step are worked out once here;
`visual.py` and `report.py` write them as Markdown and `html_report.py` as HTML. Nothing here escapes anything: the
renderers do, for where they put it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from controlzee import params
from controlzee.classify import access, action, resources, tactic
from controlzee.model.event import Event
from controlzee.model.scope import Scope
from controlzee.model.timeline import Timeline
from controlzee.timeline import actor_label, privilege_change

MAX_NODES: Final = 30  # a picture of more than this is not a picture
MAX_CALLS: Final = 15  # calls listed per identity
MAX_TOUCHED: Final = 4  # kinds of resource shown on an identity in the picture; the rest are counted
SECRET_KINDS: Final = ("secret", "parameter", "parameter path")
KIND_NAMES: Final = {"access_key_id": "access key", "principal_id": "user", "role_id": "role", "instance_id": "instance",
                     "function_name": "function"}


def idesc(kind: str, value: str) -> str:
    """"function exfil-fn", "access key ...ODMT": what a followed identity is, in a few words."""
    if kind in ("function_name", "instance_id"):
        return f"{KIND_NAMES[kind]} {value}"
    return f"{KIND_NAMES.get(kind, 'credential')} ...{value[-4:]}"


@dataclass(frozen=True)
class Issued:
    """The call that created an identity or handed it to the attacker."""

    rule: str  # "lambda:CreateFunction"
    by: str  # who made the call
    time: str
    ip: str | None
    params: list[tuple[str, str]]  # the request parameters that are safe to show (see params.py)


@dataclass(frozen=True)
class Did:
    time: str
    call: str
    target: str
    result: str
    params: str  # a write's main parameters as "name=value; ..."; empty for reads


@dataclass(frozen=True)
class IdentityFacts:
    label: str
    calls: int
    matched: list[str]  # the indicators its seed events matched; empty if it was only followed
    what: str  # "function exfil-fn" for a followed function, else ""
    who: list[tuple[str, str]]  # (field, value) for what is known about it
    issued: list[Issued]  # how it came about, for each credential or principal it acted as (first 3)
    did: list[Did]  # its first MAX_CALLS calls
    more: int  # calls not listed


@dataclass(frozen=True)
class UnusedFacts:
    """A credential or principal the attacker was handed and never used in these logs."""

    what: str
    issued: Issued


def _issued(rule: str, ev: Event) -> Issued:
    return Issued(rule=rule, by=actor_label(ev.user_identity), time=ev.event_time, ip=ev.source_ip, params=params.describe(ev))


def collect_identities(scope: Scope, tl: Timeline) -> tuple[list[IdentityFacts], list[UnusedFacts]]:
    by_id = {s.event.event_id: s for s in scope.events}
    label_of = {s.event.event_id: actor_label(s.event.user_identity) for s in scope.events}
    tainted = {f"{t.kind}:{t.value}": t for t in scope.taint.identities}
    out = []
    for actor in tl.actors[:MAX_NODES]:
        evs = [s for s in scope.events if label_of[s.event.event_id] == actor.label]
        via: list[str] = []
        for s in evs:
            if s.via and s.via in tainted and s.via not in via:
                via.append(s.via)
        matched = sorted({i for s in evs if s.origin == "seed" for i in s.matched_indicators})
        who = [("ARN", actor.arn or ""), ("Account", actor.account or ""), ("Access keys", ", ".join(actor.access_keys)),
               ("Source addresses", ", ".join(actor.source_ips)), ("User agents", "; ".join(actor.user_agents[:3])),
               ("First seen", actor.first_event_time), ("Last seen", actor.last_event_time)]
        did = []
        for s in evs[:MAX_CALLS]:
            ev = s.event
            pairs = [] if ev.read_only else params.describe(ev)[:3]  # a write's parameters say what it changed; reads are noise
            did.append(Did(time=ev.event_time, call=action(ev), target="; ".join(f"{k} {v}" for k, v in resources(ev)),
                           result=ev.error_code or "ok", params="; ".join(f"{k}={v[:60]}" for k, v in pairs)))
        out.append(IdentityFacts(
            label=actor.label, calls=len(evs), matched=matched, what=idesc(*via[0].split(":", 1)) if via else "",
            who=[(k, v) for k, v in who if v],
            issued=[_issued(tainted[v].rule, by_id[tainted[v].issued_by].event) for v in via[:3] if tainted[v].issued_by in by_id],
            did=did, more=max(len(evs) - MAX_CALLS, 0)))
    used = {s.via for s in scope.events if s.via}
    unused = [UnusedFacts(what=idesc(t.kind, t.value), issued=_issued(t.rule, by_id[t.issued_by].event))
              for t in scope.taint.identities if f"{t.kind}:{t.value}" not in used and t.issued_by in by_id]
    return out, unused


@dataclass(frozen=True)
class EvidenceRow:
    when: str  # the first time, "2026-10-20 14:30:00Z"
    who: str
    call: str
    count: int  # how many times this same call was made
    target: str
    result: str
    ids: list[str]  # the event ids of those calls


def evidence_rows(ids: list[str], scope: Scope) -> tuple[list[EvidenceRow], list[str]]:
    """The calls behind a plan step, the same call made several times as one row, and the full ids in their original order."""
    by_id = {s.event.event_id: s.event for s in scope.events}
    groups: dict[tuple[str, str, str, str], list[str]] = {}
    first: dict[tuple[str, str, str, str], str] = {}
    for i in ids:
        ev = by_id.get(i)
        if ev is None:
            continue
        key = (actor_label(ev.user_identity), action(ev), "; ".join(f"{k} {v}" for k, v in resources(ev)), ev.error_code or "ok")
        groups.setdefault(key, []).append(ev.event_id)
        first.setdefault(key, ev.event_time)
    rows = [EvidenceRow(when=first[k].replace("T", " "), who=k[0], call=k[1], count=len(v), target=k[2], result=k[3], ids=v)
            for k, v in groups.items()]
    return rows, [i for i in ids if i in by_id]


@dataclass(frozen=True)
class Touch:
    """What one identity did to one kind of resource: "changed 5 roles", "read 40 secrets"."""

    kind: str  # the resource type, "role", "secret"
    access: str  # "read", "write" or "delete"
    count: int  # distinct resources of that kind
    names: tuple[str, ...]  # the first two, in the order they were touched
    flag: str  # "admin" (it was given full control), "secret" (a secret or parameter value was read), or ""


_ACCESS_ORDER: Final = {"write": 0, "delete": 0, "read": 1}


def reads_secret(ev: Event) -> bool:
    """A successful call that reads a secret or parameter value: the one test the graph and the sequence of events both use."""
    return ev.error_code is None and tactic(ev) == "credential-access" and any(k in SECRET_KINDS for k, _ in resources(ev))


def touched_by_actor(scope: Scope) -> dict[str, list[Touch]]:
    """For each identity, the resources its successful calls changed, deleted or read, grouped by kind and access, the ones that need
    attention first. Role assumptions are left out (they are the arrows of the graph) and so are failed calls."""
    names: dict[str, dict[tuple[str, str], list[str]]] = {}
    flags: dict[str, dict[tuple[str, str], str]] = {}
    for s in scope.events:
        ev = s.event
        acc = access(ev)
        if ev.error_code is not None or acc == "assume":
            continue
        who = actor_label(ev.user_identity)
        pc = privilege_change(ev)
        for kind, name in resources(ev):
            group = names.setdefault(who, {}).setdefault((kind, acc), [])
            if name not in group:
                group.append(name)
            if pc is not None and pc.admin and pc.principal == f"{kind} {name}":
                flags.setdefault(who, {})[(kind, acc)] = "admin"
            elif acc == "read" and kind in SECRET_KINDS and reads_secret(ev):
                flags.setdefault(who, {}).setdefault((kind, acc), "secret")
    out: dict[str, list[Touch]] = {}
    for who, groups in names.items():
        touches = [Touch(kind, acc, len(found), tuple(found[:2]), flags.get(who, {}).get((kind, acc), "")) for (kind, acc), found in groups.items()]
        out[who] = sorted(touches, key=lambda t: (not t.flag, _ACCESS_ORDER.get(t.access, 2), -t.count, t.kind, t.access))
    return out
