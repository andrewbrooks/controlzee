"""Build `timeline.json` from a scope: actors, the ordered story with coverage gaps in place, tactics, and exposure.

Everything here is derived from `scope.json` alone and is deterministic: the same scope gives the same bytes.
"""
from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from controlzee import canonical
from controlzee.classify import TACTIC_ORDER, access, action, resources, service, tactic
from controlzee.model.common import Confidence, tool_info
from controlzee.model.event import Event, UserIdentity
from controlzee.model.scope import Scope, ScopedEvent
from controlzee.model.timeline import (
    Actor,
    Exposure,
    PrivilegeChange,
    ResourceAccess,
    TacticSummary,
    Timeline,
    TimelineEntry,
)
from controlzee.timeutil import parse_time_us

LISTED_EVENT_IDS = 20
ADMIN_POLICIES = frozenset({"arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws:iam::aws:policy/IAMFullAccess"})
_PRIVILEGE_CALLS = {
    "AttachUserPolicy": ("user", "userName", "policyArn"), "AttachRolePolicy": ("role", "roleName", "policyArn"),
    "AttachGroupPolicy": ("group", "groupName", "policyArn"), "PutUserPolicy": ("user", "userName", "policyName"),
    "PutRolePolicy": ("role", "roleName", "policyName"), "PutGroupPolicy": ("group", "groupName", "policyName"),
    "AddUserToGroup": ("user", "userName", "groupName"), "UpdateAssumeRolePolicy": ("role", "roleName", None),
    "CreatePolicyVersion": ("policy", "policyArn", None), "SetDefaultPolicyVersion": ("policy", "policyArn", None),
}


def actor_label(ui: UserIdentity) -> str:
    arn = ui.arn or ""
    if ui.type == "AssumedRole" and ":assumed-role/" in arn:
        return "assumed-role/" + arn.split(":assumed-role/", 1)[1]
    if ui.type in ("IAMUser", "FederatedUser") and arn.count(":") >= 5:
        return arn.split(":", 5)[5]
    if ui.type == "Root":
        return "root"
    if ui.type == "AWSAccount":
        return f"account {ui.account_id}" if ui.account_id else "another account"
    return arn or ui.principal_id or ui.type or "unknown"


def _actor_key(ui: UserIdentity) -> tuple[str, str]:
    return ui.account_id or "", actor_label(ui)


def _actors(events: list[ScopedEvent]) -> list[Actor]:
    groups: dict[tuple[str, str], list[ScopedEvent]] = defaultdict(list)
    for s in events:
        groups[_actor_key(s.event.user_identity)].append(s)
    out = []
    # in order of first appearance (events are in time order), so the list reads as the story does
    for (account, label), evs in sorted(groups.items(), key=lambda kv: (parse_time_us(kv[1][0].event.event_time), kv[0])):
        ui = evs[0].event.user_identity
        agents = sorted({e.event.user_agent for e in evs if e.event.user_agent})
        out.append(Actor(
            label=label, account=account or None, arn=ui.arn, principal_id=ui.principal_id,
            access_keys=sorted({k for e in evs if (k := e.event.user_identity.access_key_id)}),
            source_ips=sorted({e.event.source_ip for e in evs if e.event.source_ip}), user_agents=agents[:10], events=len(evs),
            first_event_time=evs[0].event.event_time, last_event_time=evs[-1].event.event_time,
            confidence=Confidence.STRONG if any(e.confidence is Confidence.STRONG for e in evs) else Confidence.WEAK,
            tainted=any(e.via for e in evs)))
    return out


def _entry(s: ScopedEvent) -> TimelineEntry:
    ev = s.event
    return TimelineEntry(kind="event", time=ev.event_time, event_id=ev.event_id, actor=actor_label(ev.user_identity),
                         action=action(ev), tactic=tactic(ev), targets=[f"{k} {v}" for k, v in resources(ev)],
                         outcome=ev.error_code or "ok", confidence=s.confidence, origin=s.origin, via=s.via, source_ip=ev.source_ip,
                         account=ev.recipient_account_id, region=ev.aws_region)


def _entries(scope: Scope) -> list[TimelineEntry]:
    """Events and gaps in time order. CloudTrail times have one-second precision, so calls in the same second are
    genuinely unordered; those that create something are listed first, so a thing appears before the calls that use it."""
    keyed: list[tuple[int, int, str, TimelineEntry]] = [
        (parse_time_us(s.event.event_time), 0 if s.event.event_name.startswith("Create") else 1, s.event.event_id, _entry(s))
        for s in scope.events]
    names = {s.event.event_id: action(s.event) for s in scope.events}
    names.update({t.event_id: f"{t.event_source.split('.', 1)[0]}:{t.event_name}" for t in scope.coverage.tampering})
    for g in scope.coverage.gaps:
        what = {"silence": "no events", "starts_late": "logs start only at the end of this span",
                "ends_early": "logs end at the start of this span"}[g.kind]
        cause = f"; possibly caused by {names.get(g.possible_cause, 'a logging change')} ({g.possible_cause})" if g.possible_cause else ""
        keyed.append((parse_time_us(g.start), 2, f"{g.account}/{g.region}", TimelineEntry(
            kind="gap", time=g.start, end=g.end, account=g.account, region=g.region,
            note=f"{g.region}: {what} for {g.minutes} minutes{cause}")))
    return [e for *_, e in sorted(keyed, key=lambda k: k[:3])]


def _tactics(entries: Iterable[TimelineEntry]) -> list[TacticSummary]:
    seen: dict[str, list[TimelineEntry]] = defaultdict(list)
    for e in entries:
        if e.kind == "event" and e.tactic:
            seen[e.tactic].append(e)
    return [TacticSummary(tactic=t, events=sum(1 for e in seen[t] if e.outcome == "ok"),
                          failed=sum(1 for e in seen[t] if e.outcome != "ok"), first_event_time=seen[t][0].time)
            for t in TACTIC_ORDER if t in seen]


def _grants_everything(document: Any) -> bool:
    """An inline policy document (JSON text, as CloudTrail logs it) with an Allow of every action."""
    try:
        doc = json.loads(document) if isinstance(document, str) else document
    except ValueError:
        return False
    statements = doc.get("Statement") if isinstance(doc, dict) else None
    for st in statements if isinstance(statements, list) else [statements]:
        if isinstance(st, dict) and st.get("Effect") == "Allow":
            acts = st.get("Action")
            if acts in ("*", "iam:*") or (isinstance(acts, list) and ("*" in acts or "iam:*" in acts)):
                return True
    return False


def privilege_change(ev: Event) -> PrivilegeChange | None:
    if service(ev.event_source) != "iam" or ev.event_name not in _PRIVILEGE_CALLS:
        return None
    kind, who_param, what_param = _PRIVILEGE_CALLS[ev.event_name]
    req = ev.request_parameters or {}
    who = req.get(who_param)
    what = req.get(what_param) if what_param else None
    admin = (what in ADMIN_POLICIES) or (ev.event_name.startswith("Put") and _grants_everything(req.get("policyDocument"))) \
        or (ev.event_name == "CreatePolicyVersion" and _grants_everything(req.get("policyDocument")))
    return PrivilegeChange(event_id=ev.event_id, time=ev.event_time, action=action(ev),
                           principal=f"{kind} {who}" if isinstance(who, str) else kind,
                           policy=what if isinstance(what, str) else None, admin=admin and ev.error_code is None,
                           outcome=ev.error_code or "ok")


def exposure(scope: Scope) -> Exposure:
    groups: dict[tuple[str, str, str, str], list[Event]] = defaultdict(list)
    changes: list[PrivilegeChange] = []
    credentials: set[str] = set()
    for s in scope.events:
        ev = s.event
        for kind, name in resources(ev):
            groups[(service(ev.event_source), kind, name, access(ev))].append(ev)
            if ev.error_code is None and tactic(ev) == "credential-access" and kind in ("secret", "parameter", "parameter path"):
                credentials.add(f"{kind} {name}")
        if (pc := privilege_change(ev)) is not None:
            changes.append(pc)
    res = []
    for (svc, kind, name, acc), evs in sorted(groups.items()):
        ok = [e for e in evs if e.error_code is None]
        res.append(ResourceAccess(service=svc, type=kind, name=name, access=acc, events=len(ok), failed=len(evs) - len(ok),
                                  first_event_time=evs[0].event_time, last_event_time=evs[-1].event_time,
                                  actions=sorted({action(e) for e in evs}), event_ids=[e.event_id for e in evs][:LISTED_EVENT_IDS]))
    accounts = sorted({s.event.recipient_account_id for s in scope.events if s.event.recipient_account_id}
                      | {u.account for u in scope.coverage.unlogged_accounts})
    admin = any(c.admin for c in changes)
    notes = []
    if admin:
        notes.append("full administrative access was granted: assume the attacker could read or change anything in the affected "
                     "account(s) from that moment, including what the logs do not show")
    if credentials:
        notes.append(f"{len(credentials)} secret(s) or parameter(s) were read: treat their values as known to the attacker")
    if any(n.startswith("no data events") for n in scope.coverage.notes):
        notes.append("the inputs have no data events, so object-level S3 access (and similar) cannot be listed here")
    if scope.coverage.unlogged_accounts:
        notes.append("activity reached account(s) with no logs in the inputs; exposure there is unknown")
    return Exposure(accounts=accounts, admin_granted=admin, credentials_read=sorted(credentials), privilege_changes=changes,
                    resources=res, notes=notes)


def build_timeline(scope: Scope) -> dict[str, Any]:
    """The sealed timeline document, ready for canonical.dumps."""
    entries = _entries(scope)
    tl = Timeline(tool=tool_info(), scope_sha256=scope.scope_sha256, actors=_actors(scope.events), tactics=_tactics(entries),
                  entries=entries, exposure=exposure(scope))
    return canonical.seal(tl.model_dump(mode="json"), "timeline_sha256")
