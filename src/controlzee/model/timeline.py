"""`timeline.json`: the in-scope events as a story (who did what, in order, with the gaps), and what was exposed."""
from __future__ import annotations

from typing import Any, Literal

from controlzee.model.common import SCHEMA_VERSION, Confidence, Model

Tactic = Literal["initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access",
                 "discovery", "lateral-movement", "collection", "exfiltration", "impact", "other"]


class Actor(Model):
    """One identity the attacker acted as, as the logs name it."""

    label: str  # "user/ci-deploy", "assumed-role/ops-admin/maint", "account 999900001111"
    account: str | None
    arn: str | None
    principal_id: str | None
    access_keys: list[str]
    source_ips: list[str]
    user_agents: list[str]  # first 10
    events: int
    first_event_time: str
    last_event_time: str
    confidence: Confidence  # the strongest of its events
    tainted: bool  # some of its events were found by following what the attacker obtained


class TimelineEntry(Model):
    kind: Literal["event", "gap"]
    time: str
    end: str | None = None  # gaps only
    event_id: str | None = None
    actor: str | None = None
    action: str | None = None  # "iam:CreateAccessKey"
    tactic: Tactic | None = None
    targets: list[str] = []  # "bucket build-artifacts", "user backdoor-svc"
    outcome: str | None = None  # "ok", or the error code of a failed call
    confidence: Confidence | None = None
    origin: Literal["seed", "propagated"] | None = None
    via: str | None = None
    source_ip: str | None = None
    account: str | None = None
    region: str | None = None
    note: str | None = None  # gaps: what was silent and what may have caused it


class TacticSummary(Model):
    tactic: Tactic
    events: int
    failed: int
    first_event_time: str


class ResourceAccess(Model):
    service: str
    type: str
    name: str
    access: Literal["read", "write", "delete", "assume"]
    events: int
    failed: int  # attempts that were refused; not counted in `events`
    first_event_time: str
    last_event_time: str
    actions: list[str]
    event_ids: list[str]  # first 20


class PrivilegeChange(Model):
    """A call that changed what a principal may do."""

    event_id: str
    time: str
    action: str
    principal: str  # "user backdoor-svc", "role support-audit", "group admins"
    policy: str | None  # managed policy ARN, inline policy name, or the group joined
    admin: bool  # grants full control (AdministratorAccess, IAMFullAccess, or an inline Allow of "*")
    outcome: str


class Exposure(Model):
    accounts: list[str]  # where in-scope activity was recorded, plus accounts reached without logs
    admin_granted: bool
    credentials_read: list[str]  # secrets and parameters successfully read: assume they are known to the attacker
    privilege_changes: list[PrivilegeChange]
    resources: list[ResourceAccess]
    notes: list[str]


class Timeline(Model):
    schema_version: str = SCHEMA_VERSION
    tool: dict[str, Any]
    scope_sha256: str  # the scope.json this was built from
    actors: list[Actor]
    tactics: list[TacticSummary]  # in ATT&CK order
    entries: list[TimelineEntry]
    exposure: Exposure
    timeline_sha256: str = ""
