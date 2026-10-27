"""The scoping result, `scope.json`: what the attacker did, as far as the logs show."""
from __future__ import annotations

from typing import Any, Literal

from controlzee.model.common import SCHEMA_VERSION, Confidence, Model
from controlzee.model.event import Event
from controlzee.model.ioc import Indicator, Window


class FileProblem(Model):
    path: str
    note: str


class InputsSummary(Model):
    manifest_sha256: str  # hash of the sidecar file list; the list itself is in <scope>.inputs.json
    file_count: int
    ingested_files: int
    skipped_files: int
    error_files: int
    ignored_files: int
    event_count: int
    duplicates_removed: int
    malformed_records: int
    first_event_time: str | None
    last_event_time: str | None
    accounts: list[str]
    regions: list[str]
    errors: list[FileProblem]  # first 20 only; the sidecar lists all
    skipped: list[FileProblem]
    malformed_samples: list[str]


class SeedInfo(Model):
    expression: str
    indicators: list[Indicator]
    window: Window | None


class ScopedEvent(Model):
    event: Event
    confidence: Confidence
    origin: Literal["seed", "propagated"] = "seed"
    matched_indicators: list[str]
    chain: list[str] = []  # event ids from a seed to the call that issued `via`; empty for seeds no taint reached
    via: str | None = None  # the tainted identity the event acted as, "<kind>:<value>"


IdentityKind = Literal["access_key_id", "principal_id", "role_id", "instance_id"]


class TaintedIdentity(Model):
    """A credential or principal the attacker created or obtained, found by following the in-scope events."""

    kind: IdentityKind
    value: str
    confidence: Confidence
    rule: str  # the call that issued it, e.g. "iam:CreateAccessKey"
    issued_by: str  # event id
    issued_at: str
    chain: list[str]  # event ids from a seed to issued_by, inclusive
    events: int  # in-scope events that acted as this identity


class TaintInfo(Model):
    enabled: bool
    identities: list[TaintedIdentity]


class NearMiss(Model):
    """An event that matched a weak indicator but is not in scope. Compact on purpose: there can be very many."""

    event_id: str
    event_time: str
    event_source: str
    event_name: str
    source_ip: str | None
    principal: str | None
    matched_indicators: list[str]
    reason: Literal["expression", "window"]


class NearMissSummary(Model):
    total: int
    listed: int
    by_reason: dict[str, int]
    by_indicator: dict[str, int]


class Summary(Model):
    events_in_scope: int
    by_confidence: dict[str, int]
    by_origin: dict[str, int]
    by_account: dict[str, int]
    by_region: dict[str, int]
    failed_calls: int
    first_event_time: str | None
    last_event_time: str | None


class LogStream(Model):
    """The events one account and region contributed: the span of time the logs cover there."""

    account: str
    region: str
    events: int
    first_event_time: str
    last_event_time: str
    typical_interval_s: int  # mean time between events; 0 for a stream with one event


class Gap(Model):
    """A silence in one stream during the incident, long for that stream. Logs may be missing; or it was just quiet."""

    account: str
    region: str
    kind: Literal["silence", "starts_late", "ends_early"]  # between two events, or before the first / after the last
    start: str
    end: str
    minutes: int
    possible_cause: str | None  # event id of a logging change in that account just before or during the gap


class TamperingEvent(Model):
    """A call that turns off, narrows or deletes logging or detection. Listed whoever made it."""

    event_id: str
    event_time: str
    event_source: str
    event_name: str
    effect: str
    account: str
    region: str
    principal: str | None
    error_code: str | None  # set when the call failed
    in_scope: bool


class UnloggedAccount(Model):
    """An account in-scope activity reached (by assuming a role in it) that none of the inputs come from."""

    account: str
    role_arns: list[str]
    event_ids: list[str]


class Coverage(Model):
    """What the logs can and cannot show about this incident."""

    period_start: str | None  # the incident period checked for gaps: the window and the in-scope events together
    period_end: str | None
    gap_minutes: int  # shortest silence reported
    streams: list[LogStream]
    gaps: list[Gap]
    tampering: list[TamperingEvent]  # first 100 only
    tampering_total: int
    unlogged_accounts: list[UnloggedAccount]
    data_events: int
    read_only_events: int
    notes: list[str]


class Scope(Model):
    schema_version: str = SCHEMA_VERSION
    tool: dict[str, Any]
    inputs: InputsSummary
    seeds: SeedInfo
    summary: Summary
    events: list[ScopedEvent]
    near_misses: list[NearMiss]
    near_miss_summary: NearMissSummary
    taint: TaintInfo
    coverage: Coverage
    scope_sha256: str = ""  # SHA-256 of this document's canonical form without this field


class ManifestFile(Model):
    path: str
    sha256: str
    size_bytes: int
    records: int
    status: Literal["ingested", "skipped", "error"]
    note: str | None


class InputsManifest(Model):
    """The sidecar `<scope>.inputs.json`: every input file with its hash, so a result can be tied to the exact evidence."""

    schema_version: str = SCHEMA_VERSION
    tool: dict[str, Any]
    manifest_sha256: str  # SHA-256 of the canonical `files` list; the same value appears in scope.json
    files: list[ManifestFile]
