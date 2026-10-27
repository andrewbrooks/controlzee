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
    chain: list[str] = []  # taint chain back to a seed; empty for seeds (filled in from milestone 2)


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
    by_account: dict[str, int]
    by_region: dict[str, int]
    failed_calls: int
    first_event_time: str | None
    last_event_time: str | None


class Scope(Model):
    schema_version: str = SCHEMA_VERSION
    tool: dict[str, Any]
    inputs: InputsSummary
    seeds: SeedInfo
    summary: Summary
    events: list[ScopedEvent]
    near_misses: list[NearMiss]
    near_miss_summary: NearMissSummary
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
