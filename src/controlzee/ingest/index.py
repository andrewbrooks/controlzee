"""The in-memory event index: one compact tuple per event, sorted by time.

The layout was chosen by measurement (see docs/architecture.md): plain tuples with interned strings index 1M events in
about two seconds on eight workers at roughly 0.5-0.7 KB per event. Full `Event` models are built only for events that end
up in scope (see `materialize`).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from controlzee.ingest.source import Source

# What a successful call handed its caller, as (kind, value) pairs; see taint/rules.py. None for almost every event.
Issued = tuple[tuple[str, str], ...]

# (event_id, ts_us, event_time, event_source, event_name, region, account, read_only, source_ip, user_agent, error_code,
#  identity_type, arn, principal_id, access_key_id, issuer_arn, source_identity, issued, file_index, record_index)
Row = tuple[
    str, int, str, str, str, str, str, bool | None, str | None, str | None, str | None,
    str | None, str | None, str | None, str | None, str | None, str | None, Issued | None, int, int,
]
R_ID: Final = 0
R_TS: Final = 1
R_TIME: Final = 2
R_SOURCE: Final = 3
R_NAME: Final = 4
R_REGION: Final = 5
R_ACCOUNT: Final = 6
R_RO: Final = 7
R_IP: Final = 8
R_UA: Final = 9
R_ERR: Final = 10
R_UITYPE: Final = 11
R_ARN: Final = 12
R_PID: Final = 13
R_AK: Final = 14
R_ISSUER: Final = 15
R_SRCID: Final = 16
R_ISSUED: Final = 17
R_FILE: Final = 18
R_REC: Final = 19


@dataclass(frozen=True)
class FileEntry:
    """One input file as seen by ingest. `path` is relative to its input root, never absolute."""

    path: str
    sha256: str
    size_bytes: int
    records: int
    status: str  # "ingested" | "skipped" | "error"
    note: str | None = None


@dataclass
class EventIndex:
    rows: list[Row]
    files: list[FileEntry]
    duplicates_removed: int = 0
    malformed_records: int = 0
    malformed_samples: list[str] = field(default_factory=list)
    data_events: int = 0  # records with eventCategory "Data" (S3 object, Lambda invoke...); counted for coverage
    ignored_files: int = 0  # files in an input directory that are not .json / .json.gz
    sources: list[Source] = field(default_factory=list)  # indexed by a row's file index
