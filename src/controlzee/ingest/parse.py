"""Fast pass over one CloudTrail file: bytes in, index rows out. Runs inside worker processes."""
from __future__ import annotations

import gc
import hashlib
import zlib
from typing import Any

import orjson

from controlzee.ingest.index import FileEntry, Row
from controlzee.ingest.source import Source
from controlzee.taint.rules import issued_by
from controlzee.timeutil import parse_time_us

DEFAULT_MAX_FILE_BYTES = 1 << 30  # decompressed size cap per file
MAX_SAMPLES = 10


def gunzip_capped(data: bytes, limit: int) -> bytes:
    """Decompress gzip (including concatenated members) refusing to produce more than `limit` bytes."""
    out: list[bytes] = []
    total = 0
    rest = data
    while rest:
        d = zlib.decompressobj(zlib.MAX_WBITS | 16)
        chunk = d.decompress(rest, limit - total + 1)
        total += len(chunk)
        if total > limit or d.unconsumed_tail:
            raise ValueError(f"decompressed size exceeds the {limit}-byte limit")
        if not d.eof:
            raise ValueError("truncated gzip data")
        out.append(chunk)
        rest = d.unused_data.lstrip(b"\x00")  # some writers pad with zero bytes
    return b"".join(out)


def load_records(data: bytes, max_bytes: int) -> list[dict[str, Any]]:
    """The `Records` list of a CloudTrail log file; `data` may be gzip or plain JSON. Raises ValueError otherwise."""
    if data[:2] == b"\x1f\x8b":
        data = gunzip_capped(data, max_bytes)
    elif len(data) > max_bytes:
        raise ValueError(f"file exceeds the {max_bytes}-byte limit")
    try:
        doc = orjson.loads(data)
    except orjson.JSONDecodeError as e:
        raise ValueError(f"not valid JSON: {e}") from None
    records = doc.get("Records") if isinstance(doc, dict) else None
    if not isinstance(records, list):
        raise ValueError("not a CloudTrail log file (no Records array)")
    return records


def row_of(rec: Any, file_index: int, record_index: int, table: dict[str, str]) -> Row | None:
    """The index row for one record, or None if it lacks the fields every event must have."""
    if not isinstance(rec, dict):
        return None
    try:
        eid, etime, source, name = rec["eventID"], rec["eventTime"], rec["eventSource"], rec["eventName"]
        ts = parse_time_us(etime)
    except (KeyError, ValueError, TypeError):
        return None
    if not (isinstance(eid, str) and isinstance(source, str) and isinstance(name, str)):
        return None
    ui = rec.get("userIdentity")
    if not isinstance(ui, dict):
        ui = {}
    sc = ui.get("sessionContext")
    iss = sc.get("sessionIssuer") if isinstance(sc, dict) else None

    def s(v: Any) -> str | None:  # only strings are kept, and equal strings share one object
        return table.setdefault(v, v) if v.__class__ is str else None

    ro = rec.get("readOnly")
    acct = s(rec.get("recipientAccountId")) or s(ui.get("accountId")) or ""
    return (
        eid, ts, etime, s(source) or "", s(name) or "", s(rec.get("awsRegion")) or "", acct,
        ro if ro.__class__ is bool else None, s(rec.get("sourceIPAddress")), s(rec.get("userAgent")),
        s(rec.get("errorCode")), s(ui.get("type")), s(ui.get("arn")), s(ui.get("principalId")),
        s(ui.get("accessKeyId")), s(iss.get("arn")) if isinstance(iss, dict) else None,
        s(ui.get("sourceIdentity")), issued_by(rec, source, name), file_index, record_index,
    )


class FileResult:
    """What a worker sends back for one file."""

    __slots__ = ("data_events", "entry", "malformed", "rows", "samples")

    def __init__(self, entry: FileEntry, rows: list[Row], malformed: int, samples: list[str], data_events: int = 0) -> None:
        self.entry, self.rows, self.malformed, self.samples, self.data_events = entry, rows, malformed, samples, data_events


def index_file(file_index: int, source: Source, max_bytes: int) -> FileResult:
    rel = source.rel
    try:
        data = source.read()
    except OSError as e:
        return FileResult(FileEntry(rel, "", 0, 0, "error", f"cannot read: {e.strerror}"), [], 0, [])
    digest = hashlib.sha256(data).hexdigest()
    size = len(data)
    try:
        records = load_records(data, max_bytes)
    except (ValueError, zlib.error) as e:
        return FileResult(FileEntry(rel, digest, size, 0, "error", str(e)), [], 0, [])
    table: dict[str, str] = {}
    rows: list[Row] = []
    bad = data_events = 0
    samples: list[str] = []
    for ri, rec in enumerate(records):
        row = row_of(rec, file_index, ri, table)
        if row is None:
            bad += 1
            if len(samples) < MAX_SAMPLES:
                samples.append(f"{rel}#{ri}")
        else:
            rows.append(row)
            if rec.get("eventCategory") == "Data":
                data_events += 1
    return FileResult(FileEntry(rel, digest, size, len(rows), "ingested"), rows, bad, samples, data_events)


def index_chunk(chunk: list[tuple[int, Source]], max_bytes: int) -> list[FileResult]:
    """Worker entry point: a batch of (file index, source)."""
    was_enabled = gc.isenabled()
    gc.disable()  # millions of short-lived containers: the cycle collector only slows this down
    try:
        return [index_file(fi, src, max_bytes) for fi, src in chunk]
    finally:
        if was_enabled:
            gc.enable()
