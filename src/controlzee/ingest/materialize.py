"""Second pass: build full `Event` models for the (few) events that ended up in scope."""
from __future__ import annotations

import gc
import multiprocessing
import os
from collections import defaultdict
from collections.abc import Sequence
from concurrent.futures import ProcessPoolExecutor

from controlzee.ingest.index import R_FILE, R_ID, R_REC, EventIndex
from controlzee.ingest.load import MAX_DEFAULT_WORKERS, PARALLEL_MIN_BYTES, IngestError
from controlzee.ingest.parse import load_records
from controlzee.ingest.source import Source
from controlzee.model.event import Event, SourceRef
from controlzee.normalize import event_from_record


def _file_events(file_index: int, source: Source, wanted: list[int], max_bytes: int, embed_raw: bool) -> list[tuple[int, int, Event]]:
    records = load_records(source.read(), max_bytes)
    out = []
    for ri in wanted:
        if ri >= len(records):
            raise IngestError(f"{source.rel} changed while scoping (record {ri} is gone)")
        out.append((file_index, ri, event_from_record(records[ri], SourceRef(input=source.rel, record=ri), embed_raw=embed_raw)))
    return out


def _chunk(items: list[tuple[int, Source, list[int]]], max_bytes: int, embed_raw: bool) -> list[tuple[int, int, Event]]:
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        return [e for fi, src, wanted in items for e in _file_events(fi, src, wanted, max_bytes, embed_raw)]
    finally:
        if was_enabled:
            gc.enable()


def materialize(index: EventIndex, positions: Sequence[int], *, max_bytes: int, embed_raw: bool = False,
                workers: int | None = None) -> dict[int, Event]:
    """Events for the given row positions, keyed by position. Re-reads only the files that contain them."""
    by_file: dict[int, list[int]] = defaultdict(list)
    for pos in positions:
        row = index.rows[pos]
        by_file[row[R_FILE]].append(row[R_REC])
    items = [(fi, index.sources[fi], sorted(recs)) for fi, recs in sorted(by_file.items())]
    n = workers or min(os.cpu_count() or 1, MAX_DEFAULT_WORKERS)
    if n <= 1 or len(items) <= 2 or sum(src.size for _, src, _ in items) < PARALLEL_MIN_BYTES:
        found = _chunk(items, max_bytes, embed_raw)
    else:
        size = max(1, -(-len(items) // (n * 4)))
        ctx = multiprocessing.get_context("spawn")
        with ProcessPoolExecutor(max_workers=n, mp_context=ctx) as pool:
            futures = [pool.submit(_chunk, items[i:i + size], max_bytes, embed_raw) for i in range(0, len(items), size)]
            found = [e for f in futures for e in f.result()]
    events = {(fi, ri): ev for fi, ri, ev in found}
    out: dict[int, Event] = {}
    for pos in positions:
        row = index.rows[pos]
        ev = events[(row[R_FILE], row[R_REC])]
        if ev.event_id != row[R_ID]:
            raise IngestError(f"{ev.source.input} changed while scoping (event ids no longer match the index)")
        out[pos] = ev
    return out
