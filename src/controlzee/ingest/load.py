"""Discover input files, index them (in parallel when worth it), and merge deterministically."""
from __future__ import annotations

import gc
import multiprocessing
import os
from collections.abc import Iterator, Sequence
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from operator import itemgetter
from pathlib import Path

from controlzee.ingest.index import R_ID, R_TS, EventIndex, FileEntry, Row
from controlzee.ingest.parse import DEFAULT_MAX_FILE_BYTES, FileResult, index_chunk
from controlzee.ingest.source import LocalSource, Source

PARALLEL_MIN_BYTES = 8 * 1024 * 1024  # below this a process pool costs more than it saves
MAX_DEFAULT_WORKERS = 16  # measured: no gain beyond this (see docs/architecture.md)
_SUFFIXES = (".json", ".json.gz")


class IngestError(Exception):
    """The inputs cannot be used at all (missing path, nothing to read)."""


@dataclass(frozen=True)
class IngestOptions:
    workers: int | None = None  # None: choose from the CPU count; 1: no subprocesses
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES


def _skip_reason(rel: str) -> str | None:
    parts = rel.split("/")
    if any(p == "CloudTrail-Digest" for p in parts) or "_CloudTrail-Digest_" in parts[-1]:
        return "CloudTrail digest file (log integrity metadata, not events)"
    if any(p == "CloudTrail-Insight" for p in parts) or "_CloudTrail-Insight_" in parts[-1]:
        return "CloudTrail Insights file (not API events)"
    return None


def _walk(root: Path) -> Iterator[tuple[str, Path]]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            yield full.relative_to(root).as_posix(), full


def discover(inputs: Sequence[Path]) -> tuple[list[Source], list[FileEntry], int]:
    """(files to index, files skipped on purpose, count of unrelated files ignored), in a deterministic order."""
    found: list[tuple[int, str, Path]] = []
    ignored = 0
    for n, root in enumerate(inputs):
        if not root.exists():
            raise IngestError(f"input path does not exist: {root}")
        if root.is_file():
            found.append((n, root.name, root))
            continue
        for rel, full in _walk(root):
            if rel.endswith(_SUFFIXES):
                found.append((n, rel, full))
            else:
                ignored += 1
    names = [rel for _, rel, _ in found]
    if len(set(names)) != len(names):  # same relative name under two inputs: keep them apart, deterministically
        found = [(n, f"{n}:{rel}", full) for n, rel, full in found]
    found.sort(key=lambda t: t[1])
    sources: list[Source] = []
    skipped: list[FileEntry] = []
    for _, rel, full in found:
        reason = _skip_reason(rel)
        if reason:
            skipped.append(FileEntry(rel, "", full.stat().st_size, 0, "skipped", reason))
        else:
            sources.append(LocalSource(rel, str(full), full.stat().st_size))
    return sources, skipped, ignored


def _chunks(sources: list[Source], workers: int) -> list[list[tuple[int, Source]]]:
    items = list(enumerate(sources))
    size = max(1, -(-len(items) // (workers * 4)))
    return [items[i:i + size] for i in range(0, len(items), size)]


def _index_all(sources: list[Source], options: IngestOptions) -> list[FileResult]:
    workers = options.workers or min(os.cpu_count() or 1, MAX_DEFAULT_WORKERS)
    total = sum(s.size for s in sources)
    if workers <= 1 or len(sources) <= 2 or total < PARALLEL_MIN_BYTES:
        return index_chunk(list(enumerate(sources)), options.max_file_bytes)
    ctx = multiprocessing.get_context("spawn")  # identical behaviour on Linux and macOS, no fork-with-threads hazards
    with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as pool:
        futures = [pool.submit(index_chunk, chunk, options.max_file_bytes) for chunk in _chunks(sources, workers)]
        return [r for f in futures for r in f.result()]  # submission order == file order, whatever finishes first


def load_index(inputs: Sequence[Path], options: IngestOptions | None = None) -> EventIndex:
    """Index every CloudTrail file under `inputs`. The result does not depend on worker count or file arrival order."""
    options = options or IngestOptions()
    sources, skipped, ignored = discover(inputs)
    if not sources:
        raise IngestError("no CloudTrail log files (.json / .json.gz) found in the given inputs")
    # Rows are all kept in memory (about 10M events per 8 GB). Taint can reach any row, since any event may act as an
    # identity the attacker obtained, so none can be dropped early; a disk-backed index is the fallback beyond that.
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        results = _index_all(sources, options)
        seen: set[str] = set()
        rows: list[Row] = []
        dup = 0
        for res in results:
            for row in res.rows:
                if row[R_ID] in seen:
                    dup += 1
                    continue
                seen.add(row[R_ID])
                rows.append(row)
        rows.sort(key=itemgetter(R_TS, R_ID))
    finally:
        if was_enabled:
            gc.enable()
    samples = [s for res in results for s in res.samples][:10]
    entries = sorted([res.entry for res in results] + skipped, key=lambda e: e.path)
    return EventIndex(rows=rows, files=entries, duplicates_removed=dup,
                      malformed_records=sum(r.malformed for r in results), malformed_samples=samples,
                      data_events=sum(r.data_events for r in results), ignored_files=ignored, sources=sources)
