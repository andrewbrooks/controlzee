"""Scoping: logs + indicators in, `scope.json` out. Pure of side effects apart from reading the inputs."""
from __future__ import annotations

import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from controlzee import canonical
from controlzee.ingest.index import (
    R_ACCOUNT,
    R_AK,
    R_ARN,
    R_ERR,
    R_ID,
    R_IP,
    R_NAME,
    R_PID,
    R_REGION,
    R_SOURCE,
    R_TIME,
    EventIndex,
)
from controlzee.ingest.load import IngestOptions, load_index
from controlzee.ingest.materialize import materialize
from controlzee.ingest.parse import DEFAULT_MAX_FILE_BYTES
from controlzee.model.common import SCHEMA_VERSION, Confidence, tool_info
from controlzee.model.ioc import SeedSpec
from controlzee.model.scope import (
    FileProblem,
    InputsSummary,
    NearMiss,
    NearMissSummary,
    Scope,
    ScopedEvent,
    SeedInfo,
    Summary,
)
from controlzee.seed import expr
from controlzee.seed.match import run_seed

LISTED_PROBLEMS = 20


@dataclass(frozen=True)
class ScopeOptions:
    workers: int | None = None
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    near_miss_limit: int = 500
    embed_raw: bool = False


@dataclass(frozen=True)
class Timings:
    """Wall-clock seconds per phase. Reported to the terminal only: they would make artifacts non-reproducible."""

    ingest_s: float
    seed_s: float
    materialize_s: float


@dataclass(frozen=True)
class ScopeOutput:
    scope: Scope
    scope_document: dict[str, Any]  # sealed, ready for canonical.dumps
    inputs_document: dict[str, Any]  # the sidecar file list
    timings: Timings

    @property
    def scope_bytes(self) -> bytes:
        return canonical.dumps(self.scope_document)

    @property
    def inputs_bytes(self) -> bytes:
        return canonical.dumps(self.inputs_document)


def _inputs_document(index: EventIndex) -> dict[str, Any]:
    files = [{"path": f.path, "sha256": f.sha256, "size_bytes": f.size_bytes, "records": f.records, "status": f.status,
              "note": f.note} for f in index.files]
    return {"schema_version": SCHEMA_VERSION, "tool": tool_info(), "manifest_sha256": canonical.sha256_hex(canonical.dumps(files)),
            "files": files}


def _inputs_summary(index: EventIndex, manifest_sha256: str) -> InputsSummary:
    rows = index.rows
    by_status = Counter(f.status for f in index.files)
    return InputsSummary(
        manifest_sha256=manifest_sha256, file_count=len(index.files), ingested_files=by_status["ingested"],
        skipped_files=by_status["skipped"], error_files=by_status["error"], ignored_files=index.ignored_files,
        event_count=len(rows), duplicates_removed=index.duplicates_removed, malformed_records=index.malformed_records,
        first_event_time=rows[0][R_TIME] if rows else None, last_event_time=rows[-1][R_TIME] if rows else None,
        accounts=sorted({r[R_ACCOUNT] for r in rows}), regions=sorted({r[R_REGION] for r in rows}),
        errors=[FileProblem(path=f.path, note=f.note or "") for f in index.files if f.status == "error"][:LISTED_PROBLEMS],
        skipped=[FileProblem(path=f.path, note=f.note or "") for f in index.files if f.status == "skipped"][:LISTED_PROBLEMS],
        malformed_samples=index.malformed_samples,
    )


def build_scope(inputs: Sequence[Path], spec: SeedSpec, options: ScopeOptions | None = None) -> ScopeOutput:
    options = options or ScopeOptions()
    t0 = time.perf_counter()
    index = load_index(inputs, IngestOptions(workers=options.workers, max_file_bytes=options.max_file_bytes))
    t1 = time.perf_counter()
    seeds = run_seed(index, spec, options.near_miss_limit)
    t2 = time.perf_counter()
    events = materialize(index, [h.row for h in seeds.hits], max_bytes=options.max_file_bytes, embed_raw=options.embed_raw,
                         workers=options.workers)
    t3 = time.perf_counter()

    scoped = [ScopedEvent(event=events[h.row], confidence=h.confidence, matched_indicators=list(h.matched)) for h in seeds.hits]
    near = []
    for nm in seeds.near_misses:
        r = index.rows[nm.row]
        near.append(NearMiss(event_id=r[R_ID], event_time=r[R_TIME], event_source=r[R_SOURCE], event_name=r[R_NAME],
                             source_ip=r[R_IP], principal=r[R_ARN] or r[R_PID] or r[R_AK], matched_indicators=list(nm.matched),
                             reason="window" if nm.reason == "window" else "expression"))
    inputs_doc = _inputs_document(index)
    summary = Summary(
        events_in_scope=len(scoped),
        by_confidence={c.value: sum(1 for s in scoped if s.confidence is c) for c in Confidence},
        by_account=dict(sorted(Counter(s.event.recipient_account_id for s in scoped).items())),
        by_region=dict(sorted(Counter(s.event.aws_region for s in scoped).items())),
        failed_calls=sum(1 for h in seeds.hits if index.rows[h.row][R_ERR] is not None),
        first_event_time=scoped[0].event.event_time if scoped else None,
        last_event_time=scoped[-1].event.event_time if scoped else None,
    )
    scope = Scope(
        tool=tool_info(), inputs=_inputs_summary(index, inputs_doc["manifest_sha256"]),
        seeds=SeedInfo(expression=expr.to_text(expr.parse(spec.expression)), indicators=list(spec.indicators), window=spec.window),
        summary=summary, events=scoped, near_misses=near,
        near_miss_summary=NearMissSummary(total=seeds.near_miss_total, listed=len(near),
                                          by_reason=dict(sorted(seeds.near_miss_by_reason.items())),
                                          by_indicator=dict(sorted(seeds.near_miss_by_indicator.items()))),
    )
    document = canonical.seal(scope.model_dump(mode="json"), "scope_sha256")
    return ScopeOutput(Scope.model_validate(document), document, inputs_doc, Timings(t1 - t0, t2 - t1, t3 - t2))
