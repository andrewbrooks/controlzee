# Architecture notes

## Pipeline (milestone 1 covers the first four steps)

ingest -> normalize -> seed -> (propagate taint) -> (timeline, exposure, coverage) -> (classify, plan) -> (report)

`scope.json` is the spine: every later command reads it. Steps in parentheses arrive in later milestones.

## Why ingest is two passes

Scoping has to be fast on millions of events, and almost all of them are irrelevant. So:

1. **Index pass.** Each file is read, hashed, decompressed (with a size cap) and parsed with orjson. Per record only the
   19 fields needed for matching are kept, as a plain tuple (`ingest/index.py`, `R_*` constants). No pydantic objects.
2. **Materialize pass.** Only the files that hold in-scope events are read again, and full `Event` models are built for
   those events alone. An event-id check catches a file that changed between the passes.

Measured on a synthetic 1M-record dataset (200 gzipped files, 1.33 GB uncompressed) on a 28-thread WSL2 machine:

| choice | finding |
|---|---|
| tuples instead of pydantic models | design choice, not measured here: building a validated model per event is work the index pass does not need for events nobody will look at |
| tuples vs. columnar `array` storage | tuples: 2.27 s total, 691 MB parent RSS. Columnar: 3.85 s, 959 MB (the merge needs string remapping and a sort by index). Tuples win and are easier to read; 8 workers, 1M rows |
| garbage collector off in workers | millions of short-lived containers; the cycle collector is not needed for them; not re-measured in isolation |
| interning strings per worker | expected memory saving, since a few hundred distinct user agents, ARNs and IPs repeat across millions of rows; not re-measured in isolation |
| spawn-based process pool | same behaviour on Linux and macOS; no fork-with-threads hazards |
| worker cap of 16 | no measured gain beyond it |
| orjson | parsing was only about 13% faster than the stdlib. The case for it is writing: 6.4x faster output, and byte-identical to `json.dumps(sort_keys=True, indent=2)`, which a property test checks |

End to end on the 1M-event set: about 2.6 s. Parallelism is skipped for inputs under 8 MiB or with at most two files,
where starting processes costs more than it saves.

**Memory.** The index holds one tuple per event, so memory grows with event count: roughly 10M events per 8 GB.
`TODO(milestone-2)` in `ingest/load.py` marks the place to drop rows that nothing downstream can need.
A disk-backed index is the fallback if someone scopes much more than that in one run.

## Determinism

Output must be byte-identical for the same inputs. How:

- Canonical JSON: sorted keys, 2-space indent, UTF-8, trailing newline. No floats in artifacts.
- No wall-clock time, hostname or absolute path in any artifact. Timings are printed to the terminal only.
- Events sort by `(event_time in microseconds, event_id)`. Duplicates (several trails delivering one event) are
  removed by `eventID`; the copy from the alphabetically first file wins.
- Files are processed in name order; worker results are merged in submission order, not completion order.
- Sets are never iterated unsorted.
- `scope_sha256` seals the document; `manifest_sha256` ties it to `<scope>.inputs.json`.

`tests/determinism/` checks hash seeds, worker counts, file order, file splitting and gzip vs. plain.

## Seeding

Indicators are strong (access key id, principal id, source identity) or weak (principal ARN, source IP, user agent).
An expression combines them with AND / OR. A branch is strong if a strong indicator took part in it; an AND of weak
indicators stays weak. A weak-only expression requires a window with a start and an end. Events that matched a weak
indicator but were left out are recorded as near misses (counted in full, listed up to a limit) so a responder can see
what the expression excluded.

## Untrusted input

Log content is attacker-influenced. User agents, names and request parameters can carry terminal escapes, bidirectional
overrides or markup. Anything printed passes through `safety.clean`; rich consoles run with `markup=False`.
Files are opened read-only; outputs are written atomically with mode 0600 and never overwrite without `--force`.
