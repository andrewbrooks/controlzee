# Architecture notes

## Pipeline

ingest -> normalize -> seed -> propagate taint -> coverage  =>  scope.json  =>  timeline (classify, exposure) / plan / report

`scope.json` is the spine: every later command reads it and nothing else, after checking its seal and schema version
(`artifacts.load_scope`). Derived documents are sealed too and cite the `scope_sha256` they came from.

## Why ingest is two passes

Scoping has to be fast on millions of events, and almost all of them are irrelevant. So:

1. **Index pass.** Each file is read, hashed, decompressed (with a size cap) and parsed with orjson. Per record only the
   20 fields needed for matching and propagation are kept, as a plain tuple (`ingest/index.py`, `R_*` constants). No pydantic objects.
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
Taint can reach any event (any of them may use a key the attacker obtained), so rows cannot be dropped early.
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

## Taint propagation

`taint/rules.py` maps a handful of calls to what a successful one hands its caller: an access key, a user id, a role id,
an instance id. The index workers apply it to every record (one dict lookup for the common case) and keep the result in
the row's `issued` field, so propagation never re-reads a file.

`taint/propagate.py` then walks breadth first from the seeds, strong seeds first and weak ones after. Each round takes
the identities issued by the newest in-scope events and makes one pass over the rows from the earliest of them onwards,
adding every event that acted as one (by access key, principal id, role-id prefix of the principal id, or instance-id
session name). An event cannot act as an identity before the event that issued it. Each event and identity is reached
once, by its shortest chain; an identity reached from a strong seed is strong.

An `AssumeRole` call also records which role it obtained a session of. That is how the entry into a role the attacker
created is found when the caller is another account with no tainted key.

Measured on 1M synthetic rows: about 0.4 s per round. Most chains are a few rounds deep.

## Coverage

`coverage.py` makes one pass over the rows (about 0.2 s per 1M) to build per-(account, region) streams, collect every
silence longer than `--gap-minutes`, and list tampering calls; data events are counted per file during the index pass.
A silence is kept when it overlaps the incident period (the seed window together with the in-scope events) and is at
least ten times the stream's mean interval, so busy streams flag missing logs while quiet ones do not flag every night.
The mean is used rather than the median so the pass needs constant memory per stream.

## Sources

`ingest/remote.py` adds two `Source` kinds behind the same discovery as local directories. `S3Input` lists a prefix and
yields `S3Source`s (bucket, key, size: picklable; each worker process makes its own client). `LookupInput` queries
CloudTrail event history once, in the parent, for exactly the seed window, sorts the records and keeps them as one
in-memory file per region, so both passes read identical bytes and the manifest hash does not depend on API order.
AWS errors become `IngestError` (listing) or an error file entry (fetching), never a traceback.

## Timeline, exposure, plan, report

`classify.py` gives each call a tactic (a table keyed by service and event name, Lambda's API-version suffix removed;
reads default to discovery) and extracts resources from the request parameters each service documents, by a fixed
table, so an unexpected parameter cannot pose as a resource. `timeline.py` groups events into actors, merges coverage
gaps in by start time, and derives exposure (resources by service, type, name and access; permission changes, with
"full control" for AdministratorAccess, IAMFullAccess or an inline Allow of `*`; secrets and parameters read).

`plan.py` turns the scope's tainted identities and in-scope events into steps. The rules are per kind of evidence: long-
term keys used (deactivate, later replace for a legitimate owner), temporary credentials (TokenIssueTime deny on the
user or role, with the time left to the shell so the plan has no clock), created users, roles and instances, permission
changes on existing principals, in-scope tampering, credentials read, unlogged accounts and gaps. Every log-derived value
in a command is checked against a shape for its kind (`_SHAPES`) and shell-quoted; a mismatch turns the step manual.

`report.py` renders Markdown from the scope plus the timeline and plan it derives, escaping every log-derived value
(`md`: `safety.clean`, then backslash escapes for Markdown punctuation and broken autolinks) and fencing commands with a
fence longer than any backtick run in them.

## Untrusted input

Log content is attacker-influenced. User agents, names and request parameters can carry terminal escapes, bidirectional
overrides or markup. Anything printed passes through `safety.clean`; rich consoles run with `markup=False`.
Files are opened read-only; outputs are written atomically with mode 0600 and never overwrite without `--force`.
