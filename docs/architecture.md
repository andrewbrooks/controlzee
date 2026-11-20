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

Measured once, with a generator that is not committed to this repository, so treat these as indicative and not reproducible. The dataset was synthetic, 1M records (200 gzipped files, 1.33 GB uncompressed) on a 28-thread WSL2 machine:

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
- No wall-clock time, hostname or absolute path in any artifact (except the operational records of `respond`: see
  Respond). Timings are printed to the terminal only.
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

An `AssumeRole` call also records which role it obtained a session of, and who called (`assumed_by`: the role name, the
caller's account, ARN and session issuer, taken from `userIdentity` when the record is indexed, because a cross-account
caller is logged with an account id and no ARN). That is how the entry into a role the attacker created is found when the
caller is another account with no tainted key.

`iam:UpdateAssumeRolePolicy` is read the same way: each AWS principal of the `Allow` statements of the logged document
becomes a `trusted_by` identity, "<role name>|<principal>" (an account, a user or role ARN, or `*`; the document is
size-capped and every value shape-checked). `acting_as` takes an optional index of these by role, and a later `AssumeRole`
row into that role by a caller the policy names is attacker-reachable, unless that caller (its role if it is a session,
else its ARN or account) had assumed the role before the change: the log shows the new policy and not the old, so history
is what separates a principal the change added from one that was already trusted. The history is read from the rows the
first time it is needed. The session the call hands out is then followed by the existing credential rule. The activity
check does not use `trusted_by` identities, since it has no history to apply that test.

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

## Respond

`respond/ops.py` is the closed list of changes controlzee can make. Each operation has argument shapes, CLI text (what
the plan shows), a read-only probe and the change. A probe reports the target's state, whether the change is already in
place, and the (IAM action, real resource ARN) pairs the change needs; for compound operations (delete a user) it lists
what is attached so every needed action is checked. `respond/run.py`:

- `dry_run` rebuilds the plan from the scope (never trusting a plan file), selects steps (operations only; disruptive
  ones only with `--allow-disruptive`; only the caller's account), identifies the caller (`sts:GetCallerIdentity`, then
  `iam:GetRole` to turn a role session into its role ARN), probes, and asks `iam:SimulatePrincipalPolicy` about every
  pair, grouped by resource. Anything not "allowed", and any probe that cannot read, fails it. Last, `respond/activity.py`
  checks whether the attacker acted after the scope: it reads CloudTrail event history from `coverage.period_end` to now
  (`ingest.remote.LookupInput`) in slices, earliest first (`plan_slices`: an hour, doubling to a day, so a long quiet window
  costs a few requests a region), for every log region of the scope and the home region, ordered by in-scope events
  (`regions_to_read`). One budget of events is spent slice by slice and, within a slice, region by region; a region that
  fails once is not asked again. `activity_check` records `slices_read`, `slices_total` and `last_time_read`, and a slice
  counts as read only when every region that could be read was read for it. Truncation is taken from botocore's
  `resume_token`, because the last page of the service's answer carries no `NextToken` when the cap cuts it short. The rows
  go through the normal ingest, and are matched with `taint.propagate.acting_as` against
  `taint.identities` plus the strong seed indicators (`seed.match.compile_indicator`). It adds `new_activity` and
  `activity_check` to the dry run and warnings, and nothing else: whatever goes wrong in it is a warning too.
- `execute` checks the dry run's seal, that it is not dated in the future, that it was made from the `--scope` given and that its steps are exactly what the plan rebuilt from that scope gives (an edited, re-sealed file cannot add an operation; the `--approve` hash is what ties execution to what was reviewed), version, pass, age and approval prefix, and that the caller is the same principal
  and account; then per step: validate again, probe again, compare identity, simulate again, journal `starting`, apply,
  journal the result, stop at the first failure (a `failed` or `drifted` step). In order: verify approval and dry run →
  refuse if the dry run's journal exists → identify the caller → create the journal (`O_EXCL`) and write its header →
  per step: re-probe → compare identity → simulate → journal `starting` → apply → journal result.

Execute is optimistic concurrency: read, compare, then act. The dry run reads each target and records its identity (the
ids and creation dates AWS never reuses); execute reads it again just before the change and acts only if the two
agree, the same idea as Terraform refreshing state before it applies. The check is on identity, not state: a key that
is already inactive is "already done", while a user deleted and made again under the same name is a different
resource and ends the run as `drifted`. No operation changes a resource's identity (a delete makes the next probe report
"done"), so earlier steps in a run cannot cause false drift. `OpSpec.identity_keys` lists the keys of each operation
(empty only where the arguments already name something AWS never reuses), and a test holds every probe to them.

The step journal is a write-ahead log: the intent to make a change is made durable (written, then `fsync`ed) before the
change is made, and the outcome after it. `respond/journal.py` creates `response.<first 16 of dryrun_sha256>.journal.jsonl`
next to `--out` with `O_EXCL` and mode 0600, one canonical JSON object per line: a header (dry run hash, caller, start
time), then per step a `starting` line, written only when a change is about to be made, and a result line. A run killed
between the two leaves a `starting` line with no result: that step may be partly made, so a person checks its target.
There is no resume: they run a new dry run, whose probes report what is already done. The same file is the replay guard.
A dry run whose journal exists is refused before any AWS call, and the file is created only after the checks that
precede the first change, so wrong credentials do not use a dry run up. `response.json` cites the journal's sha256
(`journal_sha256`, kept as a running hash of the bytes written). If a line cannot be written, no change is made without
its `starting` line, and the run stops.

Nothing is executed through a shell. `argcheck.py` holds the patterns for command-line values that reach AWS.
`dryrun.json`, `response.json` and the step journal are the exceptions to "no wall-clock time in artifacts": when the
check and each change happened is evidence the response needs.

## Untrusted input

Log content is attacker-influenced. User agents, names and request parameters can carry terminal escapes, bidirectional
overrides or markup. Anything printed passes through `safety.clean`; rich consoles run with `markup=False`.
Files are opened read-only; outputs are written atomically with mode 0600 and never overwrite without `--force`.
