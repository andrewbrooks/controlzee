# Spec: closing the time-of-check to time-of-use gaps in `controlzee respond` (lean version)

Suggested location in the repo: `docs/specs/respond-toctou.md`. Read `CLAUDE.md` first; every invariant there still holds.

## Why

`respond` already ties execution to what a person reviewed: the dry run is sealed, `--approve` takes its sha256, and
execute refuses a dry run that is edited, stale, future-dated, or checked for another principal. It rebuilds the plan
from the sealed scope and probes and simulates each step again just before it runs.

Three gaps remain between what was checked and what is true when a change is made:

1. **Same name, different thing.** Execute re-probes by name. If user `backup-svc` is deleted and recreated by someone
   else between the dry run and execute, the step acts on the new user.
2. **A killed run leaves no record.** `response.json` is written after the loop ends, so changes already made can go
   unrecorded.
3. **The attacker may still be active.** Nothing checks whether a tainted identity acted after the scope was built, so
   the plan can be missing something the attacker made since.

Three PRs, in this order, each mergeable on its own. Bump `SCHEMA_VERSION` to `0.3` in the first PR that changes a model
and regenerate `schemas/` (`uv run python -m controlzee.schemas`).

## Phase 1: identity facts on every step

**Idea.** Status changes (a key already inactive, logging already on) are handled today by `probe.done`. What isn't
handled is the target being a different resource with the same name. So each probe records the target's identity, not
its state, and execute checks it hasn't changed. No step in a run changes a resource's identity (a delete makes the next
probe report `done`), so earlier steps can't cause false drift.

**Model**

- `ops.Probe` gains `identity: dict[str, str]`, empty when the target doesn't exist.
- `OpSpec` gains `identity_keys: tuple[str, ...]`, declared explicitly for every operation, empty only where the
  arguments already name something AWS never reuses. Leave a one-line comment where it's empty.
- `DryRunStep` gains `identity: dict[str, str]`, copied from the probe.
- `ExecutedStep.result` gains `"drifted"`.

**Identity keys**

| operations | keys |
|---|---|
| access keys, login profile, user policies, group membership, user revocation, `delete_user` | `user_id` (the `AIDA…` id), `user_create_date` |
| role policies, role revocation, `delete_role` | `role_id` (the `AROA…` id), `role_create_date` |
| group policies | `group_id`, `group_create_date` |
| `delete_lambda_function` | `function_arn`, `code_sha256`, `last_modified` (Lambda has no create date; these change if the function is replaced) |
| `delete_bucket` | `bucket_creation_date` |
| instance operations | none: instance ids are never reused |
| trail, Config, GuardDuty, Security Hub | none: turning logging or detection back on is right whichever resource it is |

`group_id` is also checked for `remove_user_from_group`, alongside `user_id`.

**Execute rule.** After the re-probe, and only when the probe is neither `problem` nor `done`: if `probe.identity` differs
from the step's recorded `identity`, the result is `drifted`, with a detail naming what changed (`user backup-svc was
AIDA…1 at the dry run, is AIDA…2 now: run the dry run again`), through `safety.clean`. Nothing is applied, and later
steps are `not run`, as with any failure.

**Dry run.** Show the identity under each step, since it's part of what the person approves.

**Tests** (`tests/fake_aws.Account`, made-up identifiers only)

- A user deleted and recreated with the same name between dry run and execute: `drifted`, nothing changed, later steps
  `not run`.
- The same for a role, and for a Lambda function whose code changed.
- Deactivate, then delete, the same key in one run: both `done`.
- A target deleted between dry run and execute: `already done`, not `drifted`.
- A parametrized test over `OPS`: every operation declares `identity_keys`, and every probe of an existing target
  returns exactly those keys.
- Golden `dryrun.json` fixtures updated; review the diff.

## Phase 2: a step journal

**Journal.** Execute writes `response.<first 16 of dryrun_sha256>.journal.jsonl` next to `--out`, created with `O_EXCL`,
mode 0600, one canonical JSON object per line, each followed by `fsync`:

- a header: `dryrun_sha256`, caller, start time;
- for each step, a `starting` line **before** `apply` is called, and a result line after.

If that journal already exists, execute refuses: "this dry run was already executed (see <journal>); run a new dry run".
That is the whole replay guard. There is no resume: after an interrupted run, the person reads the journal and runs a new
dry run, whose probes report what's already done.

`response.json` is unchanged except that it cites the journal's sha256. Add journals to the list in `CLAUDE.md` of
artifacts allowed to hold wall-clock times.

**Tests**

- An exception raised inside `apply` on step 3: the journal has `starting` for step 3 and no result line.
- Executing the same dry run twice from the same folder: the second is refused before any AWS call.
- The journal and `response.json` agree on every step, and `response.json` cites the journal's hash.

README: one line saying the guard is per folder, not shared between machines.

## Phase 3: a warning when the attacker acted after the scope

**Check (dry run only).** Read CloudTrail event history from `scope.coverage.period_end` to now, with
`ingest.remote.LookupInput` (the same path as `scope --lookup-events`), for every region in `scope.coverage.streams` plus
the home region. Match those events against `scope.taint.identities` with the existing matcher, as strong seeds. That
covers every identity kind (`access_key_id`, `principal_id`, `role_id`, `instance_id`, `function_name`) with one
definition of "this is the attacker".

**Result.** A warning, not a failure, for now:

- New activity found: `dryrun.json` gets `new_activity` (time, identity, event name, region, event id; all cleaned) and a
  warning, printed prominently: "tainted identities acted after this scope was built; contain now if you need to, then
  scope again before removing what they made."
- No new activity: say so, and say that event history can lag by about 15 minutes, so this isn't proof.
- Check couldn't run (permission, throttling): a warning saying so. The dry run still passes.
- Cap the events read (`--activity-check-max-events`, default 50,000); a capped check says it was incomplete.

Event-history records are hostile input like any log: same size caps, same `safety.clean` on anything printed. Add
`cloudtrail:LookupEvents` to the README's permission list.

**Tests:** add `lookup_events` to `tests/fake_aws.Account`, validated against botocore's model.

- A tainted key calls after `period_end`: the dry run passes, with the event in `new_activity` and the warning printed.
- A role session (`principal_id` identity) acting after `period_end` is found too.
- No new activity: no `new_activity` entries, and the lag note is printed.
- `LookupEvents` denied: a warning, and the dry run still passes.

## Docs and changelog (each PR)

- README `respond` section: one line per check on what it defends against.
- `docs/architecture.md`: execute loop in order: verify approval and dry run → per step: re-probe → compare identity →
  simulate → journal `starting` → apply → journal result.
- `CHANGELOG.md` under Unreleased.
- `uv run pytest -q`, `uv run ruff check . && uv run mypy src`, schemas regenerated, goldens reviewed.

## Later, if the tool is used beyond a proof of concept

- Make new attacker activity fail the dry run for eradicate and recover steps, once the warning's noise is known.
- A signed approval (`kms:Sign` by an approver role, `kms:Verify` only for the responder) that names who approved, and
  optional two-person approval for disruptive steps.
- A replay guard shared between machines (an S3 object written with `If-None-Match: *`).
