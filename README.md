# controlzee

Incident response as code for AWS. Give it CloudTrail logs and what you know about the attacker; it tells you what they
did, in a form other tools and people can rely on.

Named for CTRL+Z, but most of the time the right answer is rebuild, not undo.

**Status:** early, and the output formats may still change (schema 0.x). `controlzee scope` matches indicators, follows
the attacker to what they created or obtained, and says what the logs cannot show. `timeline`, `plan` and `report` turn
that into a story, an exposure list, a response plan and a readable report.

```
controlzee scope --logs ./logs --iocs iocs.yaml -o scope.json   # what happened (the evidence)
controlzee timeline scope.json                                  # timeline.json: in order, with tactics and exposure
controlzee plan scope.json                                      # plan.json: contain, investigate, eradicate, recover
controlzee report scope.json                                    # report.md: all of it, for people
```

## Scope an incident

```
uv run controlzee scope --logs ./cloudtrail-logs --iocs examples/iocs.yaml -o scope.json
```

To try it without logs of your own, `examples/iocs.yaml` matches a committed scenario:

```
uv run controlzee scope --logs tests/fixtures/01_leaked_key/logs --iocs examples/iocs.yaml -o scope.json
```

Or with flags only:

```
uv run controlzee scope --logs ./logs --access-key AKIA... --ip 198.51.100.77 --expr "access_key_1 AND ip_1"
```

- `--logs` takes files, directories or `s3://bucket/prefix` URLs of `.json` / `.json.gz` (repeatable). S3 objects are
  named by their key below the prefix, so the same logs give the same bytes whether downloaded or read in place.
- `--lookup-events REGION` (repeatable) also reads CloudTrail event history for `--window`: 90 days of management events
  kept regardless of trails, useful when a trail was stopped. `--aws-profile` picks credentials for S3 and event history.
- Strong indicators (access key, principal id, source identity) are enough alone. Weak ones (IP, user agent, ARN)
  need `--window START END`, otherwise they would match unrelated traffic.
- `--guardduty finding.json` imports the key, IP and time window from a GuardDuty finding.
- Writes `scope.json` and `scope.inputs.json` (every input file with its SHA-256). Same inputs give the same bytes.
- Never modifies the logs. Existing outputs are not overwritten without `--force`.

Events that matched a weak indicator but fell outside the expression or window are listed as near misses, so you can
see what the scope left out.

## Following the attacker

The seed events are only the start. When an in-scope call hands its caller a new credential or principal, every later
event made with it joins the scope, and so on from there:

| call | what is followed |
|---|---|
| `iam:CreateAccessKey` | the new access key |
| `iam:CreateUser` | the new user (console sign-ins and calls, by its user id) |
| `iam:CreateRole` | every session of the new role, and every `AssumeRole` into it, even from another account |
| `sts:AssumeRole`, `sts:GetSessionToken`, `sts:GetFederationToken` | the temporary key |
| `ec2:RunInstances` with an instance profile | the instance's role sessions |

Each followed event says which identity it acted as (`via`) and the chain of event ids back to its seed; `taint.identities`
lists everything followed. Confidence carries over: what a weak seed obtained stays weak. The seed window does not limit
propagation, since a key the attacker created is theirs whenever it is used. `--no-propagate` turns this off.

Not followed: existing roles the attacker merely assumed (only their own session is), passwords set on existing users,
Lambda functions, and anything outside these rules.

## What the logs cannot show

`scope.json` has a `coverage` section, and the terminal prints its notes:

- **Streams**: for each account and region, the span of time its logs cover.
- **Gaps**: silences during the incident that are long for that stream (at least `--gap-minutes`, default 60, and ten
  times its usual interval). A logging change in that account just before the silence is named as a possible cause.
  A quiet region is silent too, so a short or ordinary silence is not reported.
- **Tampering**: every call that stops, narrows or deletes CloudTrail, GuardDuty, Config or Security Hub, or leaves the
  organization, marked when the attacker made it.
- **Unlogged accounts**: accounts the attacker assumed roles in that none of the inputs come from.
- **Missing event types**: no data events (S3 object access is then invisible), or no read-only events.

## From scope to response

The other commands read only `scope.json`, check that it is unaltered (its `scope_sha256`), and write one file each.
Each output cites the scope it came from; the same scope always gives the same bytes.

- **`timeline`**: the attacker's identities (actors), every in-scope event with its tactic (named after the MITRE
  ATT&CK cloud tactics), target and result, the coverage gaps in place, and **exposure**: permission changes (and
  whether full administrative access was granted), secrets and parameters read, and every resource touched.
- **`plan`**: numbered steps in four phases. Contain: deactivate keys, revoke sessions of roles and users (an inline deny
  on `aws:TokenIssueTime`, as the console's "Revoke active sessions" does), cut attacker instances off their role.
  Investigate: accounts reached without logs, gaps to fill from event history, instances to preserve. Eradicate: delete
  what the attacker created, undo permission changes. Recover: turn logging and detection back on, rotate what was
  read, replace the leaked key. Each step has its evidence, its confidence and AWS CLI commands.
  **controlzee never runs them**: they are for a person to review and run. A value from the logs reaches a command
  only if it has the documented form for its kind, and is shell-quoted; otherwise the step is manual and says why.
- **`report`**: Markdown with the summary, coverage, timeline, exposure, plan and indicators. Everything from the logs
  is escaped, so log content cannot add links, HTML or table cells.

Try them on a committed scenario: `controlzee report tests/fixtures/02_role_chain/expected/scope.json -o report.md`, or
read `tests/fixtures/*/expected/report.md`.

## What it will not tell you

controlzee can only see what CloudTrail recorded; coverage says where that falls short, but cannot recover what was never
logged. The plan covers what the logs show the attacker did: it is a starting point for responders, not a guarantee
that nothing else was touched, and it does not know your environment (which roles are critical, what may be stopped).

## Development

```
uv sync
uv run pytest
uv run ruff check . && uv run mypy src
uv run python -m tests.builders.build_fixtures --check   # fixtures match their builders
uv run python -m controlzee.schemas                      # regenerate schemas/ after a model change
UPDATE_GOLDENS=1 uv run pytest tests/unit/test_scope_scenarios.py tests/unit/test_derived.py   # then review the diff
```

See [docs/architecture.md](docs/architecture.md) for the design and the performance measurements behind it.
