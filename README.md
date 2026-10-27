# controlzee

Incident response as code for AWS. Give it CloudTrail logs and what you know about the attacker; it tells you what they
did, in a form other tools and people can rely on.

Named for CTRL+Z, but most of the time the right answer is rebuild, not undo.

**Status:** early. `controlzee scope` matches indicators (milestone 1), follows the attacker to what they created or
obtained (milestone 2) and says what the logs cannot show (milestone 3). Timeline, exposure, remediation plans and reports
are not built yet.

## Scope an incident

```
uv run controlzee scope --logs ./cloudtrail-logs --iocs examples/iocs.yaml -o scope.json
```

Or with flags only:

```
uv run controlzee scope --logs ./logs --access-key AKIA... --ip 198.51.100.77 --expr "access_key_1 AND ip_1"
```

- `--logs` takes files or directories of `.json` / `.json.gz` (repeatable). S3 and CloudTrail event history come next.
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

## What it will not tell you

Scoping finds the events that match your indicators and what can be followed from them. It can only see what CloudTrail
recorded; coverage says where that falls short, but cannot recover what was never logged. It does not yet order events
into a timeline, assess what was exposed, or plan the response.

## Development

```
uv sync
uv run pytest
uv run ruff check . && uv run mypy src
uv run python -m tests.builders.build_fixtures --check   # fixtures match their builders
uv run python -m controlzee.schemas                      # regenerate schemas/ after a model change
UPDATE_GOLDENS=1 uv run pytest tests/unit/test_scope_scenarios.py   # then review the diff
```

See [docs/architecture.md](docs/architecture.md) for the design and the performance measurements behind it.
