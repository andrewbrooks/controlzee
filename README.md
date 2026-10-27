# controlzee

Incident response as code for AWS. Give it CloudTrail logs and what you know about the attacker; it tells you what they
did, in a form other tools and people can rely on.

Named for CTRL+Z, but most of the time the right answer is rebuild, not undo.

## Purpose

AI is changing everything, including attacker behavior and incident response. The new attacker patterns are programmatic and precise, which means incident response must also be programmatic and precise. With AI-enabled attacks, we’re seeing attackers having higher success rates because LLMs give them speed and precision. Attacks can be customized in short order, and building new tooling for reconnaissance, exfiltration, and persistence is faster and cheaper than it’s ever been.

controlzee is a proof of concept intended to demonstrate what programmatic incident response looks like in a world of agentic and AI-enabled attackers. You give it your CloudTrail logs and what you know about the attacker, like a leaked access key or a suspicious IP. It traces everything that key did, every role it assumed, and every resource it created, then follows what those resources did on their own. For example, if the attacker launched an EC2 instance with a privileged role and that instance changed a bucket policy twenty minutes later, controlzee connects those dots, which is something an analyst pivoting through queries may overlook.

What you get back is a timeline of the attack, a list of the secrets and data the attacker could have touched, the places where your logs can’t tell you the full story, and a plan for each affected resource: revert it, rebuild it, rotate it, or have a human look at it. Every run produces the same output from the same inputs, so the results can go in a ticket, get reviewed, and be rerun as you learn more.

controlzee won’t fix every incident automagically. The point is to show what incident response looks like when it moves at the same speed as the attacker.

**Status:** early, and the output formats may still change (schema 0.x). `controlzee scope` matches indicators, follows
the attacker to what they created or obtained, and says what the logs cannot show. `timeline`, `plan` and `report` turn
that into a story, an exposure list, a response plan and a readable report. `respond` reverts what the attacker did,
after a dry run that a person has reviewed and approved.

```
controlzee scope --logs ./logs --iocs iocs.yaml -o scope.json   # what happened (the evidence)
controlzee timeline scope.json                                  # timeline.json: in order, with tactics and exposure
controlzee plan scope.json                                      # plan.json: contain, investigate, eradicate, recover
controlzee report scope.json                                    # report.md: all of it, for people
controlzee respond dry-run scope.json                           # dryrun.json: what would change, and may we? (changes nothing)
controlzee respond execute dryrun.json --approve <sha256>       # response.json: make the approved changes
```

## Revert the attacker's changes: `controlzee respond`

controlzee can carry out the plan's steps in AWS: deactivate the keys the attacker used or made, revoke their sessions,
cut their instances off from their roles, undo the permissions they granted, turn logging and detection back on and,
when you allow it, delete the users and roles they created. It never does this unasked. There are always two steps,
with a person in between.

**1. Dry run (changes nothing).**

```
controlzee respond dry-run scope.json --aws-profile incident-response
```

It works out who the supplied credentials are, reads the current state of every target (is the key still active? is the
trail logging?) and asks the IAM policy simulator whether those credentials may make every call each change needs, on
the target's real ARN. It prints every step with what it would do, the state now and each permission, and writes
`dryrun.json`. **If any permission is missing or any state cannot be read, the dry run fails (exit 4)** and nothing can
be executed from it. Fix the credentials, or narrow the run with `--steps A01,A03`, and run it again.

What is left out, and why, is listed too: manual steps (a new secret, a trust policy the logs do not show), steps for
another account, and disruptive steps (delete, stop, terminate), which need `--allow-disruptive`.

**2. Review, approve, execute.**

```
controlzee respond execute dryrun.json --approve 3f9a1c0be2d47a65
```

`--approve` takes the dry run's sha256, as the dry run prints it: it is your approval of exactly that dry run. Execute
refuses if the dry run failed, was changed after it was written, is older than an hour (`--max-age-minutes`), or if
the credentials are not the same principal in the same account that the dry run checked. It then runs the steps in plan
order, reads each target again first (anything already put right is skipped), stops at the first failure, and writes
`response.json`: every step, its result and when it was made.

**Safeguards.**

- No shell, ever: every change is a boto3 call with typed parameters. The AWS CLI text in the plan is for people.
- The dry run builds the plan from the sealed `scope.json` itself, so only operations the plan builder produced (from a
  fixed list) are put in it. `execute` does not rebuild the plan, but it refuses a dry run file that was edited to add a
  step: every step must be a known operation, chosen by `--steps` (or in the default set), disruptive only if the dry
  run allowed it, and must not cut off the responder's own access. Each step is simulated again just before it runs.
- Every value that came from the logs (user, role, key, instance, trail, region...) must have the documented form for
  its kind before it is used, and is checked again before each call. Anything else makes the step manual.
- Command-line values are checked too: `--aws-profile`, `--region`, `--steps`, `--approve`, `--lookup-events` regions and
  `s3://` URLs must match strict patterns, or the command stops before contacting AWS.
- Root credentials are refused, since their permissions cannot be checked. Use an IAM role or user.
- The simulator covers identity policies, permission boundaries and SCPs, not session or resource-based policies, so
  AWS can still refuse a call: execute then stops at that step and records it.

The credentials need, besides the permissions for the changes themselves: `sts:GetCallerIdentity`,
`iam:SimulatePrincipalPolicy`, `iam:GetRole` (for role sessions), and read access to the targets (`iam:GetUser`,
`iam:ListAccessKeys`, `cloudtrail:GetTrailStatus` and the like).

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
| `lambda:CreateFunction`, `UpdateFunctionCode`, `UpdateFunctionConfiguration` | the function's execution-role sessions (named after the function), from the change onwards |

Each followed event says which identity it acted as (`via`) and the chain of event ids back to its seed; `taint.identities`
lists everything followed. Confidence carries over: what a weak seed obtained stays weak. The seed window does not limit
propagation, since a key the attacker created is theirs whenever it is used. `--no-propagate` turns this off.

Not followed: existing roles the attacker merely assumed (only their own session is), passwords set on existing users,
ECS task roles, and anything outside these rules. IAM Identity Center has no taint rule: its role sessions are named after
the user, so seed with the user name (`--principal-id user@example.com` matches the session-name part), and its changes
(assignments, permission sets, identity store users) are classified in the timeline.

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
  Steps with operations can be carried out by `controlzee respond` (see above); the rest are for a person. A value from
  the logs reaches a command only if it has the documented form for its kind, and is shell-quoted; otherwise the step is
  manual and says why.
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
