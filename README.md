# controlzee

Incident response as code for AWS. Give it CloudTrail logs and what you know about the attacker; it tells you what they
did, in a form other tools and people can rely on.

Named for CTRL+Z, but most of the time the right answer is rebuild, not undo.

**Status:** early. Milestone 1 is in: `controlzee scope`. Timeline, exposure, remediation plans and reports are not built yet.

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

## What it will not tell you

Scoping finds the events that match your indicators. It does not yet follow the attacker to credentials they created
(that is milestone 2), and it can only see what CloudTrail recorded: logs that were stopped, deleted or never enabled
are not visible, and `scope.json` says so only once coverage analysis lands in milestone 3.

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
