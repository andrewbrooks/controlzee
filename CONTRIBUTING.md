# Contributing

controlzee is a proof of concept, so the most useful contributions are real-world evidence: CloudTrail shapes the
fixtures do not cover, taint or coverage cases the rules miss, and results of the steps in
[docs/field-testing.md](docs/field-testing.md) on a sandbox account.

## Setup and checks

```
uv sync
uv run pytest -q
uv run ruff check . && uv run mypy src
uv run python -m tests.builders.build_fixtures --check
```

CI runs the same four. Read the "Invariants to preserve" in [CLAUDE.md](CLAUDE.md) before changing output: artifacts
must stay byte-identical for the same inputs, log content is hostile, and nothing may change AWS without an approved dry
run.

- Fixtures are generated. Edit `tests/builders/`, rebuild with `uv run python -m tests.builders.build_fixtures`, then
  update the goldens with `UPDATE_GOLDENS=1` and review the diff. Never edit a fixture by hand.
- Run `uv run python -m controlzee.schemas` after changing a model.
- Tests must not use the network or real AWS; use the in-memory account in `tests/fake_aws.py`.
