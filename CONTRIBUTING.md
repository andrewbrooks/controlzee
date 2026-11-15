# Contributing

controlzee is a proof of concept, so the most useful contributions are real-world evidence: CloudTrail shapes the
fixtures do not cover, taint or coverage cases the rules miss, and results of the steps in
[docs/field-testing.md](docs/field-testing.md) on a sandbox account.

## Setup and checks

```
make setup    # uv sync --locked, and enables the pre-commit hook
make check    # lint and format check, mypy, fixtures check, tests
make help     # every task, including format, secrets, audit-deps and build
```

CI runs `make check` plus a secret scan of the full history and a dependency audit. The pre-commit hook scans staged
changes for secrets (`gitleaks`) and checks lint and formatting. The fake AWS key ids in the tests are allowed by exact
path in `.gitleaks.toml`; a new secret-shaped string anywhere else fails the scan, so add the file there with a reason.

Read the "Invariants to preserve" in [CLAUDE.md](CLAUDE.md) before changing output: artifacts
must stay byte-identical for the same inputs, log content is hostile, and nothing may change AWS without an approved dry
run.

- Fixtures are generated. Edit `tests/builders/`, rebuild with `uv run python -m tests.builders.build_fixtures`, then
  update the goldens with `UPDATE_GOLDENS=1` and review the diff. Never edit a fixture by hand.
- Run `uv run python -m controlzee.schemas` after changing a model.
- Tests must not use the network or real AWS; use the in-memory account in `tests/fake_aws.py`.
