# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

controlzee is a Python 3.12 CLI ("incident response as code for AWS"): CloudTrail logs plus IOCs in, a reproducible scope of what the attacker did out. Only milestone 1 (`controlzee scope`) exists; taint propagation, timeline, plan and report are planned milestones (see `README.md`, `docs/architecture.md`).

## Commands

```
uv sync
uv run pytest -q                                   # whole suite (no network: pytest-socket is on)
uv run pytest tests/unit/test_match.py::test_name  # one test
uv run pytest tests/determinism -q                 # the slow-marked determinism suite
uv run ruff check . && uv run mypy src             # mypy is --strict
uv run python -m tests.builders.build_fixtures --check   # committed fixtures match their builders (CI runs this)
uv run python -m tests.builders.build_fixtures            # regenerate fixtures after editing tests/builders/
uv run python -m controlzee.schemas                       # regenerate schemas/ after changing a model
UPDATE_GOLDENS=1 uv run pytest tests/unit/test_scope_scenarios.py   # rewrite goldens, then review the git diff
```

## Architecture

Pipeline: ingest -> normalize -> seed (IOC match) -> `scope.json`. `scope.json` is meant to be the spine that later commands read.

- **Two-pass ingest** (`ingest/`). Pass 1 (`load.py`, `parse.py`) parses every file in a spawn process pool into compact 19-field tuple rows (`index.py`; fields are addressed by the `R_*` constants, never by bare numbers). No pydantic objects at this stage. Pass 2 (`materialize.py`) re-reads only files containing in-scope events and builds full `Event` models, checking event ids against the index. Anything that touches every event must work on rows, not models.
- **Sources**: `ingest/source.py` defines the `Source` protocol (picklable, relative names only). Only `LocalSource` exists; S3 and CloudTrail LookupEvents are planned to plug in here.
- **Seeding** (`seed/`): `expr.py` is the AND/OR grammar and strong/weak evaluation, `match.py` compiles indicators to predicates and records near misses, `spec.py` and `guardduty.py` build a `SeedSpec` from YAML, CLI flags and GuardDuty findings (precedence: CLI, then IOC file, then GuardDuty). `scope.py` ties the phases together.
- **Models** (`model/`) are frozen pydantic v2 models with `extra="forbid"`. `schemas.py` exports their JSON Schemas to `schemas/`, and a test fails if the committed files are stale.

## Invariants to preserve

- **Byte-identical output** for the same inputs. All artifacts go through `canonical.dumps` (sorted keys, indent 2, trailing newline). No wall-clock times, hostnames or absolute paths inside artifacts (timings are terminal-only). Events sort by `(ts_us, event_id)`; duplicates are removed by `eventID`; worker results merge in submission order; never iterate a set unsorted.
- **Logs are hostile input.** Anything printed goes through `safety.clean`; rich consoles use `markup=False`. Files are parsed with size caps (`gunzip_capped`); bad files and records are counted and reported, not fatal (`--strict` makes them exit 3).
- **Read-only by default.** Outputs are written atomically, mode 0600, and never overwrite without `--force`.
- Raw records are referenced by pointer (`Event.source`), and embedded only with `--embed-raw`.

## Testing notes

- Fixtures are generated: `tests/builders/` (`LogSet`, scenarios) produce the CloudTrail JSON under `tests/fixtures/<scenario>/logs`, which is committed. Edit the builder, rebuild, then update goldens; never hand-edit fixtures.
- Expected outputs live in `tests/fixtures/<scenario>/expected/`. Review the diff after `UPDATE_GOLDENS=1`.
- `tests/helpers.make_row(**kw)` makes index rows for matcher tests.
- CLI tests set `COLUMNS=400` so rich does not wrap messages mid-phrase.
- Determinism tests that need the process pool monkeypatch `PARALLEL_MIN_BYTES` in both `ingest.load` and `ingest.materialize`, since the fixtures are tiny.
