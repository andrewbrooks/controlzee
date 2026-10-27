"""Write the committed scenario fixtures: `uv run python -m tests.builders.build_fixtures [--check]`.

--check rebuilds into a temporary directory and fails if the committed files differ (used by the test suite).
"""
from __future__ import annotations

import filecmp
import shutil
import sys
import tempfile
from pathlib import Path

from tests.builders import scenarios

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

SCENARIOS = {
    "01_leaked_key": (scenarios.scenario_01_leaked_key, 0),
    "02_role_chain": (scenarios.scenario_02_role_chain, 0),
    "03_instance_role": (scenarios.scenario_03_instance_role, 2),
    "04_log_tampering": (scenarios.scenario_04_log_tampering, 0),
    "06_lambda": (scenarios.scenario_06_lambda, 0),
    "05_weak_ioc": (scenarios.scenario_05_weak_ioc, 3),  # every third file gzipped, to exercise both formats
}


def build(root: Path) -> None:
    for name, (make, gzip_every) in SCENARIOS.items():
        logs_dir = root / name / "logs"
        if logs_dir.exists():
            shutil.rmtree(logs_dir)
        make().write(logs_dir, per_file=12, gzip_every=gzip_every)


def differences(a: Path, b: Path) -> list[str]:
    out: list[str] = []
    for name in SCENARIOS:
        left, right = a / name / "logs", b / name / "logs"
        lf = sorted(p.relative_to(left).as_posix() for p in left.rglob("*") if p.is_file())
        rf = sorted(p.relative_to(right).as_posix() for p in right.rglob("*") if p.is_file()) if right.exists() else []
        if lf != rf:
            out.append(f"{name}: file lists differ")
            continue
        out += [f"{name}/{rel}" for rel in lf if not filecmp.cmp(left / rel, right / rel, shallow=False)]
    return out


if __name__ == "__main__":
    if "--check" in sys.argv:
        with tempfile.TemporaryDirectory() as tmp:
            build(Path(tmp))
            diff = differences(Path(tmp), FIXTURES)
        if diff:
            print("fixtures are out of date:\n  " + "\n  ".join(diff))
            sys.exit(1)
        print("fixtures are up to date")
    else:
        build(FIXTURES)
        print(f"wrote fixtures under {FIXTURES}")
