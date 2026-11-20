"""Write the committed scenario fixtures: `uv run python -m tests.builders.build_fixtures [--check]`.

--check rebuilds into a temporary directory and fails if the committed files differ (used by the test suite). Gzipped
files are compared by their decompressed content: the compressed bytes depend on the Python and zlib version, and only
the content is what the tests read.
"""

from __future__ import annotations

import filecmp
import gzip
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
    "07_trust_backdoor": (scenarios.scenario_07_trust_backdoor, 0),
    "08_identity_provider": (scenarios.scenario_08_identity_provider, 0),
}


def build(root: Path) -> None:
    for name, (make, gzip_every) in SCENARIOS.items():
        logs_dir = root / name / "logs"
        if logs_dir.exists():
            shutil.rmtree(logs_dir)
        make().write(logs_dir, per_file=12, gzip_every=gzip_every)


def same_content(left: Path, right: Path) -> bool:
    """True if the two files hold the same bytes; for `.gz` files, the same bytes once decompressed."""
    if left.suffix == ".gz":
        return gzip.decompress(left.read_bytes()) == gzip.decompress(right.read_bytes())
    return filecmp.cmp(left, right, shallow=False)


def differences(a: Path, b: Path) -> list[str]:
    out: list[str] = []
    for name in SCENARIOS:
        left, right = a / name / "logs", b / name / "logs"
        lf = sorted(p.relative_to(left).as_posix() for p in left.rglob("*") if p.is_file())
        rf = (
            sorted(p.relative_to(right).as_posix() for p in right.rglob("*") if p.is_file())
            if right.exists()
            else []
        )
        if lf != rf:
            out.append(f"{name}: file lists differ")
            continue
        out += [f"{name}/{rel}" for rel in lf if not same_content(left / rel, right / rel)]
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
