from __future__ import annotations

import os
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def golden():
    """Compare bytes to a committed file. Set UPDATE_GOLDENS=1 to rewrite them (then review the diff)."""
    def check(path: Path, actual: bytes) -> None:
        if os.environ.get("UPDATE_GOLDENS"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(actual)
            return
        assert path.exists(), f"missing golden {path}; run with UPDATE_GOLDENS=1 to create it"
        assert actual == path.read_bytes(), f"{path.name} differs from the committed golden; if intended, rerun with UPDATE_GOLDENS=1"
    return check
