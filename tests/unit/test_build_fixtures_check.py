"""The fixtures check must not depend on which Python or zlib compressed a fixture."""

from __future__ import annotations

import gzip
from pathlib import Path

from tests.builders.build_fixtures import differences

SCENARIO = "03_instance_role"
REL = "AWSLogs/x/log.json.gz"


def _write(root: Path, rel: str, data: bytes, *, level: int = 9) -> None:
    path = root / SCENARIO / "logs" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(data, compresslevel=level, mtime=0) if rel.endswith(".gz") else data)


def test_gzip_files_with_the_same_content_but_different_bytes_match(tmp_path: Path) -> None:
    content = b'{"Records": []}\n' * 200
    _write(tmp_path / "a", REL, content, level=1)
    _write(tmp_path / "b", REL, content, level=9)
    assert (tmp_path / "a" / SCENARIO / "logs" / REL).read_bytes() != (
        tmp_path / "b" / SCENARIO / "logs" / REL
    ).read_bytes()
    assert differences(tmp_path / "a", tmp_path / "b") == []


def test_gzip_files_with_different_content_are_reported(tmp_path: Path) -> None:
    _write(tmp_path / "a", REL, b'{"Records": [1]}\n')
    _write(tmp_path / "b", REL, b'{"Records": [2]}\n')
    assert differences(tmp_path / "a", tmp_path / "b") == [f"{SCENARIO}/{REL}"]


def test_plain_files_are_still_compared_byte_for_byte(tmp_path: Path) -> None:
    _write(tmp_path / "a", "AWSLogs/x/log.json", b"one\n")
    _write(tmp_path / "b", "AWSLogs/x/log.json", b"two\n")
    assert differences(tmp_path / "a", tmp_path / "b") == [f"{SCENARIO}/AWSLogs/x/log.json"]
