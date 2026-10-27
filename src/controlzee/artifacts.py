"""Reading and writing artifacts. Later commands read `scope.json` (the spine) and nothing else of the evidence.

A scope is accepted only if it is sealed (its hash matches its content) and of this tool's schema version: everything
derived from it cites its `scope_sha256`, which would be meaningless for an edited or foreign document.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import orjson
from pydantic import ValidationError

from controlzee import canonical
from controlzee.model.common import SCHEMA_VERSION
from controlzee.model.scope import Scope

MAX_SCOPE_BYTES = 4 << 30


class ArtifactError(ValueError):
    """An input artifact is unusable; the message says why."""


def load_scope(path: Path) -> Scope:
    try:
        if path.stat().st_size > MAX_SCOPE_BYTES:
            raise ArtifactError(f"{path.name} is larger than {MAX_SCOPE_BYTES} bytes")
        doc = orjson.loads(path.read_bytes())
    except OSError as e:
        raise ArtifactError(f"cannot read {path.name}: {e.strerror}") from None
    except orjson.JSONDecodeError as e:
        raise ArtifactError(f"{path.name} is not valid JSON: {e}") from None
    if not isinstance(doc, dict) or "scope_sha256" not in doc:
        raise ArtifactError(f"{path.name} is not a scope.json written by controlzee scope")
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise ArtifactError(f"{path.name} has schema version {doc.get('schema_version')!r}; this tool reads {SCHEMA_VERSION!r}. "
                            "Run controlzee scope again with this version")
    if not canonical.is_sealed(doc, "scope_sha256"):
        raise ArtifactError(f"{path.name} was changed after it was written (its scope_sha256 does not match its content)")
    try:
        return Scope.model_validate(doc)
    except ValidationError as e:
        raise ArtifactError(f"{path.name} does not match the scope schema: {e.errors()[0]['msg']}") from None


def write_atomic(path: Path, data: bytes) -> None:
    """Write via a temporary file in the same directory (mode 0600) and rename it into place."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
