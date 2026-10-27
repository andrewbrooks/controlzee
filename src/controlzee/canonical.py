"""Canonical JSON: the one way every artifact is written and hashed.

Sorted keys, two-space indent (so artifacts diff line by line), UTF-8, a trailing newline, integers rather than
floats. The same document always produces the same bytes. The bytes equal what the standard library produces with
`sort_keys=True` and the same indent, which the tests check, so determinism does not depend on `orjson`.
"""
from __future__ import annotations

import hashlib
from typing import Any

import orjson

_OPTIONS = orjson.OPT_SORT_KEYS | orjson.OPT_INDENT_2 | orjson.OPT_APPEND_NEWLINE


def dumps(obj: Any) -> bytes:
    """Canonical bytes for a JSON-compatible value (use `model_dump(mode="json")` for pydantic models)."""
    return orjson.dumps(obj, option=_OPTIONS)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seal(doc: dict[str, Any], field: str) -> dict[str, Any]:
    """`doc` plus `field` holding the SHA-256 of its canonical form without that field."""
    body = {k: v for k, v in doc.items() if k != field}
    return {**body, field: sha256_hex(dumps(body))}


def is_sealed(doc: dict[str, Any], field: str) -> bool:
    """True when the stored hash matches the document's content."""
    return field in doc and seal(doc, field)[field] == doc[field]
