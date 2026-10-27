"""Logs are written by whoever controls the account being investigated, so every string from them is untrusted.

Anything shown to a person goes through `clean`: control characters (including terminal escape sequences) are replaced,
and length is capped. Report renderers added later use the same function.
"""
from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")


def clean(text: object, limit: int = 200) -> str:
    """A printable, single-line, length-capped rendering of untrusted text."""
    s = _CONTROL.sub("�", str(text))
    return s if len(s) <= limit else s[: limit - 1] + "…"
