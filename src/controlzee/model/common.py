"""Shared vocabulary for every artifact."""
from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict

from controlzee import __version__

# Artifacts are not stable before 1.0: this stays "0.x" until the schemas are published in milestone 6.
SCHEMA_VERSION = "0.1"


class Model(BaseModel):
    """Base for all artifact models: immutable, and unknown fields are an error rather than silently dropped."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class Confidence(StrEnum):
    STRONG = "strong"
    WEAK = "weak"


def tool_info() -> dict[str, Any]:
    return {"name": "controlzee", "version": __version__}
