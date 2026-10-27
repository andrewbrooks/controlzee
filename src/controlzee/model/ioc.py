"""Indicators of compromise, the window, and the seed specification derived from them."""
from __future__ import annotations

import ipaddress
import re
from enum import StrEnum
from typing import Literal

from pydantic import field_validator, model_validator

from controlzee.model.common import Confidence, Model

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{0,63}$")
RESERVED_NAMES = frozenset({"and", "or", "not"})
MAX_VALUE = 2048


class IndicatorKind(StrEnum):
    ACCESS_KEY_ID = "access_key_id"
    PRINCIPAL_ID = "principal_id"
    SOURCE_IDENTITY = "source_identity"
    PRINCIPAL_ARN = "principal_arn"
    SOURCE_IP = "source_ip"
    USER_AGENT = "user_agent"


STRONG_KINDS = frozenset({IndicatorKind.ACCESS_KEY_ID, IndicatorKind.PRINCIPAL_ID, IndicatorKind.SOURCE_IDENTITY})


class Indicator(Model):
    name: str
    kind: IndicatorKind
    value: str
    match: Literal["exact", "substring", "regex"] = "exact"

    @property
    def strength(self) -> Confidence:
        return Confidence.STRONG if self.kind in STRONG_KINDS else Confidence.WEAK

    @field_validator("name")
    @classmethod
    def _name_ok(cls, v: str) -> str:
        if not _NAME.match(v) or v.lower() in RESERVED_NAMES:
            raise ValueError(f"indicator name {v!r} must be letters, digits, '_' or '-', start with a letter, and not be AND/OR/NOT")
        return v

    @field_validator("value")
    @classmethod
    def _value_ok(cls, v: str) -> str:
        if not v or len(v) > MAX_VALUE or any(ord(c) < 0x20 for c in v):
            raise ValueError("indicator value must be 1-2048 printable characters")
        return v

    @model_validator(mode="after")
    def _kind_rules(self) -> Indicator:
        if self.kind is IndicatorKind.USER_AGENT:
            if self.match == "exact":  # a user agent is almost never matched whole; default to a substring
                object.__setattr__(self, "match", "substring")
            if self.match == "regex":
                try:
                    re.compile(self.value)
                except re.error as e:
                    raise ValueError(f"invalid regular expression: {e}") from None
        elif self.match != "exact":
            raise ValueError(f"{self.kind.value} indicators only support exact matching")
        if self.kind is IndicatorKind.SOURCE_IP:
            try:
                ipaddress.ip_network(self.value, strict=False)
            except ValueError:
                raise ValueError(f"{self.value!r} is not an IP address or CIDR range") from None
        return self


class Window(Model):
    """Inclusive time window in UTC, as ISO-8601 strings ending in Z."""

    start: str | None = None
    end: str | None = None


class SeedSpec(Model):
    """Everything that defines what counts as a seed. Indicators are kept sorted by name for stable output."""

    indicators: tuple[Indicator, ...]
    expression: str
    window: Window | None = None

    @model_validator(mode="after")
    def _unique_names(self) -> SeedSpec:
        names = [i.name for i in self.indicators]
        if len(set(names)) != len(names):
            raise ValueError("indicator names must be unique")
        return self
