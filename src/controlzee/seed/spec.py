"""Build a `SeedSpec` from an IOC file, command-line flags and a GuardDuty finding."""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import ValidationError

from controlzee.model.common import Model
from controlzee.model.ioc import Indicator, IndicatorKind, SeedSpec, Window
from controlzee.timeutil import normalize_time

MAX_IOC_FILE_BYTES = 1 << 20


class SpecError(ValueError):
    """The IOC input is unusable; the message says what to fix."""


@dataclass
class SpecParts:
    indicators: list[Indicator] = field(default_factory=list)
    expression: str | None = None
    window: Window | None = None
    notes: list[str] = field(default_factory=list)


class _IocBody(Model):
    type: IndicatorKind
    value: str
    match: Literal["exact", "substring", "regex"] = "exact"


class _IocFile(Model):
    version: int = 1
    indicators: dict[str, _IocBody]
    expression: str | None = None
    window: dict[str, Any] | None = None


def make_window(raw: dict[str, Any] | None) -> Window | None:
    if not raw:
        return None
    extra = set(raw) - {"start", "end"}
    if extra:
        raise SpecError(f"window only takes 'start' and 'end', not: {', '.join(sorted(map(str, extra)))}")
    try:
        return Window(start=normalize_time(raw["start"]) if raw.get("start") else None,
                      end=normalize_time(raw["end"]) if raw.get("end") else None)
    except ValueError as e:
        raise SpecError(str(e)) from None


def _explain(e: ValidationError) -> str:
    return "; ".join(f"{'.'.join(map(str, err['loc'])) or 'value'}: {err['msg']}" for err in e.errors()[:5])


def load_iocs_file(path: Path) -> SpecParts:
    try:
        if path.stat().st_size > MAX_IOC_FILE_BYTES:
            raise SpecError(f"{path.name} is larger than {MAX_IOC_FILE_BYTES} bytes")
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        raise SpecError(f"cannot read IOC file {path.name}: {e}") from None
    except yaml.YAMLError as e:
        raise SpecError(f"{path.name} is not valid YAML: {e}") from None
    if not isinstance(doc, dict):
        raise SpecError(f"{path.name} must be a mapping with an 'indicators' section")
    try:
        f = _IocFile.model_validate(doc)
        if f.version != 1:
            raise SpecError(f"unsupported IOC file version {f.version} (this tool reads version 1)")
        indicators = [Indicator(name=n, kind=b.type, value=b.value, match=b.match) for n, b in f.indicators.items()]
    except ValidationError as e:
        raise SpecError(f"{path.name}: {_explain(e)}") from None
    return SpecParts(indicators, f.expression, make_window(f.window))


def from_flags(*, access_keys: Iterable[str] = (), principal_ids: Iterable[str] = (), source_identities: Iterable[str] = (),
               arns: Iterable[str] = (), ips: Iterable[str] = (), user_agents: Iterable[str] = (),
               user_agent_regexes: Iterable[str] = ()) -> list[Indicator]:
    """Indicators from command-line values, named access_key_1, ip_1, ua_1 ... in the order given."""
    groups: list[tuple[str, IndicatorKind, Literal["exact", "substring", "regex"], Iterable[str]]] = [
        ("access_key", IndicatorKind.ACCESS_KEY_ID, "exact", access_keys),
        ("principal_id", IndicatorKind.PRINCIPAL_ID, "exact", principal_ids),
        ("source_identity", IndicatorKind.SOURCE_IDENTITY, "exact", source_identities),
        ("arn", IndicatorKind.PRINCIPAL_ARN, "exact", arns),
        ("ip", IndicatorKind.SOURCE_IP, "exact", ips),
        ("ua", IndicatorKind.USER_AGENT, "substring", user_agents),
        ("ua_regex", IndicatorKind.USER_AGENT, "regex", user_agent_regexes),
    ]
    out: list[Indicator] = []
    try:
        for prefix, kind, match, values in groups:
            for n, value in enumerate(values, 1):
                out.append(Indicator(name=f"{prefix}_{n}", kind=kind, value=value, match=match))
    except ValidationError as e:
        raise SpecError(_explain(e)) from None
    return out


def assemble(parts: Sequence[SpecParts], *, expression: str | None = None, window: Window | None = None) -> SeedSpec:
    """Merge sources. Precedence for the expression and window: command line, then IOC file, then GuardDuty."""
    indicators = [i for p in parts for i in p.indicators]
    if not indicators:
        raise SpecError("no indicators given: pass --iocs, --guardduty or an indicator flag such as --access-key")
    names = [i.name for i in indicators]
    if dup := sorted({n for n in names if names.count(n) > 1}):
        raise SpecError(f"indicator name(s) used twice: {', '.join(dup)}")
    expr_text = expression or next((p.expression for p in reversed(parts) if p.expression), None)
    if expr_text is None:
        expr_text = " OR ".join(sorted(names))
    chosen = window or next((p.window for p in reversed(parts) if p.window), None)
    try:
        return SeedSpec(indicators=tuple(sorted(indicators, key=lambda i: i.name)), expression=expr_text, window=chosen)
    except ValidationError as e:
        raise SpecError(_explain(e)) from None
