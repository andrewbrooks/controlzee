"""Import indicators from a GuardDuty finding.

Field names follow the GuardDuty finding format documentation (Resource.AccessKeyDetails, Service.Action.AwsApiCallAction,
Service.EventFirstSeen / EventLastSeen). Findings without these fields simply contribute nothing, and the notes say so.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import orjson

from controlzee.model.ioc import Indicator, IndicatorKind, Window
from controlzee.seed.spec import MAX_IOC_FILE_BYTES, SpecError, SpecParts
from controlzee.timeutil import format_time_us, parse_time_us


def _findings(doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, dict) and isinstance(doc.get("Findings"), list):
        items = doc["Findings"]
    elif isinstance(doc, list):
        items = doc
    elif isinstance(doc, dict) and ("Resource" in doc or "Service" in doc):
        items = [doc]
    else:
        raise SpecError("not a GuardDuty finding: expected a finding object, a list of findings, or {\"Findings\": [...]}")
    return [f for f in items if isinstance(f, dict)]


def _get(d: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(d, dict):
            return None
        d = d.get(key)
    return d


def from_guardduty(doc: Any) -> SpecParts:
    parts = SpecParts()
    seen: set[tuple[IndicatorKind, str]] = set()
    counters: dict[str, int] = {}
    firsts: list[int] = []
    lasts: list[int] = []

    def add(kind: IndicatorKind, prefix: str, value: str, finding: str, what: str) -> None:
        if (kind, value) in seen:
            return
        seen.add((kind, value))
        counters[prefix] = counters.get(prefix, 0) + 1
        parts.indicators.append(Indicator(name=f"gd_{prefix}_{counters[prefix]}", kind=kind, value=value))
        parts.notes.append(f"finding {finding}: imported {what} {value}")

    for f in _findings(doc):
        fid = str(f.get("Id") or f.get("Title") or "?")[:64]
        before = len(parts.indicators)
        ak = _get(f, "Resource", "AccessKeyDetails", "AccessKeyId")
        if isinstance(ak, str) and ak:
            add(IndicatorKind.ACCESS_KEY_ID, "access_key", ak, fid, "access key")
        pid = _get(f, "Resource", "AccessKeyDetails", "PrincipalId")
        if isinstance(pid, str) and pid:
            add(IndicatorKind.PRINCIPAL_ID, "principal_id", pid, fid, "principal id")
        ip = _get(f, "Service", "Action", "AwsApiCallAction", "RemoteIpDetails", "IpAddressV4")
        if isinstance(ip, str):
            try:
                ipaddress.ip_address(ip)
                add(IndicatorKind.SOURCE_IP, "ip", ip, fid, "source IP")
            except ValueError:
                pass
        for key, bucket in (("EventFirstSeen", firsts), ("EventLastSeen", lasts)):
            t = _get(f, "Service", key)
            if isinstance(t, str):
                try:
                    bucket.append(parse_time_us(t))
                except ValueError:
                    parts.notes.append(f"finding {fid}: ignored unreadable {key} {t!r}")
        if len(parts.indicators) == before:
            parts.notes.append(f"finding {fid}: no new indicators found in it")
    if firsts and lasts:
        parts.window = Window(start=format_time_us(min(firsts)), end=format_time_us(max(lasts)))
        parts.notes.append(f"window suggested from the findings: {parts.window.start} to {parts.window.end}")
    return parts


def load_guardduty_file(path: Path) -> SpecParts:
    try:
        if path.stat().st_size > MAX_IOC_FILE_BYTES * 16:
            raise SpecError(f"{path.name} is too large to be a GuardDuty finding")
        return from_guardduty(orjson.loads(path.read_bytes()))
    except OSError as e:
        raise SpecError(f"cannot read {path.name}: {e.strerror}") from None
    except orjson.JSONDecodeError as e:
        raise SpecError(f"{path.name} is not valid JSON: {e}") from None
