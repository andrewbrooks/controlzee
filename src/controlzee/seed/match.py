"""Find seed events: apply the indicators and expression to the index, and record near misses."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from controlzee.ingest.index import R_AK, R_ARN, R_IP, R_ISSUER, R_PID, R_SRCID, R_TS, R_UA, EventIndex, Row
from controlzee.model.common import Confidence
from controlzee.model.ioc import STRONG_KINDS, Indicator, IndicatorKind, SeedSpec, Window
from controlzee.seed import expr
from controlzee.timeutil import parse_time_us

Predicate = Callable[[Row], bool]


def _ip_predicate(value: str) -> Predicate:
    net = ipaddress.ip_network(value, strict=False)
    cache: dict[str, bool] = {}

    def check(row: Row) -> bool:
        ip = row[R_IP]
        if ip is None:
            return False
        hit = cache.get(ip)
        if hit is None:  # CloudTrail also puts names like "ec2.amazonaws.com" here; those simply never match
            try:
                hit = ipaddress.ip_address(ip) in net
            except ValueError:
                hit = False
            cache[ip] = hit
        return hit

    return check


def compile_indicator(ind: Indicator) -> Predicate:
    v = ind.value
    match ind.kind:
        case IndicatorKind.ACCESS_KEY_ID:
            return lambda row: row[R_AK] == v
        case IndicatorKind.SOURCE_IDENTITY:
            return lambda row: row[R_SRCID] == v
        case IndicatorKind.PRINCIPAL_ID:
            # the full principalId ("AROA...:session") or just its session-name part
            return lambda row: (pid := row[R_PID]) is not None and (pid == v or pid.partition(":")[2] == v)
        case IndicatorKind.PRINCIPAL_ARN:
            # userIdentity.arn, or the role that an assumed-role session was issued by
            return lambda row: row[R_ARN] == v or row[R_ISSUER] == v
        case IndicatorKind.SOURCE_IP:
            return _ip_predicate(v)
        case IndicatorKind.USER_AGENT:
            if ind.match == "regex":
                rx = re.compile(v)
                return lambda row: (ua := row[R_UA]) is not None and rx.search(ua) is not None
            return lambda row: (ua := row[R_UA]) is not None and v in ua
    raise AssertionError(f"unhandled indicator kind {ind.kind}")  # pragma: no cover


def window_bounds(window: Window | None) -> tuple[int | None, int | None]:
    if window is None:
        return None, None
    return (parse_time_us(window.start) if window.start else None,
            parse_time_us(window.end) if window.end else None)


def validate_spec(spec: SeedSpec) -> expr.Node:
    """Check the spec is usable and return the parsed expression. Raises ValueError with a message for the analyst."""
    if not spec.indicators:
        raise ValueError("no indicators given: pass --iocs, --guardduty or at least one indicator flag")
    node = expr.parse(spec.expression)
    defined = {i.name for i in spec.indicators}
    used = set(expr.names(node))
    if missing := sorted(used - defined):
        raise ValueError(f"the expression uses undefined indicator(s): {', '.join(missing)}")
    if unused := sorted(defined - used):
        raise ValueError(f"indicator(s) defined but not used in the expression (they would be ignored): {', '.join(unused)}")
    strong = {i.name for i in spec.indicators if i.kind in STRONG_KINDS}
    w = spec.window
    if not (used & strong) and (w is None or not (w.start and w.end)):
        raise ValueError("an expression with only weak indicators (IP, user agent, ARN) needs a time window with both a start "
                         "and an end, otherwise it would match unrelated traffic. Pass --window START END")
    if w and w.start and w.end and parse_time_us(w.start) > parse_time_us(w.end):
        raise ValueError("the window starts after it ends")
    return node


@dataclass(frozen=True)
class SeedHit:
    row: int  # position in index.rows
    confidence: Confidence
    matched: tuple[str, ...]


@dataclass(frozen=True)
class NearMissHit:
    row: int
    matched: tuple[str, ...]
    reason: str  # "expression" | "window"


@dataclass
class SeedResult:
    hits: list[SeedHit] = field(default_factory=list)
    near_misses: list[NearMissHit] = field(default_factory=list)  # capped at the limit given to run_seed
    near_miss_total: int = 0
    near_miss_by_reason: dict[str, int] = field(default_factory=dict)
    near_miss_by_indicator: dict[str, int] = field(default_factory=dict)


def run_seed(index: EventIndex, spec: SeedSpec, near_miss_limit: int = 500) -> SeedResult:
    """Walk the (time-ordered) index once. Cost is a handful of comparisons per event; most events match nothing."""
    node = validate_spec(spec)
    preds = [(i.name, compile_indicator(i)) for i in spec.indicators]
    strong = frozenset(i.name for i in spec.indicators if i.kind in STRONG_KINDS)
    weak_names = frozenset(i.name for i in spec.indicators) - strong
    lo, hi = window_bounds(spec.window)
    result = SeedResult()
    for n, row in enumerate(index.rows):
        hits = {name: True for name, p in preds if p(row)}
        if not hits:
            continue
        matched, is_strong = expr.evaluate(node, hits, strong)
        ts = row[R_TS]
        in_window = (lo is None or ts >= lo) and (hi is None or ts <= hi)
        names = tuple(sorted(hits))
        if matched and in_window:
            result.hits.append(SeedHit(n, Confidence.STRONG if is_strong else Confidence.WEAK, names))
        elif weak_names.intersection(hits):  # matched a weak indicator but was left out: worth a second look
            reason = "window" if matched else "expression"
            result.near_miss_total += 1
            result.near_miss_by_reason[reason] = result.near_miss_by_reason.get(reason, 0) + 1
            for nm in weak_names.intersection(hits):
                result.near_miss_by_indicator[nm] = result.near_miss_by_indicator.get(nm, 0) + 1
            if len(result.near_misses) < near_miss_limit:
                result.near_misses.append(NearMissHit(n, names, reason))
    return result
