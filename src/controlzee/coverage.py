"""What the logs can and cannot show: per-stream coverage, silences during the incident, logging tampering, accounts
the attacker reached that sent no logs, and missing event types.

Absence of events is not proof of missing logs: a quiet region is silent too. So a silence is reported only when it is
long both in absolute terms (`gap_minutes`) and for that stream (ten times its mean interval), and only when it overlaps
the incident period. A logging change in the same account just before or during a silence is named as a possible cause.

One pass over the index rows; the only models read are the in-scope events (for the roles they assumed).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Final, Literal

from controlzee.ingest.index import (
    R_ACCOUNT,
    R_AK,
    R_ARN,
    R_ERR,
    R_ID,
    R_NAME,
    R_PID,
    R_REGION,
    R_RO,
    R_SOURCE,
    R_TIME,
    R_TS,
    EventIndex,
)
from controlzee.model.event import Event
from controlzee.model.scope import Coverage, Gap, LogStream, TamperingEvent, UnloggedAccount
from controlzee.timeutil import format_time_us

LISTED_TAMPERING = 100
UNUSUAL_FACTOR = 10  # a silence must be this many times the stream's mean interval
CAUSE_LEAD_US = 15 * 60 * 1_000_000  # a logging change this long before a silence starts may explain it
_MINUTE_US = 60 * 1_000_000

# calls that stop, narrow or delete logging and detection, with what they do (names from each service's API reference)
TAMPERING: Final[dict[tuple[str, str], str]] = {
    ("cloudtrail.amazonaws.com", "StopLogging"): "stops a trail",
    ("cloudtrail.amazonaws.com", "DeleteTrail"): "deletes a trail",
    ("cloudtrail.amazonaws.com", "UpdateTrail"): "changes a trail's destination or scope",
    ("cloudtrail.amazonaws.com", "PutEventSelectors"): "changes which events a trail records",
    ("cloudtrail.amazonaws.com", "DeleteEventDataStore"): "deletes a CloudTrail Lake event data store",
    ("cloudtrail.amazonaws.com", "StopEventDataStoreIngestion"): "stops a CloudTrail Lake event data store",
    ("guardduty.amazonaws.com", "DeleteDetector"): "deletes a GuardDuty detector",
    ("guardduty.amazonaws.com", "UpdateDetector"): "changes or suspends a GuardDuty detector",
    ("guardduty.amazonaws.com", "DisassociateFromAdministratorAccount"): "detaches GuardDuty from its administrator",
    ("config.amazonaws.com", "StopConfigurationRecorder"): "stops AWS Config recording",
    ("config.amazonaws.com", "DeleteConfigurationRecorder"): "deletes the AWS Config recorder",
    ("config.amazonaws.com", "DeleteDeliveryChannel"): "deletes the AWS Config delivery channel",
    ("securityhub.amazonaws.com", "DisableSecurityHub"): "disables Security Hub",
    ("organizations.amazonaws.com", "LeaveOrganization"): "takes the account out of its organization",
}
# the subset that can make CloudTrail itself go quiet
_STOPS_LOGS: Final = frozenset({"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteEventDataStore",
                                "StopEventDataStoreIngestion"})


@dataclass
class _Stream:
    first: int
    last: int
    events: int = 1
    long_silences: list[tuple[int, int]] = field(default_factory=list)  # every interval of at least gap_minutes


def incident_period(window_start: int | None, window_end: int | None, in_scope_ts: Iterable[int]) -> tuple[int, int] | None:
    """The span to check for gaps: the seed window (when it has both ends) together with the in-scope events."""
    points = list(in_scope_ts)
    if window_start is not None and window_end is not None:
        points += [window_start, window_end]
    return (min(points), max(points)) if points else None


GapKind = Literal["silence", "starts_late", "ends_early"]


def _gaps(st: _Stream, period: tuple[int, int], floor: int) -> list[tuple[GapKind, int, int]]:
    mean = (st.last - st.first) // (st.events - 1) if st.events > 1 else 0
    need = max(floor, UNUSUAL_FACTOR * mean)
    lo, hi = period
    out: list[tuple[GapKind, int, int]] = [("silence", a, b) for a, b in st.long_silences if b - a >= need and a <= hi and b >= lo]
    if st.first - lo >= need:
        out.insert(0, ("starts_late", lo, st.first))
    if hi - st.last >= need:
        out.append(("ends_early", st.last, hi))
    return out


def _assumed_accounts(events: Iterable[Event]) -> dict[str, tuple[set[str], set[str]]]:
    found: dict[str, tuple[set[str], set[str]]] = {}
    for ev in events:
        if ev.event_source != "sts.amazonaws.com" or ev.event_name != "AssumeRole" or ev.error_code:
            continue
        arn = (ev.request_parameters or {}).get("roleArn")
        if not isinstance(arn, str):
            continue
        parts = arn.split(":")
        if len(parts) >= 6 and parts[0] == "arn" and parts[4].isdigit():
            roles, ids = found.setdefault(parts[4], (set(), set()))
            roles.add(arn)
            ids.add(ev.event_id)
    return found


def build_coverage(index: EventIndex, in_scope: Mapping[int, Event], period: tuple[int, int] | None,
                   gap_minutes: int) -> Coverage:
    floor = gap_minutes * _MINUTE_US
    streams: dict[tuple[str, str], _Stream] = {}
    tampering: list[TamperingEvent] = []
    stops: list[tuple[str, int, str]] = []  # (account, ts, event id) of successful calls that can silence CloudTrail
    tampering_total = read_only = 0
    for n, row in enumerate(index.rows):
        ts = row[R_TS]
        key = (row[R_ACCOUNT], row[R_REGION])
        st = streams.get(key)
        if st is None:
            streams[key] = _Stream(ts, ts)
        else:
            if ts - st.last >= floor:
                st.long_silences.append((st.last, ts))
            st.last = ts
            st.events += 1
        if row[R_RO] is True:
            read_only += 1
        effect = TAMPERING.get((row[R_SOURCE], row[R_NAME]))
        if effect is None:
            continue
        tampering_total += 1
        if row[R_ERR] is None and row[R_NAME] in _STOPS_LOGS:
            stops.append((row[R_ACCOUNT], ts, row[R_ID]))
        if len(tampering) < LISTED_TAMPERING:
            tampering.append(TamperingEvent(
                event_id=row[R_ID], event_time=row[R_TIME], event_source=row[R_SOURCE], event_name=row[R_NAME], effect=effect,
                account=row[R_ACCOUNT], region=row[R_REGION], principal=row[R_ARN] or row[R_PID] or row[R_AK],
                error_code=row[R_ERR], in_scope=n in in_scope))

    gaps: list[Gap] = []
    if period is not None:
        for key in sorted(streams):
            for kind, a, b in _gaps(streams[key], period, floor):
                cause = next((eid for acct, t, eid in stops if acct == key[0] and a - CAUSE_LEAD_US <= t <= b), None)
                gaps.append(Gap(account=key[0], region=key[1], kind=kind,
                                start=format_time_us(a), end=format_time_us(b), minutes=(b - a) // _MINUTE_US, possible_cause=cause))

    logged = {acct for acct, _ in streams}
    unlogged = [UnloggedAccount(account=acct, role_arns=sorted(roles), event_ids=sorted(ids))
                for acct, (roles, ids) in sorted(_assumed_accounts(in_scope[p] for p in sorted(in_scope)).items()) if acct not in logged]

    notes: list[str] = []
    if not index.data_events:
        notes.append("no data events in the inputs: S3 object reads and writes, Lambda invocations and other data-plane "
                     "activity are not visible")
    if index.rows and not read_only:
        notes.append("no read-only events in the inputs: the trail may record writes only, so reconnaissance is not visible")
    if unlogged:
        notes.append(f"in-scope activity assumed roles in {len(unlogged)} account(s) with no logs in the inputs: "
                     f"{', '.join(u.account for u in unlogged)}")
    if in_scope_tampering := sum(1 for t in tampering if t.in_scope and t.error_code is None):
        notes.append(f"{in_scope_tampering} in-scope call(s) changed logging or detection")
    if gaps:
        notes.append(f"{len(gaps)} unusual silence(s) in the logs during the incident period; activity may be missing there")

    return Coverage(
        period_start=format_time_us(period[0]) if period else None, period_end=format_time_us(period[1]) if period else None,
        gap_minutes=gap_minutes,
        streams=[LogStream(account=a, region=r, events=st.events, first_event_time=format_time_us(st.first),
                           last_event_time=format_time_us(st.last),
                           typical_interval_s=(st.last - st.first) // (st.events - 1) // 1_000_000 if st.events > 1 else 0)
                 for (a, r), st in sorted(streams.items())],
        gaps=gaps, tampering=tampering, tampering_total=tampering_total, unlogged_accounts=unlogged,
        data_events=index.data_events, read_only_events=read_only, notes=notes,
    )
