"""UTC timestamp helpers shared by ingest and seeding."""
from __future__ import annotations

import calendar
from datetime import UTC, date, datetime


def parse_time_us(text: str) -> int:
    """UTC microseconds since the epoch for an ISO-8601 timestamp (trailing Z is UTC; naive times are taken as UTC)."""
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return calendar.timegm(dt.utctimetuple()) * 1_000_000 + dt.microsecond


def format_time_us(us: int) -> str:
    """The canonical text for a timestamp: `YYYY-MM-DDTHH:MM:SSZ`, with microseconds only when non-zero."""
    secs, micro = divmod(us, 1_000_000)
    dt = datetime.fromtimestamp(secs, UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + (f".{micro:06d}" if micro else "") + "Z"


def normalize_time(value: object) -> str:
    """Accept a string, date or datetime (YAML parses unquoted timestamps) and return the canonical text."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return format_time_us(calendar.timegm(value.utctimetuple()) * 1_000_000 + value.microsecond)
    if isinstance(value, date):
        return format_time_us(calendar.timegm(value.timetuple()) * 1_000_000)
    if isinstance(value, str):
        try:
            return format_time_us(parse_time_us(value.strip()))
        except ValueError:
            raise ValueError(f"{value!r} is not an ISO-8601 time (example: 2026-10-20T14:30:00Z)") from None
    raise ValueError(f"{value!r} is not a time")
