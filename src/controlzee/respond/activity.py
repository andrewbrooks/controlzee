"""A check, made by the dry run, for activity by the attacker after the scope was built.

The scope is a picture of the logs at the time it was made. If the attacker still holds a credential, they may have done
more since, and a plan built from the picture can be missing something they made. This reads CloudTrail event history
from the scope's `period_end` to now (the same `LookupInput` as `scope --lookup-events`) and looks for calls made by
the identities the scope names: the ones it found the attacker obtaining, and its strong seed indicators (a key id or
principal id; an IP address or user agent would match unrelated traffic, so they are not used).

It only warns. It never fails a dry run and never blocks a step: whatever goes wrong becomes a warning saying that the
check could not be made. Event history is hostile input like any log: it goes through the normal ingest (size caps,
malformed records counted) and everything printed goes through `safety.clean`.

`find_new_activity` works on index rows and does no I/O; `check_activity` does the reading.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from controlzee.ingest.index import R_ID, R_NAME, R_REGION, R_SOURCE, R_TIME, R_TS, Row
from controlzee.ingest.load import IngestOptions, load_index
from controlzee.ingest.remote import LookupInput, PrefetchedInput, RemoteError
from controlzee.ingest.source import Source
from controlzee.model.ioc import STRONG_KINDS
from controlzee.model.respond import ActivityCheck, NewActivity
from controlzee.model.scope import Scope
from controlzee.respond.ops import Unsafe, check
from controlzee.safety import clean
from controlzee.seed.match import compile_indicator
from controlzee.taint.propagate import acting_as
from controlzee.taint.rules import rule_name
from controlzee.timeutil import parse_time_us

DEFAULT_MAX_EVENTS = 50_000
MAX_LISTED = 100  # entries in `new_activity`; the true count is `total_found`

NEW_ACTIVITY_WARNING = (
    "tainted identities acted after this scope was built; contain now if you need to, then scope again before "
    "removing what they made."
)
NO_NEW_ACTIVITY_WARNING = (
    "no tainted identity acted after this scope was built, as far as CloudTrail event history shows; event history "
    "can lag by about 15 minutes, so this is not proof."
)
SKIPPED_WARNING = "the activity check was skipped (--activity-check-max-events 0)."
NOTHING_TO_LOOK_FOR_WARNING = (
    "the activity check was skipped: the scope has no tainted identity or strong seed to look for."
)


@dataclass(frozen=True)
class Outcome:
    check: ActivityCheck
    new_activity: list[NewActivity]
    warnings: list[str]


def find_new_activity(rows: Sequence[Row], scope: Scope) -> tuple[list[NewActivity], int]:
    """(the first MAX_LISTED calls, how many in all) made at or after the scope's `period_end` that the scope does not
    already hold, by an identity it names. `rows` are in time order, as an index's are."""
    if scope.coverage.period_end is None:
        return [], 0
    since = parse_time_us(scope.coverage.period_end)
    known = {e.event.event_id for e in scope.events}
    identities: dict[tuple[str, str], str] = {
        (t.kind, t.value): f"{t.kind}:{t.value}" for t in scope.taint.identities
    }
    indicators = [
        (f"{i.kind.value}:{i.value}", compile_indicator(i))
        for i in scope.seeds.indicators
        if i.kind in STRONG_KINDS
    ]
    found: list[NewActivity] = []
    total = 0
    for row in rows:
        if row[R_ID] in known or row[R_TS] < since:
            continue
        labels = acting_as(row, identities) or [label for label, hit in indicators if hit(row)]
        if not labels:
            continue
        total += 1
        if len(found) < MAX_LISTED:
            found.append(
                NewActivity(
                    time=clean(row[R_TIME], 40),
                    identity=clean(labels[0], 200),
                    event=clean(rule_name(row[R_SOURCE], row[R_NAME]), 120),
                    region=clean(row[R_REGION], 40),
                    event_id=clean(row[R_ID], 100),
                )
            )
    return found, total


def regions_to_read(scope: Scope, home_region: str) -> tuple[list[str], list[str]]:
    """(regions to query: the home region first, then the scope's other log regions in order; names that are not a
    region, which only a hostile log would hold). Region names come from logs, so each must have the shape of one."""
    wanted = {s.region for s in scope.coverage.streams} | {home_region}
    valid: list[str] = []
    invalid: list[str] = []
    for region in [home_region, *sorted(wanted - {home_region})]:
        try:
            check("region", region)
            valid.append(region)
        except Unsafe:
            invalid.append(region)
    return valid, invalid


def _outcome(
    status: str,
    warnings: list[str],
    *,
    since: str | None = None,
    until: str | None = None,
    regions: Sequence[str] = (),
    failed: Sequence[str] = (),
    unread: Sequence[str] = (),
    events_read: int = 0,
    total: int = 0,
    complete: bool = False,
    new_activity: list[NewActivity] | None = None,
) -> Outcome:
    return Outcome(
        ActivityCheck.model_validate(
            {
                "status": status,
                "since": since,
                "until": until,
                "regions": list(regions),
                "failed_regions": list(failed),
                "unread_regions": list(unread),
                "events_read": events_read,
                "total_found": total,
                "complete": complete,
            }
        ),
        new_activity or [],
        warnings,
    )


def check_activity(
    scope: Scope,
    *,
    caller_account: str,
    profile: str | None,
    home_region: str,
    max_events: int,
    until: str,
    progress: Callable[[str], None] = lambda message: None,
) -> Outcome:
    """Look for activity after the scope. Never raises: anything that goes wrong is a warning."""
    since = scope.coverage.period_end
    try:
        if max_events <= 0:
            return _outcome("skipped", [SKIPPED_WARNING], since=since, until=until)
        if since is None or not (
            scope.taint.identities or any(i.kind in STRONG_KINDS for i in scope.seeds.indicators)
        ):
            return _outcome("skipped", [NOTHING_TO_LOOK_FOR_WARNING], since=since, until=until)
        return _check(scope, caller_account, profile, home_region, max_events, since, until, progress)
    except Exception as e:  # the check must not be able to fail a dry run
        reason = clean(f"unexpected error {type(e).__name__}: {e}", 200)
        return _outcome("could not run", [_could_not_run(reason)], since=since, until=until)


def _could_not_run(reason: str) -> str:
    return (
        f"could not check whether tainted identities acted after this scope was built ({reason}); look at "
        "CloudTrail yourself before removing anything."
    )


def _check(
    scope: Scope,
    caller_account: str,
    profile: str | None,
    home_region: str,
    max_events: int,
    since: str,
    until: str,
    progress: Callable[[str], None],
) -> Outcome:
    valid, invalid = regions_to_read(scope, home_region)
    sources: list[Source] = []
    read: list[str] = []
    failed: dict[str, str] = {}
    unread: list[str] = []
    cut_short: list[str] = []
    remaining = max_events  # one budget for every region, spent in order
    for region in valid:
        if remaining <= 0:
            unread.append(region)
            continue
        progress(f"reading CloudTrail event history of {region}")
        lookup = LookupInput(region, since, until, profile, max_events=remaining)
        try:
            records, truncated = lookup.fetch()
        except RemoteError as e:
            failed[region] = clean(e, 200)
            continue
        read.append(region)
        sources.append(lookup.source(records))
        remaining -= len(records)
        if truncated:
            cut_short.append(region)
    failed_names = [*failed, *(f"{clean(r, 40)} (not a region name)" for r in invalid)]
    if not read:
        reason = next(iter(failed.values()), "no region to read")
        return _outcome(
            "could not run", [_could_not_run(reason)], since=since, until=until, failed=failed_names
        )

    index = load_index([PrefetchedInput(tuple(sources))], IngestOptions(workers=1))
    found, total = find_new_activity(index.rows, scope)
    unparsed = index.malformed_records + sum(1 for f in index.files if f.status == "error")

    parts: list[str] = []
    if cut_short or unread:
        parts.append(
            f"it read {len(index.rows)} events and stopped at the cap of {max_events} "
            "(--activity-check-max-events), so the oldest events in the window were not read"
            + (f"; not read at all: {', '.join(unread)}" if unread else "")
        )
    if failed_names:
        parts.append(
            f"it could not read the event history of {', '.join(failed_names)}"
            + (f" ({next(iter(failed.values()))})" if failed else "")
        )
    if unparsed:
        parts.append(f"{unparsed} record(s) could not be parsed")
    warnings = [NEW_ACTIVITY_WARNING if total else NO_NEW_ACTIVITY_WARNING]
    if parts:
        warnings.append("the activity check was incomplete: " + "; ".join(parts) + ".")
    others = sorted(set(scope.inputs.accounts) - {caller_account})
    if others:
        warnings.append(
            f"event history covers only account {clean(caller_account, 20)}; the scope also has events in "
            f"{', '.join(clean(a, 20) for a in others)}, which were not checked."
        )
    return _outcome(
        "new activity" if total else "no new activity",
        warnings,
        since=since,
        until=until,
        regions=read,
        failed=failed_names,
        unread=unread,
        events_read=len(index.rows),
        total=total,
        complete=not parts,
        new_activity=found,
    )
