from controlzee.coverage import LISTED_TAMPERING, build_coverage, incident_period
from controlzee.ingest.index import EventIndex
from controlzee.model.event import Event, SourceRef, UserIdentity
from controlzee.timeutil import parse_time_us
from tests.helpers import make_row

T0 = parse_time_us("2026-10-20T12:00:00Z")
MIN = 60_000_000


def _event(event_id, source="s3.amazonaws.com", name="ListBuckets", **kw):
    return Event(event_id=event_id, event_time="2026-10-20T12:00:00Z", event_source=source, event_name=name, aws_region="us-east-1",
                 recipient_account_id="111122223333", user_identity=UserIdentity(), source=SourceRef(input="x.json", record=0), **kw)


def index(*rows, data_events=0):
    return EventIndex(rows=sorted(rows, key=lambda r: (r[1], r[0])), files=[], data_events=data_events)


def every(minutes, start, end, **kw):
    """One row every `minutes` from `start` up to (not including) `end`, both in minutes after T0."""
    return [make_row(ts=T0 + m * MIN, **kw) for m in range(start, end, minutes)]


def test_incident_period_joins_the_window_and_the_events():
    assert incident_period(None, None, []) is None
    assert incident_period(10, None, [5, 7]) == (5, 7)  # a window with one end does not count
    assert incident_period(10, 20, [5, 7]) == (5, 20)
    assert incident_period(10, 20, []) == (10, 20)


def test_a_silence_is_reported_only_when_long_for_its_stream_and_during_the_incident():
    busy = every(5, 0, 120, region="us-east-1") + every(5, 300, 600, region="us-east-1")  # silent 120..300
    quiet = every(120, 0, 600, region="us-west-2")
    cov = build_coverage(index(*busy, *quiet), {}, (T0 + 100 * MIN, T0 + 200 * MIN), 60)
    assert [(g.region, g.kind, g.minutes) for g in cov.gaps] == [("us-east-1", "silence", 185)]
    # outside the incident period nothing is reported, and no period means no gap analysis at all
    assert build_coverage(index(*busy), {}, (T0 + 400 * MIN, T0 + 500 * MIN), 60).gaps == []
    assert build_coverage(index(*busy), {}, None, 60).gaps == []
    # a higher threshold hides it
    assert build_coverage(index(*busy), {}, (T0, T0 + 600 * MIN), 200).gaps == []


def test_logs_that_start_late_or_end_early_are_gaps_at_the_edges():
    rows = every(5, 100, 200)
    cov = build_coverage(index(*rows), {}, (T0, T0 + 400 * MIN), 60)
    assert [(g.kind, g.minutes) for g in cov.gaps] == [("starts_late", 100), ("ends_early", 205)]


def test_a_successful_logging_change_in_the_same_account_is_a_possible_cause():
    rows = every(5, 0, 100) + every(5, 300, 400)
    stop = make_row(id="stop", ts=T0 + 90 * MIN, source="cloudtrail.amazonaws.com", name="StopLogging")
    denied = make_row(id="denied", ts=T0 + 91 * MIN, source="cloudtrail.amazonaws.com", name="DeleteTrail", err="AccessDenied")
    elsewhere = make_row(id="elsewhere", ts=T0 + 92 * MIN, source="cloudtrail.amazonaws.com", name="StopLogging", account="999988887777")
    period = (T0, T0 + 400 * MIN)
    assert [g.possible_cause for g in build_coverage(index(*rows, stop, denied), {0: _event("x")}, period, 60).gaps] == ["stop"]
    gaps = build_coverage(index(*rows, denied, elsewhere), {}, period, 60).gaps
    assert [g.possible_cause for g in gaps if g.account == "111122223333"] == [None]


def test_tampering_lists_every_actor_and_marks_the_in_scope_ones():
    rows = [make_row(id=f"t{n}", ts=T0 + n, source="guardduty.amazonaws.com", name="DeleteDetector") for n in range(LISTED_TAMPERING + 5)]
    idx = index(*rows)
    cov = build_coverage(idx, {3: _event(idx.rows[3][0])}, None, 60)
    assert cov.tampering_total == LISTED_TAMPERING + 5 and len(cov.tampering) == LISTED_TAMPERING
    assert [t.event_id for t in cov.tampering if t.in_scope] == [idx.rows[3][0]]
    assert cov.tampering[0].effect == "deletes a GuardDuty detector"


def _assume(event_id, role_arn, error=None):
    return _event(event_id, "sts.amazonaws.com", "AssumeRole", request_parameters={"roleArn": role_arn}, error_code=error)


def test_roles_assumed_in_accounts_without_logs_are_reported():
    idx = index(make_row(account="111122223333"))
    events = {0: _assume("a", "arn:aws:iam::444455556666:role/prod"), 1: _assume("b", "arn:aws:iam::111122223333:role/local"),
              2: _assume("c", "arn:aws:iam::777766665555:role/denied", error="AccessDenied"), 3: _assume("d", "not-an-arn")}
    cov = build_coverage(idx, events, None, 60)
    assert [(u.account, u.role_arns, u.event_ids) for u in cov.unlogged_accounts] == [
        ("444455556666", ["arn:aws:iam::444455556666:role/prod"], ["a"])]
    assert any("444455556666" in n for n in cov.notes)


def test_notes_for_missing_event_types():
    writes_only = build_coverage(index(make_row(ro=False)), {}, None, 60)
    assert [n.split(":")[0] for n in writes_only.notes] == ["no data events in the inputs", "no read-only events in the inputs"]
    assert build_coverage(index(make_row(ro=True), data_events=1), {}, None, 60).notes == []
