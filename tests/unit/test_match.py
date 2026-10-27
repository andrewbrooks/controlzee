import pytest

from controlzee.ingest.index import EventIndex
from controlzee.model.common import Confidence
from controlzee.model.ioc import Indicator, SeedSpec, Window
from controlzee.seed.match import compile_indicator, run_seed, validate_spec, window_bounds
from controlzee.timeutil import parse_time_us
from tests.helpers import make_row

T0 = parse_time_us("2026-10-20T12:00:00Z")
H = 3_600_000_000


def ind(name, kind, value, **kw):
    return Indicator(name=name, kind=kind, value=value, **kw)


def spec(*indicators, expression, window=None):
    return SeedSpec(indicators=tuple(indicators), expression=expression, window=window)


def index(*rows):
    return EventIndex(rows=sorted(rows, key=lambda r: (r[1], r[0])), files=[])


def test_each_indicator_kind():
    row = make_row(ak="AKIA1", pid="AROAX:sess", arn="arn:aws:sts::1:assumed-role/R/sess", issuer="arn:aws:iam::1:role/R",
                   srcid="alice", ip="198.51.100.9", ua="curl/8.0 (x)")
    cases = [
        (ind("a", "access_key_id", "AKIA1"), True), (ind("a", "access_key_id", "AKIA2"), False),
        (ind("a", "principal_id", "AROAX:sess"), True), (ind("a", "principal_id", "sess"), True),
        (ind("a", "principal_id", "AROAX"), False), (ind("a", "principal_id", "ess"), False),
        (ind("a", "source_identity", "alice"), True), (ind("a", "source_identity", "bob"), False),
        (ind("a", "principal_arn", "arn:aws:sts::1:assumed-role/R/sess"), True),
        (ind("a", "principal_arn", "arn:aws:iam::1:role/R"), True), (ind("a", "principal_arn", "arn:aws:iam::1:role/Q"), False),
        (ind("a", "source_ip", "198.51.100.9"), True), (ind("a", "source_ip", "198.51.100.0/24"), True),
        (ind("a", "source_ip", "198.51.101.0/24"), False), (ind("a", "source_ip", "2001:db8::/32"), False),
        (ind("a", "user_agent", "curl/"), True), (ind("a", "user_agent", "CURL/"), False),
        (ind("a", "user_agent", r"^curl/\d+", match="regex"), True), (ind("a", "user_agent", r"^wget", match="regex"), False),
    ]
    for indicator, expected in cases:
        assert compile_indicator(indicator)(row) is expected, indicator


def test_missing_fields_never_match_and_non_ip_source_addresses_are_ignored():
    bare = make_row(ak=None, pid=None, arn=None, issuer=None, srcid=None, ip=None, ua=None)
    for i in (ind("a", "access_key_id", "x"), ind("a", "principal_id", "x"), ind("a", "principal_arn", "x"),
              ind("a", "source_identity", "x"), ind("a", "source_ip", "0.0.0.0/0"), ind("a", "user_agent", "x"),
              ind("a", "user_agent", "x", match="regex")):
        assert compile_indicator(i)(bare) is False
    service_caller = make_row(ip="ec2.amazonaws.com")
    assert compile_indicator(ind("a", "source_ip", "0.0.0.0/0"))(service_caller) is False


def test_window_bounds_are_inclusive_and_may_be_open():
    assert window_bounds(None) == (None, None)
    assert window_bounds(Window(start="2026-10-20T12:00:00Z")) == (T0, None)
    s = spec(ind("k", "access_key_id", "AKIA1"), expression="k", window=Window(start="2026-10-20T12:00:00Z", end="2026-10-20T13:00:00Z"))
    idx = index(make_row(ak="AKIA1", ts=T0 - 1), make_row(ak="AKIA1", ts=T0), make_row(ak="AKIA1", ts=T0 + H),
                make_row(ak="AKIA1", ts=T0 + H + 1))
    assert [h.row for h in run_seed(idx, s).hits] == [1, 2]


def test_strong_and_weak_confidence_and_matched_names():
    s = spec(ind("key", "access_key_id", "AKIA1"), ind("ip", "source_ip", "198.51.100.0/24"), expression="key OR ip",
             window=Window(start="2026-10-20T00:00:00Z", end="2026-10-21T00:00:00Z"))
    idx = index(make_row(ak="AKIA1", ip="192.0.2.1", ts=T0), make_row(ak="AKIAOTHER", ip="198.51.100.5", ts=T0 + 1),
                make_row(ak="AKIA1", ip="198.51.100.5", ts=T0 + 2), make_row(ak="AKIAOTHER", ip="192.0.2.1", ts=T0 + 3))
    hits = run_seed(idx, s).hits
    assert [(h.row, h.confidence, h.matched) for h in hits] == [
        (0, Confidence.STRONG, ("key",)), (1, Confidence.WEAK, ("ip",)), (2, Confidence.STRONG, ("ip", "key"))]


def test_and_requires_both_and_records_the_weak_half_as_a_near_miss():
    s = spec(ind("key", "access_key_id", "AKIA1"), ind("ip", "source_ip", "198.51.100.5"), expression="key AND ip")
    idx = index(make_row(ak="AKIA1", ip="198.51.100.5", ts=T0), make_row(ak="AKIA1", ip="192.0.2.1", ts=T0 + 1),
                make_row(ak="AKIAOTHER", ip="198.51.100.5", ts=T0 + 2))
    r = run_seed(idx, s)
    assert [h.row for h in r.hits] == [0]
    assert [(n.row, n.matched, n.reason) for n in r.near_misses] == [(2, ("ip",), "expression")]
    assert r.near_miss_by_reason == {"expression": 1} and r.near_miss_by_indicator == {"ip": 1}
    # a strong-only partial match is not a near miss: it is simply not the attacker's key combination
    assert r.near_miss_total == 1


def test_weak_match_outside_the_window_is_a_window_near_miss():
    s = spec(ind("ip", "source_ip", "203.0.113.200"), expression="ip", window=Window(start="2026-10-20T12:00:00Z", end="2026-10-20T13:00:00Z"))
    idx = index(make_row(ip="203.0.113.200", ts=T0 - H), make_row(ip="203.0.113.200", ts=T0 + 1), make_row(ip="203.0.113.200", ts=T0 + 2 * H))
    r = run_seed(idx, s)
    assert [h.row for h in r.hits] == [1]
    assert [(n.row, n.reason) for n in r.near_misses] == [(0, "window"), (2, "window")]


def test_near_miss_list_is_capped_but_everything_is_counted():
    s = spec(ind("key", "access_key_id", "AKIA1"), ind("ip", "source_ip", "198.51.100.5"), expression="key AND ip")
    idx = index(*(make_row(ak="AKIAOTHER", ip="198.51.100.5", ts=T0 + n) for n in range(10)))
    r = run_seed(idx, s, near_miss_limit=3)
    assert len(r.near_misses) == 3 and r.near_miss_total == 10 and r.near_miss_by_indicator == {"ip": 10}
    assert [n.row for n in r.near_misses] == [0, 1, 2]


@pytest.mark.parametrize("indicators,expression,window,message", [
    ((), "x", None, "no indicators"),
    ((ind("k", "access_key_id", "A"),), "k AND other", None, "undefined indicator.*other"),
    ((ind("k", "access_key_id", "A"), ind("j", "access_key_id", "B")), "k", None, "defined but not used.*j"),
    ((ind("ip", "source_ip", "192.0.2.1"),), "ip", None, "needs a time window"),
    ((ind("ip", "source_ip", "192.0.2.1"),), "ip", Window(start="2026-10-20T00:00:00Z"), "needs a time window"),
    ((ind("ip", "source_ip", "192.0.2.1"),), "ip", Window(end="2026-10-20T00:00:00Z"), "needs a time window"),
    ((ind("ip", "source_ip", "192.0.2.1"), ind("ua", "user_agent", "curl")), "ip AND ua", None, "needs a time window"),
    ((ind("k", "access_key_id", "A"),), "k", Window(start="2026-10-21T00:00:00Z", end="2026-10-20T00:00:00Z"), "starts after it ends"),
])
def test_validation_errors(indicators, expression, window, message):
    with pytest.raises(ValueError, match=message):
        validate_spec(SeedSpec(indicators=indicators, expression=expression, window=window))


def test_a_strong_indicator_in_the_expression_needs_no_window():
    validate_spec(spec(ind("k", "access_key_id", "A"), ind("ip", "source_ip", "192.0.2.1"), expression="k OR ip"))
