"""The "Sequence of events" log: which moments there are, when it is left out, and that nothing from the logs can break it."""
import re

import pytest

from controlzee import story
from controlzee.html_report import _after, _sequence, build_html
from controlzee.model.timeline import Timeline
from controlzee.story import MAX_MOMENTS, MIN_MOMENTS, Moment, build_moments
from controlzee.timeline import build_timeline
from tests.unit.test_captured import load
from tests.unit.test_html_report import _hostile_scope, check_inert
from tests.unit.test_respond import scope_of


def moments(scope):
    return build_moments(scope, Timeline.model_validate(build_timeline(scope)))


def mk(n: int, **kw) -> Moment:
    base = {"kind": "issued", "title": "New access key", "detail": "iam:CreateAccessKey", "actor": "user/x", "time": "2026-10-20T10:00:00Z",
            "t_us": n * 60_000_000, "end_us": n * 60_000_000, "count": 1, "event_id": f"e{n}", "hot": False}
    return Moment(**{**base, **kw})


def test_a_scope_with_only_two_moments_has_no_log(fixtures):
    scope = scope_of(fixtures, "05_weak_ioc")  # a first call and one credential issued: the call table says that as well
    assert moments(scope) == [] and b'class="log"' not in build_html(scope)


def test_three_moments_are_the_least_that_make_a_sequence(fixtures):
    assert MIN_MOMENTS == 3
    scope = scope_of(fixtures, "01_leaked_key")
    ms = moments(scope)
    assert len(ms) >= 3 and b'class="log"' in build_html(scope)


def test_the_moments_are_in_time_order_and_the_first_is_the_first_indicator_match(fixtures):
    ms = moments(scope_of(fixtures, "02_role_chain"))
    assert [m.t_us for m in ms] == sorted(m.t_us for m in ms)
    assert ms[0].kind == "start" and {m.kind for m in ms} >= {"issued", "privilege"}


def test_a_privilege_grant_of_full_control_is_marked_as_needing_attention(fixtures):
    ms = moments(scope_of(fixtures, "01_leaked_key"))
    assert [(m.title, m.hot) for m in ms if m.kind == "privilege"] == [("Full control granted", True)]
    assert all(not m.hot for m in ms if m.kind in ("start", "issued"))


def test_logging_changes_each_get_a_moment_in_the_log_tampering_scenario(fixtures):
    ms = moments(scope_of(fixtures, "04_log_tampering"))
    assert [m.kind for m in ms] == ["start", "tamper", "tamper", "tamper"] and all(m.hot for m in ms[1:])


def test_instance_credentials_used_from_another_address_are_a_moment(fixtures):
    ms = moments(load("ec2-steal-instance-credentials")[0])
    assert [m.title for m in ms if m.kind == "instance"] == ["Instance role used from another address"] and ms[-1].kind == "instance"
    assert all(m.kind != "instance" for m in moments(load("ec2-enumerate-from-instance")[0]))  # the instance acting on its own is not one


def test_secrets_read_are_a_moment_that_needs_attention(fixtures):
    assert [(m.kind, m.hot) for m in moments(scope_of(fixtures, "06_lambda")) if m.kind == "secrets"] == [("secrets", True)] * 2


def test_a_burst_of_the_same_call_is_one_moment_with_a_count(fixtures):
    ms = moments(load("secretsmanager-retrieve-secrets")[0])
    assert len(ms) == 3 and ms[-1].count == 60 and ms[-1].kind == "secrets"


def test_repeats_further_apart_than_the_limit_are_separate_moments(fixtures, monkeypatch):
    scope = load("secretsmanager-retrieve-secrets")[0]
    monkeypatch.setattr(story, "GROUP_SECONDS", 0)
    assert len(moments(scope)) > 3  # the same calls, seconds apart, no longer count as one


def test_the_log_shows_at_most_the_cap_and_counts_the_rest():
    page = _sequence([mk(n) for n in range(MAX_MOMENTS + 5)], {f"e{n}": f"call-{n}" for n in range(30)})
    assert page.count('<li class="ev') == MAX_MOMENTS + 1 and "+5 more moments" in page


def test_each_moment_links_to_its_row_and_says_how_long_after_the_last():
    page = _sequence([mk(0), mk(1), mk(61, kind="privilege", title="Full control granted", hot=True)], {"e0": "call-1", "e1": "call-2", "e61": "call-3"})
    assert 'href="#call-3"' in page and "1 min later" in page and "1 h 0 min later" in page and 'class="ev hot"' in page
    assert "start" in page and "\u25b2" in page  # the shape is a character, so it reads without styles


def test_a_moment_without_a_row_is_plain_text_not_a_dead_link():
    page = _sequence([mk(0), mk(1), mk(2)], {"e0": "call-1"})
    assert page.count("<a href=") == 1


@pytest.mark.parametrize(("seconds", "text"), [(0, "in the same second"), (7, "7 s later"), (60, "1 min later"), (3599, "59 min later"), (5400, "1 h 30 min later")])
def test_elapsed_time_reads_naturally(seconds, text):
    assert _after(seconds) == text


HOSTILE = ['"><script>alert(1)</script>', "' onmouseover='alert(1)", "<img src=x onerror=alert(1)>", "A" * 5000]


@pytest.mark.parametrize("evil", HOSTILE)
def test_hostile_text_in_a_moment_is_inert(evil):
    page = _sequence([mk(n, title=evil, detail=evil, actor=evil) for n in range(3)], {"e0": "call-1"})
    assert "<script" not in page and "<img" not in page and 'onmouseover=' not in page.replace("&#x27; onmouseover=&#x27;", "")
    assert len(page) < 20_000  # long text is cut, not copied whole


def test_the_whole_page_with_hostile_log_text_keeps_its_log_inert(tmp_path):
    scope = _hostile_scope(tmp_path)
    page = build_html(scope)
    check_inert(page)  # no new tag, attribute, script or link
    text = page.decode()
    assert 'class="log"' in text and not re.search(r"<script>alert", text)


def test_the_log_is_the_same_bytes_every_time(fixtures):
    scope = scope_of(fixtures, "02_role_chain")
    assert build_html(scope) == build_html(scope)


def test_a_moment_that_needs_attention_has_an_icon_and_words_not_only_a_colour():
    page = _sequence([mk(0), mk(1, kind="tamper", title="Logging or detection changed", hot=True), mk(2)], {})
    assert page.count('class="flag"') == 1 and "Needs attention: " in page and "\u25b2" in page
    assert 'class="ev hot"' in page and page.count("Needs attention") == 1


def test_the_log_has_the_time_in_a_gutter_a_number_and_the_time_since_the_last():
    page = _sequence([mk(0), mk(5)], {"e0": "call-1", "e5": "call-2"})
    assert page.count('class="ev-t"') == 2 and 'class="ev-n" aria-hidden="true">2<' in page and "5 min later" in page and ">start<" in page


def test_a_log_over_several_days_names_the_day_in_the_gutter():
    page = _sequence([mk(0), mk(2, time="2026-10-22T09:00:00Z"), mk(3, time="2026-10-22T10:00:00Z")], {})
    assert "10-20 10:00:00" in page and "10-22 09:00:00" in page
