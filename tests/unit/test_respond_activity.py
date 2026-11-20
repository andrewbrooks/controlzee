"""The dry run's check for activity after the scope was built: it finds what the attacker did since, and only ever warns."""

import json

import pytest

from controlzee.model.respond import NewActivity
from controlzee.respond import activity
from controlzee.respond.activity import (
    NEW_ACTIVITY_WARNING,
    NO_NEW_ACTIVITY_WARNING,
    NOTHING_TO_LOOK_FOR_WARNING,
    SKIPPED_WARNING,
    check_activity,
    find_new_activity,
    regions_to_read,
)
from controlzee.timeutil import parse_time_us
from tests import fake_aws
from tests.builders.cloudtrail import LogSet, assumed_role, at, iam_user
from tests.helpers import make_row
from tests.unit.test_respond import (
    _journal_dir,  # noqa: F401  (autouse: a fresh journal folder for every test)
    account_01,
    account_02,
    check,
    cli,
    run,
    scope_of,
)

SINCE = "2026-10-20T14:40:00Z"  # 01_leaked_key: the scope's period_end
BACKDOOR_KEY = "AKIAIOSFODNN7BKDOOR"  # a key the attacker made in that scope
BACKDOOR_PRINCIPAL = "AIDAE18185DBD523AB726"
LEAKED_KEY = "AKIAIOSFODNN7LEAKED"  # the key the scope started from: a seed, not an issued identity


def backdoor(key=BACKDOOR_KEY):
    return iam_user("backdoor-svc", key)


def call(log, when, identity, name="ListUsers", region="us-east-1", **kw):
    return log.add(at(when), "iam.amazonaws.com", name, identity, region=region, **kw)


# ---- the spec's tests


def test_a_tainted_key_acting_after_the_scope_is_reported_and_the_dry_run_still_passes(fixtures, monkeypatch):
    scope, acct, log = scope_of(fixtures, "01_leaked_key"), account_01(), LogSet()
    rec = call(log, "2026-10-20T15:10:00Z", backdoor(), "CreateAccessKey")
    acct.history = {"us-east-1": [rec]}
    dr = check(scope, acct, monkeypatch)
    assert dr.passed and dr.problems == []
    assert dr.new_activity == [
        NewActivity(
            time="2026-10-20T15:10:00Z",
            identity=f"access_key_id:{BACKDOOR_KEY}",
            event="iam:CreateAccessKey",
            region="us-east-1",
            event_id=rec["eventID"],
        )
    ]
    assert NEW_ACTIVITY_WARNING in dr.warnings and dr.activity_check.status == "new activity"
    assert (dr.activity_check.total_found, dr.activity_check.events_read) == (1, 1)
    assert dr.activity_check.regions == ["us-east-1", "us-west-2"] and dr.activity_check.complete
    assert {(c["StartTime"], c["EndTime"]) for c in acct.lookup_calls} == {(SINCE, "2026-10-27T12:00:00Z")}
    assert acct.calls == []  # reads only
    assert run(dr.model_dump(mode="json")).completed  # a warning does not stop execute


@pytest.mark.parametrize(
    "scenario,account,identity,expected",
    [
        (  # a new session of a principal the attacker obtained, under a key the scope has never seen
            "01_leaked_key",
            account_01,
            {**backdoor("AKIAIOSFODNN7EXAMPLE"), "principalId": BACKDOOR_PRINCIPAL},
            f"principal_id:{BACKDOOR_PRINCIPAL}",
        ),
        (  # a new session of a role the attacker assumed
            "02_role_chain",
            account_02,
            {
                **assumed_role("ops-admin", "fresh-session", "ASIAIOSFODNN7EXAMPLE"),
                "principalId": "AROA562411BDB29807BFD:fresh-session",
            },
            "role_id:AROA562411BDB29807BFD",
        ),
    ],
)
def test_a_session_of_a_tainted_principal_is_found_too(
    fixtures, monkeypatch, scenario, account, identity, expected
):
    scope, acct, log = scope_of(fixtures, scenario), account(), LogSet()
    acct.history = {"us-east-1": [call(log, "2026-10-20T16:00:00Z", identity)]}
    dr = check(scope, acct, monkeypatch)
    assert dr.passed and [a.identity for a in dr.new_activity] == [expected]


def test_no_new_activity_is_said_and_it_is_not_proof(fixtures, monkeypatch):
    dr = check(scope_of(fixtures, "01_leaked_key"), account_01(), monkeypatch)
    assert dr.passed and dr.new_activity == [] and dr.activity_check.status == "no new activity"
    assert NO_NEW_ACTIVITY_WARNING in dr.warnings and "can lag by about 15 minutes" in NO_NEW_ACTIVITY_WARNING
    assert NEW_ACTIVITY_WARNING not in dr.warnings and dr.activity_check.complete


@pytest.mark.parametrize("code", ["AccessDeniedException", "ThrottlingException"])
def test_event_history_that_cannot_be_read_is_a_warning_and_the_dry_run_passes(fixtures, monkeypatch, code):
    acct = account_01()
    acct.lookup_error = code
    dr = check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch)
    assert dr.passed and dr.activity_check.status == "could not run" and dr.new_activity == []
    assert any(
        w.startswith("could not check whether tainted identities acted") and code in w for w in dr.warnings
    )
    assert run(dr.model_dump(mode="json")).completed


# ---- who counts as the attacker


def test_the_key_the_scope_started_from_is_watched_though_it_was_never_issued(fixtures, monkeypatch):
    scope, acct, log = scope_of(fixtures, "01_leaked_key"), account_01(), LogSet()
    assert LEAKED_KEY not in {t.value for t in scope.taint.identities}
    acct.history = {
        "us-west-2": [
            call(log, "2026-10-21T09:00:00Z", iam_user("ci-deploy", LEAKED_KEY), region="us-west-2")
        ]
    }
    dr = check(scope, acct, monkeypatch)
    assert [(a.identity, a.region) for a in dr.new_activity] == [(f"access_key_id:{LEAKED_KEY}", "us-west-2")]


def test_a_weak_indicator_is_not_enough_after_the_scope(fixtures, monkeypatch):
    scope, acct, log = scope_of(fixtures, "01_leaked_key"), account_01(), LogSet()
    acct.history = {  # the attacker's IP, but nobody the scope knows
        "us-east-1": [
            call(log, "2026-10-21T09:00:00Z", iam_user("someone", "AKIAIOSFODNN7EXAMPLE"), ip="198.51.100.77")
        ]
    }
    assert check(scope, acct, monkeypatch).new_activity == []


def test_events_the_scope_already_holds_are_not_new(fixtures, monkeypatch):
    scope, acct, log = scope_of(fixtures, "01_leaked_key"), account_01(), LogSet()
    rec = call(log, SINCE, backdoor())  # at period_end, with the id of an event already in scope
    rec["eventID"] = scope.events[-1].event.event_id
    acct.history = {"us-east-1": [rec]}
    assert check(scope, acct, monkeypatch).new_activity == []


@pytest.mark.parametrize(
    "scenario,kind,row",
    [
        ("01_leaked_key", "access_key_id", {"ak": BACKDOOR_KEY}),
        ("01_leaked_key", "principal_id", {"pid": BACKDOOR_PRINCIPAL, "ak": "AKIAFRESH"}),
        (
            "02_role_chain",
            "role_id",
            {"pid": "AROA562411BDB29807BFD:other", "uitype": "AssumedRole", "ak": "ASIAFRESH"},
        ),
        (
            "03_instance_role",
            "instance_id",
            {"pid": "AROAANYROLE:i-0a1b2c3d4e5f60718", "uitype": "AssumedRole", "ak": "ASIAFRESH"},
        ),
        (
            "06_lambda",
            "function_name",
            {"pid": "AROAANYROLE:exfil-fn", "uitype": "AssumedRole", "ak": "ASIAFRESH"},
        ),
    ],
)
def test_every_kind_of_tainted_identity_is_matched(fixtures, scenario, kind, row):
    scope = scope_of(fixtures, scenario)
    later = parse_time_us(scope.coverage.period_end) + 60_000_000
    found, total = find_new_activity(
        [make_row(ts=later, source="iam.amazonaws.com", name="ListUsers", **row)], scope
    )
    assert total == 1 and found[0].identity.split(":", 1)[0] == kind
    before = parse_time_us(scope.coverage.period_end) - 60_000_000
    assert find_new_activity([make_row(ts=before, **row)], scope) == ([], 0)


# ---- reading history: regions, the cap, partial failure


def test_regions_are_the_scopes_log_regions_and_the_home_region_and_only_real_region_names(fixtures):
    scope = scope_of(fixtures, "01_leaked_key")
    assert regions_to_read(scope, "eu-west-1") == (["eu-west-1", "us-east-1", "us-west-2"], [])
    hostile = scope.model_copy(
        update={
            "coverage": scope.coverage.model_copy(
                update={"streams": [scope.coverage.streams[0].model_copy(update={"region": "x; rm -rf /"})]}
            )
        }
    )
    assert regions_to_read(hostile, "us-east-1") == (["us-east-1"], ["x; rm -rf /"])


def test_the_event_cap_is_one_budget_and_the_oldest_events_are_the_ones_left_out(fixtures, monkeypatch):
    scope, acct, log = scope_of(fixtures, "01_leaked_key"), account_01(), LogSet()
    acct.history = {
        "us-east-1": [call(log, f"2026-10-20T15:{m}:00Z", backdoor()) for m in ("10", "20", "30")],
        "us-west-2": [call(log, "2026-10-20T15:40:00Z", backdoor(), region="us-west-2")],
    }
    dr = check(scope, acct, monkeypatch, activity_max_events=2)
    assert dr.passed and dr.activity_check.events_read == 2 and not dr.activity_check.complete
    assert [a.time for a in dr.new_activity] == [
        "2026-10-20T15:20:00Z",
        "2026-10-20T15:30:00Z",
    ]  # newest first
    assert dr.activity_check.unread_regions == ["us-west-2"] and dr.activity_check.regions == ["us-east-1"]
    incomplete = next(w for w in dr.warnings if w.startswith("the activity check was incomplete"))
    assert "stopped at the cap of 2" in incomplete and "--activity-check-max-events" in incomplete
    assert "not read at all: us-west-2" in incomplete


def test_a_budget_used_up_exactly_still_leaves_later_regions_unread(fixtures, monkeypatch):
    scope, acct, log = scope_of(fixtures, "01_leaked_key"), account_01(), LogSet()
    acct.history = {"us-east-1": [call(log, f"2026-10-20T15:{m}:00Z", backdoor()) for m in ("10", "20")]}
    dr = check(scope, acct, monkeypatch, activity_max_events=2)
    assert dr.activity_check.unread_regions == ["us-west-2"] and not dr.activity_check.complete


def test_a_cap_of_zero_skips_the_check(fixtures, monkeypatch):
    acct = account_01()
    dr = check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch, activity_max_events=0)
    assert dr.passed and dr.activity_check.status == "skipped" and SKIPPED_WARNING in dr.warnings
    assert acct.lookup_calls == []


def test_one_region_that_fails_does_not_stop_the_others(fixtures, monkeypatch):
    scope, acct, log = scope_of(fixtures, "01_leaked_key"), account_01(), LogSet()
    acct.history = {"us-east-1": [call(log, "2026-10-20T15:10:00Z", backdoor())]}
    real = fake_aws.FakeClient._cloudtrail_lookup_events

    def west_is_denied(self, op, **kw):
        if self.region == "us-west-2":
            raise fake_aws._err("AccessDeniedException", op)
        return real(self, op, **kw)

    monkeypatch.setattr(fake_aws.FakeClient, "_cloudtrail_lookup_events", west_is_denied)
    dr = check(scope, acct, monkeypatch)
    assert dr.passed and dr.activity_check.status == "new activity" and not dr.activity_check.complete
    assert dr.activity_check.failed_regions == ["us-west-2"] and dr.activity_check.regions == ["us-east-1"]
    assert any("could not read the event history of us-west-2" in w for w in dr.warnings)


def test_an_unexpected_error_in_the_check_is_a_warning_not_a_failure(fixtures, monkeypatch):
    def broken(*a, **kw):
        raise RuntimeError("boom")

    monkeypatch.setattr(activity, "load_index", broken)
    scope, acct, log = scope_of(fixtures, "01_leaked_key"), account_01(), LogSet()
    acct.history = {"us-east-1": [call(log, "2026-10-20T15:10:00Z", backdoor())]}
    dr = check(scope, acct, monkeypatch)
    assert dr.passed and dr.activity_check.status == "could not run"
    assert any("unexpected error RuntimeError: boom" in w for w in dr.warnings)


def test_other_accounts_are_said_to_be_unchecked(fixtures, monkeypatch):
    scope = scope_of(fixtures, "01_leaked_key")
    account_01().install(monkeypatch)
    out = check_activity(
        scope,
        caller_account="444455556666",
        profile=None,
        home_region="us-east-1",
        max_events=100,
        until="2026-10-27T12:00:00Z",
    )
    assert any("covers only account 444455556666" in w and "111122223333" in w for w in out.warnings)


def test_a_scope_with_nothing_to_look_for_says_so(fixtures, monkeypatch):
    scope = scope_of(fixtures, "03_instance_role")  # weak seeds only
    bare = scope.model_copy(update={"taint": scope.taint.model_copy(update={"identities": []})})
    account_01().install(monkeypatch)
    out = check_activity(
        bare,
        caller_account="111122223333",
        profile=None,
        home_region="us-east-1",
        max_events=100,
        until="2026-10-27T12:00:00Z",
    )
    assert out.check.status == "skipped" and out.warnings == [NOTHING_TO_LOOK_FOR_WARNING]


# ---- the command line


def run_cli(fixtures, monkeypatch, tmp_path, acct, *extra):
    acct.install(monkeypatch)
    scope = fixtures / "01_leaked_key/expected/scope.json"
    return cli("respond", "dry-run", scope, "-o", tmp_path / "dryrun.json", *extra), tmp_path / "dryrun.json"


def test_the_cli_prints_what_the_attacker_did_after_the_scope(fixtures, monkeypatch, tmp_path):
    acct, log = account_01(), LogSet()
    acct.history = {"us-east-1": [call(log, "2026-10-20T15:10:00Z", backdoor(), "CreateAccessKey")]}
    r, out = run_cli(fixtures, monkeypatch, tmp_path, acct)
    assert r.exit_code == 0, r.output
    assert NEW_ACTIVITY_WARNING in r.output.replace("\n", " ")
    assert (
        f"AFTER THE SCOPE 2026-10-20T15:10:00Z access_key_id:{BACKDOOR_KEY} iam:CreateAccessKey in us-east-1"
        in r.output
    )
    assert "reading CloudTrail event history of us-east-1" in r.output
    assert json.loads(out.read_text())["new_activity"][0]["event"] == "iam:CreateAccessKey"


def test_the_cli_says_when_there_is_none_and_that_history_lags(fixtures, monkeypatch, tmp_path):
    r, _ = run_cli(fixtures, monkeypatch, tmp_path, account_01())
    assert r.exit_code == 0 and "can lag by about 15 minutes" in r.output.replace("\n", " ")


def test_the_cli_takes_the_cap_and_zero_skips(fixtures, monkeypatch, tmp_path):
    acct = account_01()
    r, _ = run_cli(fixtures, monkeypatch, tmp_path, acct, "--activity-check-max-events", "0")
    assert r.exit_code == 0 and "skipped (--activity-check-max-events 0)" in r.output.replace("\n", " ")
    assert acct.lookup_calls == []
    r, _ = run_cli(fixtures, monkeypatch, tmp_path, acct, "--activity-check-max-events", "-1", "--force")
    assert r.exit_code == 2


def test_what_is_printed_from_event_history_is_cleaned(fixtures, monkeypatch, tmp_path):
    acct, log = account_01(), LogSet()
    rec = call(log, "2026-10-20T15:10:00Z", backdoor(), "\x1b[31mCreateAccessKey")
    rec["awsRegion"] = "\x1b[2Jus-east-1\x07"
    acct.history = {"us-east-1": [rec]}
    r, out = run_cli(fixtures, monkeypatch, tmp_path, acct)
    assert r.exit_code == 0 and "\x1b" not in r.output and "\x07" not in r.output
    assert "\x1b" not in out.read_text() and json.loads(out.read_text())["new_activity"]


def test_new_activity_is_listed_in_time_order(fixtures, monkeypatch):
    scope, acct, log = scope_of(fixtures, "01_leaked_key"), account_01(), LogSet()
    recs = [call(log, f"2026-10-20T15:{m}:00Z", backdoor()) for m in ("30", "10", "20")]
    acct.history = {"us-east-1": recs}
    dr = check(scope, acct, monkeypatch)
    assert [a.event_id for a in dr.new_activity] == [
        recs[1]["eventID"],
        recs[2]["eventID"],
        recs[0]["eventID"],
    ]


# ---- found on a real account: a scope whose period ends at or after the time of the check


@pytest.mark.parametrize(
    "until", ["2026-10-20T14:40:00Z", "2026-10-20T12:00:00Z"]
)  # the same moment, and earlier
def test_a_scope_that_ends_at_or_after_the_check_has_nothing_after_it_and_asks_aws_nothing(
    fixtures, monkeypatch, until
):
    scope, acct = scope_of(fixtures, "01_leaked_key"), account_01()
    assert scope.coverage.period_end == "2026-10-20T14:40:00Z"
    acct.install(monkeypatch)
    out = check_activity(
        scope,
        caller_account="111122223333",
        profile=None,
        home_region="us-east-1",
        max_events=100,
        until=until,
    )
    assert out.check.status == "skipped" and acct.lookup_calls == []
    assert len(out.warnings) == 1 and "which is not before this check" in out.warnings[0]
    assert "scope again once the window has ended" in out.warnings[0]


def test_the_dry_run_passes_and_warns_when_the_scope_ends_after_it_was_made(fixtures, monkeypatch):
    from datetime import UTC, datetime

    from controlzee.respond.run import dry_run

    acct = account_01()
    acct.install(monkeypatch)
    doc = dry_run(
        scope_of(fixtures, "01_leaked_key"),
        profile=None,
        home_region="us-east-1",
        clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=UTC),
    )
    assert doc["passed"] and doc["activity_check"]["status"] == "skipped" and acct.lookup_calls == []
    assert any("nothing after it to look at yet" in w for w in doc["warnings"])
