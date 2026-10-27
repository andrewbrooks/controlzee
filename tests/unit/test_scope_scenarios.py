"""End to end over the committed fixtures: assertions on meaning first, then byte-for-byte goldens."""
import pytest

from controlzee import canonical
from controlzee.scope import ScopeOptions, build_scope
from controlzee.seed.spec import SpecParts, assemble, from_flags, load_iocs_file
from tests.builders.build_fixtures import SCENARIOS

OPTS = ScopeOptions(workers=1)


def scope_for(fixtures, scenario, iocs="iocs.yaml", options=OPTS):
    root = fixtures / scenario
    spec = assemble([load_iocs_file(root / iocs)])
    return build_scope([root / "logs"], spec, options)


def names(out):
    return [s.event.event_name for s in out.scope.events]


def test_scenario_01_and_expression_isolates_the_attackers_calls(fixtures):
    out = scope_for(fixtures, "01_leaked_key")
    seeds = [s for s in out.scope.events if s.origin == "seed"]
    assert [s.event.event_name for s in seeds] == ["GetCallerIdentity", "ListUsers", "ListRoles", "ListBuckets", "DescribeInstances",
                                                   "GetAccountAuthorizationDetails", "CreateUser", "AttachUserPolicy", "CreateAccessKey"]
    assert {s.confidence.value for s in out.scope.events} == {"strong"}
    assert {s.event.source_ip for s in seeds} == {"198.51.100.77"}
    s = out.scope.summary
    assert (s.events_in_scope, s.failed_calls, s.by_confidence) == (11, 1, {"strong": 11, "weak": 0})
    assert s.first_event_time == "2026-10-20T14:30:00Z" and s.last_event_time == "2026-10-20T14:40:00Z"
    assert out.scope.seeds.expression == "leaked_key AND attacker_ip"
    assert out.scope.inputs.error_files == 0 and out.scope.inputs.accounts == ["111122223333"]
    assert out.scope.near_miss_summary.total == 0


def test_scenario_01_key_alone_also_catches_the_owners_own_use(fixtures):
    out = scope_for(fixtures, "01_leaked_key", "iocs_key_only.yaml")
    assert out.scope.summary.by_origin == {"propagated": 2, "seed": 11}
    assert {s.event.source_ip for s in out.scope.events if s.origin == "seed"} == {"198.51.100.77", "203.0.113.10"}


def test_scenario_01_taint_follows_the_backdoor_key(fixtures):
    out = scope_for(fixtures, "01_leaked_key")
    seeds = [s for s in out.scope.events if s.origin == "seed"]
    followed = [s for s in out.scope.events if s.origin == "propagated"]
    assert all(s.chain == [] and s.via is None for s in seeds)
    create_key = next(s.event.event_id for s in seeds if s.event.event_name == "CreateAccessKey")
    assert [(s.event.event_name, s.via, s.chain, s.confidence.value) for s in followed] == [
        ("ListBuckets", "access_key_id:AKIAIOSFODNN7BKDOOR", [create_key], "strong"),
        ("ListUsers", "access_key_id:AKIAIOSFODNN7BKDOOR", [create_key], "strong")]
    # the new user and its key are both tainted; the user's calls were made with that key
    assert [(i.rule, i.kind, i.events) for i in out.scope.taint.identities] == [
        ("iam:CreateUser", "principal_id", 2), ("iam:CreateAccessKey", "access_key_id", 2)]
    assert out.scope.summary.by_origin == {"propagated": 2, "seed": 9}


def test_no_propagate_keeps_only_the_seeds(fixtures):
    out = scope_for(fixtures, "01_leaked_key", options=ScopeOptions(workers=1, propagate=False))
    assert len(out.scope.events) == 9 and all(s.origin == "seed" for s in out.scope.events)
    assert out.scope.taint.enabled is False and out.scope.taint.identities == []


def test_scenario_02_follows_sessions_tokens_and_a_created_role_but_not_the_role_itself(fixtures):
    out = scope_for(fixtures, "02_role_chain")
    events = {(s.event.event_time[11:19], s.event.event_name): s for s in out.scope.events}
    assert events[("10:02:00", "ListBuckets")].via == "access_key_id:ASIAIOSFODNN7OPSMNT"  # the assumed ops-admin session
    assert events[("10:20:00", "DescribeInstances")].via == "access_key_id:ASIAIOSFODNN7JNKTOK"  # GetSessionToken
    # the outside account's entry into the role the attacker created, and its sessions: three hops from the seed
    entry = events[("13:00:00", "AssumeRole")]
    assert entry.event.user_identity.account_id == "999900001111" and entry.via and entry.via.startswith("role_id:")
    assert len(entry.chain) == 2 and len(events[("13:02:00", "ListSecrets")].chain) == 2
    # an administrator's session of the same existing role is not the attacker's
    assert all(s.event.user_identity.session_name != "alice" for s in out.scope.events)
    assert {s.confidence.value for s in out.scope.events} == {"strong"}
    assert [(u.account, u.role_arns) for u in out.scope.coverage.unlogged_accounts] == [
        ("444455556666", ["arn:aws:iam::444455556666:role/prod-deploy"])]


def test_scenario_03_weak_seeds_give_weak_taint_that_outlives_the_window(fixtures):
    out = scope_for(fixtures, "03_instance_role")
    followed = [s for s in out.scope.events if s.origin == "propagated"]
    assert [(s.event.event_name, s.via.split(":")[0]) for s in followed if s.via] == [
        ("ListBuckets", "instance_id"), ("ListSecrets", "instance_id"), ("GetSecretValue", "instance_id"),
        ("ConsoleLogin", "principal_id"), ("ListUsers", "principal_id")]
    assert {s.confidence.value for s in out.scope.events} == {"weak"}
    assert max(s.event.event_time for s in followed) > "2026-10-20T15:30:00Z"  # after the window end
    # CI's instance, launched with the same profile, is not followed
    assert all("i-0f9e8d7c6b5a40312" not in (s.event.user_identity.principal_id or "") for s in out.scope.events)
    assert out.scope.coverage.period_start == "2026-10-20T15:00:00Z"


def test_scenario_04_coverage_finds_the_stopped_trail_and_the_silence_after_it(fixtures):
    out = scope_for(fixtures, "04_log_tampering")
    cov = out.scope.coverage
    stop = next(s.event.event_id for s in out.scope.events if s.event.event_name == "StopLogging")
    assert [(g.region, g.kind, g.start, g.end, g.minutes, g.possible_cause) for g in cov.gaps] == [
        ("us-east-1", "silence", "2026-10-20T14:33:00Z", "2026-10-20T16:40:00Z", 127, stop)]
    # us-west-2 was just as silent, but it is a quiet stream, so the silence is not evidence of anything
    assert {s.region: s.typical_interval_s for s in cov.streams}["us-west-2"] > 10 * 127 * 60 // 10
    assert [(t.event_name, t.in_scope, t.error_code) for t in cov.tampering] == [
        ("UpdateTrail", False, None), ("DeleteDetector", True, "AccessDeniedException"),
        ("StopConfigurationRecorder", True, None), ("StopLogging", True, None)]
    assert cov.data_events == 4 and not any("data events" in n for n in cov.notes)
    assert "2 in-scope call(s) changed logging or detection" in cov.notes


def test_coverage_notes_missing_data_events(fixtures):
    notes = scope_for(fixtures, "01_leaked_key").scope.coverage.notes
    assert any(n.startswith("no data events") for n in notes)


def test_scenario_06_follows_lambda_functions_the_attacker_created_or_changed(fixtures):
    out = scope_for(fixtures, "06_lambda")
    followed = [(s.event.event_time[11:16], s.event.user_identity.session_name, s.via) for s in out.scope.events if s.origin == "propagated"]
    assert followed == [("11:05", "exfil-fn", "function_name:exfil-fn"), ("11:10", "billing-report", "function_name:billing-report")]
    assert [(i.rule, i.value) for i in out.scope.taint.identities] == [
        ("lambda:CreateFunction", "exfil-fn"), ("lambda:UpdateFunctionCode", "billing-report")]  # the version suffix is dropped
    # billing-report ran before the change and other-fn shares the role: neither is the attacker's
    assert all(s.event.event_time > "2026-10-20T10:59" and s.event.user_identity.session_name != "other-fn" for s in out.scope.events)


def test_scenario_05_weak_indicators_need_the_window_and_report_near_misses(fixtures):
    out = scope_for(fixtures, "05_weak_ioc")
    assert names(out) == ["ListUsers", "CreateAccessKey", "DescribeSecurityGroups"]
    assert {s.confidence.value for s in out.scope.events} == {"weak"}
    nm = out.scope.near_miss_summary
    assert (nm.total, nm.by_reason) == (3, {"expression": 2, "window": 1})
    assert nm.by_indicator == {"curl": 1, "nat": 3}  # the after-window event matched both weak indicators
    reasons = {(n.event_time[:10], n.principal.rsplit("/", 1)[-1], n.reason) for n in out.scope.near_misses}
    assert reasons == {("2026-10-19", "alice", "expression"), ("2026-10-20", "alice", "expression"), ("2026-10-21", "mallory-temp", "window")}
    assert out.scope.summary.failed_calls == 1


def test_scenario_05_without_a_window_is_refused(fixtures):
    root = fixtures / "05_weak_ioc"
    parts = load_iocs_file(root / "iocs.yaml")
    parts.window = None
    with pytest.raises(ValueError, match="needs a time window"):
        build_scope([root / "logs"], assemble([parts]), OPTS)


def test_flags_and_file_give_the_same_scope(fixtures):
    root = fixtures / "01_leaked_key"
    from_file = scope_for(fixtures, "01_leaked_key")
    spec = assemble([SpecParts(from_flags(access_keys=["AKIAIOSFODNN7LEAKED"], ips=["198.51.100.77"]))],
                    expression="access_key_1 AND ip_1")
    from_cli = build_scope([root / "logs"], spec, OPTS)
    assert [s.event.event_id for s in from_cli.scope.events] == [s.event.event_id for s in from_file.scope.events]
    assert from_cli.scope.inputs == from_file.scope.inputs


def test_embed_raw_adds_the_original_record(fixtures):
    plain = scope_for(fixtures, "01_leaked_key")
    raw = scope_for(fixtures, "01_leaked_key", options=ScopeOptions(workers=1, embed_raw=True))
    assert all(s.event.raw is None for s in plain.scope.events)
    assert all(s.event.raw and s.event.raw["eventID"] == s.event.event_id for s in raw.scope.events)


def test_the_scope_is_sealed_and_references_its_inputs_manifest(fixtures):
    out = scope_for(fixtures, "01_leaked_key")
    assert canonical.is_sealed(out.scope_document, "scope_sha256")
    assert out.scope.inputs.manifest_sha256 == out.inputs_document["manifest_sha256"]
    assert all(not f["path"].startswith("/") for f in out.inputs_document["files"])


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_goldens(fixtures, golden, scenario):
    out = scope_for(fixtures, scenario)
    golden(fixtures / scenario / "expected" / "scope.json", out.scope_bytes)
    golden(fixtures / scenario / "expected" / "scope.inputs.json", out.inputs_bytes)
