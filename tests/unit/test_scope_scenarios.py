"""End to end over the committed fixtures: assertions on meaning first, then byte-for-byte goldens."""
import pytest

from controlzee import canonical
from controlzee.scope import ScopeOptions, build_scope
from controlzee.seed.spec import SpecParts, assemble, from_flags, load_iocs_file

OPTS = ScopeOptions(workers=1)


def scope_for(fixtures, scenario, iocs="iocs.yaml", options=OPTS):
    root = fixtures / scenario
    spec = assemble([load_iocs_file(root / iocs)])
    return build_scope([root / "logs"], spec, options)


def names(out):
    return [s.event.event_name for s in out.scope.events]


def test_scenario_01_and_expression_isolates_the_attackers_calls(fixtures):
    out = scope_for(fixtures, "01_leaked_key")
    assert names(out) == ["GetCallerIdentity", "ListUsers", "ListRoles", "ListBuckets", "DescribeInstances",
                          "GetAccountAuthorizationDetails", "CreateUser", "AttachUserPolicy", "CreateAccessKey"]
    assert {s.confidence.value for s in out.scope.events} == {"strong"}
    assert {s.event.source_ip for s in out.scope.events} == {"198.51.100.77"}
    s = out.scope.summary
    assert (s.events_in_scope, s.failed_calls, s.by_confidence) == (9, 1, {"strong": 9, "weak": 0})
    assert s.first_event_time == "2026-10-20T14:30:00Z" and s.last_event_time == "2026-10-20T14:32:20Z"
    assert out.scope.seeds.expression == "leaked_key AND attacker_ip"
    assert out.scope.inputs.error_files == 0 and out.scope.inputs.accounts == ["111122223333"]
    assert out.scope.near_miss_summary.total == 0


def test_scenario_01_key_alone_also_catches_the_owners_own_use(fixtures):
    out = scope_for(fixtures, "01_leaked_key", "iocs_key_only.yaml")
    assert len(out.scope.events) == 11
    assert {s.event.source_ip for s in out.scope.events} == {"198.51.100.77", "203.0.113.10"}


def test_scenario_01_backdoor_key_activity_is_not_a_seed_yet(fixtures):
    # taint propagation (milestone 2) is what follows CreateAccessKey to the new key; scoping alone must not
    out = scope_for(fixtures, "01_leaked_key")
    assert all(s.event.user_identity.access_key_id != "AKIAIOSFODNN7BKDOOR" for s in out.scope.events)
    assert all(s.origin == "seed" and s.chain == [] for s in out.scope.events)


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


@pytest.mark.parametrize("scenario", ["01_leaked_key", "05_weak_ioc"])
def test_goldens(fixtures, golden, scenario):
    out = scope_for(fixtures, scenario)
    golden(fixtures / scenario / "expected" / "scope.json", out.scope_bytes)
    golden(fixtures / scenario / "expected" / "scope.inputs.json", out.inputs_bytes)
