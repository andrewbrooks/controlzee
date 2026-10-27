"""timeline, plan and report: built from a scope alone, deterministic, and safe with hostile log content."""
import json
import re
import shlex

import orjson
import pytest

from controlzee import canonical
from controlzee.artifacts import ArtifactError, load_scope
from controlzee.classify import access, action, resources, tactic
from controlzee.model.event import Event, SourceRef, UserIdentity
from controlzee.model.plan import Plan
from controlzee.model.timeline import Timeline
from controlzee.plan import build_plan
from controlzee.report import build_report, md
from controlzee.scope import ScopeOptions, build_scope
from controlzee.seed.spec import SpecParts, assemble, from_flags, load_iocs_file
from controlzee.timeline import build_timeline
from tests.builders.build_fixtures import SCENARIOS
from tests.builders.cloudtrail import HIDDEN, LogSet, at, iam_user


def scope_of(fixtures, scenario):
    root = fixtures / scenario
    return build_scope([root / "logs"], assemble([load_iocs_file(root / "iocs.yaml")]), ScopeOptions(workers=1)).scope


def timeline_of(scope):
    return Timeline.model_validate(build_timeline(scope))


def plan_of(scope):
    return Plan.model_validate(build_plan(scope))


def ev(source, name, *, read_only=None, request=None, response=None, error=None):
    return Event(event_id="e", event_time="2026-10-20T12:00:00Z", event_source=source, event_name=name, aws_region="us-east-1",
                 recipient_account_id="111122223333", read_only=read_only, user_identity=UserIdentity(), request_parameters=request,
                 response_elements=response, error_code=error, source=SourceRef(input="x.json", record=0))


# ---- classification

@pytest.mark.parametrize("source,name,read_only,expected", [
    ("iam.amazonaws.com", "CreateAccessKey", False, "persistence"), ("iam.amazonaws.com", "AttachUserPolicy", False, "privilege-escalation"),
    ("cloudtrail.amazonaws.com", "StopLogging", False, "defense-evasion"), ("sts.amazonaws.com", "AssumeRole", True, "lateral-movement"),
    ("secretsmanager.amazonaws.com", "GetSecretValue", True, "credential-access"), ("s3.amazonaws.com", "ListBuckets", True, "discovery"),
    ("lambda.amazonaws.com", "CreateFunction20150331", False, "persistence"), ("ec2.amazonaws.com", "TerminateInstances", False, "impact"),
    ("s3.amazonaws.com", "PutBucketPolicy", False, "exfiltration"), ("ec2.amazonaws.com", "CreateTags", False, "other"),
    ("ec2.amazonaws.com", "DescribeVpcs", None, "discovery"),
])
def test_tactics(source, name, read_only, expected):
    assert tactic(ev(source, name, read_only=read_only)) == expected


def test_actions_access_and_resources():
    lam = ev("lambda.amazonaws.com", "UpdateFunctionCode20150331v2", request={"functionName": "f"})
    assert action(lam) == "lambda:UpdateFunctionCode" and resources(lam) == [("function", "f")] and access(lam) == "write"
    obj = ev("s3.amazonaws.com", "GetObject", read_only=True, request={"bucketName": "b", "key": "k/1"})
    assert resources(obj) == [("object", "b/k/1")] and access(obj) == "read"
    run = ev("ec2.amazonaws.com", "RunInstances", response={"instancesSet": {"items": [{"instanceId": "i-1"}, "junk"]}})
    assert resources(run) == [("instance", "i-1")]
    assert resources(ev("ec2.amazonaws.com", "RunInstances", response={"instancesSet": ["odd"]})) == []
    assert access(ev("iam.amazonaws.com", "DeleteUser", request={"userName": "u"})) == "delete"
    assert access(ev("sts.amazonaws.com", "AssumeRole", request={"roleArn": "arn:aws:iam::1:role/r"})) == "assume"
    # a parameter the table does not know is not a resource, whatever it is called
    assert resources(ev("iam.amazonaws.com", "CreateUser", request={"bucketName": "not-iam"})) == []


# ---- the scenarios

def test_scenario_01_timeline_and_plan(fixtures):
    scope = scope_of(fixtures, "01_leaked_key")
    tl = timeline_of(scope)
    assert [a.label for a in tl.actors] == ["user/ci-deploy", "user/backdoor-svc"]
    assert tl.exposure.admin_granted and tl.exposure.privilege_changes[0].policy == "arn:aws:iam::aws:policy/AdministratorAccess"
    assert [t.tactic for t in tl.tactics] == ["persistence", "privilege-escalation", "discovery"]
    plan = plan_of(scope)
    assert [(a.phase, a.title) for a in plan.actions] == [
        ("contain", "Deactivate an access key the attacker used"), ("contain", "Deactivate an access key the attacker used"),
        ("investigate", "Look for object-level access elsewhere"), ("eradicate", "Delete a user the attacker created"),
        ("recover", "Give the key's owner a new key, then delete the old one")]
    delete = plan.actions[3]
    assert [(o.op, o.args) for o in delete.operations] == [("delete_user", {"user": "backdoor-svc"})] and delete.disruptive
    assert delete.commands[-1] == "aws iam delete-user --user-name backdoor-svc"
    assert [a.operations == [] for a in plan.actions] == [False, False, True, False, True]  # investigate and the new key are manual


def test_scenario_02_plan_reaches_into_the_unlogged_account(fixtures):
    plan = plan_of(scope_of(fixtures, "02_role_chain"))
    reach = next(a for a in plan.actions if a.title == "Get the logs of an account the attacker reached")
    assert reach.target == "account 444455556666" and "--access-key ASIAIOSFODNN7PRODMT" in reach.commands[0]
    assert {a.target for a in plan.actions if a.title == "Revoke the role's active sessions"} == {
        "role ops-admin (account 111122223333)", "role support-audit (account 111122223333)"}


def test_scenario_03_everything_is_weak_and_the_secret_is_rotated(fixtures):
    scope = scope_of(fixtures, "03_instance_role")
    plan = plan_of(scope)
    assert {a.confidence.value for a in plan.actions if a.evidence} == {"weak"}
    assert any("confirm them before acting" in n for n in plan.notes)
    assert "aws secretsmanager rotate-secret --region us-east-1 --secret-id prod/db" in [c for a in plan.actions for c in a.commands]
    assert timeline_of(scope).exposure.credentials_read == ["secret prod/db"]


def test_scenario_04_gap_sits_in_the_timeline_and_logging_is_restored(fixtures):
    scope = scope_of(fixtures, "04_log_tampering")
    tl = timeline_of(scope)
    gap = next(e for e in tl.entries if e.kind == "gap")
    stop = next(e for e in tl.entries if e.action == "cloudtrail:StopLogging")
    assert tl.entries.index(gap) == tl.entries.index(stop) + 1 and "cloudtrail:StopLogging" in (gap.note or "")
    titles = [a.title for a in plan_of(scope).actions]
    assert "Turn the trail back on" in titles and "Restart AWS Config recording" in titles
    assert "Re-enable GuardDuty" not in titles  # the attempt was refused


def test_scenario_06_plan_has_manual_steps_for_the_functions_and_classifies_identity_center(fixtures):
    plan = plan_of(scope_of(fixtures, "06_lambda"))
    steps = {a.title: a for a in plan.actions if "Lambda function" in a.title}
    created = steps["Delete a Lambda function the attacker created"]
    assert created.target == "function exfil-fn (us-east-1)" and not created.operations
    assert created.commands[-1] == "aws lambda delete-function --region us-east-1 --function-name exfil-fn"
    changed = steps["Review a Lambda function the attacker changed"]
    assert changed.target == "function billing-report (us-east-1)" and "redeploy" in (changed.caution or "")
    for service, name, expected in (("sso", "CreateAccountAssignment", "persistence"), ("identitystore", "CreateUser", "persistence"),
                                    ("sso", "PutInlinePolicyToPermissionSet", "privilege-escalation")):
        assert tactic(ev(f"{service}.amazonaws.com", name, read_only=False)) == expected


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_derived_goldens(fixtures, golden, scenario):
    scope = scope_of(fixtures, scenario)
    expected = fixtures / scenario / "expected"
    golden(expected / "timeline.json", canonical.dumps(build_timeline(scope)))
    golden(expected / "plan.json", canonical.dumps(build_plan(scope)))
    golden(expected / "report.md", build_report(scope))


def test_derived_documents_are_sealed_and_cite_the_scope(fixtures):
    scope = scope_of(fixtures, "01_leaked_key")
    for doc, field in ((build_timeline(scope), "timeline_sha256"), (build_plan(scope), "plan_sha256")):
        assert canonical.is_sealed(doc, field) and doc["scope_sha256"] == scope.scope_sha256


# ---- hostile log content

EVIL = "x|y`z<img src=x onerror=alert(1)>](http://evil.example)$(rm -rf ~)"


def test_hostile_values_cannot_break_out_of_the_report_or_the_commands(tmp_path):
    logs = LogSet()
    attacker = iam_user("ci", "AKIAIOSFODNN7HOSTIL")
    t = at("2026-10-20T12:00:00Z")
    logs.add(t, "iam.amazonaws.com", "CreateUser", attacker, ua=EVIL, request={"userName": EVIL},
             response={"user": {"userName": EVIL, "userId": "AIDAHOSTILE00000001"}})
    logs.add(t, "iam.amazonaws.com", "CreateAccessKey", attacker, request={"userName": EVIL},
             response={"accessKey": {"userName": EVIL, "accessKeyId": "AKIAIOSFODNN7HOSTL2", "secretAccessKey": HIDDEN}})
    logs.add(t, "secretsmanager.amazonaws.com", "GetSecretValue", attacker, request={"secretId": "ok/name"}, region=EVIL)
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "x.json").write_bytes(orjson.dumps({"Records": logs.records}))  # one flat file: the region is not a path
    scope = build_scope([tmp_path / "logs"], assemble([SpecParts(from_flags(access_keys=["AKIAIOSFODNN7HOSTIL"]))]),
                        ScopeOptions(workers=1)).scope
    report = build_report(scope).decode()
    # markup only ever appears escaped: no tag, no link, no command substitution, no autolink
    for raw in (r"(?<!\\)<img", r"(?<!\\)\]\(", r"(?<!\\)\$\(", r"http://"):
        assert not re.search(raw, report), raw
    rows = [ln for ln in report.split("## Timeline")[1].split("##")[0].splitlines() if ln.startswith("| 2026")]
    assert all(len(re.split(r"(?<!\\)\|", r)) == 9 for r in rows)
    # the odd user name never reaches a command: those steps become manual
    plan = plan_of(scope)
    commands = [c for a in plan.actions for c in a.commands]
    assert commands and all("rm -rf" not in c and "<img" not in c for c in commands)
    manual = [a for a in plan.actions if a.target.startswith(("user x|", "access key AKIAIOSFODNN7HOSTL2"))]
    assert manual and all(not a.commands and "does not have the expected form" in (a.caution or "") for a in manual)
    # and an odd region likewise
    assert all(not a.commands for a in plan.actions if a.title == "Rotate a secret the attacker read")
    for c in commands:
        shlex.split(c)  # every command is well-formed shell


def test_md_escapes_markup():
    assert md("a|b") == r"a\|b" and md("[x](y)") == r"\[x\]\(y\)" and md("http://e") == r"http:\/\/e"
    assert md("line\nbreak") == "line�break"


# ---- loading a scope

def _write(path, doc):
    path.write_bytes(canonical.dumps(doc))
    return path


def test_load_scope_refuses_edited_foreign_and_broken_files(fixtures, tmp_path):
    good = json.loads((fixtures / "01_leaked_key/expected/scope.json").read_text())
    assert load_scope(_write(tmp_path / "ok.json", good)).scope_sha256 == good["scope_sha256"]
    edited = {**good, "summary": {**good["summary"], "events_in_scope": 1}}
    with pytest.raises(ArtifactError, match="changed after it was written"):
        load_scope(_write(tmp_path / "edited.json", edited))
    with pytest.raises(ArtifactError, match="schema version"):
        load_scope(_write(tmp_path / "old.json", canonical.seal({**good, "schema_version": "0.1"}, "scope_sha256")))
    (tmp_path / "bad.json").write_text("{")
    with pytest.raises(ArtifactError, match="not valid JSON"):
        load_scope(tmp_path / "bad.json")
    with pytest.raises(ArtifactError, match="not a scope.json"):
        load_scope(_write(tmp_path / "other.json", {"x": 1}))
    with pytest.raises(ArtifactError, match="cannot read"):
        load_scope(tmp_path / "absent.json")



@pytest.mark.parametrize("attach_first", [True, False])
def test_calls_in_the_same_second_list_what_they_create_first(tmp_path, attach_first):
    # seen on a real account: CreateUser and AttachUserPolicy in one second, the attach listed first. Both insertion
    # orders are tried, so one of them gives the attach the smaller event id.
    logs = LogSet()
    key = iam_user("ci", "AKIAIOSFODNN7SAMESC")
    t = at("2026-10-20T12:00:00Z")
    calls = [("AttachUserPolicy", {"userName": "u", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}, None),
             ("CreateUser", {"userName": "u"}, {"user": {"userName": "u", "userId": "AIDASAMESECOND00001"}})]
    for name, req, resp in calls if attach_first else calls[::-1]:
        logs.add(t, "iam.amazonaws.com", name, key, request=req, response=resp)
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "x.json").write_bytes(orjson.dumps({"Records": logs.records}))
    scope = build_scope([tmp_path / "logs"], assemble([SpecParts(from_flags(access_keys=["AKIAIOSFODNN7SAMESC"]))]),
                        ScopeOptions(workers=1)).scope
    assert [e.action for e in timeline_of(scope).entries] == ["iam:CreateUser", "iam:AttachUserPolicy"]
