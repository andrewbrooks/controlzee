"""Real CloudTrail from Stratus Red Team techniques run in a sandbox account (identifiers replaced, see docs/validation.md).

The synthetic scenarios show the rules work on the shapes we expected; these show they hold on what AWS really wrote.
"""
from pathlib import Path

import pytest

from controlzee.model.plan import Plan
from controlzee.model.timeline import Timeline
from controlzee.plan import build_plan
from controlzee.scope import ScopeOptions, build_scope
from controlzee.seed.spec import assemble, load_iocs_file
from controlzee.timeline import build_timeline

CAPTURED = Path(__file__).resolve().parents[1] / "captured"


def load(name):
    root = CAPTURED / name
    scope = build_scope([root / "logs"], assemble([load_iocs_file(root / "iocs.yaml")]), ScopeOptions(workers=1)).scope
    return scope, Plan.model_validate(build_plan(scope)), Timeline.model_validate(build_timeline(scope))


def tactics(timeline):
    return {e.action: e.tactic for e in timeline.entries if getattr(e, "action", None)}


@pytest.mark.parametrize("name,event", [
    ("iam-backdoor-role", "UpdateAssumeRolePolicy"), ("iam-backdoor-user", "CreateAccessKey"), ("iam-create-backdoor-role", "CreateRole"),
    ("lambda-overwrite-code", "UpdateFunctionCode20150331v2"), ("sts-federation-token", "GetFederationToken"),
    ("secretsmanager-retrieve-secrets", "GetSecretValue"), ("ssm-retrieve-securestring-parameters", "GetParameters")])
def test_the_techniques_detonation_is_in_scope(name, event):
    scope, _, _ = load(name)
    assert event in {s.event.event_name for s in scope.events}


def test_removing_identities_credentials_and_permissions_has_a_tactic():
    _, _, tl = load("iam-create-backdoor-role")
    t = tactics(tl)
    assert t["iam:DeleteRole"] == "impact" and t["iam:DetachRolePolicy"] == "impact"
    _, _, tl = load("secretsmanager-retrieve-secrets")
    assert tactics(tl)["secretsmanager:DeleteSecret"] == "impact" and tactics(tl)["secretsmanager:PutSecretValue"] == "impact"
    _, _, tl = load("ssm-retrieve-securestring-parameters")
    assert tactics(tl)["ssm:PutParameter"] == "impact"


def test_a_service_assuming_the_attackers_role_is_not_lateral_movement():
    scope, _, tl = load("lambda-overwrite-code")
    service_assumes = [s for s in scope.events if s.event.event_name == "AssumeRole" and s.event.user_identity.type == "AWSService"]
    assert service_assumes
    assert tactics(tl)["sts:AssumeRole"] == "execution" and "lateral-movement" not in {t.tactic for t in tl.tactics}


def test_reading_many_secrets_is_one_plan_step():
    scope, plan, _ = load("secretsmanager-retrieve-secrets")
    steps = [a for a in plan.actions if "secrets the attacker read" in a.title]
    assert len(steps) == 1 and steps[0].title == "Rotate the 20 secrets the attacker read"
    assert len(steps[0].commands) == 20 and steps[0].target.startswith("20 secrets: ")
    assert not [a for a in plan.actions if a.title == "Rotate a secret the attacker read"]


def test_reading_many_parameters_is_one_plan_step():
    _, plan, _ = load("ssm-retrieve-securestring-parameters")
    steps = [a for a in plan.actions if "parameters the attacker read" in a.title]
    assert len(steps) == 1 and len(steps[0].commands) == int(steps[0].title.split()[2])


def test_the_same_trust_policy_change_made_twice_is_undone_once():
    scope, plan, _ = load("iam-backdoor-role")
    changes = [s for s in scope.events if s.event.event_name == "UpdateAssumeRolePolicy" and s.event.error_code is None]
    assert len(changes) >= 2  # the technique's set-up and its detonation both rewrite the trust policy
    undo = [a for a in plan.actions if a.title == "Undo a permission change" and "UpdateAssumeRolePolicy" in a.why]
    assert len(undo) == 1 and len(undo[0].evidence) == len(changes)


def test_federation_token_credentials_are_followed():
    scope, _, _ = load("sts-federation-token")
    assert any(i.rule == "sts:GetFederationToken" and i.kind == "access_key_id" for i in scope.taint.identities)


def test_the_lambda_function_the_attacker_created_is_followed_and_planned():
    scope, plan, _ = load("lambda-overwrite-code")
    assert any(i.kind == "function_name" for i in scope.taint.identities)
    step = next(a for a in plan.actions if a.title == "Delete a Lambda function the attacker created")
    assert [o.op for o in step.operations] == ["delete_lambda_function"] and step.disruptive


def test_a_bucket_the_attacker_created_is_planned_for_deletion_once():
    scope, plan, _ = load("lambda-overwrite-code")
    created = {s.event.request_parameters["bucketName"] for s in scope.events if s.event.event_name == "CreateBucket" and s.event.error_code is None}
    steps = [a for a in plan.actions if a.title == "Delete a bucket the attacker created"]
    assert len(created) == 1 and len(steps) == 1
    assert [(o.op, o.args["bucket"]) for o in steps[0].operations] == [("delete_bucket", next(iter(created)))] and steps[0].disruptive
    assert "look inside first" in (steps[0].caution or "")


# ---- EC2 techniques: the instance-profile rule on a real instance

def instance_role_events(scope):
    return [s for s in scope.events if s.origin == "propagated" and s.event.user_identity.type == "AssumedRole"
            and (s.event.user_identity.session_name or "").startswith("i-")]


def test_the_instance_the_attacker_launched_is_followed_and_its_role_calls_are_in_scope():
    scope, plan, _ = load("ec2-enumerate-from-instance")
    instances = [i for i in scope.taint.identities if i.kind == "instance_id" and i.rule == "ec2:RunInstances"]
    assert instances and instances[0].events > 0
    calls = {s.event.event_name for s in instance_role_events(scope)}
    assert {"GetCallerIdentity", "ListBuckets", "ListUsers", "GetAccountAuthorizationDetails"} <= calls  # what the instance did on its own
    assert {"terminate_instance", "stop_instance", "disassociate_instance_profile", "snapshot_instance"} <= {o.op for a in plan.actions for o in a.operations}


def test_credentials_stolen_from_the_instance_are_followed_when_used_elsewhere():
    scope, _, _ = load("ec2-steal-instance-credentials")
    used = [s for s in instance_role_events(scope) if s.event.event_name == "DescribeInstances"]
    assert used  # called with the role's credentials by whoever took them from the instance


def test_new_user_data_on_an_instance_is_execution_and_stopping_it_is_impact():
    scope, plan, tl = load("ec2-user-data")
    user_data = [s for s in scope.events if s.event.event_name == "ModifyInstanceAttribute" and "userData" in (s.event.request_parameters or {})]
    assert user_data
    by_event = {e.event_id: e.tactic for e in tl.entries if getattr(e, "event_id", None)}
    assert {by_event[s.event.event_id] for s in user_data} == {"execution"}
    assert tactics(tl)["ec2:StopInstances"] == "impact"
    assert any(o.op == "terminate_instance" for a in plan.actions for o in a.operations)


def test_credentials_stolen_from_an_instance_are_flagged_in_the_exposure_the_report_and_the_plan():
    scope, plan, tl = load("ec2-steal-instance-credentials")
    assert len(tl.exposure.instance_role_use) == 1
    use = tl.exposure.instance_role_use[0]
    assert use.instance.startswith("i-") and len(use.addresses) == 2
    assert any("more than one address" in n for n in tl.exposure.notes)
    step = next(a for a in plan.actions if a.title == "Find out how an instance's role credentials got out")
    assert step.phase == "investigate" and not step.operations and use.instance in step.target
    assert any("--http-tokens required" in c for c in step.commands)
    from controlzee.report import build_report
    assert "Instance role credentials used from more than one address" in build_report(scope).decode()


def test_an_instance_acting_on_its_own_is_not_flagged():
    _, plan, tl = load("ec2-enumerate-from-instance")
    assert tl.exposure.instance_role_use == []
    assert not any(a.title.startswith("Find out how an instance's role credentials") for a in plan.actions)
