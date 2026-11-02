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
