"""controlzee respond: the dry run checks and changes nothing; execute does exactly what was approved, or refuses."""
import json
from datetime import UTC, datetime, timedelta

import pytest
from typer.testing import CliRunner

from controlzee import canonical
from controlzee.cli import app
from controlzee.model.respond import DryRun, ResponseRecord
from controlzee.respond.run import RespondError, dry_run, execute
from controlzee.scope import ScopeOptions, build_scope
from controlzee.seed.spec import assemble, load_iocs_file
from tests.fake_aws import Account, Role, User

ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
T0 = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
runner = CliRunner(env={"COLUMNS": "400"})


def scope_of(fixtures, scenario):
    root = fixtures / scenario
    return build_scope([root / "logs"], assemble([load_iocs_file(root / "iocs.yaml")]), ScopeOptions(workers=1)).scope


def account_01():
    return Account(users={"ci-deploy": User(keys={"AKIAIOSFODNN7LEAKED": "Active"}),
                          "backdoor-svc": User(keys={"AKIAIOSFODNN7BKDOOR": "Active"}, attached={ADMIN})})


def check(scope, acct, monkeypatch, **kw):
    acct.install(monkeypatch)
    return DryRun.model_validate(dry_run(scope, profile=None, home_region="us-east-1", clock=lambda: T0, **kw))


def run(doc, approve=None, at=T0 + timedelta(minutes=5)):
    return ResponseRecord.model_validate(execute(doc, approve=approve or doc["dryrun_sha256"][:16], profile=None,
                                                 max_age=timedelta(hours=1), clock=lambda: at))


# ---- dry run

def test_dry_run_reads_checks_and_changes_nothing(fixtures, monkeypatch):
    acct = account_01()
    dr = check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch)
    assert dr.passed and dr.caller.principal_arn == "arn:aws:iam::111122223333:role/IncidentResponder"
    assert [(s.action_id, s.op, s.state) for s in dr.steps] == [
        ("A01", "deactivate_access_key", "key AKIAIOSFODNN7BKDOOR is Active"),
        ("A02", "deactivate_access_key", "key AKIAIOSFODNN7LEAKED is Active"),
        ("A04", "detach_user_policy", "arn:aws:iam::aws:policy/AdministratorAccess is attached to user backdoor-svc")]
    assert [c.action for c in dr.steps[0].checks] == ["iam:UpdateAccessKey"]
    assert {n.action_id: n.reason.split(":")[0].split(" (")[0] for n in dr.not_selected} == {
        "A03": "a manual step", "A05": "disruptive", "A06": "a manual step"}
    assert acct.calls == []  # nothing but reads


def test_a_missing_permission_fails_the_dry_run(fixtures, monkeypatch):
    acct = account_01()
    acct.denied = {"iam:UpdateAccessKey"}
    dr = check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch)
    assert not dr.passed and [s.ok for s in dr.steps] == [False, False, True]
    assert "not permitted: iam:UpdateAccessKey on arn:aws:iam::111122223333:user/backdoor-svc (implicitDeny)" in dr.problems[0]
    with pytest.raises(RespondError, match="did not pass"):
        run(dr.model_dump(mode="json"))


def test_without_the_simulator_nothing_can_be_checked(fixtures, monkeypatch):
    acct = account_01()
    acct.denied = {"iam:SimulatePrincipalPolicy"}
    with pytest.raises(RespondError, match="needs iam:SimulatePrincipalPolicy"):
        check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch)


def test_root_credentials_are_refused(fixtures, monkeypatch):
    acct = account_01()
    acct.caller_arn = "arn:aws:iam::111122223333:root"
    with pytest.raises(RespondError, match="root credentials"):
        check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch)


def test_steps_choose_and_must_be_runnable(fixtures, monkeypatch):
    scope = scope_of(fixtures, "01_leaked_key")
    dr = check(scope, account_01(), monkeypatch, chosen={"A02"})
    assert [s.action_id for s in dr.steps] == ["A02"] and dr.passed
    dr = check(scope, account_01(), monkeypatch, chosen={"A03", "A05", "A99"})
    assert not dr.passed and [p.split(" ")[0] for p in dr.problems] == ["--steps", "A03", "A05"]


# ---- execute

def test_execute_makes_the_approved_changes(fixtures, monkeypatch):
    acct = account_01()
    dr = check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch)
    rec = run(dr.model_dump(mode="json"))
    assert rec.completed and [s.result for s in rec.steps] == ["done", "done", "done"]
    assert acct.users["ci-deploy"].keys == {"AKIAIOSFODNN7LEAKED": "Inactive"}
    assert acct.users["backdoor-svc"].keys == {"AKIAIOSFODNN7BKDOOR": "Inactive"}
    assert [(svc, m) for svc, m, _ in acct.calls] == [("iam", "update_access_key"), ("iam", "update_access_key"), ("iam", "detach_user_policy")]
    # run again: everything is already in place, and nothing is written
    acct.calls.clear()
    again = run(check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch).model_dump(mode="json"))
    assert [s.result for s in again.steps] == ["already done"] * 3 and acct.calls == []


def test_disruptive_steps_need_the_flag_and_delete_everything(fixtures, monkeypatch):
    acct = account_01()
    acct.users["backdoor-svc"].login = True
    acct.users["backdoor-svc"].groups = {"admins"}
    dr = check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch, allow_disruptive=True)
    assert [s.op for s in dr.steps] == ["deactivate_access_key", "deactivate_access_key", "detach_user_policy", "delete_user"]
    assert {c.action for c in dr.steps[3].checks} == {"iam:DeleteUser", "iam:DeleteAccessKey", "iam:DeleteLoginProfile",
                                                     "iam:DetachUserPolicy", "iam:RemoveUserFromGroup"}
    assert run(dr.model_dump(mode="json")).completed and "backdoor-svc" not in acct.users


@pytest.mark.parametrize("change,message", [
    (lambda d: d.update(approve="0" * 16), "does not match"),
    (lambda d: d["doc"].update(caller={**d["doc"]["caller"], "account": "999999999999"}), "changed after it was written"),
    (lambda d: d.update(at=T0 + timedelta(hours=2)), "older than 60 minutes"),
    (lambda d: d.update(approve="abc"), "does not match"),
])
def test_execute_refuses_what_was_not_approved(fixtures, monkeypatch, change, message):
    doc = check(scope_of(fixtures, "01_leaked_key"), account_01(), monkeypatch).model_dump(mode="json")
    d = {"doc": doc, "approve": None, "at": T0 + timedelta(minutes=5)}
    change(d)
    with pytest.raises(RespondError, match=message):
        run(d["doc"], d["approve"], d["at"])


def test_execute_refuses_other_credentials(fixtures, monkeypatch):
    acct = account_01()
    doc = check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch).model_dump(mode="json")
    acct.caller_arn = "arn:aws:sts::111122223333:assumed-role/SomeoneElse/bob"
    acct.roles["SomeoneElse"] = Role()
    with pytest.raises(RespondError, match="the dry run was checked for"):
        run(doc)
    assert acct.calls == []


def test_execute_stops_at_the_first_failure(fixtures, monkeypatch):
    acct = account_01()
    doc = check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch).model_dump(mode="json")
    from tests import fake_aws

    def refuse(self, op, **kw):  # AWS refuses the first change, whatever the simulator said
        raise fake_aws._err("AccessDenied", op)
    monkeypatch.setattr(fake_aws.FakeClient, "_iam_update_access_key", refuse)
    rec = run(doc)
    assert not rec.completed and [s.result for s in rec.steps] == ["failed", "not run", "not run"]
    assert rec.steps[0].detail.startswith("AccessDenied")


def test_recover_and_contain_operations_of_other_scenarios(fixtures, monkeypatch):
    acct = Account(users={"ci-deploy": User(keys={"AKIAIOSFODNN7LEAKED": "Active"})},
                   trails={"arn:aws:cloudtrail:us-east-1:111122223333:trail/org-trail": False}, recorders={"default": False})
    dr = check(scope_of(fixtures, "04_log_tampering"), acct, monkeypatch)
    assert dr.passed and [s.op for s in dr.steps] == ["deactivate_access_key", "start_config_recorder", "start_logging"]
    assert run(dr.model_dump(mode="json")).completed
    assert acct.recorders == {"default": True} and all(acct.trails.values())

    acct3 = Account(users={"dev-sam": User(keys={"AKIAIOSFODNN7DEVSAM": "Active"}), "svc-metrics": User(login=True)},
                    roles={"IncidentResponder": Role(), "app-role": Role()},
                    instances={"i-0a1b2c3d4e5f60718": {"state": "running", "assoc": ["iip-assoc-1"], "volumes": ["vol-0abc"]}})
    dr3 = check(scope_of(fixtures, "03_instance_role"), acct3, monkeypatch)
    assert dr3.passed and "stop_instance" not in [s.op for s in dr3.steps]  # disruptive
    assert run(dr3.model_dump(mode="json")).completed
    assert acct3.instances["i-0a1b2c3d4e5f60718"]["assoc"] == [] and acct3.instances["i-0a1b2c3d4e5f60718"]["state"] == "running"
    assert not acct3.users["svc-metrics"].login and "controlzee-revoke-older-sessions" in acct3.roles["app-role"].inline


# ---- the command line

def cli(*args):
    return runner.invoke(app, [str(a) for a in args])


def test_cli_dry_run_then_execute(fixtures, monkeypatch, tmp_path):
    account_01().install(monkeypatch)
    scope = fixtures / "01_leaked_key/expected/scope.json"
    r = cli("respond", "dry-run", scope, "-o", tmp_path / "dryrun.json")
    assert r.exit_code == 0, r.output
    assert "A01 [ok] deactivate access key AKIAIOSFODNN7BKDOOR of user backdoor-svc" in r.stdout
    assert "allowed iam:UpdateAccessKey on arn:aws:iam::111122223333:user/backdoor-svc" in r.stdout
    doc = json.loads((tmp_path / "dryrun.json").read_text())
    assert f"--approve {doc['dryrun_sha256'][:16]}" in r.stdout
    r = cli("respond", "execute", tmp_path / "dryrun.json", "-o", tmp_path / "response.json")
    assert r.exit_code == 2 and "--approve is required" in r.output
    r = cli("respond", "execute", tmp_path / "dryrun.json", "--approve", doc["dryrun_sha256"][:16], "-o", tmp_path / "response.json")
    assert r.exit_code == 0, r.output
    assert "Done: 3 change(s) made, 0 already in place" in r.stdout
    assert canonical.is_sealed(json.loads((tmp_path / "response.json").read_text()), "response_sha256")


def test_cli_failed_dry_run_exits_4(fixtures, monkeypatch, tmp_path):
    acct = account_01()
    acct.denied = {"iam:UpdateAccessKey"}
    acct.install(monkeypatch)
    r = cli("respond", "dry-run", fixtures / "01_leaked_key/expected/scope.json", "-o", tmp_path / "d.json")
    assert r.exit_code == 4 and "Dry run FAILED" in r.output and "DENIED  iam:UpdateAccessKey" in r.stdout


@pytest.mark.parametrize("args,message", [
    (["respond", "dry-run", "SCOPE", "--aws-profile", "default; rm -rf ~"], "--aws-profile must be a profile name"),
    (["respond", "dry-run", "SCOPE", "--steps", "A01;A02"], "--steps takes plan step ids"),
    (["respond", "dry-run", "SCOPE", "--steps", "$(id)"], "--steps takes plan step ids"),
    (["respond", "dry-run", "SCOPE", "--region", "us-east-1 --endpoint-url http://evil"], "--region must be an AWS region"),
    (["respond", "execute", "DRYRUN", "--approve", "abc' OR 1=1"], "--approve takes the dry run's sha256"),
    (["respond", "execute", "DRYRUN", "--approve", "abc", "--aws-profile", "../../etc"], "--approve takes"),
    (["scope", "--logs", "s3://Bad_Bucket/x", "--access-key", "AKIAIOSFODNN7LEAKED"], "must name a valid bucket"),
    (["scope", "--logs", "s3://bucket/a\nb", "--access-key", "AKIAIOSFODNN7LEAKED"], "prefix contains characters"),
    (["scope", "--lookup-events", "us-east-1;ls", "--access-key", "AKIAIOSFODNN7LEAKED", "--window", "2026-10-20", "2026-10-21"],
     "--lookup-events must be an AWS region"),
    (["scope", "--logs", "s3://bucket/x", "--aws-profile", "$(whoami)", "--access-key", "AKIAIOSFODNN7LEAKED"], "--aws-profile must be"),
])
def test_arguments_with_the_wrong_form_are_refused_before_anything_runs(fixtures, monkeypatch, tmp_path, args, message):
    acct = account_01()
    acct.install(monkeypatch)
    scope = fixtures / "01_leaked_key/expected/scope.json"
    args = [str(scope) if a == "SCOPE" else str(tmp_path / "missing.json") if a == "DRYRUN" else a for a in args]
    r = cli(*args, "-o", tmp_path / "out.json")
    assert r.exit_code == 2 and message in r.output and "Traceback" not in r.output
    assert acct.calls == [] and not (tmp_path / "out.json").exists()


def test_plan_operations_never_carry_values_of_the_wrong_form(fixtures):
    from controlzee.model.plan import Plan
    from controlzee.plan import build_plan
    from controlzee.respond.ops import validate
    for scenario in ("01_leaked_key", "02_role_chain", "03_instance_role", "04_log_tampering"):
        for a in Plan.model_validate(build_plan(scope_of(fixtures, scenario))).actions:
            for o in a.operations:
                validate(o.op, o.args, o.region)


# ---- not cutting off the responder, and revoking only once

def account_02(caller_role="IncidentResponder"):
    return Account(caller_arn=f"arn:aws:sts::111122223333:assumed-role/{caller_role}/alice",
                   users={"jenkins": User(keys={"AKIAIOSFODNN7LEAKED": "Active"})},
                   roles={"IncidentResponder": Role(), "ops-admin": Role(),
                          "support-audit": Role(attached={"arn:aws:iam::aws:policy/ReadOnlyAccess"})})


def test_a_step_that_would_revoke_the_responder_fails_the_dry_run(fixtures, monkeypatch):
    scope = scope_of(fixtures, "02_role_chain")
    dr = check(scope, account_02("ops-admin"), monkeypatch)
    blocked = [s for s in dr.steps if s.problem and "credentials running this response" in s.problem]
    assert not dr.passed and [(s.op, s.args["role"]) for s in blocked] == [("revoke_role_sessions", "ops-admin")]
    # leaving that step out lets the rest go ahead
    others = {s.action_id for s in dr.steps} - {s.action_id for s in blocked}
    assert check(scope, account_02("ops-admin"), monkeypatch, chosen=others).passed


def test_revoking_twice_changes_nothing_the_second_time(fixtures, monkeypatch):
    acct = account_02()
    scope = scope_of(fixtures, "02_role_chain")
    first = check(scope, acct, monkeypatch)
    assert [s.op for s in first.steps].count("revoke_role_sessions") == 2
    assert run(first.model_dump(mode="json")).completed
    assert acct.documents[("role", "ops-admin", "controlzee-revoke-older-sessions")]["Statement"][0]["Effect"] == "Deny"
    acct.calls.clear()
    second = check(scope, acct, monkeypatch)
    assert all(s.already_done for s in second.steps)
    assert "which covers the attacker's last use at 2026-10-20T10:04:00Z" in next(
        s.state for s in second.steps if s.args.get("role") == "ops-admin")
    assert [s.result for s in run(second.model_dump(mode="json")).steps] == ["already done"] * len(second.steps)
    assert acct.calls == []


def test_a_revocation_that_ends_before_the_attackers_last_use_is_renewed(fixtures, monkeypatch):
    acct = account_02()
    acct.roles["ops-admin"].inline.add("controlzee-revoke-older-sessions")
    acct.documents[("role", "ops-admin", "controlzee-revoke-older-sessions")] = {
        "Statement": [{"Effect": "Deny", "Condition": {"DateLessThan": {"aws:TokenIssueTime": "2026-10-20T10:03:00Z"}}}]}
    step = next(s for s in check(scope_of(fixtures, "02_role_chain"), acct, monkeypatch).steps if s.args.get("role") == "ops-admin")
    assert not step.already_done and "ends at 2026-10-20T10:03:00Z, before the attacker's last use" in step.state


def test_lifting_a_revocation_runs_only_when_named(fixtures, monkeypatch):
    acct = account_02()
    scope = scope_of(fixtures, "02_role_chain")
    dr = check(scope, acct, monkeypatch)
    lifts = [n for n in dr.not_selected if n.title == "Lift the session revocation once the incident is over"]
    assert len(lifts) == 2 and all("only when named with --steps" in n.reason for n in lifts)  # jenkins and ops-admin
    assert run(dr.model_dump(mode="json")).completed
    lift = check(scope, acct, monkeypatch, chosen={lifts[0].action_id, lifts[1].action_id})
    assert lift.passed and {s.op for s in lift.steps} == {"lift_user_revocation", "lift_role_revocation"}
    assert run(lift.model_dump(mode="json")).completed
    assert "controlzee-revoke-older-sessions" not in acct.roles["ops-admin"].inline | acct.users["jenkins"].inline


def test_a_refused_password_check_does_not_block_deleting_a_user(fixtures, monkeypatch):
    # seen in a real sandbox: an SCP denies iam:GetLoginProfile
    from tests import fake_aws

    def refuse(self, op, **kw):
        raise fake_aws._err("AccessDenied", op)
    acct = account_01()
    monkeypatch.setattr(fake_aws.FakeClient, "_iam_get_login_profile", refuse)
    dr = check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch, chosen={"A05"}, allow_disruptive=True)
    assert dr.passed and "iam:GetLoginProfile is refused" in dr.steps[0].state
    assert run(dr.model_dump(mode="json")).completed and "backdoor-svc" not in acct.users
    # if it did have a password that could not be removed, the delete stops with a conflict instead
    acct2 = account_01()
    acct2.users["backdoor-svc"].login = True
    monkeypatch.setattr(fake_aws.FakeClient, "_iam_delete_login_profile", refuse)
    dr2 = check(scope_of(fixtures, "01_leaked_key"), acct2, monkeypatch, chosen={"A05"}, allow_disruptive=True)
    rec = run(dr2.model_dump(mode="json"))
    assert not rec.completed and rec.steps[0].detail.startswith("DeleteConflict") and "backdoor-svc" in acct2.users


# ---- regressions from the line-by-line review

def _resealed(doc):
    return canonical.seal({k: v for k, v in doc.items() if k != "dryrun_sha256"}, "dryrun_sha256")


def test_execute_refuses_a_dry_run_dated_in_the_future(fixtures, monkeypatch):
    doc = check(scope_of(fixtures, "01_leaked_key"), account_01(), monkeypatch).model_dump(mode="json")
    with pytest.raises(RespondError):
        run(doc, at=T0 - timedelta(days=30))


def test_execute_refuses_an_edited_and_resealed_dry_run(fixtures, monkeypatch):
    acct = account_01()
    doc = check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch).model_dump(mode="json")
    extra = {**doc["steps"][0], "action_id": "A99", "op": "delete_user", "args": {"user": "ci-deploy"}, "region": None, "checks": []}
    edited = _resealed({**doc, "steps": [*doc["steps"], extra]})
    with pytest.raises(RespondError):
        run(edited)
    assert "ci-deploy" in acct.users and acct.calls == []


def test_execute_simulates_again_before_each_change(fixtures, monkeypatch):
    acct = account_01()
    doc = check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch).model_dump(mode="json")
    acct.denied = {"iam:UpdateAccessKey"}  # permission lost after the dry run
    rec = run(doc)
    assert not rec.completed and rec.steps[0].result == "failed" and "no longer permitted" in rec.steps[0].detail
    assert acct.calls == []


def test_the_responder_cannot_cut_itself_off():
    from controlzee.model.respond import Caller
    from controlzee.respond.run import cuts_off_caller
    caller = Caller(account="1", arn="arn:aws:sts::1:assumed-role/IncidentResponder/a", principal_arn="arn:aws:iam::1:role/IncidentResponder")
    assert cuts_off_caller("revoke_role_sessions", {"role": "IncidentResponder"}, caller)
    assert cuts_off_caller("revoke_role_sessions", {"role": "Other"}, caller) is None
    user = Caller(account="1", arn="arn:aws:iam::1:user/alice", principal_arn="arn:aws:iam::1:user/alice")
    assert cuts_off_caller("detach_group_policy", {"group": "admins", "policy_arn": "p"}, user, frozenset({"admins"}))
    assert cuts_off_caller("detach_group_policy", {"group": "admins", "policy_arn": "p"}, user, frozenset()) is None


def test_an_unexpected_error_is_recorded_not_raised(fixtures, monkeypatch):
    from tests import fake_aws
    acct = account_01()
    doc = check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch).model_dump(mode="json")
    orig = fake_aws.FakeClient._iam_update_access_key
    n = []

    def boom(self, op, **kw):
        n.append(1)
        if len(n) == 2:
            raise RuntimeError("unexpected response shape")
        return orig(self, op, **kw)
    monkeypatch.setattr(fake_aws.FakeClient, "_iam_update_access_key", boom)
    rec = run(doc)
    assert not rec.completed and [s.result for s in rec.steps][:2] == ["done", "failed"]
    assert "may be partly made" in rec.steps[1].detail


# ---- clock skew and simulator context (items 6 and 7)

def _cutoff(acct):
    return acct.documents[("role", "ops-admin", "controlzee-revoke-older-sessions")]["Statement"][0]["Condition"]["DateLessThan"]["aws:TokenIssueTime"]


def test_a_revocation_cutoff_is_awss_time_not_this_machines(fixtures, monkeypatch):
    acct = account_02()
    acct.skew = timedelta(minutes=-2)  # AWS is 2 minutes behind this machine
    dr = check(scope_of(fixtures, "02_role_chain"), acct, monkeypatch)
    assert dr.passed and any("behind" in w or "ahead" in w for w in dr.warnings)
    before = datetime.now(UTC) + acct.skew
    assert run(dr.model_dump(mode="json")).completed
    cutoff = datetime.strptime(_cutoff(acct), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert before - timedelta(seconds=2) <= cutoff <= datetime.now(UTC) + acct.skew + timedelta(seconds=2)


def test_small_skew_is_quiet_and_a_large_one_stops_revocations_only(fixtures, monkeypatch):
    scope = scope_of(fixtures, "02_role_chain")
    assert check(scope, account_02(), monkeypatch).warnings == []
    acct = account_02()
    acct.skew = timedelta(minutes=10)
    dr = check(scope, acct, monkeypatch)
    assert not dr.passed and any("fix the clock" in p for p in dr.problems)
    # a plan with no revocation in it is only warned
    other = account_01()
    other.skew = timedelta(minutes=10)
    dr = check(scope_of(fixtures, "01_leaked_key"), other, monkeypatch)
    assert dr.passed and dr.warnings


def test_execute_will_not_revoke_if_the_clock_drifted_after_the_dry_run(fixtures, monkeypatch):
    acct = account_02()
    doc = check(scope_of(fixtures, "02_role_chain"), acct, monkeypatch).model_dump(mode="json")
    acct.skew = timedelta(minutes=10)
    rec = run(doc)
    failed = [x for x in rec.steps if x.result == "failed"]
    assert not rec.completed and failed[0].op.endswith("_sessions") and "clock" in failed[0].detail and acct.documents == {}


def test_no_date_header_fails_a_revocation_closed(fixtures, monkeypatch):
    acct = account_02()
    acct.skew = None
    dr = check(scope_of(fixtures, "02_role_chain"), acct, monkeypatch)
    assert not dr.passed and dr.warnings


def test_missing_context_is_reported_not_guessed(fixtures, monkeypatch):
    acct = account_01()
    acct.denied = {"iam:UpdateAccessKey"}
    acct.missing_context = {"iam:UpdateAccessKey": ["aws:MultiFactorAuthPresent"]}
    dr = check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch)
    assert not dr.passed  # still a failure
    assert "the simulator had no value for the condition keys aws:MultiFactorAuthPresent" in dr.problems[0]
