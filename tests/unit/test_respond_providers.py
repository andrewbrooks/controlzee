"""delete_oidc_provider and delete_saml_provider, through the in-memory account and the real dry run and execute."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from controlzee.respond.ops import OPS, Ctx, Unsafe, validate
from tests.fake_aws import Account, Provider
from tests.unit.test_respond import (
    OIDC_ARN,
    SAML_ARN,
    _journal_dir,  # noqa: F401 (the autouse fixture that gives every test a fresh journal folder)
    _results,
    _with_actions,
    account_01,
    check,
    run,
)

OTHER_OIDC = "arn:aws:iam::111122223333:oidc-provider/other.example.org"
OTHER_SAML = "arn:aws:iam::111122223333:saml-provider/LegitIdP"
RECREATED = datetime(2026, 10, 27, 12, 1, tzinfo=UTC)
STEPS = {
    "oidc": ("A91", "delete_oidc_provider", {"provider_arn": OIDC_ARN}),
    "saml": ("A92", "delete_saml_provider", {"provider_arn": SAML_ARN}),
}
ARNS = {"oidc": OIDC_ARN, "saml": SAML_ARN}
ACTIONS = {"oidc": "iam:DeleteOpenIDConnectProvider", "saml": "iam:DeleteSAMLProvider"}
CALLS = {"oidc": "delete_open_id_connect_provider", "saml": "delete_saml_provider"}
KINDS = ["oidc", "saml"]


def _account() -> Account:
    acct = account_01()
    acct.oidc_providers = {OIDC_ARN: Provider(), OTHER_OIDC: Provider(url="other.example.org")}
    acct.saml_providers = {SAML_ARN: Provider(), OTHER_SAML: Provider()}
    return acct


def _scope(fixtures, monkeypatch, kind):
    i, op, args = STEPS[kind]
    return _with_actions(fixtures, monkeypatch, "01_leaked_key", (i, op, args, None, True)), i


def _providers(acct, kind):
    return acct.oidc_providers if kind == "oidc" else acct.saml_providers


def _ctx():
    return Ctx(account="111122223333", partition="aws", profile=None, home_region="us-east-1")


@pytest.mark.parametrize("kind", KINDS)
def test_a_provider_step_needs_allow_disruptive(fixtures, monkeypatch, kind):
    scope, step = _scope(fixtures, monkeypatch, kind)
    without = check(scope, _account(), monkeypatch, chosen={step})
    assert step not in [s.action_id for s in without.steps]
    allowed = check(scope, _account(), monkeypatch, chosen={step}, allow_disruptive=True)
    assert allowed.passed and [s.action_id for s in allowed.steps] == [step]


@pytest.mark.parametrize("kind", KINDS)
def test_the_simulator_is_asked_about_the_right_action_and_provider(fixtures, monkeypatch, kind):
    scope, step = _scope(fixtures, monkeypatch, kind)
    dr = check(scope, _account(), monkeypatch, chosen={step}, allow_disruptive=True)
    assert [(c.action, c.resource) for c in dr.steps[0].checks] == [(ACTIONS[kind], ARNS[kind])]


@pytest.mark.parametrize("kind", KINDS)
def test_execute_deletes_only_that_provider(fixtures, monkeypatch, kind):
    scope, step = _scope(fixtures, monkeypatch, kind)
    acct = _account()
    dr = check(scope, acct, monkeypatch, chosen={step}, allow_disruptive=True)
    assert run(dr.model_dump(mode="json")).completed
    assert set(_providers(acct, kind)) == {OTHER_OIDC if kind == "oidc" else OTHER_SAML}
    assert (
        len(acct.saml_providers if kind == "oidc" else acct.oidc_providers) == 2
    )  # the other type is untouched
    assert [c[1] for c in acct.calls] == [CALLS[kind]]


@pytest.mark.parametrize("kind", KINDS)
def test_a_provider_made_again_after_the_dry_run_is_drift_and_untouched(fixtures, monkeypatch, kind):
    scope, step = _scope(fixtures, monkeypatch, kind)
    acct = _account()
    doc = check(scope, acct, monkeypatch, chosen={step}, allow_disruptive=True).model_dump(mode="json")
    assert set(doc["steps"][0]["identity"]) == {"provider_arn", "provider_create_date"}
    _providers(acct, kind)[ARNS[kind]] = Provider(created=RECREATED)
    rec = run(doc)
    assert _results(rec) == ["drifted"] and "provider_create_date was" in rec.steps[0].detail
    assert ARNS[kind] in _providers(acct, kind) and acct.calls == []


@pytest.mark.parametrize("kind", KINDS)
def test_a_provider_gone_before_execute_is_already_done(fixtures, monkeypatch, kind):
    scope, step = _scope(fixtures, monkeypatch, kind)
    acct = _account()
    doc = check(scope, acct, monkeypatch, chosen={step}, allow_disruptive=True).model_dump(mode="json")
    del _providers(acct, kind)[ARNS[kind]]
    rec = run(doc)
    assert rec.completed and _results(rec) == ["already done"] and acct.calls == []


@pytest.mark.parametrize("kind", KINDS)
def test_a_second_dry_run_finds_everything_already_done(fixtures, monkeypatch, kind):
    scope, step = _scope(fixtures, monkeypatch, kind)
    acct = _account()
    first = check(scope, acct, monkeypatch, chosen={step}, allow_disruptive=True)
    assert run(first.model_dump(mode="json")).completed
    again = check(scope, acct, monkeypatch, chosen={step}, allow_disruptive=True)
    assert again.passed and [s.already_done for s in again.steps] == [True]
    assert again.steps[0].state.endswith("does not exist")


@pytest.mark.parametrize(
    "op,arn",
    [
        ("delete_oidc_provider", "arn:aws:iam::111122223333:oidc-provider/idp.example.com\n"),
        ("delete_oidc_provider", "arn:aws:iam::111122223333:oidc-provider/idp\x1b[31m.example.com"),
        ("delete_oidc_provider", SAML_ARN),
        ("delete_saml_provider", OIDC_ARN),
        ("delete_oidc_provider", "arn:aws:iam::111122223333:oidc-provider/a|b"),
        ("delete_oidc_provider", "arn:aws:iam::111122223333:oidc-provider/" + "a" * 401),
        ("delete_saml_provider", "arn:aws:iam::111122223333:saml-provider/" + "a" * 129),
        ("delete_saml_provider", "arn:aws:iam::1111:saml-provider/AttackerIdP"),
        ("delete_saml_provider", "arn:aws:iam::111122223333:saml-provider/a b"),
        ("delete_saml_provider", "arn:aws:iam::111122223333:saml-provider/x;rm -rf /"),
        ("delete_saml_provider", ""),
    ],
)
def test_hostile_provider_arguments_are_refused_before_anything_runs(op, arn, monkeypatch):
    acct = _account()
    acct.install(monkeypatch)
    with pytest.raises(Unsafe):
        validate(op, {"provider_arn": arn}, None)
    with pytest.raises(Unsafe):
        OPS[op].cli({"provider_arn": arn}, None)
    assert acct.all_calls == []


def test_provider_operations_are_global_and_disruptive():
    for op in ("delete_oidc_provider", "delete_saml_provider"):
        assert OPS[op].disruptive and not OPS[op].regional
    with pytest.raises(Unsafe):
        validate("delete_oidc_provider", {"provider_arn": OIDC_ARN}, "us-east-1")


def test_the_cli_text_is_the_aws_command():
    assert OPS["delete_oidc_provider"].cli({"provider_arn": OIDC_ARN}, None)[-1] == (
        f"aws iam delete-open-id-connect-provider --open-id-connect-provider-arn {OIDC_ARN}"
    )
    assert OPS["delete_saml_provider"].cli({"provider_arn": SAML_ARN}, None)[-1] == (
        f"aws iam delete-saml-provider --saml-provider-arn {SAML_ARN}"
    )


def test_a_hostile_issuer_is_cleaned_and_capped_in_the_state(monkeypatch):
    acct = _account()
    acct.oidc_providers[OIDC_ARN] = Provider(url="evil\x1b[2J\nissuer/" + "x" * 500)
    acct.install(monkeypatch)
    state = OPS["delete_oidc_provider"].probe(_ctx(), {"provider_arn": OIDC_ARN}, None).state
    assert "\x1b" not in state and "\n" not in state and "x" * 300 not in state
    assert "evil" in state and "1 client ids and 1 thumbprints" in state


def test_the_saml_metadata_never_appears_in_the_state(monkeypatch):
    acct = _account()
    acct.install(monkeypatch)
    state = OPS["delete_saml_provider"].probe(_ctx(), {"provider_arn": SAML_ARN}, None).state
    assert "SAML-METADATA-DOCUMENT" not in state and "EntityDescriptor" not in state
    assert "valid until 2027-01-15" in state


@pytest.mark.parametrize("kind", KINDS)
def test_a_provider_of_another_account_fails_the_probe(kind, monkeypatch):
    other = ARNS[kind].replace("111122223333", "444455556666")
    acct = _account()
    _providers(acct, kind)[other] = Provider()
    acct.install(monkeypatch)
    op = f"delete_{kind}_provider"
    probe = OPS[op].probe(_ctx(), {"provider_arn": other}, None)
    assert probe.problem and "not in this account" in probe.problem


def test_a_missing_provider_is_done_with_no_identity(monkeypatch):
    Account().install(monkeypatch)
    for op, arn in (("delete_oidc_provider", OIDC_ARN), ("delete_saml_provider", SAML_ARN)):
        probe = OPS[op].probe(_ctx(), {"provider_arn": arn}, None)
        assert probe.done and probe.identity == {} and probe.state.endswith("does not exist")
