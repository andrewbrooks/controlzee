"""What the plan does about identity providers, on scenario 08.

The attacker-created providers are deleted; a legitimate provider (changed by the attacker, or only named in a trust
policy) never gets an operation, in any phase. Hostile values never become an operation or an unquoted command.
"""

from __future__ import annotations

import shlex

import pytest

from controlzee.model.plan import Plan
from controlzee.plan import _Builder, _roles_trusting, build_plan
from controlzee.planlink import steps_by_actor
from controlzee.respond.ops import OPS, Unsafe
from controlzee.timeline import exposure
from tests.builders.scenarios import (
    ACCOUNT,
    OIDC_ATTACKER,
    OIDC_BUILD,
    OIDC_CI,
    OIDC_CONTROL,
    OIDC_CORP,
    OIDC_NEWLINE,
    OIDC_WRONGTYPE,
    ROLE_ARN_AS_PROVIDER,
    SAML_ATTACKER,
    SAML_CHANGED,
    SAML_CORP,
    SAML_WRONGTYPE,
)
from tests.fake_aws import Account, Provider
from tests.unit.test_derived import plan_of, timeline_of
from tests.unit.test_respond import (
    _journal_dir,  # noqa: F401 (the autouse fixture that gives every test a fresh journal folder)
    _results,
    account_01,
    check,
    run,
    scope_of,
)

SCENARIO = "08_identity_provider"
CREATED = {OIDC_ATTACKER: "delete_oidc_provider", SAML_ATTACKER: "delete_saml_provider"}
CHANGED = {OIDC_CI, OIDC_BUILD, SAML_CHANGED}
LEGITIMATE = {OIDC_CORP, SAML_CORP, *CHANGED}


@pytest.fixture
def scope(fixtures):
    return scope_of(fixtures, SCENARIO)


@pytest.fixture
def plan(scope):
    return plan_of(scope)


def _operations(plan, arn=None):
    """(step, operation) for every operation on an identity provider, or on `arn` alone."""
    return [
        (a, o)
        for a in plan.actions
        for o in a.operations
        if "provider_arn" in o.args and (arn is None or o.args["provider_arn"] == arn)
    ]


def _mentions(plan, arn):
    """Every step whose target, text, commands or operations name `arn`."""
    return [
        a
        for a in plan.actions
        if arn in a.target + a.why + (a.caution or "") + " ".join(a.commands)
        or any(arn in o.args.values() for o in a.operations)
    ]


def _with_identities(scope, edit):
    """The scope with its taint identities replaced by `edit(identity)` (None drops one)."""
    changed = [x for t in scope.taint.identities if (x := edit(t)) is not None]
    return scope.model_copy(update={"taint": scope.taint.model_copy(update={"identities": changed})})


def _retarget(scope, kind, old, new):
    return _with_identities(
        scope, lambda t: t.model_copy(update={"value": new}) if (t.kind, t.value) == (kind, old) else t
    )


# ---- the attacker's providers are deleted, once each, with the right operation


@pytest.mark.parametrize(("arn", "op"), sorted(CREATED.items()))
def test_each_created_provider_gets_exactly_one_delete_step(plan, scope, arn, op):
    steps = _operations(plan, arn)
    assert [(o.op, o.args, o.region) for _, o in steps] == [(op, {"provider_arn": arn}, None)]
    action = steps[0][0]
    assert action.phase == "eradicate" and action.disruptive is OPS[op].disruptive is True
    issuing = [t.issued_by for t in scope.taint.identities if t.kind == "provider_arn" and t.value == arn]
    assert action.evidence == issuing


def test_only_the_two_created_providers_have_operations(plan):
    assert {o.args["provider_arn"] for _, o in _operations(plan)} == set(CREATED)


def test_failed_and_hostile_creations_in_the_scenario_give_no_step(plan):
    for arn in (OIDC_NEWLINE, OIDC_CONTROL, ROLE_ARN_AS_PROVIDER, SAML_WRONGTYPE, OIDC_WRONGTYPE):
        assert _mentions(plan, arn) == []


def test_a_roles_lookup_comes_before_each_delete_and_changes_nothing(plan):
    lookups = [a for a in plan.actions if a.title.startswith("Find the roles that trust")]
    assert [a.target for a in lookups] == [f"provider {OIDC_ATTACKER}", f"provider {SAML_ATTACKER}"]
    for a in lookups:
        assert a.phase == "investigate" and a.operations == [] and not a.disruptive
        assert len(a.commands) == 1 and a.commands[0].startswith("aws iam list-roles --query ")
    deletes = [a for a, _ in _operations(plan)]
    assert max(plan.actions.index(a) for a in lookups) < min(plan.actions.index(a) for a in deletes)


# ---- a legitimate provider never gets an operation


@pytest.mark.parametrize("arn", sorted(LEGITIMATE))
def test_a_legitimate_provider_has_no_operation_in_any_phase(plan, arn):
    assert _operations(plan, arn) == []
    assert [a for a in _mentions(plan, arn) if a.operations] == []


def test_a_changed_provider_gets_one_manual_step_with_get_commands_only(plan):
    steps = [a for a in plan.actions if a.title == "Restore an identity provider the attacker changed"]
    assert sorted(a.target for a in steps) == sorted(f"provider {arn}" for arn in CHANGED)
    for a in steps:
        assert a.operations == [] and not a.disruptive and not a.on_request
        assert len(a.commands) == 1 and " get-" in a.commands[0] and "delete" not in " ".join(a.commands)
        assert "Never delete it" in (a.caution or "")


def test_a_provider_only_named_by_a_trust_policy_gets_no_step_of_its_own(plan):
    assert _federated(
        plan
    )  # the scenario does name the corp provider, in a trust policy the attacker rewrote
    assert [a for a in plan.actions if a.target.endswith(OIDC_CORP)] == []
    assert [a for a in plan.actions if a.target.endswith(SAML_CORP)] == []


def _federated(plan):
    return [a.caution for a in plan.actions if a.caution and "logins through identity provider" in a.caution]


def test_the_trust_policy_step_names_a_federated_entry_in_words(plan):
    (text,) = _federated(plan)
    assert f"logins through identity provider {OIDC_CORP}" in text and "federated:" not in text


def test_a_provider_that_is_not_marked_created_is_not_deleted(scope):
    """The condition is the issuing call: a provider_arn identity from anything but a Create call gets no delete."""
    other = _with_identities(
        scope,
        lambda t: t.model_copy(update={"rule": "iam:UpdateSAMLProvider"}) if t.kind == "provider_arn" else t,
    )
    assert _operations(Plan.model_validate(build_plan(other))) == []


def test_a_changed_provider_that_was_also_created_is_deleted_once_and_not_reviewed(scope):
    extra = [t for t in scope.taint.identities if t.kind == "provider_arn" and t.value == OIDC_ATTACKER]
    both = _with_identities(scope, lambda t: t)
    both = both.model_copy(
        update={
            "taint": both.taint.model_copy(
                update={
                    "identities": [
                        *both.taint.identities,
                        extra[0].model_copy(update={"kind": "changed_provider"}),
                    ]
                }
            )
        }
    )
    plan = Plan.model_validate(build_plan(both))
    assert len(_operations(plan, OIDC_ATTACKER)) == 1
    assert [a for a in plan.actions if a.title.startswith("Restore") and OIDC_ATTACKER in a.target] == []


def test_a_provider_whose_issuing_event_is_not_in_scope_gets_no_step(scope):
    gone = scope.model_copy(update={"events": []})
    assert _operations(Plan.model_validate(build_plan(gone)), OIDC_ATTACKER) == []


# ---- hostile values


HOSTILE = [
    "arn:aws:iam::111122223333:oidc-provider/x'; touch /tmp/pwned; echo '",
    f"{OIDC_ATTACKER}\n",
    f"{OIDC_ATTACKER}$(id)",
    f"{OIDC_ATTACKER}`id`",
    f"{OIDC_ATTACKER}|x",
    f"{OIDC_ATTACKER}\x1b[31m",
    f"{OIDC_ATTACKER} --region evil",
    f"arn:aws:iam::{ACCOUNT}:role/not-a-provider",
    f"arn:aws:iam::{ACCOUNT}:saml-provider/with/slash",
    "arn:aws:iam::111122223333:oidc-provider/" + "a" * 401,
    "",
]


def _titled(plan, start):
    return [a for a in plan.actions if a.title.startswith(start)]


def _assert_manual_only(step, hostile):
    assert step.operations == [] and step.commands == [] and not step.disruptive
    assert "does not have the expected form" in (step.caution or "")
    assert hostile not in step.commands


@pytest.mark.parametrize("hostile", HOSTILE)
@pytest.mark.parametrize("old", sorted(CREATED))
def test_a_malformed_created_arn_becomes_one_manual_step_with_no_command(scope, old, hostile):
    plan = Plan.model_validate(build_plan(_retarget(scope, "provider_arn", old, hostile)))
    deletes = _titled(plan, "Delete an identity provider")
    assert len(deletes) == 2 and len(_operations(plan)) == 1  # only the untouched provider is an operation
    (bad,) = [a for a in deletes if not a.operations]
    _assert_manual_only(bad, hostile)
    assert len(_titled(plan, "Find the roles that trust")) == 1  # none for the malformed one
    assert [a for a in plan.actions if hostile and hostile in " ".join(a.commands)] == []


@pytest.mark.parametrize("hostile", HOSTILE)
def test_a_malformed_changed_arn_becomes_a_manual_step_with_no_command(scope, hostile):
    plan = Plan.model_validate(build_plan(_retarget(scope, "changed_provider", OIDC_CI, hostile)))
    restores = _titled(plan, "Restore an identity provider")
    assert len(restores) == 3
    (bad,) = [a for a in restores if not a.commands]
    _assert_manual_only(bad, hostile)
    assert [a for a in plan.actions if hostile and hostile in " ".join(a.commands)] == []


def test_every_command_the_plan_gives_for_a_provider_is_one_quoted_word_per_arn(scope):
    """A valid but awkward ARN (every character the SAML shape allows) stays one word in every provider command."""
    awkward = f"arn:aws:iam::{ACCOUNT}:saml-provider/a+b=c,d.e@f-g_h"
    plan = Plan.model_validate(build_plan(_retarget(scope, "provider_arn", SAML_ATTACKER, awkward)))
    commands = [c for a in plan.actions if a.target == f"provider {awkward}" for c in a.commands]
    assert len(commands) == 3  # the roles lookup, get, delete
    for command in commands:
        words = shlex.split(command)
        assert words[:2] == ["aws", "iam"]
        assert any(w == awkward for w in words) or any(
            awkward in w and w.startswith("Roles[?") for w in words
        )


def test_a_provider_name_cannot_break_out_of_the_roles_query(scope):
    """The OIDC shape allows ':' '/' '.' '@' '-' and word characters: none can close the JMESPath literal."""
    arn = f"arn:aws:iam::{ACCOUNT}:oidc-provider/host.example:8443/path@x-y"
    plan = Plan.model_validate(build_plan(_retarget(scope, "provider_arn", OIDC_ATTACKER, arn)))
    (lookup,) = [a for a in plan.actions if a.title.startswith("Find the roles") and arn in a.target]
    words = shlex.split(lookup.commands[0])
    assert words == [
        "aws",
        "iam",
        "list-roles",
        "--query",
        f"Roles[?contains(to_string(AssumeRolePolicyDocument), '{arn}')].RoleName",
        "--output",
        "text",
    ]


# ---- the plan and the operations agree: the real dry run against the in-memory account


def _account() -> Account:
    acct = account_01()
    acct.oidc_providers = {
        OIDC_ATTACKER: Provider(url="token.attacker.example.com"),
        OIDC_CORP: Provider(url="login.corp.example.com"),
        OIDC_CI: Provider(url="ci.example.com"),
        OIDC_BUILD: Provider(url="build.example.com"),
    }
    acct.saml_providers = {SAML_ATTACKER: Provider(), SAML_CORP: Provider(), SAML_CHANGED: Provider()}
    return acct


def _delete_ids(plan):
    return {a.id for a, _ in _operations(plan)}


def test_the_delete_steps_are_left_out_of_a_dry_run_without_allow_disruptive(scope, plan, monkeypatch):
    ids = _delete_ids(plan)
    without = check(scope, _account(), monkeypatch, chosen=ids)
    assert without.steps == [] and {n.action_id for n in without.not_selected} >= ids
    allowed = check(scope, _account(), monkeypatch, chosen=ids, allow_disruptive=True)
    assert allowed.passed
    assert {(s.op, s.args["provider_arn"]) for s in allowed.steps} == {
        (op, arn) for arn, op in CREATED.items()
    }


def test_every_provider_step_of_the_plan_is_accepted_by_the_operations(scope, plan, monkeypatch):
    """Not just the two deletes: no step of the plan fails the dry run's own validation of its arguments."""
    dr = check(scope, _account(), monkeypatch, chosen=_delete_ids(plan), allow_disruptive=True)
    assert [s.problem for s in dr.steps] == [None, None] and dr.problems == []
    assert {c.resource for s in dr.steps for c in s.checks} == set(CREATED)


def test_execute_deletes_the_attackers_providers_and_leaves_every_legitimate_one(scope, plan, monkeypatch):
    acct = _account()
    dr = check(scope, acct, monkeypatch, chosen=_delete_ids(plan), allow_disruptive=True)
    rec = run(dr.model_dump(mode="json"))
    assert rec.completed and _results(rec) == ["done", "done"]
    assert set(acct.oidc_providers) == {OIDC_CORP, OIDC_CI, OIDC_BUILD}
    assert set(acct.saml_providers) == {SAML_CORP, SAML_CHANGED}
    assert sorted(c[1] for c in acct.calls) == ["delete_open_id_connect_provider", "delete_saml_provider"]


# ---- exposure and the link from a step to who it is about


def test_exposure_says_what_a_created_and_a_changed_provider_mean(scope):
    notes = exposure(scope).notes
    for arn in CREATED:
        (note,) = [n for n in notes if f"identity provider {arn} was created" in n]
        assert "anyone holding a token it signs can assume the roles that trust it" in note
    for arn in CHANGED:
        (note,) = [n for n in notes if f"identity provider {arn} existed before and was changed" in n]
        assert "not the previous settings" in note
    # the corp providers were never created or changed: only the rewritten trust policy names the OIDC one
    for arn in (OIDC_CORP, SAML_CORP):
        assert [n for n in notes if f"identity provider {arn} " in n] == []


def test_exposure_names_a_federated_trust_entry_in_words(scope):
    (note,) = [n for n in exposure(scope).notes if n.startswith("the trust policy of role data-reader")]
    assert f"names logins through identity provider {OIDC_CORP};" in note and "federated:" not in note


def test_a_delete_step_is_tied_to_the_logins_through_that_provider_only(scope, plan):
    actors = timeline_of(scope).actors
    linked = steps_by_actor(plan, actors)
    delete = next(a for a, o in _operations(plan, OIDC_ATTACKER))
    assert linked[delete.id] and all(label.startswith(OIDC_ATTACKER + ":") for label in linked[delete.id])
    other = next(a for a, o in _operations(plan, SAML_ATTACKER))
    assert other.id not in linked or all(OIDC_CORP not in label for label in linked[other.id])
    changed = [a.id for a in plan.actions if a.title.startswith("Restore an identity provider")]
    assert not [i for i in changed if i in linked]  # a manual step has no operation, so it names no identity


@pytest.mark.parametrize("hostile", [h for h in HOSTILE if h])
def test_the_command_builders_refuse_a_malformed_arn_on_their_own(hostile):
    """The last line of defence: even if a bad ARN got past the type check, no command is made from it."""
    for kind in ("oidc_arn", "saml_arn"):
        with pytest.raises(Unsafe):
            _roles_trusting(kind, hostile)
        with pytest.raises(Unsafe):
            _Builder._get_provider(kind, hostile)
    with pytest.raises(Unsafe):
        _Builder._get_provider(None, OIDC_ATTACKER)
