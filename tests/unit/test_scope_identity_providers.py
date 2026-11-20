"""Scenario 8 end to end: identity providers (OIDC and SAML) an attacker plants or changes, and the sessions got through them.

Every assertion names what is in scope by event name, provider and subject (or session), not by golden. The contract is
`.team/CONTRACT-W3B.md` (semantics 1 to 6). Tests that need the taint rules of W3B-1 are marked together with `needs_w3b1`
(strict xfail): when that work is integrated, flip `NEEDS_W3B1` in one edit; an unexpected pass is a failure until then.
The tests that do not depend on it (the scenario builds, nothing is mis-ingested, no key-shaped ids) always run.
"""

import re
from pathlib import Path

import pytest

from controlzee.scope import ScopeOptions, build_scope
from controlzee.seed.spec import assemble, load_iocs_file
from tests.builders import scenarios as sc
from tests.builders.cloudtrail import LogSet, assumed_role, at, iam_user
from tests.unit.test_respond import scope_of

SCENARIO = "08_identity_provider"
ASSUME_NAMES = ("AssumeRoleWithWebIdentity", "AssumeRoleWithSAML")


@pytest.fixture(scope="module")
def scope():
    return scope_of(Path(__file__).parents[1] / "fixtures", SCENARIO)


# ---- reading a scope by what an event is, not by its id


def session_of(event) -> str | None:
    """The role session name: what an assume call asked for, or the session a call was made in."""
    return (event.request_parameters or {}).get("roleSessionName") or event.user_identity.session_name


def followed(scope) -> list:
    return [s for s in scope.events if s.origin == "propagated"]


def followed_assumes(scope) -> set[tuple[str, str]]:
    """(event name, session) of the AssumeRoleWith* calls in scope that were not seeds."""
    return {
        (s.event.event_name, session_of(s.event))
        for s in followed(scope)
        if s.event.event_name in ASSUME_NAMES
    }


def followed_uses(scope) -> set[str]:
    """Sessions whose later calls (not the assume itself) are in scope."""
    return {session_of(s.event) for s in followed(scope) if s.event.event_name not in ASSUME_NAMES}


def in_scope_sessions(scope) -> set[str]:
    return {session_of(s.event) for s in scope.events if session_of(s.event)}


def assert_rules_are_active(scope) -> None:
    """Guard for the "nothing is followed" tests: they must not pass just because nothing is followed at all."""
    assert ("AssumeRoleWithWebIdentity", "atk-web") in followed_assumes(scope)


def identities(scope, kind: str) -> list[str]:
    return sorted(i.value for i in scope.taint.identities if i.kind == kind)


# ---- always run: the scenario itself


def test_the_scenario_ingests_cleanly_and_seeds_only_the_leaked_key(scope):
    seeds = [s for s in scope.events if s.origin == "seed"]
    assert {s.event.user_identity.access_key_id for s in seeds} == {sc.LEAKED_KEY}
    assert scope.inputs.error_files == 0 and scope.inputs.malformed_records == 0
    # the failed provider creation and the hostile responses are still the leaked key's calls, so they are seeds
    assert [s.event.event_name for s in seeds].count("CreateOpenIDConnectProvider") == 6
    assert sum(1 for s in seeds if s.event.error_code) == 1


def test_no_key_shaped_id_in_the_fixture_is_a_real_looking_20_character_key():
    """CI's strict secret scan flags 20-character key ids not ending in EXAMPLE; the fixture must hold none."""
    text = "\n".join(p.read_text() for p in (sc_fixture_dir() / "logs").rglob("*.json"))
    key_shaped = set(re.findall(r"\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b", text))
    assert [k for k in key_shaped if not k.endswith("EXAMPLE")] == []
    assert set(re.findall(r"\b\d{12}\b", text)) <= {"111122223333"}  # only the documentation account id


def sc_fixture_dir() -> Path:
    return Path(__file__).parents[1] / "fixtures" / SCENARIO


# ---- the six situations (needs the taint rules)


def test_1_a_created_oidc_provider_makes_every_later_assume_through_it_the_attackers(scope):
    assert ("AssumeRoleWithWebIdentity", "atk-web") in followed_assumes(scope)  # subject attacker-sub-1
    assert "atk-web" in followed_uses(scope)  # the GetSecretValue with the session
    # the same role's legitimate users, through their own provider, before and after
    for session in ("alice-web", "alice-web-2"):
        assert session not in in_scope_sessions(scope)
    # the provider is a taint identity of kind provider_arn, issued by the attacker's create call
    created = [i for i in scope.taint.identities if i.kind == "provider_arn" and i.value == sc.OIDC_ATTACKER]
    assert [i.rule for i in created] == ["iam:CreateOpenIDConnectProvider"]


def test_1_the_provider_in_the_response_or_in_the_caller_is_enough_but_an_issuer_name_alone_is_not(scope):
    # responseElements.provider is the ARN, userIdentity.identityProvider an issuer name: followed
    assert ("AssumeRoleWithWebIdentity", "atk-iss") in followed_assumes(scope)
    assert "atk-iss" in followed_uses(scope)
    # no provider in the response, userIdentity.identityProvider is the ARN: followed (the fallback the contract names)
    assert ("AssumeRoleWithWebIdentity", "atk-arn") in followed_assumes(scope)
    assert "atk-arn" in followed_uses(scope)
    # an issuer name and no ARN anywhere (cognito-identity.amazonaws.com): no provider fact, so not followed
    assert "cog-1" not in in_scope_sessions(scope)


def test_2_a_created_saml_provider_makes_the_assume_through_it_the_attackers(scope):
    assert ("AssumeRoleWithSAML", "atk-saml") in followed_assumes(scope)  # subject attacker@evil.example
    assert "atk-saml" in followed_uses(scope)
    created = [i for i in scope.taint.identities if i.kind == "provider_arn" and i.value == sc.SAML_ATTACKER]
    assert [i.rule for i in created] == ["iam:CreateSAMLProvider"]


def test_3_a_changed_provider_follows_only_subjects_not_seen_through_it_before(scope):
    # OIDC client id added (ci.example.com): the new subject is followed, the CI subject seen before is not
    assert ("AssumeRoleWithWebIdentity", "atk-ci") in followed_assumes(scope) and "atk-ci" in followed_uses(
        scope
    )
    assert "ci-main-3" not in in_scope_sessions(scope)
    # OIDC thumbprint changed (build.example.com), the same split
    assert ("AssumeRoleWithWebIdentity", "atk-build") in followed_assumes(
        scope
    ) and "atk-build" in followed_uses(scope)
    assert "builder-2" not in in_scope_sessions(scope)
    # SAML provider updated (corp-sso-2): mallory is new, carol was seen before
    assert ("AssumeRoleWithSAML", "atk-saml2") in followed_assumes(scope) and "atk-saml2" in followed_uses(
        scope
    )
    assert "carol-2" not in in_scope_sessions(scope)
    assert identities(scope, "changed_provider") == sorted([sc.OIDC_CI, sc.OIDC_BUILD, sc.SAML_CHANGED])
    # a changed provider is not a created one
    assert not {sc.OIDC_CI, sc.OIDC_BUILD, sc.SAML_CHANGED} & set(identities(scope, "provider_arn"))


def test_4_a_legitimate_saml_provider_nobody_touched_follows_nothing(scope):
    assert_rules_are_active(scope)
    for session in ("bob-1", "bob-2", "bob-3"):
        assert session not in in_scope_sessions(scope)
    assert sc.SAML_CORP not in identities(scope, "provider_arn") + identities(scope, "changed_provider")
    # the scenario must still have followed the others, or this passes by following nothing at all
    assert ("AssumeRoleWithSAML", "atk-saml") in followed_assumes(scope)


def test_5_a_role_whose_trust_policy_names_a_federated_provider_is_entered_only_by_new_subjects(scope):
    assert ("AssumeRoleWithWebIdentity", "atk-data") in followed_assumes(
        scope
    ) and "atk-data" in followed_uses(scope)
    for session in ("alice-data", "alice-data-2"):  # its usual federated user, before and after
        assert session not in in_scope_sessions(scope)
    # exactly one federated principal: the corp provider. cognito-identity.amazonaws.com is not ARN-shaped, and the AWS
    # principal on a web-identity-only statement does not count (an AWS principal needs sts:AssumeRole)
    assert identities(scope, "trusted_by") == [f"data-reader|federated:{sc.OIDC_CORP}"]
    # the trust is for that role only: the same new subject through the same provider into another role is not followed
    assert "atk-other" not in in_scope_sessions(scope)


def test_6_failed_calls_hand_over_nothing(scope):
    assert_rules_are_active(scope)
    # the failed AssumeRoleWithWebIdentity names the attacker's provider in userIdentity.identityProvider, and is a failure
    assert "atk-fail" not in in_scope_sessions(scope)
    # the failed CreateOpenIDConnectProvider issued no provider
    assert not any("failed.attacker" in i.value for i in scope.taint.identities)
    assert identities(scope, "provider_arn") == sorted([sc.OIDC_ATTACKER, sc.SAML_ATTACKER])


# ---- identities (needs the taint rules)


def test_the_identity_kinds_and_values_are_exactly_these(scope):
    kinds = {i.kind for i in scope.taint.identities}
    assert kinds == {"provider_arn", "changed_provider", "trusted_by", "access_key_id"}
    session_keys = {
        sc.IDP_KEYS[n]
        for n in ("ATK01A", "ATK01B", "ATK01C", "ATK01D", "SAMLA1", "CHG001", "BLD002", "SAMLM1", "DRA001")
    }
    assert (
        set(identities(scope, "access_key_id")) == session_keys
    )  # the credentials of every followed assume, no others


def test_assumed_via_is_a_fact_and_never_an_identity(scope):
    assert_rules_are_active(scope)
    assert not any("assumed_via" in (i.kind, i.value, i.rule) for i in scope.taint.identities)
    assert all(i.kind != "assumed_via" for i in scope.taint.identities)
    # a provider identity is the bare ARN: no "|<subject>" packed into it
    for kind in ("provider_arn", "changed_provider"):
        assert all("|" not in v for v in identities(scope, kind))


def test_each_followed_assume_says_which_identity_let_it_in(scope):
    # Assumes the `via` is "<kind>:<value>" as for every other identity (this is the form scenario 07 shows for trusted_by).
    via = {session_of(s.event): s.via for s in followed(scope) if s.event.event_name in ASSUME_NAMES}
    assert via["atk-web"] == f"provider_arn:{sc.OIDC_ATTACKER}"
    assert via["atk-saml"] == f"provider_arn:{sc.SAML_ATTACKER}"
    assert via["atk-ci"] == f"changed_provider:{sc.OIDC_CI}"
    assert via["atk-build"] == f"changed_provider:{sc.OIDC_BUILD}"
    assert via["atk-saml2"] == f"changed_provider:{sc.SAML_CHANGED}"
    assert via["atk-data"] == f"trusted_by:data-reader|federated:{sc.OIDC_CORP}"


# ---- hostile input. The right outcome of each is stated; the ones in the scenario are checked against `scope`.


def test_hostile_a_provider_arn_with_control_characters_or_a_trailing_newline_is_not_a_provider(scope):
    assert_rules_are_active(scope)
    # A response ARN is accepted only if it matches oidc_arn exactly. "...example.com\n" must fail (Python's `$` matches
    # before a trailing newline, so a regex ending in `$` accepts it unless it is written with `\Z` or fullmatch).
    for bad in (sc.OIDC_NEWLINE, sc.OIDC_CONTROL):
        assert bad not in identities(scope, "provider_arn") and bad.rstrip("\n") not in identities(
            scope, "provider_arn"
        )
    assert "nl-1" not in in_scope_sessions(
        scope
    )  # an assume that names the bad ARN is not through any provider
    assert not any(any(ch in i.value for ch in "\n\x1b\x00") for i in scope.taint.identities)


def test_hostile_an_arn_of_the_wrong_type_is_not_a_provider(scope):
    assert_rules_are_active(scope)
    # a role ARN, a SAML ARN in CreateOpenIDConnectProvider and an OIDC ARN in CreateSAMLProvider: each fails its shape
    for bad in (sc.ROLE_ARN_AS_PROVIDER, sc.SAML_WRONGTYPE, sc.OIDC_WRONGTYPE):
        assert bad not in identities(scope, "provider_arn")
    assert identities(scope, "provider_arn") == sorted([sc.OIDC_ATTACKER, sc.SAML_ATTACKER])


def test_hostile_a_subject_containing_a_pipe_does_not_hide_the_session(scope):
    assert_rules_are_active(scope)
    # Decision D-011: a subject that would corrupt the packed "<provider>|<subject>" fact is recorded as empty, and the
    # login is still followed. Through a provider the attacker created there is no history filter, so dropping the fact
    # would let an attacker hide a session behind a subject like "x|y". The packed form is never mis-split, and the subject
    # itself never reaches an identity.
    assert "atk-pipe" in in_scope_sessions(scope)
    assert not any("evil" in i.value for i in scope.taint.identities)


def test_hostile_a_2_mb_saml_metadata_document_does_not_break_ingest(tmp_path):
    """Always runs: a 2 MB request parameter is read and reported without error."""
    out = build_big_metadata_scope(tmp_path)
    assert out.inputs.error_files == 0 and out.inputs.malformed_records == 0
    create = next(s for s in out.events if s.event.event_name == "CreateSAMLProvider")
    assert create.origin == "seed"


def test_hostile_a_2_mb_saml_metadata_document_still_makes_the_provider_the_attackers(tmp_path):
    out = build_big_metadata_scope(tmp_path)
    assert [i.value for i in out.taint.identities if i.kind == "provider_arn"] == [sc.SAML_ATTACKER]
    assert ("AssumeRoleWithSAML", "big-saml") in followed_assumes(out)
    assert "big-saml" in followed_uses(out)


def build_big_metadata_scope(tmp_path):
    logs = LogSet()
    t = at(sc.IDP_T0)
    attacker = iam_user("ci-deploy", sc.LEAKED_KEY)
    document = "<EntityDescriptor>" + "A" * (2 * 1024 * 1024) + "</EntityDescriptor>"
    sc._create_saml(logs, t, attacker, "attacker-idp", sc.SAML_ATTACKER, metadata=document)
    key = sc.IDP_KEYS["SAMLA1"]
    sc.idp_assume_saml(
        logs,
        t.replace(minute=20),
        role="saml-admin",
        session="big-saml",
        subject="attacker@evil.example",
        key=key,
        provider=sc.SAML_ATTACKER,
    )
    logs.add(
        t.replace(minute=22),
        "secretsmanager.amazonaws.com",
        "GetSecretValue",
        assumed_role("saml-admin", "big-saml", key),
        request={"secretId": "prod/saml"},
    )
    logs.write(tmp_path / "logs")
    spec = assemble([load_iocs_file(sc_fixture_dir() / "iocs.yaml")])
    return build_scope([tmp_path / "logs"], spec, ScopeOptions(workers=1)).scope
