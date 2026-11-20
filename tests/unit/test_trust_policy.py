"""Trust-policy backdoors: a tainted `iam:UpdateAssumeRolePolicy` makes whoever the new policy names, and had not assumed
the role before, an entry the attacker holds. The log has the new policy and not the old, so that is how the principals the
change added are told from the ones that were already trusted."""

import glob
import gzip
import json
from pathlib import Path

import pytest

from controlzee.respond.activity import find_new_activity
from controlzee.taint.propagate import acting_as, caller_key, principal_matches, trusted_index
from controlzee.taint.rules import ASSUMED_BY, MAX_TRUST_POLICY, TRUSTED_BY, issued_by, trust_principals
from controlzee.timeline import _trust_policy_notes
from tests.helpers import make_row
from tests.unit.test_respond import scope_of

ACCT = "111122223333"
OUTSIDE = "444455556666"


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(principal, action="sts:AssumeRole", effect="Allow"):
    return {"Effect": effect, "Principal": principal, "Action": action}


# ---- which principals a trust policy names


@pytest.mark.parametrize(
    "document,expected",
    [
        (doc(allow({"AWS": f"arn:aws:iam::{OUTSIDE}:root"})), [f"account:{OUTSIDE}"]),
        (doc(allow({"AWS": OUTSIDE})), [f"account:{OUTSIDE}"]),  # a bare account id
        (doc(allow({"AWS": f"arn:aws:iam::{ACCT}:user/alice"})), [f"arn:aws:iam::{ACCT}:user/alice"]),
        (doc(allow({"AWS": f"arn:aws:iam::{ACCT}:role/ci"})), [f"arn:aws:iam::{ACCT}:role/ci"]),
        (doc(allow({"AWS": "*"})), ["*"]),
        (doc(allow("*")), ["*"]),
        (
            doc(allow({"AWS": [f"arn:aws:iam::{OUTSIDE}:root", f"arn:aws:iam::{ACCT}:role/ci"]})),
            [f"account:{OUTSIDE}", f"arn:aws:iam::{ACCT}:role/ci"],
        ),
        (doc(allow({"AWS": f"arn:aws:iam::{OUTSIDE}:root"}, "sts:*")), [f"account:{OUTSIDE}"]),
        (  # a statement given as an object, not a list
            {"Statement": allow({"AWS": OUTSIDE})},
            [f"account:{OUTSIDE}"],
        ),
    ],
)
def test_the_principals_a_trust_policy_names(document, expected):
    assert trust_principals(document) == expected


@pytest.mark.parametrize(
    "document",
    [
        doc(allow({"Service": "ec2.amazonaws.com"})),  # a service is not a caller
        doc(
            allow(
                {"Federated": "cognito-identity.amazonaws.com"},
                "sts:AssumeRoleWithWebIdentity",
            )
        ),
        doc(allow({"AWS": OUTSIDE}, effect="Deny")),
        doc(allow({"AWS": OUTSIDE}, action="s3:GetObject")),  # not an assume-role statement
        doc({"Effect": "Allow", "NotPrincipal": {"AWS": OUTSIDE}, "Action": "sts:AssumeRole"}),
        doc(allow({"AWS": "AIDAEXAMPLEPRINCIPALID"})),  # a unique id is not a shape this reads
        doc(allow({"AWS": "arn:aws:iam::4444:root"})),
        doc(allow({"AWS": f"arn:aws:iam::{OUTSIDE}:root; rm -rf /"})),
        doc(allow({"AWS": 12345})),
        {"Statement": "not a list"},
        {"Statement": [None, 3, "x"]},
        [],
        None,
        "text",
    ],
)
def test_what_is_not_a_caller_or_not_a_shape_it_reads_is_left_out(document):
    assert trust_principals(document) == []


def test_a_policy_names_at_most_fifty_principals():
    many = doc(allow({"AWS": [f"{i:012d}" for i in range(500)]}))
    assert len(trust_principals(many)) == 50


# ---- what the index records for the two calls


def update_record(document, **kw):
    rec = {
        "eventSource": "iam.amazonaws.com",
        "eventName": "UpdateAssumeRolePolicy",
        "requestParameters": {"roleName": "ops-admin", "policyDocument": json.dumps(document)},
        "responseElements": None,
    }
    return {**rec, **kw}


def test_an_update_of_a_trust_policy_issues_an_entry_per_principal():
    out = issued_by(
        update_record(doc(allow({"AWS": [OUTSIDE, f"arn:aws:iam::{ACCT}:role/ci"]}))),
        "iam.amazonaws.com",
        "UpdateAssumeRolePolicy",
    )
    assert out == (
        (TRUSTED_BY, f"ops-admin|account:{OUTSIDE}"),
        (TRUSTED_BY, f"ops-admin|arn:aws:iam::{ACCT}:role/ci"),
    )


@pytest.mark.parametrize(
    "rec",
    [
        update_record(
            doc(allow({"AWS": OUTSIDE})), errorCode="AccessDenied"
        ),  # a failed call hands over nothing
        update_record(
            doc(allow({"AWS": OUTSIDE})), requestParameters={"roleName": "bad name!", "policyDocument": "{}"}
        ),
        {
            **update_record(doc()),
            "requestParameters": {"roleName": "ops-admin", "policyDocument": "{not json"},
        },
        {
            **update_record(doc()),
            "requestParameters": {"roleName": "ops-admin", "policyDocument": "x" * (MAX_TRUST_POLICY + 1)},
        },
        {**update_record(doc()), "requestParameters": {"roleName": "ops-admin"}},
        {**update_record(doc()), "requestParameters": None},
    ],
)
def test_a_failed_or_hostile_update_issues_nothing(rec):
    assert issued_by(rec, "iam.amazonaws.com", "UpdateAssumeRolePolicy") is None


def test_the_real_captured_record_is_read():
    """The Stratus `iam-backdoor-role` capture: the policy keeps the EC2 service statement and adds an outside account."""
    found = []
    for path in glob.glob("tests/captured/iam-backdoor-role/**/*.json*", recursive=True):
        raw = Path(path).read_bytes()
        raw = gzip.decompress(raw) if path.endswith(".gz") else raw
        found += [
            r for r in json.loads(raw).get("Records", []) if r.get("eventName") == "UpdateAssumeRolePolicy"
        ]
    assert found, "the capture holds no UpdateAssumeRolePolicy record"
    out = issued_by(found[0], "iam.amazonaws.com", "UpdateAssumeRolePolicy")
    assert out is not None and all(k == TRUSTED_BY for k, _ in out)
    assert [v.partition("|")[2] for _, v in out] == [
        "account:444455556666"
    ]  # the service principal is left out


def assume_record(role="ops-admin", caller=None, session="s1"):
    return {
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "requestParameters": {"roleArn": f"arn:aws:iam::{ACCT}:role/{role}"},
        "responseElements": {
            "credentials": {"accessKeyId": "ASIAEXAMPLE0000001"},
            "assumedRoleUser": {
                "assumedRoleId": f"AROAEXAMPLE:{session}",
                "arn": f"arn:aws:sts::{ACCT}:assumed-role/{role}/{session}",
            },
        },
        "userIdentity": caller or {"type": "AWSAccount", "accountId": OUTSIDE, "principalId": "AIDAEXAMPLE"},
    }


def test_an_assume_role_row_records_the_role_and_who_called():
    out = dict(issued_by(assume_record(), "sts.amazonaws.com", "AssumeRole"))
    assert out[ASSUMED_BY] == f"ops-admin|{OUTSIDE}||"
    user = {"type": "IAMUser", "accountId": ACCT, "arn": f"arn:aws:iam::{ACCT}:user/alice"}
    assert (
        dict(issued_by(assume_record(caller=user), "sts.amazonaws.com", "AssumeRole"))[ASSUMED_BY]
        == f"ops-admin|{ACCT}|{user['arn']}|"
    )
    session = {
        "type": "AssumedRole",
        "accountId": ACCT,
        "arn": f"arn:aws:sts::{ACCT}:assumed-role/ci/run1",
        "sessionContext": {"sessionIssuer": {"arn": f"arn:aws:iam::{ACCT}:role/ci"}},
    }
    got = dict(issued_by(assume_record(caller=session), "sts.amazonaws.com", "AssumeRole"))[ASSUMED_BY]
    assert got == f"ops-admin|{ACCT}|{session['arn']}|arn:aws:iam::{ACCT}:role/ci"
    assert (
        issued_by({**assume_record(), "errorCode": "AccessDenied"}, "sts.amazonaws.com", "AssumeRole") is None
    )


# ---- matching a caller against the policy


@pytest.mark.parametrize(
    "principal,account,arn,issuer,expected",
    [
        ("*", "", "", "", True),
        (f"account:{OUTSIDE}", OUTSIDE, "", "", True),
        (f"account:{OUTSIDE}", "", f"arn:aws:iam::{OUTSIDE}:user/mallory", "", True),  # account from the ARN
        (f"account:{OUTSIDE}", ACCT, "", "", False),
        (f"account:{OUTSIDE}", "", "", "", False),
        (f"arn:aws:iam::{ACCT}:user/alice", ACCT, f"arn:aws:iam::{ACCT}:user/alice", "", True),
        (
            f"arn:aws:iam::{ACCT}:role/ci",
            ACCT,
            f"arn:aws:sts::{ACCT}:assumed-role/ci/run1",
            f"arn:aws:iam::{ACCT}:role/ci",
            True,
        ),
        (
            f"arn:aws:iam::{ACCT}:role/ci",
            ACCT,
            f"arn:aws:sts::{ACCT}:assumed-role/other/run1",
            f"arn:aws:iam::{ACCT}:role/other",
            False,
        ),
    ],
)
def test_a_caller_is_matched_against_a_principal(principal, account, arn, issuer, expected):
    assert principal_matches(principal, account, arn, issuer) is expected


def test_a_role_session_is_one_caller_whatever_its_session_name():
    a = caller_key(ACCT, f"arn:aws:sts::{ACCT}:assumed-role/ci/run1", f"arn:aws:iam::{ACCT}:role/ci")
    b = caller_key(ACCT, f"arn:aws:sts::{ACCT}:assumed-role/ci/run2", f"arn:aws:iam::{ACCT}:role/ci")
    assert a == b == f"arn:aws:iam::{ACCT}:role/ci"
    assert caller_key(OUTSIDE, "", "") == f"account:{OUTSIDE}" and caller_key("", "", "") == ""


def test_acting_as_follows_the_role_the_caller_got_and_only_that_one():
    found = {(TRUSTED_BY, f"ops-admin|account:{OUTSIDE}"): "T"}
    trusted = trusted_index(found)
    into_role = make_row(issued=((ASSUMED_BY, f"ops-admin|{OUTSIDE}||"),), pid=None, ak=None)
    other_role = make_row(issued=((ASSUMED_BY, f"other-role|{OUTSIDE}||"),), pid=None, ak=None)
    assert acting_as(into_role, found, trusted) == ["T"]
    assert (
        acting_as(other_role, found, trusted) == [] and acting_as(into_role, found) == []
    )  # needs `trusted`


# ---- the scenario, end to end


def test_scenario_07_follows_the_outside_account_but_not_the_ci_that_assumed_the_role_before(fixtures):
    scope = scope_of(fixtures, "07_trust_backdoor")
    by_via = {}
    for e in scope.events:
        by_via.setdefault(e.via, []).append(e.event.event_name)
    assert by_via[f"trusted_by:ops-admin|account:{OUTSIDE}"] == ["AssumeRole"]
    assert by_via["access_key_id:ASIAIOSFODNN7EXT001"] == [
        "ListUsers",
        "GetSecretValue",
    ]  # the outside session, followed
    assert [t.kind for t in scope.taint.identities] == [
        "trusted_by",
        "trusted_by",
        "access_key_id",
    ]  # no assumed_by fact
    # the CI is named by the policy too, but it assumed the role before the change: its calls are not the attacker's
    assert not any(
        e.event.user_identity.access_key_id in ("ASIAIOSFODNN7OPS001", "ASIAIOSFODNN7OPS002")
        for e in scope.events
    )
    assert not any(e.event.event_name == "PutObject" for e in scope.events)


def test_scenario_07_the_plan_and_exposure_say_who_the_new_policy_names(fixtures):
    from controlzee.plan import build_plan

    scope = scope_of(fixtures, "07_trust_backdoor")
    plan = build_plan(scope)["actions"]
    step = next(a for a in plan if a["title"] == "Undo a permission change")
    assert (
        step["operations"] == [] and "account:444455556666" in step["caution"]
    )  # a manual step, naming the principals
    assert (
        step["commands"][0] == "aws iam get-role --role-name ops-admin --query Role.AssumeRolePolicyDocument"
    )
    assert any(
        o["op"] == "revoke_role_sessions" and o["args"]["role"] == "ops-admin"
        for a in plan
        for o in a["operations"]
    )
    assert any("trust policy of role ops-admin was changed" in n for n in _trust_policy_notes(scope))


def test_a_policy_that_names_everyone_is_called_out(fixtures):
    scope = scope_of(fixtures, "07_trust_backdoor")
    wide = scope.model_copy(
        update={
            "taint": scope.taint.model_copy(
                update={"identities": [scope.taint.identities[0].model_copy(update={"value": "ops-admin|*"})]}
            )
        }
    )
    note = _trust_policy_notes(wide)[0]
    assert "names everyone (*)" in note and "any principal that can reach STS can assume it" in note


# ---- who had already assumed the role (the history that separates the added principals from the kept ones)


def test_a_wildcard_policy_taints_a_new_caller_but_not_one_that_assumed_the_role_before(tmp_path):
    from controlzee.ingest.load import IngestOptions, load_index
    from controlzee.model.ioc import Indicator, IndicatorKind, SeedSpec
    from controlzee.seed.match import run_seed
    from controlzee.taint.propagate import propagate

    seed = {
        "type": "IAMUser",
        "accountId": ACCT,
        "arn": f"arn:aws:iam::{ACCT}:user/ci-deploy",
        "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "principalId": "AIDAEXAMPLE",
    }
    legit = {
        "type": "IAMUser",
        "accountId": ACCT,
        "arn": f"arn:aws:iam::{ACCT}:user/alice",
        "principalId": "AIDALICE",
    }
    newcomer = {"type": "AWSAccount", "accountId": OUTSIDE, "principalId": "AIDAEXT"}

    def rec(i, when, ident, name, source, request, response=None):
        return {
            "eventVersion": "1.09",
            "eventID": f"e{i:03d}",
            "eventTime": when,
            "eventSource": source,
            "eventName": name,
            "awsRegion": "us-east-1",
            "recipientAccountId": ACCT,
            "userIdentity": ident,
            "requestParameters": request,
            "responseElements": response,
            "sourceIPAddress": "198.51.100.7",
            "userAgent": "t",
            "eventType": "AwsApiCall",
        }

    def assume(i, when, ident):
        return rec(
            i,
            when,
            ident,
            "AssumeRole",
            "sts.amazonaws.com",
            {"roleArn": f"arn:aws:iam::{ACCT}:role/ops-admin"},
            {
                "credentials": {"accessKeyId": f"ASIAEXAMPLE{i:07d}"},
                "assumedRoleUser": {
                    "assumedRoleId": f"AROAOPS:s{i}",
                    "arn": f"arn:aws:sts::{ACCT}:assumed-role/ops-admin/s{i}",
                },
            },
        )

    records = [
        assume(1, "2026-10-20T09:00:00Z", legit),  # alice used the role before the change
        rec(
            2,
            "2026-10-20T12:00:00Z",
            seed,
            "UpdateAssumeRolePolicy",
            "iam.amazonaws.com",
            {"roleName": "ops-admin", "policyDocument": json.dumps(doc(allow({"AWS": "*"})))},
        ),
        assume(
            3, "2026-10-20T12:10:00Z", legit
        ),  # alice again: she is not made the attacker's by the wildcard
        assume(4, "2026-10-20T12:20:00Z", newcomer),  # a caller never seen before
    ]
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "a.json").write_text(json.dumps({"Records": records}))
    index = load_index([tmp_path / "logs"], IngestOptions(workers=1))
    spec = SeedSpec(
        indicators=[Indicator(name="k", kind=IndicatorKind.ACCESS_KEY_ID, value="AKIAIOSFODNN7EXAMPLE")],
        expression="k",
    )
    marked = propagate(index, run_seed(index, spec).hits).marks
    ids = sorted(index.rows[pos][0] for pos in marked)
    assert ids == ["e002", "e004"]  # the change itself and the newcomer, not alice


# ---- the dry run's activity check does not use these entries: it has no history to tell legitimate callers apart


def test_the_activity_check_does_not_mistake_a_named_callers_assume_role_for_the_attacker(fixtures):
    scope = scope_of(fixtures, "07_trust_backdoor")
    later = scope.coverage.period_end
    row = make_row(
        ts=10**18,
        issued=((ASSUMED_BY, f"ops-admin|{OUTSIDE}||"),),
        pid=None,
        ak=None,
        source="sts.amazonaws.com",
        name="AssumeRole",
    )
    assert later is not None and find_new_activity([row], scope) == ([], 0)
