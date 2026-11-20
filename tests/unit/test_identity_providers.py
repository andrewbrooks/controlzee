"""Identity providers (W3b): a provider the attacker created or changed, and the logins through it that are followed.

An attacker who plants an OIDC or SAML provider (or changes one, or names one in a role's trust policy) gets role
credentials without an access key. A provider they created is theirs for every login; one they changed or named only
for subjects that had not logged in through it before the change.
"""

import json

import pytest

from controlzee.ingest.load import IngestOptions, load_index
from controlzee.model.ioc import Indicator, IndicatorKind, SeedSpec
from controlzee.seed.match import run_seed
from controlzee.taint.propagate import acting_as, assumed_via, propagate, trusted_index
from controlzee.taint.rules import (
    ASSUMED_BY,
    ASSUMED_VIA,
    ASSUMED_VIA_ROLE,
    ASSUMES,
    CHANGED_PROVIDER,
    PROVIDER,
    TRUSTED_BY,
    issued_by,
    trust_principals,
)
from tests.helpers import make_row

ACCT = "111122223333"
OIDC = f"arn:aws:iam::{ACCT}:oidc-provider/token.example.com"
OIDC2 = f"arn:aws:iam::{ACCT}:oidc-provider/idp.example.org/tenant1"
SAML = f"arn:aws:iam::{ACCT}:saml-provider/Corp-SSO"
IAM, STS = "iam.amazonaws.com", "sts.amazonaws.com"


# ---- the provider-management calls


def call(name, request=None, response=None, **kw):
    return {
        "eventSource": IAM,
        "eventName": name,
        "requestParameters": request,
        "responseElements": response,
        **kw,
    }


# (call, where the ARN is, its field, a good ARN, the kind issued, an ARN of the other provider type)
CALLS = [
    ("CreateOpenIDConnectProvider", "response", "openIDConnectProviderArn", OIDC, PROVIDER, SAML),
    ("CreateSAMLProvider", "response", "sAMLProviderArn", SAML, PROVIDER, OIDC),
    (
        "UpdateOpenIDConnectProviderThumbprint",
        "request",
        "openIDConnectProviderArn",
        OIDC,
        CHANGED_PROVIDER,
        SAML,
    ),
    (
        "AddClientIDToOpenIDConnectProvider",
        "request",
        "openIDConnectProviderArn",
        OIDC,
        CHANGED_PROVIDER,
        SAML,
    ),
    ("UpdateSAMLProvider", "request", "sAMLProviderArn", SAML, CHANGED_PROVIDER, OIDC),
]


def provider_call(name, side, field, arn, **kw):
    body = {field: arn}
    return call(name, **({"request": body} if side == "request" else {"response": body}), **kw)


@pytest.mark.parametrize("name,side,field,arn,kind,_", CALLS)
def test_each_provider_call_issues_its_kind(name, side, field, arn, kind, _):
    assert issued_by(provider_call(name, side, field, arn), IAM, name) == ((kind, arn),)


@pytest.mark.parametrize("name,side,field,arn,kind,wrong_type", CALLS)
def test_a_failed_call_or_a_value_that_is_not_the_right_shape_issues_nothing(
    name, side, field, arn, kind, wrong_type
):
    bad = [
        wrong_type,  # a SAML ARN where an OIDC one belongs, and the other way round
        arn + "|x",
        arn + "\n",  # a trailing newline must not slip past the `$`
        arn + "\x00",
        arn + "\x1b[31m",
        arn + " ",
        arn.replace("iam::" + ACCT, "iam::12345"),
        arn.replace(":iam::", ":sts::"),
        arn + "a" * 600,
        "",
        None,
        12,
        [arn],
    ]
    for value in bad:
        assert issued_by(provider_call(name, side, field, value), IAM, name) is None, repr(value)
    failed = provider_call(name, side, field, arn, errorCode="AccessDenied")
    assert issued_by(failed, IAM, name) is None
    assert issued_by(call(name), IAM, name) is None  # no request or response at all


def test_other_partitions_are_read():
    arn = "arn:aws-us-gov:iam::111122223333:saml-provider/Corp"
    rec = provider_call("CreateSAMLProvider", "response", "sAMLProviderArn", arn)
    assert issued_by(rec, IAM, "CreateSAMLProvider") == ((PROVIDER, arn),)


# ---- the two logins


def web_login(provider=OIDC, subject="user-1", role="FederatedWebIdentityRole", **kw):
    """The documented AssumeRoleWithWebIdentity record, trimmed."""
    rec = {
        "eventSource": STS,
        "eventName": "AssumeRoleWithWebIdentity",
        "recipientAccountId": ACCT,
        "userIdentity": {
            "type": "WebIdentityUser",
            "principalId": f"{provider}:app-id:{subject}",
            "userName": subject,
            "identityProvider": provider,
        },
        "requestParameters": {"roleArn": f"arn:aws:iam::{ACCT}:role/{role}", "roleSessionName": "sess"},
        "responseElements": {
            "credentials": {"accessKeyId": "ASIAIOSFODNN7EXAMPLE", "sessionToken": "blob"},
            "subjectFromWebIdentityToken": subject,
            "assumedRoleUser": {
                "assumedRoleId": "AROAEXAMPLEROLEID:sess",
                "arn": f"arn:aws:sts::{ACCT}:assumed-role/{role}/sess",
            },
            "provider": provider,
            "audience": "app-id",
        },
    }
    return {**rec, **kw}


def saml_login(provider=SAML, subject="alice@example.com", role="SamlRole", **kw):
    rec = {
        "eventSource": STS,
        "eventName": "AssumeRoleWithSAML",
        "userIdentity": {"type": "SAMLUser", "userName": subject},
        "requestParameters": {
            "roleArn": f"arn:aws:iam::{ACCT}:role/{role}",
            "principalArn": provider,
            "roleSessionName": "sess",
            "sAMLAssertionID": "_abc",
        },
        "responseElements": {
            "credentials": {"accessKeyId": "ASIAIOSFODNN7SAML01"},
            "subject": subject,
            "assumedRoleUser": {
                "assumedRoleId": "AROASAMLROLEID:sess",
                "arn": f"arn:aws:sts::{ACCT}:assumed-role/{role}/sess",
            },
        },
    }
    return {**rec, **kw}


def test_a_web_identity_login_hands_over_the_credentials_the_role_and_the_provider_and_subject():
    out = dict(issued_by(web_login(), STS, "AssumeRoleWithWebIdentity"))
    assert out["access_key_id"] == "ASIAIOSFODNN7EXAMPLE"
    assert out[ASSUMES] == "AROAEXAMPLEROLEID"
    assert out[ASSUMED_VIA] == f"{OIDC}|user-1"
    assert out[ASSUMED_VIA_ROLE] == "FederatedWebIdentityRole"


def test_a_saml_login_hands_over_the_same_things():
    out = dict(issued_by(saml_login(), STS, "AssumeRoleWithSAML"))
    assert out["access_key_id"] == "ASIAIOSFODNN7SAML01"
    assert out[ASSUMES] == "AROASAMLROLEID"
    assert out[ASSUMED_VIA] == f"{SAML}|alice@example.com"
    assert out[ASSUMED_VIA_ROLE] == "SamlRole"


def test_the_subject_falls_back_to_the_user_name_and_may_be_empty():
    no_subject = web_login()
    del no_subject["responseElements"]["subjectFromWebIdentityToken"]
    assert dict(issued_by(no_subject, STS, "AssumeRoleWithWebIdentity"))[ASSUMED_VIA] == f"{OIDC}|user-1"
    del no_subject["userIdentity"]["userName"]
    assert dict(issued_by(no_subject, STS, "AssumeRoleWithWebIdentity"))[ASSUMED_VIA] == f"{OIDC}|"
    bare = saml_login()
    bare["userIdentity"] = {}
    del bare["responseElements"]["subject"]
    assert dict(issued_by(bare, STS, "AssumeRoleWithSAML"))[ASSUMED_VIA] == f"{SAML}|"


def test_the_provider_is_read_from_the_user_identity_only_when_it_is_an_arn():
    rec = web_login()
    del rec["responseElements"]["provider"]
    assert dict(issued_by(rec, STS, "AssumeRoleWithWebIdentity"))[ASSUMED_VIA] == f"{OIDC}|user-1"
    rec["userIdentity"]["identityProvider"] = "cognito-identity.amazonaws.com"  # an issuer name, not an ARN
    out = dict(issued_by(rec, STS, "AssumeRoleWithWebIdentity"))
    assert ASSUMED_VIA not in out and ASSUMED_VIA_ROLE not in out  # no provider fact ...
    assert out["access_key_id"] == "ASIAIOSFODNN7EXAMPLE"  # ... but the credentials are still handed over


@pytest.mark.parametrize(
    "provider",
    [
        SAML,
        OIDC + "|x",
        OIDC + "\n",
        OIDC + "\x00",
        OIDC + "a" * 500,
        "",
        None,
        5,
        f"arn:aws:iam::{ACCT}:role/x",
    ],
)
def test_a_provider_that_is_not_the_right_shape_makes_no_fact(provider):
    rec = web_login()
    rec["responseElements"]["provider"] = provider
    rec["userIdentity"]["identityProvider"] = provider
    assert ASSUMED_VIA not in dict(issued_by(rec, STS, "AssumeRoleWithWebIdentity"))
    wrong = saml_login()
    wrong["requestParameters"]["principalArn"] = provider if provider != SAML else OIDC
    assert ASSUMED_VIA not in dict(issued_by(wrong, STS, "AssumeRoleWithSAML"))


@pytest.mark.parametrize("subject", ["a|b", "a\nb", "a\x00", "\x1b[31m", "x" * 300, "a​b"])
def test_a_subject_that_cannot_be_kept_safely_is_empty_so_it_counts_as_never_seen(subject):
    out = dict(issued_by(web_login(subject=subject), STS, "AssumeRoleWithWebIdentity"))
    assert out[ASSUMED_VIA] == f"{OIDC}|"
    out = dict(issued_by(saml_login(subject=subject), STS, "AssumeRoleWithSAML"))
    assert out[ASSUMED_VIA] == f"{SAML}|"


def test_a_role_name_that_is_not_a_name_is_not_kept():
    rec = web_login()
    rec["responseElements"]["assumedRoleUser"]["arn"] = f"arn:aws:sts::{ACCT}:assumed-role/bad role!/sess"
    rec["requestParameters"]["roleArn"] = f"arn:aws:iam::{ACCT}:role/bad role!"
    out = dict(issued_by(rec, STS, "AssumeRoleWithWebIdentity"))
    assert ASSUMED_VIA in out and ASSUMED_VIA_ROLE not in out
    rec["requestParameters"]["roleArn"] = (
        f"arn:aws:iam::{ACCT}:role/ops\n"  # a trailing newline is not a name
    )
    assert ASSUMED_VIA_ROLE not in dict(issued_by(rec, STS, "AssumeRoleWithWebIdentity"))


@pytest.mark.parametrize(
    "role_arn,expected",
    [
        (f"arn:aws:iam::{ACCT}:role/FedRole", "FedRole"),
        (
            f"arn:aws:iam::{ACCT}:role/service/path/FedRole",
            "FedRole",
        ),  # the name is the last segment of the path
    ],
)
@pytest.mark.parametrize("login", [web_login, saml_login])
def test_the_role_falls_back_to_the_requested_role_when_the_session_arn_lacks_it(login, role_arn, expected):
    rec = login()
    rec["responseElements"]["assumedRoleUser"] = {"assumedRoleId": "AROAX:sess"}  # no arn
    rec["requestParameters"]["roleArn"] = role_arn
    name = rec["eventName"]
    assert dict(issued_by(rec, STS, name))[ASSUMED_VIA_ROLE] == expected
    del rec["responseElements"]["assumedRoleUser"]["assumedRoleId"]
    rec["requestParameters"] = {k: v for k, v in rec["requestParameters"].items() if k != "roleArn"}
    assert ASSUMED_VIA_ROLE not in dict(issued_by(rec, STS, name))


def test_the_session_arn_wins_over_the_requested_role():
    rec = web_login()
    rec["requestParameters"]["roleArn"] = f"arn:aws:iam::{ACCT}:role/Other"
    assert (
        dict(issued_by(rec, STS, "AssumeRoleWithWebIdentity"))[ASSUMED_VIA_ROLE] == "FederatedWebIdentityRole"
    )


@pytest.mark.parametrize(
    "arn",
    [
        "arn:aws:iam::\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668\u0669\u0660\u0661\u0662:oidc-provider/h.example.com",  # Arabic-Indic digits
        f"arn:aws:iam::{ACCT}:oidc-provider/h\u00e9.example.com",  # a non-ASCII letter
        f"arn:aws:iam::{ACCT}:oidc-provider/h.example.com\n",
        f"arn:aws-evil:iam::{ACCT}:oidc-provider/h.example.com",  # not a partition
        f"arn:awsx:iam::{ACCT}:oidc-provider/h.example.com",
    ],
)
def test_the_oidc_arn_is_ascii_and_in_a_real_partition(arn):
    from controlzee.taint.rules import OIDC_ARN

    assert OIDC_ARN.fullmatch(arn) is None
    rec = provider_call("CreateOpenIDConnectProvider", "response", "openIDConnectProviderArn", arn)
    assert issued_by(rec, IAM, "CreateOpenIDConnectProvider") is None


@pytest.mark.parametrize(
    "arn",
    [
        "arn:aws:iam::\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668\u0669\u0660\u0661\u0662:saml-provider/Corp",
        f"arn:aws:iam::{ACCT}:saml-provider/Cor\u00e9",
        f"arn:aws:iam::{ACCT}:saml-provider/Corp\n",
        f"arn:aws-evil:iam::{ACCT}:saml-provider/Corp",
    ],
)
def test_the_saml_arn_is_ascii_and_in_a_real_partition(arn):
    from controlzee.taint.rules import SAML_ARN

    assert SAML_ARN.fullmatch(arn) is None
    rec = provider_call("CreateSAMLProvider", "response", "sAMLProviderArn", arn)
    assert issued_by(rec, IAM, "CreateSAMLProvider") is None


@pytest.mark.parametrize("partition", ["aws", "aws-cn", "aws-us-gov"])
def test_each_real_partition_is_read(partition):
    arn = f"arn:{partition}:iam::{ACCT}:oidc-provider/h.example.com"
    rec = provider_call("CreateOpenIDConnectProvider", "response", "openIDConnectProviderArn", arn)
    assert issued_by(rec, IAM, "CreateOpenIDConnectProvider") == ((PROVIDER, arn),)


def test_a_failed_login_hands_over_nothing_and_makes_no_fact():
    assert issued_by(web_login(errorCode="AccessDenied"), STS, "AssumeRoleWithWebIdentity") is None
    assert issued_by(saml_login(errorCode="AccessDenied"), STS, "AssumeRoleWithSAML") is None


def test_an_ordinary_assume_role_makes_no_provider_fact():
    rec = web_login()
    rec["eventName"] = "AssumeRole"
    assert ASSUMED_VIA not in dict(issued_by(rec, STS, "AssumeRole") or ())


# ---- federated principals in a trust policy


def stmt(principal, action="sts:AssumeRoleWithWebIdentity", effect="Allow"):
    return {"Effect": effect, "Principal": principal, "Action": action}


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


@pytest.mark.parametrize(
    "document,expected",
    [
        (doc(stmt({"Federated": OIDC})), [f"federated:{OIDC}"]),
        (doc(stmt({"Federated": SAML}, "sts:AssumeRoleWithSAML")), [f"federated:{SAML}"]),
        (
            doc(stmt({"Federated": [OIDC, SAML]}, ["sts:AssumeRoleWithSAML", "s3:GetObject"])),
            sorted([f"federated:{OIDC}", f"federated:{SAML}"]),
        ),
        (doc(stmt({"Federated": OIDC}, "sts:*")), [f"federated:{OIDC}"]),
        (doc(stmt({"Federated": OIDC}, "*")), [f"federated:{OIDC}"]),
        (  # one statement may name both kinds of principal
            doc(
                stmt(
                    {"AWS": "444455556666", "Federated": OIDC},
                    ["sts:AssumeRole", "sts:AssumeRoleWithWebIdentity"],
                )
            ),
            sorted(["account:444455556666", f"federated:{OIDC}"]),
        ),
    ],
)
def test_the_providers_a_trust_policy_names(document, expected):
    assert trust_principals(document) == expected


@pytest.mark.parametrize(
    "document",
    [
        doc(stmt({"Federated": "cognito-identity.amazonaws.com"})),
        doc(stmt({"Federated": "accounts.google.com"})),
        doc(stmt({"Federated": f"{OIDC}|x"})),
        doc(stmt({"Federated": OIDC + "\n"})),
        doc(stmt({"Federated": OIDC + "a" * 500})),
        doc(stmt({"Federated": f"arn:aws:iam::{ACCT}:role/x"})),
        doc(stmt({"Federated": 7})),
        doc(stmt({"Federated": OIDC}, effect="Deny")),
        doc(stmt({"Federated": OIDC}, "sts:AssumeRole")),  # a provider cannot use plain AssumeRole
        doc(stmt({"Federated": OIDC}, "s3:GetObject")),
        doc(
            stmt({"AWS": "444455556666"}, "sts:AssumeRoleWithWebIdentity")
        ),  # an AWS principal needs AssumeRole
        doc(stmt("text", "sts:AssumeRoleWithWebIdentity")),
    ],
)
def test_what_is_not_a_provider_it_reads_is_left_out(document):
    assert trust_principals(document) == []


def test_the_federated_principals_of_a_policy_are_capped():
    many = doc(
        stmt({"Federated": [f"arn:aws:iam::{ACCT}:oidc-provider/h{i}.example.com" for i in range(500)]})
    )
    assert len(trust_principals(many)) == 50


def test_an_update_of_a_trust_policy_issues_a_federated_entry():
    rec = call(
        "UpdateAssumeRolePolicy",
        {"roleName": "ops-admin", "policyDocument": json.dumps(doc(stmt({"Federated": OIDC})))},
    )
    assert issued_by(rec, IAM, "UpdateAssumeRolePolicy") == ((TRUSTED_BY, f"ops-admin|federated:{OIDC}"),)


# ---- matching a row against the identities (no history yet)


def via_row(provider=OIDC, subject="s", role="FederatedWebIdentityRole"):
    return make_row(
        issued=((ASSUMED_VIA, f"{provider}|{subject}"), (ASSUMED_VIA_ROLE, role)), pid=None, ak=None
    )


def test_a_login_acts_as_the_provider_it_came_through_only():
    found = {(PROVIDER, OIDC): "P", (CHANGED_PROVIDER, OIDC): "C"}
    assert acting_as(via_row(), found) == ["P", "C"]
    assert acting_as(via_row(provider=OIDC2), found) == []
    assert acting_as(make_row(), found) == []
    assert assumed_via(via_row(subject="")) == (OIDC, "", "FederatedWebIdentityRole")
    assert assumed_via(make_row()) is None


def test_a_login_acts_as_a_federated_entry_for_its_role_and_provider_only():
    found = {(TRUSTED_BY, f"FederatedWebIdentityRole|federated:{OIDC}"): "T"}
    trusted = trusted_index(found)
    assert acting_as(via_row(), found, trusted) == ["T"]
    assert acting_as(via_row(), found) == []  # needs `trusted`
    assert acting_as(via_row(role="Other"), found, trusted) == []
    assert acting_as(via_row(provider=OIDC2), found, trusted) == []
    assert acting_as(via_row(role=""), found, trusted) == []


def test_a_federated_entry_is_not_matched_by_an_aws_caller():
    found = {(TRUSTED_BY, f"ops|federated:{OIDC}"): "T"}
    row = make_row(issued=((ASSUMED_BY, f"ops|{ACCT}|arn:aws:iam::{ACCT}:user/a|"),), pid=None, ak=None)
    assert acting_as(row, found, trusted_index(found)) == []


# ---- end to end


def event(i, when, ident, name, source, request, response=None, **kw):
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
        **kw,
    }


SEED = {
    "type": "IAMUser",
    "accountId": ACCT,
    "arn": f"arn:aws:iam::{ACCT}:user/ci-deploy",
    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "principalId": "AIDAEXAMPLE",
}


def seed_call(i, when, name, request=None, response=None):
    return event(i, when, SEED, name, IAM, request, response)


def login(i, when, rec, key=None):
    """A login record as event `i`: the documented record with an event id and time, and its own session key."""
    rec = {**rec, "eventID": f"e{i:03d}", "eventTime": when, "awsRegion": "us-east-1"}
    rec["responseElements"] = {
        **rec["responseElements"],
        "credentials": {"accessKeyId": key or f"ASIAEXAMPLE{i:08d}"},
    }
    return {
        "eventVersion": "1.09",
        "recipientAccountId": ACCT,
        "sourceIPAddress": "203.0.113.9",
        "userAgent": "t",
        "eventType": "AwsApiCall",
        **rec,
    }


def use(i, when, key):
    """A call made with the session key a login handed out."""
    ident = {"type": "AssumedRole", "accountId": ACCT, "accessKeyId": key, "principalId": "AROAZZ:sess"}
    return event(i, when, ident, "ListUsers", IAM, None)


def run(tmp_path, records):
    (tmp_path / "logs").mkdir(exist_ok=True)
    (tmp_path / "logs" / "a.json").write_text(json.dumps({"Records": records}))
    index = load_index([tmp_path / "logs"], IngestOptions(workers=1))
    spec = SeedSpec(
        indicators=[Indicator(name="k", kind=IndicatorKind.ACCESS_KEY_ID, value="AKIAIOSFODNN7EXAMPLE")],
        expression="k",
    )
    prop = propagate(index, run_seed(index, spec).hits)
    return [index.rows[pos][0] for pos in sorted(prop.marks)], prop


def create_oidc(i, when, arn=OIDC):
    return seed_call(i, when, "CreateOpenIDConnectProvider", None, {"openIDConnectProviderArn": arn})


def test_a_created_provider_is_followed_for_every_login_through_it_and_what_the_session_did(tmp_path):
    records = [
        create_oidc(1, "2026-10-20T12:00:00Z"),
        login(2, "2026-10-20T12:10:00Z", web_login(subject="anyone"), key="ASIAATTACKER00000001"),
        use(3, "2026-10-20T12:11:00Z", "ASIAATTACKER00000001"),
        login(4, "2026-10-20T12:12:00Z", web_login(provider=OIDC2, subject="anyone")),  # another provider
        login(5, "2026-10-20T12:13:00Z", saml_login(provider=SAML)),  # a SAML provider nobody created
    ]
    ids, prop = run(tmp_path, records)
    assert ids == ["e001", "e002", "e003"]
    assert (prop.identities[0].kind, prop.identities[0].value) == (PROVIDER, OIDC)


def test_a_created_provider_is_followed_whatever_the_subject_but_not_before_it_existed(tmp_path):
    records = [
        login(1, "2026-10-20T11:00:00Z", web_login(subject="u")),
        create_oidc(2, "2026-10-20T12:00:00Z"),
        login(
            3, "2026-10-20T12:10:00Z", web_login(subject="u")
        ),  # the same subject; no history filter applies
    ]
    ids, _ = run(tmp_path, records)
    assert ids == ["e002", "e003"]


def test_a_created_saml_provider_is_followed(tmp_path):
    records = [
        seed_call(
            1, "2026-10-20T12:00:00Z", "CreateSAMLProvider", {"name": "Corp-SSO"}, {"sAMLProviderArn": SAML}
        ),
        login(2, "2026-10-20T12:10:00Z", saml_login(subject="y")),
    ]
    ids, _ = run(tmp_path, records)
    assert ids == ["e001", "e002"]


@pytest.mark.parametrize(
    "change,request_,make_login",
    [
        (
            "UpdateOpenIDConnectProviderThumbprint",
            {"openIDConnectProviderArn": OIDC, "thumbprintList": ["a" * 40]},
            lambda s: web_login(subject=s),
        ),
        (
            "AddClientIDToOpenIDConnectProvider",
            {"openIDConnectProviderArn": OIDC, "clientID": "new-app"},
            lambda s: web_login(subject=s),
        ),
        ("UpdateSAMLProvider", {"sAMLProviderArn": SAML}, lambda s: saml_login(subject=s)),
    ],
)
def test_a_changed_provider_follows_a_new_subject_and_not_one_seen_before_the_change(
    tmp_path, change, request_, make_login
):
    records = [
        login(1, "2026-10-20T09:00:00Z", make_login("alice")),
        seed_call(2, "2026-10-20T12:00:00Z", change, request_, {}),
        login(3, "2026-10-20T12:10:00Z", make_login("alice")),  # alice is not made the attacker's
        login(4, "2026-10-20T12:20:00Z", make_login("mallory"), key="ASIAATTACKER00000002"),
        use(5, "2026-10-20T12:21:00Z", "ASIAATTACKER00000002"),
        login(6, "2026-10-20T12:30:00Z", make_login("")),  # no subject: counts as never seen
    ]
    ids, prop = run(tmp_path, records)
    assert ids == ["e002", "e004", "e005", "e006"]
    assert prop.identities[0].kind == CHANGED_PROVIDER


def test_seen_before_means_strictly_earlier_than_the_change(tmp_path):
    records = [
        seed_call(
            1,
            "2026-10-20T12:00:00Z",
            "UpdateOpenIDConnectProviderThumbprint",
            {"openIDConnectProviderArn": OIDC},
            {},
        ),
        login(2, "2026-10-20T12:00:00Z", web_login(subject="x")),  # the same second, later by id
        login(3, "2026-10-20T12:30:00Z", web_login(subject="x")),
    ]
    ids, _ = run(tmp_path, records)
    assert ids == ["e001", "e002", "e003"]


def test_a_subject_who_used_a_different_provider_before_is_still_new(tmp_path):
    records = [
        login(1, "2026-10-20T09:00:00Z", web_login(provider=OIDC2, subject="bob")),
        seed_call(
            2,
            "2026-10-20T12:00:00Z",
            "AddClientIDToOpenIDConnectProvider",
            {"openIDConnectProviderArn": OIDC},
            {},
        ),
        login(3, "2026-10-20T12:10:00Z", web_login(subject="bob")),
    ]
    ids, _ = run(tmp_path, records)
    assert ids == ["e002", "e003"]


def test_a_failed_earlier_login_is_not_history(tmp_path):
    records = [
        login(1, "2026-10-20T09:00:00Z", web_login(subject="carol", errorCode="AccessDenied")),
        seed_call(
            2,
            "2026-10-20T12:00:00Z",
            "AddClientIDToOpenIDConnectProvider",
            {"openIDConnectProviderArn": OIDC},
            {},
        ),
        login(3, "2026-10-20T12:10:00Z", web_login(subject="carol")),
    ]
    ids, _ = run(tmp_path, records)
    assert ids == ["e002", "e003"]


def trust_change(i, when, role, document):
    return seed_call(
        i, when, "UpdateAssumeRolePolicy", {"roleName": role, "policyDocument": json.dumps(document)}
    )


def test_a_role_that_now_trusts_a_provider_follows_a_new_subject_into_that_role_only(tmp_path):
    records = [
        login(1, "2026-10-20T09:00:00Z", web_login(subject="alice", role="ops-admin")),
        trust_change(2, "2026-10-20T12:00:00Z", "ops-admin", doc(stmt({"Federated": OIDC}))),
        login(3, "2026-10-20T12:10:00Z", web_login(subject="alice", role="ops-admin")),  # a regular
        login(
            4,
            "2026-10-20T12:20:00Z",
            web_login(subject="mallory", role="ops-admin"),
            key="ASIAATTACKER00000003",
        ),
        use(5, "2026-10-20T12:21:00Z", "ASIAATTACKER00000003"),
        login(6, "2026-10-20T12:30:00Z", web_login(subject="mallory", role="other-role")),  # not that role
        login(7, "2026-10-20T12:40:00Z", web_login(provider=OIDC2, subject="mallory", role="ops-admin")),
    ]
    ids, prop = run(tmp_path, records)
    assert ids == ["e002", "e004", "e005"]
    assert (prop.identities[0].kind, prop.identities[0].value) == (TRUSTED_BY, f"ops-admin|federated:{OIDC}")


def test_a_saml_provider_in_a_trust_policy_is_followed_the_same_way(tmp_path):
    records = [
        login(1, "2026-10-20T09:00:00Z", saml_login(subject="alice", role="ops-admin")),
        trust_change(
            2, "2026-10-20T12:00:00Z", "ops-admin", doc(stmt({"Federated": SAML}, "sts:AssumeRoleWithSAML"))
        ),
        login(3, "2026-10-20T12:10:00Z", saml_login(subject="alice", role="ops-admin")),
        login(4, "2026-10-20T12:20:00Z", saml_login(subject="mallory", role="ops-admin")),
    ]
    ids, _ = run(tmp_path, records)
    assert ids == ["e002", "e004"]


def test_a_legitimate_provider_nobody_tainted_is_not_followed(tmp_path):
    records = [
        seed_call(1, "2026-10-20T12:00:00Z", "ListUsers"),
        login(2, "2026-10-20T12:10:00Z", web_login(subject="alice")),
        login(3, "2026-10-20T12:20:00Z", saml_login(subject="bob")),
    ]
    ids, prop = run(tmp_path, records)
    assert ids == ["e001"]
    assert prop.identities == []


def test_a_failed_creation_taints_nothing(tmp_path):
    records = [
        event(
            1,
            "2026-10-20T12:00:00Z",
            SEED,
            "CreateOpenIDConnectProvider",
            IAM,
            None,
            None,
            errorCode="AccessDenied",
        ),
        login(2, "2026-10-20T12:10:00Z", web_login(subject="x")),
    ]
    ids, _ = run(tmp_path, records)
    assert ids == ["e001"]


def test_the_provider_facts_are_never_identities(tmp_path):
    records = [
        create_oidc(1, "2026-10-20T12:00:00Z"),
        trust_change(2, "2026-10-20T12:01:00Z", "r", doc(stmt({"Federated": OIDC}))),
        login(3, "2026-10-20T12:10:00Z", web_login(subject="x", role="r")),
        login(4, "2026-10-20T12:11:00Z", saml_login(subject="y")),
    ]
    _, prop = run(tmp_path, records)
    kinds = {t.kind for t in prop.identities}
    assert PROVIDER in kinds and TRUSTED_BY in kinds
    assert not kinds & {ASSUMED_VIA, ASSUMED_VIA_ROLE}
    assert not any(t.value.startswith((OIDC + "|", SAML + "|")) for t in prop.identities)


def test_the_scope_records_the_new_kinds_and_no_fact(tmp_path):
    from controlzee.scope import ScopeOptions, build_scope
    from controlzee.seed.spec import SpecParts, assemble, from_flags

    records = [
        seed_call(
            1, "2026-10-20T12:00:00Z", "CreateSAMLProvider", {"name": "Corp-SSO"}, {"sAMLProviderArn": SAML}
        ),
        login(2, "2026-10-20T12:10:00Z", saml_login(subject="y")),
    ]
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "a.json").write_text(json.dumps({"Records": records}))
    spec = assemble([SpecParts(indicators=from_flags(access_keys=["AKIAIOSFODNN7EXAMPLE"]))])
    scope = build_scope([tmp_path / "logs"], spec, ScopeOptions(workers=1)).scope
    assert [(t.kind, t.value) for t in scope.taint.identities][0] == ("provider_arn", SAML)
    assert {t.kind for t in scope.taint.identities} <= {"provider_arn", "access_key_id", "role_id"}
    assert [e.via for e in scope.events] == [None, f"provider_arn:{SAML}"]


# ---- a trailing newline passes `$` with match(), so every shape check uses fullmatch


def test_a_trailing_newline_is_not_part_of_any_name_or_principal():
    nl_account = "444455556666\n"
    nl_user = f"arn:aws:iam::{ACCT}:user/alice\n"
    assert trust_principals(doc(stmt({"AWS": nl_account}, "sts:AssumeRole"))) == []
    assert trust_principals(doc(stmt({"AWS": nl_user}, "sts:AssumeRole"))) == []
    policy = json.dumps(doc(stmt({"AWS": "*"}, "sts:AssumeRole")))
    update = call("UpdateAssumeRolePolicy", {"roleName": "ops\n", "policyDocument": policy})
    assert issued_by(update, IAM, "UpdateAssumeRolePolicy") is None
    fn = {
        "eventSource": "lambda.amazonaws.com",
        "eventName": "CreateFunction20150331",
        "requestParameters": {"functionName": "fn\n"},
        "responseElements": None,
    }
    assert issued_by(fn, "lambda.amazonaws.com", "CreateFunction20150331") is None


def test_older_shapes_refuse_non_ascii_look_alikes() -> None:
    from controlzee.taint import rules

    assert not rules._ACCOUNT.fullmatch("١" * 12)
    assert not rules._ROLE_NAME.fullmatch("rоle")
    assert not rules._FUNCTION_NAME.fullmatch("fé")
    assert not rules._IAM_PRINCIPAL.fullmatch("arn:awsx:iam::111122223333:root")
    assert rules._IAM_PRINCIPAL.fullmatch("arn:aws-cn:iam::111122223333:root")
