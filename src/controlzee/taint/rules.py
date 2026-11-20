"""What a successful call hands its caller: credentials and principals the caller then controls.

Each rule reads the response (and for EC2 the request) of one API call as CloudTrail logs it. Field names follow the API
reference of each action: IAM `CreateAccessKey` (accessKey.accessKeyId), `CreateUser` (user.userId), `CreateRole`
(role.roleId); STS `AssumeRole`, `GetSessionToken`, `GetFederationToken` (credentials.accessKeyId; CloudTrail redacts the
secret and session token but keeps the key id); EC2 `RunInstances` (instancesSet.items[].instanceId, and only when
requestParameters.iamInstanceProfile is set, since otherwise the instance has no credentials).

Lambda: `CreateFunction`, `UpdateFunctionCode` and `UpdateFunctionConfiguration` (CloudTrail logs their names with an API
version suffix, such as CreateFunction20150331, which is removed) taint the function by name. Its execution-role sessions
are named after it (arn:...:assumed-role/<role>/<function name>), so a function the attacker created, or whose code they
replaced, acts for them from that moment. Calls the function made before the change are not followed.

Trust-policy backdoors: `iam:UpdateAssumeRolePolicy` on a role hands the attacker whoever its new policy names. The log
holds the whole new policy and not the old one, so each `Allow` principal of AWS kind is issued as a `trusted_by`
identity, "<role name>|<principal>". An `AssumeRole` row carries who called and which role it got a session of
(`assumed_by`), so a later call into that role by a principal the policy names can be recognised (see propagate.py).

Identity providers: `CreateOpenIDConnectProvider` and `CreateSAMLProvider` taint the provider the attacker made
(`provider_arn`); the calls that change an existing one (`UpdateOpenIDConnectProviderThumbprint`,
`AddClientIDToOpenIDConnectProvider`, `UpdateSAMLProvider`) taint it as `changed_provider`. `AssumeRoleWithWebIdentity` and
`AssumeRoleWithSAML` hand over credentials like `AssumeRole`, and record which provider and subject they came through as
facts (`assumed_via`), so a login through a provider the attacker holds can be recognised (see propagate.py). A trust
policy that names a provider (`Principal: {"Federated": <arn>}`) is issued as `trusted_by` "<role>|federated:<arn>".

Runs inside the index workers on every record, so the common case (any other call) must cost one dict lookup.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, Final

import orjson

from controlzee.ingest.index import Issued

# kinds of tainted identity, and how an event is recognised as acting as one
ACCESS_KEY: Final = "access_key_id"  # userIdentity.accessKeyId
PRINCIPAL: Final = "principal_id"  # userIdentity.principalId, whole (an IAM user's userId)
ROLE: Final = "role_id"  # any session of the role: principalId "<roleId>:<session name>"
INSTANCE: Final = (
    "instance_id"  # the instance's role sessions: an AssumedRole principalId "<roleId>:<instance id>"
)
FUNCTION: Final = (
    "function_name"  # the function's role sessions: an AssumedRole principalId "<roleId>:<function name>"
)
TRUSTED_BY: Final = "trusted_by"  # "<role name>|<principal>": a principal the role's trust policy named after a tainted change
PROVIDER: Final = "provider_arn"  # an OIDC or SAML provider a tainted call created
CHANGED_PROVIDER: Final = "changed_provider"  # an existing provider a tainted call changed
KINDS: Final = (ACCESS_KEY, PRINCIPAL, ROLE, INSTANCE, FUNCTION, TRUSTED_BY, PROVIDER, CHANGED_PROVIDER)
API_VERSION: Final = re.compile(r"\d{8}(v\d+)?$")  # Lambda logs event names like CreateFunction20150331
_FUNCTION_NAME: Final = re.compile(r"^[\w-]{1,64}$")
# Not a taint: the role an AssumeRole call obtained a session of (assumedRoleUser.assumedRoleId is "<roleId>:<session>").
# The call is made by whoever assumes the role, often from another account and with no tainted key, so this is how the
# entry into a role the attacker created is found.
ASSUMES: Final = "assumes_role"
# Also not a taint: who called an AssumeRole and into which role, "<role name>|<account>|<arn>|<session issuer arn>" (any
# of the last three may be empty), so a call into a role whose trust policy was changed can be tied to a named principal.
ASSUMED_BY: Final = "assumed_by"
# Also not a taint: the provider and subject of a successful AssumeRoleWithWebIdentity / AssumeRoleWithSAML,
# "<provider arn>|<subject>" (the subject may be empty), and (kept apart, since the contract fixes the form above) the name
# of the role it gave a session of.
ASSUMED_VIA: Final = "assumed_via"
ASSUMED_VIA_ROLE: Final = "assumed_via_role"
OIDC_ARN: Final = re.compile(r"^arn:aws[\w-]*:iam::\d{12}:oidc-provider/[\w./:@-]{1,400}$")
SAML_ARN: Final = re.compile(r"^arn:aws[\w-]*:iam::\d{12}:saml-provider/[\w+=,.@-]{1,128}$")
MAX_SUBJECT: Final = 256
# UNVERIFIED paths (believed from naming patterns, not yet captured from a real account). Change them here only.
OIDC_CREATED_ARN_PATH: Final = (
    "openIDConnectProviderArn",
)  # in responseElements of CreateOpenIDConnectProvider
SAML_CREATED_ARN_PATH: Final = ("sAMLProviderArn",)  # in responseElements of CreateSAMLProvider
OIDC_CHANGED_ARN_PATH: Final = (
    "openIDConnectProviderArn",
)  # in requestParameters of the two OIDC change calls
SAML_CHANGED_ARN_PATH: Final = ("sAMLProviderArn",)  # in requestParameters of UpdateSAMLProvider
SAML_SUBJECT_PATH: Final = (
    "subject",
)  # in responseElements of AssumeRoleWithSAML; else userIdentity.userName
# Documented by AWS (AssumeRoleWithWebIdentity example): provider and subject are in responseElements; the provider may
# also be userIdentity.identityProvider, which is sometimes an issuer name and not an ARN.
WEB_PROVIDER_PATH: Final = ("provider",)
WEB_SUBJECT_PATH: Final = ("subjectFromWebIdentityToken",)
SAML_PROVIDER_REQUEST_PATH: Final = ("principalArn",)  # documented: requestParameters of AssumeRoleWithSAML
_ROLE_NAME: Final = re.compile(r"^[\w+=,.@-]{1,64}$")
_ACCOUNT: Final = re.compile(r"^\d{12}$")
_IAM_PRINCIPAL: Final = re.compile(r"^arn:aws[\w-]*:iam::(\d{12}):(root|(?:user|role)/[\w+=,./@-]{1,512})$")
MAX_TRUST_POLICY: Final = 20_000  # characters of a logged policy document that are read; AWS allows far less
MAX_TRUST_PRINCIPALS: Final = 50


def _get(d: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(d, dict):
            return None
        d = d.get(key)
    return d


def _one(kind: str, *path: str) -> Callable[[Any, Any], list[tuple[str, str]]]:
    def rule(request: Any, response: Any) -> list[tuple[str, str]]:
        v = _get(response, *path)
        return [(kind, v)] if isinstance(v, str) and v else []

    return rule


def _run_instances(request: Any, response: Any) -> list[tuple[str, str]]:
    if not _get(request, "iamInstanceProfile"):
        return []
    items = _get(response, "instancesSet", "items")
    if not isinstance(items, list):
        return []
    return [(INSTANCE, i) for item in items if isinstance(i := _get(item, "instanceId"), str) and i]


_CREDENTIALS = _one(ACCESS_KEY, "credentials", "accessKeyId")


def _function(request: Any, response: Any) -> list[tuple[str, str]]:
    """The function a Lambda call created or changed. The name may be given as a full or partial ARN or with a qualifier."""
    for source in (request, response):
        value = _get(source, "functionName")
        if isinstance(value, str):
            name = value.split(":function:", 1)[-1].split(":")[0]
            if _FUNCTION_NAME.match(name):
                return [(FUNCTION, name)]
    return []


def _assume_role(request: Any, response: Any) -> list[tuple[str, str]]:
    out = _CREDENTIALS(request, response)
    session = _get(response, "assumedRoleUser", "assumedRoleId")
    if isinstance(session, str) and (role := session.partition(":")[0]):
        out.append((ASSUMES, role))
    return out


def _actions(statement: dict[str, Any]) -> list[str]:
    action = statement.get("Action")
    return [
        a
        for a in ([action] if isinstance(action, str) else action if isinstance(action, list) else [])
        if isinstance(a, str)
    ]


def _grants_assume_role(statement: dict[str, Any]) -> bool:
    return any(a in ("sts:AssumeRole", "sts:*", "*") for a in _actions(statement))


def _grants_federated(statement: dict[str, Any]) -> bool:
    return any(
        a in ("sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML", "sts:*", "*")
        for a in _actions(statement)
    )


def _as_list(value: Any) -> list[Any]:
    return [value] if isinstance(value, str) else value if isinstance(value, list) else []


def trust_principals(document: Any) -> list[str]:
    """The principals a role's trust policy allows to assume it: "*", "account:<id>" (an account or its root), a user or
    role ARN, or "federated:<arn>" for an OIDC or SAML provider. Anything else (services, other federation such as
    Cognito, Deny statements) is left out. AWS principals need an `sts:AssumeRole` statement and providers one that grants
    `AssumeRoleWithWebIdentity` or `AssumeRoleWithSAML`. The document is hostile input: it is size-capped by the caller,
    every value is shape-checked, and nothing that fails the check is kept."""
    if not isinstance(document, dict):
        return []
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    found: set[str] = set()
    for st in statements[:MAX_TRUST_PRINCIPALS]:
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal")
        if _grants_assume_role(st):
            if principal == "*":
                found.add("*")
            aws = principal.get("AWS") if isinstance(principal, dict) else None
            for value in _as_list(aws)[:MAX_TRUST_PRINCIPALS]:
                if value == "*":
                    found.add("*")
                elif isinstance(value, str) and _ACCOUNT.match(value):
                    found.add(f"account:{value}")
                elif isinstance(value, str) and (m := _IAM_PRINCIPAL.match(value)):
                    found.add(f"account:{m.group(1)}" if m.group(2) == "root" else value)
        if isinstance(principal, dict) and _grants_federated(st):
            for value in _as_list(principal.get("Federated"))[:MAX_TRUST_PRINCIPALS]:
                if isinstance(value, str) and (OIDC_ARN.fullmatch(value) or SAML_ARN.fullmatch(value)):
                    found.add(f"federated:{value}")
    return sorted(found)[:MAX_TRUST_PRINCIPALS]


def _trust_policy(request: Any, response: Any) -> list[tuple[str, str]]:
    role, document = _get(request, "roleName"), _get(request, "policyDocument")
    if not (isinstance(role, str) and _ROLE_NAME.match(role)):
        return []
    if isinstance(document, str):
        if len(document) > MAX_TRUST_POLICY:
            return []
        try:
            document = orjson.loads(document)
        except orjson.JSONDecodeError:
            return []
    return [(TRUSTED_BY, f"{role}|{p}") for p in trust_principals(document)]


def _plain(value: Any, prefix: str = "") -> str:
    """`value` if it is a short string that cannot break the packed "a|b|c|d" form of `assumed_by`, else empty."""
    return (
        value
        if isinstance(value, str) and len(value) <= 600 and "|" not in value and value.startswith(prefix)
        else ""
    )


def _assumed_by(rec: dict[str, Any]) -> list[tuple[str, str]]:
    """Which role an AssumeRole call got a session of, and who called. This runs for every AssumeRole record, so the
    checks are plain string tests: the values are only compared with trust-policy principals later, never run."""
    session = _get(rec.get("responseElements"), "assumedRoleUser", "arn")
    role = session.partition(":assumed-role/")[2].partition("/")[0] if isinstance(session, str) else ""
    if not _ROLE_NAME.match(role):
        return []
    caller = rec.get("userIdentity")
    account = _plain(_get(caller, "accountId"))
    if len(account) != 12 or not account.isdigit():
        account = ""
    arn = _plain(_get(caller, "arn"), "arn:")
    issuer = _plain(_get(caller, "sessionContext", "sessionIssuer", "arn"), "arn:")
    return [(ASSUMED_BY, f"{role}|{account}|{arn}|{issuer}")]


def _arn_from(
    kind: str, shape: re.Pattern[str], side: int, *path: str
) -> Callable[[Any, Any], list[tuple[str, str]]]:
    """A provider ARN read from the request (`side` 0) or the response (1) and kept only if it has the shape of `shape`."""

    def rule(request: Any, response: Any) -> list[tuple[str, str]]:
        v = _get((request, response)[side], *path)
        return [(kind, v)] if isinstance(v, str) and shape.fullmatch(v) else []

    return rule


def _subject(value: Any) -> str:
    """A login subject for the history of who used a provider, or empty. It comes from a token the attacker may have
    written, so one that cannot be kept safely in a packed value is dropped: an empty subject counts as never seen, which
    errs towards following the login."""
    return (
        value
        if isinstance(value, str) and len(value) <= MAX_SUBJECT and value.isprintable() and "|" not in value
        else ""
    )


def _federated_facts(provider: str, subject: Any, rec: dict[str, Any]) -> list[tuple[str, str]]:
    out = [(ASSUMED_VIA, f"{provider}|{_subject(subject)}")]
    session = _get(rec.get("responseElements"), "assumedRoleUser", "arn")
    role = session.partition(":assumed-role/")[2].partition("/")[0] if isinstance(session, str) else ""
    if _ROLE_NAME.match(role):
        out.append((ASSUMED_VIA_ROLE, role))
    return out


def _assumed_via_web(rec: dict[str, Any]) -> list[tuple[str, str]]:
    response = rec.get("responseElements")
    provider = _get(response, *WEB_PROVIDER_PATH)
    if not (isinstance(provider, str) and OIDC_ARN.fullmatch(provider)):
        provider = _get(rec.get("userIdentity"), "identityProvider")
        if not (isinstance(provider, str) and OIDC_ARN.fullmatch(provider)):
            return []
    subject = _get(response, *WEB_SUBJECT_PATH)
    if not isinstance(subject, str):
        subject = _get(rec.get("userIdentity"), "userName")
    return _federated_facts(provider, subject, rec)


def _assumed_via_saml(rec: dict[str, Any]) -> list[tuple[str, str]]:
    provider = _get(rec.get("requestParameters"), *SAML_PROVIDER_REQUEST_PATH)
    if not (isinstance(provider, str) and SAML_ARN.fullmatch(provider)):
        return []
    subject = _get(rec.get("responseElements"), *SAML_SUBJECT_PATH)
    if not isinstance(subject, str):
        subject = _get(rec.get("userIdentity"), "userName")
    return _federated_facts(provider, subject, rec)


# Facts a call records beyond what its rule issues; these read the whole record (the caller too).
FACTS: Final[dict[tuple[str, str], Callable[[dict[str, Any]], list[tuple[str, str]]]]] = {
    ("sts.amazonaws.com", "AssumeRole"): _assumed_by,
    ("sts.amazonaws.com", "AssumeRoleWithWebIdentity"): _assumed_via_web,
    ("sts.amazonaws.com", "AssumeRoleWithSAML"): _assumed_via_saml,
}

RULES: Final[dict[tuple[str, str], Callable[[Any, Any], list[tuple[str, str]]]]] = {
    ("iam.amazonaws.com", "UpdateAssumeRolePolicy"): _trust_policy,
    ("iam.amazonaws.com", "CreateAccessKey"): _one(ACCESS_KEY, "accessKey", "accessKeyId"),
    ("iam.amazonaws.com", "CreateUser"): _one(PRINCIPAL, "user", "userId"),
    ("iam.amazonaws.com", "CreateRole"): _one(ROLE, "role", "roleId"),
    ("sts.amazonaws.com", "AssumeRole"): _assume_role,
    ("sts.amazonaws.com", "AssumeRoleWithWebIdentity"): _assume_role,
    ("sts.amazonaws.com", "AssumeRoleWithSAML"): _assume_role,
    ("iam.amazonaws.com", "CreateOpenIDConnectProvider"): _arn_from(
        PROVIDER, OIDC_ARN, 1, *OIDC_CREATED_ARN_PATH
    ),
    ("iam.amazonaws.com", "CreateSAMLProvider"): _arn_from(PROVIDER, SAML_ARN, 1, *SAML_CREATED_ARN_PATH),
    ("iam.amazonaws.com", "UpdateOpenIDConnectProviderThumbprint"): _arn_from(
        CHANGED_PROVIDER, OIDC_ARN, 0, *OIDC_CHANGED_ARN_PATH
    ),
    ("iam.amazonaws.com", "AddClientIDToOpenIDConnectProvider"): _arn_from(
        CHANGED_PROVIDER, OIDC_ARN, 0, *OIDC_CHANGED_ARN_PATH
    ),
    ("iam.amazonaws.com", "UpdateSAMLProvider"): _arn_from(
        CHANGED_PROVIDER, SAML_ARN, 0, *SAML_CHANGED_ARN_PATH
    ),
    ("sts.amazonaws.com", "GetSessionToken"): _CREDENTIALS,
    ("sts.amazonaws.com", "GetFederationToken"): _CREDENTIALS,
    ("ec2.amazonaws.com", "RunInstances"): _run_instances,
    ("lambda.amazonaws.com", "CreateFunction"): _function,
    ("lambda.amazonaws.com", "UpdateFunctionCode"): _function,
    ("lambda.amazonaws.com", "UpdateFunctionConfiguration"): _function,
}


def _base_name(source: str, name: str) -> str:
    return API_VERSION.sub("", name) if source == "lambda.amazonaws.com" else name


def rule_name(event_source: str, event_name: str) -> str:
    """Short label for the rule that applied, e.g. "iam:CreateAccessKey"."""
    return f"{event_source.split('.', 1)[0]}:{_base_name(event_source, event_name)}"


def issued_by(rec: dict[str, Any], source: str, name: str) -> Issued | None:
    """What this record's call handed its caller, or None. Failed calls hand over nothing."""
    rule = RULES.get((source, _base_name(source, name)))
    if rule is None or rec.get("errorCode") is not None:
        return None
    found = rule(rec.get("requestParameters"), rec.get("responseElements"))
    if (facts := FACTS.get((source, name))) is not None:
        found = [*found, *facts(rec)]
    return tuple(sorted(set(found))) or None
