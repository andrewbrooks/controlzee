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
KINDS: Final = (ACCESS_KEY, PRINCIPAL, ROLE, INSTANCE, FUNCTION, TRUSTED_BY)
API_VERSION: Final = re.compile(r"\d{8}(v\d+)?$")  # Lambda logs event names like CreateFunction20150331
_FUNCTION_NAME: Final = re.compile(r"^[\w-]{1,64}$")
# Not a taint: the role an AssumeRole call obtained a session of (assumedRoleUser.assumedRoleId is "<roleId>:<session>").
# The call is made by whoever assumes the role, often from another account and with no tainted key, so this is how the
# entry into a role the attacker created is found.
ASSUMES: Final = "assumes_role"
# Also not a taint: who called an AssumeRole and into which role, "<role name>|<account>|<arn>|<session issuer arn>" (any
# of the last three may be empty), so a call into a role whose trust policy was changed can be tied to a named principal.
ASSUMED_BY: Final = "assumed_by"
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


def _grants_assume_role(statement: dict[str, Any]) -> bool:
    action = statement.get("Action")
    actions = [action] if isinstance(action, str) else action if isinstance(action, list) else []
    return any(isinstance(a, str) and a in ("sts:AssumeRole", "sts:*", "*") for a in actions)


def trust_principals(document: Any) -> list[str]:
    """The AWS principals a role's trust policy allows to assume it: "*", "account:<id>" (an account or its root) or a
    user or role ARN. Anything else (services, federation, Deny statements) is left out. The document is hostile input:
    it is size-capped by the caller, every value is shape-checked, and nothing that fails the check is kept."""
    if not isinstance(document, dict):
        return []
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    found: set[str] = set()
    for st in statements[:MAX_TRUST_PRINCIPALS]:
        if not isinstance(st, dict) or st.get("Effect") != "Allow" or not _grants_assume_role(st):
            continue
        principal = st.get("Principal")
        if principal == "*":
            found.add("*")
            continue
        aws = principal.get("AWS") if isinstance(principal, dict) else None
        for value in ([aws] if isinstance(aws, str) else aws if isinstance(aws, list) else [])[
            :MAX_TRUST_PRINCIPALS
        ]:
            if value == "*":
                found.add("*")
            elif isinstance(value, str) and _ACCOUNT.match(value):
                found.add(f"account:{value}")
            elif isinstance(value, str) and (m := _IAM_PRINCIPAL.match(value)):
                found.add(f"account:{m.group(1)}" if m.group(2) == "root" else value)
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


RULES: Final[dict[tuple[str, str], Callable[[Any, Any], list[tuple[str, str]]]]] = {
    ("iam.amazonaws.com", "UpdateAssumeRolePolicy"): _trust_policy,
    ("iam.amazonaws.com", "CreateAccessKey"): _one(ACCESS_KEY, "accessKey", "accessKeyId"),
    ("iam.amazonaws.com", "CreateUser"): _one(PRINCIPAL, "user", "userId"),
    ("iam.amazonaws.com", "CreateRole"): _one(ROLE, "role", "roleId"),
    ("sts.amazonaws.com", "AssumeRole"): _assume_role,
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
    if (source, name) == ("sts.amazonaws.com", "AssumeRole"):
        found = [*found, *_assumed_by(rec)]
    return tuple(sorted(set(found))) or None
