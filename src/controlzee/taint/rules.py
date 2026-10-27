"""What a successful call hands its caller: credentials and principals the caller then controls.

Each rule reads the response (and for EC2 the request) of one API call as CloudTrail logs it. Field names follow the API
reference of each action: IAM `CreateAccessKey` (accessKey.accessKeyId), `CreateUser` (user.userId), `CreateRole`
(role.roleId); STS `AssumeRole`, `GetSessionToken`, `GetFederationToken` (credentials.accessKeyId; CloudTrail redacts the
secret and session token but keeps the key id); EC2 `RunInstances` (instancesSet.items[].instanceId, and only when
requestParameters.iamInstanceProfile is set, since otherwise the instance has no credentials).

Runs inside the index workers on every record, so the common case (any other call) must cost one dict lookup.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from controlzee.ingest.index import Issued

# kinds of tainted identity, and how an event is recognised as acting as one
ACCESS_KEY: Final = "access_key_id"  # userIdentity.accessKeyId
PRINCIPAL: Final = "principal_id"  # userIdentity.principalId, whole (an IAM user's userId)
ROLE: Final = "role_id"  # any session of the role: principalId "<roleId>:<session name>"
INSTANCE: Final = "instance_id"  # the instance's role sessions: an AssumedRole principalId "<roleId>:<instance id>"
KINDS: Final = (ACCESS_KEY, PRINCIPAL, ROLE, INSTANCE)
# Not a taint: the role an AssumeRole call obtained a session of (assumedRoleUser.assumedRoleId is "<roleId>:<session>").
# The call is made by whoever assumes the role, often from another account and with no tainted key, so this is how the
# entry into a role the attacker created is found.
ASSUMES: Final = "assumes_role"


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


def _assume_role(request: Any, response: Any) -> list[tuple[str, str]]:
    out = _CREDENTIALS(request, response)
    session = _get(response, "assumedRoleUser", "assumedRoleId")
    if isinstance(session, str) and (role := session.partition(":")[0]):
        out.append((ASSUMES, role))
    return out


RULES: Final[dict[tuple[str, str], Callable[[Any, Any], list[tuple[str, str]]]]] = {
    ("iam.amazonaws.com", "CreateAccessKey"): _one(ACCESS_KEY, "accessKey", "accessKeyId"),
    ("iam.amazonaws.com", "CreateUser"): _one(PRINCIPAL, "user", "userId"),
    ("iam.amazonaws.com", "CreateRole"): _one(ROLE, "role", "roleId"),
    ("sts.amazonaws.com", "AssumeRole"): _assume_role,
    ("sts.amazonaws.com", "GetSessionToken"): _CREDENTIALS,
    ("sts.amazonaws.com", "GetFederationToken"): _CREDENTIALS,
    ("ec2.amazonaws.com", "RunInstances"): _run_instances,
}


def rule_name(event_source: str, event_name: str) -> str:
    """Short label for the rule that applied, e.g. "iam:CreateAccessKey"."""
    return f"{event_source.split('.', 1)[0]}:{event_name}"


def issued_by(rec: dict[str, Any], source: str, name: str) -> Issued | None:
    """What this record's call handed its caller, or None. Failed calls hand over nothing."""
    rule = RULES.get((source, name))
    if rule is None or rec.get("errorCode") is not None:
        return None
    found = rule(rec.get("requestParameters"), rec.get("responseElements"))
    return tuple(sorted(set(found))) or None
