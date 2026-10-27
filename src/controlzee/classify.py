"""What an API call means for an incident: its tactic, and the resources it touched.

Tactics are named after the MITRE ATT&CK Enterprise tactics (cloud matrix) so responders can map them, but the
assignment is per API call and deliberately simple: one tactic per call, chosen for what the call usually means when an
attacker makes it. Reading calls default to discovery and other writes to "other"; the tables say where that is wrong.

Resources come from the request parameters each service documents (bucketName, secretId, roleName...). Only names the
tables know are read, so a parameter an attacker controls cannot pose as a resource of another kind.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Final, Literal

from controlzee.coverage import TAMPERING
from controlzee.model.event import Event
from controlzee.model.timeline import Tactic
from controlzee.taint.rules import API_VERSION

TACTIC_ORDER: Final[tuple[Tactic, ...]] = ("initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
                                           "credential-access", "discovery", "lateral-movement", "collection", "exfiltration",
                                           "impact", "other")
Access = Literal["read", "write", "delete", "assume"]

_BY_TACTIC: Final[dict[Tactic, dict[str, tuple[str, ...]]]] = {
    "initial-access": {"signin": ("ConsoleLogin",)},
    "execution": {"ec2": ("RunInstances",), "ssm": ("SendCommand",), "lambda": ("Invoke", "InvokeFunction")},
    "persistence": {
        "iam": ("CreateUser", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "CreateRole", "UpdateAssumeRolePolicy",
                "CreateServiceSpecificCredential", "UploadSSHPublicKey", "CreateVirtualMFADevice", "EnableMFADevice"),
        "ec2": ("ImportKeyPair", "CreateKeyPair"),
        "lambda": ("CreateFunction", "UpdateFunctionCode", "UpdateFunctionConfiguration", "AddPermission"),
        # IAM Identity Center: a new person or an assignment is a way back in
        "identitystore": ("CreateUser", "CreateGroupMembership"), "sso": ("CreateAccountAssignment", "CreateInstanceAccessControlAttributeConfiguration")},
    "privilege-escalation": {
        "iam": ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
                "AddUserToGroup", "CreatePolicyVersion", "SetDefaultPolicyVersion"),
        "ec2": ("AssociateIamInstanceProfile", "ReplaceIamInstanceProfileAssociation"),
        "sso": ("AttachManagedPolicyToPermissionSet", "AttachCustomerManagedPolicyReferenceToPermissionSet",
                "PutInlinePolicyToPermissionSet", "PutPermissionsBoundaryToPermissionSet")},
    "defense-evasion": {"ec2": ("DeleteFlowLogs",), "logs": ("DeleteLogGroup", "DeleteLogStream")},
    "credential-access": {"secretsmanager": ("GetSecretValue", "BatchGetSecretValue"),
                          "ssm": ("GetParameter", "GetParameters", "GetParametersByPath"), "ec2": ("GetPasswordData",),
                          "sts": ("GetSessionToken", "GetFederationToken"), "kms": ("Decrypt",)},
    "lateral-movement": {"sts": ("AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"),
                         "ssm": ("StartSession",), "ec2-instance-connect": ("SendSSHPublicKey",)},
    "collection": {"s3": ("GetObject",), "dynamodb": ("Scan",), "ec2": ("CreateSnapshot",)},
    "exfiltration": {"ec2": ("ModifySnapshotAttribute", "ModifyImageAttribute"),
                     "rds": ("ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute"),
                     "s3": ("PutBucketPolicy", "PutBucketAcl", "PutObjectAcl", "DeletePublicAccessBlock", "DeleteBucketPublicAccessBlock",
                            "PutBucketReplication")},
    "impact": {"s3": ("DeleteBucket", "DeleteObject", "DeleteObjects", "PutBucketEncryption"),
               "ec2": ("TerminateInstances", "DeleteVolume", "DeleteSnapshot"), "rds": ("DeleteDBInstance", "DeleteDBCluster"),
               "kms": ("ScheduleKeyDeletion", "DisableKey")},
}
_TABLE: Final[dict[tuple[str, str], Tactic]] = {
    (svc, name): tactic for tactic, by_svc in _BY_TACTIC.items() for svc, names in by_svc.items() for name in names}
_TABLE.update({(src.split(".", 1)[0], name): "defense-evasion" for src, name in TAMPERING})
_READ_PREFIXES: Final = ("Get", "List", "Describe", "Lookup", "Head", "Search", "BatchGet", "Scan", "Query")
_API_VERSION = API_VERSION


def service(event_source: str) -> str:
    return event_source.split(".", 1)[0]


def action(ev: Event) -> str:
    """"iam:CreateAccessKey", with Lambda's API-version suffix dropped."""
    return f"{service(ev.event_source)}:{_API_VERSION.sub('', ev.event_name)}"


def tactic(ev: Event) -> Tactic:
    svc, name = action(ev).split(":", 1)
    if (t := _TABLE.get((svc, name))) is not None:
        return t
    reads = ev.read_only if ev.read_only is not None else name.startswith(_READ_PREFIXES)
    return "discovery" if reads else "other"


def access(ev: Event) -> Access:
    name = _API_VERSION.sub("", ev.event_name)
    if service(ev.event_source) == "sts" and name.startswith("AssumeRole"):
        return "assume"
    if name.startswith(("Delete", "Terminate", "Remove", "ScheduleKeyDeletion")):
        return "delete"
    reads = ev.read_only if ev.read_only is not None else name.startswith(_READ_PREFIXES)
    return "read" if reads else "write"


# (service, request parameter, resource type). Lists of values are allowed where the API takes them.
_RESOURCE_PARAMS: Final[tuple[tuple[str, str, str], ...]] = (
    ("s3", "bucketName", "bucket"), ("secretsmanager", "secretId", "secret"), ("ssm", "name", "parameter"),
    ("ssm", "names", "parameter"), ("ssm", "path", "parameter path"), ("iam", "userName", "user"), ("iam", "roleName", "role"),
    ("iam", "groupName", "group"), ("iam", "policyArn", "policy"), ("iam", "instanceProfileName", "instance profile"),
    ("ec2", "instanceId", "instance"), ("ec2", "snapshotId", "snapshot"), ("ec2", "volumeId", "volume"),
    ("ec2", "groupId", "security group"), ("lambda", "functionName", "function"), ("kms", "keyId", "key"),
    ("rds", "dBInstanceIdentifier", "db instance"), ("rds", "dBSnapshotIdentifier", "db snapshot"),
    ("rds", "dBClusterIdentifier", "db cluster"), ("dynamodb", "tableName", "table"), ("cloudtrail", "name", "trail"),
    ("guardduty", "detectorId", "detector"), ("config", "configurationRecorderName", "config recorder"),
    ("sts", "roleArn", "role"), ("logs", "logGroupName", "log group"),
)
_MAX_VALUE = 512


def _dig(d: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(d, dict):
            return None
        d = d.get(key)
    return d


def _strings(v: Any) -> Iterator[str]:
    if isinstance(v, str) and v:
        yield v[:_MAX_VALUE]
    elif isinstance(v, list):
        yield from (x[:_MAX_VALUE] for x in v if isinstance(x, str) and x)


def resources(ev: Event) -> list[tuple[str, str]]:
    """(resource type, name) pairs the call acted on, sorted and unique. S3 object calls name "bucket/key"."""
    svc = service(ev.event_source)
    req = ev.request_parameters or {}
    found: set[tuple[str, str]] = set()
    for s, param, kind in _RESOURCE_PARAMS:
        if s == svc:
            found.update((kind, v) for v in _strings(req.get(param)))
    if svc == "s3" and isinstance(b := req.get("bucketName"), str) and isinstance(k := req.get("key"), str):
        found.discard(("bucket", b[:_MAX_VALUE]))
        found.add(("object", f"{b}/{k}"[:_MAX_VALUE]))
    if svc == "ec2":
        items = _dig(req, "instancesSet", "items")
        if ev.event_name == "RunInstances" and ev.error_code is None:  # the instances it created are in the response
            items = _dig(ev.response_elements, "instancesSet", "items")
        for item in items if isinstance(items, list) else []:
            found.update(("instance", v) for v in _strings(_dig(item, "instanceId")))
    return sorted(found)
