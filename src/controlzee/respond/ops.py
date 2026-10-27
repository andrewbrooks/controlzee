"""The operations `controlzee respond` can carry out, each as: argument shapes, the AWS CLI text a person would run,
a read-only probe of the current state, and the change itself.

A probe never changes anything. It reports the target's state, whether the operation is already done, and the IAM
actions (on the target's real ARN, as AWS returns it) that the change needs, so the dry run can ask the IAM policy
simulator about exactly those. The change runs only from `execute`, after a dry run was approved.

Arguments come from logs the attacker could influence, so every one is checked against the shape for its kind before
it is used, both when the plan is built and again before anything runs.
"""
from __future__ import annotations

import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final

from controlzee.ingest.remote import client

SHAPES: Final[dict[str, re.Pattern[str]]] = {
    "iam": re.compile(r"^[\w+=,.@-]{1,128}$"),  # user, role, group and inline policy names
    "key": re.compile(r"^(AKIA|ASIA)[A-Z0-9]{12,124}$"),
    "instance": re.compile(r"^i-[0-9a-f]{8,32}$"),
    "region": re.compile(r"^[a-z]{2}(-[a-z]+)+-\d{1,2}$"),
    "policy_arn": re.compile(r"^arn:aws[\w-]*:iam::(aws|\d{12}):policy/[\w+=,.@/-]{1,512}$"),
    "trail": re.compile(r"^(arn:aws[\w-]*:cloudtrail:[a-z0-9-]+:\d{12}:trail/)?[\w.-]{3,128}$"),
    "recorder": re.compile(r"^[\w.-]{1,256}$"),
    "secret": re.compile(r"^[\w/+=.@:-]{1,2048}$"),
    "parameter": re.compile(r"^[\w/.-]{1,2048}$"),
}
REVOKE_POLICY: Final = "controlzee-revoke-older-sessions"


class Unsafe(ValueError):
    """An argument does not have the shape of its kind."""


def check(kind: str, value: Any) -> str:
    if not isinstance(value, str) or not SHAPES[kind].match(value):
        raise Unsafe(kind)
    return value


def q(kind: str, value: Any) -> str:
    """Shell-quoted `value`, once it has the shape of `kind`."""
    return shlex.quote(check(kind, value))


def revoke_document(now: str) -> str:
    """Deny everything to credentials issued before `now`: what the IAM console's "Revoke active sessions" attaches."""
    return ('{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",'
            f'"Condition":{{"DateLessThan":{{"aws:TokenIssueTime":"{now}"}}}}}}]}}')


_REVOKE_CLI = revoke_document("'\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"'")  # the shell supplies the time; the plan has no clock


@dataclass(frozen=True)
class Ctx:
    """Who and where: the caller's account and partition, and credentials (a profile, or the default chain)."""

    account: str
    partition: str
    profile: str | None
    home_region: str  # for IAM and other global services

    def c(self, service: str, region: str | None = None) -> Any:
        return client(service, self.profile, region or self.home_region)

    def arn(self, service: str, region: str, resource: str) -> str:
        return f"arn:{self.partition}:{service}:{region}:{self.account}:{resource}"


@dataclass(frozen=True)
class Probe:
    state: str  # the target as it is now, for the person reviewing the dry run
    done: bool  # nothing to do: the change is already in place
    checks: tuple[tuple[str, str], ...]  # (IAM action, resource ARN) the change needs


def _code(e: Exception) -> str:
    return str(getattr(e, "response", {}).get("Error", {}).get("Code", ""))


def _absent(fn: Callable[[], Any], *codes: str) -> Any:
    """`fn()`, or None when AWS says the thing does not exist."""
    try:
        return fn()
    except Exception as e:
        if _code(e) in (codes or ("NoSuchEntity",)):
            return None
        raise


def _pages(c: Any, method: str, key: str, **kw: Any) -> list[Any]:
    return [item for page in c.get_paginator(method).paginate(**kw) for item in page.get(key, [])]


# ---- IAM

def _user_arn(ctx: Ctx, user: str) -> str | None:
    found = _absent(lambda: ctx.c("iam").get_user(UserName=user))
    return None if found is None else str(found["User"]["Arn"])


def _role_arn(ctx: Ctx, role: str) -> str | None:
    found = _absent(lambda: ctx.c("iam").get_role(RoleName=role))
    return None if found is None else str(found["Role"]["Arn"])


def _key_status(ctx: Ctx, user: str, key: str) -> str | None:
    for k in _pages(ctx.c("iam"), "list_access_keys", "AccessKeyMetadata", UserName=user):
        if k["AccessKeyId"] == key:
            return str(k["Status"])
    return None


def _probe_deactivate_key(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
    arn = _user_arn(ctx, a["user"])
    if arn is None:
        return Probe(f"user {a['user']} does not exist", True, ())
    status = _key_status(ctx, a["user"], a["key"])
    if status is None:
        return Probe(f"key {a['key']} no longer exists", True, ())
    return Probe(f"key {a['key']} is {status}", status == "Inactive", (("iam:UpdateAccessKey", arn),))


def _probe_delete_key(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
    arn = _user_arn(ctx, a["user"])
    status = _key_status(ctx, a["user"], a["key"]) if arn else None
    if arn is None or status is None:
        return Probe(f"key {a['key']} no longer exists", True, ())
    return Probe(f"key {a['key']} exists ({status})", False, (("iam:DeleteAccessKey", arn),))


def _probe_revoke_user(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
    arn = _user_arn(ctx, a["user"])
    if arn is None:
        return Probe(f"user {a['user']} does not exist", True, ())
    return Probe(f"user {a['user']} exists; sessions issued before the change will be denied", False, (("iam:PutUserPolicy", arn),))


def _probe_revoke_role(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
    arn = _role_arn(ctx, a["role"])
    if arn is None:
        return Probe(f"role {a['role']} does not exist", True, ())
    return Probe(f"role {a['role']} exists; sessions issued before the change will be denied", False, (("iam:PutRolePolicy", arn),))


def _probe_login_profile(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
    arn = _user_arn(ctx, a["user"])
    if arn is None or _absent(lambda: ctx.c("iam").get_login_profile(UserName=a["user"])) is None:
        return Probe(f"user {a['user']} has no console password", True, ())
    return Probe(f"user {a['user']} has a console password", False, (("iam:DeleteLoginProfile", arn),))


_PRINCIPAL = {"user": ("UserName", "get_user", "User"), "role": ("RoleName", "get_role", "Role"), "group": ("GroupName", "get_group", "Group")}


def _principal_arn(ctx: Ctx, kind: str, name: str) -> str | None:
    param, getter, key = _PRINCIPAL[kind]
    found = _absent(lambda: getattr(ctx.c("iam"), getter)(**{param: name}))
    return None if found is None else str(found[key]["Arn"])


def _detach(kind: str) -> tuple[Callable[[Ctx, dict[str, str], str | None], Probe], Callable[[Ctx, dict[str, str], str | None], str]]:
    param = _PRINCIPAL[kind][0]
    cap = kind.capitalize()

    def probe(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
        arn = _principal_arn(ctx, kind, a[kind])
        if arn is None:
            return Probe(f"{kind} {a[kind]} does not exist", True, ())
        attached = {p["PolicyArn"] for p in _pages(ctx.c("iam"), f"list_attached_{kind}_policies", "AttachedPolicies", **{param: a[kind]})}
        on = a["policy_arn"] in attached
        return Probe(f"{a['policy_arn']} is {'attached to' if on else 'not attached to'} {kind} {a[kind]}", not on,
                     ((f"iam:Detach{cap}Policy", arn),))

    def apply(ctx: Ctx, a: dict[str, str], region: str | None) -> str:
        getattr(ctx.c("iam"), f"detach_{kind}_policy")(**{param: a[kind], "PolicyArn": a["policy_arn"]})
        return f"detached {a['policy_arn']} from {kind} {a[kind]}"

    return probe, apply


def _delete_inline(kind: str) -> tuple[Callable[[Ctx, dict[str, str], str | None], Probe], Callable[[Ctx, dict[str, str], str | None], str]]:
    param = _PRINCIPAL[kind][0]
    cap = kind.capitalize()

    def probe(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
        arn = _principal_arn(ctx, kind, a[kind])
        if arn is None:
            return Probe(f"{kind} {a[kind]} does not exist", True, ())
        names = set(_pages(ctx.c("iam"), f"list_{kind}_policies", "PolicyNames", **{param: a[kind]}))
        on = a["policy"] in names
        return Probe(f"inline policy {a['policy']} {'is' if on else 'is not'} on {kind} {a[kind]}", not on,
                     ((f"iam:Delete{cap}Policy", arn),))

    def apply(ctx: Ctx, a: dict[str, str], region: str | None) -> str:
        getattr(ctx.c("iam"), f"delete_{kind}_policy")(**{param: a[kind], "PolicyName": a["policy"]})
        return f"deleted inline policy {a['policy']} from {kind} {a[kind]}"

    return probe, apply


def _probe_group_member(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
    group_arn = _principal_arn(ctx, "group", a["group"])
    if group_arn is None or _user_arn(ctx, a["user"]) is None:
        return Probe(f"user {a['user']} or group {a['group']} does not exist", True, ())
    member = any(g["GroupName"] == a["group"] for g in _pages(ctx.c("iam"), "list_groups_for_user", "Groups", UserName=a["user"]))
    return Probe(f"user {a['user']} {'is' if member else 'is not'} in group {a['group']}", not member,
                 (("iam:RemoveUserFromGroup", group_arn),))


@dataclass(frozen=True)
class _UserParts:
    keys: list[str]
    login: bool
    attached: list[str]
    inline: list[str]
    groups: list[tuple[str, str]]  # (name, arn)
    mfa: list[str]
    ssh: list[str]
    certs: list[str]
    service_creds: list[str]


def _user_parts(ctx: Ctx, user: str) -> _UserParts:
    iam = ctx.c("iam")
    return _UserParts(
        keys=[k["AccessKeyId"] for k in _pages(iam, "list_access_keys", "AccessKeyMetadata", UserName=user)],
        login=_absent(lambda: iam.get_login_profile(UserName=user)) is not None,
        attached=[p["PolicyArn"] for p in _pages(iam, "list_attached_user_policies", "AttachedPolicies", UserName=user)],
        inline=list(_pages(iam, "list_user_policies", "PolicyNames", UserName=user)),
        groups=[(g["GroupName"], g["Arn"]) for g in _pages(iam, "list_groups_for_user", "Groups", UserName=user)],
        mfa=[m["SerialNumber"] for m in _pages(iam, "list_mfa_devices", "MFADevices", UserName=user)],
        ssh=[k["SSHPublicKeyId"] for k in _pages(iam, "list_ssh_public_keys", "SSHPublicKeys", UserName=user)],
        certs=[c["CertificateId"] for c in _pages(iam, "list_signing_certificates", "Certificates", UserName=user)],
        service_creds=[c["ServiceSpecificCredentialId"] for c in
                       iam.list_service_specific_credentials(UserName=user).get("ServiceSpecificCredentials", [])],
    )


def _probe_delete_user(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
    arn = _user_arn(ctx, a["user"])
    if arn is None:
        return Probe(f"user {a['user']} does not exist", True, ())
    p = _user_parts(ctx, a["user"])
    checks = [("iam:DeleteUser", arn)]
    checks += [("iam:DeleteAccessKey", arn)] if p.keys else []
    checks += [("iam:DeleteLoginProfile", arn)] if p.login else []
    checks += [("iam:DetachUserPolicy", arn)] if p.attached else []
    checks += [("iam:DeleteUserPolicy", arn)] if p.inline else []
    checks += [("iam:RemoveUserFromGroup", g_arn) for _, g_arn in p.groups]
    checks += [("iam:DeactivateMFADevice", arn)] if p.mfa else []
    checks += [("iam:DeleteVirtualMFADevice", m) for m in p.mfa if ":mfa/" in m]
    checks += [("iam:DeleteSSHPublicKey", arn)] if p.ssh else []
    checks += [("iam:DeleteSigningCertificate", arn)] if p.certs else []
    checks += [("iam:DeleteServiceSpecificCredential", arn)] if p.service_creds else []
    state = (f"user {a['user']} exists with {len(p.keys)} key(s), {'a' if p.login else 'no'} console password, "
             f"{len(p.attached)} attached and {len(p.inline)} inline policy(ies), {len(p.groups)} group(s), {len(p.mfa)} MFA device(s)")
    return Probe(state, False, tuple(checks))


def _apply_delete_user(ctx: Ctx, a: dict[str, str], region: str | None) -> str:
    iam, user = ctx.c("iam"), a["user"]
    p = _user_parts(ctx, user)
    for k in p.keys:
        iam.delete_access_key(UserName=user, AccessKeyId=k)
    if p.login:
        iam.delete_login_profile(UserName=user)
    for arn in p.attached:
        iam.detach_user_policy(UserName=user, PolicyArn=arn)
    for name in p.inline:
        iam.delete_user_policy(UserName=user, PolicyName=name)
    for name, _ in p.groups:
        iam.remove_user_from_group(GroupName=name, UserName=user)
    for serial in p.mfa:
        iam.deactivate_mfa_device(UserName=user, SerialNumber=serial)
        if ":mfa/" in serial:
            iam.delete_virtual_mfa_device(SerialNumber=serial)
    for k in p.ssh:
        iam.delete_ssh_public_key(UserName=user, SSHPublicKeyId=k)
    for c in p.certs:
        iam.delete_signing_certificate(UserName=user, CertificateId=c)
    for c in p.service_creds:
        iam.delete_service_specific_credential(UserName=user, ServiceSpecificCredentialId=c)
    iam.delete_user(UserName=user)
    return f"deleted user {user} (and {len(p.keys)} key(s), {len(p.attached) + len(p.inline)} policy(ies), {len(p.groups)} group membership(s))"


def _role_parts(ctx: Ctx, role: str) -> tuple[list[str], list[str], list[tuple[str, str]]]:
    iam = ctx.c("iam")
    return ([p["PolicyArn"] for p in _pages(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=role)],
            list(_pages(iam, "list_role_policies", "PolicyNames", RoleName=role)),
            [(p["InstanceProfileName"], p["Arn"]) for p in _pages(iam, "list_instance_profiles_for_role", "InstanceProfiles", RoleName=role)])


def _probe_delete_role(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
    arn = _role_arn(ctx, a["role"])
    if arn is None:
        return Probe(f"role {a['role']} does not exist", True, ())
    attached, inline, profiles = _role_parts(ctx, a["role"])
    checks = [("iam:DeleteRole", arn)]
    checks += [("iam:DetachRolePolicy", arn)] if attached else []
    checks += [("iam:DeleteRolePolicy", arn)] if inline else []
    checks += [("iam:RemoveRoleFromInstanceProfile", p_arn) for _, p_arn in profiles]
    return Probe(f"role {a['role']} exists with {len(attached)} attached and {len(inline)} inline policy(ies), "
                 f"in {len(profiles)} instance profile(s)", False, tuple(checks))


def _apply_delete_role(ctx: Ctx, a: dict[str, str], region: str | None) -> str:
    iam, role = ctx.c("iam"), a["role"]
    attached, inline, profiles = _role_parts(ctx, role)
    for arn in attached:
        iam.detach_role_policy(RoleName=role, PolicyArn=arn)
    for name in inline:
        iam.delete_role_policy(RoleName=role, PolicyName=name)
    for name, _ in profiles:
        iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=role)
    iam.delete_role(RoleName=role)
    return f"deleted role {role}"


# ---- EC2

def _instance(ctx: Ctx, region: str, instance: str) -> dict[str, Any] | None:
    found = _absent(lambda: _pages(ctx.c("ec2", region), "describe_instances", "Reservations", InstanceIds=[instance]),
                    "InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed")
    items = [i for r in found or [] for i in r.get("Instances", [])]
    return items[0] if items else None


def _associations(ctx: Ctx, region: str, instance: str) -> list[str]:
    assocs = _pages(ctx.c("ec2", region), "describe_iam_instance_profile_associations", "IamInstanceProfileAssociations",
                    Filters=[{"Name": "instance-id", "Values": [instance]}])
    return [x["AssociationId"] for x in assocs if x.get("State") in ("associating", "associated")]


def _probe_disassociate(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
    assert region
    ids = _associations(ctx, region, a["instance"])
    return Probe(f"instance {a['instance']} has {len(ids)} instance profile association(s)", not ids,
                 (("ec2:DisassociateIamInstanceProfile", ctx.arn("ec2", region, f"instance/{a['instance']}")),))


def _apply_disassociate(ctx: Ctx, a: dict[str, str], region: str | None) -> str:
    assert region
    ids = _associations(ctx, region, a["instance"])
    for assoc in ids:
        ctx.c("ec2", region).disassociate_iam_instance_profile(AssociationId=assoc)
    return f"removed {len(ids)} instance profile association(s) from {a['instance']}"


def _instance_state(stop_states: tuple[str, ...], action: str) -> Callable[[Ctx, dict[str, str], str | None], Probe]:
    def probe(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
        assert region
        inst = _instance(ctx, region, a["instance"])
        state = inst["State"]["Name"] if inst else "gone"
        return Probe(f"instance {a['instance']} is {state}", state in (*stop_states, "gone"),
                     ((action, ctx.arn("ec2", region, f"instance/{a['instance']}")),))
    return probe


def _probe_snapshot(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
    assert region
    inst = _instance(ctx, region, a["instance"])
    if inst is None:
        return Probe(f"instance {a['instance']} is gone", True, ())
    vols = [m["Ebs"]["VolumeId"] for m in inst.get("BlockDeviceMappings", []) if "Ebs" in m]
    checks = [("ec2:CreateSnapshot", ctx.arn("ec2", region, f"volume/{v}")) for v in vols]
    checks.append(("ec2:CreateSnapshot", f"arn:{ctx.partition}:ec2:{region}::snapshot/*"))
    return Probe(f"instance {a['instance']} has {len(vols)} volume(s) to snapshot", not vols, tuple(checks))


def _apply_snapshot(ctx: Ctx, a: dict[str, str], region: str | None) -> str:
    assert region
    inst = _instance(ctx, region, a["instance"])
    vols = [m["Ebs"]["VolumeId"] for m in (inst or {}).get("BlockDeviceMappings", []) if "Ebs" in m]
    snaps = [ctx.c("ec2", region).create_snapshot(VolumeId=v, Description=f"controlzee: evidence from {a['instance']}")["SnapshotId"]
             for v in vols]
    return f"started snapshot(s) {', '.join(snaps)}" if snaps else "no volumes"


# ---- logging and detection

def _trail_arn(ctx: Ctx, region: str, trail: str) -> str:
    return trail if trail.startswith("arn:") else ctx.arn("cloudtrail", region, f"trail/{trail}")


def _probe_start_logging(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
    assert region
    status = _absent(lambda: ctx.c("cloudtrail", region).get_trail_status(Name=a["trail"]), "TrailNotFoundException")
    if status is None:
        return Probe(f"trail {a['trail']} no longer exists: recreate it by hand", False, (("cloudtrail:StartLogging", _trail_arn(ctx, region, a["trail"])),))
    on = bool(status.get("IsLogging"))
    return Probe(f"trail {a['trail']} is {'logging' if on else 'not logging'}", on,
                 (("cloudtrail:StartLogging", _trail_arn(ctx, region, a["trail"])),))


def _probe_config(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
    assert region
    found = _absent(lambda: ctx.c("config", region).describe_configuration_recorder_status(ConfigurationRecorderNames=[a["recorder"]]),
                    "NoSuchConfigurationRecorderException")
    rec = (found or {}).get("ConfigurationRecordersStatus", [])
    on = bool(rec and rec[0].get("recording"))
    return Probe(f"config recorder {a['recorder']} is {'recording' if on else 'not recording' if rec else 'missing'}", on,
                 (("config:StartConfigurationRecorder", "*"),))


def _probe_guardduty(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
    assert region
    gd = ctx.c("guardduty", region)
    ids = _pages(gd, "list_detectors", "DetectorIds")
    if not ids:
        return Probe("no GuardDuty detector", False, (("guardduty:CreateDetector", "*"),))
    status = gd.get_detector(DetectorId=ids[0]).get("Status")
    return Probe(f"GuardDuty detector {ids[0]} is {status}", status == "ENABLED",
                 (("guardduty:UpdateDetector", ctx.arn("guardduty", region, f"detector/{ids[0]}")),))


def _apply_guardduty(ctx: Ctx, a: dict[str, str], region: str | None) -> str:
    assert region
    gd = ctx.c("guardduty", region)
    ids = _pages(gd, "list_detectors", "DetectorIds")
    if ids:
        gd.update_detector(DetectorId=ids[0], Enable=True)
        return f"enabled detector {ids[0]}"
    return f"created detector {gd.create_detector(Enable=True)['DetectorId']}"


def _probe_security_hub(ctx: Ctx, a: dict[str, str], region: str | None) -> Probe:
    assert region
    on = _absent(lambda: ctx.c("securityhub", region).describe_hub(), "InvalidAccessException", "ResourceNotFoundException") is not None
    return Probe(f"Security Hub is {'enabled' if on else 'not enabled'} in {region}", on, (("securityhub:EnableSecurityHub", "*"),))


# ---- the registry

Probe_ = Callable[[Ctx, dict[str, str], str | None], Probe]
Apply = Callable[[Ctx, dict[str, str], str | None], str]


@dataclass(frozen=True)
class OpSpec:
    shapes: dict[str, str]  # argument -> SHAPES kind
    regional: bool
    disruptive: bool  # irreversible, or loses evidence: needs --allow-disruptive
    describe: Callable[[dict[str, str], str | None], str]
    cli: Callable[[dict[str, str], str | None], list[str]]
    probe: Probe_
    apply: Apply


def _r(region: str | None) -> str:
    return f"--region {q('region', region)}"


_detach_user, _detach_user_apply = _detach("user")
_detach_role, _detach_role_apply = _detach("role")
_detach_group, _detach_group_apply = _detach("group")
_inline_user, _inline_user_apply = _delete_inline("user")
_inline_role, _inline_role_apply = _delete_inline("role")
_inline_group, _inline_group_apply = _delete_inline("group")


def _iam_call(fn: str, **kw: str) -> Apply:
    """An operation that is a single IAM call; `kw` maps each API parameter to the argument that supplies it."""
    def apply(ctx: Ctx, a: dict[str, str], region: str | None) -> str:
        getattr(ctx.c("iam"), fn)(**{param: a[arg] for param, arg in kw.items()})
        return f"{fn.replace('_', ' ')}: {', '.join(f'{k} {a[k]}' for k in sorted(set(kw.values())))}"
    return apply


def _revoke(kind: str) -> Apply:
    def apply(ctx: Ctx, a: dict[str, str], region: str | None) -> str:
        from datetime import UTC, datetime
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        param = "UserName" if kind == "user" else "RoleName"
        getattr(ctx.c("iam"), f"put_{kind}_policy")(**{param: a[kind], "PolicyName": REVOKE_POLICY, "PolicyDocument": revoke_document(now)})
        return f"credentials of {kind} {a[kind]} issued before {now} are now denied"
    return apply


def _ec2(fn: str, done: str) -> Apply:
    def apply(ctx: Ctx, a: dict[str, str], region: str | None) -> str:
        getattr(ctx.c("ec2", region), fn)(InstanceIds=[a["instance"]])
        return f"{done} {a['instance']}"
    return apply


OPS: Final[dict[str, OpSpec]] = {
    "deactivate_access_key": OpSpec(
        {"user": "iam", "key": "key"}, False, False, lambda a, r: f"deactivate access key {a['key']} of user {a['user']}",
        lambda a, r: [f"aws iam update-access-key --user-name {q('iam', a['user'])} --access-key-id {q('key', a['key'])} --status Inactive"],
        _probe_deactivate_key, lambda ctx, a, r: (ctx.c("iam").update_access_key(UserName=a["user"], AccessKeyId=a["key"], Status="Inactive"),
                                                  f"key {a['key']} is now Inactive")[1]),
    "delete_access_key": OpSpec(
        {"user": "iam", "key": "key"}, False, True, lambda a, r: f"delete access key {a['key']} of user {a['user']}",
        lambda a, r: [f"aws iam delete-access-key --user-name {q('iam', a['user'])} --access-key-id {q('key', a['key'])}"],
        _probe_delete_key, _iam_call("delete_access_key", UserName="user", AccessKeyId="key")),
    "revoke_user_sessions": OpSpec(
        {"user": "iam"}, False, False, lambda a, r: f"deny credentials of user {a['user']} issued before now",
        lambda a, r: [f"aws iam put-user-policy --user-name {q('iam', a['user'])} --policy-name {REVOKE_POLICY} --policy-document '{_REVOKE_CLI}'"],
        _probe_revoke_user, _revoke("user")),
    "revoke_role_sessions": OpSpec(
        {"role": "iam"}, False, False, lambda a, r: f"deny sessions of role {a['role']} issued before now",
        lambda a, r: [f"aws iam put-role-policy --role-name {q('iam', a['role'])} --policy-name {REVOKE_POLICY} --policy-document '{_REVOKE_CLI}'"],
        _probe_revoke_role, _revoke("role")),
    "delete_login_profile": OpSpec(
        {"user": "iam"}, False, False, lambda a, r: f"remove the console password of user {a['user']}",
        lambda a, r: [f"aws iam delete-login-profile --user-name {q('iam', a['user'])}"],
        _probe_login_profile, _iam_call("delete_login_profile", UserName="user")),
    "detach_user_policy": OpSpec(
        {"user": "iam", "policy_arn": "policy_arn"}, False, False, lambda a, r: f"detach {a['policy_arn']} from user {a['user']}",
        lambda a, r: [f"aws iam detach-user-policy --user-name {q('iam', a['user'])} --policy-arn {q('policy_arn', a['policy_arn'])}"],
        _detach_user, _detach_user_apply),
    "detach_role_policy": OpSpec(
        {"role": "iam", "policy_arn": "policy_arn"}, False, False, lambda a, r: f"detach {a['policy_arn']} from role {a['role']}",
        lambda a, r: [f"aws iam detach-role-policy --role-name {q('iam', a['role'])} --policy-arn {q('policy_arn', a['policy_arn'])}"],
        _detach_role, _detach_role_apply),
    "detach_group_policy": OpSpec(
        {"group": "iam", "policy_arn": "policy_arn"}, False, False, lambda a, r: f"detach {a['policy_arn']} from group {a['group']}",
        lambda a, r: [f"aws iam detach-group-policy --group-name {q('iam', a['group'])} --policy-arn {q('policy_arn', a['policy_arn'])}"],
        _detach_group, _detach_group_apply),
    "delete_user_policy": OpSpec(
        {"user": "iam", "policy": "iam"}, False, False, lambda a, r: f"delete inline policy {a['policy']} of user {a['user']}",
        lambda a, r: [f"aws iam delete-user-policy --user-name {q('iam', a['user'])} --policy-name {q('iam', a['policy'])}"],
        _inline_user, _inline_user_apply),
    "delete_role_policy": OpSpec(
        {"role": "iam", "policy": "iam"}, False, False, lambda a, r: f"delete inline policy {a['policy']} of role {a['role']}",
        lambda a, r: [f"aws iam delete-role-policy --role-name {q('iam', a['role'])} --policy-name {q('iam', a['policy'])}"],
        _inline_role, _inline_role_apply),
    "delete_group_policy": OpSpec(
        {"group": "iam", "policy": "iam"}, False, False, lambda a, r: f"delete inline policy {a['policy']} of group {a['group']}",
        lambda a, r: [f"aws iam delete-group-policy --group-name {q('iam', a['group'])} --policy-name {q('iam', a['policy'])}"],
        _inline_group, _inline_group_apply),
    "remove_user_from_group": OpSpec(
        {"user": "iam", "group": "iam"}, False, False, lambda a, r: f"remove user {a['user']} from group {a['group']}",
        lambda a, r: [f"aws iam remove-user-from-group --user-name {q('iam', a['user'])} --group-name {q('iam', a['group'])}"],
        _probe_group_member, _iam_call("remove_user_from_group", UserName="user", GroupName="group")),
    "delete_user": OpSpec(
        {"user": "iam"}, False, True, lambda a, r: f"delete user {a['user']} with its keys, password, policies, groups and MFA devices",
        lambda a, r: [f"aws iam list-access-keys --user-name {q('iam', a['user'])}",
                      f"aws iam delete-access-key --user-name {q('iam', a['user'])} --access-key-id EACH_KEY_FROM_ABOVE",
                      f"aws iam delete-login-profile --user-name {q('iam', a['user'])}",
                      f"aws iam list-attached-user-policies --user-name {q('iam', a['user'])}",
                      f"aws iam detach-user-policy --user-name {q('iam', a['user'])} --policy-arn EACH_POLICY_FROM_ABOVE",
                      f"aws iam list-user-policies --user-name {q('iam', a['user'])}",
                      f"aws iam delete-user-policy --user-name {q('iam', a['user'])} --policy-name EACH_POLICY_FROM_ABOVE",
                      f"aws iam list-groups-for-user --user-name {q('iam', a['user'])}",
                      f"aws iam remove-user-from-group --user-name {q('iam', a['user'])} --group-name EACH_GROUP_FROM_ABOVE",
                      f"aws iam delete-user --user-name {q('iam', a['user'])}"],
        _probe_delete_user, _apply_delete_user),
    "delete_role": OpSpec(
        {"role": "iam"}, False, True, lambda a, r: f"delete role {a['role']} with its policies and instance profile memberships",
        lambda a, r: [f"aws iam list-attached-role-policies --role-name {q('iam', a['role'])}",
                      f"aws iam detach-role-policy --role-name {q('iam', a['role'])} --policy-arn EACH_POLICY_FROM_ABOVE",
                      f"aws iam list-role-policies --role-name {q('iam', a['role'])}",
                      f"aws iam delete-role-policy --role-name {q('iam', a['role'])} --policy-name EACH_POLICY_FROM_ABOVE",
                      f"aws iam list-instance-profiles-for-role --role-name {q('iam', a['role'])}",
                      f"aws iam remove-role-from-instance-profile --role-name {q('iam', a['role'])} --instance-profile-name EACH_PROFILE_FROM_ABOVE",
                      f"aws iam delete-role --role-name {q('iam', a['role'])}"],
        _probe_delete_role, _apply_delete_role),
    "disassociate_instance_profile": OpSpec(
        {"instance": "instance"}, True, False, lambda a, r: f"remove the instance profile (role credentials) from instance {a['instance']}",
        lambda a, r: [f"aws ec2 describe-iam-instance-profile-associations {_r(r)} --filters Name=instance-id,Values={q('instance', a['instance'])} "
                      "--query 'IamInstanceProfileAssociations[].AssociationId'",
                      f"aws ec2 disassociate-iam-instance-profile {_r(r)} --association-id ASSOCIATION_ID_FROM_ABOVE"],
        _probe_disassociate, _apply_disassociate),
    "stop_instance": OpSpec(
        {"instance": "instance"}, True, True, lambda a, r: f"stop instance {a['instance']} (its memory is lost)",
        lambda a, r: [f"aws ec2 stop-instances {_r(r)} --instance-ids {q('instance', a['instance'])}"],
        _instance_state(("stopping", "stopped", "shutting-down", "terminated"), "ec2:StopInstances"), _ec2("stop_instances", "stopping")),
    "snapshot_instance": OpSpec(
        {"instance": "instance"}, True, False, lambda a, r: f"snapshot every volume of instance {a['instance']}",
        lambda a, r: [f"aws ec2 describe-instances {_r(r)} --instance-ids {q('instance', a['instance'])} "
                      "--query 'Reservations[].Instances[].BlockDeviceMappings[].Ebs.VolumeId'",
                      f"aws ec2 create-snapshot {_r(r)} --volume-id VOLUME_ID_FROM_ABOVE "
                      f"--description {shlex.quote('controlzee: evidence from ' + check('instance', a['instance']))}"],
        _probe_snapshot, _apply_snapshot),
    "terminate_instance": OpSpec(
        {"instance": "instance"}, True, True, lambda a, r: f"terminate instance {a['instance']}",
        lambda a, r: [f"aws ec2 terminate-instances {_r(r)} --instance-ids {q('instance', a['instance'])}"],
        _instance_state(("shutting-down", "terminated"), "ec2:TerminateInstances"), _ec2("terminate_instances", "terminating")),
    "start_logging": OpSpec(
        {"trail": "trail"}, True, False, lambda a, r: f"turn trail {a['trail']} back on",
        lambda a, r: [f"aws cloudtrail get-trail-status {_r(r)} --name {q('trail', a['trail'])} --query IsLogging",
                      f"aws cloudtrail start-logging {_r(r)} --name {q('trail', a['trail'])}"],
        _probe_start_logging, lambda ctx, a, r: (ctx.c("cloudtrail", r).start_logging(Name=a["trail"]), f"trail {a['trail']} is logging")[1]),
    "start_config_recorder": OpSpec(
        {"recorder": "recorder"}, True, False, lambda a, r: f"restart AWS Config recorder {a['recorder']}",
        lambda a, r: [f"aws configservice start-configuration-recorder {_r(r)} --configuration-recorder-name {q('recorder', a['recorder'])}"],
        _probe_config, lambda ctx, a, r: (ctx.c("config", r).start_configuration_recorder(ConfigurationRecorderName=a["recorder"]),
                                          f"recorder {a['recorder']} started")[1]),
    "enable_guardduty": OpSpec(
        {}, True, False, lambda a, r: f"turn GuardDuty back on in {r}",
        lambda a, r: [f"aws guardduty create-detector {_r(r)} --enable"], _probe_guardduty, _apply_guardduty),
    "enable_security_hub": OpSpec(
        {}, True, False, lambda a, r: f"turn Security Hub back on in {r}",
        lambda a, r: [f"aws securityhub enable-security-hub {_r(r)}"], _probe_security_hub,
        lambda ctx, a, r: (ctx.c("securityhub", r).enable_security_hub(), "Security Hub enabled")[1]),
}


def validate(op: str, args: dict[str, str], region: str | None) -> None:
    """Raise Unsafe (or KeyError for an unknown op) unless `op` exists and every argument has its shape."""
    spec = OPS[op]
    if set(args) != set(spec.shapes):
        raise Unsafe(f"arguments of {op}")
    for name, kind in spec.shapes.items():
        check(kind, args[name])
    if spec.regional:
        check("region", region)
    elif region is not None:
        raise Unsafe(f"region for global {op}")
