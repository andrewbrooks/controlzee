"""An in-memory AWS account for respond tests. Every call is validated against botocore's real service model, so a
wrong operation or parameter name fails here as it would against AWS; the behaviour is a small model of each API."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError
from botocore.validate import validate_parameters

ACCOUNT = "111122223333"


def _err(code: str, op: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": f"{code} (fake)"}}, op)


@dataclass
class User:
    keys: dict[str, str] = field(default_factory=dict)  # key id -> status
    login: bool = False
    attached: set[str] = field(default_factory=set)
    inline: set[str] = field(default_factory=set)
    groups: set[str] = field(default_factory=set)
    mfa: list[str] = field(default_factory=list)


@dataclass
class Role:
    attached: set[str] = field(default_factory=set)
    inline: set[str] = field(default_factory=set)
    profiles: set[str] = field(default_factory=set)


@dataclass
class Account:
    caller_arn: str = f"arn:aws:sts::{ACCOUNT}:assumed-role/IncidentResponder/alice"
    users: dict[str, User] = field(default_factory=dict)
    roles: dict[str, Role] = field(default_factory=lambda: {"IncidentResponder": Role()})
    trails: dict[str, bool] = field(default_factory=dict)
    recorders: dict[str, bool] = field(default_factory=dict)
    detectors: dict[str, str] = field(default_factory=dict)
    hub: bool = True
    instances: dict[str, dict[str, Any]] = field(default_factory=dict)
    denied: set[str] = field(default_factory=set)  # IAM actions the simulator denies
    missing_context: dict[str, list[str]] = field(default_factory=dict)  # denied action -> condition keys the simulator lacked
    skew: timedelta | None = timedelta(0)  # AWS's clock minus the local one; None = no Date header
    documents: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)  # (user|role, name, policy) -> inline document
    calls: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)  # (service, operation, params), writes only

    def install(self, monkeypatch: Any, profile: str | None = None, regions: tuple[str, ...] = ("us-east-1",)) -> None:
        from controlzee.ingest import remote
        for service in ("sts", "iam", "ec2", "cloudtrail", "config", "guardduty", "securityhub"):
            for region in regions:
                monkeypatch.setitem(remote._clients, (service, profile, region), FakeClient(self, service, region))


_READS = ("get_", "list_", "describe_", "simulate_")


class FakeClient:
    def __init__(self, acct: Account, service: str, region: str) -> None:
        self.acct, self.service, self.region = acct, service, region
        real = boto3.client(service, region_name=region, aws_access_key_id="x", aws_secret_access_key="y")
        self._model = real.meta.service_model
        self._api = real.meta.method_to_api_mapping

    def get_paginator(self, method: str) -> Any:
        client = self

        class Pager:
            def paginate(self, **kw: Any) -> Any:
                yield getattr(client, method)(**kw)
        return Pager()

    def __getattr__(self, method: str) -> Any:
        if method not in self._api:
            raise AttributeError(method)
        op = self._api[method]

        def call(**kw: Any) -> Any:
            validate_parameters(kw, self._model.operation_model(op).input_shape)
            if not method.startswith(_READS):
                self.acct.calls.append((self.service, method, kw))
            return getattr(self, f"_{self.service}_{method}")(op, **kw)
        return call

    # ---- sts / iam

    def _sts_get_caller_identity(self, op: str) -> Any:
        meta = {} if self.acct.skew is None else {"HTTPHeaders": {"date": format_datetime(datetime.now(UTC) + self.acct.skew, usegmt=True)}}
        return {"Account": ACCOUNT, "Arn": self.acct.caller_arn, "UserId": "AROAFAKE:alice", "ResponseMetadata": meta}

    def _user(self, op: str, name: str) -> User:
        if name not in self.acct.users:
            raise _err("NoSuchEntity", op)
        return self.acct.users[name]

    def _role(self, op: str, name: str) -> Role:
        if name not in self.acct.roles:
            raise _err("NoSuchEntity", op)
        return self.acct.roles[name]

    def _iam_get_user(self, op: str, UserName: str) -> Any:  # noqa: N803 (AWS's spelling)
        self._user(op, UserName)
        return {"User": {"UserName": UserName, "Arn": f"arn:aws:iam::{ACCOUNT}:user/{UserName}"}}

    def _iam_get_role(self, op: str, RoleName: str) -> Any:  # noqa: N803
        self._role(op, RoleName)
        return {"Role": {"RoleName": RoleName, "Arn": f"arn:aws:iam::{ACCOUNT}:role/{RoleName}"}}

    def _iam_get_group(self, op: str, GroupName: str) -> Any:  # noqa: N803
        return {"Group": {"GroupName": GroupName, "Arn": f"arn:aws:iam::{ACCOUNT}:group/{GroupName}"}, "Users": []}

    def _iam_list_access_keys(self, op: str, UserName: str) -> Any:  # noqa: N803
        return {"AccessKeyMetadata": [{"AccessKeyId": k, "Status": s} for k, s in sorted(self._user(op, UserName).keys.items())]}

    def _iam_update_access_key(self, op: str, UserName: str, AccessKeyId: str, Status: str) -> Any:  # noqa: N803
        self._user(op, UserName).keys[AccessKeyId] = Status
        return {}

    def _iam_delete_access_key(self, op: str, UserName: str, AccessKeyId: str) -> Any:  # noqa: N803
        self._user(op, UserName).keys.pop(AccessKeyId)
        return {}

    def _iam_put_user_policy(self, op: str, UserName: str, PolicyName: str, PolicyDocument: str) -> Any:  # noqa: N803
        self._user(op, UserName).inline.add(PolicyName)
        self.acct.documents[("user", UserName, PolicyName)] = json.loads(PolicyDocument)
        return {}

    def _iam_put_role_policy(self, op: str, RoleName: str, PolicyName: str, PolicyDocument: str) -> Any:  # noqa: N803
        self._role(op, RoleName).inline.add(PolicyName)
        self.acct.documents[("role", RoleName, PolicyName)] = json.loads(PolicyDocument)
        return {}

    def _inline_document(self, op: str, kind: str, name: str, policy: str, inline: set[str]) -> Any:
        if policy not in inline:
            raise _err("NoSuchEntity", op)
        doc = self.acct.documents.get((kind, name, policy), {"Statement": []})
        return {"PolicyName": policy, "PolicyDocument": doc}  # boto3 hands back the decoded document

    def _iam_get_user_policy(self, op: str, UserName: str, PolicyName: str) -> Any:  # noqa: N803
        return {"UserName": UserName, **self._inline_document(op, "user", UserName, PolicyName, self._user(op, UserName).inline)}

    def _iam_get_role_policy(self, op: str, RoleName: str, PolicyName: str) -> Any:  # noqa: N803
        return {"RoleName": RoleName, **self._inline_document(op, "role", RoleName, PolicyName, self._role(op, RoleName).inline)}

    def _iam_get_login_profile(self, op: str, UserName: str) -> Any:  # noqa: N803
        if not self._user(op, UserName).login:
            raise _err("NoSuchEntity", op)
        return {"LoginProfile": {"UserName": UserName}}

    def _iam_delete_login_profile(self, op: str, UserName: str) -> Any:  # noqa: N803
        self._user(op, UserName).login = False
        return {}

    def _iam_list_attached_user_policies(self, op: str, UserName: str) -> Any:  # noqa: N803
        return {"AttachedPolicies": [{"PolicyArn": a} for a in sorted(self._user(op, UserName).attached)]}

    def _iam_detach_user_policy(self, op: str, UserName: str, PolicyArn: str) -> Any:  # noqa: N803
        self._user(op, UserName).attached.discard(PolicyArn)
        return {}

    def _iam_list_user_policies(self, op: str, UserName: str) -> Any:  # noqa: N803
        return {"PolicyNames": sorted(self._user(op, UserName).inline)}

    def _iam_delete_user_policy(self, op: str, UserName: str, PolicyName: str) -> Any:  # noqa: N803
        self._user(op, UserName).inline.discard(PolicyName)
        return {}

    def _iam_list_groups_for_user(self, op: str, UserName: str) -> Any:  # noqa: N803
        return {"Groups": [{"GroupName": g, "Arn": f"arn:aws:iam::{ACCOUNT}:group/{g}"} for g in sorted(self._user(op, UserName).groups)]}

    def _iam_remove_user_from_group(self, op: str, GroupName: str, UserName: str) -> Any:  # noqa: N803
        self._user(op, UserName).groups.discard(GroupName)
        return {}

    def _iam_list_mfa_devices(self, op: str, UserName: str) -> Any:  # noqa: N803
        return {"MFADevices": [{"SerialNumber": m} for m in self._user(op, UserName).mfa]}

    def _iam_list_ssh_public_keys(self, op: str, UserName: str) -> Any:  # noqa: N803
        return {"SSHPublicKeys": []}

    def _iam_list_signing_certificates(self, op: str, UserName: str) -> Any:  # noqa: N803
        return {"Certificates": []}

    def _iam_list_service_specific_credentials(self, op: str, UserName: str) -> Any:  # noqa: N803
        return {"ServiceSpecificCredentials": []}

    def _iam_delete_user(self, op: str, UserName: str) -> Any:  # noqa: N803
        u = self._user(op, UserName)
        if u.keys or u.login or u.attached or u.inline or u.groups or u.mfa:
            raise _err("DeleteConflict", op)
        del self.acct.users[UserName]
        return {}

    def _iam_list_attached_role_policies(self, op: str, RoleName: str) -> Any:  # noqa: N803
        return {"AttachedPolicies": [{"PolicyArn": a} for a in sorted(self._role(op, RoleName).attached)]}

    def _iam_detach_role_policy(self, op: str, RoleName: str, PolicyArn: str) -> Any:  # noqa: N803
        self._role(op, RoleName).attached.discard(PolicyArn)
        return {}

    def _iam_list_role_policies(self, op: str, RoleName: str) -> Any:  # noqa: N803
        return {"PolicyNames": sorted(self._role(op, RoleName).inline)}

    def _iam_delete_role_policy(self, op: str, RoleName: str, PolicyName: str) -> Any:  # noqa: N803
        self._role(op, RoleName).inline.discard(PolicyName)
        return {}

    def _iam_list_instance_profiles_for_role(self, op: str, RoleName: str) -> Any:  # noqa: N803
        return {"InstanceProfiles": [{"InstanceProfileName": p, "Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/{p}"}
                                     for p in sorted(self._role(op, RoleName).profiles)]}

    def _iam_delete_role(self, op: str, RoleName: str) -> Any:  # noqa: N803
        r = self._role(op, RoleName)
        if r.attached or r.inline or r.profiles:
            raise _err("DeleteConflict", op)
        del self.acct.roles[RoleName]
        return {}

    def _iam_simulate_principal_policy(self, op: str, PolicySourceArn: str, ActionNames: list[str], ResourceArns: list[str]) -> Any:  # noqa: N803
        if "iam:SimulatePrincipalPolicy" in self.acct.denied:
            raise _err("AccessDenied", op)
        return {"EvaluationResults": [{"EvalActionName": a, "EvalResourceName": r,
                                       "EvalDecision": "implicitDeny" if a in self.acct.denied else "allowed",
                                       **({"MissingContextValues": self.acct.missing_context[a]} if a in self.acct.missing_context else {})}
                                      for a in ActionNames for r in ResourceArns], "IsTruncated": False}

    # ---- logging and detection

    def _cloudtrail_get_trail_status(self, op: str, Name: str) -> Any:  # noqa: N803
        if Name not in self.acct.trails:
            raise _err("TrailNotFoundException", op)
        return {"IsLogging": self.acct.trails[Name]}

    def _cloudtrail_start_logging(self, op: str, Name: str) -> Any:  # noqa: N803
        self.acct.trails[Name] = True
        return {}

    def _config_describe_configuration_recorder_status(self, op: str, ConfigurationRecorderNames: list[str]) -> Any:  # noqa: N803
        return {"ConfigurationRecordersStatus": [{"name": n, "recording": self.acct.recorders[n]}
                                                 for n in ConfigurationRecorderNames if n in self.acct.recorders]}

    def _config_start_configuration_recorder(self, op: str, ConfigurationRecorderName: str) -> Any:  # noqa: N803
        self.acct.recorders[ConfigurationRecorderName] = True
        return {}

    def _securityhub_describe_hub(self, op: str) -> Any:
        if not self.acct.hub:
            raise _err("InvalidAccessException", op)
        return {"HubArn": "arn:aws:securityhub:us-east-1:111122223333:hub/default"}

    def _securityhub_enable_security_hub(self, op: str) -> Any:
        self.acct.hub = True
        return {}

    def _guardduty_list_detectors(self, op: str) -> Any:
        return {"DetectorIds": sorted(self.acct.detectors)}

    def _guardduty_get_detector(self, op: str, DetectorId: str) -> Any:  # noqa: N803
        return {"Status": self.acct.detectors[DetectorId], "ServiceRole": "x"}

    def _guardduty_create_detector(self, op: str, Enable: bool) -> Any:  # noqa: N803
        self.acct.detectors["newdetector"] = "ENABLED"
        return {"DetectorId": "newdetector"}

    def _guardduty_update_detector(self, op: str, DetectorId: str, Enable: bool) -> Any:  # noqa: N803
        self.acct.detectors[DetectorId] = "ENABLED"
        return {}

    # ---- ec2

    def _ec2_describe_instances(self, op: str, InstanceIds: list[str]) -> Any:  # noqa: N803
        found = [{"InstanceId": i, "State": {"Name": self.acct.instances[i]["state"]},
                  "BlockDeviceMappings": [{"Ebs": {"VolumeId": v}} for v in self.acct.instances[i]["volumes"]]}
                 for i in InstanceIds if i in self.acct.instances]
        if not found:
            raise _err("InvalidInstanceID.NotFound", op)
        return {"Reservations": [{"Instances": found}]}

    def _ec2_describe_iam_instance_profile_associations(self, op: str, Filters: list[Any]) -> Any:  # noqa: N803
        ids = Filters[0]["Values"]
        return {"IamInstanceProfileAssociations": [{"AssociationId": a, "InstanceId": i, "State": "associated"}
                                                   for i in ids for a in self.acct.instances.get(i, {}).get("assoc", [])]}

    def _ec2_disassociate_iam_instance_profile(self, op: str, AssociationId: str) -> Any:  # noqa: N803
        for inst in self.acct.instances.values():
            inst["assoc"] = [a for a in inst["assoc"] if a != AssociationId]
        return {}

    def _ec2_stop_instances(self, op: str, InstanceIds: list[str]) -> Any:  # noqa: N803
        for i in InstanceIds:
            self.acct.instances[i]["state"] = "stopping"
        return {}

    def _ec2_terminate_instances(self, op: str, InstanceIds: list[str]) -> Any:  # noqa: N803
        for i in InstanceIds:
            self.acct.instances[i]["state"] = "shutting-down"
        return {}

    def _ec2_create_snapshot(self, op: str, VolumeId: str, Description: str) -> Any:  # noqa: N803
        return {"SnapshotId": f"snap-{VolumeId[4:]}"}
