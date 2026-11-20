"""Compact descriptions of incidents, turned into CloudTrail logs by `cloudtrail.LogSet`."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Any

from tests.builders.cloudtrail import (
    ACCOUNT,
    HIDDEN,
    LogSet,
    assumed_role,
    at,
    iam_user,
    minutes,
    other_account,
    role_id,
)

OFFICE_IP = "203.0.113.10"
ATTACKER_IP = "198.51.100.77"
ATTACKER_IP_2 = "198.51.100.78"
ATTACKER_UA = "python-requests/2.31.0"
LEAKED_KEY = "AKIAIOSFODNN7LEAKED"
BACKDOOR_KEY = "AKIAIOSFODNN7BKDOOR"
OPS_SESSION_KEY = "ASIAIOSFODNN7OPSMNT"
PROD_SESSION_KEY = "ASIAIOSFODNN7PRODMT"
TOKEN_KEY = "ASIAIOSFODNN7JNKTOK"
AUDIT_SESSION_KEY = "ASIAIOSFODNN7AUDITS"
ATTACKER_INSTANCE = "i-0a1b2c3d4e5f60718"
CI_INSTANCE = "i-0f9e8d7c6b5a40312"


def _noise(logs: LogSet) -> None:
    """Ordinary activity by people and automation, on both sides of the incident, from the office network."""
    alice = iam_user("alice", "AKIAIOSFODNN7ALICE0")
    ci = assumed_role("deploy-role", "ci-run-4411", "ASIAIOSFODNN7CIROLE")
    t = at("2026-10-20T08:00:00Z")
    for i in range(6):
        logs.add(
            t + timedelta(hours=i * 3),
            "ec2.amazonaws.com",
            "DescribeInstances",
            alice,
            ip=OFFICE_IP,
            region="us-east-1",
        )
        logs.add(
            t + timedelta(hours=i * 3, minutes=5),
            "s3.amazonaws.com",
            "ListBuckets",
            alice,
            ip=OFFICE_IP,
            region="us-east-1",
        )
    for i in range(8):
        logs.add(
            t + timedelta(hours=i * 2, minutes=30),
            "s3.amazonaws.com",
            "PutObject",
            ci,
            ip="192.0.2.50",
            region="us-west-2",
            request={"bucketName": "build-artifacts", "key": f"builds/{i}.zip"},
            read_only=False,
        )
    logs.add(t + timedelta(hours=9), "sts.amazonaws.com", "GetCallerIdentity", alice, ip=OFFICE_IP)


def scenario_01_leaked_key() -> LogSet:
    """A leaked IAM user key creates a backdoor user, attaches AdministratorAccess and creates a new access key.

    The key's legitimate owner (the CI job) also used it from the office network, so seeding on the key alone also catches
    those two events; narrowing with the attacker IP in an AND expression removes them. The backdoor key's own activity is
    not a seed here (milestone 2 follows it by taint).
    """
    logs = LogSet()
    _noise(logs)
    ci_user = iam_user("ci-deploy", LEAKED_KEY)
    t = at("2026-10-20T14:30:00Z")
    logs.add(t - timedelta(hours=4), "s3.amazonaws.com", "ListBuckets", ci_user, ip=OFFICE_IP)
    logs.add(t - timedelta(hours=1), "ec2.amazonaws.com", "DescribeInstances", ci_user, ip=OFFICE_IP)
    kw = {"ip": ATTACKER_IP, "ua": ATTACKER_UA}
    logs.add(t, "sts.amazonaws.com", "GetCallerIdentity", ci_user, **kw)
    for off, (src, name) in enumerate(
        [
            ("iam.amazonaws.com", "ListUsers"),
            ("iam.amazonaws.com", "ListRoles"),
            ("s3.amazonaws.com", "ListBuckets"),
            ("ec2.amazonaws.com", "DescribeInstances"),
        ],
        1,
    ):
        logs.add(t + timedelta(seconds=10 * off), src, name, ci_user, **kw)
    logs.add(
        t + timedelta(seconds=55),
        "iam.amazonaws.com",
        "GetAccountAuthorizationDetails",
        ci_user,
        error=(
            "AccessDenied",
            "User: arn:aws:iam::111122223333:user/ci-deploy is not authorized to perform: iam:GetAccountAuthorizationDetails",
        ),
        **kw,
    )
    backdoor = iam_user("backdoor-svc", BACKDOOR_KEY)
    logs.add(
        t + timedelta(minutes=2),
        "iam.amazonaws.com",
        "CreateUser",
        ci_user,
        request={"userName": "backdoor-svc"},
        response={
            "user": {
                "path": "/",
                "userName": "backdoor-svc",
                "userId": backdoor["principalId"],
                "arn": f"arn:aws:iam::{ACCOUNT}:user/backdoor-svc",
                "createDate": "Oct 20, 2026 2:32:00 PM",
            }
        },
        **kw,
    )
    logs.add(
        t + timedelta(minutes=2, seconds=10),
        "iam.amazonaws.com",
        "AttachUserPolicy",
        ci_user,
        request={"userName": "backdoor-svc", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        **kw,
    )
    logs.add(
        t + timedelta(minutes=2, seconds=20),
        "iam.amazonaws.com",
        "CreateAccessKey",
        ci_user,
        request={"userName": "backdoor-svc"},
        response={
            "accessKey": {
                "userName": "backdoor-svc",
                "accessKeyId": BACKDOOR_KEY,
                "status": "Active",
                "createDate": "Oct 20, 2026 2:32:20 PM",
                "secretAccessKey": HIDDEN,
            }
        },
        **kw,
    )
    # activity by the new key, from a second attacker address
    logs.add(
        t + timedelta(minutes=9),
        "s3.amazonaws.com",
        "ListBuckets",
        backdoor,
        ip=ATTACKER_IP_2,
        ua=ATTACKER_UA,
    )
    logs.add(
        t + timedelta(minutes=10),
        "iam.amazonaws.com",
        "ListUsers",
        backdoor,
        ip=ATTACKER_IP_2,
        ua=ATTACKER_UA,
    )
    return logs


def _credentials(
    key: str, role: str | None = None, session: str | None = None, account: str = ACCOUNT
) -> dict[str, Any]:
    """An STS response as CloudTrail logs it: the key id is kept, the session token is not."""
    body: dict[str, Any] = {
        "credentials": {"accessKeyId": key, "sessionToken": HIDDEN, "expiration": "Oct 20, 2026 11:00:00 PM"}
    }
    if role and session:
        body["assumedRoleUser"] = {
            "assumedRoleId": f"{role_id(role)}:{session}",
            "arn": f"arn:aws:sts::{account}:assumed-role/{role}/{session}",
        }
    return body


def scenario_02_role_chain() -> LogSet:
    """A leaked key assumes a role, and the role session moves on: it creates a role for an outside account, assumes a
    role in a production account whose logs we do not have, and the leaked user also mints a session token.

    Followed by taint: the ops-admin session (AssumeRole), the session-token key (GetSessionToken), and every session of
    the role the attacker created (CreateRole), even though the outside account assumes it without any tainted key. Not
    followed: an administrator's own ops-admin session at the same time, which shares the role but not the credentials.
    Coverage: the production account 444455556666 was reached but sent no logs.
    """
    logs = LogSet()
    _noise(logs)
    jenkins = iam_user("jenkins", LEAKED_KEY)
    t = at("2026-10-20T10:00:00Z")
    kw = {"ip": ATTACKER_IP, "ua": ATTACKER_UA}
    logs.add(t, "sts.amazonaws.com", "GetCallerIdentity", jenkins, **kw)
    logs.add(t + timedelta(seconds=20), "iam.amazonaws.com", "ListRoles", jenkins, **kw)
    logs.add(
        t + timedelta(minutes=1),
        "sts.amazonaws.com",
        "AssumeRole",
        jenkins,
        request={"roleArn": f"arn:aws:iam::{ACCOUNT}:role/ops-admin", "roleSessionName": "maint"},
        response=_credentials(OPS_SESSION_KEY, "ops-admin", "maint"),
        **kw,
    )
    ops = assumed_role("ops-admin", "maint", OPS_SESSION_KEY)
    logs.add(t + timedelta(minutes=2), "s3.amazonaws.com", "ListBuckets", ops, **kw)
    logs.add(
        t + timedelta(minutes=3),
        "iam.amazonaws.com",
        "CreateRole",
        ops,
        request={
            "roleName": "support-audit",
            "assumeRolePolicyDocument": '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999900001111:root"},"Action":"sts:AssumeRole"}]}',
        },
        response={
            "role": {
                "roleName": "support-audit",
                "roleId": role_id("support-audit"),
                "arn": f"arn:aws:iam::{ACCOUNT}:role/support-audit",
                "path": "/",
            }
        },
        **kw,
    )
    logs.add(
        t + timedelta(minutes=3, seconds=10),
        "iam.amazonaws.com",
        "AttachRolePolicy",
        ops,
        request={"roleName": "support-audit", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
        **kw,
    )
    logs.add(
        t + timedelta(minutes=4),
        "sts.amazonaws.com",
        "AssumeRole",
        ops,
        request={"roleArn": "arn:aws:iam::444455556666:role/prod-deploy", "roleSessionName": "maint"},
        response=_credentials(PROD_SESSION_KEY, "prod-deploy", "maint", account="444455556666"),
        **kw,
    )
    logs.add(
        t + timedelta(minutes=5),
        "sts.amazonaws.com",
        "GetSessionToken",
        jenkins,
        request={"durationSeconds": 43200},
        response=_credentials(TOKEN_KEY),
        **kw,
    )
    # the session token in use, from a second address
    logs.add(
        t + timedelta(minutes=20),
        "ec2.amazonaws.com",
        "DescribeInstances",
        iam_user("jenkins", TOKEN_KEY),
        ip=ATTACKER_IP_2,
        ua=ATTACKER_UA,
    )
    # an administrator's own session of the same role, at the same time: not the attacker's
    logs.add(
        t + timedelta(minutes=6),
        "s3.amazonaws.com",
        "ListBuckets",
        assumed_role("ops-admin", "alice", "ASIAIOSFODNN7ALICE1"),
        ip=OFFICE_IP,
    )
    # the outside account assumes the attacker's role later; its call carries no tainted key, its sessions do act as the role
    t2 = at("2026-10-20T13:00:00Z")
    logs.add(
        t2,
        "sts.amazonaws.com",
        "AssumeRole",
        other_account("999900001111"),
        request={"roleArn": f"arn:aws:iam::{ACCOUNT}:role/support-audit", "roleSessionName": "audit"},
        response=_credentials(AUDIT_SESSION_KEY, "support-audit", "audit"),
        ip="198.51.100.200",
        ua=ATTACKER_UA,
    )
    audit = assumed_role("support-audit", "audit", AUDIT_SESSION_KEY)
    logs.add(
        t2 + timedelta(minutes=1),
        "s3.amazonaws.com",
        "ListBuckets",
        audit,
        ip="198.51.100.200",
        ua=ATTACKER_UA,
    )
    logs.add(
        t2 + timedelta(minutes=2),
        "secretsmanager.amazonaws.com",
        "ListSecrets",
        audit,
        ip="198.51.100.200",
        ua=ATTACKER_UA,
    )
    return logs


def scenario_03_instance_role() -> LogSet:
    """Only the attacker's network is known (weak, with a window). From it, a developer key launches an instance with an
    instance profile and creates a user with a console password.

    Followed by taint, and weak because the seed is: the instance's role sessions (session name = instance id) and the
    new user's console sign-in and calls. Both continue after the window ends, which does not stop them. Not followed: an
    instance launched by CI from the office with the same profile, whose sessions are someone else's.
    """
    logs = LogSet()
    _noise(logs)
    dev = iam_user("dev-sam", "AKIAIOSFODNN7DEVSAM")
    t = at("2026-10-20T15:05:00Z")
    kw = {"ip": "198.51.100.90", "ua": "Boto3/1.34.0 md/Botocore#1.34.0 ua/2.0 os/linux"}
    logs.add(t, "ec2.amazonaws.com", "DescribeInstanceTypes", dev, **kw)
    logs.add(
        t + timedelta(minutes=1),
        "ec2.amazonaws.com",
        "RunInstances",
        dev,
        request={
            "instanceType": "t3.micro",
            "iamInstanceProfile": {"name": "app-profile"},
            "imageId": "ami-0abcdef1234567890",
        },
        response={"instancesSet": {"items": [{"instanceId": ATTACKER_INSTANCE, "instanceType": "t3.micro"}]}},
        **kw,
    )
    logs.add(
        t + timedelta(minutes=2),
        "iam.amazonaws.com",
        "CreateUser",
        dev,
        request={"userName": "svc-metrics"},
        response={
            "user": {
                "userName": "svc-metrics",
                "userId": iam_user("svc-metrics", "")["principalId"],
                "arn": f"arn:aws:iam::{ACCOUNT}:user/svc-metrics",
                "path": "/",
            }
        },
        **kw,
    )
    logs.add(
        t + timedelta(minutes=2, seconds=30),
        "iam.amazonaws.com",
        "CreateLoginProfile",
        dev,
        request={"userName": "svc-metrics", "passwordResetRequired": False},
        **kw,
    )
    # CI launches its own instance with the same profile, from the office
    ci = assumed_role("deploy-role", "ci-run-4411", "ASIAIOSFODNN7CIROLE")
    logs.add(
        t + timedelta(minutes=3),
        "ec2.amazonaws.com",
        "RunInstances",
        ci,
        ip="192.0.2.50",
        request={"instanceType": "m5.large", "iamInstanceProfile": {"name": "app-profile"}},
        response={"instancesSet": {"items": [{"instanceId": CI_INSTANCE, "instanceType": "m5.large"}]}},
    )
    # the instances' role sessions, from their own addresses
    for n, (instance, ip) in enumerate([(ATTACKER_INSTANCE, "192.0.2.99"), (CI_INSTANCE, "192.0.2.51")]):
        session = assumed_role("app-role", instance, f"ASIAIOSFODNN7INST{n:02d}")
        session["invokedBy"] = "ec2.amazonaws.com"
        logs.add(
            t + timedelta(minutes=10 + n),
            "s3.amazonaws.com",
            "ListBuckets",
            session,
            ip=ip,
            ua="aws-sdk-go/1.50.0",
        )
        if instance == ATTACKER_INSTANCE:
            logs.add(
                t + timedelta(minutes=12),
                "secretsmanager.amazonaws.com",
                "ListSecrets",
                session,
                ip=ip,
                ua="aws-sdk-go/1.50.0",
            )
            logs.add(
                t + timedelta(hours=2),
                "secretsmanager.amazonaws.com",
                "GetSecretValue",
                session,
                ip=ip,
                ua="aws-sdk-go/1.50.0",
                request={"secretId": "prod/db"},
            )  # after the window
    # the new user signs in to the console from elsewhere, after the window
    svc = iam_user("svc-metrics", "")
    del svc["accessKeyId"]
    logs.add(
        t + timedelta(hours=3),
        "signin.amazonaws.com",
        "ConsoleLogin",
        svc,
        ip="192.0.2.150",
        ua="Mozilla/5.0 (X11; Linux x86_64)",
        response={"ConsoleLogin": "Success"},
        read_only=False,
    )
    logs.add(
        t + timedelta(hours=3, minutes=1),
        "iam.amazonaws.com",
        "ListUsers",
        {**svc, "accessKeyId": "ASIAIOSFODNN7CONSOL"},
        ip="192.0.2.150",
        ua="Mozilla/5.0 (X11; Linux x86_64)",
    )
    return logs


def scenario_04_log_tampering() -> LogSet:
    """A leaked key stops the trail, and the logs go silent until security turns it back on two hours later.

    A monitoring job polls every five minutes in us-east-1, so the silence there is plainly unusual. In us-west-2 only a CI
    job writes every two hours, so the same silence cannot be told apart from quiet and is not reported. The attacker
    also tries to delete GuardDuty (denied) and stops AWS Config; an earlier UpdateTrail by Terraform is listed as a
    logging change but not as a cause. Some S3 data events are present, so the data-event caveat does not apply.
    """
    logs = LogSet()
    _noise(logs)
    monitor = assumed_role("monitoring", "poller", "ASIAIOSFODNN7MONITR")
    day = at("2026-10-20T08:00:00Z")
    for n in range(16 * 12):
        logs.add(
            day + timedelta(minutes=5 * n),
            "monitoring.amazonaws.com",
            "DescribeAlarms",
            monitor,
            ip="192.0.2.60",
            ua="aws-sdk-java/2.25.0",
        )
    for n in range(4):
        logs.add(
            day + timedelta(hours=1, minutes=n),
            "s3.amazonaws.com",
            "GetObject",
            iam_user("alice", "AKIAIOSFODNN7ALICE0"),
            ip=OFFICE_IP,
            request={"bucketName": "reports", "key": f"q3/{n}.pdf"},
            category="Data",
        )
    logs.add(
        day + timedelta(hours=1, minutes=30),
        "cloudtrail.amazonaws.com",
        "UpdateTrail",
        assumed_role("terraform", "apply", "ASIAIOSFODNN7TFAPPL"),
        ip="192.0.2.50",
        request={"name": "org-trail", "isMultiRegionTrail": True},
        read_only=False,
    )
    ci_user = iam_user("ci-deploy", LEAKED_KEY)
    t = at("2026-10-20T14:30:00Z")
    kw = {"ip": ATTACKER_IP, "ua": ATTACKER_UA}
    logs.add(t, "sts.amazonaws.com", "GetCallerIdentity", ci_user, **kw)
    logs.add(t + timedelta(minutes=1), "cloudtrail.amazonaws.com", "DescribeTrails", ci_user, **kw)
    logs.add(t + timedelta(minutes=1, seconds=30), "guardduty.amazonaws.com", "ListDetectors", ci_user, **kw)
    logs.add(
        t + timedelta(minutes=1, seconds=40),
        "guardduty.amazonaws.com",
        "DeleteDetector",
        ci_user,
        request={"detectorId": "12abc34d567e8fa901bc2d34e56789f0"},
        error=("AccessDeniedException", "User is not authorized to perform: guardduty:DeleteDetector"),
        **kw,
    )
    logs.add(
        t + timedelta(minutes=2),
        "config.amazonaws.com",
        "StopConfigurationRecorder",
        ci_user,
        request={"configurationRecorderName": "default"},
        read_only=False,
        **kw,
    )
    stop = t + timedelta(minutes=3)
    logs.add(
        stop,
        "cloudtrail.amazonaws.com",
        "StopLogging",
        ci_user,
        request={"name": f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/org-trail"},
        read_only=False,
        **kw,
    )
    restart = at("2026-10-20T16:40:00Z")
    logs.add(
        restart,
        "cloudtrail.amazonaws.com",
        "StartLogging",
        iam_user("secops", "AKIAIOSFODNN7SECOPS"),
        ip=OFFICE_IP,
        request={"name": f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/org-trail"},
        read_only=False,
    )
    logs.add(
        restart + timedelta(minutes=20), "s3.amazonaws.com", "ListBuckets", ci_user, **kw
    )  # the attacker is still around
    # nothing is recorded while the trail is stopped
    off = (stop.strftime("%Y-%m-%dT%H:%M:%SZ"), restart.strftime("%Y-%m-%dT%H:%M:%SZ"))
    logs.records = [r for r in logs.records if not off[0] < r["eventTime"] < off[1]]
    return logs


def scenario_06_lambda() -> LogSet:
    """A leaked key creates a Lambda function with an existing execution role, and replaces the code of another.

    Followed by taint: the sessions of the function it created (session name = function name) once it exists, and the
    sessions of `billing-report` after its code was replaced. Not followed: `billing-report` running before the change,
    and an unrelated function using the same role. Lambda logs its event names with an API version suffix.
    """
    logs = LogSet()
    _noise(logs)
    attacker = iam_user("ci-deploy", LEAKED_KEY)
    t = at("2026-10-20T11:00:00Z")
    kw = {"ip": ATTACKER_IP, "ua": ATTACKER_UA}
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/lambda-exec"

    def runs(
        function: str, key: str, when
    ) -> None:  # an invocation, as the function's role session logs its calls
        session = assumed_role("lambda-exec", function, key)
        session["invokedBy"] = "lambda.amazonaws.com"
        logs.add(
            when,
            "secretsmanager.amazonaws.com",
            "GetSecretValue",
            session,
            ip="198.51.100.150",
            ua="Boto3/1.34 exec-env/AWS_Lambda_python3.12",
            request={"secretId": "prod/db"},
        )

    runs("billing-report", "ASIAIOSFODNN7BILLR1", t - timedelta(hours=2))  # the function as it was
    logs.add(t, "sts.amazonaws.com", "GetCallerIdentity", attacker, **kw)
    logs.add(
        t + timedelta(minutes=1),
        "lambda.amazonaws.com",
        "CreateFunction20150331",
        attacker,
        request={
            "functionName": "exfil-fn",
            "runtime": "python3.12",
            "role": role_arn,
            "handler": "app.handler",
        },
        response={
            "functionName": "exfil-fn",
            "functionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:exfil-fn",
            "role": role_arn,
        },
        read_only=False,
        **kw,
    )
    logs.add(
        t + timedelta(minutes=3),
        "lambda.amazonaws.com",
        "UpdateFunctionCode20150331v2",
        attacker,
        request={"functionName": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:billing-report:$LATEST"},
        response={"functionName": "billing-report", "role": role_arn},
        read_only=False,
        **kw,
    )
    runs("exfil-fn", "ASIAIOSFODNN7EXFIL01", t + timedelta(minutes=5))
    runs(
        "billing-report", "ASIAIOSFODNN7BILLR2", t + timedelta(minutes=10)
    )  # now running the attacker's code
    runs("other-fn", "ASIAIOSFODNN7OTHER01", t + timedelta(minutes=11))  # same role, unrelated function
    return logs


def scenario_05_weak_ioc() -> LogSet:
    """Only a shared NAT address is known. Attackers and legitimate staff both appear behind it.

    A window is therefore required. Events from the address outside the window, and events inside it with a different user
    agent, show up as near misses when the IOC is narrowed with a user-agent AND.
    """
    logs = LogSet()
    _noise(logs)
    nat = "203.0.113.200"
    alice = iam_user("alice", "AKIAIOSFODNN7ALICE0")
    mallory = iam_user("mallory-temp", "AKIAIOSFODNN7MALLORY")
    t = at("2026-10-20T16:00:00Z")
    logs.add(
        t - timedelta(days=1), "s3.amazonaws.com", "ListBuckets", alice, ip=nat, ua="aws-cli/2.15.0"
    )  # before the window
    logs.add(
        t + timedelta(minutes=1), "s3.amazonaws.com", "ListBuckets", alice, ip=nat, ua="aws-cli/2.15.0"
    )  # legitimate, inside
    logs.add(t + timedelta(minutes=2), "iam.amazonaws.com", "ListUsers", mallory, ip=nat, ua="curl/8.4.0")
    logs.add(
        t + timedelta(minutes=3),
        "iam.amazonaws.com",
        "CreateAccessKey",
        mallory,
        ip=nat,
        ua="curl/8.4.0",
        request={"userName": "mallory-temp"},
        response={"accessKey": {"accessKeyId": "AKIAIOSFODNN7MALKEY2", "secretAccessKey": HIDDEN}},
    )
    logs.add(
        t + timedelta(minutes=4),
        "ec2.amazonaws.com",
        "DescribeSecurityGroups",
        mallory,
        ip=nat,
        ua="curl/8.4.0",
        error=("UnauthorizedOperation", "You are not authorized to perform this operation."),
        read_only=True,
    )
    logs.add(
        t + timedelta(days=1), "s3.amazonaws.com", "ListBuckets", mallory, ip=nat, ua="curl/8.4.0"
    )  # after the window
    return logs


OUTSIDE_ACCOUNT = "444455556666"
EXTERNAL_SESSION_KEY = "ASIAIOSFODNN7EXT001"
OPS_KEY_BEFORE = "ASIAIOSFODNN7OPS001"
OPS_KEY_AFTER = "ASIAIOSFODNN7OPS002"


def scenario_07_trust_backdoor() -> LogSet:
    """A leaked key rewrites the trust policy of an existing role, `ops-admin`, to name an outside account.

    The role already trusts `deploy-role` (its CI), which assumes it before and after the change; the new policy keeps that
    and adds the outside account (and an EC2 service statement, which is not a principal anyone can call as). Later the
    outside account assumes the role (logged here as an AWSAccount caller, with no tainted key) and uses the session.

    Followed by taint: the outside account's AssumeRole call and everything done with the session it received. Not
    followed: the CI's own AssumeRole calls and its sessions, before or after the change, although the policy names it
    too, because it had assumed the role before the policy changed.
    """
    logs = LogSet()
    _noise(logs)
    attacker = iam_user("ci-deploy", LEAKED_KEY)
    ci = assumed_role("deploy-role", "ci-run-4411", "ASIAIOSFODNN7CIROLE")
    t = at("2026-10-20T12:00:00Z")
    kw = {"ip": ATTACKER_IP, "ua": ATTACKER_UA}
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/ops-admin"

    def assumes(when, caller, session: str, key: str, **extra) -> None:
        logs.add(
            when,
            "sts.amazonaws.com",
            "AssumeRole",
            caller,
            request={"roleArn": role_arn, "roleSessionName": session},
            response=_credentials(key, "ops-admin", session),
            read_only=False,
            **extra,
        )

    assumes(t - timedelta(hours=3), ci, "ci-run-4400", OPS_KEY_BEFORE, ip="192.0.2.50")
    logs.add(t, "sts.amazonaws.com", "GetCallerIdentity", attacker, **kw)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/deploy-role"},
                "Action": "sts:AssumeRole",
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{OUTSIDE_ACCOUNT}:root"},
                "Action": "sts:AssumeRole",
            },
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"},
        ],
    }
    logs.add(
        t + timedelta(minutes=2),
        "iam.amazonaws.com",
        "UpdateAssumeRolePolicy",
        attacker,
        request={"roleName": "ops-admin", "policyDocument": json.dumps(trust, indent=2)},
        response=None,
        read_only=False,
        **kw,
    )
    assumes(
        t + timedelta(minutes=20),
        other_account(OUTSIDE_ACCOUNT),
        "persist",
        EXTERNAL_SESSION_KEY,
        ip=ATTACKER_IP_2,
        ua=ATTACKER_UA,
    )
    outside = assumed_role("ops-admin", "persist", EXTERNAL_SESSION_KEY)
    logs.add(
        t + timedelta(minutes=22), "iam.amazonaws.com", "ListUsers", outside, ip=ATTACKER_IP_2, ua=ATTACKER_UA
    )
    logs.add(
        t + timedelta(minutes=24),
        "secretsmanager.amazonaws.com",
        "GetSecretValue",
        outside,
        ip=ATTACKER_IP_2,
        ua=ATTACKER_UA,
        request={"secretId": "prod/db"},
    )
    assumes(t + timedelta(minutes=30), ci, "ci-run-4412", OPS_KEY_AFTER, ip="192.0.2.50")
    after = assumed_role("ops-admin", "ci-run-4412", OPS_KEY_AFTER)
    logs.add(
        t + timedelta(minutes=32),
        "s3.amazonaws.com",
        "PutObject",
        after,
        ip="192.0.2.50",
        request={"bucketName": "build-artifacts", "key": "builds/after.zip"},
        read_only=False,
    )
    return logs


# ---- scenario 8: identity providers --------------------------------------------------------------------------------
# Record shapes follow .team/briefs/CONTRACT-W3B.md. The documented ones (AssumeRoleWithWebIdentity, the AssumeRoleWithSAML
# requestParameters) are written as documented. The UNVERIFIED ones are built by the helpers below and nowhere else, so
# the paths can be corrected in one place after a live capture:
#   CreateOpenIDConnectProvider          responseElements.openIDConnectProviderArn
#   CreateSAMLProvider                   responseElements.sAMLProviderArn, requestParameters.sAMLMetadataDocument
#   Update/AddClientID...OpenIDConnect   requestParameters.openIDConnectProviderArn
#   UpdateSAMLProvider                   requestParameters.sAMLProviderArn
#   AssumeRoleWithSAML                   userIdentity {type, userName}; responseElements {subject, credentials,
#                                        assumedRoleUser}
OIDC_CREATED_RESPONSE_PATH = "openIDConnectProviderArn"
SAML_CREATED_RESPONSE_PATH = "sAMLProviderArn"
SAML_USER_IDENTITY_TYPE = "SAMLUser"

IDP_T0 = "2026-10-21T10:00:00Z"
IDP_AUDIENCE = "sts.example.com"
OIDC_ATTACKER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.attacker.example.com"  # created by the attacker
SAML_ATTACKER = f"arn:aws:iam::{ACCOUNT}:saml-provider/attacker-idp"  # created by the attacker
OIDC_CI = f"arn:aws:iam::{ACCOUNT}:oidc-provider/ci.example.com"  # legitimate; a client id is added
OIDC_BUILD = f"arn:aws:iam::{ACCOUNT}:oidc-provider/build.example.com"  # legitimate; thumbprint changed
OIDC_CORP = f"arn:aws:iam::{ACCOUNT}:oidc-provider/login.corp.example.com"  # legitimate, never changed; a role's policy names it
SAML_CORP = f"arn:aws:iam::{ACCOUNT}:saml-provider/corp-sso"  # legitimate, never touched
SAML_CHANGED = (
    f"arn:aws:iam::{ACCOUNT}:saml-provider/corp-sso-2"  # legitimate; UpdateSAMLProvider by the attacker
)
OIDC_NEWLINE = (
    f"arn:aws:iam::{ACCOUNT}:oidc-provider/newline.attacker.example.com\n"  # a trailing newline: not an ARN
)
OIDC_CONTROL = (
    f"arn:aws:iam::{ACCOUNT}:oidc-provider/ctl.attacker.example.com\x1b[31mred\x00"  # control characters
)
ROLE_ARN_AS_PROVIDER = f"arn:aws:iam::{ACCOUNT}:role/not-a-provider"
SAML_WRONGTYPE = f"arn:aws:iam::{ACCOUNT}:saml-provider/wrongtype-idp"  # a SAML ARN where an OIDC one belongs
OIDC_WRONGTYPE = (
    f"arn:aws:iam::{ACCOUNT}:oidc-provider/wrongtype.attacker.example.com"  # and the other way round
)
IDP_SAML_METADATA = (
    '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"/>'
)

# every fake key id here is 19 characters (a real access key id is 20)
IDP_KEYS = {
    name: f"ASIAIOSFODNN7{name}"
    for name in (
        "WEB001", "WEB002", "ATK01A", "ATK01B", "ATK01C", "ATK01D", "ATK01E", "COG001", "SAMLB1", "SAMLB2", "SAMLB3",
        "SAMLA1", "SAMLC1", "SAMLC2", "SAMLM1", "CIB001", "CIB002", "CIA001", "CHG001", "BLD001", "BLD002", "BLD003",
        "DRD001", "DRD002", "DRA001", "DRO001",
    )
}  # fmt: skip


def _idp_iam_event(logs: LogSet, when, name: str, caller, request=None, response=None, error=None) -> None:
    logs.add(
        when,
        "iam.amazonaws.com",
        name,
        caller,
        ip=ATTACKER_IP,
        ua=ATTACKER_UA,
        request=request,
        response=response,
        error=error,
        read_only=False,
    )


def _create_oidc(logs: LogSet, when, caller, url: str, arn: str | None, error=None) -> None:
    thumbprint = "9e99a48a9960b14926bb7f3b02e22da2b0ab7280"
    _idp_iam_event(
        logs,
        when,
        "CreateOpenIDConnectProvider",
        caller,
        request={"url": url, "clientIDList": [IDP_AUDIENCE], "thumbprintList": [thumbprint]},
        response=None if arn is None else {OIDC_CREATED_RESPONSE_PATH: arn},
        error=error,
    )


def _create_saml(logs: LogSet, when, caller, name: str, arn: str, metadata: str = IDP_SAML_METADATA) -> None:
    _idp_iam_event(
        logs,
        when,
        "CreateSAMLProvider",
        caller,
        request={"name": name, "sAMLMetadataDocument": metadata},
        response={SAML_CREATED_RESPONSE_PATH: arn},
    )


def idp_assume_web_identity(
    logs: LogSet,
    when,
    *,
    role: str,
    session: str,
    subject: str,
    key: str | None,
    provider: str | None,
    identity_provider: str | None = None,
    error: tuple[str, str] | None = None,
    ip: str = "198.51.100.90",
) -> None:
    """A documented AssumeRoleWithWebIdentity record. `provider` is responseElements.provider (None leaves it out);
    `identity_provider` is userIdentity.identityProvider (defaults to `provider`; AWS says it can be an issuer name)."""
    shown = identity_provider if identity_provider is not None else provider
    caller = {
        "type": "WebIdentityUser",
        "principalId": f"{shown}:{IDP_AUDIENCE}:{subject}",
        "userName": subject,
        "identityProvider": shown,
    }
    response = _credentials(key, role, session) if key else {}
    response["subjectFromWebIdentityToken"] = subject
    if provider:
        response["provider"] = provider
        response["audience"] = IDP_AUDIENCE
    logs.add(
        when,
        "sts.amazonaws.com",
        "AssumeRoleWithWebIdentity",
        caller,
        ip=ip,
        ua="aws-sdk-go/1.44.0",
        request={"roleArn": f"arn:aws:iam::{ACCOUNT}:role/{role}", "roleSessionName": session},
        response=response,
        error=error,
        read_only=False,
    )


def idp_assume_saml(
    logs: LogSet, when, *, role: str, session: str, subject: str, key: str, provider: str
) -> None:
    """AssumeRoleWithSAML: requestParameters as documented; the rest per the contract's UNVERIFIED list."""
    caller = {
        "type": SAML_USER_IDENTITY_TYPE,
        "principalId": f"{role_id(role)}:{subject}",
        "userName": subject,
    }
    response = _credentials(key, role, session)
    response["subject"] = subject
    assertion = hashlib.sha1(session.encode()).hexdigest()[:16]
    logs.add(
        when,
        "sts.amazonaws.com",
        "AssumeRoleWithSAML",
        caller,
        ip="198.51.100.91",
        ua="aws-sdk-go/1.44.0",
        request={
            "roleArn": f"arn:aws:iam::{ACCOUNT}:role/{role}",
            "principalArn": provider,
            "roleSessionName": session,
            "sAMLAssertionID": f"_{assertion}",
        },
        response=response,
        read_only=False,
    )


def scenario_08_identity_provider() -> LogSet:
    """A leaked key plants login paths AWS trusts, so the attacker holds role credentials without any access key.

    Followed by taint (event name, provider, subject):
      1. AssumeRoleWithWebIdentity through the OIDC provider the attacker created (token.attacker.example.com), and what
         the sessions did; including two provider-shape variants (an issuer name in userIdentity with the ARN in the
         response; the ARN only in userIdentity).
      2. AssumeRoleWithSAML through the SAML provider the attacker created (attacker-idp), and the session's use.
      3. Through legitimate providers the attacker changed (ci.example.com client id, build.example.com thumbprint,
         corp-sso-2 UpdateSAMLProvider): only subjects not seen through that provider before the change.
      5. Into data-reader, a role whose trust policy the attacker rewrote to name login.corp.example.com: a new subject.
    Not followed: the legitimate users of the same roles (1, 3, 5), the untouched SAML provider corp-sso (4), the corp
    provider into a different role than the one rewritten, failures (6) and hostile values: ARNs with a trailing newline,
    control characters or the wrong type, a subject containing "|" (the fact is dropped whole), an issuer name with no
    ARN anywhere.
    """
    logs = LogSet()
    _noise(logs)
    attacker = iam_user("ci-deploy", LEAKED_KEY)
    t = at(IDP_T0)
    k = IDP_KEYS

    def minute(n: float):
        return minutes(t, n)

    def used(when, role, session, key, name, source, request=None, ip="198.51.100.90") -> None:
        logs.add(
            when, source, name, assumed_role(role, session, key), ip=ip, ua="aws-cli/2.15.0", request=request
        )

    def secret(when, role, session, key, secret_id="prod/db", ip="198.51.100.90") -> None:
        used(
            when,
            role,
            session,
            key,
            "GetSecretValue",
            "secretsmanager.amazonaws.com",
            {"secretId": secret_id},
            ip,
        )

    def web(n, **kw) -> None:
        idp_assume_web_identity(logs, minute(n), **kw)

    def saml(n, **kw) -> None:
        idp_assume_saml(logs, minute(n), **kw)

    office = "192.0.2.60"
    # --- legitimate traffic before the incident
    web(
        -180,
        role="web-deploy",
        session="alice-web",
        subject="alice@corp.example",
        key=k["WEB001"],
        provider=OIDC_CORP,
        ip=office,
    )
    used(
        minute(-175),
        "web-deploy",
        "alice-web",
        k["WEB001"],
        "PutObject",
        "s3.amazonaws.com",
        {"bucketName": "site-assets", "key": "a.css"},
        office,
    )
    web(
        -120,
        role="data-reader",
        session="alice-data",
        subject="alice@corp.example",
        key=k["DRD001"],
        provider=OIDC_CORP,
        ip=office,
    )
    used(
        minute(-118),
        "data-reader",
        "alice-data",
        k["DRD001"],
        "ListBuckets",
        "s3.amazonaws.com",
        None,
        office,
    )
    web(
        -180,
        role="ci-web-role",
        session="ci-main-1",
        subject="repo:acme/app:ref:main",
        key=k["CIB001"],
        provider=OIDC_CI,
        ip="192.0.2.61",
    )
    web(
        -60,
        role="ci-web-role",
        session="ci-main-2",
        subject="repo:acme/app:ref:main",
        key=k["CIB002"],
        provider=OIDC_CI,
        ip="192.0.2.61",
    )
    web(
        -60,
        role="build-role",
        session="builder-1",
        subject="builder-1",
        key=k["BLD001"],
        provider=OIDC_BUILD,
        ip="192.0.2.62",
    )
    saml(
        -240,
        role="saml-admin",
        session="bob-1",
        subject="bob@corp.example",
        key=k["SAMLB1"],
        provider=SAML_CORP,
    )
    saml(
        -30,
        role="saml-admin",
        session="bob-2",
        subject="bob@corp.example",
        key=k["SAMLB2"],
        provider=SAML_CORP,
    )
    used(
        minute(-28),
        "saml-admin",
        "bob-2",
        k["SAMLB2"],
        "ListUsers",
        "iam.amazonaws.com",
        None,
        "198.51.100.91",
    )
    saml(
        -120,
        role="saml-ro",
        session="carol-1",
        subject="carol@corp.example",
        key=k["SAMLC1"],
        provider=SAML_CHANGED,
    )

    # --- the attacker, with the leaked key, plants providers and edits trust
    logs.add(t, "sts.amazonaws.com", "GetCallerIdentity", attacker, ip=ATTACKER_IP, ua=ATTACKER_UA)
    _create_oidc(logs, minute(1), attacker, "https://token.attacker.example.com", OIDC_ATTACKER)
    _create_saml(logs, minute(2), attacker, "attacker-idp", SAML_ATTACKER)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Federated": [OIDC_CORP, "cognito-identity.amazonaws.com"]}, "Action": "sts:AssumeRoleWithWebIdentity"},
            # an AWS principal needs sts:AssumeRole; this statement names a role for the web-identity action only
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/not-a-caller"}, "Action": "sts:AssumeRoleWithWebIdentity"},
        ],
    }  # fmt: skip
    policy = json.dumps(trust, indent=2)
    _idp_iam_event(
        logs,
        minute(3),
        "UpdateAssumeRolePolicy",
        attacker,
        {"roleName": "data-reader", "policyDocument": policy},
    )
    # a failure hands over nothing
    limit = ("LimitExceeded", "Cannot exceed quota for OpenIdConnectProvidersPerAccount: 100")
    _create_oidc(logs, minute(4), attacker, "https://failed.attacker.example.com", None, error=limit)
    # hostile values in a successful response: none is an OIDC provider ARN
    _create_oidc(logs, minute(5), attacker, "https://newline.attacker.example.com", OIDC_NEWLINE)
    _create_oidc(logs, minute(5.2), attacker, "https://ctl.attacker.example.com", OIDC_CONTROL)
    _create_oidc(logs, minute(5.4), attacker, "https://wrongtype.attacker.example.com", ROLE_ARN_AS_PROVIDER)
    _create_oidc(logs, minute(5.6), attacker, "https://samlarn.attacker.example.com", SAML_WRONGTYPE)
    _create_saml(logs, minute(5.8), attacker, "oidc-arn-idp", OIDC_WRONGTYPE)
    # changes to legitimate providers
    _idp_iam_event(
        logs,
        minute(6),
        "AddClientIDToOpenIDConnectProvider",
        attacker,
        {"openIDConnectProviderArn": OIDC_CI, "clientID": "attacker-app"},
    )
    thumbprints = ["0123456789abcdef0123456789abcdef01234567"]
    _idp_iam_event(
        logs,
        minute(7),
        "UpdateOpenIDConnectProviderThumbprint",
        attacker,
        {"openIDConnectProviderArn": OIDC_BUILD, "thumbprintList": thumbprints},
    )
    _idp_iam_event(
        logs,
        minute(8),
        "UpdateSAMLProvider",
        attacker,
        {"sAMLProviderArn": SAML_CHANGED, "sAMLMetadataDocument": IDP_SAML_METADATA},
    )

    # --- 1. sessions through the OIDC provider the attacker created
    web(
        10,
        role="web-deploy",
        session="atk-web",
        subject="attacker-sub-1",
        key=k["ATK01A"],
        provider=OIDC_ATTACKER,
    )
    secret(minute(12), "web-deploy", "atk-web", k["ATK01A"])
    denied = ("AccessDenied", "Not authorized to perform sts:AssumeRoleWithWebIdentity")
    web(
        11,
        role="web-deploy",
        session="atk-fail",
        subject="attacker-sub-fail",
        key=None,
        provider=None,
        identity_provider=OIDC_ATTACKER,
        error=denied,
    )
    web(
        13, role="web-deploy", session="atk-pipe", subject="evil|sub", key=k["ATK01B"], provider=OIDC_ATTACKER
    )
    secret(minute(13.5), "web-deploy", "atk-pipe", k["ATK01B"], "prod/pipe")
    web(
        14,
        role="web-deploy",
        session="atk-iss",
        subject="attacker-sub-1b",
        key=k["ATK01C"],
        provider=OIDC_ATTACKER,
        identity_provider="token.attacker.example.com",
    )
    secret(minute(14.5), "web-deploy", "atk-iss", k["ATK01C"], "prod/issuer")
    web(
        15,
        role="web-deploy",
        session="atk-arn",
        subject="attacker-sub-1c",
        key=k["ATK01D"],
        provider=None,
        identity_provider=OIDC_ATTACKER,
    )
    secret(minute(15.5), "web-deploy", "atk-arn", k["ATK01D"], "prod/arnonly")
    web(
        16,
        role="web-deploy",
        session="cog-1",
        subject="cog-user-1",
        key=k["COG001"],
        provider=None,
        identity_provider="cognito-identity.amazonaws.com",
    )
    secret(minute(16.5), "web-deploy", "cog-1", k["COG001"], "prod/cognito")
    web(
        17,
        role="web-deploy",
        session="nl-1",
        subject="attacker-sub-nl",
        key=k["ATK01E"],
        provider=OIDC_NEWLINE,
    )
    secret(minute(17.5), "web-deploy", "nl-1", k["ATK01E"], "prod/newline")
    # --- 2. the SAML provider the attacker created
    saml(
        20,
        role="saml-admin",
        session="atk-saml",
        subject="attacker@evil.example",
        key=k["SAMLA1"],
        provider=SAML_ATTACKER,
    )
    secret(minute(22), "saml-admin", "atk-saml", k["SAMLA1"], "prod/saml", "198.51.100.91")
    # --- 3. legitimate providers the attacker changed
    web(30, role="ci-web-role", session="atk-ci", subject="attacker-sub-3", key=k["CHG001"], provider=OIDC_CI)
    secret(minute(31), "ci-web-role", "atk-ci", k["CHG001"], "prod/ci")
    web(
        32,
        role="ci-web-role",
        session="ci-main-3",
        subject="repo:acme/app:ref:main",
        key=k["CIA001"],
        provider=OIDC_CI,
        ip="192.0.2.61",
    )
    used(
        minute(33),
        "ci-web-role",
        "ci-main-3",
        k["CIA001"],
        "PutObject",
        "s3.amazonaws.com",
        {"bucketName": "build-artifacts", "key": "builds/after.zip"},
        "192.0.2.61",
    )
    web(
        36,
        role="build-role",
        session="atk-build",
        subject="attacker-sub-3b",
        key=k["BLD002"],
        provider=OIDC_BUILD,
    )
    secret(minute(37), "build-role", "atk-build", k["BLD002"], "prod/build")
    web(
        38,
        role="build-role",
        session="builder-2",
        subject="builder-1",
        key=k["BLD003"],
        provider=OIDC_BUILD,
        ip="192.0.2.62",
    )
    used(
        minute(39),
        "build-role",
        "builder-2",
        k["BLD003"],
        "PutObject",
        "s3.amazonaws.com",
        {"bucketName": "build-artifacts", "key": "builds/b.zip"},
        "192.0.2.62",
    )
    saml(
        40,
        role="saml-ro",
        session="atk-saml2",
        subject="mallory@evil.example",
        key=k["SAMLM1"],
        provider=SAML_CHANGED,
    )
    secret(minute(41), "saml-ro", "atk-saml2", k["SAMLM1"], "prod/saml2", "198.51.100.91")
    saml(
        42,
        role="saml-ro",
        session="carol-2",
        subject="carol@corp.example",
        key=k["SAMLC2"],
        provider=SAML_CHANGED,
    )
    used(
        minute(43), "saml-ro", "carol-2", k["SAMLC2"], "ListRoles", "iam.amazonaws.com", None, "198.51.100.91"
    )
    # --- 5. the role whose trust policy now names the corp provider
    web(
        50,
        role="data-reader",
        session="atk-data",
        subject="attacker-sub-5",
        key=k["DRA001"],
        provider=OIDC_CORP,
    )
    secret(minute(51), "data-reader", "atk-data", k["DRA001"], "prod/data")
    web(
        52,
        role="web-deploy",
        session="atk-other",
        subject="attacker-sub-5",
        key=k["DRO001"],
        provider=OIDC_CORP,
    )  # a role the change did not touch
    secret(minute(53), "web-deploy", "atk-other", k["DRO001"], "prod/otherrole")
    web(
        55,
        role="data-reader",
        session="alice-data-2",
        subject="alice@corp.example",
        key=k["DRD002"],
        provider=OIDC_CORP,
        ip=office,
    )
    used(
        minute(56),
        "data-reader",
        "alice-data-2",
        k["DRD002"],
        "ListBuckets",
        "s3.amazonaws.com",
        None,
        office,
    )
    # --- 4. the untouched legitimate SAML provider, and the corp provider's usual user, after
    saml(
        180,
        role="saml-admin",
        session="bob-3",
        subject="bob@corp.example",
        key=k["SAMLB3"],
        provider=SAML_CORP,
    )
    used(
        minute(182),
        "saml-admin",
        "bob-3",
        k["SAMLB3"],
        "ListUsers",
        "iam.amazonaws.com",
        None,
        "198.51.100.91",
    )
    web(
        185,
        role="web-deploy",
        session="alice-web-2",
        subject="alice@corp.example",
        key=k["WEB002"],
        provider=OIDC_CORP,
        ip=office,
    )
    used(
        minute(186),
        "web-deploy",
        "alice-web-2",
        k["WEB002"],
        "PutObject",
        "s3.amazonaws.com",
        {"bucketName": "site-assets", "key": "b.css"},
        office,
    )
    return logs
