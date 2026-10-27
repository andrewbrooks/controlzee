"""Compact descriptions of incidents, turned into CloudTrail logs by `cloudtrail.LogSet`."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from tests.builders.cloudtrail import (
    ACCOUNT,
    HIDDEN,
    LogSet,
    assumed_role,
    at,
    iam_user,
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
        logs.add(t + timedelta(hours=i * 3), "ec2.amazonaws.com", "DescribeInstances", alice, ip=OFFICE_IP, region="us-east-1")
        logs.add(t + timedelta(hours=i * 3, minutes=5), "s3.amazonaws.com", "ListBuckets", alice, ip=OFFICE_IP, region="us-east-1")
    for i in range(8):
        logs.add(t + timedelta(hours=i * 2, minutes=30), "s3.amazonaws.com", "PutObject", ci, ip="192.0.2.50", region="us-west-2",
                 request={"bucketName": "build-artifacts", "key": f"builds/{i}.zip"}, read_only=False)
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
    for off, (src, name) in enumerate([("iam.amazonaws.com", "ListUsers"), ("iam.amazonaws.com", "ListRoles"),
                                       ("s3.amazonaws.com", "ListBuckets"), ("ec2.amazonaws.com", "DescribeInstances")], 1):
        logs.add(t + timedelta(seconds=10 * off), src, name, ci_user, **kw)
    logs.add(t + timedelta(seconds=55), "iam.amazonaws.com", "GetAccountAuthorizationDetails", ci_user,
             error=("AccessDenied", "User: arn:aws:iam::111122223333:user/ci-deploy is not authorized to perform: iam:GetAccountAuthorizationDetails"), **kw)
    backdoor = iam_user("backdoor-svc", BACKDOOR_KEY)
    logs.add(t + timedelta(minutes=2), "iam.amazonaws.com", "CreateUser", ci_user, request={"userName": "backdoor-svc"},
             response={"user": {"path": "/", "userName": "backdoor-svc", "userId": backdoor["principalId"],
                                "arn": f"arn:aws:iam::{ACCOUNT}:user/backdoor-svc", "createDate": "Oct 20, 2026 2:32:00 PM"}}, **kw)
    logs.add(t + timedelta(minutes=2, seconds=10), "iam.amazonaws.com", "AttachUserPolicy", ci_user,
             request={"userName": "backdoor-svc", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}, **kw)
    logs.add(t + timedelta(minutes=2, seconds=20), "iam.amazonaws.com", "CreateAccessKey", ci_user, request={"userName": "backdoor-svc"},
             response={"accessKey": {"userName": "backdoor-svc", "accessKeyId": BACKDOOR_KEY, "status": "Active",
                                     "createDate": "Oct 20, 2026 2:32:20 PM", "secretAccessKey": HIDDEN}}, **kw)
    # activity by the new key, from a second attacker address
    logs.add(t + timedelta(minutes=9), "s3.amazonaws.com", "ListBuckets", backdoor, ip=ATTACKER_IP_2, ua=ATTACKER_UA)
    logs.add(t + timedelta(minutes=10), "iam.amazonaws.com", "ListUsers", backdoor, ip=ATTACKER_IP_2, ua=ATTACKER_UA)
    return logs


def _credentials(key: str, role: str | None = None, session: str | None = None, account: str = ACCOUNT) -> dict[str, Any]:
    """An STS response as CloudTrail logs it: the key id is kept, the session token is not."""
    body: dict[str, Any] = {"credentials": {"accessKeyId": key, "sessionToken": HIDDEN, "expiration": "Oct 20, 2026 11:00:00 PM"}}
    if role and session:
        body["assumedRoleUser"] = {"assumedRoleId": f"{role_id(role)}:{session}", "arn": f"arn:aws:sts::{account}:assumed-role/{role}/{session}"}
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
    logs.add(t + timedelta(minutes=1), "sts.amazonaws.com", "AssumeRole", jenkins,
             request={"roleArn": f"arn:aws:iam::{ACCOUNT}:role/ops-admin", "roleSessionName": "maint"},
             response=_credentials(OPS_SESSION_KEY, "ops-admin", "maint"), **kw)
    ops = assumed_role("ops-admin", "maint", OPS_SESSION_KEY)
    logs.add(t + timedelta(minutes=2), "s3.amazonaws.com", "ListBuckets", ops, **kw)
    logs.add(t + timedelta(minutes=3), "iam.amazonaws.com", "CreateRole", ops,
             request={"roleName": "support-audit", "assumeRolePolicyDocument": '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999900001111:root"},"Action":"sts:AssumeRole"}]}'},
             response={"role": {"roleName": "support-audit", "roleId": role_id("support-audit"),
                                "arn": f"arn:aws:iam::{ACCOUNT}:role/support-audit", "path": "/"}}, **kw)
    logs.add(t + timedelta(minutes=3, seconds=10), "iam.amazonaws.com", "AttachRolePolicy", ops,
             request={"roleName": "support-audit", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}, **kw)
    logs.add(t + timedelta(minutes=4), "sts.amazonaws.com", "AssumeRole", ops,
             request={"roleArn": "arn:aws:iam::444455556666:role/prod-deploy", "roleSessionName": "maint"},
             response=_credentials(PROD_SESSION_KEY, "prod-deploy", "maint", account="444455556666"), **kw)
    logs.add(t + timedelta(minutes=5), "sts.amazonaws.com", "GetSessionToken", jenkins, request={"durationSeconds": 43200},
             response=_credentials(TOKEN_KEY), **kw)
    # the session token in use, from a second address
    logs.add(t + timedelta(minutes=20), "ec2.amazonaws.com", "DescribeInstances", iam_user("jenkins", TOKEN_KEY), ip=ATTACKER_IP_2, ua=ATTACKER_UA)
    # an administrator's own session of the same role, at the same time: not the attacker's
    logs.add(t + timedelta(minutes=6), "s3.amazonaws.com", "ListBuckets", assumed_role("ops-admin", "alice", "ASIAIOSFODNN7ALICE1"), ip=OFFICE_IP)
    # the outside account assumes the attacker's role later; its call carries no tainted key, its sessions do act as the role
    t2 = at("2026-10-20T13:00:00Z")
    logs.add(t2, "sts.amazonaws.com", "AssumeRole", other_account("999900001111"),
             request={"roleArn": f"arn:aws:iam::{ACCOUNT}:role/support-audit", "roleSessionName": "audit"},
             response=_credentials(AUDIT_SESSION_KEY, "support-audit", "audit"), ip="198.51.100.200", ua=ATTACKER_UA)
    audit = assumed_role("support-audit", "audit", AUDIT_SESSION_KEY)
    logs.add(t2 + timedelta(minutes=1), "s3.amazonaws.com", "ListBuckets", audit, ip="198.51.100.200", ua=ATTACKER_UA)
    logs.add(t2 + timedelta(minutes=2), "secretsmanager.amazonaws.com", "ListSecrets", audit, ip="198.51.100.200", ua=ATTACKER_UA)
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
    logs.add(t + timedelta(minutes=1), "ec2.amazonaws.com", "RunInstances", dev,
             request={"instanceType": "t3.micro", "iamInstanceProfile": {"name": "app-profile"}, "imageId": "ami-0abcdef1234567890"},
             response={"instancesSet": {"items": [{"instanceId": ATTACKER_INSTANCE, "instanceType": "t3.micro"}]}}, **kw)
    logs.add(t + timedelta(minutes=2), "iam.amazonaws.com", "CreateUser", dev, request={"userName": "svc-metrics"},
             response={"user": {"userName": "svc-metrics", "userId": iam_user("svc-metrics", "")["principalId"],
                                "arn": f"arn:aws:iam::{ACCOUNT}:user/svc-metrics", "path": "/"}}, **kw)
    logs.add(t + timedelta(minutes=2, seconds=30), "iam.amazonaws.com", "CreateLoginProfile", dev,
             request={"userName": "svc-metrics", "passwordResetRequired": False}, **kw)
    # CI launches its own instance with the same profile, from the office
    ci = assumed_role("deploy-role", "ci-run-4411", "ASIAIOSFODNN7CIROLE")
    logs.add(t + timedelta(minutes=3), "ec2.amazonaws.com", "RunInstances", ci, ip="192.0.2.50",
             request={"instanceType": "m5.large", "iamInstanceProfile": {"name": "app-profile"}},
             response={"instancesSet": {"items": [{"instanceId": CI_INSTANCE, "instanceType": "m5.large"}]}})
    # the instances' role sessions, from their own addresses
    for n, (instance, ip) in enumerate([(ATTACKER_INSTANCE, "192.0.2.99"), (CI_INSTANCE, "192.0.2.51")]):
        session = assumed_role("app-role", instance, f"ASIAIOSFODNN7INST{n:02d}")
        session["invokedBy"] = "ec2.amazonaws.com"
        logs.add(t + timedelta(minutes=10 + n), "s3.amazonaws.com", "ListBuckets", session, ip=ip, ua="aws-sdk-go/1.50.0")
        if instance == ATTACKER_INSTANCE:
            logs.add(t + timedelta(minutes=12), "secretsmanager.amazonaws.com", "ListSecrets", session, ip=ip, ua="aws-sdk-go/1.50.0")
            logs.add(t + timedelta(hours=2), "secretsmanager.amazonaws.com", "GetSecretValue", session, ip=ip, ua="aws-sdk-go/1.50.0",
                     request={"secretId": "prod/db"})  # after the window
    # the new user signs in to the console from elsewhere, after the window
    svc = iam_user("svc-metrics", "")
    del svc["accessKeyId"]
    logs.add(t + timedelta(hours=3), "signin.amazonaws.com", "ConsoleLogin", svc, ip="192.0.2.150",
             ua="Mozilla/5.0 (X11; Linux x86_64)", response={"ConsoleLogin": "Success"}, read_only=False)
    logs.add(t + timedelta(hours=3, minutes=1), "iam.amazonaws.com", "ListUsers", {**svc, "accessKeyId": "ASIAIOSFODNN7CONSOL"},
             ip="192.0.2.150", ua="Mozilla/5.0 (X11; Linux x86_64)")
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
        logs.add(day + timedelta(minutes=5 * n), "monitoring.amazonaws.com", "DescribeAlarms", monitor, ip="192.0.2.60",
                 ua="aws-sdk-java/2.25.0")
    for n in range(4):
        logs.add(day + timedelta(hours=1, minutes=n), "s3.amazonaws.com", "GetObject", iam_user("alice", "AKIAIOSFODNN7ALICE0"),
                 ip=OFFICE_IP, request={"bucketName": "reports", "key": f"q3/{n}.pdf"}, category="Data")
    logs.add(day + timedelta(hours=1, minutes=30), "cloudtrail.amazonaws.com", "UpdateTrail", assumed_role("terraform", "apply", "ASIAIOSFODNN7TFAPPL"),
             ip="192.0.2.50", request={"name": "org-trail", "isMultiRegionTrail": True}, read_only=False)
    ci_user = iam_user("ci-deploy", LEAKED_KEY)
    t = at("2026-10-20T14:30:00Z")
    kw = {"ip": ATTACKER_IP, "ua": ATTACKER_UA}
    logs.add(t, "sts.amazonaws.com", "GetCallerIdentity", ci_user, **kw)
    logs.add(t + timedelta(minutes=1), "cloudtrail.amazonaws.com", "DescribeTrails", ci_user, **kw)
    logs.add(t + timedelta(minutes=1, seconds=30), "guardduty.amazonaws.com", "ListDetectors", ci_user, **kw)
    logs.add(t + timedelta(minutes=1, seconds=40), "guardduty.amazonaws.com", "DeleteDetector", ci_user,
             request={"detectorId": "12abc34d567e8fa901bc2d34e56789f0"},
             error=("AccessDeniedException", "User is not authorized to perform: guardduty:DeleteDetector"), **kw)
    logs.add(t + timedelta(minutes=2), "config.amazonaws.com", "StopConfigurationRecorder", ci_user,
             request={"configurationRecorderName": "default"}, read_only=False, **kw)
    stop = t + timedelta(minutes=3)
    logs.add(stop, "cloudtrail.amazonaws.com", "StopLogging", ci_user,
             request={"name": f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/org-trail"}, read_only=False, **kw)
    restart = at("2026-10-20T16:40:00Z")
    logs.add(restart, "cloudtrail.amazonaws.com", "StartLogging", iam_user("secops", "AKIAIOSFODNN7SECOPS"), ip=OFFICE_IP,
             request={"name": f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/org-trail"}, read_only=False)
    logs.add(restart + timedelta(minutes=20), "s3.amazonaws.com", "ListBuckets", ci_user, **kw)  # the attacker is still around
    # nothing is recorded while the trail is stopped
    off = (stop.strftime("%Y-%m-%dT%H:%M:%SZ"), restart.strftime("%Y-%m-%dT%H:%M:%SZ"))
    logs.records = [r for r in logs.records if not off[0] < r["eventTime"] < off[1]]
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
    logs.add(t - timedelta(days=1), "s3.amazonaws.com", "ListBuckets", alice, ip=nat, ua="aws-cli/2.15.0")  # before the window
    logs.add(t + timedelta(minutes=1), "s3.amazonaws.com", "ListBuckets", alice, ip=nat, ua="aws-cli/2.15.0")  # legitimate, inside
    logs.add(t + timedelta(minutes=2), "iam.amazonaws.com", "ListUsers", mallory, ip=nat, ua="curl/8.4.0")
    logs.add(t + timedelta(minutes=3), "iam.amazonaws.com", "CreateAccessKey", mallory, ip=nat, ua="curl/8.4.0",
             request={"userName": "mallory-temp"}, response={"accessKey": {"accessKeyId": "AKIAIOSFODNN7MALKEY2", "secretAccessKey": HIDDEN}})
    logs.add(t + timedelta(minutes=4), "ec2.amazonaws.com", "DescribeSecurityGroups", mallory, ip=nat, ua="curl/8.4.0",
             error=("UnauthorizedOperation", "You are not authorized to perform this operation."), read_only=True)
    logs.add(t + timedelta(days=1), "s3.amazonaws.com", "ListBuckets", mallory, ip=nat, ua="curl/8.4.0")  # after the window
    return logs
