"""Compact descriptions of incidents, turned into CloudTrail logs by `cloudtrail.LogSet`."""
from __future__ import annotations

from datetime import timedelta

from tests.builders.cloudtrail import (
    ACCOUNT,
    HIDDEN,
    LogSet,
    assumed_role,
    at,
    iam_user,
)

OFFICE_IP = "203.0.113.10"
ATTACKER_IP = "198.51.100.77"
ATTACKER_IP_2 = "198.51.100.78"
ATTACKER_UA = "python-requests/2.31.0"
LEAKED_KEY = "AKIAIOSFODNN7LEAKED"
BACKDOOR_KEY = "AKIAIOSFODNN7BKDOOR"


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
    logs.add(t + timedelta(minutes=2), "iam.amazonaws.com", "CreateUser", ci_user, request={"userName": "backdoor-svc"},
             response={"user": {"path": "/", "userName": "backdoor-svc", "userId": "AIDAIOSFODNN7BKDOOR",
                                "arn": f"arn:aws:iam::{ACCOUNT}:user/backdoor-svc", "createDate": "Oct 20, 2026 2:32:00 PM"}}, **kw)
    logs.add(t + timedelta(minutes=2, seconds=10), "iam.amazonaws.com", "AttachUserPolicy", ci_user,
             request={"userName": "backdoor-svc", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}, **kw)
    logs.add(t + timedelta(minutes=2, seconds=20), "iam.amazonaws.com", "CreateAccessKey", ci_user, request={"userName": "backdoor-svc"},
             response={"accessKey": {"userName": "backdoor-svc", "accessKeyId": BACKDOOR_KEY, "status": "Active",
                                     "createDate": "Oct 20, 2026 2:32:20 PM", "secretAccessKey": HIDDEN}}, **kw)
    # activity by the new key, from a second attacker address
    backdoor = iam_user("backdoor-svc", BACKDOOR_KEY)
    logs.add(t + timedelta(minutes=9), "s3.amazonaws.com", "ListBuckets", backdoor, ip=ATTACKER_IP_2, ua=ATTACKER_UA)
    logs.add(t + timedelta(minutes=10), "iam.amazonaws.com", "ListUsers", backdoor, ip=ATTACKER_IP_2, ua=ATTACKER_UA)
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
