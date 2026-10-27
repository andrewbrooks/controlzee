"""Builds CloudTrail records for tests.

Field shapes follow the AWS documentation, not live captures:
- record envelope and `userIdentity`: "CloudTrail record contents" and "CloudTrail userIdentity element"
  (docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html and ...-user-identity.html)
- file layout: "Finding your CloudTrail log files" (AWSLogs/<account>/CloudTrail/<region>/YYYY/MM/DD/...json.gz)
- IAM / STS request and response elements: the API reference for each action as logged; secrets in responses are redacted by
  CloudTrail (shown here as HIDDEN_DUE_TO_SECURITY_REASONS).
Everything is deterministic: ids come from a counter, timestamps from the scenario, gzip headers carry no clock.
"""
from __future__ import annotations

import gzip
import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import orjson

ACCOUNT = "111122223333"
_NS = uuid.UUID("5d0e1c9e-5a43-4f2a-9a55-0a4d0f1b7c11")
_READ_PREFIXES = ("Get", "List", "Describe", "Lookup", "Head")
HIDDEN = "HIDDEN_DUE_TO_SECURITY_REASONS"


def at(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def _id(prefix: str, name: str, n: int = 17) -> str:
    return prefix + hashlib.sha1(name.encode()).hexdigest()[:n].upper()


def role_id(role: str) -> str:
    return _id("AROA", role)


def iam_user(name: str, access_key: str, *, account: str = ACCOUNT) -> dict[str, Any]:
    return {"type": "IAMUser", "principalId": _id("AIDA", name), "arn": f"arn:aws:iam::{account}:user/{name}",
            "accountId": account, "accessKeyId": access_key, "userName": name}


def assumed_role(role: str, session: str, access_key: str, *, account: str = ACCOUNT, mfa: bool = False) -> dict[str, Any]:
    rid = role_id(role)
    return {"type": "AssumedRole", "principalId": f"{rid}:{session}", "arn": f"arn:aws:sts::{account}:assumed-role/{role}/{session}",
            "accountId": account, "accessKeyId": access_key,
            "sessionContext": {
                "sessionIssuer": {"type": "Role", "principalId": rid, "arn": f"arn:aws:iam::{account}:role/{role}",
                                  "accountId": account, "userName": role},
                "attributes": {"creationDate": "2026-10-20T08:00:00Z", "mfaAuthenticated": "true" if mfa else "false"}}}


def other_account(account: str) -> dict[str, Any]:
    """A caller from another account, as the target account logs it (for example when assuming one of its roles)."""
    return {"type": "AWSAccount", "principalId": _id("AIDA", f"ext-{account}"), "accountId": account}


@dataclass
class LogSet:
    account: str = ACCOUNT
    records: list[dict[str, Any]] = field(default_factory=list)

    def add(self, when: datetime, source: str, name: str, identity: dict[str, Any], *, region: str = "us-east-1",
            ip: str = "198.51.100.10", ua: str = "aws-cli/2.15.0 Python/3.11.6 Linux/5.10 exe/x86_64", request: dict[str, Any] | None = None,
            response: dict[str, Any] | None = None, error: tuple[str, str] | None = None, read_only: bool | None = None,
            resources: list[dict[str, Any]] | None = None, category: str = "Management") -> dict[str, Any]:
        n = len(self.records)
        rec: dict[str, Any] = {
            "eventVersion": "1.09", "userIdentity": identity, "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": source, "eventName": name, "awsRegion": region, "sourceIPAddress": ip, "userAgent": ua,
            "requestParameters": request, "responseElements": None if error else response,
            "requestID": str(uuid.uuid5(_NS, f"req-{self.account}-{n}")), "eventID": str(uuid.uuid5(_NS, f"evt-{self.account}-{n}")),
            "readOnly": name.startswith(_READ_PREFIXES) if read_only is None else read_only,
            "eventType": "AwsApiCall", "managementEvent": category == "Management", "recipientAccountId": self.account,
            "eventCategory": category,
        }
        if resources:
            rec["resources"] = resources
        if error:
            rec["errorCode"], rec["errorMessage"] = error
        self.records.append(rec)
        return rec

    def write(self, root: Path, *, per_file: int = 20, gzip_every: int = 0) -> list[Path]:
        """Write the S3 export layout. Records are grouped by region and day, split into files of `per_file`, ordered by time."""
        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for rec in sorted(self.records, key=lambda r: (r["eventTime"], r["eventID"])):
            groups.setdefault((rec["awsRegion"], rec["eventTime"][:10]), []).append(rec)
        written: list[Path] = []
        count = 0
        for (region, day), recs in sorted(groups.items()):
            y, m, d = day.split("-")
            folder = root / "AWSLogs" / self.account / "CloudTrail" / region / y / m / d
            folder.mkdir(parents=True, exist_ok=True)
            for i in range(0, len(recs), per_file):
                chunk = recs[i:i + per_file]
                stamp = chunk[0]["eventTime"].replace("-", "").replace(":", "")[:13] + "Z"
                name = f"{self.account}_CloudTrail_{region}_{stamp}_{hashlib.sha1(chunk[0]['eventID'].encode()).hexdigest()[:8]}.json"
                body = orjson.dumps({"Records": chunk}, option=orjson.OPT_INDENT_2) + b"\n"
                count += 1
                if gzip_every and count % gzip_every == 0:
                    path = folder / (name + ".gz")
                    path.write_bytes(gzip.compress(body, mtime=0))
                else:
                    path = folder / name
                    path.write_bytes(body)
                written.append(path)
        return written


def minutes(base: datetime, n: float) -> datetime:
    return base + timedelta(seconds=round(n * 60))
