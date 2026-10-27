"""Log files from S3, and from CloudTrail event history (the LookupEvents API).

Both only read: S3 is listed and fetched, LookupEvents is queried. Names stay relative, as for local files: an S3 object
is named by its key below the given prefix, so the same logs give the same scope whether they were downloaded first or
read in place. Event history is fetched once, in the parent process, and kept as one in-memory file per region; it is
not re-queried in the second pass, so events that arrive meanwhile cannot make the passes disagree.

Event history keeps 90 days of management events per region, independently of any trail, so it can fill a gap left by
a stopped or deleted trail. It holds no data events.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import orjson

from controlzee.ingest.source import Source
from controlzee.timeutil import parse_time_us

LOG_SUFFIXES = (".json", ".json.gz")
_clients: dict[tuple[str, str | None, str | None], Any] = {}


class RemoteError(Exception):
    """A remote input cannot be listed or queried (no credentials, access denied, no such bucket)."""


def _aws_errors() -> tuple[type[Exception], ...]:
    from botocore.exceptions import BotoCoreError, ClientError
    return (BotoCoreError, ClientError)


def client(service: str, profile: str | None, region: str | None) -> Any:
    """One client per process and settings. Sources are pickled to workers, and each worker makes its own."""
    key = (service, profile, region)
    if key not in _clients:
        import boto3
        _clients[key] = boto3.Session(profile_name=profile, region_name=region).client(service)
    return _clients[key]


@dataclass(frozen=True)
class S3Source:
    rel: str
    bucket: str
    key: str
    size: int
    profile: str | None = None

    def read(self) -> bytes:
        try:
            data: bytes = client("s3", self.profile, None).get_object(Bucket=self.bucket, Key=self.key)["Body"].read()
        except _aws_errors() as e:
            raise OSError(0, f"cannot fetch from S3: {e}") from None
        return data


@dataclass(frozen=True)
class MemorySource:
    rel: str
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)

    def read(self) -> bytes:
        return self.data


def parse_s3_url(url: str) -> tuple[str, str]:
    """(bucket, prefix) of an s3://bucket/prefix URL. The prefix is "" or ends with "/"."""
    if not url.startswith("s3://"):
        raise RemoteError(f"not an S3 URL: {url}")
    bucket, _, prefix = url[5:].partition("/")
    if not bucket:
        raise RemoteError(f"no bucket in {url}")
    return bucket, prefix if not prefix or prefix.endswith("/") else prefix + "/"


@dataclass(frozen=True)
class S3Input:
    """Every log file under an S3 prefix, like a local directory."""

    url: str
    profile: str | None = None

    def list(self) -> tuple[list[Source], int]:
        """(sources, count of other objects ignored)."""
        bucket, prefix = parse_s3_url(self.url)
        found: list[Source] = []
        ignored = 0
        try:
            pages = client("s3", self.profile, None).get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
            for page in pages:
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    rel = key[len(prefix):]
                    if not rel or key.endswith("/"):
                        continue
                    if rel.endswith(LOG_SUFFIXES):
                        found.append(S3Source(rel, bucket, key, int(obj["Size"]), self.profile))
                    else:
                        ignored += 1
        except _aws_errors() as e:
            raise RemoteError(f"cannot list {self.url}: {e}") from None
        return found, ignored


@dataclass(frozen=True)
class LookupInput:
    """CloudTrail event history for one region and time range, as a single log file named lookup-events/<region>.json."""

    region: str
    start: str
    end: str
    profile: str | None = None

    def list(self) -> tuple[list[Source], int]:
        records: list[dict[str, Any]] = []
        try:
            api = client("cloudtrail", self.profile, self.region)
            pages = api.get_paginator("lookup_events").paginate(StartTime=self.start, EndTime=self.end)
            for page in pages:
                for ev in page.get("Events", []):
                    raw = ev.get("CloudTrailEvent")
                    if isinstance(raw, str):
                        try:
                            records.append(orjson.loads(raw))
                        except orjson.JSONDecodeError:
                            records.append({"unparseable": True})  # counted as a malformed record by the index pass
        except _aws_errors() as e:
            raise RemoteError(f"cannot query CloudTrail event history in {self.region}: {e}") from None

        def order(r: Any) -> tuple[int, str]:  # the API's order is not guaranteed; the file's bytes must be
            try:
                return parse_time_us(r["eventTime"]), str(r["eventID"])
            except (KeyError, TypeError, ValueError):
                return -1, orjson.dumps(r, option=orjson.OPT_SORT_KEYS).decode()

        records.sort(key=order)
        data = orjson.dumps({"Records": records}, option=orjson.OPT_SORT_KEYS)
        return [MemorySource(f"lookup-events/{self.region}.json", data)], 0
