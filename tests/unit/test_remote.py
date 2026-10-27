"""S3 and CloudTrail event history, without the network: botocore's Stubber checks each call against the API model."""
import io

import boto3
import orjson
import pytest
from botocore.response import StreamingBody
from botocore.stub import Stubber

from controlzee.ingest import remote
from controlzee.ingest.load import IngestError, IngestOptions, discover, load_index
from controlzee.ingest.remote import LookupInput, S3Input, parse_s3_url
from controlzee.scope import ScopeOptions, build_scope
from controlzee.seed.spec import assemble, load_iocs_file


def _client(service, region="us-east-1"):
    return boto3.client(service, region_name=region, aws_access_key_id="testing", aws_secret_access_key="testing")


@pytest.fixture
def s3(monkeypatch):
    c = _client("s3")
    monkeypatch.setitem(remote._clients, ("s3", None, None), c)
    with Stubber(c) as stub:
        yield stub
        stub.assert_no_pending_responses()


def _ct_record(n, minute):
    return {"eventID": f"e{n}", "eventTime": f"2026-10-20T12:{minute:02d}:00Z", "eventSource": "iam.amazonaws.com",
            "eventName": "ListUsers", "awsRegion": "us-east-1", "recipientAccountId": "111122223333",
            "userIdentity": {"type": "IAMUser", "accessKeyId": "AKIA1", "principalId": "AIDA1"}}


@pytest.mark.parametrize("url,expected", [
    ("s3://b", ("b", "")), ("s3://b/", ("b", "")), ("s3://b/AWSLogs", ("b", "AWSLogs/")), ("s3://b/a/b/", ("b", "a/b/"))])
def test_parse_s3_url(url, expected):
    assert parse_s3_url(url) == expected


def test_s3_listing_names_files_below_the_prefix_and_skips_like_a_directory(s3):
    s3.add_response("list_objects_v2", {"Contents": [
        {"Key": "case/AWSLogs/1/CloudTrail/us-east-1/2026/10/20/b.json.gz", "Size": 10},
        {"Key": "case/AWSLogs/1/CloudTrail/us-east-1/2026/10/20/a.json", "Size": 20},
        {"Key": "case/AWSLogs/1/CloudTrail-Digest/us-east-1/2026/10/20/1_CloudTrail-Digest_x.json.gz", "Size": 5},
        {"Key": "case/notes.txt", "Size": 1}, {"Key": "case/folder/", "Size": 0}]}, {"Bucket": "evidence", "Prefix": "case/"})
    sources, skipped, ignored = discover([S3Input("s3://evidence/case")])
    assert [s.rel for s in sources] == ["AWSLogs/1/CloudTrail/us-east-1/2026/10/20/a.json", "AWSLogs/1/CloudTrail/us-east-1/2026/10/20/b.json.gz"]
    assert [e.status for e in skipped] == ["skipped"] and ignored == 1


def test_s3_errors_are_explained_not_raised(s3):
    s3.add_client_error("list_objects_v2", service_error_code="AccessDenied", http_status_code=403)
    with pytest.raises(IngestError, match="cannot list s3://evidence/case"):
        discover([S3Input("s3://evidence/case")])


class FakeS3:
    """Serves a local directory as if it were a bucket under `prefix`, for the end-to-end comparison."""

    def __init__(self, root, prefix):
        self.files = {prefix + p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return self

    def paginate(self, Bucket, Prefix):  # noqa: N803 (boto3's spelling)
        keys = sorted(self.files, reverse=True)  # S3 returns keys sorted; reversed here to show order does not matter
        yield {"Contents": [{"Key": k, "Size": len(self.files[k])} for k in keys[:3]]}
        yield {"Contents": [{"Key": k, "Size": len(self.files[k])} for k in keys[3:]]}

    def get_object(self, Bucket, Key):  # noqa: N803
        data = self.files[Key]
        return {"Body": StreamingBody(io.BytesIO(data), len(data))}


def test_the_same_logs_in_s3_give_byte_identical_output(fixtures, monkeypatch):
    root = fixtures / "01_leaked_key"
    monkeypatch.setitem(remote._clients, ("s3", None, None), FakeS3(root / "logs", "incident-42/"))
    out = build_scope([S3Input("s3://evidence/incident-42/")], assemble([load_iocs_file(root / "iocs.yaml")]), ScopeOptions(workers=1))
    assert out.scope_bytes == (root / "expected/scope.json").read_bytes()
    assert out.inputs_bytes == (root / "expected/scope.inputs.json").read_bytes()


def test_an_object_that_cannot_be_fetched_is_an_error_file(s3):
    s3.add_response("list_objects_v2", {"Contents": [{"Key": "x.json", "Size": 3}]}, {"Bucket": "b", "Prefix": ""})
    s3.add_client_error("get_object", service_error_code="NoSuchKey", http_status_code=404)
    idx = load_index([S3Input("s3://b")], IngestOptions(workers=1))
    assert [(f.status, (f.note or "")[:21]) for f in idx.files] == [("error", "cannot read: cannot f")]


@pytest.fixture
def cloudtrail(monkeypatch):
    c = _client("cloudtrail")
    monkeypatch.setitem(remote._clients, ("cloudtrail", None, "us-east-1"), c)
    with Stubber(c) as stub:
        yield stub
        stub.assert_no_pending_responses()


def test_event_history_becomes_one_sorted_file_per_region(cloudtrail):
    params = {"StartTime": "2026-10-20T00:00:00Z", "EndTime": "2026-10-21T00:00:00Z"}
    later, earlier = _ct_record(2, 30), _ct_record(1, 10)
    cloudtrail.add_response("lookup_events", {"Events": [{"EventId": "e2", "CloudTrailEvent": orjson.dumps(later).decode()}],
                                              "NextToken": "t"}, params)
    cloudtrail.add_response("lookup_events", {"Events": [{"EventId": "e1", "CloudTrailEvent": orjson.dumps(earlier).decode()},
                                                         {"EventId": "bad", "CloudTrailEvent": "{not json"}]},
                            {**params, "NextToken": "t"})
    idx = load_index([LookupInput("us-east-1", *params.values())], IngestOptions(workers=1))
    assert [f.path for f in idx.files] == ["lookup-events/us-east-1.json"]
    assert [r[0] for r in idx.rows] == ["e1", "e2"] and idx.malformed_records == 1
    # the file's bytes, and so its hash in the manifest, do not depend on the order the API returned the events in
    records = orjson.loads(idx.sources[0].read())["Records"]
    assert records[0] == {"unparseable": True} and [r["eventID"] for r in records[1:]] == ["e1", "e2"]


def test_event_history_errors_are_explained(cloudtrail):
    cloudtrail.add_client_error("lookup_events", service_error_code="UnrecognizedClientException", http_status_code=400)
    with pytest.raises(IngestError, match="cannot query CloudTrail event history in us-east-1"):
        discover([LookupInput("us-east-1", "2026-10-20T00:00:00Z", "2026-10-21T00:00:00Z")])
