import gzip
import zlib

import orjson
import pytest

from controlzee.ingest.index import R_ID, R_TS
from controlzee.ingest.load import IngestError, IngestOptions, discover, load_index
from controlzee.ingest.materialize import materialize
from controlzee.ingest.parse import gunzip_capped, load_records, row_of
from controlzee.timeutil import parse_time_us

LIMIT = 1 << 20


def rec(n, **kw):
    r = {"eventID": f"e{n}", "eventTime": f"2026-10-20T12:00:{n:02d}Z", "eventSource": "s3.amazonaws.com", "eventName": "ListBuckets",
         "awsRegion": "us-east-1", "recipientAccountId": "111122223333", "sourceIPAddress": "192.0.2.1", "userAgent": "ua",
         "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/a", "principalId": "AIDA1", "accessKeyId": "AKIA1"}}
    r.update(kw)
    return r


def put(path, records, *, gz=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    data = orjson.dumps({"Records": records})
    path.write_bytes(gzip.compress(data, mtime=0) if gz else data)
    return path


# ---- gzip safety

def test_gunzip_handles_multiple_members_and_zero_padding():
    a, b = gzip.compress(b'{"Records": [', mtime=0), gzip.compress(b"]}", mtime=0)
    assert gunzip_capped(a + b + b"\x00" * 7, LIMIT) == b'{"Records": []}'


def test_gunzip_rejects_truncation_and_bombs():
    whole = gzip.compress(b"x" * 1000, mtime=0)
    with pytest.raises(ValueError, match="truncated"):
        gunzip_capped(whole[:-10], LIMIT)
    with pytest.raises(ValueError, match="exceeds"):
        gunzip_capped(gzip.compress(b"\0" * 100_000, mtime=0), 1000)
    with pytest.raises(ValueError, match="exceeds"):  # a second member must not slip past the cap
        gunzip_capped(gzip.compress(b"a" * 600, mtime=0) * 2, 1000)
    with pytest.raises(zlib.error):
        gunzip_capped(b"\x1f\x8bgarbage", LIMIT)


@pytest.mark.parametrize("data,message", [
    (b"not json", "not valid JSON"), (b"[]", "no Records"), (b'{"Records": {}}', "no Records"), (b'{"x": 1}', "no Records")])
def test_load_records_rejects_other_files(data, message):
    with pytest.raises(ValueError, match=message):
        load_records(data, LIMIT)


def test_load_records_plain_gzip_and_size_cap():
    body = orjson.dumps({"Records": [rec(1)]})
    assert load_records(body, LIMIT) == load_records(gzip.compress(body), LIMIT)
    with pytest.raises(ValueError, match="exceeds"):
        load_records(body, 10)


# ---- rows

def test_row_fields_and_fallbacks():
    table: dict[str, str] = {}
    row = row_of(rec(1), 3, 4, table)
    assert row is not None
    assert row[R_ID] == "e1" and row[R_TS] == parse_time_us("2026-10-20T12:00:01Z")
    assert row[-2:] == (3, 4)
    # account falls back to the identity's, then to ""
    r = rec(2)
    del r["recipientAccountId"]
    r["userIdentity"]["accountId"] = "999988887777"
    assert row_of(r, 0, 0, table)[6] == "999988887777"  # type: ignore[index]
    del r["userIdentity"]
    assert row_of(r, 0, 0, table)[6] == ""  # type: ignore[index]


def test_row_interns_repeated_strings():
    table: dict[str, str] = {}
    a, b = row_of(rec(1), 0, 0, table), row_of(rec(2), 0, 1, table)
    assert a and b and a[12] is b[12] and a[9] is b[9]


@pytest.mark.parametrize("bad", [
    "not a dict", None, 5, {}, {**rec(1), "eventID": 7}, {**rec(1), "eventTime": "yesterday"}, {**rec(1), "eventTime": None},
    {**rec(1), "eventName": None}, {k: v for k, v in rec(1).items() if k != "eventSource"}])
def test_rows_need_the_mandatory_fields(bad):
    assert row_of(bad, 0, 0, {}) is None


def test_odd_optional_fields_become_none_not_errors():
    r = rec(1, readOnly="yes", errorCode=5, userIdentity="garbage", sourceIPAddress=["x"])
    row = row_of(r, 0, 0, {})
    assert row is not None and row[7] is None and row[10] is None and row[8] is None and row[12] is None


# ---- discovery and loading

def test_discover_skips_digest_and_insight_files_and_counts_ignored(tmp_path):
    put(tmp_path / "AWSLogs/1/CloudTrail/us-east-1/2026/10/20/a.json.gz", [rec(1)], gz=True)
    put(tmp_path / "AWSLogs/1/CloudTrail-Digest/us-east-1/2026/10/20/1_CloudTrail-Digest_x.json.gz", [], gz=True)
    put(tmp_path / "AWSLogs/1/CloudTrail-Insight/us-east-1/2026/10/20/i.json.gz", [], gz=True)
    (tmp_path / "README.txt").write_text("hi")
    sources, skipped, ignored = discover([tmp_path])
    assert [s.rel for s in sources] == ["AWSLogs/1/CloudTrail/us-east-1/2026/10/20/a.json.gz"]
    assert sorted(e.status for e in skipped) == ["skipped", "skipped"] and ignored == 1


def test_discover_missing_input_and_collisions(tmp_path):
    with pytest.raises(IngestError, match="does not exist"):
        discover([tmp_path / "nope"])
    a, b = tmp_path / "a", tmp_path / "b"
    put(a / "x.json", [rec(1)])
    put(b / "x.json", [rec(2)])
    assert [s.rel for s in discover([a, b])[0]] == ["0:x.json", "1:x.json"]
    # a single file input is named by its basename
    assert [s.rel for s in discover([a / "x.json"])[0]] == ["x.json"]


def test_nothing_to_read_is_an_error(tmp_path):
    (tmp_path / "x.txt").write_text("no")
    with pytest.raises(IngestError, match="no CloudTrail log files"):
        load_index([tmp_path])


def test_load_dedupes_sorts_and_reports_problems(tmp_path):
    put(tmp_path / "b.json", [rec(5), rec(2), {"junk": True}])
    put(tmp_path / "a.json.gz", [rec(3), rec(2)], gz=True)  # e2 is a duplicate (a.json.gz sorts first, so it wins)
    (tmp_path / "broken.json").write_bytes(b"{truncated")
    idx = load_index([tmp_path], IngestOptions(workers=1))
    assert [r[R_ID] for r in idx.rows] == ["e2", "e3", "e5"]
    assert idx.duplicates_removed == 1 and idx.malformed_records == 1 and idx.malformed_samples == ["b.json#2"]
    by_path = {f.path: f for f in idx.files}
    assert by_path["broken.json"].status == "error" and "not valid JSON" in (by_path["broken.json"].note or "")
    assert by_path["a.json.gz"].records == 2 and by_path["a.json.gz"].status == "ingested"
    # the surviving e2 is the one from a.json.gz
    assert idx.files[idx.rows[0][-2]].path == "a.json.gz"


def test_equal_timestamps_order_by_event_id(tmp_path):
    put(tmp_path / "x.json", [rec(1, eventID="zz"), rec(1, eventID="aa"), rec(1, eventID="mm")])
    assert [r[R_ID] for r in load_index([tmp_path], IngestOptions(workers=1)).rows] == ["aa", "mm", "zz"]


# ---- second pass

def test_materialize_builds_events_for_requested_rows_only(tmp_path):
    put(tmp_path / "x.json", [rec(n) for n in range(1, 8)])
    put(tmp_path / "y.json.gz", [rec(n) for n in range(10, 14)], gz=True)
    idx = load_index([tmp_path], IngestOptions(workers=1))
    evs = materialize(idx, [0, 9, 3], max_bytes=LIMIT, workers=1)
    assert sorted(evs) == [0, 3, 9]
    assert [evs[p].event_id for p in (0, 3, 9)] == [idx.rows[p][R_ID] for p in (0, 3, 9)]
    assert evs[0].source.input == "x.json" and evs[9].source.input == "y.json.gz"
    assert evs[0].raw is None


def test_materialize_detects_files_changed_underneath(tmp_path):
    p = put(tmp_path / "x.json", [rec(1), rec(2)])
    idx = load_index([tmp_path], IngestOptions(workers=1))
    put(p, [rec(2), rec(1)])  # same events, different order
    with pytest.raises(IngestError, match="changed while scoping"):
        materialize(idx, [0], max_bytes=LIMIT, workers=1)
    put(p, [rec(1)])
    with pytest.raises(IngestError, match="changed while scoping"):
        materialize(idx, [1], max_bytes=LIMIT, workers=1)
