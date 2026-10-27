from __future__ import annotations

import itertools

from controlzee.ingest.index import Row

_counter = itertools.count(1)


def make_row(**kw: object) -> Row:
    """An index row with sensible defaults; override any field by name."""
    n = next(_counter)
    f: dict[str, object] = {
        "id": f"evt-{n:06d}", "ts": 1_760_000_000_000_000 + n * 1_000_000, "time": "2026-10-09T08:53:20Z", "source": "s3.amazonaws.com",
        "name": "ListBuckets", "region": "us-east-1", "account": "111122223333", "ro": True, "ip": "192.0.2.1", "ua": "aws-cli/2.15.0",
        "err": None, "uitype": "IAMUser", "arn": "arn:aws:iam::111122223333:user/alice", "pid": "AIDAEXAMPLE", "ak": "AKIAALICE",
        "issuer": None, "srcid": None, "issued": None, "file": 0, "rec": n - 1,
    }
    unknown = set(kw) - set(f)
    assert not unknown, unknown
    f.update(kw)
    return (f["id"], f["ts"], f["time"], f["source"], f["name"], f["region"], f["account"], f["ro"], f["ip"], f["ua"], f["err"],  # type: ignore[return-value]
            f["uitype"], f["arn"], f["pid"], f["ak"], f["issuer"], f["srcid"], f["issued"], f["file"], f["rec"])
