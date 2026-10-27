"""Same inputs, same bytes: whatever the hash seed, worker count, file arrival order, file splitting or compression."""
import gzip
import json
import os
import random
import shutil
import subprocess
import sys

import orjson
import pytest

from controlzee.scope import ScopeOptions, build_scope
from controlzee.seed.spec import assemble, load_iocs_file

pytestmark = pytest.mark.slow


def spec_for(root, iocs="iocs.yaml"):
    return assemble([load_iocs_file(root / iocs)])


def scope_bytes(logs, spec, workers=1):
    return build_scope([logs], spec, ScopeOptions(workers=workers)).scope_bytes


@pytest.mark.parametrize("scenario", ["01_leaked_key", "05_weak_ioc"])
def test_hash_seed_does_not_change_the_output(fixtures, tmp_path, scenario):
    root = fixtures / scenario
    outputs = set()
    for seed in ("0", "1", "12345", "random"):
        out = tmp_path / f"scope-{seed}.json"
        env = {**os.environ, "PYTHONHASHSEED": seed}
        r = subprocess.run([sys.executable, "-m", "controlzee", "scope", "--logs", str(root / "logs"), "--iocs", str(root / "iocs.yaml"),
                            "-o", str(out), "--workers", "1"], env=env, capture_output=True, text=True, check=False)
        assert r.returncode == 0, r.stderr
        outputs.add((out.read_bytes(), out.with_name(out.stem + ".inputs.json").read_bytes()))
    assert len(outputs) == 1
    assert next(iter(outputs))[0] == (root / "expected/scope.json").read_bytes()


@pytest.mark.parametrize("scenario", ["01_leaked_key", "05_weak_ioc"])
def test_worker_count_does_not_change_the_output(fixtures, scenario, monkeypatch):
    root = fixtures / scenario
    # force the process pool even though the fixtures are tiny
    monkeypatch.setattr("controlzee.ingest.load.PARALLEL_MIN_BYTES", 0)
    monkeypatch.setattr("controlzee.ingest.materialize.PARALLEL_MIN_BYTES", 0)
    spec = spec_for(root)
    results = {w: scope_bytes(root / "logs", spec, w) for w in (1, 2, 4)}
    assert len(set(results.values())) == 1
    assert results[1] == (root / "expected/scope.json").read_bytes()


def _records(logs):
    out = []
    for p in sorted(logs.rglob("*.json*")):
        data = p.read_bytes()
        out += orjson.loads(gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data)["Records"]
    return out


def _rewrite(records, dest, *, per_file, gz, seed):
    """The same records, differently split, ordered, named and compressed."""
    rnd = random.Random(seed)
    recs = list(records)
    rnd.shuffle(recs)
    dest.mkdir(parents=True)
    for n, start in enumerate(range(0, len(recs), per_file)):
        body = orjson.dumps({"Records": recs[start:start + per_file]})
        name = f"part-{rnd.randrange(10**6):06d}-{n}.json"
        if gz(n):
            (dest / (name + ".gz")).write_bytes(gzip.compress(body, mtime=rnd.randrange(10**9)))
        else:
            (dest / name).write_bytes(body)


@pytest.mark.parametrize("scenario", ["01_leaked_key", "05_weak_ioc"])
def test_the_events_do_not_depend_on_how_the_files_are_arranged(fixtures, tmp_path, scenario):
    root = fixtures / scenario
    spec = spec_for(root)
    records = _records(root / "logs")
    baseline = json.loads(scope_bytes(root / "logs", spec))
    base_events = baseline["events"]
    layouts = [{"per_file": 1, "gz": lambda n: False}, {"per_file": 7, "gz": lambda n: n % 2 == 0}, {"per_file": 1000, "gz": lambda n: True}]
    for i, layout in enumerate(layouts):
        dest = tmp_path / f"layout{i}"
        _rewrite(records, dest, seed=i, **layout)
        doc = json.loads(scope_bytes(dest, spec))
        # file names and record positions legitimately differ; everything else about each event must not
        strip = lambda evs: [{**e, "event": {k: v for k, v in e["event"].items() if k != "source"}} for e in evs]  # noqa: E731
        assert strip(doc["events"]) == strip(base_events)
        assert doc["near_misses"] == baseline["near_misses"] and doc["near_miss_summary"] == baseline["near_miss_summary"]
        assert doc["summary"] == baseline["summary"] and doc["seeds"] == baseline["seeds"]


def test_same_layout_in_a_different_directory_order_is_byte_identical(fixtures, tmp_path):
    root = fixtures / "01_leaked_key"
    spec = spec_for(root)
    a, b = tmp_path / "a", tmp_path / "b"
    shutil.copytree(root / "logs", a)
    shutil.copytree(root / "logs", b)
    # same files, but created in the opposite order, so directory listing order differs
    for p in sorted(b.rglob("*.json*"), reverse=True):
        data = p.read_bytes()
        p.unlink()
        p.write_bytes(data)
    assert scope_bytes(a, spec) == scope_bytes(b, spec) == (root / "expected/scope.json").read_bytes()


def test_duplicate_delivery_by_a_second_trail_changes_only_the_duplicate_count(fixtures, tmp_path):
    root = fixtures / "01_leaked_key"
    spec = spec_for(root)
    a = tmp_path / "second-trail"
    shutil.copytree(root / "logs", a)
    shutil.copytree(root / "logs", tmp_path / "extra")  # the same events delivered again
    shutil.move(tmp_path / "extra", a / "AWSLogs-copy")
    doc = json.loads(scope_bytes(a, spec))
    base = json.loads((root / "expected/scope.json").read_bytes())
    assert doc["inputs"]["duplicates_removed"] == base["inputs"]["event_count"]
    assert [e["event"]["event_id"] for e in doc["events"]] == [e["event"]["event_id"] for e in base["events"]]
    assert doc["summary"] == base["summary"]
