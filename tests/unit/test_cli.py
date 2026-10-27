import json
import os
import stat

import pytest
from typer.testing import CliRunner

from controlzee import __version__
from controlzee.cli import app

runner = CliRunner(env={"COLUMNS": "400"})  # keep rich from wrapping messages mid-phrase


def run(*args):
    return runner.invoke(app, [str(a) for a in args])


@pytest.fixture
def s01(fixtures):
    return fixtures / "01_leaked_key"


def test_version_and_help():
    assert __version__ in run("--version").stdout
    r = run("scope", "--help")
    assert r.exit_code == 0 and "--logs" in r.stdout and "--window" in r.stdout


def test_scope_writes_both_files_and_reports(s01, tmp_path):
    out = tmp_path / "scope.json"
    r = run("scope", "--logs", s01 / "logs", "--iocs", s01 / "iocs.yaml", "-o", out, "--workers", 1)
    assert r.exit_code == 0, r.output
    assert "In scope: 11 events (11 strong, 0 weak), 1 of them failed calls" in r.stdout
    assert "Followed 2 credential(s) or principal(s)" in r.stdout and "coverage: no data events" in r.output
    doc = json.loads(out.read_text())
    assert doc["summary"]["events_in_scope"] == 11 and (tmp_path / "scope.inputs.json").exists()
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    assert str(tmp_path) not in out.read_text()  # paths are shown on the terminal, never written into the artifact


def test_output_matches_the_golden_byte_for_byte(s01, tmp_path):
    out = tmp_path / "scope.json"
    assert run("scope", "--logs", s01 / "logs", "--iocs", s01 / "iocs.yaml", "-o", out).exit_code == 0
    assert out.read_bytes() == (s01 / "expected/scope.json").read_bytes()
    assert (tmp_path / "scope.inputs.json").read_bytes() == (s01 / "expected/scope.inputs.json").read_bytes()


def test_flags_without_a_file(s01, tmp_path):
    r = run("scope", "--logs", s01 / "logs", "--access-key", "AKIAIOSFODNN7LEAKED", "--ip", "198.51.100.77",
            "--expr", "access_key_1 AND ip_1", "-o", tmp_path / "s.json")
    assert r.exit_code == 0 and "In scope: 11 events" in r.stdout
    # the key alone matches 11 events; without propagation the backdoor key's two are not added
    r = run("scope", "--logs", s01 / "logs", "--access-key", "AKIAIOSFODNN7LEAKED", "--no-propagate", "-o", tmp_path / "t.json")
    assert r.exit_code == 0 and "In scope: 11 events" in r.stdout and "Followed" not in r.stdout


def test_refuses_to_overwrite_without_force(s01, tmp_path):
    out = tmp_path / "scope.json"
    args = ("scope", "--logs", s01 / "logs", "--iocs", s01 / "iocs.yaml", "-o", out)
    assert run(*args).exit_code == 0
    first = out.read_bytes()
    r = run(*args)
    assert r.exit_code == 2 and "already exists" in r.output and out.read_bytes() == first
    (tmp_path / "scope.inputs.json").unlink()  # only the sidecar missing: the scope file still blocks
    assert run(*args).exit_code == 2
    assert run(*args, "--force").exit_code == 0


@pytest.mark.parametrize("extra,message", [
    (["--expr", "access_key_1 AND nope"], "undefined indicator"),
    (["--expr", "access_key_1 &&"], "unexpected character"),
    (["--ip", "300.1.1.1"], "not an IP address"),
    (["--window", "2026-10-21T00:00:00Z", "2026-10-20T00:00:00Z"], "starts after it ends"),
    (["--window", "yesterday", "today"], "time"),
])
def test_bad_input_is_a_clean_exit_2(s01, tmp_path, extra, message):
    r = run("scope", "--logs", s01 / "logs", "--access-key", "AKIAIOSFODNN7LEAKED", *extra, "-o", tmp_path / "s.json")
    assert r.exit_code == 2 and message in r.output and "Traceback" not in r.output
    assert not (tmp_path / "s.json").exists()


def test_no_indicators_and_weak_only_without_window(s01, tmp_path):
    r = run("scope", "--logs", s01 / "logs", "-o", tmp_path / "s.json")
    assert r.exit_code == 2 and "no indicators given" in r.output
    r = run("scope", "--logs", s01 / "logs", "--ip", "198.51.100.77", "-o", tmp_path / "s.json")
    assert r.exit_code == 2 and "needs a time window" in r.output


def test_missing_logs_and_s3_are_explained(tmp_path):
    r = run("scope", "--logs", tmp_path / "absent", "--access-key", "A", "-o", tmp_path / "s.json")
    assert r.exit_code == 2 and "does not exist" in r.output
    r = run("scope", "--logs", "s3://bucket/prefix", "--access-key", "A", "-o", tmp_path / "s.json")
    assert r.exit_code == 2 and "S3 input is not available" in r.output


def test_strict_turns_unreadable_input_into_exit_3(s01, tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "bad.json").write_bytes(b"{")
    good = next((s01 / "logs").rglob("*.json*"))
    (logs / good.name).write_bytes(good.read_bytes())
    args = ("scope", "--logs", logs, "--access-key", "AKIAIOSFODNN7LEAKED", "-o", tmp_path / "s.json")
    lenient = run(*args)
    assert lenient.exit_code == 0 and "1 file(s) could not be read" in lenient.output
    strict = run(*args, "--force", "--strict")
    assert strict.exit_code == 3 and (tmp_path / "s.json").exists()


def test_terminal_output_cannot_be_hijacked_by_log_content(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "x\x1b[2Jevil[bold red]‮.json").write_bytes(b"{")
    r = run("scope", "--logs", logs, "--access-key", "A", "-o", tmp_path / "s.json")
    assert r.exit_code == 0 and "\x1b" not in r.output and "‮" not in r.output


def test_guardduty_import_prints_what_it_took(s01, tmp_path):
    finding = tmp_path / "f.json"
    finding.write_text(json.dumps({"Id": "f1", "Resource": {"AccessKeyDetails": {"AccessKeyId": "AKIAIOSFODNN7LEAKED"}}, "Service": {}}))
    r = run("scope", "--logs", s01 / "logs", "--guardduty", finding, "-o", tmp_path / "s.json")
    assert r.exit_code == 0 and "imported access key AKIAIOSFODNN7LEAKED" in r.stdout and "In scope: 13 events" in r.stdout
