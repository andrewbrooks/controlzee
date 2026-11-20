"""The step journal: what `respond execute` writes before it changes anything, and what that guards against."""

import hashlib
import json
import os
import stat

import pytest
from hypothesis import given
from hypothesis import strategies as st

from controlzee import canonical
from controlzee.model.respond import ExecutedStep, JournalLine
from controlzee.respond.journal import Journal, JournalExists, journal_path
from controlzee.respond.run import RespondError
from tests import fake_aws
from tests.unit import test_respond as tr
from tests.unit.test_respond import (
    _journal_dir,  # noqa: F401  (autouse: a fresh journal folder for every test)
    account_01,
    check,
    cli,
    run,
    scope_of,
)


class Killed(BaseException):
    """What a SIGKILL looks like from inside the process: nothing after it runs, and nothing catches it."""


def dry_run_doc(fixtures, monkeypatch, acct):
    return check(scope_of(fixtures, "01_leaked_key"), acct, monkeypatch).model_dump(mode="json")


def read_journal(doc):
    path = journal_path(tr.JOURNAL_DIR, doc["dryrun_sha256"])
    return path, [json.loads(line) for line in path.read_text().splitlines()]


def shape(lines):
    return [(x["kind"], x.get("action_id")) for x in lines]


# ---- the spec's tests


def test_a_run_killed_during_a_change_leaves_starting_and_no_result(fixtures, monkeypatch):
    acct = account_01()
    doc = dry_run_doc(fixtures, monkeypatch, acct)

    def kill(self, op, **kw):  # the third step: the process dies inside apply
        raise Killed

    monkeypatch.setattr(fake_aws.FakeClient, "_iam_detach_user_policy", kill)
    with pytest.raises(Killed):
        run(doc)
    _, lines = read_journal(doc)
    assert shape(lines) == [
        ("header", None),
        ("starting", "A01"),
        ("result", "A01"),
        ("starting", "A02"),
        ("result", "A02"),
        ("starting", "A04"),
    ]
    assert lines[0]["dryrun_sha256"] == doc["dryrun_sha256"] and lines[-1]["op"] == "detach_user_policy"


def test_the_same_dry_run_cannot_be_executed_twice_from_one_folder(fixtures, monkeypatch):
    acct = account_01()
    doc = dry_run_doc(fixtures, monkeypatch, acct)
    assert run(doc).completed
    acct.all_calls.clear()
    with pytest.raises(
        RespondError, match=r"already executed \(see .*response\.[0-9a-f]{16}\.journal\.jsonl\)"
    ):
        run(doc)
    assert acct.all_calls == []  # refused before any call to AWS, reads included


def test_the_journal_and_the_response_agree_and_the_response_cites_the_journal(fixtures, monkeypatch):
    acct = account_01()
    doc = dry_run_doc(fixtures, monkeypatch, acct)
    rec = run(doc)
    path, lines = read_journal(doc)
    results = [x for x in lines if x["kind"] == "result"]
    assert [
        ExecutedStep.model_validate({k: v for k, v in x.items() if k != "kind"}) for x in results
    ] == rec.steps
    assert rec.journal_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert canonical.is_sealed(rec.model_dump(mode="json"), "response_sha256")
    assert [JournalLine.model_validate(x) for x in lines]  # every line has the documented shape
    assert (
        lines[0]["caller"]["principal_arn"] == rec.caller.principal_arn
        and lines[0]["started_at"] == rec.started_at
    )


# ---- the write-ahead property and the other ways a step can end


def test_the_starting_line_is_on_disk_before_the_change_is_made(fixtures, monkeypatch):
    acct = account_01()
    doc = dry_run_doc(fixtures, monkeypatch, acct)
    seen = []
    real = fake_aws.FakeClient._iam_update_access_key

    def spy(self, op, **kw):
        _, lines = read_journal(doc)
        seen.append((lines[-1]["kind"], lines[-1]["action_id"]))
        return real(self, op, **kw)

    monkeypatch.setattr(fake_aws.FakeClient, "_iam_update_access_key", spy)
    run(doc)
    assert seen == [("starting", "A01"), ("starting", "A02")]


def test_an_error_in_a_change_is_a_result_line_and_later_steps_are_not_run(fixtures, monkeypatch):
    doc = dry_run_doc(fixtures, monkeypatch, account_01())

    def boom(self, op, **kw):
        raise RuntimeError("boom")

    monkeypatch.setattr(fake_aws.FakeClient, "_iam_update_access_key", boom)
    rec = run(doc)
    _, lines = read_journal(doc)
    assert shape(lines) == [
        ("header", None),
        ("starting", "A01"),
        ("result", "A01"),
        ("result", "A02"),
        ("result", "A04"),
    ]
    assert [x["result"] for x in lines[2:]] == ["failed", "not run", "not run"] and not rec.completed
    assert "may be partly made" in lines[2]["detail"]


def test_a_step_that_changes_nothing_has_only_a_result_line(fixtures, monkeypatch):
    acct = account_01()
    acct.users["backdoor-svc"].keys["AKIAIOSFODNN7BKDOOR"] = "Inactive"
    doc = dry_run_doc(fixtures, monkeypatch, acct)
    rec = run(doc)
    _, lines = read_journal(doc)
    assert rec.steps[0].result == "already done" and shape(lines)[:3] == [
        ("header", None),
        ("result", "A01"),
        ("starting", "A02"),
    ]


def test_a_journal_that_cannot_be_written_before_a_change_stops_the_run_unchanged(fixtures, monkeypatch):
    acct = account_01()
    doc = dry_run_doc(fixtures, monkeypatch, acct)
    real = Journal.append

    def flaky(self, entry):
        if entry.kind == "starting":
            raise OSError(28, "No space left on device")
        real(self, entry)

    monkeypatch.setattr(Journal, "append", flaky)
    rec = run(doc)
    assert [s.result for s in rec.steps] == ["failed", "not run", "not run"] and not rec.completed
    assert (
        "cannot write the step journal (No space left on device); nothing was changed" in rec.steps[0].detail
    )
    assert acct.calls == []


def test_a_result_line_that_cannot_be_written_keeps_the_result_and_stops_the_run(fixtures, monkeypatch):
    acct = account_01()
    doc = dry_run_doc(fixtures, monkeypatch, acct)
    real = Journal.append

    def flaky(self, entry):
        if entry.kind == "result":
            raise OSError(5, "Input/output error")
        real(self, entry)

    monkeypatch.setattr(Journal, "append", flaky)
    rec = run(doc)
    assert [s.result for s in rec.steps] == ["done", "not run", "not run"] and not rec.completed
    assert "the step journal could not be written: Input/output error" in rec.steps[0].detail
    assert (
        acct.users["backdoor-svc"].keys["AKIAIOSFODNN7BKDOOR"] == "Inactive"
    )  # the change was made, and said so


# ---- the guard


def test_refusals_before_the_first_change_leave_no_journal(fixtures, monkeypatch):
    acct = account_01()
    doc = dry_run_doc(fixtures, monkeypatch, acct)
    with pytest.raises(RespondError, match="--approve does not match"):
        run(doc, approve="0" * 16)
    acct.caller_arn = "arn:aws:sts::111122223333:assumed-role/SomeoneElse/bob"
    acct.roles["SomeoneElse"] = fake_aws.Role()
    with pytest.raises(RespondError, match="the dry run was checked for"):
        run(doc)
    assert list(tr.JOURNAL_DIR.iterdir()) == []
    acct.caller_arn = "arn:aws:sts::111122223333:assumed-role/IncidentResponder/alice"
    assert run(doc).completed  # the dry run was not used up


def test_the_journal_is_private_and_made_exclusively(fixtures, monkeypatch):
    doc = dry_run_doc(fixtures, monkeypatch, account_01())
    run(doc)
    path, _ = read_journal(doc)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(JournalExists):
        Journal.create(path)


def test_an_existing_journal_is_refused_even_if_empty_and_even_with_force(fixtures, monkeypatch, tmp_path):
    acct = account_01()
    acct.install(monkeypatch)
    scope = fixtures / "01_leaked_key/expected/scope.json"
    out = tmp_path / "out"
    out.mkdir()
    r = cli("respond", "dry-run", scope, "-o", out / "dryrun.json")
    assert r.exit_code == 0, r.output
    doc = json.loads((out / "dryrun.json").read_text())
    journal_path(out, doc["dryrun_sha256"]).touch()
    args = [
        "respond",
        "execute",
        out / "dryrun.json",
        "--scope",
        scope,
        "--approve",
        doc["dryrun_sha256"][:16],
    ]
    for extra in ([], ["--force"]):
        r = cli(*args, "-o", out / "response.json", *extra)
        assert r.exit_code == 2 and "already executed" in r.output, r.output
    assert not (out / "response.json").exists() and acct.calls == []


def test_the_command_line_names_the_journal(fixtures, monkeypatch, tmp_path):
    account_01().install(monkeypatch)
    scope = fixtures / "01_leaked_key/expected/scope.json"
    assert cli("respond", "dry-run", scope, "-o", tmp_path / "dryrun.json").exit_code == 0
    doc = json.loads((tmp_path / "dryrun.json").read_text())
    args = [
        "respond",
        "execute",
        tmp_path / "dryrun.json",
        "--scope",
        scope,
        "--approve",
        doc["dryrun_sha256"][:16],
    ]
    r = cli(*args, "-o", tmp_path / "response.json")
    assert r.exit_code == 0, r.output
    name = f"response.{doc['dryrun_sha256'][:16]}.journal.jsonl"
    assert f"Journal: {tmp_path / name}" in r.stdout and (tmp_path / name).exists()
    saved = json.loads((tmp_path / "response.json").read_text())
    assert saved["journal_sha256"] == hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
    again = cli(*args, "-o", tmp_path / "again.json")
    assert again.exit_code == 2 and "run a new dry run" in again.output


# ---- the format


def test_one_line_per_entry_whatever_the_text(tmp_path):
    journal = Journal.create(tmp_path / "j.jsonl")
    step = ExecutedStep(
        action_id="A01",
        op="stop_instance",
        args={},
        region=None,
        result="failed",
        detail="first\nsecond\r\n third",
        at=None,
    )
    from controlzee.model.respond import JournalResult

    journal.append(JournalResult(**step.model_dump()))
    journal.close()
    raw = (tmp_path / "j.jsonl").read_bytes()
    assert raw.count(b"\n") == 1 and raw.endswith(b"\n")
    assert json.loads(raw)["detail"] == step.detail and journal.sha256 == hashlib.sha256(raw).hexdigest()
    assert stat.S_IMODE(os.stat(tmp_path / "j.jsonl").st_mode) == 0o600


JSON = st.recursive(
    st.none() | st.booleans() | st.integers(-(2**53), 2**53) | st.text(),
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(st.text(), inner, max_size=4),
    max_leaves=12,
)


@given(JSON)
def test_a_journal_line_equals_the_standard_library_form(doc):
    expected = (json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    assert canonical.dumps_line(doc) == expected
