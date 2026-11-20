"""`dryrun.json` and `response.json`: what `controlzee respond` checked, and what it then did.

These are operational records, not analysis: unlike the other artifacts they carry wall-clock times (when the check was
made, when each change was applied), because that is evidence the response needs. They are still sealed, canonical
and free of host names and local paths. The step journal (`response.<hash>.journal.jsonl`) is the third such record: it
is not sealed, since it is written line by line while the run is still going, but `response.json` cites its hash.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field, RootModel

from controlzee.model.common import SCHEMA_VERSION, Model


class Caller(Model):
    """Who the supplied credentials are."""

    account: str
    arn: str  # as STS reports it (a role session's ARN names the session)
    principal_arn: str  # the user or role whose policies apply, as checked with the IAM policy simulator


class PermissionCheck(Model):
    action: str  # "iam:UpdateAccessKey"
    resource: str
    decision: str  # "allowed", or the simulator's refusal ("implicitDeny", "explicitDeny"), possibly with a note on condition keys


class DryRunStep(Model):
    action_id: str  # the plan step, "A01"
    phase: str
    title: str
    op: str
    args: dict[str, str]
    region: str | None
    description: str  # what would be done, in words
    state: str  # the target as it is now
    identity: dict[str, str]  # which resource it is (ids, creation dates); execute stops if that has changed
    already_done: bool
    checks: list[PermissionCheck]
    ok: bool
    problem: str | None


class NotSelected(Model):
    action_id: str
    title: str
    reason: str


class DryRun(Model):
    schema_version: str = SCHEMA_VERSION
    tool: dict[str, Any]
    scope_sha256: str
    plan_sha256: str
    caller: Caller
    home_region: str
    checked_at: str
    allow_disruptive: bool
    chosen_steps: list[str] | None  # the plan steps named with --steps, or None for "every step that can run"
    steps: list[DryRunStep]  # in the order execute would run them
    not_selected: list[NotSelected]
    warnings: list[str] = []  # worth reading, but they do not stop execute
    problems: list[str]
    passed: bool  # every selected step can be done with these credentials; execute refuses otherwise
    dryrun_sha256: str = ""


class ExecutedStep(Model):
    action_id: str
    op: str
    args: dict[str, str]
    region: str | None
    result: Literal[
        "done", "already done", "failed", "drifted", "not run"
    ]  # drifted: not the target the dry run checked
    detail: str
    at: str | None


class ResponseRecord(Model):
    schema_version: str = SCHEMA_VERSION
    tool: dict[str, Any]
    dryrun_sha256: str  # the approved dry run
    caller: Caller
    started_at: str
    finished_at: str
    steps: list[ExecutedStep]
    completed: bool  # every step done or already done, and the journal was written in full
    journal_sha256: str  # the step journal of this run, as written
    response_sha256: str = ""


class JournalHeader(Model):
    """First line of the step journal: which dry run is being carried out, by whom, and when it began."""

    kind: Literal["header"] = "header"
    schema_version: str = SCHEMA_VERSION
    dryrun_sha256: str
    caller: Caller
    started_at: str


class JournalStarting(Model):
    """Written and flushed to disk before a step's change is made. A step with this line and no result line was
    started and its outcome is not known: the change may be partly made."""

    kind: Literal["starting"] = "starting"
    action_id: str
    op: str
    args: dict[str, str]
    region: str | None
    at: str


class JournalResult(ExecutedStep):
    """What became of a step, as it is later in `response.json`. A step that never reached its change has only this."""

    kind: Literal["result"] = "result"


class JournalLine(
    RootModel[Annotated[JournalHeader | JournalStarting | JournalResult, Field(discriminator="kind")]]
):
    """Any one line of the step journal."""
