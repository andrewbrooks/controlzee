"""`dryrun.json` and `response.json`: what `controlzee respond` checked, and what it then did.

These are operational records, not analysis: unlike the other artifacts they carry wall-clock times (when the check was
made, when each change was applied), because that is evidence the response needs. They are still sealed, canonical
and free of host names and local paths.
"""
from __future__ import annotations

from typing import Any, Literal

from controlzee.model.common import SCHEMA_VERSION, Model


class Caller(Model):
    """Who the supplied credentials are."""

    account: str
    arn: str  # as STS reports it (a role session's ARN names the session)
    principal_arn: str  # the user or role whose policies apply, as checked with the IAM policy simulator


class PermissionCheck(Model):
    action: str  # "iam:UpdateAccessKey"
    resource: str
    decision: str  # "allowed", "implicitDeny", "explicitDeny"


class DryRunStep(Model):
    action_id: str  # the plan step, "A01"
    phase: str
    title: str
    op: str
    args: dict[str, str]
    region: str | None
    description: str  # what would be done, in words
    state: str  # the target as it is now
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
    result: Literal["done", "already done", "failed", "not run"]
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
    completed: bool  # every step done or already done
    response_sha256: str = ""
