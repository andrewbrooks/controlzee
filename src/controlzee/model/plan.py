"""`plan.json`: what to do about the incident, as reviewable steps with the AWS CLI commands that carry them out.

Steps with `operations` can be carried out by `controlzee respond`, only after a dry run that a person approved; their
`commands` are the same thing as AWS CLI text. Steps without operations are for a person.
"""
from __future__ import annotations

from typing import Any, Literal

from controlzee.model.common import SCHEMA_VERSION, Confidence, Model

Phase = Literal["contain", "investigate", "eradicate", "recover"]


class Operation(Model):
    """One change `controlzee respond` knows how to make (see respond/ops.py), with its checked arguments."""

    op: str
    args: dict[str, str]
    region: str | None  # None for global services (IAM)


class PlanAction(Model):
    id: str  # "A01", in the order to work through them
    phase: Phase
    title: str
    target: str
    why: str
    account: str | None  # the account the step acts in, when known
    confidence: Confidence  # weak: the evidence is weak; verify before acting
    commands: list[str]  # AWS CLI text; empty when the step needs judgement rather than a command
    operations: list[Operation]  # what respond would do; empty for manual steps
    disruptive: bool  # deletes, terminates or stops something: respond runs it only with --allow-disruptive
    caution: str | None
    evidence: list[str]  # event ids, first 10


class Plan(Model):
    schema_version: str = SCHEMA_VERSION
    tool: dict[str, Any]
    scope_sha256: str
    actions: list[PlanAction]
    notes: list[str]
    plan_sha256: str = ""
