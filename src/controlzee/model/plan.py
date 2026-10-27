"""`plan.json`: what to do about the incident, as reviewable steps with the AWS CLI commands that carry them out.

controlzee never runs these commands. They are written for a person to read, adjust and run, in phase order.
"""
from __future__ import annotations

from typing import Any, Literal

from controlzee.model.common import SCHEMA_VERSION, Confidence, Model

Phase = Literal["contain", "investigate", "eradicate", "recover"]


class PlanAction(Model):
    id: str  # "A01", in the order to work through them
    phase: Phase
    title: str
    target: str
    why: str
    confidence: Confidence  # weak: the evidence is weak; verify before acting
    commands: list[str]  # empty when the step needs judgement rather than a command
    caution: str | None
    evidence: list[str]  # event ids, first 10


class Plan(Model):
    schema_version: str = SCHEMA_VERSION
    tool: dict[str, Any]
    scope_sha256: str
    actions: list[PlanAction]
    notes: list[str]
    plan_sha256: str = ""
