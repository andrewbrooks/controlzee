"""Which identity of the graph a plan step is about, so the report can light them up together.

Read off the step's operations (the user, role, access key or function it names), never from free text. A step that is about something
the attacker created and never used as an identity has nothing to light up, and gets no link. Display only: nothing here is saved.
"""
from __future__ import annotations

from controlzee.model.plan import Plan
from controlzee.model.timeline import Actor


def _about(value: str, actor: Actor) -> bool:
    return value in actor.access_keys or value == actor.arn or value in actor.label.split("/")[1:]


def steps_by_actor(plan: Plan, actors: list[Actor]) -> dict[str, list[str]]:
    """For each step id, the labels of the identities its operations name, in the order the actors are listed."""
    out: dict[str, list[str]] = {}
    for a in plan.actions:
        values = [v for op in a.operations for v in op.args.values()]
        hit = [x.label for x in actors if any(_about(v, x) for v in values)]
        if hit:
            out[a.id] = hit
    return out
