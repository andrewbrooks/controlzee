"""Which identity of the graph a plan step is about, so the report can light them up together.

Read off the step's operations (the user, role, access key, instance or function it names, by the name of the argument), never from free text. A step that is about something
the attacker created and never used as an identity has nothing to light up, and gets no link. Display only: nothing here is saved.
"""
from __future__ import annotations

from controlzee.model.plan import Plan
from controlzee.model.timeline import Actor


def _about(arg: str, value: str, actor: Actor) -> bool:
    """Whether an operation's argument (`arg` is its name: "user", "role", "key", ...) names this identity. Typed, so that the user
    `maint` and a role session called `maint` are not taken for each other."""
    if arg == "user":
        return actor.label == f"user/{value}"
    if arg == "role":
        return actor.label.startswith(f"assumed-role/{value}/")
    if arg == "key":
        return value in actor.access_keys
    if arg in ("instance", "function"):  # a role session named for the instance or the function
        return actor.label.startswith("assumed-role/") and actor.label.endswith("/" + value)
    return False


def steps_by_actor(plan: Plan, actors: list[Actor]) -> dict[str, list[str]]:
    """For each step id, the labels of the identities its operations name, in the order the actors are listed."""
    out: dict[str, list[str]] = {}
    for a in plan.actions:
        named = [(k, v) for op in a.operations for k, v in op.args.items()]
        hit = [x.label for x in actors if any(_about(k, v, x) for k, v in named)]
        if hit:
            out[a.id] = hit
    return out
