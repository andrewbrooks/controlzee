"""Dry run and execute: carry out a plan's operations against AWS, only as approved.

dry_run builds the plan from the (sealed) scope itself rather than reading a plan file, so only the plan builder's
shape-checked operations can ever run. It identifies the caller, reads each target's current state (read-only calls),
and asks the IAM policy simulator whether the caller may make every call each change needs. If any of that fails, the
dry run fails. The simulator covers identity policies, permission boundaries and SCPs, but not session policies or
resource-based policies, so execute can still be refused: it then stops at that step.

execute runs exactly the steps of an approved dry run: the approval must match the dry run's hash, the dry run must
have passed and be recent, and the caller must be the same principal in the same account. Each step's state is read
again first, so something already put right is skipped rather than repeated. It stops at the first failure.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from controlzee import canonical
from controlzee.ingest.remote import aws_errors, client
from controlzee.model.common import SCHEMA_VERSION, tool_info
from controlzee.model.plan import Plan, PlanAction
from controlzee.model.respond import (
    Caller,
    DryRun,
    DryRunStep,
    ExecutedStep,
    NotSelected,
    PermissionCheck,
    ResponseRecord,
)
from controlzee.model.scope import Scope
from controlzee.plan import build_plan
from controlzee.respond.ops import OPS, Ctx, Probe, Unsafe, validate
from controlzee.safety import clean

Clock = Callable[[], datetime]
MAX_DRY_RUN_BYTES = 64 << 20


class RespondError(Exception):
    """The response cannot go ahead; the message says why."""


def _now(clock: Clock) -> str:
    return clock().astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _aws_message(e: Exception) -> str:
    err = getattr(e, "response", {}).get("Error", {})
    return clean(f"{err.get('Code', type(e).__name__)}: {err.get('Message', e)}", 300)


def identify(profile: str | None, home_region: str) -> tuple[Ctx, Caller]:
    """The caller, and the principal whose policies the simulator should evaluate."""
    try:
        ident = client("sts", profile, home_region).get_caller_identity()
    except aws_errors() as e:
        raise RespondError(f"cannot identify the supplied credentials: {_aws_message(e)}") from None
    arn, account = str(ident["Arn"]), str(ident["Account"])
    partition = arn.split(":", 2)[1]
    ctx = Ctx(account=account, partition=partition, profile=profile, home_region=home_region)
    if arn.endswith(":root"):
        raise RespondError("these are the account's root credentials; use an IAM role or user so permissions can be checked")
    if ":assumed-role/" in arn:
        role = arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
        try:
            principal = str(ctx.c("iam").get_role(RoleName=role)["Role"]["Arn"])
        except aws_errors() as e:
            raise RespondError(f"cannot look up role {role} of the supplied credentials (needs iam:GetRole): {_aws_message(e)}") from None
    elif ":user/" in arn:
        principal = arn
    else:
        raise RespondError(f"credentials of this kind ({clean(arn)}) cannot be checked; use an IAM role or user")
    return ctx, Caller(account=account, arn=arn, principal_arn=principal)


def simulate(ctx: Ctx, principal_arn: str, checks: list[tuple[str, str]]) -> dict[tuple[str, str], str]:
    """(action, resource) -> the simulator's decision, for every check."""
    by_resource: dict[str, set[str]] = defaultdict(set)
    for action, resource in checks:
        by_resource[resource].add(action)
    decisions: dict[tuple[str, str], str] = {}
    try:
        for resource in sorted(by_resource):
            pages = ctx.c("iam").get_paginator("simulate_principal_policy").paginate(
                PolicySourceArn=principal_arn, ActionNames=sorted(by_resource[resource]), ResourceArns=[resource])
            for page in pages:
                for r in page.get("EvaluationResults", []):
                    decisions[(r["EvalActionName"], resource)] = str(r["EvalDecision"])
    except aws_errors() as e:
        raise RespondError(f"cannot check permissions with the IAM policy simulator (needs iam:SimulatePrincipalPolicy): "
                           f"{_aws_message(e)}") from None
    return decisions


def _select(plan: Plan, caller: Caller, chosen: set[str] | None, allow_disruptive: bool) -> tuple[list[PlanAction], list[NotSelected], list[str]]:
    known = {a.id for a in plan.actions}
    problems = [f"--steps names {i}, which is not a step of this plan" for i in sorted((chosen or set()) - known)]
    selected, skipped = [], []
    for a in plan.actions:
        explicit = chosen is not None and a.id in chosen
        reason = None
        if chosen is not None and not explicit:
            reason = "not chosen with --steps"
        elif not a.operations:
            reason = "a manual step: controlzee cannot carry it out"
        elif a.on_request and not explicit:
            reason = "runs only when named with --steps (it undoes a containment step)"
        elif a.disruptive and not allow_disruptive:
            reason = "disruptive (deletes, stops or terminates something): pass --allow-disruptive to include it"
        elif a.account and a.account != caller.account:
            reason = f"acts in account {a.account}; these credentials are for {caller.account}"
        if reason is None:
            selected.append(a)
            continue
        skipped.append(NotSelected(action_id=a.id, title=a.title, reason=reason))
        if explicit and not reason.startswith("not chosen"):
            problems.append(f"{a.id} was chosen with --steps but cannot run: {reason}")
    return selected, skipped, problems


# operations that would cut off the principal running the response, by the argument naming it
_CUTS_OFF = {"role": {"revoke_role_sessions", "delete_role"},
             "user": {"revoke_user_sessions", "deactivate_access_key", "delete_access_key", "delete_user"}}


def cuts_off_caller(op: str, args: dict[str, str], caller: Caller) -> str | None:
    """Why `op` would revoke the credentials running the response, or None. Checked before anything else."""
    kind = "role" if ":role/" in caller.principal_arn else "user"
    name = caller.principal_arn.rsplit("/", 1)[1]
    if op in _CUTS_OFF[kind] and args.get(kind) == name:
        return (f"it would revoke the credentials running this response ({kind} {name}), so the steps after it would fail: "
                "run the response as a different role or user, or leave this step out with --steps")
    return None


def dry_run(scope: Scope, *, profile: str | None, home_region: str, chosen: set[str] | None = None, allow_disruptive: bool = False,
            clock: Clock = lambda: datetime.now(UTC)) -> dict[str, Any]:
    plan = Plan.model_validate(build_plan(scope))
    ctx, caller = identify(profile, home_region)
    selected, skipped, problems = _select(plan, caller, chosen, allow_disruptive)
    probed: list[tuple[PlanAction, Any, Probe | None, str | None]] = []
    for a in selected:
        for o in a.operations:
            try:
                validate(o.op, o.args, o.region)
                if (harm := cuts_off_caller(o.op, o.args, caller)) is not None:
                    probed.append((a, o, None, harm))
                    continue
                probed.append((a, o, OPS[o.op].probe(ctx, o.args, o.region), None))
            except (Unsafe, KeyError):
                probed.append((a, o, None, "the operation's arguments are not valid"))
            except aws_errors() as e:
                probed.append((a, o, None, f"cannot read the target's current state: {_aws_message(e)}"))
    needed = sorted({c for _, _, p, _ in probed if p and not p.done for c in p.checks})
    decisions = simulate(ctx, caller.principal_arn, needed) if needed else {}
    steps = []
    for a, o, p, problem in probed:
        checks = [PermissionCheck(action=act, resource=res, decision=decisions.get((act, res), "not evaluated"))
                  for act, res in (p.checks if p and not p.done else ())]
        denied = [c for c in checks if c.decision != "allowed"]
        if problem is None and denied:
            problem = "not permitted: " + ", ".join(f"{c.action} on {c.resource} ({c.decision})" for c in denied)
        steps.append(DryRunStep(action_id=a.id, phase=a.phase, title=a.title, op=o.op, args=o.args, region=o.region,
                                description=OPS[o.op].describe(o.args, o.region) if problem != "the operation's arguments are not valid" else o.op,
                                state=p.state if p else "unknown", already_done=bool(p and p.done), checks=checks,
                                ok=problem is None, problem=problem))
    problems += [f"{s.action_id} {s.op}: {s.problem}" for s in steps if s.problem]
    doc = DryRun(tool=tool_info(), scope_sha256=scope.scope_sha256, plan_sha256=plan.plan_sha256, caller=caller,
                 home_region=home_region, checked_at=_now(clock), allow_disruptive=allow_disruptive, steps=steps,
                 not_selected=skipped, problems=problems, passed=not problems)
    return canonical.seal(doc.model_dump(mode="json"), "dryrun_sha256")


def load_dry_run(doc: Any) -> DryRun:
    if not isinstance(doc, dict) or "dryrun_sha256" not in doc:
        raise RespondError("not a dry run written by controlzee respond dry-run")
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise RespondError(f"the dry run has schema version {doc.get('schema_version')!r}; run the dry run again with this version")
    if not canonical.is_sealed(doc, "dryrun_sha256"):
        raise RespondError("the dry run was changed after it was written (its dryrun_sha256 does not match its content)")
    try:
        return DryRun.model_validate(doc)
    except ValueError as e:
        raise RespondError(f"the dry run does not match its schema: {clean(e, 200)}") from None


def execute(doc: Any, *, approve: str, profile: str | None, max_age: timedelta,
            clock: Clock = lambda: datetime.now(UTC), progress: Callable[[ExecutedStep], None] = lambda s: None) -> dict[str, Any]:
    dr = load_dry_run(doc)
    if not dr.passed:
        raise RespondError("this dry run did not pass; fix what it reports and run the dry run again")
    if len(approve) < 12 or not dr.dryrun_sha256.startswith(approve):
        raise RespondError("--approve does not match this dry run's sha256; approve the dry run you reviewed")
    checked = datetime.strptime(dr.checked_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    if clock() - checked > max_age:
        raise RespondError(f"the dry run is older than {int(max_age.total_seconds() // 60)} minutes; run it again so the "
                           "checks reflect the account as it is now")
    ctx, caller = identify(profile, dr.home_region)
    if (caller.account, caller.principal_arn) != (dr.caller.account, dr.caller.principal_arn):
        raise RespondError(f"these credentials are {clean(caller.principal_arn)} in {caller.account}; the dry run was checked for "
                           f"{clean(dr.caller.principal_arn)} in {dr.caller.account}")
    started = _now(clock)
    done: list[ExecutedStep] = []
    failed = False
    for s in dr.steps:
        if failed:
            done.append(ExecutedStep(action_id=s.action_id, op=s.op, args=s.args, region=s.region, result="not run",
                                     detail="an earlier step failed", at=None))
            continue
        try:
            validate(s.op, s.args, s.region)
            if OPS[s.op].probe(ctx, s.args, s.region).done:
                step = ExecutedStep(action_id=s.action_id, op=s.op, args=s.args, region=s.region, result="already done",
                                    detail="the target was already in the intended state", at=_now(clock))
            else:
                detail = OPS[s.op].apply(ctx, s.args, s.region)
                step = ExecutedStep(action_id=s.action_id, op=s.op, args=s.args, region=s.region, result="done",
                                    detail=clean(detail, 400), at=_now(clock))
        except (Unsafe, KeyError):
            step = ExecutedStep(action_id=s.action_id, op=s.op, args=s.args, region=s.region, result="failed",
                                detail="the operation's arguments are not valid", at=_now(clock))
        except aws_errors() as e:
            step = ExecutedStep(action_id=s.action_id, op=s.op, args=s.args, region=s.region, result="failed",
                                detail=_aws_message(e), at=_now(clock))
        failed = step.result == "failed"
        progress(step)
        done.append(step)
    record = ResponseRecord(tool=tool_info(), dryrun_sha256=dr.dryrun_sha256, caller=caller, started_at=started,
                            finished_at=_now(clock), steps=done, completed=all(s.result in ("done", "already done") for s in done))
    return canonical.seal(record.model_dump(mode="json"), "response_sha256")
