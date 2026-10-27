"""The `controlzee` command line."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.text import Text

from controlzee import __version__, argcheck, canonical
from controlzee.artifacts import ArtifactError, load_scope, write_atomic
from controlzee.ingest.load import IngestError, Input
from controlzee.ingest.remote import LookupInput, S3Input
from controlzee.safety import clean
from controlzee.scope import ScopeOptions, ScopeOutput, build_scope
from controlzee.seed import expr
from controlzee.seed.guardduty import load_guardduty_file
from controlzee.seed.match import validate_spec
from controlzee.seed.spec import SpecError, SpecParts, assemble, from_flags, load_iocs_file, make_window

app = typer.Typer(no_args_is_help=True, add_completion=False, rich_markup_mode=None,
                  help="Incident response as code for AWS: scope an incident from CloudTrail, then plan the response.\n\n"
                       "controlzee scope writes scope.json; timeline, plan and report each read it.")
out = Console(highlight=False, markup=False)
err = Console(stderr=True, highlight=False, markup=False)


def _version(show: bool) -> None:
    if show:
        typer.echo(f"controlzee {__version__}")
        raise typer.Exit()


@app.callback()
def main(version: Annotated[bool, typer.Option("--version", callback=_version, is_eager=True, help="Show the version.")] = False) -> None:
    """controlzee"""


def _fail(message: str, code: int = 2) -> typer.Exit:
    err.print(Text("error: " + message, style="bold red"))
    return typer.Exit(code)


def _print_summary(result: ScopeOutput, scope_path: Path, inputs_path: Path) -> None:
    s, i = result.scope.summary, result.scope.inputs
    t = result.timings
    out.print(f"Scoped {i.event_count:,} events from {i.ingested_files:,} files in {t.ingest_s + t.seed_s + t.materialize_s:.1f} s "
              f"(read {t.ingest_s:.1f} s, match {t.seed_s:.1f} s, load {t.materialize_s:.1f} s)")
    out.print(f"In scope: {s.events_in_scope:,} events ({s.by_confidence.get('strong', 0):,} strong, "
              f"{s.by_confidence.get('weak', 0):,} weak), {s.failed_calls:,} of them failed calls")
    taint = result.scope.taint
    if taint.identities:
        acted = sum(1 for e in result.scope.events if e.via)
        out.print(f"Followed {len(taint.identities):,} credential(s) or principal(s) the attacker created or obtained: "
                  f"{acted:,} in-scope event(s) acted as them, {s.by_origin.get('propagated', 0):,} found only that way")
    if s.first_event_time:
        out.print(f"First to last in-scope event: {s.first_event_time} to {s.last_event_time}")
    nm = result.scope.near_miss_summary
    if nm.total:
        out.print(f"Near misses: {nm.total:,} events matched a weak indicator but are not in scope "
                  f"({', '.join(f'{k}: {v:,}' for k, v in nm.by_reason.items())}); {nm.listed:,} listed")
    for note in result.scope.coverage.notes:
        err.print(Text("coverage: " + clean(note, 300), style="yellow"))
    if i.error_files:
        err.print(Text(f"{i.error_files} file(s) could not be read; e.g. {clean(i.errors[0].path)}: {clean(i.errors[0].note)}", style="yellow"))
    if i.skipped_files:
        err.print(Text(f"{i.skipped_files} file(s) skipped on purpose; e.g. {clean(i.skipped[0].path)}: {clean(i.skipped[0].note)}"))
    if i.malformed_records:
        err.print(Text(f"{i.malformed_records:,} record(s) were not valid CloudTrail events and were ignored", style="yellow"))
    out.print(f"Wrote {scope_path} (sha256 {result.scope.scope_sha256[:16]}...) and {inputs_path}")


@app.command()
def scope(
    logs: Annotated[list[str] | None, typer.Option("--logs", help="CloudTrail file, directory or s3://bucket/prefix (.json, .json.gz); repeatable.")] = None,
    lookup_events: Annotated[list[str] | None, typer.Option("--lookup-events", metavar="REGION", help="Also read CloudTrail event history (LookupEvents) for this region over --window; repeatable.")] = None,
    aws_profile: Annotated[str | None, typer.Option("--aws-profile", help="AWS profile for S3 and event history (default: the usual credential chain).")] = None,
    iocs: Annotated[Path | None, typer.Option("--iocs", help="IOC file (YAML); see examples/iocs.yaml.")] = None,
    guardduty: Annotated[list[Path] | None, typer.Option("--guardduty", help="GuardDuty finding JSON to import indicators from.")] = None,
    access_key: Annotated[list[str] | None, typer.Option("--access-key", help="Access key id (strong). Repeatable.")] = None,
    principal_id: Annotated[list[str] | None, typer.Option("--principal-id", help="Principal id or session name (strong).")] = None,
    source_identity: Annotated[list[str] | None, typer.Option("--source-identity", help="Source identity (strong).")] = None,
    arn: Annotated[list[str] | None, typer.Option("--arn", help="Principal ARN, or the role ARN of its sessions (weak).")] = None,
    ip: Annotated[list[str] | None, typer.Option("--ip", help="Source IP or CIDR range (weak).")] = None,
    user_agent: Annotated[list[str] | None, typer.Option("--user-agent", help="User-agent substring (weak).")] = None,
    user_agent_regex: Annotated[list[str] | None, typer.Option("--user-agent-regex", help="User-agent regular expression (weak).")] = None,
    expression: Annotated[str | None, typer.Option("--expr", help="Combine indicators, e.g. '(arn_1 AND ip_1) OR access_key_1'. Default: any.")] = None,
    window: Annotated[tuple[str, str] | None, typer.Option("--window", help="Only count events from START to END (UTC). Required for weak-only IOCs.", metavar="START END")] = None,
    out_path: Annotated[Path, typer.Option("--out", "-o", help="Where to write scope.json (a .inputs.json file goes beside it).")] = Path("scope.json"),
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing output files.")] = False,
    workers: Annotated[int | None, typer.Option("--workers", min=1, help="Worker processes (default: up to 16, by CPU count).")] = None,
    near_miss_limit: Annotated[int, typer.Option("--near-miss-limit", min=0, help="Most near misses to list; all are counted.")] = 500,
    embed_raw: Annotated[bool, typer.Option("--embed-raw", help="Embed each in-scope event's raw record in scope.json (much larger).")] = False,
    strict: Annotated[bool, typer.Option("--strict", help="Exit with status 3 if any input file or record could not be read.")] = False,
    no_propagate: Annotated[bool, typer.Option("--no-propagate", help="Do not follow credentials and principals the attacker created or obtained.")] = False,
    gap_minutes: Annotated[int, typer.Option("--gap-minutes", min=1, help="Shortest silence in the logs to report as a coverage gap.")] = 60,
) -> None:
    """Find what the attacker did: match indicators against CloudTrail and write scope.json."""
    if not logs and not lookup_events:
        raise _fail("no logs given: pass --logs (a file, directory or s3:// prefix) or --lookup-events REGION")
    inputs_path = out_path.with_name(out_path.stem + ".inputs.json")
    existing = [p for p in (out_path, inputs_path) if p.exists()]
    if existing and not force:
        raise _fail(f"{existing[0]} already exists; use --force to overwrite it, or choose another --out")
    try:
        parts: list[SpecParts] = []
        if iocs:
            parts.append(load_iocs_file(iocs))
        for g in guardduty or []:
            gd = load_guardduty_file(g)
            for note in gd.notes:
                out.print(Text(clean(note, 300)))
            parts.append(gd)
        parts.append(SpecParts(indicators=from_flags(
            access_keys=access_key or [], principal_ids=principal_id or [], source_identities=source_identity or [],
            arns=arn or [], ips=ip or [], user_agents=user_agent or [], user_agent_regexes=user_agent_regex or [])))
        win = make_window({"start": window[0], "end": window[1]}) if window else None
        spec = assemble(parts, expression=expression, window=win)
        validate_spec(spec)
        aws_profile = argcheck.profile(aws_profile)
        sources: list[Input] = [S3Input(argcheck.s3_url(p), aws_profile) if p.startswith("s3://") else Path(p) for p in logs or []]
        if lookup_events:
            lookup_events = [argcheck.region(r, "--lookup-events") for r in lookup_events]
            w = spec.window
            if w is None or not (w.start and w.end):
                raise SpecError("--lookup-events needs --window START END (or a window in the IOC file): event history is "
                                "queried for exactly that range, so the result can be reproduced")
            sources += [LookupInput(region, w.start, w.end, aws_profile) for region in sorted(set(lookup_events))]
        result = build_scope(sources, spec,
                             ScopeOptions(workers=workers, near_miss_limit=near_miss_limit, embed_raw=embed_raw,
                                          propagate=not no_propagate, gap_minutes=gap_minutes))
    except (SpecError, expr.ExpressionError, IngestError, argcheck.ArgError, ValueError) as e:
        raise _fail(clean(e, 600)) from None
    write_atomic(out_path, result.scope_bytes)
    write_atomic(inputs_path, result.inputs_bytes)
    _print_summary(result, out_path, inputs_path)
    i = result.scope.inputs
    if strict and (i.error_files or i.malformed_records):
        raise typer.Exit(3)


ScopeArg = Annotated[Path, typer.Argument(help="A scope.json written by controlzee scope.", exists=False)]
Force = Annotated[bool, typer.Option("--force", help="Overwrite the output file.")]


def _derive(scope_path: Path, out_path: Path, force: bool, build: Callable[[Any], bytes]) -> Any:
    """Shared by the commands that read a scope: refuse to overwrite, load and check the scope, build, write."""
    if out_path.exists() and not force:
        raise _fail(f"{out_path} already exists; use --force to overwrite it, or choose another --out")
    try:
        scope_doc = load_scope(scope_path)
    except ArtifactError as e:
        raise _fail(clean(e, 600)) from None
    data = build(scope_doc)
    write_atomic(out_path, data)
    return scope_doc


@app.command()
def timeline(
    scope_path: ScopeArg = Path("scope.json"),
    out_path: Annotated[Path, typer.Option("--out", "-o", help="Where to write timeline.json.")] = Path("timeline.json"),
    force: Force = False,
) -> None:
    """Order the in-scope events into a story (actors, tactics, gaps) and list what was exposed."""
    from controlzee.model.timeline import Timeline
    from controlzee.timeline import build_timeline

    doc: dict[str, Any] = {}

    def build(sc: Any) -> bytes:
        doc.update(build_timeline(sc))
        return canonical.dumps(doc)

    _derive(scope_path, out_path, force, build)
    tl = Timeline.model_validate(doc)
    out.print(f"Timeline: {sum(1 for e in tl.entries if e.kind == 'event'):,} events by {len(tl.actors)} identit{'y' if len(tl.actors) == 1 else 'ies'}, "
              f"{sum(1 for e in tl.entries if e.kind == 'gap')} gap(s); tactics: {', '.join(t.tactic for t in tl.tactics) or 'none'}")
    x = tl.exposure
    out.print(f"Exposure: {len(x.resources)} resource(s), {len(x.privilege_changes)} permission change(s)"
              + ("; full administrative access was granted" if x.admin_granted else "")
              + (f"; {len(x.credentials_read)} credential(s) read" if x.credentials_read else ""))
    out.print(f"Wrote {out_path} (sha256 {tl.timeline_sha256[:16]}...)")


@app.command()
def plan(
    scope_path: ScopeArg = Path("scope.json"),
    out_path: Annotated[Path, typer.Option("--out", "-o", help="Where to write plan.json.")] = Path("plan.json"),
    force: Force = False,
) -> None:
    """Write the response plan: contain, investigate, eradicate, recover, with AWS CLI commands (never run)."""
    from controlzee.model.plan import Plan
    from controlzee.plan import PHASES, build_plan

    doc: dict[str, Any] = {}

    def build(sc: Any) -> bytes:
        doc.update(build_plan(sc))
        return canonical.dumps(doc)

    _derive(scope_path, out_path, force, build)
    p = Plan.model_validate(doc)
    counts = ", ".join(f"{n} {ph}" for ph in PHASES if (n := sum(1 for a in p.actions if a.phase == ph)))
    out.print(f"Plan: {len(p.actions)} step(s) ({counts or 'nothing to do'}); controlzee runs none of the commands")
    out.print(f"Wrote {out_path} (sha256 {p.plan_sha256[:16]}...)")


@app.command()
def report(
    scope_path: ScopeArg = Path("scope.json"),
    out_path: Annotated[Path, typer.Option("--out", "-o", help="Where to write the Markdown report.")] = Path("report.md"),
    force: Force = False,
) -> None:
    """Write a Markdown report: summary, coverage, timeline, exposure and the response plan."""
    from controlzee.report import build_report

    _derive(scope_path, out_path, force, build_report)
    out.print(f"Wrote {out_path}")


respond_app = typer.Typer(no_args_is_help=True, add_completion=False, rich_markup_mode=None,
                          help="Carry out the plan's operations in AWS: first a dry run for a person to review, then, with "
                               "their approval, the changes.")
app.add_typer(respond_app, name="respond")
Profile = Annotated[str | None, typer.Option("--aws-profile", help="AWS profile to act with (default: the usual credential chain).")]


@respond_app.command("dry-run")
def respond_dry_run(
    scope_path: ScopeArg = Path("scope.json"),
    out_path: Annotated[Path, typer.Option("--out", "-o", help="Where to write the dry run.")] = Path("dryrun.json"),
    steps: Annotated[str | None, typer.Option("--steps", help="Only these plan steps, e.g. A01,A03 (default: every step that can run).")] = None,
    allow_disruptive: Annotated[bool, typer.Option("--allow-disruptive", help="Include steps that delete, stop or terminate things.")] = False,
    aws_profile: Profile = None,
    region: Annotated[str, typer.Option("--region", help="Region for IAM and STS calls.")] = "us-east-1",
    force: Force = False,
) -> None:
    """Check, without changing anything, what the plan would do and that these credentials may do it."""
    from controlzee.model.respond import DryRun
    from controlzee.respond.run import RespondError, dry_run

    if out_path.exists() and not force:
        raise _fail(f"{out_path} already exists; use --force to overwrite it, or choose another --out")
    try:
        chosen, profile = argcheck.steps(steps), argcheck.profile(aws_profile)
        argcheck.region(region, "--region")
        doc = dry_run(load_scope(scope_path), profile=profile, home_region=region, chosen=chosen, allow_disruptive=allow_disruptive)
    except (ArtifactError, RespondError, argcheck.ArgError) as e:
        raise _fail(clean(e, 600)) from None
    write_atomic(out_path, canonical.dumps(doc))
    dr = DryRun.model_validate(doc)
    out.print(f"Credentials: {clean(dr.caller.arn)} (account {dr.caller.account})")
    for st in dr.steps:
        mark = "already done" if st.already_done else ("ok" if st.ok else "CANNOT RUN")
        out.print(f"  {st.action_id} [{mark}] {clean(st.description, 300)}")
        out.print(f"      now: {clean(st.state, 300)}")
        for c in st.checks:
            out.print(f"      {'allowed' if c.decision == 'allowed' else 'DENIED '} {clean(c.action)} on {clean(c.resource, 300)}")
        if st.problem:
            err.print(Text(f"      {clean(st.problem, 400)}", style="red"))
    for n in dr.not_selected:
        out.print(f"  {n.action_id} not included: {clean(n.reason, 300)}")
    out.print(f"Wrote {out_path}")
    if not dr.passed:
        err.print(Text(f"Dry run FAILED: {len(dr.problems)} problem(s); nothing can be executed from it", style="bold red"))
        raise typer.Exit(4)
    todo = sum(1 for st in dr.steps if not st.already_done)
    if not todo:
        out.print("Nothing to do: every selected step is already in place")
        return
    out.print(f"Dry run passed: {todo} change(s) to make. Review the steps above (and {out_path}); to make them, run:")
    out.print(f"  controlzee respond execute {out_path} --approve {dr.dryrun_sha256[:16]}")


@respond_app.command("execute")
def respond_execute(
    dryrun_path: Annotated[Path, typer.Argument(help="A dry run written by controlzee respond dry-run.")] = Path("dryrun.json"),
    approve: Annotated[str, typer.Option("--approve", help="The dry run's sha256 (or its first 12+ characters): your approval of exactly that dry run.")] = "",
    out_path: Annotated[Path, typer.Option("--out", "-o", help="Where to write the record of what was done.")] = Path("response.json"),
    aws_profile: Profile = None,
    max_age_minutes: Annotated[int, typer.Option("--max-age-minutes", min=1, max=1440, help="Refuse a dry run older than this.")] = 60,
    force: Force = False,
) -> None:
    """Make the changes of an approved dry run, in order, stopping at the first failure."""
    from datetime import timedelta

    import orjson

    from controlzee.model.respond import ResponseRecord
    from controlzee.respond.run import MAX_DRY_RUN_BYTES, RespondError, execute

    if out_path.exists() and not force:
        raise _fail(f"{out_path} already exists; use --force to overwrite it, or choose another --out")
    try:
        if not approve:
            raise argcheck.ArgError("--approve is required: pass the dry run's sha256, as printed by the dry run, once you have reviewed it")
        approval, profile = argcheck.approval(approve), argcheck.profile(aws_profile)
        if dryrun_path.stat().st_size > MAX_DRY_RUN_BYTES:
            raise argcheck.ArgError(f"{dryrun_path.name} is too large to be a dry run")
        doc = orjson.loads(dryrun_path.read_bytes())
        result = execute(doc, approve=approval, profile=profile, max_age=timedelta(minutes=max_age_minutes),
                         progress=lambda st: out.print(f"  {st.action_id} {st.result}: {clean(st.detail, 300)}"))
    except OSError as e:
        raise _fail(f"cannot read {dryrun_path.name}: {e.strerror}") from None
    except orjson.JSONDecodeError:
        raise _fail(f"{dryrun_path.name} is not valid JSON") from None
    except (RespondError, argcheck.ArgError) as e:
        raise _fail(clean(e, 600)) from None
    write_atomic(out_path, canonical.dumps(result))
    rec = ResponseRecord.model_validate(result)
    out.print(f"Wrote {out_path}")
    if not rec.completed:
        err.print(Text("Stopped: a step failed; later steps were not run. See the record above.", style="bold red"))
        raise typer.Exit(5)
    out.print(f"Done: {sum(1 for st in rec.steps if st.result == 'done')} change(s) made, "
              f"{sum(1 for st in rec.steps if st.result == 'already done')} already in place")
