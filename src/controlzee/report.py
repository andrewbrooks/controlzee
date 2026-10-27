"""`report.md`: the scope, timeline, exposure and plan as one Markdown document for people.

Built from `scope.json` alone (the timeline and plan are derived on the way), so it always agrees with them.
Every value that came from the logs is attacker-influenced: it goes through `safety.clean` and then Markdown escaping,
so it cannot add links, HTML, headings or table cells. Commands are in fenced blocks longer than any backtick run.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

from controlzee import __version__
from controlzee.model.plan import Plan
from controlzee.model.scope import Scope
from controlzee.model.timeline import Timeline
from controlzee.plan import PHASES, build_plan
from controlzee.safety import clean
from controlzee.timeline import build_timeline

_SPECIAL = re.compile(r"([\\`*_{}\[\]<>()#+!|~&$])")
_PHASE_TITLES = {"contain": "Contain", "investigate": "Investigate", "eradicate": "Eradicate", "recover": "Recover"}


def md(value: object, limit: int = 200) -> str:
    """Untrusted text, safe inline in Markdown: control characters replaced, length capped, markup escaped."""
    text = _SPECIAL.sub(r"\\\1", clean(value, limit))
    return text.replace("://", r":\/\/").replace("www.", r"www\.")  # no autolinks


def _fence(lines: Iterable[str]) -> list[str]:
    body = [clean(line, 4000) for line in lines]
    longest = max((len(m) for line in body for m in re.findall(r"`+", line)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + "sh", *body, fence]


def _n(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _gap(out: list[str]) -> list[str]:
    """`out` ending in exactly one blank line, ready for the next block."""
    while out and out[-1] == "":
        out.pop()
    return [*out, ""]


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    return ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)] + ["| " + " | ".join(r) + " |" for r in rows]


def _summary(scope: Scope, tl: Timeline) -> list[str]:
    s, x = scope.summary, tl.exposure
    out = ["## Summary", ""]
    if not s.events_in_scope:
        return [*out, "No events matched the indicators.", ""]
    out.append(f"- **{s.events_in_scope} events** in scope ({s.by_confidence.get('strong', 0)} strong, "
               f"{s.by_confidence.get('weak', 0)} weak), from {md(s.first_event_time)} to {md(s.last_event_time)}; "
               f"{s.failed_calls} of them failed.")
    out.append(f"- **{_n(len(tl.actors), 'identity', 'identities')}** acted for the attacker: {', '.join(md(a.label) for a in tl.actors)}.")
    if scope.taint.identities:
        out.append(f"- **{len(scope.taint.identities)} credentials or principals** were created or obtained by the attacker and "
                   f"followed; {s.by_origin.get('propagated', 0)} events were found only that way.")
    out.append(f"- **Tactics:** {', '.join(f'{t.tactic} ({t.events})' for t in tl.tactics)}.")
    out.append(f"- **Accounts:** {', '.join(md(a) for a in x.accounts)}.")
    if x.admin_granted:
        out.append("- **Full administrative access was granted.**")
    if x.credentials_read:
        out.append(f"- **Credentials read:** {', '.join(md(c) for c in x.credentials_read)}.")
    return [*out, ""]


def _coverage(scope: Scope) -> list[str]:
    cov = scope.coverage
    out = ["## What the logs cannot show", ""]
    if not (cov.notes or cov.tampering):
        return [*out, "Nothing found: the logs cover the incident period without unusual silences or logging changes.", ""]
    out += [f"- {md(n, 400)}" for n in cov.notes]
    if cov.gaps:
        out += ["", "Silences during the incident:", ""]
        out += _table(["Account", "Region", "From", "To", "Minutes", "Possible cause"],
                      [[md(g.account), md(g.region), md(g.start), md(g.end), str(g.minutes), md(g.possible_cause or "")] for g in cov.gaps])
    if cov.tampering:
        out += ["", "Logging and detection changes (all actors):", ""]
        out += _table(["Time", "Call", "Effect", "By", "Result", "Attacker"],
                      [[md(t.event_time), md(f"{t.event_source.split('.', 1)[0]}:{t.event_name}"), md(t.effect), md(t.principal or ""),
                        md(t.error_code or "ok"), "yes" if t.in_scope else "no"] for t in cov.tampering])
        if cov.tampering_total > len(cov.tampering):
            out.append(f"\n{cov.tampering_total - len(cov.tampering)} more are counted in scope.json but not listed.")
    return [*out, ""]


def _timeline(tl: Timeline) -> list[str]:
    out = ["## Timeline", "", "All times UTC. *Found by*: a seed matched the indicators; *followed* acted as something the "
           "attacker obtained.", ""]
    rows = []
    for e in tl.entries:
        if e.kind == "gap":
            rows.append([md(e.time), "", f"**gap until {md(e.end)}**", md(e.note or "", 400), "", "", ""])
            continue
        found = "seed" if e.origin == "seed" and not e.via else ("followed" if e.origin == "propagated" else "seed, followed")
        rows.append([md(e.time), md(e.actor), md(e.action), md("; ".join(e.targets), 300), md(e.outcome),
                     md(e.tactic), f"{found} ({e.confidence.value if e.confidence else ''})"])
    return [*out, *_table(["Time", "Actor", "Action", "Target", "Result", "Tactic", "Found by"], rows), ""]


def _exposure(tl: Timeline) -> list[str]:
    x = tl.exposure
    out = ["## Exposure", ""]
    out += [f"- {md(n, 400)}" for n in x.notes]
    if x.privilege_changes:
        out = _gap(out) + ["Permission changes:", ""]
        out += _table(["Time", "Change", "Principal", "Policy", "Full control", "Result"],
                      [[md(p.time), md(p.action), md(p.principal), md(p.policy or ""), "**yes**" if p.admin else "no", md(p.outcome)]
                       for p in x.privilege_changes])
    if x.resources:
        out = _gap(out) + ["Resources touched:", ""]
        out += _table(["Service", "Type", "Name", "Access", "Calls", "Refused", "Actions"],
                      [[md(r.service), md(r.type), md(r.name, 300), r.access, str(r.events), str(r.failed), md(", ".join(r.actions), 300)]
                       for r in x.resources])
    if len(out) == 2:
        out.append("No resources were named in the in-scope calls.")
    return [*out, ""]


def _plan(plan: Plan) -> list[str]:
    out = ["## Response plan", ""] + [f"- {md(n, 400)}" for n in plan.notes] + [""]
    for phase in PHASES:
        actions = [a for a in plan.actions if a.phase == phase]
        if not actions:
            continue
        out += [f"### {_PHASE_TITLES[phase]}", ""]
        for a in actions:
            weak = " *(weak evidence: confirm first)*" if a.confidence.value == "weak" else ""
            runs = ("`controlzee respond` can do this, with --allow-disruptive" if a.disruptive else
                    "`controlzee respond` can do this") if a.operations else "manual"
            out += [f"**{a.id}. {md(a.title)}**: {md(a.target, 300)}{weak}", "", f"{md(a.why, 600)}. *({runs})*"]
            if a.caution:
                out += ["", f"Caution: {md(a.caution, 600)}."]
            if a.commands:
                out += ["", *_fence(a.commands)]
            if a.evidence:
                out += ["", f"Evidence: {', '.join(md(e) for e in a.evidence)}"]
            out.append("")
    return out


def _appendix(scope: Scope) -> list[str]:
    out = ["## Appendix", "", "Indicators:", ""]
    out += _table(["Name", "Kind", "Value", "Match"],
                  [[md(i.name), i.kind.value, md(i.value, 300), i.match] for i in scope.seeds.indicators])
    out += ["", f"Expression: {md(scope.seeds.expression, 600)}"]
    if scope.seeds.window:
        out.append(f"Window: {md(scope.seeds.window.start or 'open')} to {md(scope.seeds.window.end or 'open')}")
    if scope.taint.identities:
        out += ["", "Followed identities:", ""]
        out += _table(["Kind", "Value", "Issued by", "At", "Events", "Confidence"],
                      [[t.kind, md(t.value), md(t.rule), md(t.issued_at), str(t.events), t.confidence.value] for t in scope.taint.identities])
    i = scope.inputs
    out += ["", f"Inputs: {i.event_count} events from {i.ingested_files} files ({i.error_files} unreadable, {i.skipped_files} skipped), "
            f"{i.first_event_time and md(i.first_event_time)} to {i.last_event_time and md(i.last_event_time)}; "
            f"accounts {', '.join(md(a) for a in i.accounts)}; manifest sha256 {i.manifest_sha256}.", ""]
    return out


def build_report(scope: Scope) -> bytes:
    tl = Timeline.model_validate(build_timeline(scope))
    plan = Plan.model_validate(build_plan(scope))
    lines = ["# Incident report", "",
             f"Generated by controlzee {__version__} from scope {scope.scope_sha256} (timeline {tl.timeline_sha256}, "
             f"plan {plan.plan_sha256}). Everything here is derived from that scope.json; regenerate it rather than editing it.", ""]
    for part in (_summary(scope, tl), _coverage(scope), _timeline(tl), _exposure(tl), _plan(plan), _appendix(scope)):
        lines += part
    return ("\n".join(lines).rstrip("\n") + "\n").encode("utf-8")
