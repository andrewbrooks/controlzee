"""Write the demo site that GitHub Pages serves: `uv run python -m tests.builders.build_demo [--check]`.

`docs/index.html` is a landing page with a card for each example incident, and `docs/examples/<name>.html` is the HTML report of
each, built from the committed logs of that scenario (made-up fixtures, and sanitized captures of real CloudTrail). Nothing here is
hand-edited: --check rebuilds in memory and fails if the committed files differ (the test suite runs it too).
"""
from __future__ import annotations

import base64
import hashlib
import html
import sys
from dataclasses import dataclass
from pathlib import Path

from controlzee.html_report import build_html
from controlzee.scope import ScopeOptions, build_scope
from controlzee.seed.spec import assemble, load_iocs_file

TESTS = Path(__file__).resolve().parents[1]
DOCS = TESTS.parent / "docs"
REPO = "https://github.com/andrewbrooks/controlzee"


@dataclass(frozen=True)
class Example:
    name: str  # the scenario's folder, and the report's file name
    source: str  # "fixtures": made-up logs; "captured": sanitized real CloudTrail
    title: str
    story: str
    look_at: tuple[str, ...]


EXAMPLES = (
    Example("02_role_chain", "fixtures", "A chain of roles",
            "A key assumes a role, that role creates a second one, and then a role is assumed in an account whose logs are not in the inputs.",
            ("The graph draws the account with no logs as a dotted box, so the chain does not seem to end where the logs do.",
             "The timeline cuts a 2 h 40 min pause short and labels it.",
             "In the plan, hover over step A03: the role it revokes is outlined in the graph.")),
    Example("04_log_tampering", "fixtures", "Logging switched off",
            "A leaked key stops CloudTrail, deletes a GuardDuty detector and stops AWS Config, and then the logs go quiet.",
            ("Three logging changes are marked on the timeline, and the cut axis says the logs were silent for 2 h 27 min.",
             "The plan turns the trail and AWS Config back on.",
             "There is only one identity and nothing was issued, so there is no graph: a picture that would add nothing is left out.")),
    Example("03_instance_role", "fixtures", "An instance and its role",
            "A user launches an instance and creates a new user; the instance's role then reads a secret.",
            ("The secret read is starred in the graph and is one step in the sequence of events.",
             "Two long pauses are cut from the timeline.")),
    Example("05_weak_ioc", "fixtures", "Weak evidence",
            "All that is known is a shared NAT address and the user agent curl. Both are weak, so the search is limited to a one-hour window.",
            ("Every event is marked weak, and the report says to confirm them before acting.",)),
    Example("ec2-steal-instance-credentials", "captured", "Stolen instance credentials",
            "An attacker creates a role and launches an instance, then uses the instance's role credentials from another address.",
            ("Over 200 calls come down to a handful of steps in the sequence of events.",
             "The credentials used from another address are flagged as needing attention.",
             "The plan cuts the instance off from its role, stops it and terminates it.")),
    Example("secretsmanager-retrieve-secrets", "captured", "Twenty secrets read",
            "An attacker lists and reads 20 secrets in under a minute.",
            ("The reads are grouped into one step in the sequence of events instead of 60 rows.",
             "What stands out says to treat the values as known to the attacker, and the plan rotates the secrets.")),
)

_CSS = """
:root{color-scheme:light;--paper:#FAF8F4;--card:#fff;--ink:#1B1A17;--mut:#57524A;--line:#DDD6C8;--accent:#0F5C63;--accent-soft:#E2EEEE;
--serif:Charter,"Bitstream Charter","Sitka Text",Cambria,Georgia,serif;--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 var(--sans)}
main{max-width:1040px;margin:0 auto;padding:36px 20px 64px}
h1{font:700 32px/1.2 var(--serif);margin:0 0 6px}h1 span{color:var(--accent)}h2{font:700 19px/1.3 var(--serif);margin:0 0 6px}
.lede{color:var(--mut);max-width:740px;margin:0 0 26px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px 18px;display:flex;flex-direction:column;box-shadow:0 1px 2px rgba(27,26,23,.07)}
.tag{display:inline-block;align-self:flex-start;margin:0 0 8px;padding:1px 9px;border:1px solid var(--line);border-radius:999px;font-size:12px;color:var(--mut)}
.tag.real{border-color:var(--accent);color:var(--accent);background:var(--accent-soft)}
.card p{margin:0 0 10px;color:var(--mut)}.look{font-size:11.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);margin:6px 0 2px}
.card ul{margin:2px 0 14px;padding-left:18px;color:var(--mut);font-size:14px}.card li{margin:2px 0}
a.open{margin-top:auto;align-self:flex-start;padding:6px 14px;border:1px solid var(--accent);border-radius:6px;color:var(--accent);font-weight:600;text-decoration:none}
a.open:hover{background:var(--accent-soft)}a{color:var(--accent)}a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.note{color:var(--mut);font-size:13px;margin-top:28px;max-width:780px}
"""


def _hash(text: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def _card(e: Example) -> str:
    real = e.source == "captured"
    tag = '<span class="tag real">Real CloudTrail, sanitized</span>' if real else '<span class="tag">Made-up logs</span>'
    items = "".join(f"<li>{html.escape(x)}</li>" for x in e.look_at)
    return (f'<article class="card">{tag}<h2>{html.escape(e.title)}</h2><p>{html.escape(e.story)}</p><div class="look">Look at</div>'
            f'<ul>{items}</ul><a class="open" href="examples/{e.name}.html">Open the report</a></article>')


def landing() -> bytes:
    csp = f"default-src 'none'; style-src '{_hash(_CSS)}'; base-uri 'none'; form-action 'none'"
    made, real = sum(e.source == "fixtures" for e in EXAMPLES), sum(e.source == "captured" for e in EXAMPLES)
    page = (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{csp}">\n<title>controlzee: example reports</title>\n<style>{_CSS}</style></head>\n'
        '<body><main><h1>control<span>zee</span>: example reports</h1>\n'
        '<p class="lede">controlzee turns CloudTrail logs and what you know about an attacker into a scope, a timeline and a response plan. '
        f'These are the HTML reports it produced for {len(EXAMPLES)} example incidents. Each is one self-contained file that makes no external requests. '
        f'{made} use made-up logs; {real} are sanitized copies of real CloudTrail from '
        '<a href="https://github.com/DataDog/stratus-red-team">Stratus Red Team</a> runs in a sandbox account. Start with the first one.</p>\n'
        f'<div class="grid">{"".join(_card(e) for e in EXAMPLES)}</div>\n'
        '<p class="note">The reports are read-only: they say what the logs show, and what a response could look like. Nothing here touches an AWS account. '
        'A report prints, and it works with scripts switched off. '
        f'Source and documentation: <a href="{REPO}">{REPO}</a>.</p>\n</main></body></html>\n')
    return page.encode("utf-8")


def report(e: Example) -> bytes:
    root = TESTS / e.source / e.name
    scope = build_scope([root / "logs"], assemble([load_iocs_file(root / "iocs.yaml")]), ScopeOptions(workers=1)).scope
    return build_html(scope)


def pages() -> dict[Path, bytes]:
    """Every file of the demo site, by its path under docs/."""
    out: dict[Path, bytes] = {Path("index.html"): landing()}
    for e in EXAMPLES:
        out[Path("examples") / f"{e.name}.html"] = report(e)
    return out


def main(argv: list[str]) -> int:
    built = pages()
    if "--check" in argv:
        stale = [str(p) for p, data in built.items() if not (DOCS / p).exists() or (DOCS / p).read_bytes() != data]
        extra = sorted(str(p.relative_to(DOCS)) for p in (DOCS / "examples").glob("*.html") if p.relative_to(DOCS) not in built) if (DOCS / "examples").exists() else []
        if stale or extra:
            print("demo site is out of date:", *stale, *(f"unexpected {x}" for x in extra), sep="\n  ")
            return 1
        print("demo site is up to date")
        return 0
    for p, data in built.items():
        target = DOCS / p
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    print(f"wrote {len(built)} pages under {DOCS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
