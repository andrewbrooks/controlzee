"""The standalone HTML report: self-contained, deterministic, and inert whatever the logs say."""
import base64
import hashlib
import os
import re
import subprocess
import sys
from html.parser import HTMLParser

import orjson
import pytest
from typer.testing import CliRunner

from controlzee._html_static import CSS, JS
from controlzee.cli import app
from controlzee.html_report import build_html
from controlzee.plan import build_plan
from controlzee.scope import ScopeOptions, build_scope
from controlzee.seed.spec import SpecParts, assemble, from_flags
from tests.builders.build_fixtures import SCENARIOS
from tests.builders.cloudtrail import HIDDEN, LogSet, at, iam_user
from tests.unit.test_derived import EVIL
from tests.unit.test_respond import scope_of

runner = CliRunner(env={"COLUMNS": "400"})

TAGS = {"html", "head", "meta", "title", "style", "script", "body", "header", "nav", "main", "section", "article", "footer", "h1", "h2", "h3",
        "p", "div", "span", "a", "button", "input", "ul", "ol", "li", "table", "thead", "tbody", "tr", "th", "td", "details", "summary", "pre",
        "code", "strong", "i", "progress", "svg", "g", "rect", "path", "text", "defs", "marker", "line", "circle"}
ATTRS = {"lang", "charset", "name", "content", "http-equiv", "class", "id", "href", "type", "value", "max", "checked", "placeholder", "aria-label",
         "role", "tabindex", "title", "open", "colspan", "viewbox", "d", "x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "width", "height", "rx",
         "text-anchor", "marker-end", "refx", "refy", "markerwidth", "markerheight", "orient", "preserveaspectratio", "transform"}
VOID = {"meta", "input", "path", "rect", "line", "circle"}


class Audit(HTMLParser):
    """Collects what a page contains, so a test can say what it may contain."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.attrs, self.hrefs, self.ids, self.targets, self.copies, self.scripts, self.styles = [], [], [], [], [], [], [], []
        self.stack, self._in = [], None

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for k, v in attrs:
            self.attrs.append((tag, k, v))
            if k == "href":
                self.hrefs.append(v)
            elif k == "id":
                self.ids.append(v)
            elif k == "data-target":
                self.targets.append(v)
            elif k == "data-copy":
                self.copies.append(v)
        if tag in ("script", "style"):
            self._in = tag
            (self.scripts if tag == "script" else self.styles).append("")
        if tag not in VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._in = None
        if tag not in VOID:
            assert self.stack and self.stack[-1] == tag, f"</{tag}> closes <{self.stack[-1:]}>"
            self.stack.pop()

    def handle_data(self, data):
        if self._in == "script":
            self.scripts[-1] += data
        elif self._in == "style":
            self.styles[-1] += data


def audit(page: bytes) -> Audit:
    a = Audit()
    a.feed(page.decode("utf-8"))
    a.close()
    assert a.stack == [], f"unclosed: {a.stack}"
    return a


def check_inert(page: bytes) -> Audit:
    """The rules every page must keep: only known tags and attributes, no script but ours, nothing from elsewhere."""
    a = audit(page)
    assert set(a.tags) <= TAGS, set(a.tags) - TAGS
    for tag, k, _v in a.attrs:
        assert k in ATTRS or k.startswith(("data-", "aria-")), (tag, k)
        assert not k.startswith("on") and k != "style" and k != "src", (tag, k)
    assert all(re.fullmatch(r"#[\w-]+", v) for v in a.hrefs), [v for v in a.hrefs if not re.fullmatch(r"#[\w-]+", v)]
    assert len(a.scripts) == 1 and len(a.styles) == 1 and a.scripts[0] == JS and a.styles[0] == CSS  # ours, byte for byte
    csp = next(v for t, k, v in a.attrs if t == "meta" and k == "content" and "default-src" in v)
    for kind, text in (("style-src", CSS), ("script-src", JS)):
        digest = base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()
        assert f"{kind} 'sha256-{digest}'" in csp
    assert "default-src 'none'" in csp and "unsafe" not in csp and "http" not in csp
    assert len(a.ids) == len(set(a.ids)), "duplicate ids"
    assert all(h[1:] in a.ids for h in a.hrefs), [h for h in a.hrefs if h[1:] not in a.ids]
    assert all(t in a.ids for t in a.targets)
    return a


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_every_scenario_page_is_self_contained_and_well_formed(fixtures, scenario):
    a = check_inert(build_html(scope_of(fixtures, scenario)))
    assert "svg" in a.tags and "details" in a.tags and a.tags.count("script") == 1


def test_the_page_has_what_a_responder_needs(fixtures):
    scope = scope_of(fixtures, "02_role_chain")
    page = build_html(scope).decode()
    a = check_inert(page.encode())
    for section in ("glance", "path", "swimlanes", "identities", "coverage", "calls", "exposure", "plan", "appendix"):
        assert f'<section id="{section}">' in page
    assert a.tags.count("svg") >= 3 and 'class="step"' in page and 'type="checkbox"' in page and "Expand all" in page
    assert len(a.targets) >= 2  # a node of the graph takes the reader to its identity


def test_the_evidence_ids_to_copy_are_the_full_ids_of_the_step(fixtures):
    scope = scope_of(fixtures, "01_leaked_key")
    a = check_inert(build_html(scope).decode().encode())
    plan = build_plan(scope)
    step = next(x for x in plan["actions"] if x["id"] == "A02")
    full = [c for c in a.copies if "\n" not in c and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f-]{27}", c)]
    assert all(i in full for i in step["evidence"]) and len(step["evidence"]) == 9


def test_commands_can_be_copied_whole(fixtures):
    scope = scope_of(fixtures, "01_leaked_key")
    a = check_inert(build_html(scope))
    assert any(c.startswith("aws iam update-access-key") for c in a.copies)


# ---- hostile log content

def _hostile_scope(tmp_path):
    logs = LogSet()
    attacker = iam_user("ci", "AKIAIOSFODNN7HOSTIL")
    logs.add(at("2026-10-20T12:00:00Z"), "iam.amazonaws.com", "CreateAccessKey", attacker, ua=EVIL, request={"userName": EVIL},
             response={"accessKey": {"userName": EVIL, "accessKeyId": "AKIAIOSFODNN7HOSTL2", "secretAccessKey": HIDDEN}})
    logs.add(at("2026-10-20T12:05:00Z"), "s3.amazonaws.com", "ListBuckets", iam_user(EVIL, "AKIAIOSFODNN7HOSTL2"))
    logs.add(at("2026-10-20T12:06:00Z"), "secretsmanager.amazonaws.com", "GetSecretValue", iam_user(EVIL, "AKIAIOSFODNN7HOSTL2"),
             request={"secretId": EVIL})
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "x.json").write_bytes(orjson.dumps({"Records": logs.records}))
    return build_scope([tmp_path / "logs"], assemble([SpecParts(from_flags(access_keys=["AKIAIOSFODNN7HOSTIL"]))]), ScopeOptions(workers=1)).scope


def test_hostile_names_stay_inert_everywhere_in_the_page(tmp_path):
    page = build_html(_hostile_scope(tmp_path))
    a = check_inert(page)  # no extra tag, attribute, script, link or style appeared
    text = page.decode()
    assert "&lt;img" in text and "onerror=alert(1)" in text  # shown as text, because it is data
    assert not re.search(r"<img", text) and "javascript:" not in text.replace("&#x27;", "'") or "javascript:" not in " ".join(a.hrefs)
    assert "svg" in a.tags


def test_the_static_script_does_not_build_markup_from_data():
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function", "document.write", "setTimeout('", 'setTimeout("'):
        assert bad not in JS, bad


# ---- determinism and the command

def test_same_scope_same_bytes(fixtures):
    scope = scope_of(fixtures, "03_instance_role")
    assert build_html(scope) == build_html(scope)


def test_hash_seed_does_not_change_the_page(fixtures, tmp_path):
    scope = fixtures / "02_role_chain/expected/scope.json"
    outputs = set()
    for seed in ("0", "777", "random"):
        out = tmp_path / f"{seed}.html"
        r = subprocess.run([sys.executable, "-m", "controlzee", "report", str(scope), "--format", "html", "-o", str(out)],
                           env={**os.environ, "PYTHONHASHSEED": seed}, capture_output=True, text=True, check=False)
        assert r.returncode == 0, r.stderr
        outputs.add(out.read_bytes())
    assert len(outputs) == 1


def test_the_report_command_writes_html_with_the_format_option(fixtures, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    scope = fixtures / "01_leaked_key/expected/scope.json"
    r = runner.invoke(app, ["report", str(scope), "--format", "html"])
    assert r.exit_code == 0 and "Wrote report.html" in r.stdout and (tmp_path / "report.html").read_bytes().startswith(b"<!doctype html>")
    r = runner.invoke(app, ["report", str(scope)])
    assert r.exit_code == 0 and "Wrote report.md" in r.stdout
    r = runner.invoke(app, ["report", str(scope), "--format", "pdf"])
    assert r.exit_code == 2


def test_a_scope_with_no_events_still_gives_a_page(tmp_path):
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "x.json").write_bytes(orjson.dumps({"Records": []}))
    scope = build_scope([tmp_path / "logs"], assemble([SpecParts(from_flags(access_keys=["AKIAIOSFODNN7NOTHER"]))]), ScopeOptions(workers=1)).scope
    page = build_html(scope)
    check_inert(page)
    assert b"No events matched the indicators" in page


def test_every_mark_of_the_timeline_links_to_its_row_in_the_call_table(fixtures):
    scope = scope_of(fixtures, "01_leaked_key")
    page = build_html(scope).decode()
    marks = re.findall(r'<g class="dot [^"]*" data-t="(\d+)" data-y="[\d.]+" data-target="(call-\d+)"', page)
    assert len(marks) == len(scope.events)
    rows = re.findall(r'<tr id="(call-\d+)"', page)
    assert len(set(rows)) == len(rows) and {t for _, t in marks} <= set(rows)  # check_inert also holds every data-target to an id
    check_inert(page.encode())
