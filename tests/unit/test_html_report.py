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
from tests.unit.test_captured import load
from tests.unit.test_derived import EVIL
from tests.unit.test_respond import scope_of

runner = CliRunner(env={"COLUMNS": "400"})

TAGS = {"html", "head", "meta", "title", "style", "script", "body", "header", "nav", "main", "section", "article", "footer", "h1", "h2", "h3",
        "p", "div", "span", "a", "button", "input", "ul", "ol", "li", "table", "thead", "tbody", "tr", "th", "td", "details", "summary", "pre",
        "code", "strong", "i", "progress", "svg", "g", "rect", "path", "text", "defs", "marker", "line", "circle", "dl", "dt", "dd", "caption"}
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
    for section in ("glance", "path", "sequence", "swimlanes", "identities", "coverage", "calls", "exposure", "plan", "appendix"):
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
    logs.add(at("2026-10-20T12:07:00Z"), "iam.amazonaws.com", "AttachUserPolicy", iam_user(EVIL, "AKIAIOSFODNN7HOSTL2"),
             request={"userName": EVIL, "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
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


# ---- the case header

def _case(page: bytes) -> dict[str, str]:
    """The header's terms and their text, tags removed."""
    block = re.search(r'<dl class="case">(.*?)</dl>', page.decode(), re.S).group(1)
    return {k: re.sub(r"<[^>]+>", "", v).strip() for k, v in re.findall(r"<dt>(.*?)</dt><dd>(.*?)</dd>", block, re.S)}


def test_the_case_header_has_the_window_accounts_identities_events_and_plan(fixtures):
    got = _case(build_html(scope_of(fixtures, "02_role_chain")))
    assert list(got) == ["Incident window", "Accounts", "Identities", "Events in scope", "Plan steps"]
    assert got["Incident window"].startswith("2026-10-20, 10:00:00 to 13:02:00 UTC") and "3 h 02 min" in got["Incident window"]
    assert got["Events in scope"].startswith("12") and "12 strong, 0 weak" in got["Events in scope"] and "8 can be run by respond" in got["Plan steps"]


def test_an_account_reached_without_logs_is_flagged_beside_its_number_not_as_a_card(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain"))
    assert "444455556666 \u25b2 no logs from it" in _case(page)["Accounts"] and b'class="card' not in page
    assert "no logs from it" not in _case(build_html(scope_of(fixtures, "01_leaked_key")))["Accounts"]


def test_the_case_header_links_to_the_sections_behind_its_figures(fixtures):
    page = build_html(scope_of(fixtures, "01_leaked_key"))
    a = check_inert(page)  # every href is an id on the page
    for target in ("identities", "calls", "plan"):
        assert f'<a href="#{target}">' in page.decode() and target in a.ids


def test_the_figures_of_the_header_are_not_shown_twice_as_alert_cards(fixtures):
    page = build_html(scope_of(fixtures, "01_leaked_key")).decode()
    assert "full control granted" not in page and "Full administrative access was granted" in page  # what stands out is said once, in words


# ---- the tactics used

def test_the_kill_chain_lists_the_tactics_in_attack_order_with_the_used_ones_filled(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    strip = re.search(r'<svg class="killchain".*?</svg>', page, re.S).group(0)
    names = re.findall(r'<g class="kc (kc-hit [\w-]+|kc-miss)"><title>([\w-]+):', strip)
    assert [n for _, n in names] == ["initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access",
                                     "discovery", "lateral-movement", "collection", "exfiltration", "impact"]
    assert [n for c, n in names if c.startswith("kc-hit")] == ["persistence", "privilege-escalation", "credential-access", "discovery", "lateral-movement"]
    assert 'class="tactic-bar"' not in page and 'class="chips"' not in page.split('id="calls"')[0]


def test_the_kill_chain_says_so_when_calls_are_in_no_tactic(fixtures):
    page = build_html(load("ec2-steal-instance-credentials")[0]).decode()
    assert "calls are not in any of these tactics" in page


def test_the_kill_chain_is_left_out_when_no_call_has_a_tactic():
    from controlzee.diagrams import killchain_svg
    from controlzee.model.timeline import Timeline
    tl = Timeline.model_construct(tactics=[])
    assert killchain_svg(tl) == ""


# ---- the timeline

def test_each_tactic_has_its_own_shape_and_the_shapes_are_all_different():
    from controlzee.classify import TACTIC_ORDER
    from controlzee.diagrams import marker_path
    paths = [marker_path(t) for t in TACTIC_ORDER]
    assert len(set(paths)) == len(TACTIC_ORDER)


def test_a_failed_call_is_a_hollow_mark_and_a_followed_call_an_outlined_one(fixtures):
    page = build_html(scope_of(fixtures, "01_leaked_key")).decode()
    assert re.search(r'<g class="dot t-[\w-]+ prop[^"]*"', page) and "fail" in re.sub(r"\s", "", CSS) and ".dot.fail .body{fill:var(--card)" in CSS


def test_the_legend_shows_the_shape_of_each_tactic_in_the_timeline(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    legend = page.split('<div class="legend">')[1].split("</div>")[0]
    assert legend.count('<svg class="mk') == 5 and 'role="img"' in legend


def test_a_long_silence_is_cut_short_and_labelled_with_its_length(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    assert re.search(r'<g class="brk"><title>2 h 40 min, no activity', page) and "2 h 40 min, no activity" in page.split('class="brk-lab"')[1]
    assert 'data-breaks="' in page


def test_a_silence_the_logs_confirm_says_logs_silent(fixtures):
    page = build_html(scope_of(fixtures, "04_log_tampering")).decode()
    assert "logs silent" in page.split('class="brk-lab"')[1] and "no activity" not in page.split('class="brk-lab"')[1].split("</g>")[0]


def test_short_incidents_and_short_pauses_are_not_cut(fixtures):
    for name in ("01_leaked_key", "05_weak_ioc", "06_lambda"):  # a 5 min pause in a 10 min incident is half of it, but under the 15 min floor
        assert 'class="brk"' not in build_html(scope_of(fixtures, name)).decode(), name
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    assert page.count('class="brk"') == 1  # the 15 minute pause in the same incident is 8 % of it: under the share


def test_the_threshold_is_a_floor_and_a_share():
    from controlzee.diagrams import BREAK_MIN_US, BREAK_SHARE, _breaks
    minute = 60_000_000
    assert 15 * minute == BREAK_MIN_US and BREAK_SHARE == 0.20
    assert _breaks([0, 14 * minute, 20 * minute], 20 * minute) == []                 # 14 min: under the floor
    assert _breaks([m * minute for m in (0, 15, 30, 45, 60, 75, 90, 100)], 100 * minute) == []  # 15 min, but 15 % of the incident: under the share
    assert _breaks([m * minute for m in (0, 20, 30, 40, 50, 60, 100)], 100 * minute) == [(0, 20 * minute), (60 * minute, 100 * minute)]
    assert _breaks([0, 80 * minute, 82 * minute], 82 * minute) == [(0, 80 * minute)]


def test_the_marks_after_a_cut_sit_after_it_and_the_axis_is_the_length_it_is_drawn(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    span = int(re.search(r'data-span="(\d+)"', page).group(1))
    real = int(re.search(r'data-real="(\d+)"', page).group(1))
    cut = [int(x) for x in re.search(r'data-breaks="(\d+),(\d+),(\d+)"', page).groups()]
    assert real == 182 * 60_000_000 and cut[2] == 160 * 60_000_000 and span < real
    marks = [int(t) for t in re.findall(r'<g class="dot [^"]*" data-t="(\d+)"', page)]
    assert max(marks) <= span and sorted(marks)[-1] > cut[0] + cut[1] - 1  # the last marks come after the cut


# ---- the graph box

def test_the_graph_can_be_resized_vertically_only_and_zoomed(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    assert '<div class="gwrap">' in page and page.count('data-gzoom=') == 3
    assert "resize:vertical" in CSS and "resize:both" not in CSS and "resize:horizontal" not in CSS
    assert ".g-zoom{display:none}.js .g-zoom{display:flex" in CSS  # the buttons wait for the script: nothing dead without it


def test_zoom_changes_the_width_attribute_not_a_style():
    assert "setAttribute('width'" in JS and ".style" not in JS and "setAttribute('style'" not in JS
