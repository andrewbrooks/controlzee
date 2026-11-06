"""The smaller things: nav labels, the date of the calls, an identity on one line, badges."""
import re

import orjson

from controlzee._html_static import CSS
from controlzee.html_report import _who, build_html
from controlzee.scope import ScopeOptions, build_scope
from controlzee.seed.spec import SpecParts, assemble, from_flags
from tests.builders.build_fixtures import SCENARIOS
from tests.builders.cloudtrail import LogSet, at, iam_user
from tests.unit.test_html_report import audit, check_inert
from tests.unit.test_respond import scope_of


def two_day_scope(tmp_path):
    logs = LogSet()
    user = iam_user("ci", "AKIAIOSFODNN7TWODAY")
    logs.add(at("2026-10-20T23:50:00Z"), "iam.amazonaws.com", "ListUsers", user)
    logs.add(at("2026-10-21T00:10:00Z"), "iam.amazonaws.com", "ListRoles", user)
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "x.json").write_bytes(orjson.dumps({"Records": logs.records}))
    return build_scope([tmp_path / "logs"], assemble([SpecParts(from_flags(access_keys=["AKIAIOSFODNN7TWODAY"]))]), ScopeOptions(workers=1)).scope


# ---- the nav

def test_every_nav_label_is_the_heading_of_its_section(fixtures):
    for name in SCENARIOS:
        page = build_html(scope_of(fixtures, name)).decode()
        nav = re.findall(r'<nav>(.*?)</nav>', page, re.S)[0]
        links = re.findall(r'<a href="#(\w+)">([^<]*)</a>', nav)
        heads = dict(re.findall(r'<section id="(\w+)"><h2>([^<]*)</h2>', page))
        assert [i for i, _ in links] == list(heads) and all(label == heads[i] for i, label in links), name


def test_the_nav_uses_the_words_of_the_headings_not_shorter_ones(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    nav = re.findall(r'<nav>(.*?)</nav>', page, re.S)[0]
    assert "How the attacker moved" in nav and "What the logs cannot show" in nav and "Response plan" in nav and "Attack path" not in nav


def test_a_page_with_nothing_in_scope_still_has_a_matching_nav(tmp_path):
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "x.json").write_bytes(orjson.dumps({"Records": []}))
    scope = build_scope([tmp_path / "logs"], assemble([SpecParts(from_flags(access_keys=["AKIAIOSFODNN7NOTHER"]))]), ScopeOptions(workers=1)).scope
    page = build_html(scope).decode()
    assert re.findall(r'<a href="#(\w+)">([^<]*)</a>', re.findall(r"<nav>(.*?)</nav>", page, re.S)[0]) == [("glance", "At a glance"), ("coverage", "What the logs cannot show"), ("appendix", "Appendix")]


def test_the_header_keeps_the_nav_on_its_own_row_so_every_label_fits():
    assert "header.top nav{order:3;flex:1 0 100%" in CSS and "flex-wrap:wrap" in CSS


# ---- the calls table

def test_when_every_call_is_on_one_day_the_date_is_said_once_and_the_rows_show_the_time(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    table = page.split('<table id="call-table">')[1].split("</table>")[0]
    assert table.startswith("<caption>All times are UTC, on 2026-10-20.</caption>")
    rows = re.findall(r'<tr id="call-\d+"[^>]*><td class="nowrap mono">([^<]*)</td>', table)
    assert rows and all(re.fullmatch(r"\d\d:\d\d:\d\d", r) for r in rows) and "2026-10-20T" not in table.split("</caption>")[1]


def test_the_gap_rows_follow_the_same_rule(fixtures):
    table = build_html(scope_of(fixtures, "04_log_tampering")).decode().split('<table id="call-table">')[1].split("</table>")[0]
    gap = re.search(r'<tr class="gap"><td class="nowrap">([^<]*)</td><td colspan="6">gap until ([^:]*(?::\d\d){2}):', table)
    assert gap and re.fullmatch(r"\d\d:\d\d:\d\d", gap.group(1)) and re.fullmatch(r"\d\d:\d\d:\d\d", gap.group(2))


def test_calls_over_more_than_one_day_keep_the_whole_time_in_every_row(tmp_path):
    page = build_html(two_day_scope(tmp_path)).decode()
    table = page.split('<table id="call-table">')[1].split("</table>")[0]
    assert table.startswith("<caption>All times are UTC.</caption>")
    assert "2026-10-20T23:50:00Z" in table and "2026-10-21T00:10:00Z" in table


def test_the_caption_is_allowed_on_purpose_and_the_page_stays_inert(fixtures):
    a = check_inert(build_html(scope_of(fixtures, "02_role_chain")))
    assert "caption" in a.tags


# ---- an identity on one line

LONG = "assumed-role/stratus-red-team-ec2-steal-creds-5807a640-role/i-05b3deccffd26d672"


def test_a_long_identity_is_cut_in_the_middle_and_whole_in_the_tooltip():
    out = _who(LONG)
    assert 'title="' + LONG + '"' in out and "\u2026" in out
    shown = re.search(r">([^<]*)</span>$", out).group(1)
    assert len(shown) == 34 and shown.startswith("assumed-role/stratu") and shown.endswith("d672")


def test_a_short_identity_is_left_whole():
    assert _who("user/jenkins") == '<span class="who" title="user/jenkins">user/jenkins</span>'


def test_the_identity_column_is_monospace_wide_and_never_wraps():
    assert "td.actor,.who{white-space:nowrap}" in CSS and "#call-table{table-layout:fixed}" in CSS
    widths = [int(w) for w in re.findall(r"#call-table th:nth-child\(\d\)\{width:(\d+)%\}", CSS)]
    assert len(widths) == 7 and sum(widths) == 100  # the columns share the width of the box, so nothing is pushed off to a scroll bar


def test_the_calls_table_and_the_evidence_use_the_same_one_line_identity(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    assert page.count('<span class="who"') >= 12 and 'class="mono actor"' in page


def test_a_hostile_identity_cannot_break_out_of_its_tooltip_or_the_cell():
    for evil in ('"><script>alert(1)</script>', "' onmouseover='alert(1)", "<img src=x onerror=alert(1)>", "A" * 5000):
        out = _who(evil)
        parsed = audit(f"<table><tr><td>{out}</td></tr></table>".encode())
        assert set(parsed.tags) <= {"table", "tr", "td", "span"}
        assert [k for _, k, _ in parsed.attrs if k not in ("class", "title")] == [] and len(out) < 1000


# ---- the badges

def test_the_three_kinds_of_badge_differ_in_fill_border_and_icon(fixtures):
    assert ".badge.run{border-color:var(--accent);color:var(--accent);background:var(--accent-soft)}" in CSS
    assert "background:var(--attn-soft);font-weight:600" in CSS and ".badge:not(.run):not(.danger){border-style:dashed" in CSS
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    for icon, words in (("\u25b6", "respond can do this"), ("\u25b2", "respond can do this, with --allow-disruptive"), ("\u270b", "manual")):
        assert f'<span aria-hidden="true">{icon}</span> {words}' in page
