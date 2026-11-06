"""The page built around the response plan: its order, the numbered arrows, the phase bar, and the links between plan and graph."""
import re

from controlzee._html_static import CSS, JS
from controlzee.diagrams import COL_GAP, MIN_W, NODE_W, PAD, WIDE
from controlzee.html_report import build_html
from tests.unit.test_captured import load
from tests.unit.test_html_report import check_inert
from tests.unit.test_respond import scope_of

ORDER = ["glance", "path", "sequence", "swimlanes", "plan", "identities", "coverage", "exposure", "calls", "appendix"]


def sections(page: str) -> list[str]:
    return re.findall(r'<section id="([\w-]+)">', page)


def test_the_sections_come_in_the_order_of_a_case_file(fixtures):
    assert sections(build_html(scope_of(fixtures, "02_role_chain")).decode()) == ORDER


def test_the_header_then_what_to_do_first_then_the_picture_of_the_attack(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    assert page.index('<dl class="case">') < page.index('class="dofirst"') < page.index('class="callout"') < page.index('<section id="path">')
    assert "Do first" in page and "Revoke the role&#x27;s active sessions" in page.split('class="dofirst"')[1].split("</div>")[0]


def test_every_section_that_is_present_keeps_its_place_when_others_are_left_out(fixtures):
    got = sections(build_html(scope_of(fixtures, "04_log_tampering")).decode())  # no graph, no sequence log needed
    assert [s for s in ORDER if s in got] == got and "plan" in got and got.index("plan") < got.index("identities") < got.index("calls")


# ---- the graph

def test_the_graph_is_drawn_at_a_size_whose_text_can_be_read_without_zooming():
    for rule in (r"\.node \.name\{[^}]*font-size:(\d+(?:\.\d+)?)px", r"\.node \.sub\{[^}]*font-size:(\d+(?:\.\d+)?)px",
                 r"\.rc text\{[^}]*font-size:(\d+(?:\.\d+)?)px", r"\.rc-more\{font-size:(\d+(?:\.\d+)?)px", r"\.eb text\{font:\d+ (\d+(?:\.\d+)?)px"):
        assert float(re.search(rule, CSS).group(1)) >= 12, rule


def test_a_graph_of_four_columns_fits_the_box_without_being_shrunk_much(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    width = int(re.search(r'<svg class="graph[^"]*" width="(\d+)"', page).group(1))
    assert width == 4 * NODE_W + 3 * COL_GAP + 2 * PAD <= WIDE and width >= MIN_W
    assert 1240 / width >= 0.9  # the box at a 1280 pixel window: the text is drawn at 90 % of its size or more
    assert 'class="graph wide"' not in page


def test_a_small_graph_is_centred_on_a_canvas_of_the_minimum_width(fixtures):
    page = build_html(scope_of(fixtures, "01_leaked_key")).decode()
    assert int(re.search(r'<svg class="graph[^"]*" width="(\d+)"', page).group(1)) == MIN_W


def test_the_graph_box_is_as_wide_as_the_window_allows_and_resizes_vertically_only():
    assert "width:min(1320px,calc(100vw - 40px))" in CSS and "resize:vertical" in CSS and "resize:both" not in CSS


# ---- numbered arrows

def numbers(page: str) -> tuple[list[int], list[int], list[int]]:
    badges = [int(n) for n in re.findall(r'<g class="eb"><title>Step \d+[^<]*</title><circle[^>]*/><text[^>]*>(\d+)</text>', page)]
    listed = [int(n) for n in re.findall(r'<li><span class="no">(\d+)</span>', page.split('class="arrows"')[1].split("</ul>")[0])]
    log = [int(n) for n in re.findall(r'class="ev-n" aria-hidden="true">(\d+)<', page)]
    return badges, listed, log


def test_the_numbers_on_the_arrows_are_the_numbers_of_the_steps_in_the_sequence(fixtures):
    for name in ("02_role_chain", "03_instance_role", "06_lambda"):
        badges, listed, log = numbers(build_html(scope_of(fixtures, name)).decode())
        assert badges and sorted(badges) == sorted(listed) and set(badges) <= set(log), name


def test_an_arrow_that_is_not_a_step_of_the_sequence_is_a_dot_and_a_dash_in_the_list(fixtures):
    page = build_html(scope_of(fixtures, "05_weak_ioc")).decode()  # too few moments for a sequence: nothing to number
    assert 'id="sequence"' not in page and 'class="eb none"' in page and '<span class="no">&ndash;</span>' in page


def test_the_list_under_the_picture_says_what_each_arrow_is(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    lst = page.split('class="arrows"')[1].split("</ul>")[0]
    assert "CreateRole" in lst and "from" in lst and "to" in lst and "444455556666" in lst and "(no logs)" in lst


# ---- plan and graph

def test_a_step_about_an_identity_and_that_identity_point_at_each_other(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    check_inert(page.encode())
    step = re.search(r'<article class="step" id="step-A03"[^>]*data-nodes="([^"]+)"', page)
    assert step and 'data-node="identity-1"' in page and "identity-1" in step.group(1).split()
    node = re.search(r'<g class="node[^"]*" data-target="identity-1" data-node="identity-1"[^>]*data-steps="([^"]+)"', page)
    assert node and "A03" in node.group(1).split()


def test_a_manual_step_that_names_no_identity_links_to_nothing(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    assert re.search(r'<article class="step" id="step-A05" data-phase="investigate">', page)  # no data-nodes


def test_every_link_between_plan_and_graph_points_at_something(fixtures):
    for name in ("02_role_chain", "03_instance_role", "06_lambda"):
        page = build_html(scope_of(fixtures, name)).decode()
        nodes = set(re.findall(r'data-node="([^"]+)"', page))
        steps = set(re.findall(r'<article class="step" id="step-(\w+)"', page))
        for ids in re.findall(r'data-nodes="([^"]+)"', page):
            assert set(ids.split()) <= nodes | set(re.findall(r'<details id="(identity-\d+)"', page)), name
        for ids in re.findall(r'data-steps="([^"]+)"', page):
            assert set(ids.split()) <= steps, name


def test_the_link_is_also_a_plain_link_for_a_reader_without_scripts(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    assert re.search(r'<p class="concerns">About the identity <a href="#identity-1">', page)


# ---- the phase bar

def test_the_phase_bar_names_the_phases_in_order_and_each_link_goes_to_its_phase(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    bar = re.search(r'<nav class="phasebar".*?</nav>', page, re.S).group(0)
    assert re.findall(r'data-phase="(\w+)"', bar) == ["contain", "investigate", "eradicate", "recover"]
    assert "4 steps" in bar and "2 steps" in bar and "3 steps" in bar
    check_inert(page.encode())  # every href is an id on the page, including #phase-...


def test_a_phase_without_steps_is_not_in_the_bar(fixtures):
    bar = re.search(r'<nav class="phasebar".*?</nav>', build_html(scope_of(fixtures, "04_log_tampering")).decode(), re.S).group(0)
    assert "Eradicate" not in bar and "Contain" in bar


def test_the_phase_bar_stays_in_view_in_the_plan_and_is_not_sticky_on_paper():
    assert ".phasebar{position:sticky" in CSS and ".phasebar{position:static}" in CSS.split("@media print")[1]


def test_storage_that_is_blocked_cannot_stop_the_page():
    assert "try { if (v === undefined)" in JS and "catch (e) { return null; }" in JS
    assert "try { state = JSON.parse(store(key)" in JS and "catch (e) { state = {}; }" in JS


# ---- commands

def test_a_long_command_is_laid_out_and_the_copy_button_copies_the_same_text(fixtures):
    page = build_html(scope_of(fixtures, "01_leaked_key")).decode()
    shown = re.search(r"<pre><code>(aws iam update-access-key[^<]*)</code>", page).group(1)
    copy = re.search(r'data-copy="(aws iam update-access-key[^"]*)"', page).group(1)
    assert shown.count(" \\\n") == 3 and copy == shown.replace("\n", "&#10;")
    assert "overflow-x:auto" not in CSS.split("pre{")[1].split("}")[0]  # no sideways scroll bar on a command


def test_the_date_in_the_revoke_command_is_still_worked_out_by_the_shell_when_copied(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    copy = re.search(r'data-copy="(aws iam put-user-policy[^"]*)"', page).group(1)
    assert "&#x27;&quot;$(date -u +%Y-%m-%dT%H:%M:%SZ)&quot;&#x27;" in copy and "&#10;" in copy


def test_the_badges_of_a_step_have_an_icon_as_well_as_words(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    assert "▶</span> respond can do this" in page and "✋</span> manual" in page and "▲</span> respond can do this, with --allow-disruptive" in page


def test_the_big_captures_still_render_a_plan(fixtures):
    page = build_html(load("secretsmanager-retrieve-secrets")[0]).decode()
    assert sections(page)[:3] == ["glance", "path", "sequence"] and 'class="phasebar"' in page


def test_on_paper_the_graph_shrinks_to_the_page_the_zoom_buttons_go_and_the_box_has_no_fixed_height():
    printing = CSS.split("@media print")[1]
    assert ".g-zoom{display:none" in printing and "height:auto !important" in printing and "resize:none" in printing
    assert "width:100% !important;min-width:0 !important" in printing and ".gbox{width:auto" in printing


def test_without_a_graph_a_step_does_not_point_at_a_picture_that_is_not_there(fixtures):
    page = build_html(scope_of(fixtures, "04_log_tampering")).decode()
    assert 'class="graph' not in page and "in the picture" not in page and "data-nodes=" not in page and "Hover over or tab" not in page
    assert re.search(r'<p class="concerns">About the identity <a href="#identity-0"><code class="ident">[^<]*</code></a>\.</p>', page)  # still a link to its details
