"""The HTML report in a real browser (dev only: skipped when Playwright or its browser is not installed).

Checks what the unit tests cannot: the script runs without errors, and the page still has its sections and
working in-page links with JavaScript switched off.
"""
import pytest

from tests.builders.build_fixtures import SCENARIOS
from tests.unit.test_respond import scope_of

sync_api = pytest.importorskip("playwright.sync_api")
from controlzee.html_report import build_html  # noqa: E402


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except sync_api.Error as e:  # browser or its system libraries are missing
            pytest.skip(f"no browser: {str(e).splitlines()[0]}")
        yield b
        b.close()


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("js", [True, False])
def test_page_works_with_and_without_script(browser, fixtures, tmp_path, scenario, js):
    page_file = tmp_path / "report.html"
    page_file.write_bytes(build_html(scope_of(fixtures, scenario)))
    ctx = browser.new_context(color_scheme="light", java_script_enabled=js)
    page = ctx.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.goto(page_file.as_uri())
    assert page.locator("section#glance").is_visible()
    hrefs = page.eval_on_selector_all("a[href^='#']", "els => els.map(e => e.getAttribute('href').slice(1))") if js else \
        [h[1:] for h in __import__("re").findall(r'href="(#[\w-]+)"', page.content())]
    assert all(page.locator(f"[id='{h}']").count() == 1 for h in hrefs)
    assert errors == []
    ctx.close()


def test_a_click_on_a_moment_opens_and_highlights_its_row_in_the_calls(browser, fixtures, tmp_path):
    page_file = tmp_path / "report.html"
    page_file.write_bytes(build_html(scope_of(fixtures, "01_leaked_key")))
    page = browser.new_context().new_page()
    page.goto(page_file.as_uri())
    link = page.locator(".log a").last
    row_id = link.get_attribute("href")[1:]
    link.click()
    row = page.locator(f"tr[id='{row_id}']")
    assert row.is_visible()
    page.wait_for_selector(f"tr[id='{row_id}'].hit")


def test_the_graph_resizes_vertically_only_and_zooms(browser, fixtures, tmp_path):
    page_file = tmp_path / "report.html"
    page_file.write_bytes(build_html(scope_of(fixtures, "02_role_chain")))
    page = browser.new_context(viewport={"width": 1280, "height": 900}).new_page()
    page.goto(page_file.as_uri())
    assert page.eval_on_selector(".gwrap", "e => getComputedStyle(e).resize") == "vertical"
    before = page.eval_on_selector("svg.graph", "e => e.getBoundingClientRect().width")
    page.click("[data-gzoom=in]")
    after = page.eval_on_selector("svg.graph", "e => e.getBoundingClientRect().width")
    assert after > before
    page.click("[data-gzoom=reset]")
    assert abs(page.eval_on_selector("svg.graph", "e => e.getBoundingClientRect().width") - before) < 2
    assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")


def test_a_cut_axis_still_zooms_and_names_times(browser, fixtures, tmp_path):
    page_file = tmp_path / "report.html"
    page_file.write_bytes(build_html(scope_of(fixtures, "02_role_chain")))
    page = browser.new_context(viewport={"width": 1280, "height": 900}).new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(page_file.as_uri())
    page.click("[data-zoom=in]")
    page.click("[data-zoom=in]")
    labels = page.eval_on_selector_all("svg.timeline .tick-label", "els => els.map(e => e.textContent)")
    assert labels and all(":" in x for x in labels) and errors == []


def _open(browser, fixtures, tmp_path, scenario="02_role_chain", **context):
    page_file = tmp_path / "report.html"
    page_file.write_bytes(build_html(scope_of(fixtures, scenario)))
    page = browser.new_context(viewport={"width": 1280, "height": 900}, **context).new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(page_file.as_uri())
    return page, errors


def test_hovering_a_step_outlines_its_identity_in_the_graph_and_the_other_way_round(browser, fixtures, tmp_path):
    page, errors = _open(browser, fixtures, tmp_path)
    page.hover("#step-A03")
    assert page.locator(".node.hl").count() == 1 and page.locator(".node.hl").get_attribute("data-node") == "identity-1"
    page.hover("#path h2")
    assert page.locator(".node.hl").count() == 0 and page.locator(".step.hl").count() == 0
    page.locator(".node[data-node=identity-1]").dispatch_event("mouseenter")
    assert {e.get_attribute("id") for e in page.locator(".step.hl").all()} == {"step-A03", "step-A10"}  # both steps that name the role
    assert errors == []


def test_keyboard_focus_on_a_step_does_the_same_as_hovering(browser, fixtures, tmp_path):
    page, _ = _open(browser, fixtures, tmp_path)
    page.focus("#step-A03 input")
    assert page.locator(".node.hl").count() == 1
    page.focus("#step-A01 input")
    assert page.locator(".node.hl").get_attribute("data-node") == "identity-0"


def test_ticking_steps_moves_the_phase_bar_and_is_remembered(browser, fixtures, tmp_path):
    page, _ = _open(browser, fixtures, tmp_path)
    assert "0 of 4 done" in page.inner_text(".phasebar a[data-phase=contain]")
    page.check("#step-A01 input")
    page.check("#step-A02 input")
    assert "2 of 4 done" in page.inner_text(".phasebar a[data-phase=contain]") and page.eval_on_selector("#progress", "e => e.value") == 2
    page.reload()
    assert page.is_checked("#step-A01 input") and "2 of 4 done" in page.inner_text(".phasebar a[data-phase=contain]")


def test_the_phase_bar_stays_in_view_and_a_click_goes_to_its_phase(browser, fixtures, tmp_path):
    page, _ = _open(browser, fixtures, tmp_path)
    page.click("header.top nav a[href='#plan']")
    page.mouse.wheel(0, 700)
    page.wait_for_timeout(200)
    top = page.eval_on_selector(".phasebar", "e => e.getBoundingClientRect().top")
    assert 0 <= top <= 120
    page.click(".phasebar a[data-phase=eradicate]")
    page.wait_for_timeout(300)
    assert 0 <= page.eval_on_selector("#phase-eradicate", "e => e.getBoundingClientRect().top") < 300


def test_the_page_works_when_storage_is_blocked(browser, fixtures, tmp_path):
    page_file = tmp_path / "report.html"
    page_file.write_bytes(build_html(scope_of(fixtures, "02_role_chain")))
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    ctx.add_init_script("""const boom = () => { throw new DOMException('blocked', 'SecurityError'); };
        Object.defineProperty(window, 'localStorage', { get: boom });""")
    page = ctx.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(page_file.as_uri())
    page.check("#step-A01 input")
    assert page.is_checked("#step-A01 input") and "1 of 4 done" in page.inner_text(".phasebar a[data-phase=contain]") and errors == []


def test_a_graph_of_four_columns_has_no_sideways_scroll_in_its_box_at_two_window_widths(browser, fixtures, tmp_path):
    for width in (1280, 1568):
        page_file = tmp_path / "report.html"
        page_file.write_bytes(build_html(scope_of(fixtures, "02_role_chain")))
        page = browser.new_context(viewport={"width": width, "height": 900}).new_page()
        page.goto(page_file.as_uri())
        assert page.eval_on_selector(".gwrap", "e => e.scrollWidth <= e.clientWidth + 1")
        assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        size = page.eval_on_selector(".node .name", "e => parseFloat(getComputedStyle(e).fontSize) * e.getScreenCTM().a")
        assert size >= 12, (width, size)  # the node names are drawn at 12 pixels or more
