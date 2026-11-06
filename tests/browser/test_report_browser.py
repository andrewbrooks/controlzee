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
