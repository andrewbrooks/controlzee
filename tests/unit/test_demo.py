"""The demo report that GitHub Pages serves (docs/demo/index.html): built from a made-up scenario, and never out of step with the code."""
import re
from pathlib import Path

from typer.testing import CliRunner

from controlzee.cli import app
from tests.unit.test_html_report import check_inert

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "docs/demo/index.html"
URL = "https://andrewbrooks.github.io/controlzee/demo/"
runner = CliRunner(env={"COLUMNS": "400"})


def test_the_demo_is_exactly_what_the_report_command_builds_from_the_committed_scenario(fixtures, tmp_path, golden):
    out = tmp_path / "demo.html"
    r = runner.invoke(app, ["report", str(fixtures / "02_role_chain/expected/scope.json"), "--format", "html", "-o", str(out)])
    assert r.exit_code == 0
    golden(DEMO, out.read_bytes())  # UPDATE_GOLDENS=1 uv run pytest tests/unit/test_demo.py, then review the diff


def test_the_demo_is_a_self_contained_page_that_asks_the_network_for_nothing():
    page = DEMO.read_bytes()
    check_inert(page)
    assert set(re.findall(r"https?://[^\s\"'<)]+", page.decode())) == {"http://www.w3.org/2000/svg"}  # the SVG namespace, not a request


def test_the_demo_shows_only_made_up_identifiers():
    text = DEMO.read_text()
    assert set(re.findall(r"\b\d{12}\b", text)) <= {"111122223333", "444455556666", "999900001111"}
    keys = re.findall(r"\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b", text)
    assert keys and all(k.startswith(("AKIAIOSFODNN7", "ASIAIOSFODNN7")) for k in keys)  # AWS's documented example prefix, then a made-up ending


def test_pages_serves_the_folder_as_it_is_and_the_readme_links_to_the_demo():
    assert (ROOT / "docs/.nojekyll").exists()  # no Jekyll build: the page is served byte for byte
    readme = (ROOT / "README.md").read_text()
    assert readme.count(URL) == 2 and "made-up" in readme
