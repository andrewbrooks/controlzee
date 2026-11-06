"""The demo site that GitHub Pages serves (docs/index.html and docs/examples/): built from the committed scenarios, never out of step
with the code, and saying only what is true of the reports it links to."""
import gzip
import re
from pathlib import Path

import pytest

from tests.builders.build_demo import DOCS, EXAMPLES, REPO, landing, pages, report
from tests.unit.test_html_report import audit, check_inert

ROOT = DOCS.parent
SITE = "https://andrewbrooks.github.io/controlzee/"
TESTS = ROOT / "tests"


@pytest.fixture(scope="module")
def built():
    return pages()


def test_the_site_is_exactly_what_the_builder_makes_from_the_committed_scenarios(built, golden):
    for path, data in built.items():
        golden(DOCS / path, data)  # UPDATE_GOLDENS=1 uv run pytest tests/unit/test_demo.py, or: uv run python -m tests.builders.build_demo
    on_disk = sorted(p.name for p in (DOCS / "examples").glob("*.html"))
    assert on_disk == sorted(f"{e.name}.html" for e in EXAMPLES)  # no page is left over from a scenario that was dropped


def test_every_example_page_is_a_self_contained_report_that_asks_the_network_for_nothing(built):
    for e in EXAMPLES:
        page = built[Path("examples") / f"{e.name}.html"]
        check_inert(page)
        urls = [v for _tag, _attr, v in audit(page).attrs if v and re.match(r"(?:https?:)?//", v)]
        assert urls == [], e.name  # a URL may appear as text (a user agent says "+https://www.terraform.io"), but no attribute points at one


def test_nothing_on_a_page_is_newer_than_the_logs_it_came_from(built):
    """Every account number and access key in a report is one that the committed (made-up or sanitized) logs already contain."""
    for e in EXAMPLES:
        text = built[Path("examples") / f"{e.name}.html"].decode()
        files = [p for p in (TESTS / e.source / e.name).rglob("*") if p.is_file()]
        source = "".join((gzip.decompress(p.read_bytes()) if p.suffix == ".gz" else p.read_bytes()).decode(errors="ignore") for p in files)
        for token in set(re.findall(r"\b\d{12}\b|\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b", text)):
            assert token in source, (e.name, token)


def test_the_landing_page_is_inert_and_links_to_every_report(built):
    page = built[Path("index.html")].decode()
    assert "<script" not in page and "style=" not in page and not re.search(r"\son\w+=", page) and "default-src 'none'" in page
    hrefs = re.findall(r'href="([^"]+)"', page)
    for e in EXAMPLES:
        assert f"examples/{e.name}.html" in hrefs and (DOCS / "examples" / f"{e.name}.html").exists()
    assert {h for h in hrefs if h.startswith("http")} == {REPO, "https://github.com/DataDog/stratus-red-team"}


def test_the_landing_page_tells_made_up_logs_from_real_ones_and_counts_them_right(built):
    page = built[Path("index.html")].decode()
    made = sum(e.source == "fixtures" for e in EXAMPLES)
    real = len(EXAMPLES) - made
    assert page.count("Made-up logs") == made and page.count("Real CloudTrail, sanitized") == real
    assert f"for {len(EXAMPLES)} example incidents" in page and f"{made} use made-up logs; {real} are sanitized" in page


def test_a_hostile_card_cannot_add_markup():
    from tests.builders.build_demo import Example, _card
    out = _card(Example("x", "fixtures", '"><script>alert(1)</script>', "<img src=x onerror=alert(1)>", ("<b>&</b>",)))
    assert "<script" not in out and "<img" not in out and "<b>" not in out and "&lt;script&gt;" in out


# ---- what the cards say is true of the reports

CLAIMS = {
    "02_role_chain": ["2 h 40 min, no activity", "444455556666", 'class="node ghost"', 'id="step-A03" data-phase="contain" data-nodes='],
    "04_log_tampering": ["2 h 27 min, logs silent", "Logging or detection changed", "Restart AWS Config recording", "Turn the trail back on"],
    "03_instance_role": ["Secrets read", "1 h 48 min, no activity", "1 h 00 min, no activity", "★ read secret prod/db"],
    "05_weak_ioc": ["on weak evidence only: confirm them before acting on them"],
    "ec2-steal-instance-credentials": ["Instance role used from another address", "Cut an attacker&#x27;s instance off from its role",
                                       "Stop an attacker&#x27;s instance", "Terminate an attacker&#x27;s instance"],
    "secretsmanager-retrieve-secrets": ["Secrets read", "&times;60", "treat the values as known to the attacker", "Rotate the 20 secrets"],
}


def test_every_scenario_has_a_card_and_claims_to_check():
    assert {e.name for e in EXAMPLES} == set(CLAIMS)


@pytest.mark.parametrize("name", sorted(CLAIMS))
def test_what_a_card_says_to_look_at_is_in_the_report(built, name):
    text = built[Path("examples") / f"{name}.html"].decode()
    for needle in CLAIMS[name]:
        assert needle in text, (name, needle)


def test_the_cards_that_say_there_is_no_graph_are_right_and_the_others_have_one(built):
    no_graph = {"04_log_tampering"}
    for e in EXAMPLES:
        has = 'class="graph' in built[Path("examples") / f"{e.name}.html"].decode()
        assert has == (e.name not in no_graph), e.name


def test_the_big_capture_really_is_over_two_hundred_calls(built):
    text = built[Path("examples") / "ec2-steal-instance-credentials.html"].decode()
    assert int(re.search(r'<dt>Events in scope</dt><dd><a href="#calls">(\d+)</a>', text).group(1)) > 200


# ---- the repository

def test_pages_serves_the_folder_byte_for_byte_and_the_readme_links_to_the_site():
    assert (ROOT / "docs/.nojekyll").exists() and not (ROOT / "docs/demo").exists()
    readme = (ROOT / "README.md").read_text()
    assert readme.count(SITE) == 2 and "made-up" in readme and "demo/" not in readme


def test_the_landing_page_builds_the_same_twice():
    assert landing() == landing() and report(EXAMPLES[0]) == report(EXAMPLES[0])
