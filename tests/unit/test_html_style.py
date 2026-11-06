"""The report's look: light only, every colour a variable, red kept for "needs attention"."""
import colorsys
import re

from controlzee._html_static import CSS, JS
from controlzee.html_report import build_html
from tests.unit.test_respond import scope_of


def variables(css: str) -> dict[str, str]:
    return dict(re.findall(r"(--[\w-]+):([^;}]+)", css.split("@media print")[0].split("*{box-sizing")[0]))


def hue(hex_colour: str) -> float:
    r, g, b = (int(hex_colour[i:i + 2], 16) / 255 for i in (1, 3, 5))
    return colorsys.rgb_to_hsv(r, g, b)[0] * 360


def test_the_page_is_light_only():
    assert "color-scheme:light" in CSS and "prefers-color-scheme" not in CSS and "data-theme" not in CSS and "dark" not in CSS.lower()
    assert "theme" not in JS.lower()


def test_there_is_no_theme_button(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    assert 'id="theme"' not in page and ">Theme<" not in page


def test_every_colour_is_a_variable_declared_at_the_top():
    outside = re.sub(r":root\{[^}]*\}", "", CSS)
    assert not re.findall(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", outside), "a colour is written outside :root: use a variable"


def test_the_look_is_paper_ink_and_one_accent():
    v = variables(CSS)
    assert v["--paper"] == "#FAF8F4" and v["--accent"] == "#0F5C63" and v["--card"] == "#fff"
    assert "Charter" in v["--serif"] and "Georgia" in v["--serif"]


def test_red_is_only_for_attention_no_tactic_is_red():
    v = variables(CSS)
    red = hue(v["--attn"])
    assert red < 15 or red > 345
    for name, value in v.items():
        if name.startswith("--c-"):
            h = hue(value.strip())
            assert not (h < 15 or h > 345) or value.strip() in ("#3D3D3D", "#2E4057"), (name, value)  # greys and navy have no hue to speak of
    assert v["--c-privilege-escalation"] != v["--attn"]


def test_a_node_that_matched_an_indicator_is_marked_by_a_shape_not_only_a_colour(fixtures):
    page = build_html(scope_of(fixtures, "02_role_chain")).decode()
    assert page.count('class="rim"') == 1  # the one identity that matched: a second outline


def test_the_page_carries_a_print_stylesheet_that_expands_and_keeps_steps_whole():
    printing = CSS.split("@media print")[1]
    assert "header.top" in printing and "display:none" in printing and "details::details-content" in printing
    assert ".step" in printing and "break-inside:avoid" in printing and "tr," in printing
