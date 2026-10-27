import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from controlzee import canonical
from controlzee.safety import clean
from controlzee.timeutil import format_time_us, normalize_time, parse_time_us

JSON = st.recursive(
    st.none() | st.booleans() | st.integers(-(2**53), 2**53) | st.text(),
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=8), inner, max_size=4),
    max_leaves=12,
)


@given(JSON)
def test_canonical_bytes_equal_the_standard_library_form(doc):
    """The determinism guarantee must not depend on orjson: stdlib json with the same options gives the same bytes."""
    expected = (json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
    assert canonical.dumps(doc) == expected


def test_canonical_is_sorted_indented_and_newline_terminated():
    assert canonical.dumps({"b": 1, "a": {"z": [1, 2], "y": None}}) == (
        b'{\n  "a": {\n    "y": null,\n    "z": [\n      1,\n      2\n    ]\n  },\n  "b": 1\n}\n')


def test_seal_hashes_everything_but_the_hash_field():
    doc = {"x": 1, "y": [1, 2]}
    sealed = canonical.seal(doc, "h")
    assert sealed["h"] == canonical.sha256_hex(canonical.dumps(doc)) and canonical.is_sealed(sealed, "h")
    assert canonical.seal(sealed, "h") == sealed  # sealing is idempotent
    assert not canonical.is_sealed({**sealed, "x": 2}, "h") and not canonical.is_sealed(doc, "h")


@pytest.mark.parametrize("text,us", [
    ("2026-10-20T14:30:11Z", 1_792_506_611_000_000),
    ("2026-10-20T14:30:11.250Z", 1_792_506_611_250_000),
    ("2026-10-20T16:30:11+02:00", 1_792_506_611_000_000),
    ("2026-10-20T14:30:11", 1_792_506_611_000_000),  # naive means UTC
])
def test_parse_time(text, us):
    assert parse_time_us(text) == us


@pytest.mark.parametrize("bad", ["", "yesterday", "2026-13-40T00:00:00Z", "10/20/2026"])
def test_parse_time_rejects_garbage(bad):
    with pytest.raises(ValueError):
        parse_time_us(bad)


@given(st.integers(0, 4_000_000_000_000_000))
def test_time_round_trip(us):
    assert parse_time_us(format_time_us(us)) == us


def test_normalize_time_accepts_what_yaml_produces():
    import datetime as dt
    assert normalize_time("2026-10-20T14:30:11+02:00") == "2026-10-20T12:30:11Z"
    assert normalize_time(dt.datetime(2026, 10, 20, 14, 30, 11)) == "2026-10-20T14:30:11Z"
    assert normalize_time(dt.date(2026, 10, 20)) == "2026-10-20T00:00:00Z"
    assert normalize_time("2026-10-20T14:30:11.5Z") == "2026-10-20T14:30:11.500000Z"
    with pytest.raises(ValueError, match="not an ISO-8601 time"):
        normalize_time("soon")
    with pytest.raises(ValueError):
        normalize_time(42)


def test_clean_neutralizes_terminal_escapes_and_caps_length():
    hostile = "\x1b[31mred\x1b[0m\r\nnext\x00line‮evil"
    out = clean(hostile)
    assert "\x1b" not in out and "\n" not in out and "\r" not in out and "\x00" not in out and "‮" not in out
    assert out.startswith("�[31mred")
    assert len(clean("x" * 1000, 50)) == 50 and clean("x" * 1000, 50).endswith("…")
    assert clean("plain text") == "plain text" and clean(123) == "123"
