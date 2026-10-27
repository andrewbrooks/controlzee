import itertools

import pytest
from hypothesis import given
from hypothesis import strategies as st

from controlzee.seed.expr import And, ExpressionError, Or, Ref, evaluate, names, parse, to_text


def test_precedence_and_grouping():
    assert parse("a") == Ref("a")
    assert parse("a AND b OR c") == Or((And((Ref("a"), Ref("b"))), Ref("c")))
    assert parse("a OR b AND c") == Or((Ref("a"), And((Ref("b"), Ref("c")))))
    assert parse("(a OR b) AND c") == And((Or((Ref("a"), Ref("b"))), Ref("c")))
    assert parse("a and b Or c") == parse("a AND b OR c")  # operators are case-insensitive, names are not
    assert parse("a AND (b AND c)") == And((Ref("a"), Ref("b"), Ref("c")))  # nested same operator is flattened
    assert parse("access-key_1 OR ip.1".replace(".", "_")) == Or((Ref("access-key_1"), Ref("ip_1")))


@pytest.mark.parametrize("bad,why", [
    ("", "empty"), ("   ", "empty"), ("a b", "AND or OR"), ("a AND", "ends"), ("AND a", "needs an indicator"),
    ("(a", "missing"), ("a)", "unexpected"), ("()", "unexpected"), ("NOT a", "NOT is not supported"),
    ("a & b", "unexpected character"), ("a AND OR b", "needs an indicator"), ("a" * 5000, "too long"),
])
def test_errors_say_what_is_wrong(bad, why):
    with pytest.raises(ExpressionError, match=why):
        parse(bad)


def test_names_are_sorted_and_unique():
    assert names(parse("b AND (a OR b) OR c")) == ["a", "b", "c"]


def test_to_text_is_canonical_and_adds_only_needed_parentheses():
    assert to_text(parse("a   and  b or   c")) == "a AND b OR c"
    assert to_text(parse("(a OR b) AND c")) == "(a OR b) AND c"
    assert to_text(parse("a OR (b AND c)")) == "a OR b AND c"
    assert to_text(parse("((a))")) == "a"


def test_strength_follows_the_satisfied_branch():
    strong = frozenset({"key"})
    # an OR is strong when a matching branch is strong; a weak match alone is weak
    assert evaluate(parse("key OR ip"), {"key": True}, strong) == (True, True)
    assert evaluate(parse("key OR ip"), {"ip": True}, strong) == (True, False)
    assert evaluate(parse("key OR ip"), {"key": True, "ip": True}, strong) == (True, True)
    # an AND is strong when a strong indicator takes part; two weak ones stay weak
    assert evaluate(parse("key AND ip"), {"key": True, "ip": True}, strong) == (True, True)
    assert evaluate(parse("key AND ip"), {"ip": True}, strong) == (False, False)
    assert evaluate(parse("ip AND ua"), {"ip": True, "ua": True}, strong) == (True, False)
    # a strong indicator that did not match does not lend strength to a weak match elsewhere
    assert evaluate(parse("(key AND ip) OR ua"), {"ua": True}, strong) == (True, False)


def _tree(draw, depth=0):
    leaf = st.sampled_from(["a", "b", "c", "d"])
    if depth >= 3 or draw(st.integers(0, 3)) == 0:
        return draw(leaf)
    op = draw(st.sampled_from([" AND ", " OR "]))
    return "(" + op.join(_tree(draw, depth + 1) for _ in range(draw(st.integers(2, 3)))) + ")"


@st.composite
def expressions(draw):
    return _tree(draw)


@given(expressions())
def test_matches_python_boolean_semantics_and_strength_invariants(text):
    node = parse(text)
    # to_text then parse is stable
    assert parse(to_text(node)) == node
    for combo in itertools.product([False, True], repeat=4):
        hits = dict(zip("abcd", combo, strict=True))
        reference = eval(text.replace(" AND ", " and ").replace(" OR ", " or "), {"__builtins__": {}}, dict(hits))  # noqa: S307
        for strong in (frozenset(), frozenset("a"), frozenset("ab"), frozenset("abcd")):
            matched, is_strong = evaluate(node, hits, strong)
            assert matched == reference
            assert not is_strong or matched
            assert not is_strong or any(hits[n] for n in strong & set(names(node)))
            if not strong:
                assert not is_strong
