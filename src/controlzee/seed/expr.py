"""IOC expressions: indicator names combined with AND / OR and parentheses. AND binds tighter than OR."""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

_TOKEN = re.compile(r"\s*(?:(?P<paren>[()])|(?P<word>[A-Za-z_][A-Za-z0-9_\-]*)|(?P<bad>\S))")
MAX_LENGTH = 4096


class ExpressionError(ValueError):
    pass


@dataclass(frozen=True)
class Ref:
    name: str


@dataclass(frozen=True)
class And:
    terms: tuple[Node, ...]


@dataclass(frozen=True)
class Or:
    terms: tuple[Node, ...]


Node = Ref | And | Or


def _tokens(text: str) -> list[str]:
    if len(text) > MAX_LENGTH:
        raise ExpressionError("expression is too long")
    out, pos = [], 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            break
        if m.group("bad"):
            raise ExpressionError(f"unexpected character {m.group('bad')!r}; use indicator names, AND, OR and parentheses")
        out.append(m.group("paren") or m.group("word"))
        pos = m.end()
    return out


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.t, self.i = tokens, 0

    def peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self) -> str:
        tok = self.t[self.i]
        self.i += 1
        return tok

    def or_expr(self) -> Node:
        terms = [self.and_expr()]
        while (p := self.peek()) is not None and p.upper() == "OR":
            self.take()
            terms.append(self.and_expr())
        return terms[0] if len(terms) == 1 else Or(tuple(_flatten(Or, terms)))

    def and_expr(self) -> Node:
        terms = [self.atom()]
        while (p := self.peek()) is not None and p.upper() == "AND":
            self.take()
            terms.append(self.atom())
        return terms[0] if len(terms) == 1 else And(tuple(_flatten(And, terms)))

    def atom(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise ExpressionError("the expression ends where an indicator name or '(' was expected")
        if tok == "(":
            self.take()
            node = self.or_expr()
            if self.peek() != ")":
                raise ExpressionError("missing ')'")
            self.take()
            return node
        if tok == ")":
            raise ExpressionError("unexpected ')'")
        if tok.upper() == "NOT":
            raise ExpressionError("NOT is not supported: list the indicators that must match, not ones that must not")
        if tok.upper() in ("AND", "OR"):
            raise ExpressionError(f"{tok.upper()} needs an indicator name on both sides")
        return Ref(self.take())


def _flatten(kind: type[And] | type[Or], terms: list[Node]) -> list[Node]:
    out: list[Node] = []
    for t in terms:
        out.extend(t.terms if isinstance(t, kind) else [t])
    return out


def parse(text: str) -> Node:
    tokens = _tokens(text)
    if not tokens:
        raise ExpressionError("the expression is empty")
    parser = _Parser(tokens)
    node = parser.or_expr()
    if parser.peek() is not None:
        raise ExpressionError(f"unexpected {parser.peek()!r}; two indicators need AND or OR between them")
    return node


def names(node: Node) -> list[str]:
    """Every indicator name used, sorted and unique."""
    if isinstance(node, Ref):
        return [node.name]
    return sorted({n for t in node.terms for n in names(t)})


def to_text(node: Node) -> str:
    """Canonical text: single spaces, upper-case operators, parentheses only where they change the meaning."""
    if isinstance(node, Ref):
        return node.name
    if isinstance(node, And):
        return " AND ".join(f"({to_text(t)})" if isinstance(t, Or) else to_text(t) for t in node.terms)
    return " OR ".join(to_text(t) for t in node.terms)


def evaluate(node: Node, hits: Mapping[str, bool], strong: frozenset[str]) -> tuple[bool, bool]:
    """(matched, matched with a strong indicator taking part in a satisfied branch)."""
    if isinstance(node, Ref):
        h = bool(hits.get(node.name))
        return h, h and node.name in strong
    results = [evaluate(t, hits, strong) for t in node.terms]
    if isinstance(node, And):
        matched = all(m for m, _ in results)
        return matched, matched and any(s for _, s in results)
    return any(m for m, _ in results), any(s for _, s in results)
