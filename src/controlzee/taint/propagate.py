"""Follow the attacker from the seeds to what they created or obtained, and to everything done with it.

A seed event that, say, created an access key taints that key; every later event made with the key joins the scope,
and whatever those events created is tainted in turn. The walk is breadth first, so each event and identity records its
shortest chain back to a seed. Strong seeds are followed first: an identity reached from a strong seed is strong, one
reached only from weak seeds stays weak, and an event inherits the confidence of the identity it acted as.

The seed window does not limit propagation. A key the attacker created is the attacker's whenever it is used; the
window exists to keep weak indicators from matching unrelated traffic, and taint is not an indicator match.

Works on index rows only (no models): every round is one pass over the rows from the earliest new identity onwards.
"""
from __future__ import annotations

from bisect import bisect_left
from collections.abc import Sequence
from dataclasses import dataclass
from operator import itemgetter

from controlzee.ingest.index import R_AK, R_ID, R_ISSUED, R_PID, R_TS, R_UITYPE, EventIndex, Row
from controlzee.model.common import Confidence
from controlzee.seed.match import SeedHit
from controlzee.taint.rules import ACCESS_KEY, ASSUMES, INSTANCE, PRINCIPAL, ROLE


@dataclass(frozen=True)
class Taint:
    """An identity the attacker holds, and how they came to hold it."""

    kind: str
    value: str
    confidence: Confidence
    row: int  # position of the event that issued it
    chain: tuple[str, ...]  # event ids from a seed to the issuing event, inclusive


@dataclass(frozen=True)
class Mark:
    """Why an event is in scope. `via` is None for a seed that no tainted identity reached."""

    confidence: Confidence
    chain: tuple[str, ...]
    via: Taint | None


@dataclass
class Propagation:
    marks: dict[int, Mark]  # row position -> mark, for every in-scope event (seeds included)
    identities: list[Taint]  # in the order they were found: by round, then by issuing event


def acting_as(row: Row, found: dict[tuple[str, str], Taint]) -> list[Taint]:
    """Every tainted identity this event acted as, in a fixed order (key, principal, role, instance, role assumed)."""
    keys: list[tuple[str, str]] = []
    if (ak := row[R_AK]) is not None:
        keys.append((ACCESS_KEY, ak))
    if (pid := row[R_PID]) is not None:
        keys.append((PRINCIPAL, pid))
        role, sep, session = pid.partition(":")
        if sep:
            keys.append((ROLE, role))
            if row[R_UITYPE] == "AssumedRole":
                keys.append((INSTANCE, session))
    keys += [(ROLE, v) for k, v in row[R_ISSUED] or () if k == ASSUMES]
    return [t for k in keys if (t := found.get(k)) is not None]


def propagate(index: EventIndex, seeds: Sequence[SeedHit]) -> Propagation:
    rows = index.rows
    seed_conf = {h.row: h.confidence for h in seeds}
    marks: dict[int, Mark] = {}
    identities: dict[tuple[str, str], Taint] = {}
    for conf in (Confidence.STRONG, Confidence.WEAK):
        frontier = sorted(pos for pos, c in seed_conf.items() if c is conf and pos not in marks)
        for pos in frontier:
            marks[pos] = Mark(conf, (), None)
        while frontier:
            new: dict[tuple[str, str], Taint] = {}
            for pos in frontier:  # row order is time order, so the first issuer of an identity wins
                row = rows[pos]
                for kind, value in row[R_ISSUED] or ():
                    key = (kind, value)
                    if kind != ASSUMES and key not in identities and key not in new:
                        new[key] = Taint(kind, value, conf, pos, marks[pos].chain + (row[R_ID],))
            if not new:
                break
            identities.update(new)
            frontier = []
            start = bisect_left(rows, min(rows[t.row][R_TS] for t in new.values()), key=itemgetter(R_TS))
            for n in range(start, len(rows)):
                if n in marks:
                    continue
                row = rows[n]
                # an identity cannot act before it exists
                t = next((t for t in acting_as(row, new) if t.row != n and row[R_TS] >= rows[t.row][R_TS]), None)
                if t is None:
                    continue
                marks[n] = Mark(conf, t.chain, t)
                frontier.append(n)
    return Propagation(marks, list(identities.values()))


def seeds_only(seeds: Sequence[SeedHit]) -> Propagation:
    """The result of not propagating at all (--no-propagate)."""
    return Propagation({h.row: Mark(h.confidence, (), None) for h in seeds}, [])
