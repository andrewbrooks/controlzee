"""Follow the attacker from the seeds to what they created or obtained, and to everything done with it.

A seed event that, say, created an access key taints that key; every later event made with the key joins the scope,
and whatever those events created is tainted in turn. The walk is breadth first, so each event and identity records its
shortest chain back to a seed. Strong seeds are followed first: an identity reached from a strong seed is strong, one
reached only from weak seeds stays weak, and an event inherits the confidence of the identity it acted as.

The seed window does not limit propagation. A key the attacker created is the attacker's whenever it is used; the
window exists to keep weak indicators from matching unrelated traffic, and taint is not an indicator match.

A role whose trust policy a tainted call changed (`trusted_by` identities, one per principal the new policy names) is
reached by an `AssumeRole` call into it from a caller that policy names and that had not assumed the role before the
change: the call joins the scope, and the session it hands out is followed like any other. The log holds the new policy
and not the old, so "had not assumed it before" is how the principals the change added are told from the ones that were
already trusted. That history is read from the rows the first time it is needed.

Works on index rows only (no models): every round is one pass over the rows from the earliest new identity onwards.
"""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from operator import itemgetter

from controlzee.ingest.index import R_AK, R_ID, R_ISSUED, R_PID, R_TS, R_UITYPE, EventIndex, Row
from controlzee.model.common import Confidence
from controlzee.seed.match import SeedHit
from controlzee.taint.rules import (
    ACCESS_KEY,
    ASSUMED_BY,
    ASSUMES,
    FUNCTION,
    INSTANCE,
    PRINCIPAL,
    ROLE,
    TRUSTED_BY,
)

_FACTS = frozenset({ASSUMES, ASSUMED_BY})  # recorded on a row, but not identities the attacker holds


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


def assumed_by(row: Row) -> tuple[str, str, str, str] | None:
    """(role name, caller account, caller ARN, caller's session issuer ARN) of an AssumeRole row, else None."""
    for kind, value in row[R_ISSUED] or ():
        if kind == ASSUMED_BY and len(parts := value.split("|")) == 4:
            return parts[0], parts[1], parts[2], parts[3]
    return None


def caller_key(account: str, arn: str, issuer: str) -> str:
    """Who a caller is, for telling a new one from one seen before: its role if it is a session, else its ARN or account."""
    return issuer or arn or (f"account:{account}" if account else "")


def principal_matches(principal: str, account: str, arn: str, issuer: str) -> bool:
    """Whether a trust policy's principal ("*", "account:<id>" or a user or role ARN) names this caller."""
    if principal == "*":
        return True
    if principal.startswith("account:"):
        parts = arn.split(":")
        return (account or (parts[4] if len(parts) > 4 else "")) == principal[8:]
    return principal in (arn, issuer)


def trusted_index[T](found: Mapping[tuple[str, str], T]) -> dict[str, list[tuple[str, T]]]:
    """The `trusted_by` identities of `found` by role name: [(principal, identity), ...]."""
    index: dict[str, list[tuple[str, T]]] = {}
    for (kind, value), identity in found.items():
        if kind == TRUSTED_BY:
            role, _, principal = value.partition("|")
            index.setdefault(role, []).append((principal, identity))
    return index


def acting_as[T](
    row: Row,
    found: Mapping[tuple[str, str], T],
    trusted: Mapping[str, Sequence[tuple[str, T]]] | None = None,
) -> list[T]:
    """Every tainted identity this event acted as, in a fixed order (key, principal, role, instance, function, role assumed,
    then a trust policy that names the caller). `found` maps (kind, value) to whatever the caller keeps about an identity;
    this returns those values. `trusted` is `trusted_index(found)`, given by callers that follow trust-policy backdoors."""
    keys: list[tuple[str, str]] = []
    if (ak := row[R_AK]) is not None:
        keys.append((ACCESS_KEY, ak))
    if (pid := row[R_PID]) is not None:
        keys.append((PRINCIPAL, pid))
        role, sep, session = pid.partition(":")
        if sep:
            keys.append((ROLE, role))
            if row[R_UITYPE] == "AssumedRole":
                keys.extend([(INSTANCE, session), (FUNCTION, session)])
    keys += [(ROLE, v) for k, v in row[R_ISSUED] or () if k == ASSUMES]
    out = [t for k in keys if (t := found.get(k)) is not None]
    if trusted and (who := assumed_by(row)) is not None:
        role, account, arn, issuer = who
        out += [
            t for principal, t in trusted.get(role, ()) if principal_matches(principal, account, arn, issuer)
        ]
    return out


def propagate(index: EventIndex, seeds: Sequence[SeedHit]) -> Propagation:
    rows = index.rows
    first_assumed: dict[tuple[str, str], int] | None = (
        None  # (role name, caller key) -> time of its first AssumeRole
    )

    def known_before(t: Taint, row: Row) -> bool:
        """True if `t` is a trust-policy identity and this caller assumed that role before the policy was changed."""
        nonlocal first_assumed
        if t.kind != TRUSTED_BY or (who := assumed_by(row)) is None or not (key := caller_key(*who[1:])):
            return False
        if first_assumed is None:
            first_assumed = {}
            for r in rows:  # in time order, so the first AssumeRole of a caller is the one kept
                if r[R_ISSUED] and (w := assumed_by(r)) is not None:
                    first_assumed.setdefault((w[0], caller_key(*w[1:])), r[R_TS])
        first = first_assumed.get((who[0], key))
        return first is not None and first < rows[t.row][R_TS]

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
                    if kind not in _FACTS and key not in identities and key not in new:
                        new[key] = Taint(kind, value, conf, pos, marks[pos].chain + (row[R_ID],))
            if not new:
                break
            identities.update(new)
            trusted = trusted_index(new)
            frontier = []
            start = bisect_left(rows, min(rows[t.row][R_TS] for t in new.values()), key=itemgetter(R_TS))
            for n in range(start, len(rows)):
                if n in marks:
                    continue
                row = rows[n]
                # an identity cannot act before it exists, and a caller that assumed a role before its trust policy was
                # changed is not made the attacker's by the change
                t = next(
                    (
                        t
                        for t in acting_as(row, new, trusted)
                        if t.row != n and row[R_TS] >= rows[t.row][R_TS] and not known_before(t, row)
                    ),
                    None,
                )
                if t is None:
                    continue
                marks[n] = Mark(conf, t.chain, t)
                frontier.append(n)
    return Propagation(marks, list(identities.values()))


def seeds_only(seeds: Sequence[SeedHit]) -> Propagation:
    """The result of not propagating at all (--no-propagate)."""
    return Propagation({h.row: Mark(h.confidence, (), None) for h in seeds}, [])
