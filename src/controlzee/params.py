"""What a call was asked to do: the parameters of a logged request, as short `name: value` pairs for people.

Request parameters are attacker-influenced text, and some are secrets. So this shows less than is logged, on purpose:
- values CloudTrail itself hid stay hidden;
- names that carry a secret are never shown, and neither are the values of environment variables (only their names);
- every value is cut to a length, nested structures are cut to a depth and a count, and policy documents are summarised
  (effect, actions, who) and not copied.
The caller still escapes each string for where it is put (Markdown or HTML).
"""
from __future__ import annotations

import json
from typing import Any, Final

from controlzee.model.event import Event
from controlzee.safety import clean

MAX_PAIRS: Final = 14
MAX_VALUE: Final = 160
MAX_DEPTH: Final = 3
HIDDEN_BY_CLOUDTRAIL: Final = ("HIDDEN_DUE_TO_SECURITY_REASONS", "<sensitiveDataRemoved>")
_NEVER: Final = frozenset({
    "secretstring", "secretbinary", "password", "newpassword", "oldpassword", "userdata", "privatekey", "secretaccesskey",
    "sessiontoken", "token", "authorizationtoken", "plaintext", "ciphertextblob", "zipfile", "body", "keymaterial", "cacertificate"})
_NOISE: Final = frozenset({"clienttoken", "clientrequesttoken", "idempotencytoken", "requestid", "dryrun"})
_POLICY_KEYS: Final = frozenset({"policydocument", "assumerolepolicydocument", "policy", "resourcepolicy"})


def _scalar(v: Any) -> str | None:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int | float):
        return str(v)
    if isinstance(v, str):
        return "(hidden by CloudTrail)" if v in HIDDEN_BY_CLOUDTRAIL else clean(v, MAX_VALUE)
    return None


def _principals(p: Any) -> list[str]:
    if isinstance(p, str):
        return [p]
    if isinstance(p, dict):
        return [x for v in p.values() for x in _principals(v)]
    if isinstance(p, list):
        return [x for v in p for x in _principals(v)]
    return []


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else [] if v is None else [v]


def policy_summary(document: Any) -> str | None:
    """"Allow sts:AssumeRole by ec2.amazonaws.com; Deny s3:* on 2 resources", or None if this is not a policy document."""
    if isinstance(document, str):
        if not document.lstrip().startswith("{"):
            return None
        try:
            document = json.loads(document)
        except ValueError:
            return None
    if not isinstance(document, dict) or "Statement" not in document:
        return None
    parts = []
    for st in _as_list(document["Statement"])[:4]:
        if not isinstance(st, dict):
            continue
        actions = [a for a in _as_list(st.get("Action")) if isinstance(a, str)]
        text = f"{st.get('Effect', '?')} {', '.join(actions[:3])}{' ...' if len(actions) > 3 else ''}"
        who = _principals(st.get("Principal"))
        if who:
            text += f" by {', '.join(who[:3])}{' ...' if len(who) > 3 else ''}"
        resources = [r for r in _as_list(st.get("Resource")) if isinstance(r, str)]
        if len(resources) == 1 and resources[0] == "*":
            text += " on all resources"
        elif resources:
            text += f" on {len(resources)} resource{'s' if len(resources) != 1 else ''}"
        parts.append(text)
    more = len(_as_list(document["Statement"])) - 4
    return clean("; ".join(parts) + (f"; and {more} more" if more > 0 else ""), MAX_VALUE * 2) if parts else None


def _walk(value: Any, name: str, depth: int, out: list[tuple[str, str]]) -> None:
    key = name.rsplit(".", 1)[-1].split("[", 1)[0].lower()
    if key in _NEVER or key in _NOISE or len(out) >= MAX_PAIRS:
        return
    if key in _POLICY_KEYS and (s := policy_summary(value)) is not None:
        out.append((name, s))
    elif key == "environment" and isinstance(value, dict):  # the names say what it is for; the values may be secrets
        names = sorted(str(k) for k in _as_list_keys(value.get("variables")))
        if names:
            out.append(("environment variables", clean(", ".join(names[:12]) + (" ..." if len(names) > 12 else ""), MAX_VALUE)))
    elif (s := _scalar(value)) is not None:
        if (summary := policy_summary(s)) is not None:
            s = summary
        out.append((name, s))
    elif isinstance(value, dict):
        if depth < MAX_DEPTH:
            for k in sorted(value, key=str):
                _walk(value[k], f"{name}.{k}" if name else str(k), depth + 1, out)
    elif isinstance(value, list) and value:
        scalars = [_scalar(v) for v in value]
        if all(s is not None for s in scalars):
            shown = [s for s in scalars[:5] if s is not None]
            out.append((name, clean(", ".join(shown) + (f" (and {len(scalars) - 5} more)" if len(scalars) > 5 else ""), MAX_VALUE)))
        elif depth < MAX_DEPTH:
            for i, v in enumerate(value[:3]):
                _walk(v, f"{name}[{i}]", depth + 1, out)
            if len(value) > 3:
                out.append((name, f"{len(value)} items"))


def _as_list_keys(v: Any) -> list[Any]:
    return list(v) if isinstance(v, dict) else []


def describe(ev: Event) -> list[tuple[str, str]]:
    """The request's parameters as (name, value) pairs, at most MAX_PAIRS, names sorted. Safe to show: see the module doc."""
    out: list[tuple[str, str]] = []
    params = ev.request_parameters or {}
    for k in sorted(params, key=str):
        _walk(params[k], str(k), 1, out)
    return [(clean(n, 80), v) for n, v in out][:MAX_PAIRS]
