"""Make CloudTrail records safe to share: replace what identifies an account, a person or a credential.

Account ids, organization ids, IP addresses, access key ids, principal ids, UUIDs (event and request ids) and email
addresses are replaced by stable stand-ins: the same original always becomes the same replacement within one
`Sanitizer`, so the relations between events (who acted, which key, which account) survive. Replacements are numbered in
the order values are first seen, so records must be given in a fixed order (sort them by time and event id) for the
output to be reproducible. Nothing is derived from an original value, so a replacement cannot be reversed.

`leaks` is the safety net: it scans text for any original value that was seen, and for anything that still has the
shape of an identifier but is not one of the replacements. Run it over the final output before sharing it.
"""
from __future__ import annotations

import re
import uuid
from typing import Any, Final

_UUID_NS: Final = uuid.UUID("5d1b2c0e-0000-4000-8000-000000000001")  # fixed, only so replacements look like UUIDs

_ACCOUNT = re.compile(r"(?<![\d])\d{12}(?![\d])")
_ORG = re.compile(r"\b(o|r|p)-[a-z0-9]{4,32}\b|\bou-[a-z0-9]{4,32}-[a-z0-9]{8,32}\b")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_ACCESS_KEY = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")
_PRINCIPAL = re.compile(r"\b(AIDA|AROA|AIPA|ANPA|AGPA|ASCA)[A-Z0-9]{16,17}\b")
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
# SDK user agents carry the operating system and kernel of the machine that made the call ("os/linux#5.15.0-1-generic")
_CLIENT_OS = re.compile(r"\bos/(\w+)#\S+")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")

# addresses reserved for documentation (RFC 5737): safe stand-ins
_DOC_NETS: Final = ("192.0.2.", "198.51.100.", "203.0.113.")
_FAKE_ACCOUNTS: Final = ("111122223333", "444455556666", "777788889999", "222233334444", "555566667777", "888899990000")


def _valid_ipv4(s: str) -> bool:
    return all(o.isdigit() and 0 <= int(o) <= 255 for o in s.split("."))


def _is_documentation_ip(ip: str) -> bool:
    return ip.startswith(_DOC_NETS)


class Sanitizer:
    def __init__(self) -> None:
        self._maps: dict[str, dict[str, str]] = {k: {} for k in ("account", "org", "ip", "key", "principal", "uuid", "email")}

    # ---- replacements, numbered in first-seen order

    def _get(self, kind: str, original: str, make: Any) -> str:
        m = self._maps[kind]
        if original not in m:
            m[original] = make(len(m) + 1)
        return m[original]

    def _account(self, s: str) -> str:
        return self._get("account", s, lambda n: _FAKE_ACCOUNTS[n - 1] if n <= len(_FAKE_ACCOUNTS) else f"{900000000000 + n}")

    def _org(self, m: re.Match[str]) -> str:
        s = m.group(0)
        return self._get("org", s, lambda n: f"{s.split('-', 1)[0]}-example{n:05d}")

    def _ip(self, s: str) -> str:
        if not _valid_ipv4(s) or _is_documentation_ip(s):
            return s
        return self._get("ip", s, lambda n: f"203.0.113.{n}" if n < 255 else f"198.51.100.{n - 254}")

    def _key(self, m: re.Match[str]) -> str:
        if "IOSFODNN7" in m.group(0):  # AWS's documentation keys, and our own stand-ins
            return m.group(0)
        return self._get("key", m.group(0), lambda n: f"{m.group(1)}IOSFODNN7{n:07d}")

    def _principal(self, m: re.Match[str]) -> str:
        s = m.group(0)
        return self._get("principal", s, lambda n: f"{m.group(1)}EXAMPLEID{n:08d}"[: len(s)].ljust(len(s), "0"))

    def _uuid(self, m: re.Match[str]) -> str:
        def make(n: int) -> str:
            u = str(uuid.uuid5(_UUID_NS, str(n)))
            return u[:-12] + "f" + u[-11:]  # a letter in the tail, so it can never look like a 12-digit account id
        return self._get("uuid", m.group(0), make)

    def _email(self, m: re.Match[str]) -> str:
        return self._get("email", m.group(0), lambda n: f"user{n}@example.com")

    # ---- public

    def text(self, s: str) -> str:
        s = _CLIENT_OS.sub(r"os/\1", s)  # before the IP pattern, which reads a kernel version as an address
        s = _UUID.sub(self._uuid, s)  # first: a UUID's digits must not be taken for an account id
        s = _EMAIL.sub(self._email, s)
        s = _ORG.sub(self._org, s)
        s = _ACCOUNT.sub(lambda m: self._account(m.group(0)), s)
        s = _IPV4.sub(lambda m: self._ip(m.group(0)), s)
        s = _ACCESS_KEY.sub(self._key, s)
        return _PRINCIPAL.sub(self._principal, s)

    def clean(self, value: Any) -> Any:
        """The same structure with every string passed through `text` (keys too, since an ARN can be a key)."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.clean(v) for v in value]
        if isinstance(value, dict):
            return {self.text(k): self.clean(v) for k, v in value.items()}
        return value

    def replacement(self, original: str) -> str | None:
        """What an original value was replaced by, or None if it was never seen (to write IOCs for the cleaned logs)."""
        for m in self._maps.values():
            if original in m:
                return m[original]
        return None

    def originals(self) -> list[str]:
        return sorted(o for m in self._maps.values() for o in m)

    def leaks(self, text: str) -> list[str]:
        """Things in `text` that should not be shared: an original value that was replaced, or an identifier-shaped value
        that is not one of the stand-ins. Empty means nothing was found, which is not proof that nothing is there."""
        found = [o for o in self.originals() if o in text]
        replaced = {r for m in self._maps.values() for r in m.values()}
        found += [a for a in _ACCOUNT.findall(text) if a not in replaced and a not in _FAKE_ACCOUNTS]
        found += [ip for ip in _IPV4.findall(text) if ip not in replaced and not _is_documentation_ip(ip) and _valid_ipv4(ip)]
        found += [m.group(0) for m in _ACCESS_KEY.finditer(text) if m.group(0) not in replaced and "IOSFODNN7" not in m.group(0)]
        found += [m.group(0) for m in _CLIENT_OS.finditer(text)]
        found += [m.group(0) for m in _EMAIL.finditer(text) if m.group(0) not in replaced and not m.group(0).endswith("@example.com")]
        return sorted(set(found))
