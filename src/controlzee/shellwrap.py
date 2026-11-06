"""Lay a shell command out over several lines for reading: one flag to a line, joined by `\\` continuations, and a JSON argument
(an inline policy document) indented.

Display only. The plan's commands are not changed and `plan.json` keeps them as they were; this is what the HTML report shows and what its
Copy button copies, so it has to run exactly as the original does. So the command is read as the shell reads it, word by word, and
anything the shell would treat specially that this cannot reproduce exactly (a variable, a glob, a pipe, a redirect, a backslash) makes it
return the command as it came. The one expansion it keeps is a `"$(...)"` spliced into a single-quoted JSON document, the form the plan
uses for "now": the JSON around it is indented and the expansion is left exactly as written.
"""
from __future__ import annotations

import json
import re
import shlex
from typing import Final

LONG: Final = 88  # a command up to this many characters stays on one line
_SAFE_BARE: Final = re.compile(r"[A-Za-z0-9_@%+=:,./-]+")
_Word = list[tuple[str, str]]  # segments of one shell word: ("bare" | "single" | "double", text)


def _scan(command: str) -> list[_Word] | None:
    """The words of a command with their quoting kept, or None when it holds anything this will not guess at."""
    words: list[_Word] = []
    cur: _Word = []
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if c in " \t":
            if cur:
                words.append(cur)
                cur = []
            i += 1
        elif c in "'\"":
            end = command.find(c, i + 1)
            if end < 0:
                return None
            text = command[i + 1:end]
            if c == '"' and ("\\" in text or "!" in text):
                return None
            cur.append(("single" if c == "'" else "double", text))
            i = end + 1
        else:
            m = _SAFE_BARE.match(command, i)
            if m is None:  # a character the shell treats specially
                return None
            cur.append(("bare", m.group()))
            i = m.end()
    if cur:
        words.append(cur)
    return words


def _is_dynamic(seg: tuple[str, str]) -> bool:
    return seg[0] == "double" and ("$" in seg[1] or "`" in seg[1])


def _arg(token: str) -> str:
    """One plain argument as shell text: a JSON document over several lines in single quotes, anything else quoted only as far as it needs."""
    stripped = token.strip()
    if stripped[:1] in "{[" and stripped[-1:] in "}]" and "'" not in token:
        try:
            doc = json.loads(token)
        except ValueError:
            doc = None
        if isinstance(doc, (dict, list)):
            return "'" + json.dumps(doc, indent=2) + "'"
    return shlex.quote(token)


def _render(word: _Word) -> str | None:
    """One word as shell text, or None when it cannot be laid out without changing what the shell makes of it."""
    if not any(_is_dynamic(s) for s in word):
        return _arg("".join(text for _, text in word))
    # JSON with an expansion spliced in between single-quoted parts: indent the JSON, keep each expansion as it was written
    marks: list[str] = []
    text = ""
    for seg in word:
        if _is_dynamic(seg):
            text += f"__czee_{len(marks)}__"
            marks.append(f'"{seg[1]}"')
        else:
            text += seg[1]
    if "'" in text:
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    pretty = json.dumps(doc, indent=2)
    if not isinstance(doc, (dict, list)) or any(pretty.count(f"__czee_{k}__") != 1 for k in range(len(marks))):
        return None
    for k, raw in enumerate(marks):
        pretty = pretty.replace(f"__czee_{k}__", f"'{raw}'")
    return "'" + pretty + "'"


def wrap(command: str) -> str:
    """The command over several lines when it is long, else as it is. Never changes what the shell would run."""
    if len(command) <= LONG or "\n" in command:
        return command
    words = _scan(command)
    if not words:
        return command
    rendered = [_render(w) for w in words]
    if any(r is None for r in rendered):
        return command
    head: list[str] = []
    groups: list[list[str]] = []
    for w, r in zip(words, rendered, strict=True):
        flag = len(w) == 1 and w[0][0] == "bare" and w[0][1].startswith("--") and len(w[0][1]) > 2
        if flag:
            groups.append([w[0][1]])
        elif groups:
            groups[-1].append(r or "")
        else:
            head.append(r or "")
    lines = [" ".join(head)] + ["  " + " ".join(g) for g in groups]
    return " \\\n".join(lines)


def collapse(wrapped: str) -> str:
    """The wrapped text with its line continuations undone: what the shell reads it as, up to the layout of a JSON argument."""
    return re.sub(r" \\\n", " ", wrapped)
