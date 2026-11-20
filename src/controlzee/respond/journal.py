"""The step journal: a write-ahead log of what `controlzee respond execute` is about to do and what became of it.

Before a step's change is made, a `starting` line is on disk (written, then `fsync`ed); after it, a result line. A run
that is killed in between therefore leaves a journal that says which step may be partly made. The journal is created
with `O_EXCL` and never reopened, so its existence is also the replay guard: a dry run is carried out once. There is
no resume; after an interrupted run a person reads the journal and runs a new dry run, whose probes report what is
already done.

The journal is append-only, mode 0600, one canonical JSON object per line. It holds wall-clock times (an operational
record, like `response.json`), and `response.json` cites its sha256.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
from pathlib import Path

from pydantic import BaseModel

from controlzee import canonical


class JournalExists(Exception):
    """A journal for this dry run is already there: it was executed (or started)."""


def journal_path(directory: Path, dryrun_sha256: str) -> Path:
    """Where the journal of this dry run lives: next to the response, named for the dry run."""
    return directory / f"response.{dryrun_sha256[:16]}.journal.jsonl"


def replayed(path: Path) -> bool:
    """True if a journal is already there (a dangling symlink counts: nothing may be written through it)."""
    return os.path.lexists(path)


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Journal:
    """An open journal. `append` returns only once the line is on disk."""

    def __init__(self, path: Path, fd: int) -> None:
        self.path = path
        self._fd: int | None = fd
        self._hash = hashlib.sha256()

    @classmethod
    def create(cls, path: Path) -> Journal:
        """Make the file (mode 0600), failing with JournalExists if it is already there, and make its existence durable."""
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        except FileExistsError:
            raise JournalExists(str(path)) from None
        try:
            _fsync_directory(path.parent)
        except BaseException:
            os.close(fd)
            with contextlib.suppress(OSError):
                path.unlink()
            raise
        return cls(path, fd)

    def append(self, entry: BaseModel) -> None:
        """Write one line and `fsync` it. Raises OSError if it cannot be made durable."""
        if self._fd is None:
            raise ValueError("the journal is closed")
        data = canonical.dumps_line(entry.model_dump(mode="json"))
        view = memoryview(data)
        while view:
            view = view[os.write(self._fd, view) :]
        os.fsync(self._fd)
        self._hash.update(data)

    @property
    def sha256(self) -> str:
        """The hash of every byte written so far, which is the file's hash."""
        return self._hash.hexdigest()

    def discard(self) -> None:
        """Close and remove a journal into which nothing has been written (nothing was changed)."""
        self.close()
        with contextlib.suppress(OSError):
            self.path.unlink()

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
