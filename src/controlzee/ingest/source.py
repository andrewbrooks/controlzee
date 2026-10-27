"""Where log files come from. Local files now; S3 and CloudTrail event history plug in here (milestone 1.5)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class Source(Protocol):
    """One log file. Must be picklable: sources are sent to worker processes."""

    @property
    def rel(self) -> str:
        """Name relative to its input root; never an absolute path."""
        ...

    @property
    def size(self) -> int: ...

    def read(self) -> bytes: ...


@dataclass(frozen=True)
class LocalSource:
    rel: str
    path: str
    size: int

    def read(self) -> bytes:
        return Path(self.path).read_bytes()
