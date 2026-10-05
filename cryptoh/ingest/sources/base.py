from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    weight: float = 1.0
    raw: str = ""
    timestamp: str = ""


class Source(Protocol):
    name: str

    def edges_from_path(self, path: str) -> list[Edge]: ...
