"""Tumbling window accumulator over raw log lines."""

from __future__ import annotations

from cryptoh.ingest.sources.base import Edge
from cryptoh.ingest.sources.nginx_access_log import parse_line


class TumblingWindow:
    def __init__(self, seconds: float = 5.0) -> None:
        self.seconds = seconds
        self._lines: list[str] = []

    def add_raw(self, line: str) -> None:
        self._lines.append(line)

    def flush(self) -> list[Edge]:
        edges = [e for line in self._lines if (e := parse_line(line)) is not None]
        self._lines = []
        return edges

    def __len__(self) -> int:
        return len(self._lines)
