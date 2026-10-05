"""Nginx combined access-log source."""

from __future__ import annotations

import re

from cryptoh.ingest.sources.base import Edge

name = "nginx"

PATTERN = re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)')


def parse_line(line: str) -> Edge | None:
    m = PATTERN.match(line)
    if not m:
        return None
    path = m.group("path")
    dst = path.strip("/").split("/")[0] or "/"
    return Edge(src=m.group("ip"), dst=dst, weight=1.0, raw=line)


def edges_from_path(path: str) -> list[Edge]:
    edges: list[Edge] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            edge = parse_line(line)
            if edge is not None:
                edges.append(edge)
    return edges
