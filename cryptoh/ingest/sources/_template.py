"""Example source adapter.

Copy this module to add a new source (e.g. ``my_source.py``):
rename ``name``, adapt ``parse_line`` to the new line format, and
keep ``edges_from_path`` reading the file line by line. Register
the new import in ``cryptoh.ingest`` if it should be re-exported.
"""

from __future__ import annotations

from cryptoh.ingest.sources.base import Edge

name = "template"


def parse_line(line: str) -> Edge | None:
    """Parse ``src -> dst`` lines; return None for blank or malformed lines."""
    if "->" not in line:
        return None
    left, _, right = line.partition("->")
    src, dst = left.strip(), right.strip()
    if not src or not dst:
        return None
    return Edge(src=src, dst=dst, weight=1.0, raw=line)


def edges_from_path(path: str) -> list[Edge]:
    edges: list[Edge] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            edge = parse_line(line.rstrip("\n"))
            if edge is not None:
                edges.append(edge)
    return edges
