"""VPC flow-log source — AWS VPC flow log format (space separated).

Fields: version account-id interface-id srcaddr dstaddr srcport dstport
protocol packets bytes start end action log-status. Edge weight is the
packet count; header lines are skipped.
"""

from __future__ import annotations

from cryptoh.ingest.sources.base import Edge

name = "vpc"


def parse_line(line: str) -> Edge | None:
    parts = line.split()
    if len(parts) < 12 or parts[0] != "2":
        return None
    src, dst = parts[3], parts[4]
    if src == "-" or dst == "-":
        return None
    try:
        weight = float(parts[8])
    except (ValueError, IndexError):
        weight = 1.0
    return Edge(src=src, dst=dst, weight=weight, raw=line)


def edges_from_path(path: str) -> list[Edge]:
    edges: list[Edge] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            edge = parse_line(line.strip())
            if edge is not None:
                edges.append(edge)
    return edges
