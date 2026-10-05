"""Syslog source — parses syslog files for host-to-host pairs.

Understands ``src=<ip> dst=<ip>`` pairs, ``a -> b`` pairs, and falls
back to the first two IPv4 addresses on the line. Lines without at
least two addresses are skipped; the raw line is always preserved.
"""

from __future__ import annotations

import re

from cryptoh.ingest.sources.base import Edge

name = "syslog"

_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_PAIR = re.compile(r"src=(\S+)\s+dst=(\S+)")


def parse_line(line: str) -> Edge | None:
    m = _PAIR.search(line)
    if m:
        return Edge(src=m.group(1), dst=m.group(2), weight=1.0, raw=line)
    if "->" in line:
        left, _, right = line.partition("->")
        src_ips, dst_ips = _IP.findall(left), _IP.findall(right)
        if src_ips and dst_ips:
            return Edge(src=src_ips[0], dst=dst_ips[0], weight=1.0, raw=line)
    ips = _IP.findall(line)
    if len(ips) >= 2:
        return Edge(src=ips[0], dst=ips[1], weight=1.0, raw=line)
    return None


def edges_from_path(path: str) -> list[Edge]:
    edges: list[Edge] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            edge = parse_line(line.rstrip("\n"))
            if edge is not None:
                edges.append(edge)
    return edges
