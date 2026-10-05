"""eBPF socket-trace source — NDJSON socket events.

Accepts one JSON object per line with either ``saddr``/``daddr`` or
``src``/``dst`` keys, plus an optional ``bytes``/``weight`` field.
Malformed lines are skipped.
"""

from __future__ import annotations

import json

from cryptoh.ingest.sources.base import Edge

name = "ebpf"


def parse_obj(obj: dict) -> Edge | None:
    src = obj.get("src", obj.get("saddr"))
    dst = obj.get("dst", obj.get("daddr"))
    if not (isinstance(src, str) and src and isinstance(dst, str) and dst):
        return None
    weight = obj.get("weight", obj.get("bytes", 1.0))
    try:
        w = float(weight)
    except (TypeError, ValueError):
        w = 1.0
    return Edge(src=src, dst=dst, weight=w, raw=json.dumps(obj))


def edges_from_path(path: str) -> list[Edge]:
    edges: list[Edge] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                edge = parse_obj(obj)
                if edge is not None:
                    edges.append(edge)
    return edges
