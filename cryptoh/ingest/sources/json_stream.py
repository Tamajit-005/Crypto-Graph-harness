"""NDJSON edge-stream source: one {"src","dst"[,"weight"]} object per line."""

from __future__ import annotations

import json

from cryptoh.ingest.sources.base import Edge

name = "json"


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
            if not isinstance(obj, dict):
                continue
            src, dst = obj.get("src"), obj.get("dst")
            if not (isinstance(src, str) and src and isinstance(dst, str) and dst):
                continue
            edges.append(
                Edge(
                    src=src,
                    dst=dst,
                    weight=float(obj.get("weight", 1.0)),
                    raw=line,
                )
            )
    return edges
