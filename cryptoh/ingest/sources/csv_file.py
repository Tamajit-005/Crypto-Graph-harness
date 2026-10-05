"""CSV edge-list source with src,dst[,weight] columns."""

from __future__ import annotations

import csv

from cryptoh.ingest.sources.base import Edge

name = "csv"


def edges_from_path(path: str) -> list[Edge]:
    edges: list[Edge] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        missing = [c for c in ("src", "dst") if c not in fields]
        if missing:
            raise ValueError(f"missing required columns: {', '.join(missing)}")
        for row in reader:
            edges.append(
                Edge(
                    src=row["src"],
                    dst=row["dst"],
                    weight=float(row.get("weight", 1.0) or 1.0),
                    raw=str(row),
                )
            )
    return edges
