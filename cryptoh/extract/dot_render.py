"""Graphviz DOT writer (no graphviz binary required)."""
from __future__ import annotations


def to_dot(subgraph: dict, anomalous_nodes: list[str] | None = None) -> str:
    nodes = subgraph.get("nodes", [])
    edges = subgraph.get("edges", [])
    anom = set(anomalous_nodes or nodes)
    lines = ["digraph cryptoh {", '  rankdir=LR;', '  bgcolor="#0a0a0a";']
    for n in nodes:
        color = "#ff00ff" if n in anom else "#e6e6e6"
        lines.append(f'  "{n}" [color="{color}", fontcolor="{color}"];')
    for s, d, w in edges:
        color = "#ff0000" if (s in anom or d in anom) else "#555555"
        lines.append(f'  "{s}" -> "{d}" [label="{w:g}", color="{color}", fontcolor="{color}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"
