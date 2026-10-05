"""Dark-theme PNG topology renderer (matplotlib Agg)."""
from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx


def save_png(G: nx.Graph, anomalous_nodes: list[str], path: str) -> str:
    anom = set(anomalous_nodes)
    pos = nx.spring_layout(G, seed=7)
    fig, ax = plt.subplots(figsize=(10, 7.5), dpi=100)
    fig.patch.set_facecolor("#0a0a0a")
    ax.set_facecolor("#0a0a0a")
    node_colors = ["#ff00ff" if n in anom else "#00ffff" for n in G.nodes]
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors, node_size=500, edgecolors="#e6e6e6")
    nx.draw_networkx_labels(G, pos, ax=ax, font_color="#e6e6e6", font_size=8)
    edge_colors = ["#ff0000" if (u in anom or v in anom) else "#555555" for u, v in G.edges]
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color=edge_colors, width=1.5)
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(path, facecolor="#0a0a0a")
    plt.close(fig)
    return path

def save_subgraph_png(subgraph: dict, path: str) -> str:
    """Convenience: build a DiGraph from an extract() dict and render it."""
    G = nx.DiGraph()
    G.add_nodes_from(subgraph.get("nodes", []))
    for s, d, w in subgraph.get("edges", []):
        G.add_edge(s, d, weight=w)
    return save_png(G, list(subgraph.get("nodes", [])), path)
