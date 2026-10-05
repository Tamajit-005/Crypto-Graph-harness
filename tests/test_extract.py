import numpy as np
from scipy import sparse

from cryptoh.extract.dot_render import to_dot
from cryptoh.extract.png_render import save_png
from cryptoh.extract.subgraph import extract


def test_extract_caps_k():
    A = sparse.csr_matrix(np.ones((12, 12)) - np.eye(12))
    ids = [f"n{i}" for i in range(12)]
    fiedler = np.arange(12, dtype=float)
    sub = extract(A, ids, fiedler, outlier_nodes=["n3"], k=8)
    assert len(sub["nodes"]) <= 8 and "n3" in sub["nodes"]
    dot = to_dot(sub)
    assert "digraph" in dot and "n3" in dot


def test_extract_empty_safe():
    A = sparse.csr_matrix((4, 4), dtype=float)
    sub = extract(A, ["a", "b", "c", "d"], np.zeros(4), outlier_nodes=[], k=8)
    assert isinstance(sub["nodes"], list)


def test_png_written(tmp_path):
    import networkx as nx
    G = nx.path_graph(["a", "b", "c"])
    out = save_png(G, ["b"], str(tmp_path / "t.png"))
    assert out.endswith(".png")
