"""Shared spectral analysis pipeline used by the CLI and the web API.

Pure computation: no I/O, no LLM calls, no printing. Given a list of
edges, splits them into windows, builds the interaction graph per
window, computes the normalized Laplacian spectrum, runs the three
spectral detectors with the 2-of-3 rule, and extracts the anomaly
subgraph (nodes, edges, DOT, raw logs) for anomalous windows.
"""

from __future__ import annotations

from cryptoh.extract.dot_render import to_dot
from cryptoh.extract.subgraph import extract
from cryptoh.ingest.graph_builder import build_matrix
from cryptoh.ingest.sources.base import Edge
from cryptoh.spectral.baseline import Baseline
from cryptoh.spectral.clustering import detect as cluster_detect
from cryptoh.spectral.fiedler import detect as fiedler_detect
from cryptoh.spectral.laplacian import normalized_laplacian, smallest_eigenpairs
from cryptoh.spectral.multiplicity import detect as mult_detect
from cryptoh.spectral.multiplicity import multiplicity
from cryptoh.spectral.rule import combine


def analyze_window(
    chunk: list[Edge],
    baseline: Baseline,
    window_no: int,
    delta: float = 0.20,
) -> dict:
    """Analyze one window against a caller-owned baseline (single window)."""
    matrix, node_ids = build_matrix(chunk)
    count = len(node_ids)
    if count < 3:
        return {"window": window_no, "n": count, "m": len(chunk), "lambda2": 0.0,
                "mult": 1, "status": "normal", "reason": "tiny graph"}
    lap = normalized_laplacian(matrix)
    vals, vecs = smallest_eigenpairs(lap, k=min(8, count - 1))
    lambda2 = float(vals[1]) if len(vals) > 1 else 0.0
    mult = multiplicity(vals)
    embedding = vecs[:, 1:]
    if not baseline.ready:
        baseline.update(lambda2, mult)
        return {"window": window_no, "n": count, "m": len(chunk), "lambda2": lambda2,
                "mult": mult, "status": "baseline"}
    fiedler = fiedler_detect(baseline.lambda2, lambda2, delta=delta)
    mult_sig = mult_detect(baseline.mult, mult)
    cluster = cluster_detect(embedding, node_ids)
    decision = combine([fiedler["fired"], mult_sig["fired"], cluster["fired"]])
    baseline.update(lambda2, mult)
    record: dict = {
        "window": window_no, "n": count, "m": len(chunk), "lambda2": lambda2,
        "mult": mult, "baseline_lambda2": baseline.lambda2,
        "baseline_mult": baseline.mult, "fiedler": fiedler, "mult_sig": mult_sig,
        "cluster": cluster, "votes": decision["votes"],
        "status": "ANOMALY" if decision["anomaly"] else "normal",
    }
    if decision["anomaly"]:
        fiedler_vec = vecs[:, 1] if vecs.shape[1] > 1 else vecs[:, 0] * 0.0
        outliers = list(cluster.get("nodes", []))
        sub = extract(matrix, node_ids, fiedler_vec, outlier_nodes=outliers, k=8)
        record["subgraph"] = sub
        record["outliers"] = outliers
        record["dot"] = to_dot(sub, anomalous_nodes=outliers or sub["nodes"])
        record["logs"] = [e.raw for e in chunk if e.raw][:30]
    return record


def analyze_windows(
    edges: list[Edge],
    window_lines: int = 200,
    baseline_windows: int = 12,
    delta: float = 0.20,
    adaptive: bool = False,
) -> list[dict]:
    baseline = Baseline(warmup_windows=baseline_windows, adaptive=adaptive)
    results: list[dict] = []
    for index in range(0, len(edges), window_lines):
        chunk = edges[index:index + window_lines]
        results.append(
            analyze_window(chunk, baseline, index // window_lines, delta=delta)
        )
    return results
