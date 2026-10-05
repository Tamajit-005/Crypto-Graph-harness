"""Route helpers shared by the API routers (no FastAPI imports here)."""

from __future__ import annotations

from cryptoh.config import settings
from cryptoh.core.analysis import analyze_windows
from cryptoh.ingest.sources.base import Edge
from cryptoh.llm.fallback import diagnose as fallback_diagnose
from cryptoh.llm.gemma import diagnose_live
from cryptoh.llm.parser import parse_json_response
from cryptoh.llm.prompts.diagnose import DIAGNOSE_PROMPT
from cryptoh.llm.scrub import scrub_pii
from cryptoh.mitigate import render as render_template
from cryptoh.mitigate import validate_iptables
from cryptoh.web import state


def diagnose_edges(items: list[dict]) -> dict:
    """Run the full pipeline over posted edges and update server state."""
    edges = [
        Edge(src=str(it.get("src", "")), dst=str(it.get("dst", "")),
             weight=float(it.get("weight", 1.0)),
             raw=str(it.get("raw", "")))
        for it in items
        if isinstance(it, dict) and it.get("src") and it.get("dst")
    ]
    if len(edges) < 12:
        return {"ok": False, "error": "post at least 12 edges with src/dst"}
    window_lines = max(3, len(edges) // 4)
    results = analyze_windows(edges, window_lines=window_lines, baseline_windows=3)
    anomalies = [r for r in results if r["status"] == "ANOMALY"]
    latest = results[-1]
    state.last_detection = {
        "anomaly": latest["status"] == "ANOMALY",
        "votes": int(latest.get("votes", 0)),
        "signals": {
            "lambda2": latest.get("lambda2", 0.0),
            "multiplicity": latest.get("mult", 1),
        },
        "windows": len(results),
        "anomalies": len(anomalies),
        "note": ("anomaly in latest window" if latest["status"] == "ANOMALY"
                 else f"latest window normal ({len(anomalies)} anomalies total)"),
    }
    out_anomalies = []
    for r in anomalies:
        nodes = list(r["subgraph"]["nodes"])
        logs = scrub_pii(r.get("logs", []))
        strength = r["votes"] / 3.0
        if settings.gemini_api_key:
            prompt = DIAGNOSE_PROMPT.format(
                dot=r["dot"], logs="\n".join(logs),
                spectral_strength=f"{strength:.2f}")
            try:
                diagnosis = parse_json_response(
                    diagnose_live(settings.gemini_api_key, prompt))
            except RuntimeError:
                diagnosis = fallback_diagnose(
                    dot=r["dot"], logs=logs,
                    spectral_strength=strength, nodes=nodes)
        else:
            diagnosis = fallback_diagnose(
                dot=r["dot"], logs=logs,
                spectral_strength=strength, nodes=nodes)
        mitigation = diagnosis.get("mitigation", {}) if isinstance(diagnosis, dict) else {}
        script = mitigation.get("script", "") if isinstance(mitigation, dict) else ""
        validated = bool(script) and all(
            validate_iptables(ln).get("valid", False)
            for ln in script.splitlines() if ln.strip()
        )
        if not script and nodes:
            script = render_template("iptables_drop.j2", attacker_ip=nodes[0], service="any")
            mitigation = {"type": "iptables", "script": script,
                          "explanation": "Rendered fallback template."}
            validated = True
        aid = state.next_id()
        state.mitigations[aid] = {"type": mitigation.get("type", "iptables"),
                                  "script": script,
                                  "explanation": mitigation.get("explanation", ""),
                                  "validated": validated,
                                  "nodes": nodes,
                                  "dot": r.get("dot", "")}
        out_anomalies.append({
            "id": aid,
            "window": r["window"],
            "nodes": nodes,
            "signals": {"lambda2": r["lambda2"], "multiplicity": r["mult"],
                        "votes": r["votes"]},
            "dot": r["dot"],
            "diagnosis": diagnosis if isinstance(diagnosis, dict)
            else {"diagnosis": str(diagnosis)},
            "mitigation_id": aid,
            "validated": validated,
        })
    return {"ok": True, "summary": state.last_detection, "anomalies": out_anomalies,
            "windows": [{"window": r["window"], "n": r["n"], "m": r["m"],
                         "lambda2": round(r["lambda2"], 4),
                         "status": r["status"]} for r in results]}
