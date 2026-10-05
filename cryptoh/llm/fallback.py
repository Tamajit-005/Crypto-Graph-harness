"""Offline heuristic diagnosis — no API key, no network. Deterministic."""
from __future__ import annotations

import re
from collections import Counter


def diagnose(dot: str, logs: list[str], spectral_strength: float, nodes: list[str]) -> dict:
    dests = Counter()
    for line in logs:
        m = re.search(r'"[A-Z]+\s+(\S+)', line)
        if m:
            dests[m.group(1)] += 1
    top, count = dests.most_common(1)[0] if dests else ("unknown", 0)
    if len(dests) == 1 and count >= 3:
        pattern = f"low-rate beaconing against {top} ({count} hits)"
    elif len(nodes) >= 5:
        pattern = f"fan-out from {nodes[0]} to {len(nodes) - 1} peers"
    else:
        pattern = "anomalous dense subgraph"
    total = round(max(0.0, min(1.0, 0.5 * spectral_strength + 0.3)), 2)
    attacker = nodes[0] if nodes else "unknown"
    return {
        "diagnosis": f"Heuristic (offline): {pattern}.",
        "root_cause": f"Patient zero candidate: {attacker}.",
        "confidence": {"spectral": round(spectral_strength, 2), "log": 0.3, "total": total},
        "mitigation": {
            "type": "iptables",
            "script": f"iptables -A INPUT -s {attacker} -j DROP\niptables -A OUTPUT -d {attacker} -j DROP",
            "explanation": "Isolate the candidate host pending review.",
        },
    }
