# Gemma 4 Payload Contract

Gemma 4 receives:

1. PNG image of the anomaly subgraph (dark theme, red anomalous edges, magenta anomalous nodes).
2. DOT/Graphviz text of the same subgraph.
3. Filtered log lines for anomalous nodes only (last 60s, PII-scrubbed).
4. Spectral signal strength as a 0-1 float.

Response must be JSON with keys: `diagnosis`, `root_cause`, `confidence` (`spectral`, `log`, `total`), `mitigation` (`type`, `script`, `explanation`).
