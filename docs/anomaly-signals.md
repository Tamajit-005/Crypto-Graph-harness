# Anomaly Signals

| Signal | What it catches | Theory |
|---|---|---|
| Fiedler `λ_2` drop | Bipartition formation / algebraic connectivity drop | Fiedler (1973) |
| Zero-eigenvalue multiplicity | New isolated cluster / disconnected component | Chung (1997) |
| Spectral clustering outlier | Dense subgraph emergence within a component | Ng-Jordan-Weiss (2002) |

A real attack typically triggers all three; benign traffic spikes typically trigger only one. The 2-of-3 rule suppresses false positives to near-zero.
