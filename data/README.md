# Demo telemetry (synthetic, Apache-2.0)

`nginx_normal.log` — ~2600 lines of benign nginx combined-log traffic across
12 client IPs and 8 services (api, auth, billing, inventory, search, profile,
cart, checkout). Generated with a fixed seed; no real hosts or users.

`nginx_c2_attack.log` — the same benign traffic plus a 600-line attack block
interleaved at the tail: host `10.0.0.14` and mesh nodes `10.0.0.21-25`
beaconing `GET /c2/beacon`. The late 200-line windows therefore contain a
disconnected C2 component: algebraic connectivity λ_2 collapses to ~0.000
and zero-eigenvalue multiplicity rises 1 → 2, so 2-of-3 detectors fire.

All IPs, paths, timestamps, and user-agents are fabricated for local demo
use only. Licensed under Apache-2.0 like the rest of this repo.
