# Mitigation Safety

Mitigation scripts are **never auto-applied**. Every script is:

1. Validated structurally before display.
2. Shown to the operator with a `y/N` prompt.
3. Logged to an append-only NDJSON audit trail.

Unvalidated scripts are displayed with a warning and never executed by the harness.
