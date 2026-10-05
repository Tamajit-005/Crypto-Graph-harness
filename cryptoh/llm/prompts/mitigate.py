"""Mitigation prompt template — turns a diagnosis into a ready-to-apply script."""

MITIGATE_PROMPT = """You are a senior infrastructure engineer writing a safe, minimal
network mitigation for an incident that has already been diagnosed.

DIAGNOSIS:
{diagnosis}

AFFECTED NODES:
{nodes}

CONSTRAINTS:
- Output exactly one mitigation script, nothing else wrapped around it.
- Prefer append-only, reversible rules (block the attacker, never flush tables).
- Never include destructive commands (no flush, no delete-chain, no default-policy change).
- Add a one-line comment stating the target host or network.
- Respond with JSON ONLY using these keys: type, script, explanation.

Types: one of iptables, docker, k8s, nginx.
"""
