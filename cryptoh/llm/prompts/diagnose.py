"""Diagnosis prompt template (PRD section 6.2)."""

DIAGNOSE_PROMPT = """You are a senior security analyst investigating a crypto-mining botnet or C2 incident.

Tasks:
A. Identify the attack pattern (e.g. low-rate beaconing, fan-out, dense C2 mesh).
B. Determine the root cause and patient zero host.
C. Report confidence as a 0-1 score decomposed into spectral and log components.
D. Provide a mitigation script of one of these types: iptables, docker, k8s, nginx.
E. Respond with JSON ONLY using these keys: diagnosis, root_cause, confidence (with spectral, log, total), mitigation (with type, script, explanation).

NOTE: A GRAPH IMAGE of the suspect subgraph is attached alongside this prompt when available; correlate it with the DOT data below.

DOT:
{dot}

LOGS:
{logs}

SPECTRAL SIGNAL STRENGTH:
{spectral_strength}
"""
