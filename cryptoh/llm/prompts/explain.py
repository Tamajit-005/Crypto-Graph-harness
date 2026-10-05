"""Operator-explanation template — plain-language summary of an anomaly event."""

EXPLAIN_PROMPT = """You are an on-call analyst explaining an incident to an operator
who is not a graph-theory specialist.

SPECTRAL EVIDENCE:
{evidence}

DIAGNOSIS:
{diagnosis}

Write three short sentences, no jargon:
1. What happened, in plain terms.
2. Which host or service to look at first, and why.
3. What the suggested mitigation does.

Keep it under 80 words. No JSON, just the explanation.
"""
