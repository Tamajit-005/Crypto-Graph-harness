"""iptables rule validator — allowlists safe append-only filter rules."""
from __future__ import annotations

import shlex

_CHAINS = {"INPUT", "OUTPUT", "FORWARD"}
_TARGETS = {"DROP", "REJECT", "ACCEPT", "LOG"}
_DESTRUCTIVE = {"-F", "-X", "-P", "--flush", "--delete-chain"}


def validate(script: str) -> dict:
    """Validate a single iptables invocation. Returns {"valid", "reason"}; never raises."""
    if not isinstance(script, str):
        return {"valid": False, "reason": "input must be a string"}
    try:
        argv = shlex.split(script)
    except ValueError as exc:
        return {"valid": False, "reason": f"unparseable: {exc}"}
    if not argv or argv[0] != "iptables":
        return {"valid": False, "reason": "must start with iptables"}
    if any(tok in _DESTRUCTIVE for tok in argv):
        return {"valid": False, "reason": "destructive flag rejected"}
    if "-A" not in argv:
        return {"valid": False, "reason": "missing -A <chain>"}
    chain = argv[argv.index("-A") + 1] if argv.index("-A") + 1 < len(argv) else ""
    if chain not in _CHAINS:
        return {"valid": False, "reason": f"unsupported chain: {chain!r}"}
    if "-j" not in argv:
        return {"valid": False, "reason": "missing -j <target>"}
    target = argv[argv.index("-j") + 1] if argv.index("-j") + 1 < len(argv) else ""
    if target not in _TARGETS:
        return {"valid": False, "reason": f"unsupported target: {target!r}"}
    if "-s" not in argv and "-d" not in argv:
        return {"valid": False, "reason": "missing -s or -d address"}
    return {"valid": True, "reason": "ok"}
