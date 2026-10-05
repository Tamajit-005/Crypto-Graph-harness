"""iptables rule validator — allowlists safe append-only filter rules."""
from __future__ import annotations

import re
import shlex

_CHAINS = {"INPUT", "OUTPUT", "FORWARD"}
_TARGETS = {"DROP", "REJECT", "ACCEPT", "LOG"}
_DESTRUCTIVE = {"-F", "-X", "-P", "--flush", "--delete-chain"}
_PLACEHOLDER = re.compile(r"<\s*[A-Za-z_][A-Za-z0-9_.\-]*\s*>|\$\{[A-Za-z_][A-Za-z0-9_]*\}")


def has_unresolved_placeholder(script: str) -> bool:
    """True if the script still contains unfilled placeholders like <C2_IP> or ${ip}.

    Deliberately narrow: nginx and docker snippets legitimately contain `$vars`
    and braces, so only angle-bracket tokens and ${...} references count. A model
    that emits an unfilled placeholder produces a rule that parses but is
    meaningless (or harmful) when applied.
    """
    return bool(_PLACEHOLDER.search(script))


def validate(script: str) -> dict:
    """Validate a single iptables invocation. Returns {"valid", "reason"}; never raises."""
    if not isinstance(script, str):
        return {"valid": False, "reason": "input must be a string"}
    if has_unresolved_placeholder(script):
        return {"valid": False, "reason": "unresolved placeholder in script"}
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
