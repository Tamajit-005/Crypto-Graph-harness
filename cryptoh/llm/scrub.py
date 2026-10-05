"""PII / secret scrubber — runs before any LLM call. Never raises."""
from __future__ import annotations

import re

_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_EMAIL = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_BEARER = re.compile(r"(?i)(bearer\s+[a-zA-Z0-9\-._~+/=]+|api[_-]?key\s*[:=]\s*\S+)")

def scrub_pii(lines: list[str]) -> list[str]:
    out = []
    for line in lines:
        line = _IP.sub("[REDACTED-IP]", line)
        line = _EMAIL.sub("[REDACTED-EMAIL]", line)
        line = _BEARER.sub("[REDACTED-SECRET]", line)
        out.append(line)
    return out
