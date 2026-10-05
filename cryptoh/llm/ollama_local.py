"""Local Ollama client for Gemma 4 (air-gapped / no-API-key mode)."""
from __future__ import annotations

import json
import urllib.request
import urllib.error


def diagnose_local(endpoint: str, prompt: str, png_bytes: bytes | None = None, model: str = "gemma3:27b") -> str:
    """POST to a local Ollama `/api/generate` endpoint. Returns raw text."""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 512},
    }
    if png_bytes:
        payload["images"] = [png_bytes.decode("latin1")]
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint.rstrip("/") + "/api/generate",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return str(body.get("response", "")).strip()
    except (urllib.error.URLError, ValueError, OSError) as exc:
        raise RuntimeError(f"ollama request failed: {exc}") from exc
