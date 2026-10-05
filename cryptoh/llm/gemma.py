"""Gemma 4 via Gemini API (google-genai). Lazy import — never required at import time."""
from __future__ import annotations

import time

MODEL_ID = "gemma-4-26b-a4b-it"
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = 1.5


def diagnose_live(
    api_key: str,
    prompt: str,
    png_bytes: bytes | None = None,
    model: str | None = None,
    attempts: int = MAX_ATTEMPTS,
) -> str:
    """Call Gemini API, return raw response text.

    Raises RuntimeError when the key or the SDK is missing. Transient upstream
    failures (5xx, rate limits, timeouts) are retried with backoff; a persistent
    failure re-raises as RuntimeError so callers can fall back instead of crashing.
    """
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set")
    try:
        from google import genai
        from google.genai import types
    except ImportError as e:
        raise RuntimeError("google-genai is not installed") from e
    client = genai.Client(api_key=api_key)
    contents: list = [prompt]
    if png_bytes:
        contents.append(types.Part.from_bytes(data=png_bytes, mime_type="image/png"))
    last: Exception | None = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            response = client.models.generate_content(model=model or MODEL_ID, contents=contents)
            return response.text or ""
        except Exception as exc:  # noqa: BLE001 - SDK raises several unrelated types
            last = exc
            if attempt >= max(1, attempts):
                break
            time.sleep(BACKOFF_SECONDS * attempt)
    raise RuntimeError(f"model call failed after {attempts} attempt(s): {last}") from last
