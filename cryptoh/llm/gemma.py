"""Gemma 4 via Gemini API (google-genai). Lazy import — never required at import time."""
from __future__ import annotations

MODEL_ID = "gemma-3-27b-it"


def diagnose_live(api_key: str, prompt: str, png_bytes: bytes | None = None) -> str:
    """Call Gemini API, return raw response text. Raises RuntimeError if lib/key missing."""
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
    response = client.models.generate_content(model=MODEL_ID, contents=contents)
    return response.text or ""
