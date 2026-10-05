from cryptoh.config import Settings


def test_plain_gemini_key_honored(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "plain-key")
    monkeypatch.delenv("CRYPTOH_GEMINI_API_KEY", raising=False)
    assert Settings().gemini_api_key == "plain-key"


def test_prefixed_gemini_key_honored(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("CRYPTOH_GEMINI_API_KEY", "prefixed-key")
    assert Settings().gemini_api_key == "prefixed-key"


def test_model_override(monkeypatch):
    monkeypatch.setenv("CRYPTOH_MODEL", "custom-x")
    assert Settings().model == "custom-x"
