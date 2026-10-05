from cryptoh.llm.fallback import diagnose as fallback_diagnose
from cryptoh.llm.parser import parse_json_response


def test_parser_handles_fences():
    out = parse_json_response('```json\n{"a": 1}\n```')
    assert out == {"a": 1}


def test_parser_invalid_returns_text_shape():
    out = parse_json_response("not json at all")
    assert "diagnosis" in out


def test_fallback_needs_no_key():
    d = fallback_diagnose(dot="digraph {}", logs=["l1"], spectral_strength=0.7, nodes=["x"])
    assert d["confidence"]["total"] >= 0 and "mitigation" in d


def test_prompt_formats():
    from cryptoh.llm.prompts.diagnose import DIAGNOSE_PROMPT

    p = DIAGNOSE_PROMPT.format(dot="DOT", logs="LOGS", spectral_strength=0.5)
    assert "DOT" in p and "LOGS" in p


def test_scrub_redacts_ip_and_secret():
    from cryptoh.llm.scrub import scrub_pii
    out = scrub_pii(['10.0.0.14 - "GET /x" Bearer abc123'])
    assert "10.0.0.14" not in out[0] and "abc123" not in out[0]

def test_scrub_never_raises():
    from cryptoh.llm.scrub import scrub_pii
    assert scrub_pii([]) == []
