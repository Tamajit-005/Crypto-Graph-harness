"""Tests for the model-call layer: retry, error containment, PNG attachment."""
import pytest

from cryptoh.llm import gemma as gemma_mod
from cryptoh.llm.fallback import diagnose as fallback_diagnose
from cryptoh.llm.gemma import diagnose_live
from cryptoh.mitigate import validate_mitigation
from cryptoh.mitigate.iptables import has_unresolved_placeholder


def test_missing_key_raises_runtime_error():
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY"):
        diagnose_live("", "prompt")


class _FakeClient:
    """Stands in for google.genai.Client with a scripted failure sequence."""

    def __init__(self, failures: int):
        self.failures = failures
        self.calls = 0
        self.last_contents = None

    def _make(self):
        outer = self

        class Models:
            def generate_content(self, model, contents):
                outer.calls += 1
                outer.last_contents = contents
                if outer.calls <= outer.failures:
                    raise RuntimeError("upstream 500")
                return type("R", (), {"text": '{"diagnosis": "ok"}'})()

        return type("C", (), {"models": Models()})()


@pytest.fixture
def fake_sdk(monkeypatch):
    def install(failures: int):
        client = _FakeClient(failures)
        module = type("M", (), {})
        module.Client = lambda api_key=None: client._make()
        module.types = type("T", (), {"Part": type("P", (), {
            "from_bytes": staticmethod(lambda data, mime_type: {"bytes": data, "mime": mime_type})
        })})
        monkeypatch.setitem(__import__("sys").modules, "google.genai", module)
        monkeypatch.setitem(__import__("sys").modules, "google", type("G", (), {"genai": module}))
        monkeypatch.setattr(gemma_mod, "BACKOFF_SECONDS", 0)
        return client
    return install


def test_retries_transient_failure_then_succeeds(fake_sdk):
    client = fake_sdk(failures=2)
    out = diagnose_live("key", "prompt", attempts=3)
    assert out == '{"diagnosis": "ok"}'
    assert client.calls == 3


def test_persistent_failure_raises_runtime_error(fake_sdk):
    client = fake_sdk(failures=99)
    with pytest.raises(RuntimeError, match="attempt"):
        diagnose_live("key", "prompt", attempts=2)
    assert client.calls == 2, "must stop after the attempt budget"


def test_png_bytes_are_attached(fake_sdk):
    client = fake_sdk(failures=0)
    png = b"\x89PNG\r\n\x1a\n-fake"
    diagnose_live("key", "prompt", png)
    contents = client.last_contents
    assert len(contents) == 2
    assert contents[0] == "prompt"
    assert contents[1]["bytes"] == png
    assert contents[1]["mime"] == "image/png"


def test_no_png_means_text_only(fake_sdk):
    client = fake_sdk(failures=0)
    diagnose_live("key", "prompt")
    assert client.last_contents == ["prompt"]


def test_diagnose_falls_back_instead_of_crashing(monkeypatch):
    """A model outage must degrade to the heuristic, never abort the run."""
    from cryptoh.cli import _diagnose

    monkeypatch.setattr("cryptoh.cli.settings.gemini_api_key", "key", raising=False)
    monkeypatch.setattr("cryptoh.cli.diagnose_live",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("500")))
    out = _diagnose("digraph {}", ["l1"], 0.67, ["10.0.0.14"], b"png")
    assert "Heuristic (offline)" in out["diagnosis"]
    assert "mitigation" in out


def test_fallback_shape_matches_prompt_contract():
    out = fallback_diagnose(dot="digraph {}", logs=["GET /c2/x"], spectral_strength=0.7,
                            nodes=["10.0.0.14"])
    assert set(out) >= {"diagnosis", "root_cause", "confidence", "mitigation"}
    assert set(out["confidence"]) >= {"spectral", "log", "total"}


def test_placeholder_detection():
    assert has_unresolved_placeholder("iptables -d <C2_IP> -j DROP")
    assert has_unresolved_placeholder("iptables -d ${ip} -j DROP")
    assert not has_unresolved_placeholder("iptables -A INPUT -s 10.0.0.14 -j DROP")


def test_validate_mitigation_rejects_placeholder():
    res = validate_mitigation("iptables", "iptables -A OUTPUT -d <C2_IP> -j DROP")
    assert res["valid"] is False
    assert "placeholder" in res["reason"]


def test_validate_mitigation_dispatches_on_type():
    nginx = "limit_req_zone $binary_remote_addr zone=c:10m rate=5r/s;"
    assert validate_mitigation("nginx", nginx)["valid"] is True
    # previously every type was run through the iptables validator and rejected
    assert validate_mitigation("iptables", nginx)["valid"] is False
    k8s = "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nspec:\n  podSelector: {}\n"
    assert validate_mitigation("k8s", k8s)["valid"] is True


def test_validate_mitigation_multiline_iptables():
    script = ("iptables -A INPUT -s 10.0.0.14 -j DROP\n"
              "iptables -A OUTPUT -d 10.0.0.14 -j DROP\n")
    assert validate_mitigation("iptables", script)["valid"] is True
    bad = script + "iptables -F\n"
    assert validate_mitigation("iptables", bad)["valid"] is False


def test_validate_mitigation_empty_and_garbage():
    assert validate_mitigation("iptables", "")["valid"] is False
    assert validate_mitigation("iptables", "rm -rf /")["valid"] is False
    assert validate_mitigation("nginx", "deny all;")["valid"] is True
