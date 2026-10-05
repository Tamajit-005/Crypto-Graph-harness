"""Tests for real-time ingestion: file tailer, web tailer, SSE payload."""
import json
import subprocess
import sys
import textwrap
import time

from fastapi.testclient import TestClient

from cryptoh.ingest.tailer import collect_follower
from cryptoh.web import server as server_mod
from cryptoh.web.tailer import FileTailer, tailer_from_env

_LINE = ('{ip} - - [05/Oct/2026:10:00:02 +0000] "GET {path} HTTP/1.1" 200 3437 '
         '"-" "curl/7.81"')
BENIGN = _LINE.format(ip="10.0.0.6", path="/api/v1/health")
BEACON = _LINE.format(ip="10.0.0.14", path="/c2/beacon?id=14")

_CLIENTS = [f"10.0.0.{i}" for i in range(1, 9)]
_SERVICES = ["api", "auth", "billing", "inventory", "search", "profile", "cart"]


def benign_lines(n: int) -> list[str]:
    """n deterministic benign lines spanning several clients and services.

    Variety matters: a graph of one client and one service has <3 nodes and is
    skipped by the spectral layer as a tiny graph.
    """
    out = []
    for i in range(n):
        ip = _CLIENTS[i % len(_CLIENTS)]
        svc = _SERVICES[i % len(_SERVICES)]
        out.append(_LINE.format(ip=ip, path=f"/{svc}/v1/ping"))
    return out


def beacon_lines(n: int) -> list[str]:
    """n beacon lines from a mesh of hosts to an isolated C2 endpoint."""
    return [_LINE.format(ip=f"10.0.0.{i}", path="/c2/beacon")
            for i in [14, 21, 22, 23, 24, 25] for _ in range(n // 6 + 1)][:n]


def mixed_attack_window(n: int = 200) -> list[str]:
    """Benign traffic interleaved with the C2 beacon mesh.

    The beacon endpoint shares no node with the benign services, so the window
    contains two components: zero-eigenvalue multiplicity rises 1 -> 2 and λ₂
    collapses, which is what the 2-of-3 rule keys on. A pure beacon star is a
    single connected component and legitimately does NOT fire — documented so a
    future edit does not "fix" that case by weakening the detectors.
    """
    beacons = beacon_lines(n // 2)
    return benign_lines(n - len(beacons)) + beacons


def test_follow_lines_reads_existing_content(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("\n".join([BENIGN] * 5) + "\n")
    got = collect_follower([str(f)], max_lines=5, timeout=5.0, poll_seconds=0.05)
    assert got == [BENIGN] * 5


def test_follow_lines_from_end_skips_existing(tmp_path):
    f = tmp_path / "b.log"
    f.write_text("\n".join([BENIGN] * 4) + "\n")
    got = collect_follower([str(f)], max_lines=1, timeout=1.0,
                           poll_seconds=0.05, from_end=True)
    assert got == [], "from_end must not replay existing lines"


def test_follow_lines_picks_up_appends_live(tmp_path):
    """A child process appends after the follower starts: proves real tailing."""
    f = tmp_path / "live.log"
    f.write_text("")
    script = textwrap.dedent(f"""
        import time, pathlib
        time.sleep(1.0)
        with open({str(f)!r}, "a") as fh:
            for _ in range(3):
                fh.write({BEACON!r} + "\\n")
                fh.flush()
                time.sleep(0.2)
    """)
    proc = subprocess.Popen([sys.executable, "-c", script])
    try:
        got = collect_follower([str(f)], max_lines=3, timeout=12.0, poll_seconds=0.1)
    finally:
        proc.wait(timeout=10)
    assert len(got) == 3, f"expected 3 appended lines, got {len(got)}"


def test_follow_lines_handles_rotation(tmp_path):
    f = tmp_path / "c.log"
    f.write_text("\n".join([BENIGN] * 3) + "\n")
    got = collect_follower([str(f)], max_lines=3, timeout=5.0, poll_seconds=0.05)
    assert got == [BENIGN] * 3
    # rotate to a new, shorter inode; the follower must not stall or duplicate
    f.unlink()
    f.write_text(BEACON + "\n")
    after = collect_follower([str(f)], max_lines=1, timeout=3.0, poll_seconds=0.05)
    assert BEACON in after, f"rotation lost data: {after}"


def test_web_tailer_produces_baseline_window(tmp_path):
    f = tmp_path / "live3.log"
    f.write_text("\n".join(benign_lines(200)) + "\n")
    t = FileTailer([str(f)], window_lines=200, baseline_windows=12, poll_seconds=0.05)
    results = t.ingest_lines(t.read_new_lines())
    assert len(results) == 1
    rec = results[0]
    assert rec["status"] == "baseline", rec
    assert rec["n"] >= 8 and rec["m"] == 200
    assert not t.baseline_ready


def test_web_tailer_fires_on_anomaly_window(tmp_path):
    """Baseline windows, then a beacon mesh appended live: 2-of-3 must fire."""
    f = tmp_path / "live4.log"
    f.write_text("\n".join(benign_lines(400)) + "\n")
    t = FileTailer([str(f)], window_lines=200, baseline_windows=2, poll_seconds=0.05)
    warm = t.ingest_lines(t.read_new_lines())
    assert [r["status"] for r in warm] == ["baseline", "baseline"]
    assert t.baseline_ready
    with f.open("a") as fh:
        fh.write("\n".join(mixed_attack_window(200)) + "\n")
    fired = t.ingest_lines(t.read_new_lines())
    assert len(fired) == 1
    rec = fired[0]
    assert rec["status"] == "ANOMALY", rec
    assert rec["votes"] >= 2
    assert rec["dot"].startswith("digraph")
    assert rec["subgraph"]["nodes"]


def test_web_tailer_publish_and_state(tmp_path):
    import asyncio

    from cryptoh.web import state

    f = tmp_path / "live5.log"
    f.write_text("\n".join(benign_lines(200)) + "\n")
    t = FileTailer([str(f)], window_lines=200, baseline_windows=12, poll_seconds=0.05)
    q = t.subscribe()

    async def run():
        rec = t.ingest_lines(t.read_new_lines())[0]
        t._publish_record(rec)
        return await asyncio.wait_for(q.get(), timeout=5.0)

    event, payload = asyncio.new_event_loop().run_until_complete(run())
    assert event == "window"
    assert payload["live"] is True
    assert payload["status"] == "baseline"
    assert isinstance(payload["lambda2"], float)
    assert state.last_detection["windows"] == 1


def test_tailer_from_env(tmp_path, monkeypatch):
    f = tmp_path / "e.log"
    f.write_text(BENIGN + "\n")
    monkeypatch.setenv("CRYPTOH_SOURCE", str(f))
    t = tailer_from_env()
    assert t is not None and t.followed == [str(f)]
    monkeypatch.setenv("CRYPTOH_SOURCE", str(tmp_path / "missing.log"))
    assert tailer_from_env() is None


def test_health_reports_live_ingestion(tmp_path, monkeypatch):
    f = tmp_path / "h.log"
    f.write_text("\n".join([BENIGN] * 400) + "\n")
    monkeypatch.setenv("CRYPTOH_SOURCE", str(f))
    with TestClient(server_mod.app) as client:
        body = client.get("/api/v1/health").json()
        assert body["status"] == "ok"
        assert body["live_ingestion"] is True
        assert body["following"] == [str(f)]
        # the tailer must actually consume the file it was pointed at
        for _ in range(60):
            if server_mod._tailer and server_mod._tailer[0]._window_no:
                break
            time.sleep(0.1)
        assert server_mod._tailer[0]._window_no, "tailer never ingested the log"
        assert server_mod._tailer[0].running


def test_health_without_source(monkeypatch):
    monkeypatch.delenv("CRYPTOH_SOURCE", raising=False)
    monkeypatch.delenv("CRYPTOH_WATCH", raising=False)
    with TestClient(server_mod.app) as client:
        body = client.get("/api/v1/health").json()
        assert body["live_ingestion"] is False
        assert body["following"] == []


def test_sse_anomaly_event_carries_diagnosis_and_mitigation():
    from cryptoh.web import state

    state.mitigations.clear()
    state.mitigations["aX"] = {
        "type": "iptables",
        "script": "iptables -A INPUT -s 10.0.0.14 -j DROP",
        "explanation": "isolate host",
        "validated": True,
        "nodes": ["10.0.0.14"],
        "dot": 'digraph cryptoh { "10.0.0.14" -> "c2" }',
        "diagnosis": {"diagnosis": "beaconing", "confidence": {"total": 0.95}},
    }
    state.last_detection = {
        "anomaly": True, "votes": 2,
        "signals": {"lambda2": 0.0, "multiplicity": 2},
        "windows": 13, "anomalies": 1, "note": "test",
    }
    events = dict(server_mod._state_events({}))
    assert "anomaly" in events
    payload = events["anomaly"]
    assert payload["dot"], "anomaly event must carry DOT for the topology view"
    # the dashboard renders these directly; without them it showed the literal 'anomaly'
    assert payload["diagnosis"]["diagnosis"] == "beaconing"
    assert payload["diagnosis"]["confidence"]["total"] == 0.95
    assert payload["mitigation"]["script"].startswith("iptables")
    assert payload["mitigation"]["validated"] is True
    state.mitigations.clear()


def test_sse_window_event_shape():
    from cryptoh.web import state

    state.mitigations.clear()
    state.last_detection = {"anomaly": False, "votes": 0,
                            "signals": {"lambda2": 0.62, "multiplicity": 1},
                            "windows": 5, "anomalies": 0, "note": "ok"}
    payload = dict(server_mod._state_events({}))["window"]
    assert payload["window"] == 5
    assert payload["lambda2"] == 0.62
    assert payload["mult"] == 1
    assert payload["status"] == "normal"
    assert payload["live"] is False


def test_sse_emits_each_anomaly_once():
    from cryptoh.web import state

    state.mitigations.clear()
    state.mitigations["aY"] = {
        "type": "iptables", "script": "iptables -A INPUT -s 1.2.3.4 -j DROP",
        "explanation": "", "validated": True, "nodes": [], "dot": "digraph {}",
        "diagnosis": {"diagnosis": "x"},
    }
    state.last_detection = {"anomaly": True, "votes": 2, "signals": {},
                            "windows": 1, "anomalies": 1, "note": "t"}
    last: dict = {}
    first = server_mod._state_events(last)
    second = server_mod._state_events(last)
    assert any(n == "anomaly" for n, _ in first)
    assert second == [], "anomaly must be emitted once per mitigation id"
    state.mitigations.clear()


def test_state_events_are_json_serializable():
    from cryptoh.web import state

    state.mitigations.clear()
    state.mitigations["aZ"] = {
        "type": "nginx", "script": "limit_req_zone $binary_remote_addr zone=c:1m rate=5r/s;",
        "explanation": "", "validated": True, "nodes": ["a"], "dot": "digraph {}",
        "diagnosis": {"diagnosis": "x", "confidence": {"total": 0.5}},
    }
    state.last_detection = {"anomaly": True, "votes": 2,
                            "signals": {"lambda2": 0.0, "multiplicity": 2},
                            "windows": 1, "anomalies": 1, "note": "t"}
    for name, payload in server_mod._state_events({}):
        assert json.loads(server_mod._sse_format(name, payload).split("data: ", 1)[1])
