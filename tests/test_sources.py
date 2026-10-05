from cryptoh.ingest.graph_builder import build_matrix
from cryptoh.ingest.sources.csv_file import edges_from_path as csv_edges
from cryptoh.ingest.sources.json_stream import edges_from_path as json_edges
from cryptoh.ingest.sources.nginx_access_log import parse_line
from cryptoh.ingest.window import TumblingWindow


def test_parse_combined_log():
    line = '10.0.0.14 - - [05/Oct/2026:10:00:01 +0000] "GET /api/v1/health HTTP/1.1" 200 12 "-" "curl/7.81"'
    edge = parse_line(line)
    assert edge is not None
    assert edge.src == "10.0.0.14"


def test_parse_garbage_returns_none():
    assert parse_line("not a log line") is None


def test_window_flush(tmp_path):
    w = TumblingWindow(seconds=5)
    w.add_raw('10.0.0.1 - - [x] "GET /a HTTP/1.1" 200 1 "-" "-"')
    edges = w.flush()
    assert len(edges) == 1
    assert w.flush() == []


def test_graph_builder_weights(tmp_path):
    edges = csv_edges(str(_write(tmp_path, "s.csv", "src,dst,weight\n10.0.0.1,svc,2\n10.0.0.1,svc,3\n")))
    A, nodes = build_matrix(edges)
    assert A.shape == (2, 2)
    assert A.sum() == 5.0
    assert sorted(nodes) == ["10.0.0.1", "svc"]


def test_json_stream_skips_bad(tmp_path):
    p = _write(tmp_path, "s.ndjson", '{"src": "a", "dst": "b"}\nBAD LINE\n{"src": "a"}')
    edges = json_edges(str(p))
    assert len(edges) == 1 and edges[0].src == "a"


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return p
