"""Ingest: nginx/csv/json sources, tumbling window, graph builder."""

from cryptoh.ingest.graph_builder import build_matrix
from cryptoh.ingest.sources.base import Edge
from cryptoh.ingest.sources.csv_file import edges_from_path as csv_edges_from_path
from cryptoh.ingest.sources.json_stream import edges_from_path as json_edges_from_path
from cryptoh.ingest.sources.nginx_access_log import edges_from_path as nginx_edges_from_path
from cryptoh.ingest.sources.nginx_access_log import parse_line as nginx_parse_line
from cryptoh.ingest.window import TumblingWindow

parse_line = nginx_parse_line
edges_from_path = nginx_edges_from_path

__all__ = [
    "Edge",
    "TumblingWindow",
    "build_matrix",
    "csv_edges_from_path",
    "edges_from_path",
    "json_edges_from_path",
    "nginx_edges_from_path",
    "nginx_parse_line",
    "parse_line",
]
