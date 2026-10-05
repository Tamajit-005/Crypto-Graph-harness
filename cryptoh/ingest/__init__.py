"""Ingest: nginx/csv/json/docker/ebpf/vpc/pcap/syslog sources, tumbling window, graph builder."""

from cryptoh.ingest.graph_builder import build_matrix
from cryptoh.ingest.sources.base import Edge
from cryptoh.ingest.sources.csv_file import edges_from_path as csv_edges_from_path
from cryptoh.ingest.sources.docker_bridge import edges_from_path as docker_edges_from_path
from cryptoh.ingest.sources.ebpf_socket import edges_from_path as ebpf_edges_from_path
from cryptoh.ingest.sources.json_stream import edges_from_path as json_edges_from_path
from cryptoh.ingest.sources.nginx_access_log import edges_from_path as nginx_edges_from_path
from cryptoh.ingest.sources.nginx_access_log import parse_line as nginx_parse_line
from cryptoh.ingest.sources.pcap_file import edges_from_path as pcap_edges_from_path
from cryptoh.ingest.sources.syslog_udp import edges_from_path as syslog_edges_from_path
from cryptoh.ingest.sources.vpc_flow_log import edges_from_path as vpc_edges_from_path
from cryptoh.ingest.window import TumblingWindow

parse_line = nginx_parse_line
edges_from_path = nginx_edges_from_path

__all__ = [
    "Edge",
    "TumblingWindow",
    "build_matrix",
    "csv_edges_from_path",
    "docker_edges_from_path",
    "ebpf_edges_from_path",
    "edges_from_path",
    "json_edges_from_path",
    "nginx_edges_from_path",
    "pcap_edges_from_path",
    "syslog_edges_from_path",
    "vpc_edges_from_path",
    "nginx_parse_line",
    "parse_line",
]
