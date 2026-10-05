"""PCAP source — minimal IPv4 pair extractor (standard library only).

Reads classic pcap files (little- or big-endian, Ethernet links) and
emits one edge per IPv4 packet, ``src_ip -> dst_ip``. Non-IPv4 frames
are skipped. No third-party capture library required.
"""

from __future__ import annotations

import struct

from cryptoh.ingest.sources.base import Edge

name = "pcap"

_MAGIC_LE = 0xA1B2C3D4
_DLT_EN10MB = 1


def _ip_str(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def edges_from_path(path: str) -> list[Edge]:
    with open(path, "rb") as f:
        blob = f.read()
    if len(blob) < 24:
        return []
    magic, = struct.unpack("<I", blob[:4])
    endian = "<" if magic == _MAGIC_LE else ">"
    try:
        _, _, _, _, _, _, network = struct.unpack(endian + "IHHIIII", blob[:24])
    except struct.error:
        return []
    if network != _DLT_EN10MB:
        return []
    edges: list[Edge] = []
    off = 24
    while off + 16 <= len(blob):
        try:
            _, _, caplen, _ = struct.unpack(endian + "IIII", blob[off:off + 16])
        except struct.error:
            break
        start = off + 16
        frame = blob[start:start + caplen]
        off = start + caplen
        if len(frame) < 34:
            continue
        if struct.unpack("!H", frame[12:14])[0] != 0x0800:
            continue
        ip = frame[14:]
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            continue
        src, dst = _ip_str(ip[12:16]), _ip_str(ip[16:20])
        edges.append(Edge(src=src, dst=dst, weight=1.0, raw=f"{src} -> {dst}"))
    return edges
