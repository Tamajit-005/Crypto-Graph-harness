"""Docker bridge source — parses `docker network inspect` JSON snapshots.

Expected input: a JSON file as produced by
`docker network inspect <net>`. Each attached container becomes an
edge ``container_name -> network_name``. If a top-level ``"flows"``
list of ``{"src","dst"}`` objects is present, it is used instead.
"""

from __future__ import annotations

import json

from cryptoh.ingest.sources.base import Edge

name = "docker"


def edges_from_path(path: str) -> list[Edge]:
    with open(path, encoding="utf-8") as f:
        obj = json.load(f)
    edges: list[Edge] = []
    networks = obj if isinstance(obj, list) else [obj]
    for net in networks:
        if not isinstance(net, dict):
            continue
        if isinstance(net.get("flows"), list):
            for flow in net["flows"]:
                if not isinstance(flow, dict):
                    continue
                src, dst = flow.get("src"), flow.get("dst")
                if isinstance(src, str) and src and isinstance(dst, str) and dst:
                    edges.append(Edge(src=src, dst=dst,
                                      weight=float(flow.get("weight", 1.0)),
                                      raw=json.dumps(flow)))
            continue
        net_name = str(net.get("Name", "bridge"))
        containers = net.get("Containers") or {}
        for cid, info in containers.items():
            if not isinstance(info, dict):
                continue
            cname = str(info.get("Name") or cid)
            edges.append(Edge(src=cname, dst=net_name, weight=1.0,
                              raw=f"{cname} attached to {net_name}"))
    return edges
