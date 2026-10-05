# Adapter Guide

A new telemetry source is a single Python file in `cryptoh/ingest/sources/`.

Requirements:
- Module-level `name = "my_source"`.
- `parse_line(line: str) -> Edge | None` for line-based sources.
- `edges_from_path(path: str) -> list[Edge]` for file-based sources.

Register in `cryptoh/ingest/__init__.py` and add to the `SOURCES` dict in `cryptoh/cli.py`.

See `cryptoh/ingest/sources/_template.py` for a starter.
