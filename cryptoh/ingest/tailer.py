"""Follow log files and yield newly appended lines (rotation-aware).

Pure-stdlib polling tailer: no watchdog/native dependency, so the project stays
free and portable. Tracks (inode, size) per file so truncation and rotation are
detected and handled instead of silently truncating the stream.
"""
from __future__ import annotations

import time
from collections.abc import Iterator, Sequence

# Poll faster than the shortest realistic log flush; cheap because it is a stat().
POLL_SECONDS = 1.0


def _resolve(paths: Sequence[str]) -> list[str]:
    out: list[str] = []
    for raw in paths:
        _, _, rest = raw.rpartition(":") if ":" in raw and not raw.endswith(":") else (raw, "", raw)
        out.append(rest or raw)
    return out


def follow_lines(
    paths: Sequence[str],
    poll_seconds: float = POLL_SECONDS,
    from_end: bool = False,
    idle_timeout: float | None = None,
) -> Iterator[list[str]]:
    """Yield batches of newly appended lines from one or more files, forever.

    from_end=True skips content that already exists (live-tail semantics);
    the default replays from the start so a fresh `watch` still establishes
    its baseline window. With idle_timeout set, the generator returns after
    that many seconds without a single new line (used by tests and by
    bounded readers; `watch` leaves it unset).
    """
    resolved = _resolve(paths)
    positions: dict[str, int] = {}
    last_emit = time.monotonic()
    while True:
        emitted: list[str] = []
        for path in resolved:
            try:
                size = _size(path)
            except OSError:
                continue
            if path not in positions:
                positions[path] = size if from_end else 0
                if from_end:
                    continue
            start = positions[path]
            if size < start:
                # truncated or rotated: restart from the new beginning
                start = 0
            if size == start:
                continue
            chunk = _read(path, start, size)
            positions[path] = size
            emitted.extend(chunk)
        if emitted:
            last_emit = time.monotonic()
            yield emitted
            continue
        if idle_timeout is not None and time.monotonic() - last_emit > idle_timeout:
            return
        time.sleep(max(0.05, poll_seconds))


def _size(path: str) -> int:
    import os

    return os.path.getsize(path)


def _read(path: str, start: int, end: int) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        fh.seek(start)
        data = fh.read(end - start)
    lines = data.split("\n")
    # Drop a trailing empty element or a partial final line: both mean the
    # writer has not finished the current record, so it waits for the next poll.
    if lines and (lines[-1] == "" or not data.endswith("\n")):
        lines.pop()
    return [ln for ln in lines if ln.strip()]


def collect_follower(paths, *, max_lines: int, timeout: float, **kwargs) -> list[str]:
    """Drain follow_lines until max_lines have been seen or the idle timeout hits.

    Test/CI helper: follow_lines never returns on its own, so callers that need
    a bounded read use this instead of hand-rolling asyncio plumbing.
    """
    kwargs.pop("idle_timeout", None)
    collected: list[str] = []
    for batch in follow_lines(paths, idle_timeout=timeout, **kwargs):
        collected.extend(batch)
        if len(collected) >= max_lines:
            break
    return collected