"""Real-time log ingestion: follow files, window them, update server state.

Pure-stdlib polling tailer (no watchdog dependency, keeps the free/no-native-deps
promise). Tracks inode + byte offset per file so log rotation is handled, feeds
new lines through the same nginx parser the batch path uses, and publishes each
completed window into `state` for the SSE stream to pick up.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
from pathlib import Path

from cryptoh.core.analysis import analyze_window
from cryptoh.ingest.sources.base import Edge
from cryptoh.ingest.sources.nginx_access_log import parse_line
from cryptoh.spectral.baseline import Baseline
from cryptoh.web import state

WINDOW_LINES = 200
BASELINE_WINDOWS = 12
POLL_SECONDS = 0.5
MAX_BUFFER_LINES = 20000


class FileTailer:
    """Follow one or more log files and emit windows of parsed edges."""

    def __init__(
        self,
        paths: list[str],
        window_lines: int = WINDOW_LINES,
        baseline_windows: int = BASELINE_WINDOWS,
        poll_seconds: float = POLL_SECONDS,
    ) -> None:
        self.paths = [Path(p) for p in paths]
        self.window_lines = max(3, window_lines)
        self.baseline_windows = baseline_windows
        self.poll_seconds = poll_seconds
        self._offsets: dict[str, tuple[int, int]] = {}  # path -> (inode, size)
        self._pending: list[Edge] = []
        self._baseline = Baseline(warmup_windows=max(1, baseline_windows))
        self._window_no = 0
        self._task: asyncio.Task | None = None
        self._clients: set[asyncio.Queue] = set()

    @property
    def baseline_ready(self) -> bool:
        """True once enough windows have been observed to judge anomalies."""
        return self._baseline.ready

    # ---- lifecycle -----------------------------------------------------
    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def followed(self) -> list[str]:
        return [str(p) for p in self.paths]

    # ---- pub/sub for direct SSE consumers ------------------------------
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._clients.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._clients.discard(q)

    def _publish(self, event: str, payload: dict) -> None:
        for q in list(self._clients):
            if q.full():
                with contextlib.suppress(asyncio.QueueEmpty):
                    q.get_nowait()
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait((event, payload))

    # ---- tailing -------------------------------------------------------
    def read_new_lines(self) -> list[str]:
        """Read bytes appended since the last call. Handles truncation/rotation."""
        lines: list[str] = []
        for path in self.paths:
            try:
                st = path.stat()
            except OSError:
                continue
            prev = self._offsets.get(str(path))
            if prev is None:
                offset = 0  # first sight: start from the beginning
            else:
                inode, size = prev
                if inode != st.st_ino or st.st_size < size:
                    offset = 0  # rotated or truncated
                else:
                    offset = size
            if st.st_size == offset:
                self._offsets[str(path)] = (st.st_ino, st.st_size)
                continue
            try:
                with path.open("r", errors="replace") as fh:
                    fh.seek(offset)
                    chunk = fh.read()
                    self._offsets[str(path)] = (st.st_ino, fh.tell())
            except OSError:
                continue
            lines.extend(chunk.splitlines())
        return lines

    def ingest_lines(self, lines: list[str]) -> list[dict]:
        """Parse lines into edges and analyze every completed window."""
        for line in lines:
            edge = parse_line(line)
            if edge is not None:
                self._pending.append(edge)
        if len(self._pending) > MAX_BUFFER_LINES:
            self._pending = self._pending[-MAX_BUFFER_LINES:]
        results: list[dict] = []
        while len(self._pending) >= self.window_lines:
            chunk = self._pending[: self.window_lines]
            self._pending = self._pending[self.window_lines :]
            # One persistent baseline across windows: a live stream must learn
            # "normal" from the windows it has already seen, not restart each time.
            results.append(
                analyze_window(chunk, self._baseline, self._window_no)
            )
            self._window_no += 1
        return results

    async def _run(self) -> None:
        while True:
            try:
                results = self.ingest_lines(self.read_new_lines())
            except Exception as exc:  # noqa: BLE001 - tailer must never die
                self._publish("error", {"error": f"tailer: {exc}"})
                results = []
            for rec in results:
                self._publish_record(rec)
            await asyncio.sleep(self.poll_seconds)

    def _publish_record(self, rec: dict) -> None:
        signals = {"lambda2": round(float(rec.get("lambda2", 0.0)), 6),
                   "multiplicity": rec.get("mult", 1)}
        state.last_detection = {
            "anomaly": rec["status"] == "ANOMALY",
            "votes": int(rec.get("votes", 0)),
            "signals": signals,
            "windows": int(rec.get("window", 0)) + 1,
            "anomalies": int(state.last_detection.get("anomalies", 0))
            + (1 if rec["status"] == "ANOMALY" else 0),
            "note": ("anomaly in latest window" if rec["status"] == "ANOMALY"
                     else f"latest window normal (tailing {', '.join(self.followed)})"),
        }
        self._publish("window", {
            "window": int(rec.get("window", 0)),
            "n": rec.get("n", 0),
            "m": rec.get("m", 0),
            "lambda2": signals["lambda2"],
            "mult": signals["multiplicity"],
            "votes": int(rec.get("votes", 0)),
            "status": rec["status"],
            "live": True,
        })


def tailer_from_env() -> FileTailer | None:
    """Build a tailer from CRYPTOH_SOURCE / --source style env vars, if configured."""
    raw = os.environ.get("CRYPTOH_SOURCE") or os.environ.get("CRYPTOH_WATCH")
    if not raw:
        return None
    paths = [p.strip() for p in raw.split(",") if p.strip()]
    existing = [p for p in paths if Path(p).exists()]
    if not existing:
        return None
    window = int(os.environ.get("CRYPTOH_WINDOW_LINES", WINDOW_LINES))
    return FileTailer(existing, window_lines=window)