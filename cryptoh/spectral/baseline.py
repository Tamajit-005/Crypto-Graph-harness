"""Rolling baseline over the first N windows (default 60s / 5s = 12)."""
from __future__ import annotations


class Baseline:
    def __init__(self, warmup_windows: int = 12) -> None:
        self.warmup = warmup_windows
        self.lambda2_history: list[float] = []
        self.mult_history: list[int] = []

    def update(self, lambda2: float, mult: int) -> None:
        self.lambda2_history.append(lambda2)
        self.mult_history.append(mult)

    @property
    def ready(self) -> bool:
        return len(self.lambda2_history) >= self.warmup

    @property
    def lambda2(self) -> float:
        h = self.lambda2_history[: self.warmup]
        return sum(h) / len(h)

    @property
    def mult(self) -> int:
        return self.mult_history[0] if self.mult_history else 1
