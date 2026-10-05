"""Rolling and adaptive baselines for spectral signals."""
from __future__ import annotations


class Baseline:
    def __init__(self, warmup_windows: int = 12, adaptive: bool = False, alpha: float = 0.3) -> None:
        self.warmup = warmup_windows
        self.adaptive = adaptive
        self.alpha = alpha
        self.lambda2_history: list[float] = []
        self.mult_history: list[int] = []
        self._ema_lambda2: float = 0.0
        self._ema_mult: float = 0.0
        self._ema_ready: bool = False

    def update(self, lambda2: float, mult: int) -> None:
        self.lambda2_history.append(lambda2)
        self.mult_history.append(mult)
        if self.adaptive:
            if not self._ema_ready:
                self._ema_lambda2 = float(lambda2)
                self._ema_mult = float(mult)
                self._ema_ready = True
            else:
                self._ema_lambda2 = self.alpha * float(lambda2) + (1.0 - self.alpha) * self._ema_lambda2
                self._ema_mult = self.alpha * float(mult) + (1.0 - self.alpha) * self._ema_mult

    @property
    def ready(self) -> bool:
        return len(self.lambda2_history) >= self.warmup

    @property
    def lambda2(self) -> float:
        if self.adaptive and self._ema_ready:
            return self._ema_lambda2
        h = self.lambda2_history[: self.warmup]
        return sum(h) / len(h)

    @property
    def mult(self) -> int:
        if self.adaptive and self._ema_ready:
            return int(round(self._ema_mult))
        return self.mult_history[0] if self.mult_history else 1
