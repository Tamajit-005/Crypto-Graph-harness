"""Operator feedback loop — threshold auto-tuning from feedback labels."""
from __future__ import annotations

from cryptoh.spectral.baseline import Baseline


def apply_feedback(baseline: Baseline, feedback: str, signals: dict) -> Baseline:
    """Tune baseline/alpha from feedback labels (true_positive / false_positive)."""
    fb = (feedback or "").strip().lower()
    if fb == "false_positive":
        baseline.alpha = min(0.7, baseline.alpha + 0.05)
    elif fb == "true_positive":
        baseline.alpha = max(0.1, baseline.alpha - 0.05)
    return baseline
