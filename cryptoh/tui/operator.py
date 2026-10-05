"""Colored operator display."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel


def show_diagnosis(console: Console, event) -> None:
    d = event.diagnosis if isinstance(event.diagnosis, dict) else {"diagnosis": str(event.diagnosis)}
    console.print(Panel(d.get("diagnosis", ""), title="Diagnostics", border_style="magenta"))
    m = event.mitigation if isinstance(event.mitigation, dict) else {}
    script = m.get("script", "") if isinstance(m, dict) else ""
    if script:
        console.print(Panel(script, title="Recommended Mitigation", border_style="green"))
