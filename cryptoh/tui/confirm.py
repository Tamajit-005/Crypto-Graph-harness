"""y/N apply prompt."""
from __future__ import annotations

import typer


def confirm_apply(message: str = "apply mitigation?") -> bool:
    return typer.confirm(message, default=False)
