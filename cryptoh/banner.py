from pyfiglet import figlet_format
from rich.console import Console

SPLASH = figlet_format("CryptoGraph", font="ansi_shadow")
SUBTITLE = "[ Crypto-Graph Harness — Spectral Telemetry Diagnostics ]"


def show_banner() -> None:
    Console().print(f"[bright_cyan]{SPLASH}[/bright_cyan][magenta]{SUBTITLE}[/magenta]")
