"""cryptoh CLI — watch / batch / list over spectral anomaly detection."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console

from cryptoh.banner import show_banner
from cryptoh.config import settings
from cryptoh.core.analysis import analyze_windows
from cryptoh.core.events import AnomalyEvent
from cryptoh.extract.png_render import save_subgraph_png
from cryptoh.ingest.sources.base import Edge
from cryptoh.ingest.sources.csv_file import edges_from_path as csv_edges
from cryptoh.ingest.sources.docker_bridge import edges_from_path as docker_edges
from cryptoh.ingest.sources.ebpf_socket import edges_from_path as ebpf_edges
from cryptoh.ingest.sources.json_stream import edges_from_path as json_edges
from cryptoh.ingest.sources.nginx_access_log import edges_from_path as nginx_edges
from cryptoh.ingest.sources.pcap_file import edges_from_path as pcap_edges
from cryptoh.ingest.sources.syslog_udp import edges_from_path as syslog_edges
from cryptoh.ingest.sources.vpc_flow_log import edges_from_path as vpc_edges
from cryptoh.llm.fallback import diagnose as fallback_diagnose
from cryptoh.llm.gemma import diagnose_live
from cryptoh.llm.ollama_local import diagnose_local
from cryptoh.llm.parser import parse_json_response
from cryptoh.llm.prompts.diagnose import DIAGNOSE_PROMPT
from cryptoh.llm.scrub import scrub_pii
from cryptoh.mitigate import render as render_template
from cryptoh.mitigate import validate_iptables
from cryptoh.tui.audit import write_audit
from cryptoh.tui.confirm import confirm_apply
from cryptoh.tui.operator import show_diagnosis

app = typer.Typer(help="Crypto-Graph Harness — spectral telemetry diagnostics.")

SOURCE_HELP = "source:path (nginx, csv, json, docker, ebpf, vpc, pcap, syslog) or bare path"

SOURCES = {
    "nginx": nginx_edges,
    "csv": csv_edges,
    "json": json_edges,
    "docker": docker_edges,
    "ebpf": ebpf_edges,
    "vpc": vpc_edges,
    "pcap": pcap_edges,
    "syslog": syslog_edges,
}
DETECTORS = ["fiedler", "multiplicity", "clustering"]
MITIGATIONS = ["iptables", "docker", "k8s", "nginx"]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo("cryptoh 0.1.0")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True),
) -> None:
    if ctx.invoked_subcommand is None:
        show_banner()
        typer.echo(ctx.get_help())


@app.command("list")
def list_cmd(kind: str = typer.Argument(..., help="sources|detectors|mitigations")) -> None:
    key = kind.lower()
    if key in ("source", "sources"):
        typer.echo("telemetry sources:")
        for name in sorted(SOURCES):
            typer.echo(f"  - {name}")
    elif key in ("detector", "detectors"):
        typer.echo("spectral detectors:")
        for name in DETECTORS:
            typer.echo(f"  - {name}")
    elif key in ("mitigation", "mitigations"):
        typer.echo("mitigation backends:")
        for name in MITIGATIONS:
            typer.echo(f"  - {name}")
    else:
        raise typer.BadParameter(f"unknown list kind: {kind!r} (sources|detectors|mitigations)")


def _load_edges(source: str) -> list[Edge]:
    name, path = "nginx", source
    if ":" in source:
        maybe, rest = source.split(":", 1)
        if maybe in SOURCES:
            name, path = maybe, rest
        elif "/" not in maybe and "\\" not in maybe and not Path(source).exists():
            raise typer.BadParameter(f"unknown source: {maybe!r}")
    if not Path(path).exists():
        raise typer.BadParameter(f"source file not found: {path!r}")
    return SOURCES[name](path)


def _parse_window(window: str) -> int:
    text = window.strip().lower().rstrip("s")
    try:
        return max(1, int(float(text)))
    except ValueError:
        raise typer.BadParameter(f"cannot parse --window {window!r} (try '5s')")


def _analyze(
    edges: list[Edge], window_lines: int = 200, baseline_windows: int = 12,
    delta: float = 0.20,
) -> list[dict]:
    """Thin wrapper over the shared pipeline (kept for backward compatibility)."""
    return analyze_windows(edges, window_lines, baseline_windows, delta)


def _diagnose(dot: str, logs: list[str], strength: float, nodes: list[str],
              png_bytes: bytes | None = None) -> dict:
    logs = scrub_pii(logs)
    # dot kept unscrubbed: node IDs are graph structure, not PII.
    if settings.gemini_api_key:
        prompt = DIAGNOSE_PROMPT.format(
            dot=dot, logs="\n".join(logs), spectral_strength=f"{strength:.2f}"
        )
        try:
            return parse_json_response(diagnose_live(settings.gemini_api_key, prompt, png_bytes))
        except RuntimeError:
            pass
    return fallback_diagnose(dot=dot, logs=logs, spectral_strength=strength, nodes=nodes)


def _validate_script(script: str) -> bool:
    lines = [ln.strip() for ln in script.splitlines() if ln.strip()]
    if not lines:
        return False
    return all(validate_iptables(ln).get("valid", False) for ln in lines)


def _run(
    edges: list[Edge],
    source: str,
    model: str,
    window_secs: int,
    baseline_secs: float,
    output_dir: str,
    no_mitigate: bool,
    mode: str,
) -> None:
    show_banner()
    console = Console()
    typer.echo(f"loading telemetry source {source} ... [ok] ({len(edges)} edges, model={model})")
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    warmup = max(1, int(baseline_secs / window_secs))
    results = _analyze(edges, baseline_windows=warmup)
    anomalies = [r for r in results if r["status"] == "ANOMALY"]
    for r in results:
        stamp = f"{r['window'] * window_secs // 60:02d}:{r['window'] * window_secs % 60:02d}"
        typer.echo(
            f"[t={stamp}] graph: {r['n']} nodes, {r['m']} edges, "
            f"\u03bb_2={r['lambda2']:.3f} [{r['status']}]"
        )
        if r["status"] != "ANOMALY":
            continue
        typer.echo(f"  \u03bb_2 shift: {r['fiedler']['detail']} (baseline {r['baseline_lambda2']:.3f})")
        typer.echo(f"  multiplicity: {r['mult_sig']['detail']} | {r['cluster']['detail']}")
        typer.echo(f"  votes: {r['votes']}/3 — extracting anomaly subgraph ...")
        png_path = str(outdir / f"anomaly_w{r['window']}.png")
        save_subgraph_png(r["subgraph"], png_path)
        typer.echo(f"  subgraph PNG: {png_path}")
        try:
            with open(png_path, "rb") as fh:
                png_bytes: bytes | None = fh.read()
        except OSError:
            png_bytes = None
        nodes = list(r["subgraph"]["nodes"])
        if no_mitigate:
            diagnosis: dict = {"diagnosis": "mitigation skipped (--no-mitigate)"}
            mitigation: dict = {"type": "none", "script": "", "explanation": "skipped"}
        else:
            strength = r["votes"] / 3.0
            diagnosis = _diagnose(r["dot"], r["logs"], strength, nodes, png_bytes)
            mitigation = diagnosis.get("mitigation", {}) if isinstance(diagnosis, dict) else {}
            script = mitigation.get("script", "") if isinstance(mitigation, dict) else ""
            if script and not _validate_script(script):
                typer.echo("  \u26a0 UNVALIDATED mitigation script — review before applying")
            if not script and nodes:
                rendered = render_template(
                    "iptables_drop.j2", attacker_ip=nodes[0], service="any"
                )
                mitigation = {"type": "iptables", "script": rendered,
                              "explanation": "Rendered fallback template."}
        event = AnomalyEvent(
            nodes=nodes,
            signals={"lambda2": r["lambda2"], "multiplicity": r["mult"], "votes": r["votes"]},
            diagnosis=diagnosis if isinstance(diagnosis, dict) else {"diagnosis": str(diagnosis)},
            mitigation=mitigation if isinstance(mitigation, dict) else {},
            dot=r["dot"],
            png_path=png_path,
        )
        if not no_mitigate:
            show_diagnosis(console, event)
            if sys.stdin.isatty() and not confirm_apply("apply mitigation?"):
                typer.echo("  mitigation NOT applied (operator declined)")
        audit_path = write_audit("cryptoh-audit", event)
        typer.echo(f"  audit: {audit_path}")
    report = [f"# cryptoh {mode} report", f"source: {source}", f"windows: {len(results)}",
              f"anomalies: {len(anomalies)}", ""]
    for r in results:
        report.append(
            f"- w{r['window']}: n={r['n']} m={r['m']} \u03bb_2={r['lambda2']:.3f} [{r['status']}]"
        )
        if r["status"] == "ANOMALY":
            report += ["", "```dot", r["dot"].rstrip(), "```", ""]
    (outdir / "report.md").write_text("\n".join(report) + "\n")
    typer.echo(f"report: {outdir / 'report.md'}")
    if anomalies:
        typer.echo(f"ANOMALY detected in {len(anomalies)} window(s)")
    else:
        typer.echo("no anomaly — traffic within baseline")


@app.command()
def batch(
    source: str = typer.Option(..., help=SOURCE_HELP),
    model: str = typer.Option("gemma-4"),
    window: str = typer.Option("5s"),
    baseline: float = typer.Option(60.0),
    output_dir: str = typer.Option("cryptoh-report"),
    no_mitigate: bool = typer.Option(False, "--no-mitigate"),
) -> None:
    """Single pass over a telemetry file in 200-line windows."""
    _run(_load_edges(source), source, model, _parse_window(window),
         baseline, output_dir, no_mitigate, "batch")


@app.command()
def watch(
    source: str = typer.Option(..., help=SOURCE_HELP),
    model: str = typer.Option("gemma-4"),
    window: str = typer.Option("5s"),
    baseline: float = typer.Option(60.0),
    output_dir: str = typer.Option("cryptoh-report"),
    no_mitigate: bool = typer.Option(False, "--no-mitigate"),
) -> None:
    """Tail a telemetry file (MVP: single streaming pass over current content)."""
    typer.echo("watch mode (single pass over current file contents)")
    _run(_load_edges(source), source, model, _parse_window(window),
         baseline, output_dir, no_mitigate, "watch")


@app.command()
def serve(
    port: int = typer.Option(8000, help="port to listen on"),
    host: str = typer.Option("0.0.0.0", help="interface to bind"),
) -> None:
    """Launch the monitoring dashboard and JSON API."""
    try:
        import uvicorn
    except ImportError:
        typer.echo("server dependencies are not installed", err=True)
        raise typer.Exit(code=1)
    show_banner()
    typer.echo(f"serving dashboard at http://{host}:{port}")
    uvicorn.run("cryptoh.web.server:app", host=host, port=port)


@app.command()
def calibrate(
    source: str = typer.Option(..., help=SOURCE_HELP),
    window: str = typer.Option("5s"),
    baseline: float = typer.Option(60.0),
) -> None:
    """Sweep detection thresholds over a dataset and report anomaly counts."""
    edges = _load_edges(source)
    window_secs = _parse_window(window)
    warmup = max(1, int(baseline / window_secs))
    typer.echo(f"calibrating on {len(edges)} edges from {source}")
    for delta in (0.10, 0.15, 0.20, 0.30):
        results = _analyze(edges, baseline_windows=warmup, delta=delta)
        anomalies = sum(1 for r in results if r["status"] == "ANOMALY")
        lambdas = [r["lambda2"] for r in results if r["status"] != "tiny graph"]
        spread = f"{min(lambdas):.3f}..{max(lambdas):.3f}" if lambdas else "n/a"
        typer.echo(f"  delta={delta:.2f}: {anomalies}/{len(results)} anomalous windows "
                   f"(lambda2 range {spread})")
    typer.echo("recommended: smallest delta with zero anomalies on benign traffic")
