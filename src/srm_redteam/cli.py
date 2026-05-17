from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from srm_redteam.dashboard import build_dashboard
from srm_redteam.evidence import benchmark, export_demo_pack, export_evidence_pack, verify
from srm_redteam.runner import init_demo as init_demo_project
from srm_redteam.runner import run_suite


app = typer.Typer(no_args_is_help=True)
console = Console()


def root_path() -> Path:
    return Path.cwd()


@app.command()
def init_demo(force: bool = False) -> None:
    """Create runtime directories for the local demo."""
    console.print_json(json.dumps(init_demo_impl(force=force)))


def init_demo_impl(force: bool = False) -> dict[str, str]:
    return init_demo_project(root_path(), force=force)


@app.command()
def run(iterations: int = typer.Option(20, help="Suite repetitions. 20 x 12 cases = 240 runs.")) -> None:
    """Run the nightly red-team suite against the local SRM reference target."""
    console.print_json(json.dumps(run_suite(root_path(), iterations=iterations)))


@app.command()
def evidence() -> None:
    """Export ISO 42001 Annex A.6 evidence files."""
    console.print_json(json.dumps(export_evidence_pack(root_path())))


@app.command()
def verify_cmd() -> None:
    """Verify run count, recall, evidence integrity, and control coverage."""
    report = verify(root_path())
    console.print_json(report.model_dump_json())
    if not report.passed:
        raise typer.Exit(1)


@app.command(name="verify")
def verify_alias() -> None:
    verify_cmd()


@app.command()
def dashboard() -> None:
    """Build an offline static dashboard."""
    console.print_json(json.dumps(build_dashboard(root_path())))


@app.command()
def benchmark_cmd(synthetic_runs: int = 1000) -> None:
    """Run a deterministic local benchmark."""
    console.print_json(json.dumps(benchmark(root_path(), synthetic_runs=synthetic_runs)))


@app.command(name="benchmark")
def benchmark_alias(synthetic_runs: int = 1000) -> None:
    benchmark_cmd(synthetic_runs=synthetic_runs)


@app.command("export-demo-pack")
def export_demo_pack_cmd() -> None:
    """Write a concise local demo pack."""
    console.print_json(json.dumps(export_demo_pack(root_path())))


def main() -> None:
    app()
