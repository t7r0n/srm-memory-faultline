from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from typer.testing import CliRunner

from srm_redteam.cli import app
from srm_redteam.evidence import export_evidence_pack, verify
from srm_redteam.runner import init_demo, read_findings, read_runs, run_suite


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def reset_runtime() -> None:
    for name in ["runs", "data", "outputs"]:
        path = PROJECT_ROOT / name
        if path.exists():
            shutil.rmtree(path)


def test_end_to_end_suite_has_expected_findings() -> None:
    reset_runtime()
    init_demo(PROJECT_ROOT)
    result = run_suite(PROJECT_ROOT, iterations=20)
    assert result["runs"] == 240
    assert result["unique_findings"] == 7
    export_evidence_pack(PROJECT_ROOT)
    report = verify(PROJECT_ROOT)
    assert report.passed
    assert report.recall >= 0.8


def test_evidence_pack_claims_reference_real_evidence_ids() -> None:
    reset_runtime()
    init_demo(PROJECT_ROOT)
    run_suite(PROJECT_ROOT, iterations=20)
    export_evidence_pack(PROJECT_ROOT)
    runs = read_runs(PROJECT_ROOT)
    known = {run.evidence_id for run in runs}
    pack = (PROJECT_ROOT / "outputs" / "evidence_pack.md").read_text(encoding="utf-8")
    claim_lines = [line for line in pack.splitlines() if line.startswith("CLAIM:")]
    assert claim_lines
    for line in claim_lines:
        assert any(evidence_id in line for evidence_id in known)


def test_findings_have_annex_controls_and_mitigations() -> None:
    reset_runtime()
    init_demo(PROJECT_ROOT)
    run_suite(PROJECT_ROOT, iterations=20)
    findings = read_findings(PROJECT_ROOT)
    controls = {finding.annex_control for finding in findings}
    assert {"A.6.2.4", "A.6.2.6", "A.6.2.7", "A.6.2.8"}.issubset(controls)
    assert all(finding.mitigation for finding in findings)


def test_cli_workflow() -> None:
    reset_runtime()
    runner = CliRunner()
    old_cwd = Path.cwd()
    os.chdir(PROJECT_ROOT)
    for args in [
        ["init-demo"],
        ["run", "--iterations", "20"],
        ["evidence"],
        ["verify"],
        ["dashboard"],
        ["benchmark"],
        ["export-demo-pack"],
    ]:
        try:
            result = runner.invoke(app, args)
            assert result.exit_code == 0, result.output
        finally:
            os.chdir(PROJECT_ROOT)
    os.chdir(old_cwd)
    assert (PROJECT_ROOT / "outputs" / "dashboard.html").exists()
    assert (PROJECT_ROOT / "outputs" / "demo_pack.md").exists()


def test_dashboard_escapes_fixture_text() -> None:
    reset_runtime()
    suite_path = PROJECT_ROOT / "suites" / "nightly.json"
    original = suite_path.read_text(encoding="utf-8")
    try:
        data = json.loads(original)
        data["cases"][0]["payload"] = "<script>alert('x')</script> retype champion"
        suite_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        init_demo(PROJECT_ROOT)
        run_suite(PROJECT_ROOT, iterations=20)
        export_evidence_pack(PROJECT_ROOT)
        from srm_redteam.dashboard import build_dashboard

        build_dashboard(PROJECT_ROOT)
        html = (PROJECT_ROOT / "outputs" / "dashboard.html").read_text(encoding="utf-8")
        assert "<script>alert('x')</script>" not in html
    finally:
        suite_path.write_text(original, encoding="utf-8")
