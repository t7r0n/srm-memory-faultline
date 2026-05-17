from __future__ import annotations

from pathlib import Path

import plotly.graph_objects as go
from jinja2 import Environment, select_autoescape
from markupsafe import Markup

from srm_redteam.runner import project_paths, read_findings, read_runs


TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SRM Redteam Dashboard</title>
  <style>
    :root { color-scheme: light dark; --bg:#f7f8fb; --fg:#171923; --muted:#5b6472; --card:#ffffff; --line:#d8dee8; --accent:#2563eb; }
    @media (prefers-color-scheme: dark) { :root { --bg:#101318; --fg:#f3f6fb; --muted:#a8b3c4; --card:#171b22; --line:#2a3240; --accent:#7aa2ff; } }
    body { margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--fg); }
    main { max-width:1180px; margin:0 auto; padding:32px 20px 56px; }
    header { display:flex; justify-content:space-between; align-items:flex-end; gap:24px; border-bottom:1px solid var(--line); padding-bottom:20px; }
    h1 { margin:0; font-size:32px; line-height:1.1; }
    h2 { font-size:18px; margin:0 0 14px; }
    .muted { color:var(--muted); }
    .grid { display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:14px; margin:24px 0; }
    .card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:16px; box-shadow:0 1px 2px rgba(0,0,0,.04); }
    .metric { font-size:30px; font-weight:750; margin-top:8px; }
    .charts { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px; }
    table { width:100%; border-collapse:collapse; font-size:14px; }
    th, td { padding:10px 8px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
    th { color:var(--muted); font-weight:650; }
    code { color:var(--accent); }
    @media (max-width:850px) { .grid, .charts { grid-template-columns:1fr; } header { display:block; } }
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>SRM Redteam Dashboard</h1>
      <p class="muted">Graph, memory, drift, and avatar attack runs mapped to ISO 42001 Annex A.6 controls.</p>
    </div>
    <div class="muted">Offline static artifact</div>
  </header>
  <section class="grid">
    <div class="card"><div class="muted">Attack Runs</div><div class="metric">{{ run_count }}</div></div>
    <div class="card"><div class="muted">Unique Findings</div><div class="metric">{{ finding_count }}</div></div>
    <div class="card"><div class="muted">Controls Touched</div><div class="metric">{{ control_count }}</div></div>
    <div class="card"><div class="muted">Max Severity</div><div class="metric">{{ max_severity }}</div></div>
  </section>
  <section class="charts">
    <div class="card"><h2>Findings by Family</h2>{{ family_chart }}</div>
    <div class="card"><h2>Annex Control Coverage</h2>{{ control_chart }}</div>
  </section>
  <section class="card">
    <h2>Finding Drilldown</h2>
    <table>
      <thead><tr><th>ID</th><th>Family</th><th>Control</th><th>Evidence</th><th>Mitigation</th></tr></thead>
      <tbody>
      {% for finding in findings %}
        <tr>
          <td><code>{{ finding.finding_id }}</code></td>
          <td>{{ finding.title }}</td>
          <td><code>{{ finding.annex_control }}</code></td>
          <td>{{ finding.evidence_ids | join(", ") }}</td>
          <td>{{ finding.mitigation }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </section>
</main>
</body>
</html>
"""


def build_dashboard(root: Path) -> dict[str, str | int]:
    paths = project_paths(root)
    runs = read_runs(root)
    findings = read_findings(root)
    family_counts: dict[str, int] = {}
    control_counts: dict[str, int] = {}
    for finding in findings:
        family_counts[finding.family.value] = family_counts.get(finding.family.value, 0) + 1
        control_counts[finding.annex_control] = control_counts.get(finding.annex_control, 0) + 1

    family_chart = go.Figure(
        data=[go.Bar(x=list(family_counts.keys()), y=list(family_counts.values()), marker_color="#2563eb")]
    )
    family_chart.update_layout(margin=dict(l=20, r=20, t=10, b=80), height=320)
    control_chart = go.Figure(
        data=[
            go.Bar(
                x=list(control_counts.keys()),
                y=list(control_counts.values()),
                marker_color=["#2563eb", "#0f766e", "#9333ea", "#dc2626"][: len(control_counts)],
            )
        ]
    )
    control_chart.update_layout(margin=dict(l=20, r=20, t=10, b=80), height=320)
    env = Environment(autoescape=select_autoescape(default=True))
    html = env.from_string(TEMPLATE).render(
        run_count=len(runs),
        finding_count=len(findings),
        control_count=len(control_counts),
        max_severity=max((finding.severity for finding in findings), default=0),
        findings=findings,
        family_chart=Markup(family_chart.to_html(full_html=False, include_plotlyjs="inline")),
        control_chart=Markup(control_chart.to_html(full_html=False, include_plotlyjs=False)),
    )
    paths.dashboard.write_text(html, encoding="utf-8")
    return {"dashboard": str(paths.dashboard), "bytes": paths.dashboard.stat().st_size}
