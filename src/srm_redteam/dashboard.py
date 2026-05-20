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
    .visual { display:block; width:100%; height:auto; border:1px solid var(--line); border-radius:8px; background:#fff; }
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
    <h2>Attack Evidence Console</h2>
    <img class="visual" src="project_working.svg" alt="SRM redteam working evidence console">
  </section>
  <section class="card">
    <h2>Evidence Path</h2>
    <img class="visual" src="evidence_map.svg" alt="SRM redteam evidence path">
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


def _svg_escape(value: object) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _svg_short(value: object, limit: int = 44) -> str:
    cleaned = " ".join(str(value).replace("_", " ").split())
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3].rstrip() + "..."


def _svg_lines(value: object, limit: int = 32, max_lines: int = 2) -> list[str]:
    words = " ".join(str(value).replace("_", " ").split()).split()
    lines: list[str] = []
    current: list[str] = []
    for word in words:
        candidate = " ".join([*current, word])
        if len(candidate) <= limit:
            current.append(word)
            continue
        if current:
            lines.append(" ".join(current))
        current = [word]
        if len(lines) == max_lines:
            break
    if current and len(lines) < max_lines:
        lines.append(" ".join(current))
    if len(lines) == max_lines and len(" ".join(words)) > len(" ".join(lines)):
        lines[-1] = _svg_short(lines[-1], max(8, limit - 1))
    return lines or [""]


def _svg_text(value: object, x: int, y: int, css: str, limit: int, max_lines: int, line_height: int) -> str:
    parts = [f'<text class="{css}" x="{x}" y="{y}">']
    for index, line in enumerate(_svg_lines(value, limit=limit, max_lines=max_lines)):
        dy = 0 if index == 0 else line_height
        parts.append(f'<tspan x="{x}" dy="{dy}">{_svg_escape(line)}</tspan>')
    parts.append("</text>")
    return "".join(parts)


def write_visual_assets(root: Path, findings: list) -> None:
    paths = project_paths(root)
    paths.outputs.mkdir(parents=True, exist_ok=True)
    ranked = sorted(findings, key=lambda item: (item.severity, len(item.evidence_ids)), reverse=True)[:4]
    colors = ["#2563eb", "#0f766e", "#7c3aed", "#dc2626"]
    bars = []
    cards = []
    for index, finding in enumerate(ranked):
        y = 366 + index * 68
        width = min(390, 180 + int(finding.severity) * 42)
        evidence_id = finding.evidence_ids[0]
        bars.append(
            f'<text class="label" x="92" y="{y - 12}">{_svg_escape(_svg_short(finding.title, 42))}</text>'
            f'<text class="mono" x="462" y="{y - 12}">{_svg_escape(evidence_id)}</text>'
            f'<rect x="92" y="{y}" width="396" height="14" rx="7" fill="#e5e7eb"/>'
            f'<rect x="92" y="{y}" width="{width}" height="14" rx="7" fill="{colors[index % len(colors)]}"/>'
            f'<text class="caption" x="92" y="{y + 40}">{_svg_escape(finding.annex_control)}</text>'
        )
        card_x = 626 + (index % 2) * 238
        card_y = 350 + (index // 2) * 144
        cards.append(
            f'<rect class="actioncard" x="{card_x}" y="{card_y}" width="212" height="118" rx="8"/>'
            f'<text class="rank" x="{card_x + 18}" y="{card_y + 28}">finding {index + 1}</text>'
            + _svg_text(finding.mitigation, card_x + 18, card_y + 56, "cardtext", 24, 3, 17)
            + f'<text class="mono" x="{card_x + 18}" y="{card_y + 102}">{_svg_escape(evidence_id)}</text>'
        )
    working = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1120" height="700" viewBox="0 0 1120 700" role="img" aria-label="SRM redteam evidence console">
  <defs><style>
    .bg {{ fill:#f8fafc; }} .panel,.card,.actioncard {{ fill:#ffffff; stroke:#d8e1ec; stroke-width:1.1; }}
    .title {{ font:760 30px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; fill:#111827; }}
    .sub {{ font:420 15px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; fill:#475569; }}
    .label {{ font:700 14px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; fill:#1f2937; }}
    .caption {{ font:500 12px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; fill:#64748b; }}
    .small {{ font:650 12px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; fill:#64748b; }}
    .metric {{ font:780 29px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; fill:#0f172a; }}
    .rank {{ font:760 13px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; fill:#2563eb; }}
    .cardtext {{ font:650 14px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; fill:#142033; }}
    .mono {{ font:700 12px ui-monospace,SFMono-Regular,Menlo,monospace; fill:#334155; }}
  </style></defs>
  <rect class="bg" width="1120" height="700"/>
  <rect class="panel" x="28" y="28" width="1064" height="644" rx="8"/>
  <text class="title" x="64" y="76">SRM Memory Faultline Console</text>
  {_svg_text("Graph, memory, drift, and avatar attack runs mapped to ISO 42001 Annex A.6 controls.", 64, 108, "sub", 86, 2, 22)}
  <rect class="card" x="64" y="166" width="232" height="84" rx="8"/><text class="small" x="84" y="194">unique findings</text><text class="metric" x="84" y="230">{len(findings)}</text>
  <rect class="card" x="320" y="166" width="232" height="84" rx="8"/><text class="small" x="340" y="194">controls touched</text><text class="metric" x="340" y="230">{len({item.annex_control for item in findings})}</text>
  <rect class="card" x="576" y="166" width="480" height="84" rx="8"/><text class="small" x="596" y="194">highest severity attack</text>{_svg_text(ranked[0].title if ranked else "No finding", 596, 224, "label", 56, 1, 16)}
  <rect class="card" x="64" y="292" width="492" height="338" rx="8"/><text class="label" x="92" y="322">attack families with cited evidence</text>{''.join(bars)}
  <text class="label" x="626" y="324">mitigation packets</text>{''.join(cards)}
</svg>
"""
    nodes = []
    edges = []
    for index, finding in enumerate(ranked):
        y = 118 + index * 88
        evidence_id = finding.evidence_ids[0]
        nodes.append(
            f'<rect class="lane" x="64" y="{y}" width="178" height="56" rx="8"/>'
            + _svg_text(finding.family.value, 78, y + 23, "node", 21, 2, 16)
            + f'<rect class="failure" x="294" y="{y}" width="186" height="56" rx="8"/>'
            + _svg_text(finding.annex_control, 308, y + 34, "node", 24, 1, 16)
            + f'<rect class="evidencebox" x="548" y="{y}" width="146" height="56" rx="8"/>'
            + f'<text class="mono" x="575" y="{y + 35}">{_svg_escape(evidence_id)}</text>'
            + f'<rect class="actionbox" x="764" y="{y}" width="292" height="56" rx="8"/>'
            + _svg_text(finding.mitigation, 778, y + 23, "node", 36, 2, 16)
        )
        edges.extend(
            [
                f'<path d="M242 {y + 28} L294 {y + 28}" class="edge"/>',
                f'<path d="M480 {y + 28} L548 {y + 28}" class="edge"/>',
                f'<path d="M694 {y + 28} L764 {y + 28}" class="edge"/>',
            ]
        )
    evidence = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1120" height="500" viewBox="0 0 1120 500" role="img" aria-label="SRM redteam evidence path">
  <defs><style>
    .bg {{ fill:#f8fafc; }} .panel {{ fill:#ffffff; stroke:#d8e1ec; stroke-width:1.1; }}
    .title {{ font:760 28px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; fill:#111827; }}
    .node {{ font:620 13px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; fill:#1f2937; }}
    .head {{ font:700 14px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; fill:#64748b; }}
    .mono {{ font:720 13px ui-monospace,SFMono-Regular,Menlo,monospace; fill:#334155; }}
    .edge {{ stroke:#94a3b8; stroke-width:2; fill:none; marker-end:url(#arrow); }}
    .lane {{ fill:#eff6ff; stroke:#dbeafe; }} .failure {{ fill:#ecfeff; stroke:#bae6fd; }}
    .evidencebox {{ fill:#fef9c3; stroke:#fde68a; }} .actionbox {{ fill:#f0fdf4; stroke:#bbf7d0; }}
  </style><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8"/></marker></defs>
  <rect class="bg" width="1120" height="500"/><rect class="panel" x="28" y="28" width="1064" height="444" rx="8"/>
  <text x="56" y="70" class="title">SRM attack evidence path</text>
  <text x="64" y="104" class="head">attack</text><text x="294" y="104" class="head">control</text><text x="548" y="104" class="head">evidence</text><text x="764" y="104" class="head">mitigation</text>
  {''.join(edges)}{''.join(nodes)}
</svg>
"""
    (paths.outputs / "project_working.svg").write_text(working, encoding="utf-8")
    (paths.outputs / "evidence_map.svg").write_text(evidence, encoding="utf-8")


def build_dashboard(root: Path) -> dict[str, str | int]:
    paths = project_paths(root)
    runs = read_runs(root)
    findings = read_findings(root)
    write_visual_assets(root, findings)
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
