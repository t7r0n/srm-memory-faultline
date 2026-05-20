# srm-redteam

![srm-redteam working preview](outputs/project_working.svg)
Local SRM architecture red-team harness for graph-backed, memoryful AI agents.

The project models a Sales Reasoning Model-style architecture with a typed ontology, knowledge graph traversal, structured tenant memory, attack families, evidence mapping, and an offline dashboard. It is designed to run entirely on deterministic local fixtures.

## Decision surface

Local SRM architecture red-team harness for graph, memory, drift, and ISO 42001 evidence.

## Evaluator shape

- Five architecture-aware attack families: ontology poisoning, memory smuggling, graph-walk injection, drift probes, and avatar transcript jailbreaks.
- Paired-run graph invariant diffing that catches internal state corruption even when the visible answer looks acceptable.
- ISO/IEC 42001 Annex A.6 evidence export with deterministic evidence IDs and mitigation mapping.
- Local DuckDB run store, JSONL evidence artifacts, benchmark output, and static dashboard.

## Quick path

```bash
uv sync
uv run srm-redteam init-demo
uv run srm-redteam run --iterations 20
uv run srm-redteam evidence
uv run srm-redteam verify
uv run srm-redteam dashboard
```


![srm-redteam evidence map](outputs/evidence_map.svg)

## Materialized results

- `outputs/summary.json` for headline metrics and gate status
- `outputs/reports.json` for per-case results
- `outputs/dashboard.html` for visual inspection
- `outputs/demo-pack.zip` or `outputs/demo_pack/` for portable review

## Acceptance checks

```bash
uv run pytest -q
uv run ruff check .
uv run srm-redteam benchmark
uv run srm-redteam export-demo-pack
```

## Repo boundary

The `srm-redteam` public surface is source, tests, lockfile, and docs. It does not need credentials, browser state, customer records, or hosted services.
