# Security Review

Reviewed as a local synthetic-data showcase project on 2026-05-17.

## Threat Model

- Assets: synthetic ontology, synthetic tenant memory, generated findings, dashboard HTML, and evidence exports.
- Trust boundaries: local CLI arguments, local JSON/TOML fixture files, generated HTML rendering.
- Out of scope: real customer data, vendor production systems, live SRM endpoints, OAuth, and external network calls.

## Findings

No reportable security findings remain for local showcase use.

## Scan Coverage

- Threat model: local CLI and static dashboard over synthetic fixtures; no real tenant data, production endpoints, credentials, or browser cookies are in scope.
- Finding discovery checked command execution, deserialization, network clients, filesystem writes, template rendering, DuckDB usage, and secret-like patterns.
- Validation confirmed no application shell execution, no external network client, no unsafe deserialization, no hardcoded credentials, parameterized DuckDB inserts, and autoescaped dashboard rendering.
- Attack-path analysis found no realistic attacker-reachable high-impact path because the app has no server-side listener, auth boundary, external network calls, or privileged state-changing surface.

## Notes

- No application shell execution is used.
- No external network client is used by the application.
- DuckDB writes use parameterized inserts.
- Dashboard text is autoescaped; only internally generated Plotly HTML is marked trusted.
- Generated state is excluded by `.gitignore`.
