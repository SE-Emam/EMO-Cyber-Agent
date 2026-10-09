# Changelog

## 0.2.1 — Sanitizer control-char hardening (POST-T021)

- Bounded `subagent/sanitizer.py::normalize()` fix: stripped control
  characters (`\r`, `\x0b`, `\x0c`, …) now emit a collapsing space separator
  instead of deleting, so grouped controls can no longer fuse tokens and
  bypass detection (`ignore\rthe policy` → detected). Benign CRLF handling
  unchanged (`\r\n` still folds to `\n`); no authority, policy, severity,
  evidence, or verification semantics changed.
- 20 new `post_t021/` benchmark cases (measurement-only, gap-mapped) and
  online Linux/Windows runtime parity proof (ubuntu-24.04 + windows-2025 ×
  Python 3.11/3.14). Requires Python >=3.11. See POST-T021 final review.

## 0.2.0 — Threat-intel + HTTP transport (POST-T018/POST-T020)

- New `threat_intel` package: leak monitor, feed triage, ATT&CK mapper,
  Kali detector pack (defensive knowledge only); new opt-in MCP tool
  `cyber_threat_intel` (7-tool surface).
- Streamable HTTP transport (`mcp/http_server.py`, stdlib-only).
- Checklists, official report templates, benchmark corpus expansion.
- Requires Python >=3.11. See POST-T020 acceptance assessment.

## 0.1.0 — Final Release (ECA-T016)

Release gate: `reports/development/ECA-T016-release-security-assessment.md`
(decision PASS; manifest `release/release-manifest.json`).

- MCP stdio adapter (6 high-level tools) and universal CLI (8 commands,
  documented exit codes, stdout/stderr split, `--version` flag).
- Extension ecosystem (POST-RC-014): manifest contract, digest-bound
  identity, host-side trust, compatibility, provenance, conflicts,
  deterministic resolver, gated loader, read-only CLI/MCP surfaces.
- Evaluation lab (POST-RC-013): blind corpus, scoring runner, oracles,
  metric pools, threshold gates, cross-interface parity (all green).
- Packaging: wheel+sdist with 36 schemas, 2 policies, 94-file official
  catalog, LICENSE; version-consistent metadata (Core Metadata 2.6,
  SPDX Apache-2.0); `pyyaml`/`jsonschema` promoted to runtime
  dependencies (base installs load all content).
- Verification: 1401 tests green (1350 unit + 51 release), 36/36 schemas,
  ruff clean on release scope, OSV/Trivy 0 vulnerabilities, no shipped
  secrets, 12/12 invariants PASS from the installed artifact.

Security fixes (not hidden): execution decisions are now target- and
policy-version-bound; path/ref validators deny null bytes, percent- and
double-encoded traversal, and drive-letter paths; Markdown escaping
collapses newlines in single-line contexts.

Limitations: audit persistence, live runners/harnesses, MCP-over-HTTP,
progress streaming, and real-network integrations are explicitly out of
this release. No scores, no remediation automation, no exploit
capabilities — by design, permanently.

## 0.1.0-rc1 — Release Candidate 1

Delivered through ECA-T001…ECA-T016 (reports in `reports/development/`):

- Domain Core + state machine; PolicyEngine (default-deny) + ToolRegistry.
- Repository + Supabase read-only integrations (scope-bound, redacted).
- Deterministic toolchain: semgrep/trivy/osv-scanner/gitleaks behind an
  argv-only, confined, secret-free execution boundary.
- Evidence graph + deterministic correlation; reasoning loop with bounded
  budgets and no model authority; verification layer (plans, never
  exploits); finding lifecycle with gated promotion; JSON/JSONL/Markdown
  reporting (projection only, no scores).
- MCP stdio adapter (5 high-level tools) and universal CLI (7 commands,
  documented exit codes, stdout/stderr split).
- Security hardening campaign (ECA-T015): 3 real boundary weaknesses
  found and fixed in-boundary (execution-decision binding, encoded path
  traversal, report newline confinement) with regression tests.
- Packaging: wheel+sdist with bundled schemas/policies/LICENSE,
  version-consistent metadata, Apache-2.0 license.

Security fixes (not hidden): execution decisions are now target- and
policy-version-bound; path/ref validators deny null bytes, percent- and
double-encoded traversal, and drive-letter paths; Markdown escaping
collapses newlines in single-line contexts.

Limitations: audit persistence, live runners/harnesses, MCP-over-HTTP,
progress streaming, and real-network integrations are release-integration
work, explicitly out of this RC. No scores, no remediation automation,
no exploit capabilities — by design, permanently.

## 0.1.0-foundation

- Initial repository foundation.
- Project charter and requirements.
- Architecture and security methodology.
- MCP/CLI/Python API contracts.
- Tool and permission model.
- Versioned JSON schemas.
- Implementation phases and evaluation plan.
- Model-agnostic provider interface.
