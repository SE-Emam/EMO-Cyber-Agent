# ECA-T012 — Reporting & Export Contracts

## Objective
Turn Core SecurityFindings into consumable JSON / JSONL / Markdown with
identity, provenance, verification chains, severity, confidence,
classifications, scope, timestamps, and version metadata fully preserved.
Reporting projects; it never decides, mutates, reinterprets, or scores.
Core Finding = source of truth, then and always.

## Scope
In scope: read-only projection models, Core-gated reportability, three
deterministic serializers, versioned export schema + round-trip
validation, deterministic ordering, provenance/verification preservation,
suppression/duplicate visibility rules, defense-in-depth redaction,
untrusted-content escaping, unified snapshot semantics, failure codes,
partial-state visibility, derived-only summaries (no scores), limitations,
ReportGenerator contract, thin CLI adapter, Python API, 23 offline tests.
Out of scope (deferred): MCP server (T013), full CLI (T014), stabilized
Python API surface (T015), hardening/RC (T016), AI narrative, scoring,
remediation execution.

## Reporting Architecture
```text
                    EMO Core
                       │
        ┌──────────────┴──────────────┐
        │                             │
  Security Engine               Evidence Graph
        │                             │
        └──────────────┬──────────────┘
                       │
                 SecurityFinding
                       │
                 Reportability (Core gate)
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
         JSON         JSONL       Markdown
```
`core/reporting.py` (~380 lines) owns projection + serializers.
`ReportService`/`generate_report` is the ONLY Core→Reporting path; CLI
parses args and prints. No Model→Report, Scanner→Report, or Tool→Report
path exists.

## Report Model
Export-only mirrors (never domain replacements): `AuditReport`
(metadata/summary/findings/non_reportable), `ReportMetadata`
(report/schema/emo versions, ONE generated_at, audit/project/scope,
policy/correlation/classification versions, limitations),
`FindingReport` (all finding fields + `EvidenceReference`/
`VerificationReference` id-sets), `AssetReport`-equivalent data carried
inside finding asset/location fields, `SummaryStats` (pure inventory
counts + severity split — no score field exists anywhere).

## JSON Contract
Canonical: UTF-8, `sort_keys`, compact separators, stable nulls (null
stays null; display fallbacks like "Not assessed" exist ONLY in
Markdown), versioned envelope (`report_version`/`schema_version` 1.0),
machine-readable, schema-validated in tests (round-trip:
domain → projection → JSON → schema → parse → semantic re-check).

## JSONL Contract
Formal stream, documented and pinned: `{"record":"metadata"…}` then one
`{"record":"finding"…}` per finding in canonical order, then
`{"record":"summary"…}`. Streamable, deterministic, line-parseable
(stream test parses every line independently).

## Markdown Contract
Human target with fixed sections: Summary (counts + explicit
anti-misreading disclaimer), Limitations, Findings (severity/confidence/
location/evidence+verification refs, root cause, impact, remediation,
references), Non-reportable appendix (visible, never silently dropped).
Raw secrets never rendered; nulls render as "Not assessed"/"n/a"/"none".

## Schemas
`docs/schemas/report.schema.json` (NEW, `$id`-versioned, report 1.0):
metadata/summary/findings/non_reportable with severity enum, confidence
range, required identity fields, `additionalProperties: false`.
Direction honored: Domain → serialization → schema (schema validates the
projection; nothing in Core derives behavior from it). Legacy schemas
untouched; 5/5 files syntactically valid.

## Versioning
Independent `report_version = "1.x"` (+ schema/emo versions in every
envelope); breaking export changes bump major. Deliberately NOT tied to
the Python package version except as recorded metadata.

## Ordering
Canonical read-order severity→category→asset→location→finding_id,
implemented once (`order_findings`) and shared by all three formats.
Documented as readability-only; ranking language ("best/worst") absent
by construction and by test.

## Provenance
Finding → candidate/observation/evidence/verification ids +
classification/policy/schema versions + per-evidence tool/location/
timestamp/digest references + per-verification method/status/confidence.
Full-object embedding avoided (references stay stable; bulk stays out).

## Verification Presentation
Statuses render verbatim (supported/refuted/inconclusive confirmed
unchanged across formats by test); no INCONCLUSIVE→LOW or
BLOCKED→REFUTED remapping exists anywhere in the projection code.

## Suppression/Duplicate Handling
Default report = reportable findings only; `include_non_reportable=True`
appends a clearly-labeled appendix (projection choice, zero Core-state
effect). Refuted/suppressed/duplicate/resolved stay visible there, never
deleted.

## Redaction
Final defense-in-depth at projection: repository + Supabase redactors
over every string field (titles, descriptions, locations, references,
provenance strings); javascript:/data:/vbscript: references dropped, not
rendered. Principle kept: secrets must never enter domain evidence in the
first place — this layer only catches strays (all redaction assertions
use planted secrets).

## Untrusted Content
`md_escape` neutralizes Markdown/HTML structure (`< > [ ] ( ) # * _ |`
+ backtick→fullwidth) and `md_fence` neutralizes code fences; oversized
fields capped (title 500/desc 2000/etc.), unicode preserved as escaped
text. Battery: hostile titles/descriptions/paths/SQL/unicode/oversized —
output stays inert text with balanced fences (test-pinned).

## Snapshot Semantics
`build_report` stamps ONE `generated_at` reused by JSON envelope,
JSONL metadata line, and Markdown header; all sections derive from the
single input list in one call (no T1-list/T2-metadata skew possible).

## Failure Semantics
`ReportErrorCode`: INVALID / SCHEMA_ERROR / SERIALIZATION_ERROR /
REDACTION_ERROR / SOURCE_MISSING / REPORTABILITY_DENIED /
CONSISTENCY_ERROR. Empty audit → INVALID; foreign-audit finding →
REPORTABILITY_DENIED (never a partial-looking-complete report); CLI maps
failures to exit 2 (usage/data) / 3 (runtime).

## CLI Adapter
`cyber-agent report --findings <json> --audit-id <id> --format
json|jsonl|markdown [--output path] [--include-non-reportable]`:
parses args → validates `SecurityFinding` items → `ReportService` →
prints/writes. Builds nothing itself (verified by inspection + CLI tests
incl. invalid-format/missing-file/cross-audit exits).

## Python API Adapter
`ReportService.generate/generate_json/generate_jsonl/generate_markdown`
+ functional `generate_report()` — the single seam for future CLI/MCP/CI/
host-agent use, with zero duplication.

## Security Tests
In `test_reporting.py` (offline): hostile title/desc/path/SQL, HTML/JS
links, secret-planted titles/descriptions, oversized (5000-char) +
unicode + null-byte inputs, javascript: reference dropping, cross-audit
injection (CLI + API), secret-absence across all three formats, fence
balance, no-LLM source scan.

## Fixtures
Builder-based deterministic fixtures: FULL_REPORT (5 severities),
EMPTY_AUDIT, CONFIRMED/REFUTED/INCONCLUSIVE/SUPPRESSED/DUPLICATE states,
MULTI_SOURCE (evidence+verification refs), MALICIOUS_CONTENT_REPORT,
SECRET_REDACTION_REPORT, CONFLICTED (severity-split display),
PARTIAL_AUDIT (limitations). All fixed ids/rules/severities.

## Files Inspected
- `core/findings.py` (SecurityFinding/is_reportable — reused, not reimplemented)
- `core/correlation.py`, `core/verification.py`, `core/policy.py`,
  `core/tool_registry.py`, `core/execution.py`, `core/scanners.py`,
  `core/repository.py`, `core/supabase.py`, `core/contracts.py`,
  `domain/models.py`, `cli/main.py`, `adapters/*`
- `docs/16/02/03`, `docs/schemas/*`, all prior unit tests

## Files Changed
- `src/emo_cyber_agent/core/reporting.py` (NEW): models, projection,
  ordering, summaries, 3 serializers, escaping/redaction, ReportGenerator,
  ReportService, `generate_report`, failure codes.
- `docs/schemas/report.schema.json` (NEW): versioned export contract.
- `src/emo_cyber_agent/cli/main.py` (ADDITIVE): thin `report` command only.
- `tests/unit/test_reporting.py` (NEW): 23 offline tests.
- (No domain/policy/adapter/schema-legacy changes; no LLM; no scoring.)

## Invariant Impact
1. Read-only — ENFORCED (frozen models; input list provably unmutated).
2. Untrusted content — ENFORCED (escaping + caps + fence balance).
3. No finding without evidence — PROTECTED (Core gate reused verbatim).
4. No destructive action — ENFORCED (no mutating surface).
5. Tool outputs are evidence — PROTECTED (references preserved end-to-end).
6. Uncertainty explicit — ENFORCED (confidence/severity verbatim + nulls kept).
7. Same contracts — ENFORCED (single service path for all adapters).
8. Provider external — ENFORCED (no provider imports).
9. Scanner provenance — ENFORCED (tool/location/digest refs in every finding).
10. No cross-project reuse — ENFORCED (per-finding audit match; cross-audit denied at API + CLI).
11. Specialist worker — ENFORCED (projection-only module; no-LLM scan).
12. Host delegates — PROTECTED (report objects are delegation returns).
No invariant weakened; reporting adds zero authority by construction.

## Known Limitations
- CLI `report` consumes a findings-JSON file; live audit persistence +
  `audit → report` wiring awaits release integration (adapters stay thin
  by design, so this is a seam, not a gap).
- Markdown is single-locale English; i18n out of scope.
- `non_reportable` detail level mirrors finding projections (no separate
  redacted tier yet — same redaction applies).

## Deferred Work
T013 MCP server, T014 full CLI, T015 Python API stabilization, T016
hardening/host-integration/RC; AI narrative (separate feature, must not
alter canonical reports); scoring/grading (explicitly never); remediation
execution (never autonomous).

## Evidence
- `pytest tests/ -p no:warnings` → `238 passed, 3 skipped`.
- `validate_schemas.py` → 5/5 OK (incl. new report schema).
- Schema round-trip test validates generated JSON against
  `report.schema.json` via `jsonschema`. `compileall` → OK.
- Determinism tests (JSON + JSONL byte-equality), order test, fence
  balance, secret-absence, cross-audit denial (API + CLI exits 2/3).
- Files: `core/reporting.py`, `docs/schemas/report.schema.json`,
  `cli/main.py` (+report), `tests/unit/test_reporting.py`.

## Final Status
**PASS** — all 23 exit criteria met: port/service, 3 exports, public
versioned schema + validation, deterministic ordering, full provenance +
verbatim verification/severity/confidence, zero Core mutation, zero LLM,
zero reinterpretation/scoring, zero secret leakage, injection escaping,
visible partial/blocked states, Core-gated reportability, cross-audit
blocking, snapshot consistency, failure codes, unit + security tests,
prior suites + schemas green. No BLOCKED condition (no severity/
confidence/status/verification/evidence/policy/classification mutation)
observed. T013 (MCP) may proceed — as a pure interface over this Core.
