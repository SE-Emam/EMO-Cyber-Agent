# ECA-T016 — Invariant Release Gate

For each of the 12 non-negotiable invariants: definition, enforcing
layer, regression tests, release evidence, residual limitation, RC status.
Nothing here is claimed without a test behind it.

Release refresh (final): full suite **1399 passed, 2 skipped** (1401
collected: 1350 unit + 51 release); invariant matrix
`test_hardening.py::test_invariant_regression_matrix` (12 live
assertions) PASS; evaluation owner suite 116/116 PASS; schemas 36/36;
6 MCP tools + 8 CLI commands (additive since the RC draft: `extensions`
command, `cyber_extensions` tool — no surface removed).

## 1. Read-only by default
- Enforcing layer: `StrictPolicyEngine` (default-deny) + read_only-forced
  adapters + `VerificationService` profile gate.
- Tests: `test_hardening.py::test_invariant_regression_matrix[1]`,
  `test_toolchain.py` (read-only specs), `test_verification.py`
  (active-under-read_only denial), `test_cli.py` (no write flags exist).
- Release evidence: clean-install `doctor` reports `read_only` posture;
  `verify`/`controlled_reproduction` denied without verify profile + grant.
- Residual: live-runner wiring may add future profiles only via new
  explicit grants. RC: PASS.

## 2. Repository content is untrusted data
- Enforcing layer: `mark_untrusted` envelopes + constructor/model
  boundaries + escaped reporting.
- Tests: 12-phrase corpus × evidence/correlation/MCP/CLI (all DATA),
  envelope preservation end-to-end.
- Release evidence: 1401-test suite green incl. corpus battery.
- Residual: future renderers must reuse `md_escape`/envelopes. RC: PASS.

## 3. No material finding without evidence
- Enforcing layer: constructors (`SecurityObservation`,
  `FindingCandidate`, `FindingStore.add`), eligibility, reportability.
- Tests: evidenceless construction/storage/promotion/report denials.
- Release evidence: `is_reportable` gate on every report path.
- Residual: none known. RC: PASS.

## 4. No destructive action without explicit permission
- Enforcing layer: absence by construction (no destructive method exists
  in any phase) + deny patterns in policy + plan-time SQL classification.
- Tests: write/destructive SQL battery, destructive-capability denials,
  exploit-primitive source scans.
- Release evidence: purity greps clean; wheel contains no exploit code.
- Residual: none (capability does not exist to be misused). RC: PASS.

## 5. Tool outputs are evidence, not instructions
- Enforcing layer: normalization parsers + untrusted envelopes +
  mandatory correlation re-entry + injection-as-data handling.
- Tests: prompt-injection outputs, malicious tool-output storage test,
  unsafe-request criteria mapping.
- Release evidence: injection battery green incl. post-packaging rerun.
- Residual: none known. RC: PASS.

## 6. Model uncertainty is represented explicitly
- Enforcing layer: graph-grounded confidence everywhere; model
  uncertainty informational only; severity⊥confidence.
- Tests: confidence determinism tables, 0.99-uncertainty non-transfer,
  no-LLM-score assertions.
- Release evidence: no model SDK in runtime deps; no scores anywhere.
- Residual: none. RC: PASS.

## 7. MCP, CLI, and Python API use the same domain contracts
- Enforcing layer: single delegate/service paths (`ReportService`,
  `VerificationService.plan`, `SecurityAuditor`).
- Tests: MCP≡CLI equivalence (report bytes via both paths), contract
  chain tests, `test_invariant_regression_matrix[7]`.
- Release evidence: interop + CLI E2E against the installed wheel.
- Residual: none. RC: PASS.

## 8. Provider/model choice remains external to the Core
- Enforcing layer: ABC ports only; zero vendor imports in Core;
  config selects endpoint names, never policy.
- Tests: provider-external source scan; config policy-key rejection;
  MODEL_UNAVAILABLE-is-failure (not downgrade) path.
- Release evidence: `pip` metadata shows no model/provider runtime deps.
- Residual: future provider wiring must preserve the ABC boundary. RC: PASS.

## 9. Scanner facts keep provenance; models don't overwrite them
- Enforcing layer: tool/version/invocation/digest on every observation;
  scanner severities verbatim-as-data; conflict preservation.
- Tests: provenance completeness, conflict non-resolution, downgrade
  with recorded reason.
- Release evidence: suite green; no finding overwrites scanner strings.
- Residual: none. RC: PASS.

## 10. Cross-project state reuse is prohibited
- Enforcing layer: audit-bound fingerprints/queries/contexts/decisions/
  evidence/plans/findings/reports; per-request scoping in adapters.
- Tests: cross-audit/cross-project matrices per layer + concurrent
  isolation + split-facts non-join.
- Release evidence: full matrices green post-packaging.
- Residual: none. RC: PASS.

## 11. The Security Agent is a specialist worker
- Enforcing layer: 6 MCP tools + 8 CLI commands, all security-scoped;
  no general coding surface exists to expose.
- Tests: surface-exactness (MCP + CLI), no-general-capability scans.
- Release evidence: discovery payload + `--help` contain only the
  documented surface; installed `--help` verified clean.
- Residual: none. RC: PASS.

## 12. The host delegates; EMO owns the workflow after delegation
- Enforcing layer: session/result objects as delegation returns;
  adapters stateless; Core owns all transitions.
- Tests: session scoping, statelessness (no `_audit` attrs), E2E
  delegation flows (mock host + CLI).
- Release evidence: live SDK interop + installed-CLI E2E green.
- Residual: persistent sessions are future work (stateless per request
  today — documented, not hidden). RC: PASS.

## Overall
12/12 PASS with test-backed evidence each. No invariant weakened since
T015; two boundaries tightened (execution binding, path validation).
Final release evidence: installed wheel + pipx install verified,
Python API/CLI/MCP/extension smoke green from the installed artifact,
adversarial suites (POST-RC-014: 177 extension tests incl. 46
adversarial; evaluation: 116) all green, 36/36 schemas from the wheel.
