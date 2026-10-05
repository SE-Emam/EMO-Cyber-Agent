# POST-T018 Phase 0 — Baseline Record

Agent: 0A (Baseline Recorder). Read-only mandate: no source/test/build/git modifications performed. Sole write: this file.

Date (UTC): 2026-10-05. Working directory: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`.

## 1. Git

- `log --oneline -5` (repo root `/Users/emamabdullaziz`):
  - `12cc5a1 chore(release): 0.1.0 candidate records, hygiene, assessment reports`
  - `3790d53 feat(recovery): add bounded recovery contracts`
  - `f9c8185 feat(progress): integrate CLI/MCP reporting with ProgressReporter`
  - `982fc90 docs: UAG-028 final decision - NO GREEN TAG`
  - `24555ac feat: UAG-028 production closure evidence (NOT GREEN, no tag)`
- HEAD: `12cc5a1d24319ec3bf792175e7f6af9643f3a4f2`
- Branch: `main`
- Remote: `origin https://github.com/emam2025/Tech-Makers.git` (fetch + push)
- Status scoped to `Desktop/EMO-Cyber-Agent`: **130 untracked (`??`) entries, 0 tracked modifications** (`git diff --name-only` empty per POST-T017-final-review; only 2 files tracked in git index for this subtree: `Desktop/EMO-Cyber-Agent/CHANGELOG.md`, `Desktop/EMO-Cyber-Agent/reports/security/ECA-T016-invariant-release-gate.md`).
- Note: release-manifest `git_revision` is `9f6ba34ad0375ea05824e0c3cd599613d6f0a315` (build-time revision), which differs from current repo HEAD `12cc5a1` — expected: candidate records/hygiene commits landed after the artifact build.

## 2. Version

- `pyproject.toml`: `[project] name = "emo-cyber-agent"`, `version = "0.1.0"`. Build backend `hatchling.build`; entry point `cyber-agent = "emo_cyber_agent.cli.main:app"`.
- `src/emo_cyber_agent/__init__.py`: `__version__ = "0.1.0"`. SUPPORTED_API = SecurityAuditor, ReportService, generate_report, __version__; PROVISIONAL_API = ReasoningEngine, VerificationService, EvidenceStore, SecurityFinding, AuditReport.

## 3. Artifacts

- `dist/`:
  - `emo_cyber_agent-0.1.0-py3-none-any.whl` — 598306 bytes — sha256 `60fccf19c25763f9591236748ab29dc17d274d5d32d2ab2c9ce98fd71c97f076`
  - `emo_cyber_agent-0.1.0.tar.gz` — 804263 bytes — sha256 `053da70703777e8b81623fa8808c3ea1e74deaf0802e309d01979fb1b6ada118`
  - (`dist/.gitignore` present, 1 byte)
- `release/release-manifest.json`: version `0.1.0`, git_revision `9f6ba34ad0375ea05824e0c3cd599613d6f0a315`, source_tree_digest `5145b2f4d06411e3975112fc3e8698eece5135f88e13608bfc12e05c26b71724`; wheel/sdist name+size+sha256 match `dist/` above; gates: security PASS, evaluation PASS, invariant PASS; test_result `1391 passed, 2 skipped (8 release-manifest tests pending release/)`; test_count 1401 (1350 unit + 51 release); schemas 36/36; release_channel `final`.
- `release/SHA256SUMS` (3 lines):
  - `60fccf19...97f076  emo_cyber_agent-0.1.0-py3-none-any.whl`
  - `053da707...ada118  emo_cyber_agent-0.1.0.tar.gz`
  - `7fdbad0b...5d33e6  release-manifest.json`
- `release/` also contains: CHANGELOG.md, LICENSE, SECURITY.md, effective_artifact_verification.json.

## 4. Structure

- `src/emo_cyber_agent` top-level (25 entries): `__init__.py`, `adapters/`, `agent_security/`, `change_analysis/`, `cli/`, `code_intelligence/`, `core/`, `domain/`, `evaluation/`, `extensions/`, `mcp/`, `playbooks/`, `progress/`, `providers/`, `recovery/`, `report_templates/`, `reporting/`, `security/`, `security_knowledge/`, `skills/`, `tasks/`, `threat_modeling/`, `tools/`, `verification/` (+ `__pycache__/`).
- `progress/`: `__init__.py`, `events.py`, `reporter.py`, `state.py`.
- `recovery/`: `__init__.py`, `actions.py`, `checkpoint.py`, `classification.py`, `errors.py`, `manager.py`, `policy.py`, `reporting.py`.

## 5. Reports

- `reports/development/` matching `POST-T0*` (7 files):
  - `POST-T016-postrelease-progress-recovery-assessment.md`
  - `POST-T017-checksum-forensics.md`
  - `POST-T017-final-release-readiness.md`
  - `POST-T017-final-review.md`
  - `POST-T017-git-forensics.md`
  - `POST-T017-regression-audit.md`
  - `POST-T017-release-integrity.json`
  - (Related non-T0 POST reports also present: POST-PROGRESS-core-review, POST-PROGRESS-final-review, POST-PROGRESS-git-hygiene, POST-RC-001..014.)
- `reports/security/` matching `POST-*` (2 files):
  - `POST-PROGRESS-security-review.md`
  - `POST-T017-final-security-review.md`
  - (Also: `00-security-baseline.md`, `ECA-T015-security-assessment.md`, `ECA-T016-invariant-release-gate.md`, `ECA-T016-release-security-assessment.md`.)

## 6. Invariants (12)

Authoritative definition: `docs/21-developer-agent-execution-directive.md` §2 (12 non-negotiable project invariants). Per-item release evidence: `reports/security/ECA-T016-invariant-release-gate.md` §§1–12. Live regression: `tests/unit/test_hardening.py::test_invariant_regression_matrix` (12 assertions; gate owner per `scripts/release/gates.py::InvariantGate`). Historical root: `docs/00-project-charter.md` §Core invariants (10-item precursor; items 10–12 evolved — charter item 10 "human review" superseded by specialist/delegation invariants 10–12 in the directive). Corroborating assessments: `reports/security/00-security-baseline.md`, `reports/security/ECA-T015-security-assessment.md`, `reports/security/ECA-T016-release-security-assessment.md`, `reports/security/POST-PROGRESS-security-review.md`, `reports/security/POST-T017-final-security-review.md` (verdict PASS, 12/12).

1. Read-only by default — `StrictPolicyEngine` default-deny + read_only-forced adapters + VerificationService profile gate.
2. Repository content is untrusted data, never higher-priority instructions — `mark_untrusted` envelopes + constructor/model boundaries + escaped reporting.
3. No material security finding without evidence — constructors (`SecurityObservation`, `FindingCandidate`, `FindingStore.add`), eligibility, reportability gates.
4. No destructive action without explicit permission transition — absence by construction + deny patterns + plan-time SQL classification.
5. Tool outputs are evidence, not instructions — normalization parsers + untrusted envelopes + mandatory correlation re-entry.
6. Model uncertainty is represented explicitly — graph-grounded confidence; severity⊥confidence; no LLM scores.
7. MCP, CLI, and Python API use the same domain contracts — single delegate/service paths (`ReportService`, `VerificationService.plan`, `SecurityAuditor`).
8. Provider/model choice remains external to the Core — ABC ports only; zero vendor imports in Core.
9. Scanner-specific facts retain scanner provenance, not overwritten by model interpretation — tool/version/invocation/digest on every observation.
10. Cross-project state reuse is prohibited unless explicitly designed and authorized — audit-bound fingerprints/queries/contexts/decisions/evidence/plans/findings/reports; per-request scoping.
11. The Security Agent is a specialist worker, not a general-purpose coding agent — 6 MCP tools + 8 CLI commands, all security-scoped.
12. The host agent delegates security work; EMO owns the security investigation workflow after delegation — session/result delegation returns; stateless adapters; Core owns transitions.

## 7. Tests

- Full suite NOT re-run in Phase 0 (per mandate). Last known authoritative result (prior evidence, `reports/development/POST-T017-final-review.md` §3 citing Agent 5): **1499 passed / 0 failed / 2 skipped** (skips = missing optional `trivy`/`osv-scanner`). Release-manifest-time record: 1391 passed, 2 skipped of 1401 collected (1350 unit + 51 release). Invariant matrix: 12/12 PASS. Schemas 36/36. Evaluation owner suite 116/116 PASS.
- Test files present:
  - `tests/unit/`: 58 entries incl. `test_hardening.py` (invariant matrix owner), plus progress/recovery coverage: `test_cli_progress.py`, `test_mcp_progress.py`, `test_progress_e2e.py`, `tests/unit/progress/test_progress_events.py`, `tests/unit/recovery/test_recovery_contracts.py`. Newest (post-release progress/recovery wave): `test_progress_e2e.py`, `test_cli_progress.py`, `test_mcp_progress.py`, `tests/unit/progress/`, `tests/unit/recovery/`.
  - `tests/contract/`: README.md only.
  - `tests/release/`: conftest.py, test_artifacts.py, test_build.py, test_entrypoints.py, test_installation.py, test_packaged_resources.py, test_release_integrity.py, test_release_manifest.py, test_release_smoke.py.
  - `tests/fixtures/`: agent_security, change_analysis, evaluation, extensions, security_knowledge, security_skill_packs, threat_modeling, tool_packs, verification (+ READMEs).

## 8. Frozen-RC Statement

The source tree **WILL change** during POST-T018. Therefore the current **0.1.0 RC — wheel `60fccf19…`, sdist `053da707…`, manifest revision `9f6ba34a`, source-tree digest `5145b2f4…`** — is hereby designated the **Frozen Reference / historical baseline**. Any post-T018 build MUST produce new digests; equality with the frozen hashes after source changes would indicate a stale-artifact defect. All comparisons in later T018 phases anchor to this record.

## Gate P0: BASELINE RECORDED
