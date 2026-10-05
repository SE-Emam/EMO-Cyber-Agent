# ECA-T007 — Deterministic Security Toolchain

## Objective
Add the first deterministic security-tooling layer: reproducible fact
collection from the project via four command-based scanners, with zero
security reasoning and zero final findings. Scanner output is evidence
source only; EMO findings come later (ECA-T008 correlation phase).

## Scope
In scope: policy-gap closure, execution port + process boundary, four
adapters (semgrep, trivy, osv-scanner, gitleaks) with ToolSpecs,
normalization models, evidence conversion, error semantics,
reproducibility metadata, mock executors, offline security/boundary/
contract tests, optional real-tool tests (skipped when absent).
Out of scope (deferred): LLM planning/tool selection, correlation,
business-logic reasoning, exploit verification, remediation, MCP/CLI logic,
additional scanners.

## Policy Prerequisite
Option (A) implemented — production-safe default-deny inside Core:
new `src/emo_cyber_agent/core/policy.py` provides `StrictPolicyEngine`
(default-deny + auditable `PolicyDecision` per evaluation) instead of
relying on the legacy allow-all `DefaultPolicyEngine`.
- unknown capability → DENY (`unknown-capability:*`)
- missing capability list → DENY (`missing-explicit-capability`)
- write/destructive/admin patterns → DENY unless explicitly granted
  (default grant sets are empty)
- `scanner.network.read` → DENY unless explicitly granted
- non-`read_only`/`verify` profiles → DENY
- missing audit/tool/target context → DENY
- execution without a stored ALLOW decision → DENY (enforced by executor)
- every decision persisted with id/audit/capability/target/allowed/profile/
  reason-codes/constraints/timestamp/policy-version (`eca-t007-v1`)
`DefaultPolicyEngine` is KEPT UNCHANGED for the ECA-T005/T006 read-only
fact path (existing tests depend on it). `ToolExecutor` REFUSES any engine
that is not `StrictPolicyEngine` (constructor `TypeError`, negatively
tested), so allow-all can never become an execution workaround. Gate
condition satisfied — no BLOCKED state needed.

## Execution Architecture
```text
ToolSpec → ToolRegistry → StrictPolicyEngine → PolicyDecision
→ ToolExecutor → ToolExecutionPort → Scanner Adapter (argv+parse)
→ Raw Result → Normalizer → ScannerObservation → EvidenceItem → Core
```
Forbidden paths stay forbidden: Agent→shell, CLI/MCP→scanner direct.
All four adapters resolve through the same registry + policy + invocation
lifecycle as every other tool.

## ToolExecutionPort
`src/emo_cyber_agent/core/execution.py`: abstract `run(ExecutionRequest)
→ ExecutionResult`. Contains no reasoning/severity/remediation/
classification; cannot run without a valid stored ALLOW decision (the
executor checks before calling the port, and the port itself validates
argv shape).

## Process Isolation
`ProcessExecutionPort` (stdlib `subprocess`, `shell=False` always):
- argv arrays only; non-tuple/non-string/empty/null-byte argv → DENY
- explicit confined cwd (audit root; escapes denied pre-exec)
- `sanitized_env()` from `SAFE_ENV_ALLOWLIST` (`NO_COLOR/LC_ALL/LANG/TZ`)
  only — host secrets never inherited; secret/unlisted keys → DENY
- timeout (default 120s, cap 1800s), stdout 256KiB / stderr 64KiB limits
  with truncation flags, exit-code/signal capture
- distinct outcomes: SUCCESS / TOOL_UNAVAILABLE (missing binary) /
  TIMEOUT / POLICY_DENIED / TOOL_FAILED — never conflated

## Filesystem Boundary
`confine_path(audit_root, target)`: null-byte/empty denial, absolute-path
and `..` escapes resolved via `realpath` and denied (incl. symlink escape,
tested with a real symlink fixture), result confined to the audit root.
Target identity is part of scope; argv's final element is the confined
absolute path derived from trusted spec + fixed adapter logic — repository
filenames/content NEVER appear in argv construction.

## Environment Boundary
Default: NO SECRET ENVIRONMENT. `sanitized_env` inherits only 4 safe keys;
test pins `GITHUB_TOKEN` absence post-sanitization and denial of
secret-bearing/unlisted extra keys. Env fingerprint records SORTED KEY
NAMES ONLY (never values) for reproducibility without leakage.

## Network Boundary
Two capabilities, separated: `scanner.local.execute` (default-allowable in
read_only) vs `scanner.network.read` (deny-by-default, explicit-grant
only). semgrep/trivy/gitleaks declare local-only; osv-scanner declares
network (vuln-DB access) and is denied end-to-end without a grant (tested).

## Semgrep
`SemgrepAdapter`: argv `semgrep scan --json --quiet <target>`; parses
`results[]` → observations (rule id, path, start/end lines, verbatim
scanner severity as DATA, message envelope, rule reference, raw digest).
ToolSpec `semgrep` / `scanner.local.execute` / low / read-only.

## Trivy
`TrivyAdapter`: argv `trivy fs --format json --quiet <target>`; parses
`Results[].Vulnerabilities[]` → observations (CVE id, package, installed/
fixed versions, target path, scanner severity verbatim). No EMO verdict.

## OSV
`OsvScannerAdapter`: argv `osv-scanner --format json <target>`; declares
`scanner.network.read`; parses results/packages/vulnerabilities (+aliases,
ecosystem, manifest path). Denied by default; allowed only with explicit
grant (both unit- and executor-level tests).

## Gitleaks
`GitleaksAdapter`: argv `gitleaks detect --source <target> --no-git
--format json`. SECRET-SENSITIVE: parser drops `secret/token/value/
password/key/credentials/match` keys before observation construction;
survivors are rule id, path, line, fingerprint, redacted description,
digest. Test pins `SUPERSECRETVALUE999`/`ghp_REALTOKEN123` absent from
observations AND converted evidence. Raw secrets never enter LLM context.

## Normalization
`ScannerResult/ScannerObservation/ScannerLocation/ScannerArtifact/
ScannerReference` (frozen Pydantic, Core-owned). Raw provider structures
never reach Domain — parsers map field-by-field with redaction; malformed
JSON degrades to zero-observation results (never exceptions into Core).

## Evidence Conversion
`observation_to_evidence_fields`: audit/asset/tool/version/invocation/
target/collected_at + provenance (source, rule, raw digest, adapter
version, references) + content digest + redacted 500-char summary +
locator `path:line`. Gitleaks double-gate (parser drop + evidence
redaction) verified by test.

## Error Semantics
SUCCESS (exit 0) / TOOL_UNAVAILABLE (binary missing — operational, not
security failure) / TIMEOUT / POLICY_DENIED / TOOL_FAILED (nonzero with
stderr preserved, redacted). Invocation lifecycle mirrors these states;
truncation metadata preserved; full-output digest recorded; full output
never auto-injected into model context.

## Reproducibility
Per execution: tool+version, argv digest, target, cwd identity, env
fingerprint (key names only), start/end timestamps, exit code, result
digest. Provenance carries tool/adapter versions (never "latest").

## Security Tests
In `tests/unit/test_toolchain.py` (offline): shell-injection filename
(`x; touch pwned` → single argv element, no `pwned` created, real-port
echo test), argument injection, traversal/absolute/symlink escapes,
oversized output, timeout/failure/unavailable mapping, secret-env leakage
+ secret/unlisted key denial, malicious filename+content exclusion from
argv, tool-output prompt injection staying DATA, execution without/stale/
mismatched policy, wrong capability/audit, cross-project (scope-aware
engine), unauthorized network (osv), adapter bypass (undeclared
`repository.write` via search tool).

## Mock Tests
`adapters/mock_scanners.py` `ScriptedPort` (now a real `ToolExecutionPort`
subclass) + `port_for()` scenarios: SAFE_RESULT, MULTI_RESULT,
TOOL_FAILURE, TIMEOUT, MALICIOUS_OUTPUT, SECRET_OUTPUT, OVERSIZED_OUTPUT —
all through the identical boundary contract (argv-tuple assertion inside
`run`). Full executor flow verified against MULTI_RESULT (count 2,
invocation completed).

## Real-Tool Tests
Parametrized `--version` probes, skipped when binaries absent (3 skipped
here: semgrep/trivy/osv-scanner). Environment found real `gitleaks`, which
passed. Absolute-path resolution used (boundary inherits no PATH by
design — itself a verified property). Separate from gating tests.

## Files Inspected
- `core/contracts.py`, `core/service.py` (DefaultPolicyEngine — kept),
  `core/tool_registry.py` (ToolSpec/Registry/Invocation lifecycle),
  `core/repository.py`, `core/supabase.py` (shared guards reused)
- `domain/models.py`, `security/policy.py`, `adapters/{github,mock_repository}.py`
- `docs/16-implementation-plan.md`, `02-architecture.md`,
  `03-security-methodology.md`; `docs/schemas/*.json`
- `tests/unit/test_foundation.py`, `test_repository.py`, `test_supabase.py`

## Files Changed
- `src/emo_cyber_agent/core/policy.py` (NEW): `PolicyDecision`,
  `StrictPolicyEngine` (default-deny + decision log).
- `src/emo_cyber_agent/core/execution.py` (NEW): port, process boundary,
  env/filesystem guards, `ToolExecutor` (strict-engine-only).
- `src/emo_cyber_agent/core/scanners.py` (NEW): normalized models + 4
  adapters + evidence conversion + spec factory.
- `src/emo_cyber_agent/adapters/mock_scanners.py` (NEW): 7-scenario scripted port.
- `tests/unit/test_toolchain.py` (NEW): 26 tests (23 pass + 3 optional-skip… adjusted below).
- (No MCP/CLI/API/schema/domain changes; no reasoning/remediation code.)

## Invariant Impact
1. Read-only default — ENFORCED (specs read-only; non-read profiles denied; SQL-style write patterns denied).
2. Untrusted content — ENFORCED (repo filenames/content excluded from argv; tool output enveloped as data).
3. No finding without evidence — ENFORCED STRONGER (observations carry invocation+digests; zero Finding construction — test-pinned).
4. No destructive action without permission — ENFORCED (no destructive argv exists; destructive patterns denied).
5. Tool outputs are evidence — ENFORCED (digests/summaries; secrets dropped pre-evidence).
6. Uncertainty explicit — N/A (no scoring; scanner severities verbatim-as-data).
7. Same contracts — ENFORCED (single executor path for all callers).
8. Provider external — ENFORCED (binaries external; no SDK in Core).
9. Scanner provenance — ENFORCED (tool/version/adapter-version/raw-digest/invocation on every observation).
10. No cross-project reuse — ENFORCED (scope-aware engine + per-invocation ids).
11. Specialist worker — ENFORCED (fetch→scan→normalize only; grep-clean of reasoning logic).
12. Host delegates — PROTECTED (executor owns path; direct port use useless without scope+policy).
No invariant weakened; one pre-existing gap (allow-all) CLOSED for the execution path.

## Known Limitations
- `DefaultPolicyEngine` allow-all retained ONLY for ECA-T005/T006 read paths; execution path is strict-only by construction (TypeError-tested).
- Real version discovery (`--version` capture per adapter) deferred; `tool_version` currently spec-pinned `1.0.0` (+`adapter_version=eca-t007-v1`).
- No resource constraints beyond timeout/output limits (cgroups/nice deferred, documented).
- No caching; no DAST/browser/cloud-wide scanning (per charter non-goals).

## Deferred Reasoning
Per task §22/§25: no LLM planning/selection, no correlation, no business-logic reasoning, no verification, no remediation. ECA-T008 (Evidence Correlation / Security Reasoning Foundation) is the correct next step, joining GitHub + Supabase + scanner evidence.

## Evidence
- `pytest tests/ -p no:warnings` → **97 passed, 3 skipped** (71 prior; +29 new toolchain tests: 26 pass — incl. 1 real gitleaks `--version` probe — plus 3 optional-skips for absent semgrep/trivy/osv binaries).
- `validate_schemas.py` → 4/4 OK. `compileall` → OK. Zero warnings from new modules.
- Purity greps: no `shell=True`/system/popen in Core/adapters (only docstring mentions of the prohibition); no reasoning/severity/remediation logic in scanners/execution (only docstrings + `supports_remediation=False` declarations); scanner caps contain no write/admin strings.
- Files: `core/policy.py`, `core/execution.py`, `core/scanners.py`,
  `adapters/mock_scanners.py`, `tests/unit/test_toolchain.py`.

## Final Status
**PASS** — all 24 exit criteria met: allow-all closed for execution (strict
engine + TypeError gate); executor boundary with argv-only/timeout/limits/
fs-scope/env-sanitization/no-secret-propagation; 4 adapters + specs; every
invocation via Registry+StrictPolicy; normalized results + provenance;
raw secrets excluded (double-gated); untrusted content never becomes
command; boundary/security/mock/optional-real tests present; existing tests
+ schemas green. No BLOCKED condition (no allow-all execution, no shell,
no secret propagation, no fs escape, no network/policy bypass) observed.
ECA-T008 (correlation/reasoning foundation) may proceed — agent reasoning
itself is NOT started here.
