# POST-T017 Final Security Review — Independent Reviewer (Agent 7)

**Reviewer:** Agent 7 — Independent Security Reviewer (release recovery)
**Date (UTC):** 2026-10-05
**Working directory:** `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`
**Mandate:** STRICTLY READ-ONLY on source/tests/builds. Sole authorized artifact: this file
(`reports/security/POST-T017-final-security-review.md`). No source, test, config,
release, or build file was created, modified, or rebuilt by this reviewer.
**Verdict: PASS — 12/12 invariants hold. Highest-severity finding: Low.**

---

## 1. Scope

Review of all changes since the last release gate (`9f6ba34^..working tree`).
The working tree carries the new code as uncommitted/untracked files under a
home-directory git root, so the review was performed by direct full-file reads
of the in-scope surface (git diff is empty for untracked content):

| Area | Files reviewed |
|---|---|
| Progress package (4 files) | `src/emo_cyber_agent/progress/__init__.py`, `events.py`, `reporter.py`, `state.py` |
| Recovery package (8 files) | `src/emo_cyber_agent/recovery/__init__.py`, `actions.py`, `checkpoint.py`, `classification.py`, `errors.py`, `manager.py`, `policy.py`, `reporting.py` |
| CLI wiring | `src/emo_cyber_agent/cli/main.py` (`_cli_progress`, `_cli_progress_ids`, audit/review call sites) |
| MCP wiring | `src/emo_cyber_agent/mcp/server.py` (progress-token extraction, `_McpProgressTracker`, notification interleave) |
| Release/build records (records only) | `release/release-manifest.json`, `release/SHA256SUMS`, `release/effective_artifact_verification.json`, `dist/` identity cross-check |
| Prior gates (invariant source) | `reports/security/00-security-baseline.md`, `reports/security/ECA-T015-security-assessment.md`, `reports/security/ECA-T016-invariant-release-gate.md`, `reports/security/ECA-T016-release-security-assessment.md`, `reports/security/POST-PROGRESS-security-review.md`, `tests/unit/test_hardening.py::test_invariant_regression_matrix` |

Hunt list (all covered): privilege escalation, policy bypass, secrets / CoT /
raw-tool-data leakage, cross-audit AND cross-project contamination, MCP
`progressToken` misuse, recovery privilege widening / unbounded retry loops /
checkpoint contamination, terminal-state corruption, arbitrary command execution
/ shell bypass (`subprocess` / `os.system` / `eval` / `exec` / `popen` grep over
new code), path/scope violations, integrity-check bypass, event injection via
untrusted strings, ANSI/TTY injection in `cli_sink`.

## 2. Method

1. Full read of all 12 new-package source files plus the CLI and MCP wiring
   regions (line-verified, not sampled).
2. Content greps over `src/emo_cyber_agent/progress/`, `.../recovery/`,
   `.../cli/`, `.../mcp/` for: `subprocess|os.system|popen|shell=True|eval(|exec(`
   → **zero matches in new code** (only hit in the whole tree is the pre-existing
   confined `core/execution.py` argv-only boundary, out of scope and unchanged);
   and for secret/prompt/CoT/policy/finding/evidence/shell/path/pickle markers
   → hits in `recovery/` are docstring prose and the `_FORBIDDEN_MUTATION_TARGETS`
   contract-witness strings only; zero capability imports.
3. Data-flow traces: `ProgressEvent` construction → `to_dict`/`from_dict` →
   `ProgressState.advance` → `ProgressReporter.report` → `cli_sink` /
   `mcp_notification`; `classify` → `decide` → `RecoveryManager.recover` →
   bounded executor loop → `build_report`; `capture`/`restore` digest binding.
4. Read-only verification runs (no files touched): release-integrity +
   release-manifest suites green; `test_hardening.py` (incl. 12-assertion
   invariant matrix) green; `shasum` cross-check of all 14 in-scope source files
   tree-vs-sdist (14/14 MATCH); `shasum` verification of manifest/SHA256SUMS
   against `dist/` bytes.
5. Cross-consumer check: no caller outside `cli/main.py` and `mcp/server.py`
   consumes progress APIs; nothing imports `recovery` except its own package
   (the `build_report` name collisions in `evaluation/report.py` and
   `core/reporting.py` are unrelated same-name functions, verified by read).

## 3. New-Code Findings

No Critical, High, or Medium findings. Highest severity: **Low**.
Three carried Low hardening notes (unchanged since the POST-PROGRESS audit, still
requiring already-trusted code to misuse the API — no remote PoC confined to the
new code) plus three Info notes, one of them new (N3).

| ID | Severity | Category | Location | Description | Exploitable? |
|----|----------|----------|----------|-------------|--------------|
| F1 (carried) | Low | ANSI/TTY + log injection (defense-in-depth) | `src/emo_cyber_agent/progress/reporter.py:37`; inputs `progress/events.py:62-89` | `cli_sink._sink` interpolates `event.phase` / `event.message_code` verbatim into `print(...)` with no stripping of `\n`, `\r`, `\x1b`. Fake multi-line / ANSI-redraw output possible. **Mitigating facts (verified):** neither shipped adapter uses `cli_sink` — CLI uses its own fixed-vocabulary sink (`cli/main.py:193-196`, constants only) and MCP projects via structured dict (`mcp/server.py:87-98`, `json.dumps` downstream escapes content). Exploitation requires trusted code to register `cli_sink` AND forward untrusted text into `phase`. | No |
| F2 (carried) | Low | Unbounded memory growth (local DoS hardening) | `progress/state.py:20,70`; `progress/reporter.py:17,23` | `ProgressState.events` and `ProgressReporter._events` are uncapped append-only lists; a tight `advance()`/`report()` loop grows memory without bound. Caller must already hold the API (no remote trigger). `reporter.events` returns a copy (good, prevents external mutation) but does not bound growth. | No |
| F3 (carried) | Low | Display-level terminal-state spoofing (no allowlist on direct path) | `progress/events.py:62-89,121-138` vs `progress/state.py:52-55` | Direct `ProgressEvent(...)` / `from_dict` accept any non-empty `phase`/`status`/`message_code` (e.g. `phase="COMPLETED"`); only `ProgressState.advance(phase=...)` allowlists against `self.phases`. Both shipped adapters construct via `advance()` with fixed tuples (`_CLI_PROGRESS_PHASES`, `cli/main.py:164`; `_MCP_PROGRESS_PHASES`, `mcp/server.py:31`), so the spoof path is unreachable from shipped code. Impact is display-only in any case: no lifecycle, policy, or control-flow decision in any layer consumes these strings. | No |
| N1 (info) | Info | Shared-reporter run interleaving | `progress/reporter.py:15-26` | Reporter aggregates all runs into one `_events` list with no per-`run_id` partitioning. `ProgressState` binds ids correctly per event (`state.py:57-59`); no identifier is ever overwritten or swapped. Consumer-hygiene note only. | No |
| N2 (info) | Info | Naive local timestamps | `progress/events.py:31-41` | Default `datetime.now()` (naive, local tz); `__eq__` deliberately excludes `timestamp` (deterministic equality preserved). No security decision consumes timestamps. Auditability noise only. | No |
| N3 (info, new) | Info | Executor-context contract note | `src/emo_cyber_agent/recovery/manager.py:94,114` | `recover()` passes the executor a copy of the caller-supplied `context` snapshot only; `audit_id` is not threaded into the executor payload. An executor implementing `RESUME_FROM_CHECKPOINT` must therefore close over `audit_id` itself to call `restore(..., audit_id=...)` correctly. Not a vulnerability: the executor is host-injected trusted code, the request-level cross-audit refusal (`manager.py:87-91`) always fires first, and `restore()` independently re-verifies audit binding + digest. Documented here so integrator guidance states the closure requirement. | No |

### Explicitly hunted with no finding

- **Privilege escalation / recovery privilege widening:** no privilege/grant/sudo vocabulary, no PolicyEngine handle, no finding/evidence/source imports anywhere in new code; executor is host-injected and budget-capped; terminal actions invoke zero executor calls (`manager.py:96-109`).
- **Policy bypass:** `decide()` is a pure function granting no capability; `NEVER_RETRY` enforced by table (0 attempts, non-retryable) AND a defense-in-depth assertion (`policy.py:71-73`); manager clamps `min(decision.max_attempts, MAX_RECOVERY_ATTEMPTS=3)` (`manager.py:112`) — unbounded retry loops are structurally impossible.
- **Secrets / CoT / raw-tool-data leakage:** event schema is fixed counters/identifiers/codes; no secret, prompt, CoT, tool-output, or path fields exist; `__repr__`/`to_dict`/CLI/MCP emit only those fields; CLI redacts targets (`main.py:342,374`); MCP notifications carry token/phase/percent/code only.
- **Cross-audit / cross-project contamination:** checkpoint digest binds `audit_id + label + payload` (sha256, `checkpoint.py:46`); cross-audit `restore` → `ScopeViolationError` (`checkpoint.py:62-66`); cross-audit `recover` → `ScopeViolationError` (`manager.py:87-91`); payload treated as opaque immutable bytes, never interpreted/merged; context shallow-copied, never written back (`manager.py:65,114`).
- **MCP progressToken misuse:** malformed token → `None`, request runs normally with zero notifications and identical dispatch result (`server.py:34-52,184-185`); token is opaque, range-checked (int ≥ 0; str non-empty ≤ 256; bool rejected), never reaches Core (`dispatch(name, arguments)` receives only `arguments`, `server.py:191`); notifications are structured dicts, single-line `json.dumps` — no framing injection; tracker is failure-proof (`try/except: pass`, `server.py:78-100`) so reporting can never break or steer execution.
- **Terminal-state corruption:** no lifecycle decision consumes progress events; CLI cancel/failure paths emit CANCELLED/FAILED and never misleading COMPLETED (`main.py:204-222`); MCP's lack of CANCELLED is an intentional documented delta (cancellation is a CLI/keyboard concept), not a corruption.
- **Arbitrary command execution / shell bypass:** zero `subprocess`/`os.system`/`eval`/`exec`/`popen`/`shell=True` in `progress/`, `recovery/`, CLI progress region, or MCP progress region.
- **Path/scope violations:** no `open`/`os`/`pathlib`/filesystem access in either new package.
- **Integrity-check bypass:** checkpoint `restore` verifies type → audit binding → digest → size, in that order (`checkpoint.py:60-78`); `build_report` validates the outcome enum (`reporting.py:75-76`).
- **Event injection via untrusted strings:** `event_type` is a strict 2-member allowlist (`events.py:17-28`); numerics reject bools, enforce ranges and `completed ≤ total` (`events.py:68-85`); unknown `from_dict` keys ignored, missing keys raise; classification normalizes then strict-maps, garbage raises `ClassificationError` (fail-loud on the manager's strict path).
- **Release/build records:** `release-manifest.json` + `SHA256SUMS` + `dist/` bytes are mutually consistent TODAY (wheel `60fccf19…`, 598306 B; sdist `053da707…`, 804263 B; manifest self-hash `7fdbad0b…` — all verified by fresh `shasum` and by green `tests/release/test_release_integrity.py` + `test_release_manifest.py`). The stale-record drift documented in the earlier checksum forensics (set-A signature vs set-B bytes) has since been resolved by regeneration (records mtime 07:25, post-dating the 07:23 `dist/` build). All 14 in-scope source files are byte-identical tree-vs-shipped-sdist (14/14 MATCH), and the sdist/wheel both contain the full `progress/` + `recovery/` packages — no frozen-intermediate-tree hazard remains.

## 4. Twelve-Invariant Matrix — 12/12 PASS

Invariant wordings per the task brief; the 12th ("host delegates; EMO owns the
workflow after delegation") is taken as documented in the authoritative gate
`reports/security/ECA-T016-invariant-release-gate.md` §12, the one gate item
with no counterpart among the 11 named framings. Each item carries live
regression backing (`test_hardening.py::test_invariant_regression_matrix`,
re-run green: 37/37) plus new-code-specific evidence below.

| # | Invariant | Verdict | Per-item evidence (new code) |
|---|-----------|---------|------------------------------|
| 1 | Core source of truth | PASS | New packages import stdlib + intra-package siblings only; zero imports of Core stores/services; recovery reports are DATA projections, never competing truth (`recovery/reporting.py:28-60`). |
| 2 | Adapters thin | PASS | `_cli_progress` (~50 lines, `cli/main.py:172-222`) and `_McpProgressTracker` (`mcp/server.py:55-120`) only build state, emit fixed-vocabulary events, and project to display/transport. Business paths (`result.model_dump`, `_redact`, `_emit`, `dispatch`) untouched. |
| 3 | Model proposes / Core disposes | PASS | Progress events carry no instructions; no adapter return value feeds any decision; dispatch outcome identical with/without token (`mcp/server.py:182-185`). |
| 4 | PolicyEngine sole authority | PASS | `decide()` grants no capability and performs no I/O (`recovery/policy.py:1-10`); CLI config still rejects policy keys (`cli/main.py:231,247-250`); matrix assertion 1/4 green. |
| 5 | Evidence-as-data | PASS | Recovery `context` snapshotted via `dict()` copy, never mutated (`recovery/manager.py:58-65`); `_FORBIDDEN_MUTATION_TARGETS` names policy_engine/findings/evidence/severity/source/approvals/scope/privileges (`manager.py:34-45`); reports are frozen dataclasses. |
| 6 | No finding-without-evidence | PASS | Recovery never mints findings/evidence (no imports, no constructors); `RecoveryReport` is outcome DATA only; matrix assertion 3 green. |
| 7 | No confirmation-without-verification | PASS | No verification bypass exists in new code (`__init__.py:1-8` explicitly lists bypassing verification among what recovery NEVER does); terminal POLICY_DENIED/INTEGRITY_FAILURE paths make zero attempts. |
| 8 | Read-only default | PASS | New code adds no execution path; recovery actions are named intents run via injected callables within fixed budgets; QUARANTINE/FAIL_CLOSED are non-executing terminals; matrix assertions 1/4 green. |
| 9 | No cross-audit leakage | PASS | Two-layer refusal: `restore()` audit-binding + digest check (`checkpoint.py:51-78`) and `recover()` `checkpoint_audit_id != audit_id` refusal (`manager.py:87-91`); opaque immutable payloads; per-request stateless adapters; matrix assertion 10 green. |
| 10 | No skill-derived permissions | PASS | Classification grants no capability (`classification.py:1-6`); policy grants no capability (`policy.py:1-10`); config policy-key rejection unchanged; no permission vocabulary in new code. |
| 11 | No arbitrary shell | PASS | Grep-verified zero `subprocess`/`os.system`/`eval`/`exec`/`popen`/`shell=True` in `progress/`, `recovery/`, CLI progress region, MCP progress region; existing confined argv-only executor untouched. |
| 12 | Host delegates; EMO owns workflow after delegation (as documented, gate §12) | PASS | `RecoveryManager` stateless (executor injected per construction, no retained audit state, `manager.py:68-77`); `McpServer` holds transport queue only, no audit state (`mcp/server.py:126-138`); matrix assertion 12 green. |

**Invariant score: 12/12.**

## 5. Verdict

**PASS.** No real exploitable issue was found in the Progress package, the
Recovery package, the CLI wiring, the MCP wiring, or the release/build records.
The three Low findings are display-hardening notes carried unchanged from the
prior audit (each requires already-trusted code to misuse the API; neither
shipped adapter exposes the reachable path), and the three Info notes are
hygiene/contract documentation. The 12-invariant matrix holds 12/12 with
per-item evidence above and live regression backing. **BLOCKED is not warranted:**
per the review rule it requires a real exploitable issue with reasoning, and
none exists. The previously reported stale release-record drift is verified
resolved in the current on-disk state (records regenerated and consistent;
release-integrity suites green; tree-vs-sdist 14/14 MATCH).

*End of report. No source, test, CLI, MCP, release, or build files were created
or modified; this report file is the sole artifact.*
