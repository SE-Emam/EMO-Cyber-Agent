# POST-T021 Full Regression — T21-R (G7) RUN RECORD

- **Date (UTC):** 2026-10-08 (runs spanned 2026-10-08T23:59:39Z → ~2026-10-09T00:06Z)
- **Owner:** T21-R — G7 Full Regression Owner (RUN + DOCUMENT ONLY, read-only on source)
- **Scope:** project's official full suite post-Wave-D / post-T021 (incl. authoritative suites, heuristic hardening T21-G cases, benchmark corpus sanity, MCP/HTTP, progress/recovery, host contracts, Android-related tests where applicable)
- **Gate:** G7

## 1. Suite discovery (official command)

- `Makefile` (`test:` target) → `pytest`
- `pyproject.toml` `[tool.pytest.ini_options]`: `asyncio_mode = "auto"`, `addopts = "-q"`, `pythonpath = ["src"]`
- CI (`.github/workflows/ci.yml`) runs the same `pytest` entrypoint.
- **Exact authoritative command executed (verbatim):**
  ```
  python3 -m pytest tests -q -rs --junitxml=/tmp/t21r.xml
  ```
  (`-rs` added only to print skip reasons; `--junitxml` added only to capture machine-readable counts. No test selection, no deselect, no expected-outcome edits.)
- Interpreter: `Python 3.14.5` (system Homebrew python3; repo requires >=3.11 — satisfied).
- A first unadorned run (`python3 -m pytest tests -q`, wall 181.78 s real, exit 0) printed no trailing summary line on this console, so the authoritative counted run above (with junitxml) is the record of truth. Both runs: exit code 0, zero failures.

## 2. Headline results (authoritative, from `/tmp/t21r.xml` + exit code)

| Metric | Value |
|---|---|
| Collected (testcases) | 2726 |
| **Passed** | **2720** |
| **Failed** | **0** |
| Errors | 0 |
| **Skipped** | **6** |
| xfailed | 0 |
| xpassed | 0 |
| **Exit code** | **0** |
| Wall runtime (authoritative run) | ~118 s (first full run: 181.78 s real / 57.40 s user / 9.24 s sys) |
| junit suite time | 117.101 s |

## 3. Per-area breakdown (derived from junitxml testcase classnames; passed / skipped)

| Area | Passed | Skipped |
|---|---|---|
| unit (other) | 866 | 4 |
| security/verification (incl. adversarial, isolation, threat-intel, attack-surface, hardening, T21-G heuristics) | 949 | 0 |
| mcp | 123 | 0 |
| http | 192 | 2 |
| progress/recovery | 114 | 0 |
| benchmark + evaluation sanity | 174 | 0 |
| contracts/release (tests/release/*, adapter-contract) | 302 | 0 |
| android-dedicated pytest files | 0 (no such files exist — see §5) | 0 |
| **Total** | **2720** | **6** |

Spot-checks: `test_heuristics_evaluation.py` = 8/8 green (T21-G heuristic hardening included and passing). Benchmark corpus sanity (`test_benchmark_corpus.py`, `test_benchmark_eval.py`, evaluation suites) all green. MCP, MCP/HTTP, host-client, progress/recovery, contract/release suites all green.

## 4. Baseline comparison (pre-Wave-D: 2716 passed / 6 skipped / 0 failed)

| | Baseline | This run | Delta |
|---|---|---|---|
| Passed | 2716 | 2720 | **+4 (growth from new G+I cases — EXPECTED, not a mismatch)** |
| Skipped | 6 | 6 | 0 |
| Failed | 0 | 0 | 0 |

Zero regressions. Count growth (+4 passed, +4 collected: 2722 → 2726) is consistent with newly added G+I cases, all passing.

## 5. Skips — every skip justified + declared (6/6, all with specific evidence)

1. `tests/unit/subagent/test_e2e_matrix.py::test_vendor_environment[anythingllm]` — `NOT EXECUTED: no anythingllm binary (anythingllm, anything-llm) on PATH in this environment`. Host binary absent; cannot execute. Justified.
2. `tests/unit/test_mcp_http_clients.py::test_host_http_probe[pi]` — `NOT-ENVIRONMENT-TESTED pi: pi --help shows no remote/HTTP MCP registration (has --url=False, mentions mcp=False)`. Host capability absent by inspection. Justified.
3. `tests/unit/test_mcp_http_clients.py::test_host_http_probe[jan]` — `NOT-ENVIRONMENT-TESTED jan: jan --help shows no remote/HTTP MCP registration (has --url=False, mentions mcp=False)`. Same. Justified.
4. `tests/unit/test_report_templates.py::test_g11_l1_trusted_requires_authenticated_provenance` — `G11-L1 DEFERRED` with full in-reason documentation (loader-context authentication requires changing files outside that fix's write scope; recorded as counted skip, not hidden). Declared deferral with reason. Justified.
5. `tests/unit/test_toolchain.py::test_real_tools_optional[trivy]` — `trivy not installed (optional)`. Optional external tool absent. Justified.
6. `tests/unit/test_toolchain.py::test_real_tools_optional[osv-scanner]` — `osv-scanner not installed (optional)`. Same. Justified.

No failure relabeled known/environmental (there were no failures). No expected outcomes edited (read-only role; nothing in `tests/` or `src/` touched by this owner).

Android note: no Android/Termux-dedicated pytest files exist in `tests/` (verified by filename search — no match). Android coverage is carried by host-matrix/CLI/MCP/HTTP evidence in `POST-T021-android-*` reports plus the shared suites above; there is no Android pytest path to include or skip. Nothing hidden.

## 6. Defects

**None.** Zero failures, zero errors, zero xpass. No DEFECT section required. No CLASSIFY / OWNER assignment needed. No targeted-retest pending.

## 7. Observations (no action taken — read-only role)

- Pre-existing uncommitted working-tree modifications were present before this run (`src/emo_cyber_agent/subagent/sanitizer.py`, `tests/unit/subagent/test_sanitizer.py`, `test_delegation.py`, plus untracked POST-T021 report drafts). Untouched by T21-R; suite result above reflects this exact tree state.
- Non-blocking warnings only: one `PytestUnknownMarkWarning` (`contract_only` in `test_e2e_matrix.py`) and two `RuntimeWarning`s (un-awaited `FoundationSecurityAuditor.audit` coroutine in progress tests). Cosmetic; no gate impact.

## 8. G7 gate decision

**G7: PASS** — all required tests green (2720 passed, 0 failed, 0 errors, exit 0), all 6 skips justified + declared above with specific evidence, zero unresolved regressions vs the pre-Wave-D baseline (+4 passed = expected new-case growth).
