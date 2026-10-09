# POST-T021 Baseline — EMO-Cyber-Agent (T21-0A Baseline Auditor)

Owner: T21-0A · Date (UTC): 2026-10-08 · Working dir: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`
Method: all values recomputed from disk at audit time. Read-only except this file.
Labels used: PASS / PASS-WITH-NOTES / NOT-EXECUTED / ENVIRONMENT-BLOCKED / BLOCKED.

## 1. Git identity — PASS

- HEAD: `9098006c5a674e5be70f1394a6357dc72966f195`
- Branch: `main`
- `git log --oneline -6`:
  - `9098006 docs: architect brief 2026-10-07 (full-fidelity status)`
  - `9af310f docs(release): sync 0.2.0 changelog`
  - `2815ea9 docs(release): public release record for emo-cyber 0.2.0`
  - `67512ab release: bump to 0.2.0 (threat-intel + HTTP transport)` (= v0.2.0 tag target)
  - `de770dc fix: py3.11 enum membership + bash on all CI runners`
  - `d58ce4e feat: threat-intel package + cyber_threat_intel MCP tool + T020 batch`
- `git status --porcelain` (excluding `__pycache__`) — **NOT clean, 5 lines**:
  - `M reports/development/POST-T020-G1-host-matrix.md` (uncommitted 1-line edit: AnythingLLM row upgraded to ENV/full-loop wording; see §10)
  - `?? reports/development/POST-T021-baseline.md` (this file)
  - `?? reports/development/POST-T021-gap-matrix.md`
  - `?? reports/development/POST-T021-jan-native.md`
  - `?? reports/development/POST-T021-pi-native.md`

## 2. Release tag — PASS

- `git rev-list -n 1 v0.2.0`: `67512ab65a6437e2d66535ba6d8a504f61100952`
- Tag type: `tag` (`git cat-file -t v0.2.0` → `tag`) = **annotated**; tagger `SE-Emam <eng.waheedea@gmail.com>`; message: `EMO-Cyber-Agent v0.2.0`.
- Post-release commits (`git log --oneline v0.2.0..HEAD`): **3 commits**:
  - `9098006 docs: architect brief 2026-10-07 (full-fidelity status)` → `reports/development/ARCHITECT-BRIEF-2026-10-07.md`
  - `9af310f docs(release): sync 0.2.0 changelog` → `release/CHANGELOG.md`
  - `2815ea9 docs(release): public release record for emo-cyber 0.2.0` → `reports/release/POST-T020-public-release-0-2-0.md`
- All 3 post-tag commits are **docs-only** (reports/release only); **no `src/` change after the `0.2.0` bump** — 0.2.0 source appears frozen.

## 3. Package / protocol / CLI version — PASS

- `pyproject.toml`: `name = emo-cyber`, `version = 0.2.0`, `requires-python = >=3.11`.
- `src/emo_cyber_agent/__init__.py`: `__version__ = "0.2.0"` (verified via `PYTHONPATH=src python3 -c "import emo_cyber_agent"` → `0.2.0`).
- MCP protocol (`src/emo_cyber_agent/mcp/protocol.py`): `SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")`, `LATEST_PROTOCOL_VERSION = "2025-06-18"` (MCP date versions; package version is separate: **0.2.0**; `SERVER_NAME = "emo-cyber-agent"`, `SERVER_VERSION = "0.2.0"`).
- CLI version: `emo-cyber 0.2.0` via Typer `CliRunner().invoke(app, ['--version'])` (exit 0). Note: `cyber-agent` console script is **not on PATH** in this shell (`which cyber-agent` → not found); CliRunner method used instead.
- Verdict: **0.2.0 × 3 consistent** (pyproject + `__init__` + CLI).

## 4. MCP tool count — PASS

- `len(emo_cyber_agent.mcp.tools.TOOLS)`: **7** (TOOLS is a list of dicts; names via `t['name']`).
- Names: `cyber_audit, cyber_review, cyber_verify, cyber_report, cyber_status, cyber_extensions, cyber_threat_intel`.

## 5. Host matrix (`src/emo_cyber_agent/subagent/compat_matrix.py` HOST_MATRIX) — PASS-WITH-NOTES

| host_id | display | support_status | evidence (abridged) |
|---|---|---|---|
| `opencode` | OpenCode | **Not-tested** | No contract/environment test names this host |
| `pi` | Pi | **Not-tested** | No contract/environment test names this host |
| `hermes` | Hermes | **Not-tested** | No contract/environment test names this host |
| `jan` | Jan | **Not-tested** | No contract/environment test names this host |
| `anythingllm` | AnythingLLM | **Environment-tested** | Full loop register→discover→filter→delegate→execute→result proven live 2026-10-07 (G1-anythingllm addendum part 3) |
| `generic-mcp` | Generic MCP (tested baseline) | **Contract-tested** | Exercised by `tests/unit/subagent/test_contracts.py`, `test_mcp_security.py` over stdio |

Counts: 4× Not-tested + 1× Environment-tested + 1× Contract-tested (6 rows).
Protocol window for all rows: `2024-11-05` → `2025-06-18`; transports `("stdio",)` for all rows.
Note: anythingllm row carries residual `known_limits`: live call needs reachable LLM provider + quota; malicious-context-via-host NOT-EXECUTED.

## 6. Python matrix — PASS-WITH-NOTES

- Declared: `requires-python = ">=3.11"`; classifiers list `3.11, 3.12, 3.13, 3.14`; ruff `target-version = "py311"`; mypy `python_version = "3.11"`, `strict = true` (consistent floor 3.11). Dev-pin ranges: `mypy>=1.15,<2`, `ruff>=0.11,<1`.
- Local toolchain: `ruff` and `mypy` binaries **not installed** in this shell (`No module named mypy`, `command not found: ruff`; system `python3` = 3.14.5) → local mypy/ruff version re-verification is **ENVIRONMENT-BLOCKED**; declared floors above are from `pyproject.toml` on disk.
- G6 report staleness: `reports/development/POST-T020-G6-python.md` (dated 2026-10-06) tested 4 interpreters (3.11.15 / 3.12.7 / 3.13.13 / 3.14.5), each **53/53 PASS** — **but at version 0.1.0 / 6 tools** (`cyber_audit, cyber_review, cyber_verify, cyber_report, cyber_status, cyber_extensions`; `cyber_threat_intel` absent). Predates the 0.2.0 bump; needs re-run at 0.2.0/7 tools in POST-T021.

## 7. OS matrix — PASS-WITH-NOTES

- G7 report: `reports/development/POST-T020-G7-platform.md` (dated 2026-10-06, 0.1.0 wheel + HEAD source for HTTP rows).
- `darwin/arm64`: **23/23 PASS live** (D1–D23: wheel install, doctor human/json, audit json/human, MCP stdio init/list/call + rejections, HTTP bind/init/call/routing/refusal/restart, paths spaces+unicode, traversal, argv, env, timeout, schemas, progress, recovery).
- `linux`: **PORTABLE-BY-INSPECTION / NEEDS-RUNTIME-PROOF** (no Linux runner here; CI `ubuntu-latest` build-only, no G7 battery job).
- `windows`: **PORTABLE-BY-INSPECTION for primitives / NEEDS-RUNTIME-PROOF overall**, with defect candidate N1 (extension `platforms` `win32` vs `host_profile()` `windows` vocabulary mismatch) and notes N2–N7.
- Staleness note: 0.1.0 wheel lacks `mcp/http_server.py`; HTTP rows proven via `PYTHONPATH=src` only at that time. G7 battery never re-run at 0.2.0.

## 8. Heuristic inventory (one line per family) — PASS

- `sanitizer` (`src/emo_cyber_agent/subagent/sanitizer.py`, 318 lines): pure NFKC→ANSI-strip→control-strip→bound(64 KiB)→detect pipeline returning allow/sanitize/quarantine/deny hint; never authorizes.
- `delegation` (`src/emo_cyber_agent/subagent/delegation.py`, 415 lines + `src/emo_cyber_agent/agent_security/delegation.py`): scope-guard family (scope-widening/confused-deputy refusal, in-scope allow, vague-scope UNCLEAR); evaluation cases `delegation-01..06`.
- `firewall` inbound (`src/emo_cyber_agent/subagent/firewall.py`, 285 lines) + outbound (`src/emo_cyber_agent/subagent/result_firewall.py`, 426 lines): inbound host-context DATA-ONLY gate (everything UNTRUSTED); outbound recursive scrub (secrets/CoT/raw-output/paths/provider-internals/oversize, authz ref preserved + `removed` list).
- `skills` (`src/emo_cyber_agent/skills/spec.py::INJECTION_PATTERNS`, 13 literals + `skills/builtin/` + `skills/packs/`): regex-screen heuristic — presence marks skill content untrusted, never trusted (defense-in-depth).
- `secret` (`src/emo_cyber_agent/core/execution.py::sanitized_env`, `SAFE_ENV_ALLOWLIST` 4 names + `SECRET_ENV_BLOCKLIST` 11 substrings): build-never-inherit child env, blocklist-substring deny, 256-char truncation; secrets never in config/CLI output (presence only).
- `threat-rules` (`src/emo_cyber_agent/agent_security/threat_rules.py`, 134 lines + `src/emo_cyber_agent/threat_intel/` 4 modules: `feed_triage` 307 / `kali_detectors` 475 / `leak_monitor` 362 / `technique_mapper` 508 lines): deterministic parse/triage/match/map over caller-supplied data only (leak-check/triage/map-technique/exposure-check/coverage); never fetches/executes/networks.
- `resolvers` (`src/emo_cyber_agent/tools/packs/resolver.py` 167 lines + `executor.py` 206 lines argv-only `shell=False` + validator/catalog/registry/spec; `shutil.which` presence-only): fixed adapter logic → validated `tuple[str,…]` NUL-rejected argv → single `core/execution.py` shell-free execution site; repo content never influences argv.

## 9. Benchmark corpus counts — PASS

- `find tests/fixtures/evaluation -type f | wc -l`: **135**.
- Subdirs of `tests/fixtures/evaluation/`: 12 (`adversarial, agent, authorization, change, dependency, hostile_input, mcp, memory, post_t020, secrets, verification, web`) + `dataset.json` manifest.
- `dataset.json`: `dataset_id = emo-evaluation-benchmark`, `version = 0.1.0`, **`case_count = 104`** (manifest stale at 0.1.0, same staleness class as G6/G7).
- `post_t020` subdir: **30 files** (`cloud-01..06`, `contamination-01..06`, `delegation-01..06`, `recovery-01..06`, `threat-model-01..06`).

## 10. Known limitations — PASS-WITH-NOTES

Residuals from `POST-T020-acceptance-assessment.md` quoted verbatim (non-blocking, documented): `L1 trust-root string-based; M2 map partial; D5/D6 word-order/padding; anythingllm NOT-EXECUTED; Windows/Linux NEEDS-RUNTIME-PROOF; CI unexecuted until push; contract_only warning.` Final decision at that time: **PASS-WITH-NOTES** (zero blockers; v0.1.0 untouched; next release requires version decision + fresh build/verify per G16 pattern).
Supersession note: the `anythingllm NOT-EXECUTED` residual was superseded the same cycle by the Environment-tested live loop recorded in HOST_MATRIX and `POST-T020-G1-anythingllm.md` addendum part 3 (2026-10-07, user-provided key, quota-approved); **malicious-context-via-host remains NOT-EXECUTED** (contract simulation stands). The working-tree edit to `POST-T020-G1-host-matrix.md` (§1) updates that report's AnythingLLM row to the same effect but is **uncommitted**.

## 11. Quick sanity (read-only pytest, NOT full suite) — PASS

- Command: `python3 -m pytest tests/unit/subagent/test_contracts.py tests/unit/progress -q --tb=no -p no:cacheprovider`
- Result: **53 passed, 0 failed, 0 skipped in 0.28 s** (recomputed 2026-10-08; full suite deliberately NOT run per brief).

---

**BASELINE RECORDED.** HEAD `9098006` (main, +3 docs-only over annotated `v0.2.0` `67512ab`); tree has 1 modified + 4 untracked report files (all under `reports/development/`); version `0.2.0` ×3; 7 MCP tools; hosts 4× Not-tested + 1× Environment-tested + 1× Contract-tested; Python `>=3.11` (3.11–3.14, G6 at 0.1.0 needs refresh); darwin 23/23, linux/win inspection-only; heuristics 7 families inventoried; corpus 135 files (post_t020: 30; dataset.json case_count 104 @ v0.1.0); residuals carried with anythingllm partial supersession; subset **53 passed in 0.28 s**.
