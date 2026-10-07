# POST-T020 G0 Baseline — EMO-Cyber-Agent (READ-ONLY audit)

- Role: G0-A Baseline Auditor for POST-T020.
- Mode: STRICTLY READ-ONLY (no source modifications; read-only `pytest` allowed). This file is the single authorized write.
- Date (UTC): 2026-10-06. Working directory: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`.
- Method: every record below recomputed from disk; nothing trusted from memory.

## IMMUTABILITY STATEMENT

**v0.1.0 tag / GitHub Release / PyPI `emo-cyber 0.1.0` are IMMUTABLE. `main` (HEAD `1c0fc53`) is the NEXT-version dev line — 2 commits ahead of the v0.1.0 tag target. No tag, release, or PyPI action is authorized from this baseline.**

## 1. Git HEAD record (recomputed)

- HEAD: `1c0fc53fb9c2abacb44e76befbc0826e80d7a8f0`
- Branch: `main`
- `git log --oneline -5`:
  - `1c0fc53 docs(release): public release assessment for emo-cyber 0.1.0`
  - `cb71fb8 fix(cli): display installed distribution name dynamically`
  - `52888c5 fix(release): isolate wheel+sdist for PyPI upload`
  - `7581c9f release: rename distribution to emo-cyber`
  - `5e9b7f5 fix(release): checkout in release job; create Draft release`
- `git status --porcelain`: EMPTY (0 lines).
  - Tracked-modified/staged: 0. Untracked: 0.
  - `__pycache__` noise excluded (gitignored; present on disk under e.g. `src/emo_cyber_agent/report_templates/__pycache__/`, `src/emo_cyber_agent/subagent/__pycache__/` but not tracked).

## 2. v0.1.0 tag

- `git rev-list -n 1 v0.1.0` (tag target commit): `52888c58701faa8db5c1077cb794dac3e7f6d274`
- `git show-ref v0.1.0` (tag object): `6bb333382f0a06e499d5306d446db235d6c1f46d refs/tags/v0.1.0`
- `git cat-file -t v0.1.0`: `tag` → **annotated tag** (`v0.1.0  EMO-Cyber-Agent v0.1.0`).
- Tag-target log (`-3`): `52888c5 fix(release): isolate wheel+sdist for PyPI upload`, `7581c9f release: rename distribution to emo-cyber`, `5e9b7f5 fix(release): checkout in release job; create Draft release`.

## 3. Tag-vs-HEAD relationship

- Commits `main` is ahead of `v0.1.0`: **2**.
- `git log --oneline v0.1.0..HEAD`:
  - `1c0fc53 docs(release): public release assessment for emo-cyber 0.1.0`
  - `cb71fb8 fix(cli): display installed distribution name dynamically`
- Interpretation: tag froze at `52888c5`; post-tag dev line adds a CLI display fix + release-assessment docs. Any post-T018/Post-T020 change invalidates old RC artifacts (per T018 final-review §10 rule).

## 4. GitHub Release state

- `gh release view v0.1.0 --repo SE-Emam/EMO-Cyber-Agent --json tagName,isDraft,assets`:
  - `tagName`: `v0.1.0`
  - `isDraft`: **false** → **published** (not a draft).
  - Assets (4, all `uploaded`): `emo_cyber-0.1.0-py3-none-any.whl` (698673 B), `emo_cyber-0.1.0.tar.gz` (982847 B), `release-manifest.json` (2837 B), `SHA256SUMS` (276 B).
  - Release created: `2026-10-06T19:24:34Z`.

## 5. PyPI

- `curl -s -m 15 https://pypi.org/pypi/emo-cyber/json`:
  - Project name: **`emo-cyber`** (confirmed).
  - Version: **`0.1.0`**.
  - Releases keys: `['0.1.0']` (single release line).

## 6. Package version (expect 0.1.0 everywhere)

- `pyproject.toml [project]`: `name = "emo-cyber"`, `version = "0.1.0"`.
- `src/emo_cyber_agent/__init__.py`: `__version__ = "0.1.0"`.
- MCP protocol `src/emo_cyber_agent/mcp/protocol.py`: `SERVER_VERSION = "0.1.0"` (advertised in `initialize_result` `serverInfo`).
- Mirror: `src/emo_cyber_agent/subagent/discovery.py`: `SERVER_VERSION = "0.1.0"`.
- Note: `main` is now the NEXT-version dev line, but no version bump has been cut yet — all three pins still read `0.1.0` at HEAD `1c0fc53`.

## 7. Python support

- `requires-python = ">=3.11"`.
- Classifiers: `Programming Language :: Python :: 3`, `3.11`, `3.12`, `3.13`, `3.14`; `Development Status :: 5 - Production/Stable`; `Operating System :: OS Independent`; `Topic :: Security`.
- Build: `hatchling>=1.25`; `tool.ruff target-version py311`; `tool.mypy python_version 3.11 strict`.
- Optional extras: `mcp` (`mcp>=1.15,<2`), `http` (`fastapi>=0.115,<1`, `uvicorn>=0.34,<1`), `dev`, `all`.

## 8. Host matrix (POST-T018 §15 + `compat_matrix.py HOST_MATRIX`)

Source: `reports/development/POST-T018-subagent-readiness-assessment.md` §§15/18 + `src/emo_cyber_agent/subagent/compat_matrix.py` `HOST_MATRIX` (6 entries, all `transports=("stdio",)`):

| host_id | display | support_status | evidence / notes |
|---|---|---|---|
| `opencode` | OpenCode | **Not-tested** | lifecycle assumed, not live-verified; §15: 5 config-only adapters, binary present `--version` OK |
| `pi` | Pi | **Not-tested** | assumed standard lifecycle; alias `pi`→`pi-host` (`DECISION_HOST_IDS`) documented; binary present |
| `hermes` | Hermes | **Not-tested** | assumed standard lifecycle; binary present |
| `jan` | Jan | **Not-tested** | assumed standard lifecycle; binary present |
| `anythingllm` | AnythingLLM | **Not-tested** | desktop-app wrapping unverified; §15/E2E: binary absent → honest NOT EXECUTED |
| `generic-mcp` | Generic MCP (tested baseline) | **Contract-tested** | only entry with test evidence: in-repo contract tests (`tests/unit/subagent/test_contracts.py`, `test_mcp_surface_security.py`) over stdio JSON-RPC |

Honesty policy (module docstring): every host-specific unverified claim is `NOT_TESTED`. `evaluate_compat` is pure/deterministic; UNKNOWN verdicts quarantine via `assert_usable`, never silent fallback.

## 9. HTTP support in `src/emo_cyber_agent/mcp/` (gap record)

- Directory: `__init__.py`, `delegate.py`, `protocol.py`, `server.py`, `tools.py`.
- Grep `http|streamable|sse|server` hits are only: `serverInfo` (protocol.py), `McpServer`/`create_server`/`run_stdio` docstrings/logs, tool description "Read-only".
- **No HTTP server, no Streamable HTTP, no SSE transport in `mcp/`. Transport is stdio-only**: `McpServer.run_stdio()` (single-line JSON-RPC over stdin/stdout; `handle_message` rejects batch, requires `jsonrpc 2.0`; methods `initialize`/`ping`/`tools/list`/`tools/call` only).
- **Gap recorded**: HTTP transports out-of-scope (consistent with T018 §§21, compat entry `known_limits`: "HTTP/SSE transports are out of scope"). `fastapi`/`uvicorn` exist only as the optional `http` extra in `pyproject.toml`; no server code consumes them in `mcp/`. Pi `streamable-http` placeholder noted as Info (I1) in T018 final-review §9, not a blocker.

## 10. Heuristic inventory (inventory only, one line each)

- `src/emo_cyber_agent/agent_security/*` (19 modules: `threat_rules`, `prompt_analysis`, `tool_poisoning`, `scope_analysis`, `memory_analysis`, `credential_analysis`, `attack_surface`, `mcp_model`, `agent_model`, `taxonomy`, `identity`, `provenance`, `delegation`, `verification`, `delta`, `queries`, `errors`, `spec`, `service`) — agent-security analysis family (pattern/taxonomy/model-driven detectors; heuristic-adjacent).
- `src/emo_cyber_agent/skills/spec.py::INJECTION_PATTERNS` (13 literal instruction-override strings: `ignore previous instructions`, `grant permission`, …) — presence marks skill content untrusted, never trusted (regex-screen heuristic, defense-in-depth per T018 §21).
- `src/emo_cyber_agent/subagent/sanitizer.py` — pure NFKC→ANSI-strip→control-strip→bound(64 KiB)→detect pipeline returning `SanitizedInput` + `DecisionHint allow/sanitize/quarantine/deny`; never decides authorization.
- `src/emo_cyber_agent/subagent/firewall.py` — inbound Host-context DATA-ONLY gate (scope→size→normalize+policy); ignores inbound classification claims, labels everything UNTRUSTED; regex screens are heuristic, not semantic.
- `src/emo_cyber_agent/subagent/result_firewall.py::scrub` — outbound recursive strip (secrets/CoT/raw-output/paths/provider-internals/oversize; preserves only exact bound authz ref); deterministic `removed` list.
- `src/emo_cyber_agent/verification/matrix.py` (POST-RC-012) — pure table lookup mapping hypothesis→evidence/strategies/adapter-caps/safety/target/oracle/refutation; deterministic, model-free, severity-free (not a regex heuristic; included as requested).

## 11. Checklist inventory (presence/absence)

- **PRESENT**: `src/emo_cyber_agent/subagent/bootstrap.py` — "Host bootstrap readiness checklist" (POST-T018): frozen `BootstrapCheck` data items (`name`, `required`, `check_kind`); `bootstrap_profile(host_id)` returns the ordered host-generic readiness checklist (evaluate-only, no probing). Grep `checklist` hits only here (docstring + `Frozen checklist item` + `ordered checklist`/`ordered readiness checklist`).
- No other checklist framework found in `src/` (single grep family).

## 12. Template inventory (`report_templates/` + `templates/`)

- `src/emo_cyber_agent/report_templates/`: `__init__.py`, `spec.py`, `registry.py`, `resolver.py`, `validator.py`, `service.py`, `library.py` (+ `__pycache__/` noise).
- `templates/reports/official/`: **20 files** — `agent-security`, `ai-security`, `api-security`, `authentication-security`, `authorization-security`, `business-logic-security`, `cloud-security`, `container-security`, `database-security`, `dependency-security`, `developer-security`, `executive-security`, `mcp-security`, `pre-release-security`, `regression-security`, `security-audit`, `supabase-security`, `supply-chain-security`, `threat-model`, `web-app-security` (all `.yaml`) + `templates/reports/REPORT-TEMPLATE.yaml`.
- Adjacent template trees (for context): `templates/playbooks/` (19 official + template), `templates/skills/` (templates + 8 official packs), `templates/tasks/` (22 official + template + example), `templates/verification/` (templates + 3 official strategies), `templates/threat-modeling/`, `templates/agent-security/`, `templates/tools/packs/` (trivy/gitleaks/osv/semgrep), `templates/security-knowledge/`, `templates/extensions/`.

## 13. Benchmark baseline

- `evaluation/` directory: **ABSENT** (`ls evaluation/` → No such file or directory).
- `reports/` benchmark reference: **PRESENT** — `reports/development/POST-RC-013-evaluation-assessment.md` (matched `reports/*RC-013*`).
- Deferred-work note (T018 §22): benchmarks (alongside CPG/Joern/CodeQL, live red-team, exploit runners, approval workflows, monitoring, durable knowledge, feeds, multi-version templates) explicitly deferred — not blockers.

## 14. Test counts (read-only subset run)

- Command (read-only, no writes): `python3 -m pytest tests/unit/subagent tests/unit/progress tests/unit/recovery -p no:cacheprovider --tb=no`
- Result: **766 passed, 1 skipped, 1 warning in ~9 s** (warning: `PytestUnknownMarkWarning: Unknown pytest.mark.contract_only` at `tests/unit/subagent/test_e2e_matrix.py:31` — known cosmetic, cf. T018 final-review §9.4).
- Scope: full suite NOT re-run by G0 (per brief). Prior evidence cited: **2202 passed, 0 failed, 3 skipped** single-command full suite (T018 readiness §19: "2202 passed, 3 skipped, 0 failed (100 s)"; final-review §7: subagent+hardening 740/1, full unit 2151/3 at that HEAD).
- Skips are optional-scanner skips (consistent with prior reports).

## 15. 12 invariants (T018 final-review score cited)

- Source: `reports/development/POST-T018-final-review.md` §2 (Agent 15 independent count) + `POST-T018-subagent-readiness-assessment.md` §20.
- Score: **12/12 PASS with per-invariant evidence** (read-only-by-default, repo-content-untrusted, no-finding-without-evidence, no-destructive-without-permission, tool-outputs-as-evidence, uncertainty-explicit, same-domain-contracts, provider-external, provenance-preserved, no-cross-project-reuse, specialist-not-coder, host-delegates/EMO-owns-workflow).
- Overall T018 verdict cited: **PASS-WITH-NOTES** (pure PASS withheld only for by-design `NOT_TESTED` vendor interop + `anythingllm` NOT EXECUTED — openly declared, not code defects; no BLOCKED condition).

## Verdict

**BASELINE RECORDED.** All sections recomputed from disk at HEAD `1c0fc53` (main, +2 over `v0.1.0` target `52888c5`); tree clean; tag annotated; Release published (not draft, 4 assets); PyPI `emo-cyber 0.1.0`; pins `0.1.0` ×3; Python `>=3.11` (3.11–3.14); hosts 5× Not-tested + generic-mcp Contract-tested; MCP stdio-only (HTTP gap); heuristics inventoried; checklist present (`bootstrap.py`); templates listed (20 official report templates); no `evaluation/` dir, RC-013 present; subset **766 passed / 1 skipped**; invariants **12/12** (T018 PASS-WITH-NOTES).
