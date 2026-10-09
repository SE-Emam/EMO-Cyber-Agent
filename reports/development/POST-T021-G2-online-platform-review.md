# POST-T021 G2-Online Platform Review — O6 Independent Review

**Date (UTC):** 2026-10-09
**Reviewer:** O6 (Independent Platform Reviewer; wrote NO workflow/tests — O1–O5 did)
**Scope:** FULLY READ-ONLY on code/workflow/scripts. Sole writes: this file + overwrite of `POST-T021-G2-platform-parity-review.md`. No src/workflow/script edits, no publish, no tags.
**Inputs:** `POST-T021-linux-parity.md` (O3), `POST-T021-windows-parity.md` (O4), live `gh` cross-checks below, local `git` facts.
**Run:** https://github.com/SE-Emam/EMO-Cyber-Agent/actions/runs/37866150660 · workflow `runtime-parity` · event `workflow_dispatch` · conclusion `success`.

## 1. Runner identity + SHA (independently verified via `gh`)

- `gh run view 37866150660 --json conclusion,headSha,event,workflowName,jobs` → conclusion `success`, headSha `5c808807cabf5e6d0b86f2f5651ffe485f1e44ae`, event `workflow_dispatch`, all 5 jobs `completed/success`: build (ubuntu-24.04) + parity-linux 3.11/3.14 + parity-windows 3.11/3.14.
- Local `git log --oneline -8`: HEAD == `5c80880 fix(ci): correct module paths + schema location in package_resources harness`. Matches run headSha.
- Runner identities (per O3/O4 job logs, accepted as reported — O6 did not re-pull full logs): Linux `ubuntu-24.04`, CPython 3.11.17 / 3.14.8; Windows `windows-2025` (Server 2025 `10.0.26100`, image `windows-2025-vs2026` 20260925.250.1), CPython 3.11.9 / 3.14.7, x64. Harness shell on ALL jobs (incl. Windows): Git bash (`bash.EXE --noprofile --norc -e -o pipefail`) per workflow `defaults.run.shell: bash`.

## 2. Artifact identity (CI download re-hashed by O6)

Downloaded `parity-dist` via `gh run download 37866150660 -n parity-dist` and re-hashed locally:

| File | sha256 | size_bytes |
|---|---|---|
| `emo_cyber-0.2.0-py3-none-any.whl` | `df176c2c434ebccc2ed6dc4de90c44af0acece4ec99de18b76023ff821bf946b` | 754365 |
| `emo_cyber-0.2.0.tar.gz` | `c9075057457068c5091c19a0c3e6757f94ad16e76b2de3994bf6f8614593fc8e` | 1158577 |

- Manifest (`parity-manifest.json` in same download): `commit_sha=5c808807cabf5e6d0b86f2f5651ffe485f1e44ae` == run headSha == local HEAD. Exact filename set + per-file sha256 + size asserted by on-runner fail-closed gate on all 4 parity jobs (no MISMATCH fired; verify step `success`).
- Wheel content spot-check (O6 extraction): contains `emo_cyber_agent/subagent/sanitizer.py` **with** the T21-G control-char-separator fix (`emits a single`) and sdist likewise — i.e. CI artifacts genuinely built from 5c80880 source. 391 wheel entries.

## 3. Installed origins (wheel/sdist/pypi × py × OS)

Workflow installs per combo three isolated venvs: `.venv-wheel` (`pip install ./parity-artifacts/*.whl`), `.venv-sdist` (`pip install ./parity-artifacts/*.tar.gz`), `.venv-pypi` (`pip install emo-cyber==0.2.0` live from PyPI). PyPI side provably executed (O3/O4 log refs: `Collecting emo-cyber==0.2.0` → `Downloading emo_cyber-0.2.0-py3-none-any.whl (754 kB)` → `Successfully installed`). HEAD-vs-PyPI kept SEPARATE in all evidence (per-origin JSON filenames); no conflation.

## 4. Runtime results — O6 independently recomputed from downloaded JSON

Downloaded all four result artifacts (`parity-results-linux-py3.11/3.14`, `parity-results-windows-py3.11/3.14`), 18 JSON each (6 scripts × 3 origins), summed `checks`/`ok:false`:

| Combo | Files | Total checks | `ok:false` | Verdict |
|---|---|---|---|---|
| linux py 3.11 | 18 | 234 | 0 | **PASS** |
| linux py 3.14 | 18 | 234 | 0 | **PASS** |
| windows py 3.11 | 18 | 234 | 0 | **PASS** |
| windows py 3.14 | 18 | 234 | 0 | **PASS** |

Per-origin per-script summaries spot-verified (lin311 all 18, win311 all 18): verify_artifact 8/8, cli_matrix 16/16, mcp_stdio 12/12, http_battery 16/16, security_matrix 11/11, package_resources 15/15 — on wheel, sdist, AND pypi origins alike. Zero `NOT-EXECUTED` inside any JSON; `grep -rn "NOT-EXECUTED|skip" scripts/runtime-parity/*.py` → empty (no hidden-skip machinery in harness).

## 5. Capability detail (per O3/O4 logs + O6 JSON spot-checks)

- **CLI/JSON:** 16/16 × 3 origins × 4 combos. Version/help/doctor/status/audit/review/verify/report, JSON purity, exit codes (unknown-status 1, bad mode/format 2), stderr separation (0 bytes), redaction canary (no leak), resolvable binary (incl. `Scripts\cyber-agent.exe` on Windows), doctor 14 keys.
- **MCP stdio:** 12/12 × 3 × 4. initialize → tools/list (**7 tools confirmed live**: cyber_audit, cyber_extensions, cyber_report, cyber_review, cyber_status, cyber_threat_intel, cyber_verify) → safe call → malformed → progress → shutdown; framing intact; `no_secret_leak ok:true`; exit 0; invalid/oversized/progress-token correctly rejected (-32602/-32700).
- **HTTP security:** 16/16 × 3 × 4. Localhost-only bind, hostile Host/Origin → 403, oversized → 413, session-mismatch → 404, malformed → 400, 7-tool discovery, clean termination. No bypass.
- **Path behavior / security matrix:** 11/11 × 3 × 4. Traversal/NUL/absolute-path/cwd/argv-only/env-allowlist/presence-only/timeout/cleanup/progress-advisory/recovery; NUL detail `argv NUL client-denied; product denies in-process`.
- **Resources:** 15/15 × 3 × 4 (prior-round 12/15 fixed by 5c80880 module-path/schema-location fix — confirmed live). `installed.not_under_repo_src`, catalog + skills/tasks/playbooks/templates/toolpacks registries, `data.subagent.has_SubagentSession`, 36 schemas present + valid.
- **Progress/recovery:** covered inside security_matrix progress-advisory/recovery checks (all `ok:true`); no separate battery exists in harness — not a skip, a harness shape (see limitations for what is genuinely uncovered).
- **Full battery confirmed — NOT smoke-only:** every combo ran all 6 scripts (verify_artifact, cli_matrix, mcp_stdio, http_battery, security_matrix, package_resources) on all 3 origins (72 JSON total). **Install-only-as-all-interfaces refused:** CLI+MCP+HTTP exercised live per venv, not merely installed. **Mock-as-proof refused:** all probes executed against real installed packages (PyPI venv proves live network install; wheel/sdist venvs prove HEAD build).

## 6. Skips / failures

- **Failures: NONE** (936/936 checks green across 4 combos, independently recomputed).
- **Hidden skips: NONE** (no skip/continue logic in harness; every expected JSON present: 18/18 × 4).
- **Explicit NOT-EXECUTED (declared, not hidden):** (a) PowerShell/heredoc LIVE session — workflow pins bash on Windows, no PS session driven, `$PSVersionTable` not recorded (O4); (b) CLI quoting/spaces/Unicode/Ctrl-C-cancel cases — no such cases in `cli_matrix.py`; (c) broader Windows security surface (drive letters, UNC, separators, PATHEXT/exe lookup, temp dirs, permissions, line endings, ANSI/control) beyond the 11 checks; (d) `/etc/os-release` not catted on Linux (distro from runner-image metadata only). All carried as limitations, none as gate failures.

## 7. Workflow + release hygiene (O6 verified read-only)

- **No `continue-on-error` in `runtime-parity.yml`** (grep: zero hits). The only `continue-on-error: true` in the repo is the documented, intentional non-gating Windows smoke leg in `ci.yml:130` — out of scope for this gate, not a hidden skip here.
- **Permissions `contents: read` only** (`runtime-parity.yml:16-17`); no `id-token:write`, no PyPI credentials.
- **No publish/tag/PyPI-upload steps anywhere in `runtime-parity.yml`** (grep for publish/twine/upload-to-pypi/tag/release-steps: only comments + `pip install` consumer lines + artifact upload of JSON results).
- **v0.2.0 untouched:** `git tag --list` → `v0.1.0`, `v0.2.0` present, unmodified. `git diff v0.2.0..HEAD -- release/SHA256SUMS release/release-manifest.json` → empty (release artifacts unchanged). Only `release/CHANGELOG.md` differs (post-release notes addition, not an artifact). `git diff v0.2.0..HEAD --stat` shows only post-release dev: runtime-parity workflow+harness (new), sanitizer fix + tests (T21-G), briefs/changelogs.

## 8. Red-run fix trail (harness bugs, each fixed — confirmed)

| Red run | Head SHA (=commit) | Conclusion | Fixed by (next commit) |
|---|---|---|---|
| 37864297858 | 2eebbf9 (heuristics fix) | failure | c858903 (pass --manifest/--artifacts-dir to verify_artifact) |
| 37864678617 | c858903 | failure | 554f1bf (exclude own manifest from extras scan) |
| 37865407926 | 4f22886 (double-/mcp fix) | failure | 18b7c4f (traversal/NUL/progress probes) |
| 37865822303 | 18b7c4f | failure (build OK, all 4 parity jobs failed — consistent with harness bug: resources 12/15) | 5c80880 (module paths + schema location) |
| **37866150660** | **5c80880** | **success (5/5 jobs)** | — |

All red→green transitions are harness-only changes; product-code delta in range is solely the T21-G sanitizer fix (bounded, with regression tests). No product failure was ever observed.

## 9. Artifact-identity drift note (CI wheel vs local O2 wheel — RECORDED ANOMALY, not gate failure)

- Local `parity-artifacts/parity-manifest.json` (untracked O2 build log, `commit_sha=9098006…`) records wheel `df176c2c…` (754365 B) — **identical hash to the CI 5c80880 wheel** — but sdist `9ac274…` (1253437 B) differing from CI sdist `c90750…` (1158577 B).
- Sdist drift is EXPECTED (sdist embeds `scripts/runtime-parity/*`, added/changed across 96fc1f6..5c80880).
- Wheel match is UNEXPECTED: `git diff 9098006..5c80880 -- src/` shows the T21-G `sanitizer.py` change (packaged code), which must alter wheel bytes; yet hashes are byte-identical, and the CI wheel provably contains the fix. A pristine-9098006 build cannot yield this hash — the O2 local build tree must already have contained the fix (dirty tree) or its manifest `commit_sha` is mislabeled. Cause cannot be determined read-only; recorded honestly.
- **Gate impact: none.** The gate rests on CI self-consistency (manifest commit_sha == 5c80880 == HEAD, on-runner fail-closed verify on all 4 jobs, wheel content matches 5c80880 source) — all verified. The O2 local manifest is superseded evidence, not release material.

## 10. Limitations carried (unchanged, non-blocking)

PS-live NOT-EXECUTED (Git-bash-only harness); CLI quoting/Unicode/Ctrl-C surface absent from harness; broader Windows-security surface beyond 11 checks; `/etc/os-release` not catted. Owned by harness/product owners as future coverage; require no re-dispatch of this gate.

## 11. Verdict

- **Linux: PASS (online)** — ubuntu-24.04 × py 3.11/3.14, full battery, 234/234 × 2, PyPI executed, HEAD-vs-PyPI separate, zero leaks/bypasses.
- **Windows: PASS (online, PS gap noted)** — windows-2025 × py 3.11/3.14, full battery, 234/234 × 2, same separations; PS-live NOT-EXECUTED scope gap only.
- Host env debts (AnythingLLM/Pi/Jan) untouched by this gate (see parity-review overwrite §18).
