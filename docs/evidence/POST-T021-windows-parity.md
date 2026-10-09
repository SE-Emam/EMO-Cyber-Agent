# POST-T021 Windows Runtime Parity — O4 Report (sixth collection round)

Date (UTC): 2026-10-09 · Owner: O4 (Windows Runtime Parity Agent) · Scope: Windows jobs only (linux is O3's)
Run: https://github.com/SE-Emam/EMO-Cyber-Agent/actions/runs/37866150660 (workflow_dispatch, commit `5c80880` "fix(ci): correct module paths + schema location in package_resources harness")
Authorized write: this file only. No `src/`/workflow/script edits, no publish, no tags.

## VERDICT: PASS (both Windows combos green — 234/234 checks per combo, 0 failures, 0 leaks)

Build job `build (ubuntu-24.04, single wheel+sdist build)` → `success`
(`https://github.com/SE-Emam/EMO-Cyber-Agent/actions/runs/37866150660/job/113613247041`).
The `5c80880` module-path/schema-location harness fix is CONFIRMED live: `package_resources` now **15/15 on all three origins** (wheel/sdist/pypi) on both combos, and the full matrix (verify 8/8, CLI 16/16, MCP 12/12, HTTP 16/16, security 11/11) passes on every venv. No secret leak, no bypass, no session anomaly observed. PowerShell/heredoc LIVE remains honestly **NOT-EXECUTED** (Git-bash-only harness, see below) — recorded as a scope gap, not a gate failure.

Poll: both windows `in_progress` at 00:43:23 UTC → 3.11 `completed/success` at 00:44:25 UTC, 3.14 `completed/success` at 00:45:27 UTC (third 60s poll; no 50-min wait needed).

---

## Per-combo evidence

### Combo A — parity-windows (windows-2025, py 3.11) → PASS
- Job: https://github.com/SE-Emam/EMO-Cyber-Agent/actions/runs/37866150660/job/113613300001 · status `completed`, conclusion `success`.
- OS: Microsoft Windows Server 2025 `10.0.26100` Datacenter · Image `windows-2025-vs2026` version `20260925.250.1` · runner v2.337.0, Azure region westus3. Arch: x64 per toolcache `C:\hostedtoolcache\windows\Python\3.11.9\x64` + `win_amd64` dependency wheels (pydantic-core/pyyaml/rpds-py `cp311-win_amd64`).
- Python: setup-python `Successfully set up CPython (3.11.9)`. pip: venv base `24.0` (`Requirement already satisfied: pip in …\.venv-wheel\lib\site-packages (24.0)`); harness ran `pip install --upgrade pip` with no upgrade line observed.
- PowerShell: ALL harness steps ran under Git bash (`shell: C:\Program Files\Git\bin\bash.EXE --noprofile --norc -e -o pipefail`). `$PSVersionTable`: NOT-RECORDED (no PS session driven). PowerShell/heredoc LIVE: **NOT-EXECUTED** (recorded honestly; Git-bash-only).
- Commit SHA: checkout `ref: 5c808807cabf5e6d0b86f2f5651ffe485f1e44ae`, `HEAD is now at 5c80880…`; manifest `commit_sha=5c808807cabf5e6d0b86f2f5651ffe485f1e44ae`; on-runner verify printed `manifest commit_sha=5c808807cabf5e6d0b86f2f5651ffe485f1e44ae`. Verified.
- Artifact identity: **VERIFIED on-runner (fail closed)** — step `Verify sha256 against manifest (fail closed)` → `success`, both `OK` lines (`whl df176c…`, `sdist c90750…`) asserted on-runner. Off-runner re-hash matches (see Artifact identity section).
- Venvs (all three created, isolated): wheel (`pip install ./parity-artifacts/*.whl` → `Successfully installed … emo-cyber-0.2.0 …`), sdist (`pip install ./parity-artifacts/*.tar.gz` → built `emo_cyber-0.2.0-py3-none-any.whl size=754365 sha256=e780c173…` locally), pypi (`pip install emo-cyber==0.2.0` from PyPI). Results uploaded as `parity-results-windows-py3.11` (18 JSON files).
- Harness per origin: wheel 78/78 · sdist 78/78 · pypi 78/78 (verify 8/8, CLI 16/16, MCP 12/12, HTTP 16/16, security 11/11, resources 15/15 each). Total **234/234, 0 fails**.
- Steps: checkout/setup-python/download-artifact/verify/harness/upload all `success`.

### Combo B — parity-windows (windows-2025, py 3.14) → PASS
- Job: https://github.com/SE-Emam/EMO-Cyber-Agent/actions/runs/37866150660/job/113613300003 · status `completed`, conclusion `success`.
- OS: Microsoft Windows Server 2025 `10.0.26100` Datacenter · Image `windows-2025-vs2026` version `20260925.250.1` · runner v2.337.0. Arch: x64 per toolcache `C:\hostedtoolcache\windows\Python\3.14.7\x64` (+ win_amd64-class deps).
- Python: setup-python `Successfully set up CPython (3.14.7)`. pip: venv base already `26.2.1` (`Requirement already satisfied: pip in .\.venv-wheel\Lib\site-packages (26.2.1)`); same for sdist/pypi venvs.
- PowerShell: same Git bash harness (`bash.EXE --noprofile --norc -e -o pipefail`); `$PSVersionTable`: NOT-RECORDED. PowerShell/heredoc LIVE: **NOT-EXECUTED**.
- Commit SHA: checkout `5c808807cabf5e6d0b86f2f5651ffe485f1e44ae`; manifest `commit_sha` identical; on-runner verify `success` with both `OK` lines. Verified.
- Venvs: wheel/sdist/pypi all created same as Combo A (sdist local build `size=753946 sha256=eae89855…` — build-reproducibility variance only, NOT the distributed artifact; distributed artifact hashes verified separately). Results uploaded as `parity-results-windows-py3.14` (18 JSON files).
- Harness per origin: wheel 78/78 · sdist 78/78 · pypi 78/78. Total **234/234, 0 fails**.
- Steps: all `success` (same as Combo A).

---

## Artifact identity (fail closed — PASS on both combos)

| File | sha256 | size_bytes |
|---|---|---|
| `emo_cyber-0.2.0-py3-none-any.whl` | `df176c2c434ebccc2ed6dc4de90c44af0acece4ec99de18b76023ff821bf946b` | 754365 |
| `emo_cyber-0.2.0.tar.gz` | `c9075057457068c5091c19a0c3e6757f94ad16e76b2de3994bf6f8614593fc8e` | 1158577 |

- On-runner: both combos printed both `OK` lines + `manifest commit_sha=5c808807cabf5e6d0b86f2f5651ffe485f1e44ae`; verify step conclusion `success` on both. No mismatch → no fail-closed trip.
- Off-runner cross-check (read-only `gh run download 37866150660`, `parity-dist/parity-manifest.json`): `commit_sha` == `5c808807cabf5e6d0b86f2f5651ffe485f1e44ae` == local `git log` HEAD `5c80880`; recomputed local sha256/sizes of both files match the table exactly.
- HEAD vs PyPI-0.2.0: **SEPARATE — both sides EXECUTED and both green.** HEAD wheel-origin and HEAD sdist-origin each 78/78; PyPI (`emo-cyber==0.2.0`) origin 78/78 on both combos. No pass-count divergence between HEAD and PyPI 0.2.0 on any battery. (No byte-identical claim beyond the harness pass counts; the PyPI wheel is upstream's, the HEAD wheel is this commit's.)

## Battery evidence (all three origins executed on both combos)

- CLI (`version/help/doctor/status/audit/review/verify/report`, JSON purity, exit codes): **PASS 16/16 × 3 origins × 2 combos.** Includes `cli.resolvable` (`.venv-<origin>\Scripts\cyber-agent.exe`), `cli.version` (`emo-cyber 0.2.0`), `cli.doctor.json` (14 keys), unknown-status exit=1, exit-2 bad mode/format, `cli.stderr.separation` (0 bytes), `cli.redaction.canary` (no leak). Quoting/spaces/Unicode/Ctrl-C-cancel: **NOT-EXECUTED — no such case exists in `cli_matrix.py`** (coverage gap, not a pass; script-owner scope).
- PowerShell/heredoc regression, LIVE Windows result: **NOT-EXECUTED.** Harness shell was Git bash on both combos (workflow pins `shell: bash`; Windows PowerShell cannot parse heredocs); no PowerShell/CMD session was driven and no quoting/Unicode/Ctrl-C case ran. The regression stays open until a fixed-workflow run drives a PS session. Recorded honestly; NOT claimed.
- MCP stdio (`initialize → tools/list (7 tools) → safe call → malformed → progress → shutdown`; framing): **PASS 12/12 × 3 × 2.** `mcp.tools_list.count7 ok: true` with `got=['cyber_audit', 'cyber_extensions', 'cyber_report', 'cyber_review', 'cyber_status', 'cyber_threat_intel', 'cyber_verify']` (7 tools confirmed LIVE on Windows in every venv), `mcp.framing.intact`, `mcp.no_secret_leak ok: true`, `mcp.process.exit code=0`. Invalid/oversized/progress-token probes correctly rejected (`-32602`/`-32700`). No bypass observed.
- HTTP battery (Host/Origin/auth/session/timeout/reconnect/oversized): **PASS 16/16 × 3 × 2.** `http.discover.7tools`, localhost-only bind (`http://127.0.0.1:*/mcp`), hostile-Host/Origin → 403, oversized → 413, session-mismatch → 404, malformed → 400, server terminated. No bypass observed.
- Windows security (`security_matrix`): **PASS 11/11 × 3 × 2.** Traversal/NUL/absolute-path/cwd/argv-only/env-allowlist/presence-only/timeout/cleanup/progress-advisory/recovery all `ok: true`; NUL detail `argv NUL client-denied; product denies in-process`. The `5c80880` fix holds on Windows. Broader Windows security (drive letters, UNC, separators, exe lookup, temp dirs, permissions, line endings, ANSI/control) beyond the harness's 11 checks: **NOT-EXECUTED** (no such cases in harness; coverage gap, not a pass).
- Resources (`package_resources`): **PASS 15/15 × 3 × 2** (was 12/15 at run 37865822303 — the three prior failures `data.threat_intel`, `data.checklists`, `data.schemas.present` now pass after the `5c80880` module-path/schema-location fix). Includes `installed.not_under_repo_src`, `resources.catalog_exists`, skills/tasks/playbooks/templates/toolpacks registries, `data.subagent.has_SubagentSession`, `data.schemas.present` (36 schemas) + `data.schemas.valid`.
- Failures/leaks: **NONE.** Zero `ok: false` across 468 Windows checks (234 × 2 combos). No secret leak (`cli.redaction.canary`, `mcp.no_secret_leak`, `sec.env.allowlist`, `sec.cleanup.no_canary_residue` all true), no traversal/NUL bypass, no session anomaly. Nothing unexplained → no BLOCKED owner assignment this round.

## Gate verdict

| Combo | Verdict |
|---|---|
| windows-2025 · py 3.11 (verify 8/8, CLI 16/16, MCP 12/12 incl. 7-tools, HTTP 16/16, security 11/11, resources 15/15 — wheel/sdist/pypi all green; 234/234) | **PASS** (identity + hashes verified; PS-live NOT-EXECUTED scope gap only) |
| windows-2025 · py 3.14 (same; 234/234) | **PASS** (same) |
| Windows overall | **PASS** — full Windows parity green at `5c80880`. Remaining non-blocking scope gaps (require no re-dispatch of this gate): live PowerShell quoting/Unicode session, CLI quoting/Unicode/Ctrl-C cases, broader Windows-security surface — all NOT-EXECUTED, owned by harness/product owners as future coverage |
