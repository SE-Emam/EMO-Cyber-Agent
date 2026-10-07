# POST-T020-G8 — CI Matrix (EMO-Cyber-Agent)

Owner: G8-A (CI Matrix Owner) · Date (UTC): 2026-10-06 · Working dir: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`

Scope: this task created exactly two files — `.github/workflows/ci.yml` + this report. No other files touched.

## 1. Tier table

| Tier | Where | Trigger | What runs | Gate? |
|---|---|---|---|---|
| Tier 1 — fast | `ci.yml` job `fast` | PR to `main` / push to `main` (tags excluded) | Linux + Python 3.11 (minimum per `requires-python>=3.11`) + 3.14 (latest): `pip install -e ".[dev]"`, version-consistency check (`pyproject.toml` == installed metadata; `cyber-agent --version`), fast subset `pytest tests/unit/subagent tests/unit/progress tests/unit/recovery tests/unit/test_cli.py tests/unit/test_mcp.py` | **Gating** — any failure blocks |
| Tier 2a — compatibility | `ci.yml` job `compat` | Same as Tier 1 | Linux + macOS × Python 3.12/3.13: install + `import emo_cyber_agent` + `cyber-agent --version` + in-process MCP `tools/list` smoke (`create_server().handle_message`, asserts ≥6 tools) + `pytest tests/unit/subagent/test_contracts.py` | **Gating** — any failure blocks |
| Tier 2b — compatibility (Windows) | `ci.yml` job `windows` | Same as Tier 1 | Single `windows-latest` + Python 3.12 job, same steps as Tier 2a | **RECORDED non-blocking** (`continue-on-error: true` with explicit NEEDS-RUNTIME-PROOF comment — see §3) |
| Tier 3 — release qualification | `release.yml` (already owns it; **NOT duplicated in `ci.yml`**) | Push of tag `v*` | Tag==version check, `pip install -e .`, `hatchling build` once, unit suite → `make_release.py` records → `tests/release` identity suite → draft GitHub Release → PyPI trusted publishing | Gating on tags (unchanged) |

Trigger split: `ci.yml` handles `push.branches:[main]` + `pull_request.branches:[main]` with `tags-ignore: ["v*"]`; `release.yml` handles `push.tags:["v*"]`. No overlap, no gap.

## 2. What runs where (job count)

- `fast`: matrix `python-version: [3.11, 3.14]` on `ubuntu-latest` → **2 runs**.
- `compat`: matrix `os: [ubuntu-latest, macos-latest]` × `python-version: [3.12, 3.13]` → **4 runs**.
- `windows`: matrix `python-version: [3.12]` on `windows-latest` → **1 run**.
- **Total: 3 job definitions, 7 job runs** — far under GitHub's 256-job matrix limit.
- Python coverage: 3.11 / 3.12 / 3.13 / 3.14 = exactly the declared stables from G6 (`requires-python>=3.11`; classifiers list 3.11–3.14; all four PASS locally per G6). OS coverage: ubuntu + macos gating, windows recorded (G7: darwin 23/23 PASS live; linux/windows inspection-only).

## 3. Windows caveat (no hidden skips)

- Only the `windows` job carries `continue-on-error: true`, and it is annotated in-file with the reason: **Windows is NEEDS-RUNTIME-PROOF per G7** — concrete defect candidate N1 (`ExtensionCompatibility` default `platforms` uses `sys.platform` vocabulary `"win32"` while `host_profile()` emits `platform.system().lower()` → `"windows"`; `spec.py:537` vs `compatibility.py:183-194`), plus zero prior Windows runtime evidence (host matrix 5× Not-tested).
- `continue-on-error` does **not** hide the result: the job still runs, still logs, still annotates; a failure shows as recorded-but-non-blocking. The standing instruction is: if it fails, fix the product (expected: vocabulary normalization) or the workflow, and document — never silence further.
- No other job uses `continue-on-error`; no `if: false`, no conditional skips, no `fail-fast` masking (`fail-fast: false` everywhere so one matrix leg never hides another).

## 4. Reproducibility / safety rules

- Actions pinned to majors (`actions/checkout@v4`, `actions/setup-python@v5`) — same pins as `release.yml` uses.
- `permissions: contents: read` (least privilege); **no secrets referenced**; no privileged steps (no `sudo`, no docker, no network beyond pip).
- `concurrency: group ci-${{ github.ref }}, cancel-in-progress: true` — superseded runs cancel.
- Failures visible: `pytest --tb=short` with real exit codes; smoke scripts `assert` with printed tool lists; no output-swallowing (`tail`-style masking from release.yml not copied here).

## 5. Facts reused (not re-proven)

- G6 (`POST-T020-G6-python.md`): minimum Python 3.11; 3.11.15/3.12.7/3.13.13/3.14.5 all PASS (53-test subset + MCP 6 tools: `cyber_audit, cyber_review, cyber_verify, cyber_report, cyber_status, cyber_extensions`); single 3.14 note is a third-party `pytest-asyncio` DeprecationWarning, not product code.
- G7 (`POST-T020-G7-platform.md`): darwin/arm64 23/23 PASS live; linux/windows inspection-only; N1 windows vocabulary mismatch is the reason Tier 2b is non-blocking.
- `release.yml` structure (read 2026-10-06): `build-verify` → `github-release` → `pypi-publish`, all `ubuntu-latest`, tag-gated — Tier 3 stays there.

## 6. Validation done here (and NOT done)

- **Done:** careful read-through of `ci.yml` against the brief; `python yaml.safe_load` parse OK (after quoting the `on:` key to avoid the YAML 1.1 `on`→`True` quirk; GitHub accepts quoted `on`); job-run count verified (2+4+1=7); trigger/concurrency/permissions keys verified; smoke-test API (`create_server().handle_message({"method":"tools/list"})`) verified against `src/emo_cyber_agent/mcp/server.py:123-167`.
- **NOT done (by design, per brief):** no `act`, no local runner execution, no push. **CI runs were NOT executed here — first execution happens on next push/PR.** Fast-subset paths (`tests/unit/subagent`, `tests/unit/progress`, `tests/unit/recovery`, `tests/unit/test_cli.py`, `tests/unit/test_mcp.py`) confirmed to exist on disk.

## 7. Verdict

`ci.yml` delivers Tier 1 (fast) + Tier 2 (compat incl. recorded Windows) within ~7 jobs; Tier 3 remains solely in `release.yml`. Windows non-blocking status is explicit, justified by G7-N1, and reversible once runtime proof lands.
