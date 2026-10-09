# POST-T021 Linux Runtime Parity — O3 Report (6th collection round)

**Date (UTC):** 2026-10-09
**Agent:** O3 (Linux Runtime Parity)
**Workflow:** `.github/workflows/runtime-parity.yml`, run id `37866150660`, commit `5c808807cabf5e6d0b86f2f5651ffe485f1e44ae` (harness fixes only; product code = T21-G included)
**Run URL:** https://github.com/SE-Emam/EMO-Cyber-Agent/actions/runs/37866150660
**VERDICT: PASS** — both `parity-linux` jobs `completed/success` with full per-venv evidence, fail-closed hashes, no leaks/bypasses, no unexplained or missing checks.

Scope compliance: sole write is this file. No src/workflow/script edits, no other files, no publish, no tags. Windows combos out of scope (noted only: both `parity-windows` jobs also `completed/success` this run — O4's scope).

## Poll record

- Polled `gh run view 37866150660 --json jobs` on ~60s cadence; poll 1 (00:43 UTC) both linux `in_progress`; poll 2 (00:44 UTC) both linux `completed/success`; poll 3 (00:45 UTC) full run `completed/success`.
- `build (ubuntu-24.04, single wheel+sdist build)` job `113613247041`: `completed/success` — https://github.com/SE-Emam/EMO-Cyber-Agent/actions/runs/37866150660/job/113613247041
- `parity-linux (ubuntu-24.04, py 3.11)` job `113613299992`: `completed/success` — https://github.com/SE-Emam/EMO-Cyber-Agent/actions/runs/37866150660/job/113613299992
- `parity-linux (ubuntu-24.04, py 3.14)` job `113613300008`: `completed/success` — https://github.com/SE-Emam/EMO-Cyber-Agent/actions/runs/37866150660/job/113613300008

## Artifact identity (verified, fail-closed MATCH)

- **Manifest** `parity-artifacts/parity-manifest.json`, `commit_sha=5c808807cabf5e6d0b86f2f5651ffe485f1e44ae` (matches dispatched HEAD; checkout `ref: 5c80880…` in both linux logs). Fail-closed gate `Verify sha256 against manifest` asserts exact filename set, per-file sha256 + size; no MISMATCH fired on either combo.
- `emo_cyber-0.2.0-py3-none-any.whl` — sha256 `df176c2c434ebccc2ed6dc4de90c44af0acece4ec99de18b76023ff821bf946b`, 754365 bytes (`OK …` in both logs; unchanged vs prior rounds — expected, wheel packs only package).
- `emo_cyber-0.2.0.tar.gz` — sha256 `c9075057457068c5091c19a0c3e6757f94ad16e76b2de3994bf6f8614593fc8e`, 1158577 bytes (`OK …` in both logs; changed vs round-5 `b5d6e681…` — expected, sdist embeds harness scripts this commit touched).
- These are **HEAD-build** hashes. They are **NOT** the published PyPI files — never conflated (see PyPI-vs-HEAD section).

## Combo 1 — parity-linux py 3.11 — verdict: PASS

- **Environment:** runner `ubuntu-24.04` (`Image: ubuntu-24.04`, runner version `2.337.0`); OS `Ubuntu`; CPython `3.11.17` (toolcache `/opt/hostedtoolcache/Python/3.11.17/x64`); checkout `ref: 5c80880…`. `/etc/os-release` not catted — distro/version from runner-image metadata only.
- **Per-venv evidence (18 JSON uploaded as `parity-results-linux-py3.11`, artifact id `11588675656`):** `rg '"summary"'` → 3× `8/8`, 6× `16/16`, 3× `12/12`, 3× `15/15`, 3× `11/11`; `rg '"ok": false'` → 0. Zero `NOT-EXECUTED`.
- **Evidence log refs (job URL above):** hash gate `OK wheel…` / `OK sdist…` / `manifest commit_sha=5c80880…`; PyPI venv proves PyPI side executed (`Collecting emo-cyber==0.2.0`, `Downloading emo_cyber-0.2.0-py3-none-any.whl (754 kB)`); `ls results/` lists all 18 `*-py3.11-Linux.json`.

### Per-venv / per-probe evidence (py 3.11)

| Origin venv | verify_artifact | CLI matrix | MCP stdio (7 tools?) | HTTP battery | Security matrix | Package resources |
|---|---|---|---|---|---|---|
| HEAD wheel (`.venv-wheel`) | 8/8 PASS | 16/16 PASS | 12/12 PASS, 7 tools YES (`mcp.tools_list.count7 got=[…7…]`) | 16/16 PASS (`http.discover.7tools`) | 11/11 PASS | 15/15 PASS |
| HEAD sdist (`.venv-sdist`) | 8/8 PASS | 16/16 PASS | 12/12 PASS, 7 tools YES | 16/16 PASS | 11/11 PASS | 15/15 PASS |
| PyPI 0.2.0 (`.venv-pypi`) | 8/8 PASS | 16/16 PASS | 12/12 PASS, 7 tools YES | 16/16 PASS | 11/11 PASS | 15/15 PASS |

No leak/bypass on any venv (`mcp.no_secret_leak ok:true` ×3, `cli.redaction.canary ok:true` ×3).

## Combo 2 — parity-linux py 3.14 — verdict: PASS

- **Environment:** runner `ubuntu-24.04` (`Ubuntu 24.04.5 LTS`, runner version `2.337.0`, Hosted Compute `20261002.596`, region `westcentralus`); CPython `3.14.8` (toolcache `/opt/hostedtoolcache/Python/3.14.8/x64`); checkout `ref: 5c80880…`. Same os-release caveat.
- **Per-venv evidence (18 JSON uploaded as `parity-results-linux-py3.14`):** identical counts — 3× `8/8`, 6× `16/16`, 3× `12/12`, 3× `15/15`, 3× `11/11`; `rg '"ok": false'` → 0. Zero `NOT-EXECUTED`.
- **Evidence log refs (job URL above):** same hash-gate `OK` lines + `manifest commit_sha=5c80880…`; PyPI venv proves PyPI side executed (`Collecting emo-cyber==0.2.0`, `Downloading emo_cyber-0.2.0-py3-none-any.whl (754 kB)`).

### Per-venv / per-probe evidence (py 3.14)

| Origin venv | verify_artifact | CLI matrix | MCP stdio (7 tools?) | HTTP battery | Security matrix | Package resources |
|---|---|---|---|---|---|---|
| HEAD wheel | 8/8 PASS | 16/16 PASS | 12/12 PASS, 7 tools YES | 16/16 PASS | 11/11 PASS | 15/15 PASS |
| HEAD sdist | 8/8 PASS | 16/16 PASS | 12/12 PASS, 7 tools YES | 16/16 PASS | 11/11 PASS | 15/15 PASS |
| PyPI 0.2.0 | 8/8 PASS | 16/16 PASS | 12/12 PASS, 7 tools YES | 16/16 PASS | 11/11 PASS | 15/15 PASS |

**7-tools: YES on both combos × all 3 venvs** (`mcp.tools_list.count7` + `http.discover.7tools`). **Security: YES 11/11 on both combos × all 3 venvs** (incl. `sec.null_byte.rejected: argv NUL client-denied; product denies in-process`). **Resources: YES 15/15 on both combos × all 3 venvs** (prior-round 3 failures fixed). **PyPI side: EXECUTED on both combos.**

## PyPI-vs-HEAD section (kept SEPARATE)

- HEAD-build artifacts (this run, commit `5c80880`): wheel `df176c2c…` (754365 B), sdist `c9075057…` (1158577 B) — verified above by manifest fail-closed gate in each linux job.
- Published PyPI `emo-cyber==0.2.0`: installed live in `.venv-pypi` on both combos (`Collecting emo-cyber==0.2.0` → `Downloading emo_cyber-0.2.0-py3-none-any.whl (754 kB)` → `Successfully installed … emo-cyber-0.2.0`); its 6 per-origin JSON (`pypi-*-py3.11/3.14-Linux.json`) are recorded **separately** from HEAD wheel/sdist JSON — never conflated. HEAD-vs-PyPI comparison: all three origins pass identically, so no divergence to explain.
- Leak/bypass check: none — `mcp.no_secret_leak ok:true` and `cli.redaction.canary ok:true` on every venv; no `bypass` evidence; no unexplained `ok:false`; no missing probes.

## Gate verdict

- **Linux gate: PASS** — py 3.11 PASS + py 3.14 PASS; SHA+hashes fail-closed MATCH; full per-venv evidence (wheel/sdist/pypi) × (CLI 16/16, MCP 12/12 with 7 tools, HTTP 16/16, security 11/11, resources 15/15); PyPI side executed with HEAD-vs-PyPI kept separate; zero leaks/bypasses, zero unexplained, zero NOT-EXECUTED. Linux is **runtime-verified** for commit `5c80880` on ubuntu-24.04 × py 3.11/3.14.
