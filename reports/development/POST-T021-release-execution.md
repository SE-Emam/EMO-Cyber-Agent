# POST-T021 Release Execution — v0.2.1 RELEASED

Date (UTC): 2026-10-09 · Executor: Lead Orchestrator (official path only: tag → release.yml → Trusted Publishing/OIDC; no manual uploads, no version reuse)
Working dir: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`

## 1. Version decision — 0.2.1 (patch)

`git diff v0.2.0..HEAD -- src/`: exactly ONE file (`subagent/sanitizer.py`, +17/−3, internal `normalize()` behavior). Zero public `def`/`class` changes; CLI/MCP surfaces, tool count (7), schemas, and config formats unchanged; threat-intel/HTTP features belonged to 0.2.0. Compatible bug fix → PATCH per SemVer. Pins updated (same 8-file shape as the 0.2.0 precedent): `pyproject.toml`, `__init__.__version__`, `EMO_VERSION`, `service.doctor version`, `mcp/protocol.SERVER_VERSION`, `subagent/discovery.SERVER_VERSION`, both `CHANGELOG.md`, 4 test version-pins, regenerated `release/` records.

## 2. Source commit + tag

- Release commit: `28ecdce72553873ad09ee7f104c0bc8966249451` (`release: bump to 0.2.1`), 14 files, tracked tree clean (`git status` clean except untracked local `parity-artifacts/`).
- Tag: `v0.2.1` (annotated, `EMO-Cyber-Agent v0.2.1`) → `28ecdce`. No prior tag moved.

## 3. Test evidence (real commands + counts)

- Candidate full suite `python3 -m pytest tests -q -p no:cacheprovider --junitxml`: **2726 collected, 0 failures, 0 errors, 6 skipped** (→ 2720 passed), exit 0, at the release tree.
- Sanitizer/security subsets: 110 + 109 passed. Sanitizer probes re-verified live (`\r/\x0b/\x0c` joins→deny; CRLF/benign→allow/sanitize).
- Gate incident + minimal fix (no test weakening): first candidate run showed 17 failures + 25 errors, ALL classified as version-identity staleness, never product faults — (a) 4 test literals pinning `"0.2.0"` (updated to `"0.2.1"`, same as bump-commit `67512ab` did for 0.2.0); (b) 2 missed `SERVER_VERSION` pins (`mcp/protocol.py`, `subagent/discovery.py`); (c) `release/` records regenerated from candidate bytes via `scripts/release/make_release.py` (project mechanism, same as CI). Re-ran to green; no expected-outcome edits beyond the version identity itself.
- CI incident (transient, resolved by evidence): first release run failed `build-verify`/`Run unit suite` with exit 1 and empty step output. Reproduced-equivalent stacks locally (py3.12 + pytest 9.1.1 ± asyncio plugin; py3.14 + pytest 9.1.1): all green 2675/0/0/6 — root cause undetermined from available logs (pytest 9.1.1 was new in CI that day). Reran the SAME workflow run (no repo change): full green. Recorded honestly; not hidden.

## 4. Artifacts (built from tagged source by the official workflow)

| File | Size | SHA-256 |
|---|---|---|
| `emo_cyber-0.2.1-py3-none-any.whl` | 755024 B | `651e92f29b4cf8bb5494a3c822d8c4467c0905ec4360795e724beccfe8b1cbd6` |
| `emo_cyber-0.2.1.tar.gz` | 1269077 B | `af355295d862043c64774e82c9a9e7e58d52065d71e8d928fecec352048c5c707b6a2fb8847301` |

- Locally-built `dist/` from the release tree is byte-identical in hashes (same table) → local↔CI determinism for identical content confirmed again.
- `release-manifest.json` + `SHA256SUMS` regenerated from CI bytes by `make_release.py` (authoritative); recomputed from downloaded release assets — match.
- Package hygiene: 391 wheel entries; filename scan for secrets/env/keys: only two legitimate content packs (`secrets-sensitive-data.yaml`, `secret-audit.yaml` — detection playbooks, no secret values; value-shape grep clean).

## 5. Publication proof (not workflow-start claims)

- Actions run: https://github.com/SE-Emam/EMO-Cyber-Agent/actions/runs/37877758667 — `build-verify`/`github-release`/`pypi-publish` all `success` (after one transient-failure rerun, §3).
- GitHub Release: https://github.com/SE-Emam/EMO-Cyber-Agent/releases/tag/v0.2.1 — published (draft→published, mirroring v0.2.0 handling), 4 assets (wheel + sdist + SHA256SUMS + manifest).
- PyPI: https://pypi.org/project/emo-cyber/ — `0.2.1` files live (wheel sha256 `651e92f2…` via simple API; JSON API lagged, simple API authoritative).
- Published-package match: PyPI wheel bytes == release wheel bytes (`651e92f2…`, re-hashed after download) == release `SHA256SUMS` entry.

## 6. Post-install verification (published 0.2.1, clean venv `/tmp/smoke021`)

- `pip install emo-cyber==0.2.1` from PyPI: success (20 packages; first attempt hit transient index lag, retry clean — noted, not hidden).
- `cyber-agent --version` → `emo-cyber 0.2.1`; `import emo_cyber_agent.__version__` → `0.2.1` from site-packages (not repo src).
- MCP stdio (initialize → notifications/initialized → tools/list): `serverInfo {emo-cyber-agent, 0.2.1}`, 7/7 tools live. (Note: two earlier smoke attempts failed on the harness side — macOS has no `timeout(1)`; product was never at fault. Re-ran via Python subprocess: green.)

## 7. Old releases untouched (explicit confirmation)

- Tags: `v0.1.0`, `v0.2.0` unmoved (`v0.2.0`→`67512ab`); only ADD is `v0.2.1`→`28ecdce`.
- `v0.2.0` on PyPI still listed and downloadable; `release/SHA256SUMS` + `release-manifest.json` at `v0.2.0` byte-identical (diff vs tag: only `release/CHANGELOG.md` notes, pre-existing).
- No `release.yml` runs except the tag-triggered ones; no manual uploads; no secrets in repo or reports (values never printed).

## 8. Remaining open items (preserved, non-blocking)

Host env-blockeds (AnythingLLM/Pi/Jan), test-key LOW/OPEN, heuristic open-by-design residuals, platform scope edges (PS-live etc.), manifest dirty-tree labeling note — all carried from POST-T021 assessments, none inflated or hidden by this release.

## Verdict: RELEASED — emo-cyber 0.2.1 is live on GitHub and PyPI with verified package integrity.
