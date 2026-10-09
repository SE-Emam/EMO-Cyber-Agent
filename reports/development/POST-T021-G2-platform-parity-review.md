# POST-T021-G2 Platform Parity Review — T21-XREV-PLATFORM

**Date (UTC):** 2026-10-08 (local-only review) · **Online update:** 2026-10-09 by O6 (see §18+)
**Reviewer:** T21-XREV-PLATFORM (independent; did not execute T21-D/E)
**Scope:** READ-ONLY except this file. No src/tests/docs/tags/releases touched.
**Inputs:** POST-T021-linux-parity.md (T21-D), POST-T021-windows-parity.md (T21-E), POST-T021-baseline.md §§6–7, POST-T020-G6-python.md, POST-T020-G7-platform.md, .github/workflows/ci.yml + cheap-fact re-verification below.

> HISTORICAL NOTE (O6, 2026-10-09): §§1–17 below are the preserved local-only review (both OSes ENVIRONMENT-BLOCKED at that time, G2 FAIL). They are kept verbatim as history. The online gate evidence (§18+) supersedes the OS verdicts but does NOT rewrite this history.

## 1. Linux status — ENVIRONMENT-BLOCKED

- **Verdict: ENVIRONMENT-BLOCKED.** T21-D D1 blocked: Docker client 29.8.0 present, socket exists, but daemon unresponsive (`docker version` server half / `docker ps` / socket curl hang 8–12 s, killed, 4× reproduced). No limactl/multipass/VBoxManage/SSH host. Docker Desktop restart deliberately not attempted (other active session). Claim accepted as reproducible; rationale is environment, not product.
- D2–D9: **NOT-EXECUTED** (0 live runs: no clean install, CLI, MCP, HTTP, security, progress/recovery, package-resources, E2E on Linux).
- No defects recorded by T21-D; Gap-4 (Linux runtime parity, OPEN) unchanged. No per-platform relaxation applied — correct.

## 2. Windows status — ENVIRONMENT-BLOCKED

- **Verdict: ENVIRONMENT-BLOCKED.** T21-E E1 blocked: macOS-only host, `pwsh/powershell/wine/VBoxManage/multipass/lima` all absent, no UTM/Parallels/VMware app, no WSL, no remote/RDP/WinRM env, Docker context `desktop-linux` only. Claim accepted; repro commands given.
- E2–E10: **NOT-EXECUTED** (no install, CLI, PowerShell/CMD, MCP, HTTP, security, progress/recovery, resources, E2E on Windows).
- Carried defects (recorded, src untouched — correct per wave ownership):
  - **D1 (source-fix present, runtime-unproven):** `extensions/spec.py:537` default `platforms` uses `sys.platform` vocab (`win32`) vs `host_profile()` `platform.system().lower()` (`windows`, `compatibility.py:188-191`); fix `_PLATFORM_ALIASES` at `compatibility.py:219-221` verified in source but **needs Windows runtime proof**. Fail-closed direction. Blocks any Windows-compatible claim + blocks flipping `windows` job to gating.
  - **D2 (candidate):** `HostProfile.platform` default `"darwin"` (`compatibility.py:163`).
- PowerShell heredoc regression fix (`ci.yml:20-24` `defaults.run.shell: bash`) file-verified; interactive PowerShell/CMD battery still NOT-EXECUTED — correctly not closed.

## 3. macOS baseline standing

- G7 (2026-10-06): **darwin/arm64 23/23 PASS live** (D1–D23: wheel install, doctor human/json, audit json/human, MCP stdio init/list/call + 3 rejections, HTTP bind/init/call/routing/refusal/restart, spaces+unicode, traversal, argv, env, timeout, schemas, progress, recovery). Accepted as baseline.
- **Staleness (both reports + baseline §7 agree):** G7 ran at **0.1.0 wheel** (372 entries, lacks `mcp/http_server.py`; HTTP rows via `PYTHONPATH=src`) + HEAD source for HTTP. **G7 battery never re-run at 0.2.0/7 tools.** Baseline labels §§6–7 = PASS-WITH-NOTES, not unqualified PASS. Prior-OS evidence is **not reusable** as Linux/Windows PASS.
- Baseline HEAD `9098006` (+3 docs-only over annotated `v0.2.0` `67512ab`); version 0.2.0 ×3 consistent.

## 4. Python versions

- Declared: `requires-python >=3.11`; classifiers 3.11/3.12/3.13/3.14; ruff py311 + mypy 3.11 strict floors consistent.
- G6 (2026-10-06): 3.11.15/3.12.7/3.13.13/3.14.5 each **53/53 PASS** — but at **0.1.0/6 tools** (`cyber_threat_intel` absent). **Needs refresh at 0.2.0/7 tools in POST-T021.**
- Local: `python3` = 3.14.5 (this review); ruff/mypy binaries absent per baseline (ENVIRONMENT-BLOCKED for local lint re-verify; not re-probed here to stay read-only-cheap).
- CI Python coverage: tier1 ubuntu 3.11+3.14 (gating), tier2 ubuntu+macos 3.12+3.13 (gating), tier2-windows 3.12 only (non-gating). No 0.2.0 full-matrix rerun evidence in CI logs cited beyond smoke.

## 5. CLI results

- Linux: NOT-EXECUTED (no `--version/--help/doctor/status/audit/review/verify/report`, human or JSON).
- Windows: NOT-EXECUTED (same; plus PowerShell/CMD quoting/Unicode/spaces/streams/exit-code/Ctrl-C matrix not run).
- macOS: G7 D2–D5 PASS at 0.1.0 (see §3 staleness). **No parity conclusion drawable.**

## 6. MCP results

- Linux: NOT-EXECUTED (no initialize→tools/list→call live).
- Windows: NOT-EXECUTED (no stdio live; `\r\n`/universal-newline interop + third-party-host framing remain unproven; G7-N7 carried).
- macOS: G7 D6–D9 PASS at 0.1.0. CI `tools/list` in-process smoke (all OS legs) is **not** stdio plumbing and **not** a substitute.

## 7. HTTP results

- Linux: NOT-EXECUTED (no start→init→discover→call→notification→progress→shutdown; no Host/Origin/auth/oversize/timeout/reconnect/session checks).
- Windows: NOT-EXECUTED (same; `AF_INET`-only vs `::1` edge G7-N6 carried on all OSes).
- macOS: G7 D10–D14 PASS (HEAD-source only; 0.1.0 wheel lacked `http_server.py`).

## 8. Security results

- Linux: NOT-EXECUTED — path normalization, null-byte, encoded traversal, cwd, argv-only exec, env allowlist, timeout, cleanup, stream isolation **not compared**. T21-D explicitly claims **no delta observed or claimable** — endorsed.
- Windows: NOT-EXECUTED — drive-letter/separator/UNC/relative/encoded/NUL/ADS/case-aliasing/symlink, argv `;`-injection/PATHEXT, `sanitized_env`, temp/permission/line-ending/ANSI matrix **not run**. T21-E claims **no delta, none waived; future delta = BLOCKED UNTIL EXPLAINED** — endorsed.
- macOS: G7 D16–D19 PASS live (confine/normalize/argv/env). Residuals carried: ADS colon-forms + case-aliasing need Windows proof (fail-closed by design, unproven).
- **No security parity verdict possible on either OS.**

## 9. Progress

- Linux + Windows: NOT-EXECUTED (no normal/failure/recovery/cancel runs; no `mcp_notification` projection check).
- macOS: G7 D22 PASS at 0.1.0 (4-event lifecycle → 100%, notification projection).

## 10. Recovery

- Linux + Windows: NOT-EXECUTED (no capture/restore round-trip, cross-audit scope, TRANSIENT→RETRY, cancel; no privilege-escalation-on-platform-error check).
- macOS: G7 D23 PASS at 0.1.0 (byte-identical round-trip, ScopeViolationError, RETRY, 10-row policy table).

## 11. Package resources

- Linux + Windows: NOT-EXECUTED (no installed-package inventory of skills/tasks/playbooks/templates/threat_intel/subagent/checklists/schemas; no `resource_origin()`/`validate_packaged_schemas()` from installed 0.2.0).
- macOS: G7 D21 PASS at 0.1.0 (`packaged` origin, 5 schemas OK). Staleness: 0.2.0 wheel/sdist present in `dist/` but content listing deliberately not substituted as Windows/Linux evidence (T21-E) — correct.
- Note: 0.2.0 adds `cyber_threat_intel` (7th tool) + threat-intel package; resource surface changed since G7 — another reason G7 cannot stand in for 0.2.0.

## 12. Failures

- No product failures observed (no runtime reached). Zero src/ changes by T21-D/E confirmed (see §14). No new defects filed by T21-D; two carried items from T21-E (D1 fix-unproven, D2 candidate). No unexplained failure to adjudicate — blockers are environmental with repro steps.

## 13. Limitations

1. Single-machine (macOS Darwin 25.3.0 arm64) review; Linux/Windows verdicts rest on T21-D/E discovery + own cheap-fact re-checks, not on new runtimes (out of scope to provision).
2. Docker daemon hang not re-probed invasively (would disturb another session); accepted on T21-D's 4× repro + socket/client evidence.
3. CI logs not re-pulled (`gh run view` cited by T21-E taken as side-channel only); ci.yml read directly — sufficient since CI ≠ runtime per rule.
4. G6/G7 source files re-read; product `src/` not re-audited line-by-line (baseline + T21-E read-only facts accepted).

## 14. Evidence (cheap facts re-verified 2026-10-08)

- `python3 --version` → `Python 3.14.5`; `uname -a` → `Darwin … 25.3.0 … RELEASE_ARM64_T8103 arm64`.
- `which docker` → `/usr/local/bin/docker`; `which pwsh powershell wine` → all `not found` (matches T21-E E1).
- `git status --porcelain` → `M reports/development/POST-T020-G1-host-matrix.md` + 7 untracked `??` under `reports/development/` + `reports/security/` (T21-D/E files among them); **zero `src/`/`tests/` changes** — T21-D/E scope compliance confirmed.
- `git log --oneline -3` → `9098006 / 9af310f / 2815ea9` (matches baseline HEAD).
- CI matrix (`ci.yml` read verbatim): tier1-fast ubuntu 3.11/3.14 **gating** (fast subset + version check); tier2-compat ubuntu+macos × 3.12/3.13 **gating** (import + `--version` + in-process tools/list + contracts); tier2-windows windows-latest 3.12 **`continue-on-error: true` (ci.yml:130), recorded non-blocking** (same smoke only). `defaults.run.shell: bash` (ci.yml:20-24) present. No full G7 battery job on any OS.

## 15. CI-vs-runtime gap statement

CI is green-ish signal only: the sole Windows leg is explicitly non-gating smoke (import + `--version` + in-process `tools/list` + contracts — no CLI matrix, no stdio plumbing, no HTTP, no security/progress/recovery battery); ubuntu/macos gating legs are the same smoke subset, not the D/E or G7 battery. **Per rule, CI PASS → Runtime PASS is forbidden; no Linux/Windows runtime PASS is claimable from CI.**

## 16. STOP conditions

None triggered as an observed product violation (no security difference / bypass / framing corruption / session confusion / widening / leakage observed — nothing executed to observe them). The carried `win32`-vs-`windows` vocabulary mismatch is a **known defect candidate with fix present but runtime-unproven**, fail-closed, not a widening or leak. **However, absence of evidence is not PASS: the gate still FAILS on missing runtime proof (§17), and any future unexplained failure or delta remains BLOCKED per standing rule.**

## 17. Final Gate Decision — G2 FAIL (local-only, 2026-10-08; SUPERSEDED for Linux/Windows by §18)

**G2 FAIL (local scope).** Reason at the time: neither Linux nor Windows had any live runtime verification (both ENVIRONMENT-BLOCKED, 0 batteries executed); macOS baseline stale (0.1.0); Python matrix stale; Windows vocabulary defect runtime-unproven; CI cannot substitute. This verdict stands as the correct local-only conclusion and is preserved here; §§18–19 record what the online gate changed and what it did not.

---

# ONLINE SECTION (O6, 2026-10-09) — full detail in `POST-T021-G2-online-platform-review.md`

## 18. Online gate evidence (run 37866150660, commit 5c80880 — O6 independently re-verified)

- Run `conclusion: success`, headSha `5c80880…` == local HEAD; 5/5 jobs green (build + linux 3.11/3.14 + windows 3.11/3.14). Red-run trail confirmed: 37864297858/37864678617/37865407926/37865822303 all `failure` on successive pre-fix SHAs (last red: build OK, all 4 parity jobs failed — harness bug, resources 12/15), each fixed by the next harness-only commit, green only at 5c80880.
- O6 downloaded `parity-dist` + all four result artifacts and recomputed: manifest `commit_sha=5c80880…`; wheel `df176c2c…` (754365 B) / sdist `c90750…` (1158577 B); **234/234 checks, 0 `ok:false`, per combo × 4 combos (936/936)**; per-script splits verify 8/8, CLI 16/16, MCP 12/12 (7 tools live), HTTP 16/16, security 11/11, resources 15/15 on wheel/sdist/pypi alike. Full battery (6 scripts × 3 origins) — smoke-only refused, install-only refused, mock-as-proof refused, no hidden skips (no skip logic in harness; 18/18 JSON × 4 present).
- Workflow hygiene: no `continue-on-error` in `runtime-parity.yml`, `permissions: contents: read`, no publish/tag/PyPI-upload steps. v0.2.0 tag untouched; `release/SHA256SUMS` + `release-manifest.json` unchanged vs tag (only `release/CHANGELOG.md` notes differ).
- Drift note: CI wheel `df176c2c…` == local O2 manifest (9098006-era) wheel hash — UNEXPECTED given the T21-G `sanitizer.py` diff in range (CI wheel provably contains the fix); O2 tree must have included the fix or its manifest SHA is mislabeled. No gate impact (CI self-consistent). Sdist drift EXPECTED (embeds harness scripts).
- Explicit NOT-EXECUTED carried honestly: PS-live session, CLI quoting/Unicode/Ctrl-C cases, broader Windows-security surface, `/etc/os-release` cat.

## 19. Separated statuses + G2 verdict (online)

- **Linux: PASS (online)** — ubuntu-24.04 × py 3.11/3.14, full battery live, PyPI executed, HEAD-vs-PyPI separate, zero leaks/bypasses. Supersedes §1 ENVIRONMENT-BLOCKED for the online gate. (Local Docker-block history above unchanged.)
- **Windows: PASS (online, PS gap noted)** — windows-2025 × py 3.11/3.14, same battery green; PS-live NOT-EXECUTED scope gap only. Supersedes §2 ENVIRONMENT-BLOCKED for the online gate. §2 D1/D2 vocabulary items: covered by the live Windows runtime proof to the extent the harness exercises them (all green, fail-closed, no bypass); interactive-PS proof remains future coverage, not a gate blocker.
- **Android-Termux: PASS (unchanged)** — no new evidence this round; prior local-only standing carries as-is.
- **macOS baseline: per latest evidence** — G7 23/23 at 0.1.0 stands as baseline with §3 staleness (0.2.0/7-tool re-run still open); not re-proven here, not needed for the Linux/Windows gate.
- **Published 0.2.0: independent status** — PyPI `emo-cyber==0.2.0` installed live in `.venv-pypi` on all 4 combos and green on every battery (78/78 per combo per O3/O4 counting; O6 recomputed within the 234/combo totals). Upstream release files themselves untouched (tag + SHA256SUMS + manifest unchanged).
- **Current HEAD test artifact: independent status** — wheel `df176c2c…` + sdist `c90750…` built from 5c80880, hashes recorded above; this is a TEST artifact, NOT a release (no publish/tag step exists in the workflow).
- **G2 overall: PASS (online scope: Linux + Windows runtime parity).** Failures none, hidden skips none, limitations carried explicitly.
- **Host env debts (AnythingLLM / Pi / Jan): UNCHANGED by this gate — NO.** No evidence in this run touches them; no files under those tracks modified (`git diff v0.2.0..HEAD --stat` shows only workflow+harness, sanitizer fix+tests, briefs/changelogs). They remain open on their own tracks.
