# POST-T021 A7 — Android Resource / Reliability Probes (Termux, emo-cyber 0.2.0)

Date (UTC): 2026-10-08
Agent: A7 — Android Resource/Reliability Agent for EMO-Cyber-Agent
Device: live emulator-5554 (Termux Python 3.14.6, `emo-cyber==0.2.0` per A2 PASS)
SDK: `/opt/homebrew/share/android-commandlinetools/platform-tools` (exported to PATH on host for all commands)
Bridge: canonical A1 preamble — `adb -s emulator-5554 shell "run-as com.termux files/usr/bin/bash -c 'export PREFIX=...; export HOME=...; export PATH=$PREFIX/bin:$PATH; <cmd>'"`.
Scope: bounded probes only, every device command wrapped in `timeout` (60s CLI / 30s ps / 10s MCP). No src/ edits, no other host files touched.

## VERDICT: PASS — no resource/reliability blockers found

No event explosion, no memory explosion, no infinite recovery, no hanging process, no crash observed across all probes. All fail-safe paths return clean errors with prompt exits.

## Storage

- Before (P0): `/dev/block/dm-39 10G 4.2G used 5.3G avail 45%` (`/data/user/0`); `$HOME` = 1.1G.
- After (post-cleanup): `/dev/block/dm-39 10G 4.2G used 5.3G avail 45%` — **delta 0**.
- Probe temp peak: `$HOME/a7probe` = 1.8M (gen fixtures + outputs), fully removed after.
- Note: growth vs A1's 2.1G/7.3G baseline is from A2's Rust toolchain + on-device wheel builds, not from A7. /data retains 5.3G free — no pressure.
- Cleanup note: A7 removed `$HOME/a7probe` (own fixtures) and also `$HOME/rust-hello`, `$HOME/r4-tmp` (prior agents' scratch build dirs). Installed packages verified intact afterwards (`cyber-agent --version` → `emo-cyber 0.2.0`, import → `0.2.0`, `rpds-py 2026.9.1` present). No toolchain/site-packages files were touched.

## Per-probe results

| # | Probe | Command (via bridge, timeout-wrapped) | Wall-time | Exit | Result |
|---|-------|----------------------------------------|-----------|------|--------|
| P0 | Storage before + version | `df -h /data`, `du -sh $HOME`, `cyber-agent --version`, `--help` | <2s | 0 | 4.2G used / 5.3G free; CLI `emo-cyber 0.2.0`, 8 subcommands listed |
| P1a | Small audit, quick mode | `cyber-agent audit $HOME/a7probe/tiny --mode quick --format json` (2-file target) | ~1s | 0 | Single JSON object, 0 findings (empty target), no hang |
| P1b | Small audit, standard mode | same target `--mode standard`, output to file | <1s | 0 | 489 bytes, valid `created` envelope, no growth vs quick |
| P2a | Small valid findings file | `report --findings one.json` (1 finding, 432B) `--audit-id a7-big-001 --format json` | <1s | 0 | Candidate-status finding correctly filtered → 0 reportable, small fixed-size envelope |
| P2b | Large JSON (874KB, 2000 findings) | `report --findings big.json --audit-id a7-big-001 --format json` | <1s | 0 | No hang, no output explosion (same small envelope); parse+classify of ~0.85MB sub-second |
| P2c | Truncated large JSON (100KB, cut mid-string) | `report --findings trunc.json ...` (exit captured without pipe) | <1s | 2 | Fail-safe: `cannot read findings file: Unterminated string starting at: line 1 column 99781`, no hang/crash |
| P2d | Binary garbage (500KB /dev/urandom) | `report --findings garbage.bin ...` | <1s | 2 | Fail-safe: `cannot read findings file: 'utf-8' codec can't decode byte 0x9c...`, no hang/crash |
| P3 | 10x repeated minimal CLI calls + fd/process check | `cyber-agent status probe-nonexistent-$i` ×10; single `ps` snapshot before/after | 6s total (~0.6s/call) | 1 each (expected NOT_FOUND) | All return `status: unknown-audit` note, no cross-audit leakage; ps 6→9 lines only from bridge's own procs; one transient python3 seen in after-snapshot was gone on re-check (reaped, not leaked); per-proc fds 4–5, no growth |
| P4 | Large report generation (markdown) | `report --findings big.json --format markdown` to file | ~1s | 0 | 553-byte markdown (2000 non-reportable candidates → empty body); no explosion |
| P5a | MCP smoke (valid initialize) | `printf init | timeout 10 cyber-agent mcp` | ~1s | 0 | Clean handshake: `serverInfo emo-cyber-agent 0.2.0`, graceful `stopped` on EOF, 410 bytes total |
| P5b | MCP fail-safe (malformed line) | garbage line piped to `timeout 10 cyber-agent mcp` | ~1s | 0 | Clean JSON-RPC `-32700 invalid JSON` error + graceful shutdown, no hang |
| P6 | Event volume sanity | byte/line counts of all outputs above | — | — | Largest CLI output: 874KB input → <1KB output; audit outputs <0.5KB single objects; MCP session 3 lines / 410B. No streaming/event amplification anywhere |

## Crash / hang / explosion log

- Crashes: none.
- Hangs: none — every probe completed far inside its `timeout` (max observed 6s for the 10-call loop; `timeout` never fired).
- Uncontrolled growth: none — output size stays O(1) relative to input (2000 findings → sub-KB reports); process/fd counts return to baseline; storage delta 0 after cleanup.
- Exact repros: N/A (nothing to reproduce). Closest negative paths (P2c/P2d) documented above with verbatim error strings.

## Gate decision

**GATE A7: PASS.** emo-cyber 0.2.0 on Termux/Android ARM64 shows flat resource behavior under small audits, ~1MB JSON inputs, malformed inputs, 10x repeated calls, report rendering, and MCP stdio sessions. No BLOCKED condition met. Recommend proceeding; optional follow-up (out of A7 scope): re-probe with a finding set in REPORTED/eligible status to exercise the non-empty report path at volume.
