# ECA-T016 — Release Security Assessment

## Security Baseline Delta Since T015
No new attack surface added (one new module `core/resources.py` — pure
file reads; one thin CLI command set already covered in T014; license
metadata only). Two boundaries tightened post-T015 with regression tests
(execution-decision target+version binding; path/ref null-byte, encoded-
traversal, and drive-letter denial; report newline confinement). Full
suite re-verified green after every change: no T015 regression.

## New Attack Surface
Packaged distribution itself: wheel/sdist contents inspected (schemas,
policies, LICENSE data files + code + entry points; no hooks, no
executables beyond the `cyber-agent` console script, no setup-time code).
`import emo_cyber_agent` verified side-effect-free (no threads, no
network, no subprocess). CLI `--help`/doctor verified cheap and
external-call-free.

## Regression Status
323 passed, 3 skipped (pre-existing optional binary probes). T015
campaign re-run in full post-packaging: 37/37. Invariant matrix 12/12.

## Packaging Security
Artifacts built from a clean checkout state via hatchling in an isolated
venv; SHA-256 recorded in `dist/SHA256SUMS.txt` and `release-manifest.json`
(version, timestamp, platform, python, hashes, schema/policy/rule
versions). Install path tested twice: editable-equivalent dev runs and a
pristine venv wheel install with zero source-tree dependence.

## MCP/CLI Exposure
MCP: 5 tools, discovery-payload scanned, live SDK interop re-verified
against the INSTALLED package (initialize/list/4 calls incl. verify plan
and report). CLI: 7 commands, exit codes, stdout/stderr split, SIGINT,
secret-free outputs re-verified. Both remain pure adapters (decision-verb
source scans green).

## Dependency Status
Runtime pins all bounded below+above, no URL/git sources (parsed
in-test); optionals (`mcp`, `http`, `dev`) stay optional; license field
`Apache-2.0` declared; installed inventory sane. No new dependency added
in T016 (hatchling is build-time only, never shipped).

## Residual Risks
Carried from the T015 baseline unchanged, plus two RC-specific notes:
(1) persistent audit sessions, live runners/harnesses, MCP-over-HTTP,
and progress streaming are unwired seams (documented in help/README,
never implied working); (2) the absent-host matrix entries below are
NOT_TESTED, never claimed. Nothing graded PASS without a test.

## Known Limitations
PEP-668-managed interpreters cannot `pip install` without an isolated
environment (venv/pipx equivalent used throughout); Windows drive-letter
paths are denied at the Core boundary by policy (POSIX assumed);
`DefaultPolicyEngine` allow-all persists ONLY on the legacy read path
with strict-only execution gating (unchanged, documented).

## Accepted Limitations
Same set as the T015 baseline §4 (claimant-provided hashes/versions,
deferred harnesses/runners/transports/caching/scoring, no live external
semantics). Accepted explicitly by keeping them out of PASS claims.

## Host Compatibility Matrix

| Host | Method | Transport | Invocation | Status | Limitations | Evidence |
|---|---|---|---|---|---|---|
| Reference MCP SDK | subprocess stdio | stdio | initialize/list/4×call | PASS | subset lifecycle only | interop logs (T013 + T016 rerun) |
| CLI fallback (any agent/script) | binary | pipes/files | audit/report/doctor/status | PASS | file-based findings input | CLI E2E + installed E2E |
| OpenCode | MCP | stdio | — | NOT_TESTED | binary present, not exercised | none claimed |
| Hermes | MCP | stdio | — | NOT_TESTED | binary present, not exercised | none claimed |
| pi | MCP/CLI | stdio/pipes | — | NOT_TESTED | binary present, not exercised | none claimed |
| VS Code | MCP | stdio | — | NOT_TESTED | binary present, not exercised | none claimed |
| Cline/Forge/Klio | — | — | — | NOT_TESTED | binaries absent | n/a |
| pipx | isolated install | n/a | — | NOT_TESTED | pipx absent; venv equivalent used | venv gates |

## Release Recommendation
Factual status only, no score: all RC gates satisfied with nothing
outstanding — license resolved (Apache-2.0, LICENSE + manifest +
metadata consistent), artifacts built and hashed, clean-install gates
(CLI/MCP/API/E2E) green, security regression green, docs reviewed,
residuals stated. **RC PASS** pending your acceptance of the stated
residuals; no BLOCKED condition observed.
