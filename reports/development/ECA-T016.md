# ECA-T016 — Release Candidate & Host Compatibility

## Objective
Prove EMO-Cyber-Agent works — and stays safe — as an installed package
outside the source tree: reproducible build, clean install, CLI/MCP/
Python API gates, contract + security regression, host evidence, version
metadata, docs, changelog, license, manifest, and residual-risk sign-off.
No new features; only release-necessary fixes (packaged resources,
license) were made.

## Scope
RC work only: version freeze (0.1.0, RC1), wheel+sdist build, fresh-venv
install gates, resource loading without source-tree assumptions, public
API tiers, release tests, CHANGELOG/LICENSE/docs review, artifacts +
manifest + checksums, offline E2E from the installed package, host
matrix, invariant gate, security assessment. Deferred (documented, not
built): persistent audit store, live runners/harnesses, MCP-over-HTTP,
progress streaming, real-network integrations.

## Release Scope
Same product as T001–T015, now distributable. Explicitly NOT added:
scanners, providers, host-specific logic, UI/PDF, remediation automation,
scores, or any security logic anywhere new.

## Version
Canonical package `0.1.0` (RC1 marker in CHANGELOG + manifest only —
no version churn across contracts). Consistency pinned by test:
package = CLI doctor = MCP serverInfo = report `emo_version` = `0.1.0`;
independent versions stay independent (`eca-t007-v1`, `corr-v1`,
`cls-v1`, report schema `1.0` — never implicitly tied).

## Package Build
hatchling in an isolated venv: `wheel` + `sdist`, both produced cleanly.
Wheel verified to contain code + `data/schemas` (5 files) + `data/
policies` (2 files) + `data/LICENSE` + entry points; sdist carries full
source/docs. No hooks, no executables beyond `cyber-agent`, no setup-time
code.

## Artifacts
`dist/emo_cyber_agent-0.1.0-py3-none-any.whl`,
`dist/emo_cyber_agent-0.1.0.tar.gz`, `dist/SHA256SUMS.txt`
(`8b30c3…066`, `4d9700…cad`), plus root `release-manifest.json`
(version/build/platform/python/hashes/schema+policy+rule versions).

## Clean Install
Fresh venv → `pip install <wheel>` (deps resolved, no PYTHONPATH, no
editable install, cwd-independent): `cyber-agent --help`, `doctor`,
`doctor --format json` (`schemas: OK (packaged)` — the key resource test),
`audit /tmp --format json` all green. pipx absent here → isolated-venv
equivalence used and recorded.

## pipx
Not installed in this environment; the fresh-venv install above is the
documented equivalent (isolated executable environment, same assertions).

## CLI
All 7 commands re-verified post-packaging mindset; `doctor` now resolves
schemas via packaged resources (works installed AND in checkout).
Stdout/stderr, exit codes, SIGINT, secret-freedom, isolation all green
in-suite; installed-binary smoke green out-of-tree.

## MCP
Re-verified against the INSTALLED package with the reference SDK over
real stdio (`cyber-agent mcp` binary): initialize (2025-06-18), exact
5-tool list, `cyber_status`/`cyber_audit`/`cyber_verify`/`cyber_report`
all ok — INSTALLED INTEROP PASS. (Protocol-version note from T013 still
applies: the version string is the negotiated SDK version at test time.)

## Python API
Installed-package check: `__all__` + version + `ReportService` +
`generate_report` all live; empty-audit report builds. Tiers documented
in-package: SUPPORTED (4 names, pinned), PROVISIONAL (5 homes),
INTERNAL (everything else — absence-from-top-level pinned).

## Host Matrix
See assessment §Host Compatibility Matrix: reference SDK PASS; CLI
fallback PASS (installed E2E); OpenCode/Hermes/pi/VS Code NOT_TESTED
(binaries present but unexercised — never claimed); Cline/Forge/Klio
NOT_TESTED (absent); pipx NOT_TESTED (absent, venv equivalent used).

## Configuration
Precedence (flags > env > file > defaults) and policy-key rejection
re-verified; unknown env ignored; symlink/malformed configs fail safe.

## Security Regression
Full suite 323 passed / 3 skipped (pre-existing optional probes);
T015 campaign 37/37 re-run green post-packaging; critical boundaries
(target/version-bound decisions, traversal family, redaction, markdown
confinement, MCP/CLI injection screens) re-asserted in-suite.

## Dependency Audit
Runtime pins all bounded below+above, no URL/git sources (parsed
in-test); optionals stay optional (`mcp`, `http`, `dev`); license field
declared; zero new runtime deps in T016 (hatchling is build-time only).

## Import Safety
Subprocess import: returncode 0, zero thread delta, version + API
surface correct. No network/subprocess/credential/state side effects
by construction (imports are declarative; verified by absence of
failures plus source inspection).

## Startup Safety
`--help` cheap and clean (sub-second, no scanning/network/secrets);
`mcp` idles until a tool request crosses Core (interop logs show only
dispatch lines).

## Offline Mode
Entire gate (323 tests, schemas, build except dependency fetching,
install, interop, E2E) needs no GitHub/Supabase/model credentials or
network beyond PyPI fetches for the isolated venvs — recorded as the
release baseline.

## Documentation
README (install/quickstart/commands/exit-codes/CI/security, implemented-
only), CHANGELOG (0.1.0-rc1 entry with fixes + limitations, nothing
hidden), MCP example (already canonical `cyber-agent mcp`), SECURITY.md
(reporting guidance present; private contact mechanism still
to-be-established — recorded limitation), CONTRIBUTING.md (aligned:
tests, no secrets, adapter discipline).

## Changelog
Updated as above; prior foundation entry preserved.

## License
Apache-2.0 chosen; full text in `LICENSE`; placeholder retired;
`pyproject.toml` declares `license = "Apache-2.0"`; manifest + metadata
consistent.

## Security Notice
SECURITY.md reviewed: reporting guidance, read-only boundaries present.
Gap recorded (not papered): no established private contact channel yet —
required before public distribution beyond RC testers.

## Release Manifest
Root `release-manifest.json`: version, RC tag, timestamps, platform,
artifacts + hashes + sizes, python floor, schema/policy/rule versions.

## End-to-End Tests
Installed-package offline E2E: Core classify+promote → findings JSON →
installed `cyber-agent report` markdown containing the finding id; plus
installed `audit` JSON parse and `doctor` gates. MCP host E2E: 5-tool
round trip above.

## Known Limitations
PEP-668 interpreters need isolated envs (documented); Windows drive
paths denied by policy; persistent sessions/runners/harnesses/HTTP/
streaming unwired (documented seams); `DefaultPolicyEngine` allow-all
persists on legacy read paths with strict-only execution (unchanged).

## Evidence
- `pytest tests/ -p no:warnings` → `323 passed, 3 skipped`.
- Schemas 6/6 (incl. report). `compileall` clean.
- `tests/unit/test_release.py` (9 tests): versions, API tiers, import/
  startup safety, resources, license/changelog/docs, report inventory,
  MCP example, dependency strategy.
- Installed gates: doctor/audit JSON, 5-tool SDK interop, API import,
  finding→report E2E — all from `/tmp`, no source tree.
- Artifacts + manifest + checksums on disk.

## Final Status
**PASS** — RC gates satisfied: versions consistent, wheel+sdist built and
inspected, clean install + CLI + MCP + API + E2E green, host matrix
honest (2 PASS, rest NOT_TESTED, zero claims without evidence),
config/security regression green, deps audited, import/startup safe,
offline baseline holds, docs/changelog/license/manifest complete,
residuals stated. No BLOCKED condition (no install failure, no
source-tree dependence, no interop failure, no regression, no leakage,
no unsafe default, no schema mismatch, no missing artifact, license
resolved, no undocumented API change) observed. Architectural feature
work stops here per directive; forward work is usage-driven.
