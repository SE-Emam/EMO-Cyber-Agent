# POST-T019 Public Release Assessment — emo-cyber 0.1.0

Date: 2026-10-06. Orchestrator: Release Orchestrator (subagents R0/R1 + Lead execution).

## 1. Release identity

- Product: EMO-Cyber-Agent — portable, model-agnostic, governed security subagent.
- Version 0.1.0, Tag v0.1.0 (annotated, on release commit).

## 2. Repository

- Canonical: `SE-Emam/EMO-Cyber-Agent` (public, fresh local repo; remote HEAD == local HEAD at push time).
- Prior state (home-dir monorepo nesting) eliminated for this product.

## 3. Commit SHA

- Release commit (tag target): see `git rev-list -n 1 v0.1.0` (post-release main has one extra docs/display commit; tag immutable).

## 4. Tag

- `v0.1.0` annotated; tag == release commit; version == 0.1.0 (CI gate).

## 5. GitHub Release

- Published: https://github.com/SE-Emam/EMO-Cyber-Agent/releases/tag/v0.1.0 (was Draft → published after R9 gates).

## 6-8. Wheel/SDist SHA256 + sizes

- Recorded in draft `SHA256SUMS` + `release-manifest.json` (CI-regenerated from CI bytes).
- Draft bytes == PyPI bytes (verified recomputation, IDENTITY PASS).

## 9. CI run

- Tag-gated release workflow: build-verify SUCCESS (unit + regen + release suites), github-release SUCCESS, pypi-publish SUCCESS.
- Fixes applied during release ops (workflow-only/test-path only, no security logic): uv provisioning, build→test order, exit-code gate, JUnit-XML counts, machine-independent test paths, PyPI dir isolation, draft mode, checkout in release job.

## 10. Test result

- Unit 2202 passed / 3 skipped (CI); release 51/51 (CI + local).

## 11-12. Security gate / 12 invariants

- 12/12 PASS (T018 final review, unchanged code paths).

## 13-15. GitHub/PyPI status + PyPI hashes

- GitHub Release: PUBLISHED with 4 assets. PyPI: `emo-cyber 0.1.0` live (Trusted Publishing/OIDC, no tokens used).
- PyPI wheel/sdist hashes == draft asset hashes (byte-identical, verified).

## 16-19. pip/pipx/CLI/MCP verification (public bits)

- `pip install emo-cyber==0.1.0`: import 0.1.0, --version, doctor, JSON audit, MCP 6 tools + token→4 notes / no-token→silence: ALL PASS.
- `pipx install emo-cyber==0.1.0`: installs, runs (reports old display label — cosmetic, fixed post-release on main).
- Host matrix: per T018 honesty labels (4/5 binaries present; anythingllm NOT EXECUTED).

## 20-21. Known limitations / deferred work

- Per T018 assessment (unchanged): vendor interop beyond contracts, HTTP transports, checklist template, heuristic regex screens.
- Display label fix (`_dist_name`) committed post-release; ships in next version, NOT backported (PyPI 0.1.0 immutable).

## 22. Rollback/incident guidance

- Do NOT delete/reuse v0.1.0. Blocker found post-publish → INCIDENT → patch version (0.1.1+) via same pipeline. Tag/release/PyPI files immutable.

## 23. Final decision

**PUBLIC RELEASE — PASS.** Exact validated candidate became the exact public artifact (commit→tag→CI→draft→PyPI byte identity proven at every link).
