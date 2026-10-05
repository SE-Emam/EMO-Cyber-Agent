# POST-T017 — Artifact Checksum Forensics (EMO-Cyber-Agent Release Recovery)

**Agent:** Agent 2 — Artifact Checksum Forensics
**Date:** 2026-10-05 (UTC)
**Scope:** READ-ONLY investigation. No source modified, no rebuild executed.
**Method:** `ls`/`stat`/`shasum`, file reads, read-only `pytest`, read-only `git show`/`rev-parse`, in-place inspection of `dist/*.tar.gz` / `*.whl` bytes (tar/zip listing, member hashes). Nothing was written outside this report.

---

## 1. Artifact Inventory (ground truth, measured just now)

| Artifact | Size (bytes) | SHA-256 | mtime (birth) |
|---|---|---|---|
| `dist/emo_cyber_agent-0.1.0-py3-none-any.whl` | 581789 | `63b455ed…b49f` (`63b455edd832f6666fb6cb517b45450487ec192ae83a402d9747b617dfb6b49f`) | 2026-10-04 21:27:53 (born 21:27:50) |
| `dist/emo_cyber_agent-0.1.0.tar.gz` | 737069 | `0c5481…8a51d` (`0c5481739e23f96b5bf16b70683ab92c82ca1001a2bf9db7990dd9466518a51d`) | 2026-10-04 21:27:51 (born 21:27:50) |
| `release/release-manifest.json` | 2966 | `c0fcffbf…3496d0` (self-consistent — matches SHA256SUMS line 3) | 2026-10-04 20:53:44 |
| `release/SHA256SUMS` | 288 | n/a (checksum list) | 2026-10-04 20:53:44 |
| `release/effective_artifact_verification.json` | 703 | n/a | 2026-10-04 22:01:31 |

Recorded (stale) identity inside `release/release-manifest.json` + `release/SHA256SUMS`:

| Artifact | Recorded size | Recorded SHA-256 |
|---|---|---|
| sdist `emo_cyber_agent-0.1.0.tar.gz` | **731492** | **`136b4672825ea3ef15734371687e96ac6b89fd202ec9d75815b1d58f5347cfd6`** |
| wheel `emo_cyber_agent-0.1.0-py3-none-any.whl` | 581789 | `63b455edd832f6666fb6cb517b45450487ec192ae83a402d9747b617dfb6b49f` (matches dist exactly) |
| `release-manifest.json` | (hash `c0fcffbf…3496d0` — matches current file) | — |

Manifest metadata: `build_timestamp: 2026-10-04T17:53:44Z` (= 20:53 local, matches file mtime), `git_revision: d2cf50c9f725548763d2a8828d587b8f965ce21f`, backend `hatchling` via `uv-build` (`uv 0.11.7`).

**Key timeline (all local, +03):**

- **20:53** — manifest + SHA256SUMS written, recording sdist **`136b46…`/731492** (artifact set **A**).
- **21:18** — commit `9f6ba34` (POST-RC-014 extension work; tracked only 2 files, working tree carried the rest).
- **21:27:50–53** — `dist/` **rebuilt**: both wheel and sdist rewritten (artifact set **B**). Manifest/SHA256SUMS were **not** regenerated.
- **22:01** — `effective_artifact_verification.json` written: `status PASS`, records sdist size **737069** (= current dist) — i.e. a *second* record that agrees with dist but disagrees with the manifest's 731492.
- **22:16 → Oct 5** — working tree moved on again (`progress/` born 22:16, `recovery/` Oct 5 02:06, `cli/main.py` + `mcp/server.py` modified Oct 5). Current sources now differ from *both* artifact sets (see §5).

## 2. Failure reproduction (read-only `python3 -m pytest tests/release/ -q --tb=short`)

3 failed, 41 passed. The 3 failures, verbatim:

1. `test_sha256sums_verifies_in_clean_environment` (`test_release_integrity.py:44`) — recomputes every SHA256SUMS line from disk:
   `assert '0c548173…' == '136b4672…'` for `emo_cyber_agent-0.1.0.tar.gz` (**actual dist bytes vs recorded hash**).
2. `test_manifest_hash_matches_dist_identity` (`test_release_integrity.py:95`) — compares manifest's recorded hashes to freshly hashed `dist/` bytes:
   `assert '136b4672…' == '0c548173…'` for sdist (**recorded vs actual**; wheel line passes).
3. `test_manifest_artifacts_match_dist_files` (`test_release_manifest.py:72`) — compares recorded name/size/hash per artifact:
   `assert 731492 == 737069` (**recorded sdist size vs `stat()` of dist file**; fails before even reaching the hash).

## 3. What each failing test compares

| Test | Comparison | Nature of expectation |
|---|---|---|
| `test_sha256sums_verifies_in_clean_environment` | `sha256(dist/<name>)` vs the hash printed in `release/SHA256SUMS` | No hardcoded hash in the test — the expectation lives in the **signed file** (`136b46…`). |
| `test_manifest_hash_matches_dist_identity` | `manifest["artifacts"][key]["sha256"]` vs `sha256(dist file)` for wheel + sdist | No hardcoded hash — expectation lives in the **manifest** (`136b46…`, size 731492). |
| `test_manifest_artifacts_match_dist_files` | `manifest["artifacts"][key]` name/size/sha256 vs `dist/` name/`st_size`/fresh sha256 | Same — expectation lives in the **manifest**. |

None of the three tests hardcode `136b46…`; all three derive "expected" from the release records and "actual" from `dist/` bytes. They are **identity-link tests** (record ↔ bytes), and they are correct to fail: the link is genuinely broken for the sdist.

## 4. Root-Cause Mechanism (not "it's old" — the actual sequence)

**A was signed, then B was built, and the signature was never re-taken.**

1. At 20:53 a build produced artifact set A (sdist `136b46…`, 731492 bytes) and the release records were generated **from those exact bytes** (manifest + SHA256SUMS mutually consistent; manifest's own hash line still verifies today — proof the records haven't been hand-edited since).
2. Source kept changing (POST-RC-014 extension/compat work, committed 21:18 as `9f6ba34`), and at 21:27 `dist/` was **rebuilt from the newer tree** → set B (sdist `0c5481…`, 737069 bytes, **+5577 bytes**). Nobody regenerated the manifest/SHA256SUMS afterward.
3. So the tests compare **B's bytes against A's signature** and fail on hash (×2) and size (×1). Artifact A's file is not retained anywhere — only its hash/size survive in the records — so a byte-level A-vs-B file diff is impossible; the delta is bounded instead (§5).

**The drift is content, not clock.** The build backend is deterministic and exonerated:

- Hatchling clamps **all 615 sdist tar members to one mtime: `1580601600` (2020-02-02T00:00:00Z)**; the gzip header mtime is the same value. No `SOURCE_DATE_EPOCH` is set in the environment — the `2020-02-02` stamp is hatchling's documented default, applied uniformly.
- The wheel likewise carries a **single ZIP timestamp `(2020, 2, 2, 0, 0, 0)` across all 329 entries**; uid/gid `0/0`, empty uname/gname, mode `0644`, no pax headers.
- Therefore identical source ⇒ byte-identical output. A rebuild from the *same* tree cannot explain a 5577-byte / full-hash change. There is **no timestamp flake**; the bytes differ because the **source differed** between the two builds.

## 5. Sdist status (current set B) vs manifest

- Current sdist: 615 members, all mtimes clamped (see §4). Top-level content mix: `src` (191), `tests` (221), `docs` (59), `templates` (94), `reports` (35 incl. `reports/security/ECA-T016-invariant-release-gate.md`), `release` (3), `scripts` (3) + root files (`PKG-INFO`, `pyproject.toml`, `CHANGELOG.md` 3536 B, `LICENSE`, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `Makefile`).
- `sdist CHANGELOG.md == working-tree CHANGELOG.md` byte-for-byte (3536 B) — but the working tree has since moved on elsewhere, so this only pins CHANGELOG, not the whole tree.
- Content-drift evidence (set B vs today's tree): sdist's `cli/main.py` (sha prefix `21332698…`) ≠ working tree (`d9634d67…`); sdist's `mcp/server.py` (`7a8193b5…`) ≠ working tree (`6da2bfde…`). Both sdist copies **already import the `progress` modules** (`mcp/server.py` imports `progress.events/reporter/state`) while the sdist contains **zero `progress/` or `recovery/` files** — set B froze an intermediate tree state (consumers wired, provider packages either absent or not yet included), consistent with a 21:27 build predating the `progress/` (22:16) and `recovery/` (Oct 5) package births.
- Bounding the A→B delta: the +5577 bytes / full-hash change between the 20:53 and 21:27 builds coincides with the POST-RC-014 extension-compat landing (commit `9f6ba34` at 21:18 sits between the two builds). Exact A-vs-B file listing is unrecoverable (artifact A not retained; manifest stores hash/size only, no file list), but the mechanism needs no per-file diff: two builds from two different tree states, one signature.

## 6. Wheel status — Agent 8's claim CONFIRMED

Wheel `63b455edd832f6666fb6cb517b45450487ec192ae83a402d9747b617dfb6b49f`, 581789 bytes: **matches the manifest, matches SHA256SUMS, all 329 entry timestamps clamped, RECORD intact.** The wheel's embedded `cli/main.py` and `mcp/server.py` are byte-identical to the sdist's copies (MATCH), so wheel↔sdist are mutually consistent snapshots. The intervening source edits simply did not change any wheel payload bytes (wheel excludes `docs/tests/reports/templates` per `pyproject.toml [tool.hatch]`, and its `src` payload happened to be hash-stable across the A→B window — deterministic timestamps did the rest), which is why only the sdist link broke and the wheel tests stay green. **The wheel is fine and must be preserved, not rebuilt gratuitously** — though the final fix rebuilds both together (see §7) so the pair ships from one invocation.

## 7. Fix Direction — the RECORDS must move, not the tests (rebuild + resign; do NOT execute yet)

Justification: the tests assert record↔bytes identity and contain no stale hardcoded values — "fixing" them would mean deleting the release-integrity guarantee. The `dist/` pair (set B) is internally consistent (wheel↔sdist payloads match; sdist CHANGELOG == tree) and is the newer build; the manifest/SHA256SUMS describe a superseded set A whose file no longer exists. The stale side is the recorded identity. Additionally `effective_artifact_verification.json` (22:01) already describes set B's size (737069) with `status PASS` on installability — a second witness that set B is the real, working artifact — yet it cannot substitute for the manifest signature.

Exact steps (for the release owner, **not executed** by this agent):

1. Freeze the source tree at the intended release commit; verify `git rev-parse HEAD` and a clean `git status` for the included paths.
2. Clean build outputs only: remove `dist/*.{whl,tar.gz}` (keep `dist/.gitignore`), `build/`, `*.egg-info/` if present.
3. Single final build from the frozen tree (e.g. `uv build`), optionally with `SOURCE_DATE_EPOCH` pinned and recorded; note hatchling already clamps to 2020-02-02 by default.
4. From the **final bytes**, recompute `sha256` + `size` for wheel and sdist; rewrite the `artifacts` section of `release/release-manifest.json` (also refresh `build_timestamp`, `git_revision` = final HEAD, `source_tree_digest`, `test_result`); regenerate `release/SHA256SUMS` (wheel, sdist, manifest lines); regenerate `effective_artifact_verification.json` against the final pair.
5. Re-run `python3 -m pytest tests/release/ -q` — all 44 must pass, including the 3 fixed-by-resigning identity tests — before tagging or publishing.

## 8. Verdict table

| Question | Answer |
|---|---|
| Which artifact does `136b46…`/731492 belong to? | The **20:53 sdist build (set A)** — recorded in manifest + SHA256SUMS, file itself **not retained**. |
| Which artifact does `0c5481…`/737069 belong to? | The **21:27 rebuilt sdist (set B)** — the file actually in `dist/` today. |
| Rebuild-after-signing or stale test expectation? | **Rebuild-after-signing (identity break: A tested/signed, B shipped).** Test expectations are not hardcoded; they read the stale records. |
| Timestamp flake / reproducibility bug? | **No.** All mtimes clamped (tar + gzip + zip all `2020-02-02`); drift is pure source-content change (+5577 B). |
| Wheel `63b455ed…`? | **Matches everywhere** (manifest, SHA256SUMS, dist). Healthy; keep. |
| Which side must move? | **The records: rebuild final pair from the frozen tree, then regenerate manifest + SHA256SUMS (+ effective verification).** Do not weaken the tests. |
