# POST-T021 A2 — Published Package Verification (emo-cyber==0.2.0 on Termux)

Date (UTC): 2026-10-08
Agent: A2 — Package Installer Agent for EMO-Cyber-Agent
Device: live emulator-5554 (Termux Python 3.14.6 + pip 26.2.1, bridge per `reports/development/POST-T021-android-runtime.md`)
SDK: `/opt/homebrew/share/android-commandlinetools/platform-tools` (exported to PATH on host for all commands)

## VERDICT: BLOCKED — GATE A2 NOT SATISFIED

- `pip install emo-cyber==0.2.0` (official PyPI only): FAILED — transitive build dependency `rpds-py` cannot build on Termux/aarch64-android (see Step 1).
- Installed version 0.2.0: NO (`pip show emo-cyber` → "Package(s) not found").
- Import `emo_cyber_agent` / `__version__`: FAIL (`ModuleNotFoundError`).
- CLI `cyber-agent`: ABSENT (`command not found`).
- Classification: **dependency-build BLOCKED, NOT environment/network-blocked** — in-emulator network works (pip downloaded `maturin-1.15.0.tar.gz` from PyPI during the attempt). No source-tree substitution was used as package proof, per mission rules.

## Step 1 — `python3 -m pip install emo-cyber==0.2.0` (official PyPI only)

- Environment: Termux user shell via canonical bridge preamble (`export PREFIX=...; export HOME=...; export PATH=$PREFIX/bin:$PATH`), Python 3.14.6, pip 26.2.1.
- Command:
  ```
  adb -s emulator-5554 shell "run-as com.termux files/usr/bin/bash -c 'export PREFIX=/data/data/com.termux/files/usr; export HOME=/data/data/com.termux/files/home; export PATH=\$PREFIX/bin:\$PATH; time python3 -m pip install emo-cyber==0.2.0 2>&1 | tail -40'"
  ```
- Expected: clean install of `emo-cyber==0.2.0` from PyPI.
- Observed (verbatim output tail):
  ```
  error: subprocess-exited-with-error

  × installing build dependencies for rpds-py did not run successfully.
  │ exit code: 1
  ╰─> [31 lines of output]
      Collecting maturin<2.0,>=1.9
        Downloading maturin-1.15.0.tar.gz (385 kB)
        Installing build dependencies: started
        Installing build dependencies: finished with status 'done'
        Getting requirements to build wheel: started
        Getting requirements to build wheel: finished with status 'done'
        Installing backend dependencies: started
        Installing backend dependencies: finished with status 'done'
        Preparing metadata (pyproject.toml): started
        Preparing metadata (pyproject.toml): finished with status 'error'
        error: subprocess-exited-with-error

        × Preparing metadata (pyproject.toml) did not run successfully.
        │ exit code: 1
        ╰─> [6 lines of output]
            /data/data/com.termux/files/usr/tmp/pip-build-env-cwj4n6jk/overlay/lib/python3.14/site-packages/setuptools/_vendor/wheel/bdist_wheel.py:4: FutureWarning: The 'wheel' package is no longer the canonical location of the 'bdist_wheel' command, and will be removed in a future release. Please update to setuptools v70.1 or later which contains an integrated version of this command.
              warn(
            Python reports SOABI: cpython-314-aarch64-linux-android
            Computed rustc target triple: aarch64-unknown-linux-android
            Target triple not supported by rustup: aarch64-unknown-linux-android
            Rust not found, installing into a temporary directory
            [end of output]

        note: This error originates from a subprocess, and is likely not a problem with pip.
      error: metadata-generation-failed

      × Encountered error while generating package metadata.
      ╰─> maturin

      note: This is an issue with the package mentioned above, not pip.
      hint: See above for details.
      [end of output]

  note: This error originates from a subprocess, and is likely not a problem with pip.
  ERROR: Failed to build 'rpds-py' when installing build dependencies for rpds-py

  real	3m16.800s
  user	0m32.509s
  sys	0m16.596s
  ```
- Pass/Fail: **FAIL.**
- Evidence/notes:
  - Install time: **3m16.8s real** (mostly network fetch of build frontends + failed `maturin` bootstrap).
  - Root cause: `rpds-py` (Rust extension, transitive dep of the `emo-cyber==0.2.0` closure) builds via `maturin`, which cannot provision a Rust toolchain for `aarch64-unknown-linux-android` (`Target triple not supported by rustup`), and no system `rustc` exists in this Termux prefix. `maturin` metadata generation then errors out, aborting the whole `pip install` transaction (no partial `emo-cyber` install left behind — see Step 2).
  - Network inside the emulator is **available** (PyPI reachable; `maturin-1.15.0.tar.gz 385 kB` downloaded), so this is NOT an ANDROID ENVIRONMENT-BLOCKED wave.
  - Size impact: none retained — `/data` still `10G 2.1G 7.3G 23%` (unchanged vs A1 post-provisioning state); pip rolled back the failed transaction.
  - No source-tree install was substituted as package proof (mission rule); source-tree remains a separate dev-only path, unverified here.

## Step 2 — Version / import / show verification

- Environment: same bridge.
- Commands:
  ```
  python3 -m pip show emo-cyber 2>&1
  python3 -c "import emo_cyber_agent; print(emo_cyber_agent.__version__)" 2>&1
  ```
- Expected: version 0.2.0 shown; import prints `0.2.0`.
- Observed (verbatim):
  ```
  ===PIPSHOW===
  WARNING: Package(s) not found: emo-cyber
  ===IMPORT===
  Traceback (most recent call last):
    File "<string>", line 1, in <module>
      import emo_cyber_agent; print(emo_cyber_agent.__version__)
      ^^^^^^^^^^^^^^^^^^^^^^
  ModuleNotFoundError: No module named 'emo_cyber_agent'
  ```
- Pass/Fail: **FAIL** (both).

## Step 3 — CLI availability

- Environment: same bridge (Termux bin dir on PATH via preamble).
- Commands: `which cyber-agent 2>&1; cyber-agent --version 2>&1`
- Expected: path + `0.2.0`-style version output.
- Observed (verbatim): `cyber-agent: command not found`
- Pass/Fail: **FAIL** — CLI absent (consistent with install failure; no entry point installed).

## Step 4 — Installed resource presence (brief; full audit is A3+ scope)

- Command: `python3 -m pip list 2>/dev/null | grep -i -e emo -e rpds -e maturin -e jsonschema`
- Observed: **no output** — no `emo*`, `rpds*`, `maturin`, or `jsonschema` packages present. Nothing to audit; deferred to A3+ after install succeeds.
- Pass/Fail: **N/A (blocked upstream).**

## Gate decision

**GATE A2: BLOCKED.** Installed package + version==0.2.0 + import PASS not demonstrated. Exact reason: `python3 -m pip install emo-cyber==0.2.0` from official PyPI fails inside Termux (Python 3.14.6 / pip 26.2.1 / aarch64-android) because the transitive dependency `rpds-py` requires building via `maturin`, which cannot obtain a Rust toolchain for `aarch64-unknown-linux-android`. Suggested follow-ups (out of A2 scope): publish a prebuilt `rpds-py` wheel for `cp314-android/aarch64`, relax/pin the dependency chain to avoid the Rust extension on Android, or document an officially supported Termux install path (e.g. Termux `pkg install rust` + retry — untested here).

## A2-Retest (R1–R3)

Date (UTC): 2026-10-08
Agent: A2-R — Rust Toolchain Agent
Device: live emulator-5554 (same Termux bridge preamble per `reports/development/POST-T021-android-runtime.md`)
SDK: `/opt/homebrew/share/android-commandlinetools/platform-tools` (exported to PATH on host)

Retest reason: prior A2 attempt preceded toolchain completion (no system rustc existed when maturin ran).

R1 — READ-ONLY discovery (verbatim, pre-install):
- `rustc --version` → `The program rustc is not installed. Install it by executing: pkg install rust`
- `cargo --version` → `The program cargo is not installed. Install it by executing: pkg install rust`
- `rustup --version` → `No command rustup found` (exit 127)
- `rustc -vV` → same `pkg install rust` notice (exit 127)
- `rustup target list` → `No command rustup found` (exit 127)
- Note: maturin's computed triple `aarch64-unknown-linux-android` was NOT assumed correct; verified against toolchain below.

R2 — Install via Termux official package path only (`pkg update` then `pkg install -y rust`, official Termux repo mirror `mirrors.sdu.edu.cn` auto-selected; 133 MB: `rust 1.99.0` + `rust-std-aarch64-linux-android 1.99.0` + `libandroid-execinfo`). Post-install verbatim:
- `rustc --version` → `rustc 1.99.0 (b940084d7 2026-09-28) (built from a source tarball)`
- `cargo --version` → `cargo 1.99.0 (5f94df478 2026-08-27) (built from a source tarball)`
- `rustc -vV` → `rustc 1.99.0 ... / binary: rustc / commit-hash: b940084d7... / commit-date: 2026-09-28 / host: aarch64-linux-android / release: 1.99.0 / LLVM version: 21.1.8`
- `rustup` still absent (Termux ships no rustup; N/A by design).
- Target state: `rustc --print target-list | grep android` → `aarch64-linux-android, arm-linux-androideabi, armv7-linux-androideabi, i686-linux-android, riscv64-linux-android, thumbv7neon-linux-androideabi, x86_64-linux-android`; installed std in `$PREFIX/lib/rustlib/`: `aarch64-linux-android` present (plus armv7, i686, x86_64). Correct ARM64 Android target is `aarch64-linux-android` (no `unknown` infix) — maturin's `aarch64-unknown-linux-android` does not match any rustc-known target.

R3 — Native Rust build proof (tiny test, NOT the EMO project; `$HOME/rust-hello/hello.rs` = `fn main(){println!("hello-android-arm64")}`):
- `rustc $HOME/rust-hello/hello.rs -o $HOME/rust-hello/hello && $HOME/rust-hello/hello` → output `hello-android-arm64`, exit 0. Native rustc → Android ARM64 build → execute: PASS end-to-end through the adb bridge.

Interim classification: **A2-RUST = PASS** (toolchain sound; native build+run proven). STOP per sequence — maturin/pip reinstall (A2-R4/R5) is a later order, not attempted here.

## A2-Retest R4 — Maturin Target Investigation

Date (UTC): 2026-10-08/09
Agent: A2-R45 — Maturin/Package-Retest Agent
Device: live emulator-5554 (same Termux bridge preamble)
SDK: `/opt/homebrew/share/android-commandlinetools/platform-tools` (exported to PATH on host)

R4-0 READ-FIRST (verbatim, pre-install):
- `maturin --version` → `No command maturin found` (not installed; prior run only had it in an ephemeral pip-build-env overlay)
- `python3 -m maturin --version` → `No module named maturin`
- `rustc -vV` → `rustc 1.99.0 ... host: aarch64-linux-android ... LLVM version: 21.1.8` (unchanged from R2)
- `rustc --print target-list | grep android` → `aarch64-linux-android, arm-linux-androideabi, armv7-linux-androideabi, i686-linux-android, riscv64-linux-android, thumbv7neon-linux-androideabi, x86_64-linux-android` (no `unknown`-infix target exists)
- `python3 --version` → `Python 3.14.6`; `pip --version` → `pip 26.2.1`
- maturin install (official PyPI only, per mission): `python3 -m pip install maturin` picked **maturin-1.15.0.tar.gz (385 kB)** — NO prebuilt wheel for cp314-android/aarch64 (PyPI has none for Android), so pip compiled maturin from sdist natively via `cargo build --manifest-path Cargo.toml ... --release` (no `--target` flag; plain native build). Result: `Successfully installed maturin-1.15.0`; `maturin --version` → `maturin 1.15.0`, `python3 -m maturin --version` → `maturin 1.15.0`. (One stale duplicate build from a timed-out host pipe was killed by exact PID; survivor built clean.)
- Host-side PyPI check (supporting): rpds-py latest `2026.9.1` ships 128 files incl. cp314 wheels for macOS/manylinux/musllinux/Windows but **zero `android` tags** → Termux MUST build rpds-py from sdist (`rpds_py-2026.9.1.tar.gz`).

R4-1 Minimal dependency build (CLEAN dir `$HOME/r4-tmp`, `cd` there first, FULLY NATURAL `python3 -m pip install rpds-py` — no --no-build-isolation, no --only-binary, no substitution):
- pip picked **rpds_py-2026.9.1.tar.gz (63 kB)** (sdist; cached), build isolation fetched `maturin<2.0,>=1.9`, metadata + wheel build both `finished with status 'done'`.
- Verbatim tail:
  ```
  Created wheel for rpds-py: filename=rpds_py-2026.9.1-cp314-cp314-android_24_arm64_v8a.whl size=394719 sha256=36e4ed75d4e62b594c920faa9d251c6e32bcfa1cc200e2cbf63e6c4cee9aeaed
  Successfully built rpds-py
  Installing collected packages: rpds-py
  Successfully installed rpds-py-2026.9.1
  real 1m12.162s / user 1m23.965s / sys 0m26.820s
  ```
- Import proof: `python3 -c "import rpds; ..."` → `rpds ok`; `pip show rpds-py` → `Version: 2026.9.1`.
- Target evidence: wheel tag `cp314-cp314-android_24_arm64_v8a` proves maturin mapped the target correctly once a system rustc existed. The prior `aarch64-unknown-linux-android` string was generated **by maturin itself** (its rustup-bootstrap path: `Computed rustc target triple: aarch64-unknown-linux-android` → `Target triple not supported by rustup` → `Rust not found, installing into a temporary directory`), ONLY because no system rustc existed then — NOT by pip, NOT by package metadata, NOT by env. With rustc 1.99.0 (host `aarch64-linux-android`) present, maturin used it directly and the bad triple never appeared.

R4 verdict: **R4 = PASS** — rpds-py builds/installs/imports on Android ARM64. No PACKAGING COMPATIBILITY ISSUE to record (toolchain was the sole cause; dependency + backend are sound). No EMO edits made.

## A2-Retest R5 — Clean Published Artifact Install

R5-0 `cd $HOME/r4-tmp && python3 -m pip install emo-cyber==0.2.0` (FULLY NATURAL flags; rpds-py 2026.9.1 already installed from R4 retained as evidence, not destroyed):
- Resolved: `emo_cyber-0.2.0-py3-none-any.whl (754 kB)`, `jsonschema-4.26.0`, `pydantic-2.14.0`, `pydantic-core` (sdist → built on-device), `pyyaml` (sdist → built on-device), plus pure-Python deps (rich, typer, pydantic-settings, referencing, etc.).
- Verbatim tail:
  ```
  Created wheel for pydantic-core: filename=pydantic_core-2.50.0-cp314-cp314-android_24_arm64_v8a.whl size=2096518 sha256=98e699d6d89ee760403569649939337aced4745820b91e4297715fef50c8f69a
  Created wheel for pyyaml: filename=pyyaml-6.0.3-cp314-cp314-android_24_arm64_v8a.whl size=45469 sha256=965095a1efbe5db073a5986784977eddd688d1c99f58a0f5855e9231ae76ca10
  Successfully built pydantic-core pyyaml
  Successfully installed annotated-doc-0.0.5 annotated-types-0.8.0 attrs-26.1.0 emo-cyber-0.2.0 jsonschema-4.26.0 jsonschema-specifications-2025.9.1 markdown-it-py-4.2.0 mdurl-0.1.2 pydantic-2.14.0 pydantic-core-2.50.0 pydantic-settings-2.15.0 pygments-2.21.0 python-dotenv-1.2.4 pyyaml-6.0.3 referencing-0.37.0 rich-14.3.4 shellingham-1.5.4 typer-0.27.3 typing-extensions-4.16.0 typing-inspection-0.4.4
  real 14m16.083s / user 15m48.100s / sys 2m37.248s
  ```
- Chain: emo-cyber 0.2.0 → jsonschema 4.26.0 → rpds-py 2026.9.1 (R4) + maturin 1.15.0 / Rust 1.99.0.

R5-1 verification (verbatim):
- `pip show emo-cyber` → `Name: emo-cyber / Version: 0.2.0`
- `python3 -c "import emo_cyber_agent; print(emo_cyber_agent.__version__)"` → `0.2.0`
- `which cyber-agent` → `/data/data/com.termux/files/usr/bin/cyber-agent`; `cyber-agent --version` → `emo-cyber 0.2.0`
- R5 = **PASS**. No CASE1–CASE4 classification needed. No src/ edits, no sideloads, no system-image mods, no v0.2.0 changes.

## Final Classification

**PASS** (GATE A2 SATISFIED — published `emo-cyber==0.2.0` installs from official PyPI and runs on Termux/Android ARM64)
- Rust readiness: PASS (rustc 1.99.0, host aarch64-linux-android, native hello + on-device Rust extension builds)
- Maturin readiness: PASS (maturin 1.15.0 built from official PyPI sdist, native cargo build, no --target flag needed)
- Dependency build: PASS (rpds-py 2026.9.1 → cp314-android_24_arm64_v8a wheel, imports OK; pydantic-core 2.50.0 + pyyaml 6.0.3 also built on-device)
- Published artifact install: PASS (emo-cyber==0.2.0, natural flags, 14m16s, 20 packages)
- Import: PASS (`emo_cyber_agent.__version__` == 0.2.0)
- CLI: PASS (`cyber-agent --version` == emo-cyber 0.2.0)
- Root-cause note: prior BLOCKED verdict was a missing-toolchain failure, not a packaging defect — maturin's `aarch64-unknown-linux-android` triple came from its own rustup-bootstrap fallback when no system rustc existed. A3/A4/A5/A7 NOT started per orders.
