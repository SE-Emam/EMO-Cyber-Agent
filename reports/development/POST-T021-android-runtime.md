# POST-T021 A1 — Android Runtime Provisioning (Termux Python)

Date (UTC): 2026-10-08
Agent: A1 — Android Runtime Provisioning Agent for EMO-Cyber-Agent
Device: live emulator serial `emulator-5554` (verified `device`, `sdk_gphone64_arm64`)
SDK: `/opt/homebrew/share/android-commandlinetools/platform-tools` (exported to PATH for all commands)
Baseline (A0, `reports/development/POST-T021-android-discovery.md`): Android 14 / SDK 34 / arm64-v8a, Termux INSTALLED (`com.termux`), Python NOT FOUND, /data 8G free. Confirmed again this session.

## VERDICT: PASS — GATE A1 SATISFIED

- Python runtime available (>= 3.11): YES — **Python 3.14.6**
- pip/installation path available: YES — **pip 26.2.1** (Termux official repo package `python-pip 26.2.1` + `python-ensurepip-wheels`)
- Shell invocation possible end-to-end from host: YES — proven below
- No project source edits, no system-image hacks, no `-writable-system`, no root mods, no sideloaded APKs. All installs from Termux's own configured official repo.

## Method per attempt (verbatim commands/outputs)

### 0. Device verification + A0 reconfirmation

Command:

```
export PATH=/opt/homebrew/share/android-commandlinetools/platform-tools:$PATH; adb devices -l; adb -s emulator-5554 shell getprop ro.build.version.sdk; adb -s emulator-5554 shell "getprop ro.build.version.release; getprop ro.product.cpu.abi; df -h /data | tail -2; pm list packages | grep -i termux; which python3; python3 --version 2>&1"
```

Output (verbatim, abridged):

```
List of devices attached
emulator-5554          device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a transport_id:1
34
14
arm64-v8a
Filesystem       Size Used Avail Use% Mounted on
/dev/block/dm-39  10G 1.5G  8.0G  16% /data/user/0
package:com.termux
/system/bin/sh: python3: inaccessible or not found
```

### 1. `run-as com.termux` — WORKS (contrary to the expected-fail hypothesis)

Command:

```
adb -s emulator-5554 shell "run-as com.termux id 2>&1"
```

Output (verbatim):

```
uid=10194(u0_a194) gid=10194(u0_a194) groups=10194(u0_a194),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid),3012(readtracefs),50194(all_a194) context=u:r:runas_app:s0:c194,c256,c512,c768
```

Note: `run-as` only lists the top-level app dir with bare relative args (absolute `/data/data/...` paths return `Permission denied` through the `run-as` frontend itself). All subsequent commands therefore use **relative** paths for `run-as` builtins, e.g. `run-as com.termux ls files/usr` — which correctly revealed the Termux bootstrap (`bin etc include lib libexec share tmp var`). No `am start`/Tasker/BOOT path was needed.

### 2. Direct adb→Termux shell bridge — ESTABLISHED via `run-as` + Termux's own `bash`

Command:

```
adb -s emulator-5554 shell "run-as com.termux files/usr/bin/bash -c 'echo hello; id'"
```

Output (verbatim):

```
hello
uid=10194(u0_a194) gid=10194(u0_a194) groups=...,50194(all_a194) context=u:r:runas_app:s0:c194,c256,c512,c768
```

Two quoting pitfalls documented for reproducibility:
- (a) The whole remote script must be wrapped so the device shell (not `adb`) parses `;`: outer `"..."` for `adb shell` + inner `'...'` for `bash -c`. A bare `adb shell run-as ... -c 'echo hello; id'` splits at `;` and the tail runs as `shell` (uid 2000).
- (b) `export PREFIX=... PATH=$PREFIX/bin:$PATH` in a single statement expands `$PREFIX` to the OLD (empty) value, yielding `PATH=/bin:...` and `pkg`/`apt`/`dpkg` unresolvable. Fix: separate statements — `export PREFIX=...; export PATH=$PREFIX/bin:$PATH`.

Canonical bridge preamble (used for every command below):

```
adb -s emulator-5554 shell "run-as com.termux files/usr/bin/bash -c 'export PREFIX=/data/data/com.termux/files/usr; export HOME=/data/data/com.termux/files/home; export PATH=\$PREFIX/bin:\$PATH; <command>'"
```

Post-fix resolution proof:

```
PATH=/data/data/com.termux/files/usr/bin:/product/bin:/apex/com.android.runtime/bin:...
/data/data/com.termux/files/usr/bin/pkg
/data/data/com.termux/files/usr/bin/apt
/data/data/com.termux/files/usr/bin/dpkg
```

### 3. Pre-install state: bootstrap present, Python absent (official repo reachable)

Command (bridge preamble + `python3 --version 2>&1; apt update 2>&1 | tail`):

Output (verbatim):

```
The program python3 is not installed. Install it by executing:
 pkg install python
...
Get:1 https://mirrors.nguyenhoang.cloud/termux/termux-main stable InRelease [14.0 kB]
Get:2 https://mirrors.nguyenhoang.cloud/termux/termux-main stable/main aarch64 Packages [585 kB]
Fetched 599 kB in 6s (102 kB/s)
...
77 packages can be upgraded. Run 'apt list --upgradable' to see them.
```

Sources (`$PREFIX/etc/apt/sources.list`, unmodified, official): `deb https://mirrors.nguyenhoang.cloud/termux/termux-main stable main`. No third-party repos added, no APKs sideloaded.

### 4. Provisioning — preferred path: Termux official repos only

Command (bridge preamble + `pkg install -y python`):

Output (verbatim tail):

```
Selecting previously unselected package python-pip.
Preparing to unpack .../18-python-pip_26.2.1_all.deb ...
Unpacking python-pip (26.2.1) ...
Setting up gdbm (1.26-1) ...
Setting up ndk-sysroot (30) ...
Setting up libandroid-posix-semaphore (0.1-4) ...
Setting up libsqlite (3.53.4) ...
Setting up libffi (3.8.0) ...
Setting up libcrypt (0.2-6) ...
Setting up ncurses-ui-libs (6.6.20260307+really6.5.20250830) ...
Setting up make (4.4.1-1) ...
Setting up libcompiler-rt (21.1.8-3) ...
Setting up python (3.14.6-1) ...
Setting up libxml2 (2.15.4-1) ...
Setting up python-ensurepip-wheels (3.14.6-1) ...
Setting up python-pip (26.2.1) ...
pip setup...
Writing to /data/data/com.termux/files/usr/etc/pip.conf
Setting up libllvm (21.1.8-3) ...
Setting up glib (2.90.1) ...
No schema files found: doing nothing.
Setting up lld (21.1.8-3) ...
Setting up pkg-config (0.29.2-3) ...
Setting up llvm (21.1.8-3) ...
Setting up clang (21.1.8-3) ...
```

Fallbacks (b)/(c) were NOT needed: no device-python hunt, no NOT-possible verdict.

## Versions (verbatim end-to-end proof from host)

Command:

```
adb -s emulator-5554 shell "run-as com.termux files/usr/bin/bash -c 'export PREFIX=/data/data/com.termux/files/usr; export HOME=/data/data/com.termux/files/home; export PATH=\$PREFIX/bin:\$PATH; python3 --version; pip --version; python3 -m pip --version; python3 -c \"print(\\\"hello-from-termux-python\\\")\"'"
```

Output (verbatim):

```
Python 3.14.6
pip 26.2.1 from /data/data/com.termux/files/usr/lib/python3.14/site-packages/pip (python 3.14)
pip 26.2.1 from /data/data/com.termux/files/usr/lib/python3.14/site-packages/pip (python 3.14)
hello-from-termux-python
```

- `python3 --version` → **Python 3.14.6** (>= 3.11 ✓)
- `pip --version` / `python3 -m pip --version` → **pip 26.2.1** ✓
- Shell invocation path proven end-to-end from host: `adb -s emulator-5554 shell "run-as com.termux files/usr/bin/bash -c '... python3 -c ...'"` → `hello-from-termux-python` ✓

## Storage impact

- Before: `/dev/block/dm-39  10G  1.5G  8.0G  16% /data/user/0`
- After: `/dev/block/dm-39  10G  2.1G  7.3G  23% /data/user/0`
- Delta: **~0.6 GB** (`pkg install python` pulled python 3.14.6 + pip + build deps incl. clang/llvm toolchain). /data still has **7.3G free** — no pressure.

## Gate decision

**GATE A1: PASS.** Python >= 3.11 + pip/install path + host-driven shell invocation all demonstrated with verbatim evidence above. Environment is NOT blocked.

## Next step for A2

Reuse the canonical bridge preamble to run the A2 workload as the normal Termux user (uid u0_a194, no root):

```
adb -s emulator-5554 shell "run-as com.termux files/usr/bin/bash -c 'export PREFIX=/data/data/com.termux/files/usr; export HOME=/data/data/com.termux/files/home; export PATH=\$PREFIX/bin:\$PATH; python3 --version && python3 -m pip --version && <A2-command>'"
```

Caveats for A2: (1) keep the two-step `export` order (pitfall 2b); (2) wrap remote scripts in outer `"..."` + inner `'...'` (pitfall 2a); (3) prefer `python3 -m pip install` (pip.conf was auto-written by the package setup); (4) ~7.3G free on /data, heavyweight installs (torch etc.) should be weighed against the ~0.6G python baseline.
