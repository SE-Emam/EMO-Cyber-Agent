# POST-T021 Android Discovery (A0) — 2026-10-08 (UTC)

## VERDICT: PASS

**GATE A0: PASS** — emulator reachable (serial `emulator-5554`), ABI identified (`arm64-v8a`), Android version identified (release `14`, SDK `34`) with verbatim evidence below. `sys.boot_completed=1` proves booted.

## 1. adb toolchain (§ adb)

SDK binaries NOT on default `PATH`; all commands run with explicit export (read-only, no installs, no image mods):

```
export PATH="/opt/homebrew/share/android-commandlinetools/platform-tools:/opt/homebrew/share/android-commandlinetools/emulator:$PATH"
```

Verbatim `adb version`:

```
Android Debug Bridge version 1.0.41
Version 37.0.1-15733141
Installed as /opt/homebrew/share/android-commandlinetools/platform-tools/adb
Running on Darwin 25.3.0 (arm64)
```

## 2. Device discovery (§ discovery)

Verbatim `adb devices -l`:

```
List of devices attached
emulator-5554          device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a transport_id:1
```

- Device count: **1**. Serial: **`emulator-5554`**, state `device` (not `offline`/`unauthorized`).
- Single-device; all subsequent shell commands used `adb -s emulator-5554` per multi-device rule.
- `emulator -list-avds` → `emo3b` (exactly one defined AVD; the running instance corresponds to it — see §4 AVD config).

## 3. Target properties (§ props)

Verbatim per-prop reads (`adb -s emulator-5554 shell getprop <key>`):

```
ro.build.version.release=14
ro.build.version.sdk=34
ro.product.cpu.abi=arm64-v8a
ro.product.cpu.abilist=arm64-v8a
ro.product.manufacturer=Google
ro.product.model=sdk_gphone64_arm64
ro.product.device=emu64a
sys.boot_completed=1
```

Corroborating verbatim dump (`adb -s emulator-5554 shell getprop | grep -E "build.version|product.cpu|product.manufacturer|product.model|product.device|boot_completed"`):

```
[ro.build.version.incremental]: [12077443]
[ro.build.version.release]: [14]
[ro.build.version.sdk]: [34]
[ro.build.version.security_patch]: [2023-09-05]
[ro.product.cpu.abi]: [arm64-v8a]
[ro.product.cpu.abilist]: [arm64-v8a]
[ro.product.cpu.abilist32]: []
[ro.product.cpu.abilist64]: [arm64-v8a]
[ro.product.device]: [emu64a]
[ro.product.manufacturer]: [Google]
[ro.product.model]: [sdk_gphone64_arm64]
[sys.boot_completed]: [1]
[sys.bootstat.first_boot_completed]: [1]
```

- `sys.boot_completed=[1]` → target is booted.
- No `-writable-system`, no root mods, no image changes performed.

## 4. Environment signals (§ environment — non-invasive, read-only)

- **Termux installed? YES.** Verbatim:
  - `adb -s emulator-5554 shell cmd package list packages | grep -i termux` → `package:com.termux`
  - `adb -s emulator-5554 shell pm path com.termux` → `package:/data/app/~~iFFPEIhj49WsFqYRajPJ9Q==/com.termux-zZz_8YwaslfjCjrlrM4Lug==/base.apk`
- **Python present? NO (target shell).** Verbatim:
  - `which python3; which python` → (empty, no output)
  - `python3 --version` → `/system/bin/sh: python3: inaccessible or not found`
  - No installs attempted or permitted.
- **Storage (`df -h /data`), verbatim:**
  ```
  Filesystem       Size Used Avail Use% Mounted on
  /dev/block/dm-39  10G 1.5G  8.0G  16% /data
  ```
  Full `df -h` head confirms `/` 789M (94%), `/data` 10G (16% used). No writes performed.
- **AVD name + target (host-side definition, read-only):**
  - `emulator -list-avds` → `emo3b`
  - `~/.android/avd/emo3b.ini`: `target=android-34`
  - `~/.android/avd/emo3b.avd/config.ini`: `abi.type=arm64-v8a`, `target=android-34`, `image.sysdir.1=system-images/android-34/google_apis/arm64-v8a/` — consistent with live props (SDK 34, `arm64-v8a`).

## 5. Host vs Target (§ host-vs-target)

Strictly separated; no macOS evidence presented as Android internals.

**Host (macOS, measured):**

```
ProductName:		macOS
ProductVersion:		26.3
BuildVersion:		25D125
uname -m:		arm64
```

**Test Target (Android emulator, measured via `adb -s emulator-5554`):**

```
serial:			emulator-5554 (device)
Android release:	14
SDK:			34
ABI:			arm64-v8a
abilist:		arm64-v8a
manufacturer/model/device: Google / sdk_gphone64_arm64 / emu64a
boot_completed:		1
Termux:			installed (com.termux)
Python3 (target):	not found
AVD:			emo3b (android-34)
```

## 6. Reproduction (§ reproduction)

Read-only steps; no boot, no `-writable-system`, no root mods, no installs, no image changes:

1. `export PATH="/opt/homebrew/share/android-commandlinetools/platform-tools:/opt/homebrew/share/android-commandlinetools/emulator:$PATH"`
2. `adb version` → 1.0.41 / 37.0.1-15733141.
3. `adb devices -l` → `emulator-5554 device ...` (single device).
4. `for p in ro.build.version.release ro.build.version.sdk ro.product.cpu.abi ro.product.cpu.abilist ro.product.manufacturer ro.product.model ro.product.device sys.boot_completed; do printf "%s=" "$p"; adb -s emulator-5554 shell getprop "$p"; done`
5. `adb -s emulator-5554 shell cmd package list packages | grep -i termux` → `package:com.termux`; `adb -s emulator-5554 shell pm path com.termux` → base.apk path.
6. `adb -s emulator-5554 shell "which python3; which python"` → empty; `adb -s emulator-5554 shell "python3 --version"` → not found.
7. `adb -s emulator-5554 shell df -h /data` → 10G / 16%.
8. `emulator -list-avds` → `emo3b`; `grep -E "target|abi|image.sysdir" ~/.android/avd/emo3b.avd/config.ini`; `sw_vers`; `uname -m`.

*GATE A0: PASS → emulator reachable: yes. serial: emulator-5554. ABI (live): arm64-v8a. Android version (live): 14 / SDK 34. Sanitized: no secrets present.*
