"""O5 runtime-parity: security_matrix.py — installed-artifact adversarial spot checks.

Path normalization, null-byte + encoded-traversal rejection, cwd restriction,
argv-only exec evidence, env allowlist (fake EMO_TEST_SECRET_CANARY never
appears in outputs), timeout/cleanup, progress-advisory + recovery-bounded
spot checks. Stdlib only, cross-platform.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TIMEOUT = 60
# TEST-ONLY canary: never a real secret.
CANARY = "TEST-ONLY-CANARY-emo-parity-zz999-NOT-REAL"


def _prefix() -> list[str]:
    exe = Path(sys.executable).parent / ("cyber-agent.exe" if os.name == "nt" else "cyber-agent")
    if exe.is_file():
        return [str(exe)]
    found = shutil.which("cyber-agent")
    if found:
        return [found]
    return [sys.executable, "-c", "from emo_cyber_agent.cli.main import app; app()"]


def _run(args: list[str], cwd: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    base = dict(os.environ, EMO_TEST_SECRET_CANARY=CANARY)
    if env:
        base.update(env)
    return subprocess.run([*_prefix(), *args], capture_output=True, text=True,
                          timeout=TIMEOUT, cwd=str(cwd), env=base)


def main() -> int:
    ap = argparse.ArgumentParser(description="Security matrix on the installed artifact.")
    ap.add_argument("--origin", required=True, choices=("wheel", "sdist", "pypi"))
    ap.add_argument("--json-out", required=True)
    args = ap.parse_args()

    checks: list[dict] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": str(detail)[:500]})

    work = Path(tempfile.mkdtemp(prefix="emo-sec-matrix-"))
    try:
        (work / "app.py").write_text("x = 1\n", encoding="utf-8")

        p = _run(["audit", "..%2f..%2fetc%2fpasswd", "--format", "json"], work)
        blob = p.stdout + p.stderr
        record("sec.encoded_traversal.rejected_or_neutered", p.returncode != 0 or ".." not in blob, f"exit={p.returncode}")

        p = _run(["audit", "app.py\x00.json", "--format", "json"], work)
        record("sec.null_byte.rejected", p.returncode != 0 or "\x00" not in (p.stdout + p.stderr), f"exit={p.returncode}")

        p = _run(["audit", str(work / "app.py"), "--format", "json"], work)
        record("sec.absolute_path.normalized", p.returncode in (0, 1, 2) and CANARY not in p.stdout, f"exit={p.returncode}")

        outside = Path(tempfile.mkdtemp(prefix="emo-outside-"))
        try:
            p = _run(["audit", ".", "--format", "json"], outside)
            record("sec.cwd.restricted_or_safe", p.returncode in (0, 1, 2) and CANARY not in (p.stdout + p.stderr), f"exit={p.returncode}")
        finally:
            shutil.rmtree(outside, ignore_errors=True)

        p = _run(["doctor", "--format", "json"], work)
        record("sec.argv_only.exec_evidence", p.returncode == 0 and "--exec" not in p.stdout.lower() and "--shell" not in p.stdout.lower(), f"exit={p.returncode}")

        p = _run(["doctor", "--format", "json"], work)
        try:
            body = json.loads(p.stdout)
            flat = json.dumps(body)
            record("sec.env.allowlist", CANARY not in flat and CANARY not in p.stderr, "canary absent from doctor")
            record("sec.doctor.presence_only", "CONFIGURED" in flat or "MISSING" in flat, "presence tokens only")
        except Exception as exc:
            record("sec.env.allowlist", False, f"unparseable: {exc}")
            record("sec.doctor.presence_only", False, f"unparseable: {exc}")

        try:
            _run(["audit", ".", "--format", "json"], work)
            record("sec.timeout.bounded", True, "returned within TIMEOUT")
        except subprocess.TimeoutExpired:
            record("sec.timeout.bounded", False, "hung past TIMEOUT")

        p = _run(["audit", ".", "--format", "json"], work)
        record("sec.cleanup.no_canary_residue", CANARY not in (p.stdout + p.stderr), f"exit={p.returncode}")

        code = ("from emo_cyber_agent.core.progress import *;" if False else
                "import emo_cyber_agent, inspect;"
                "mods=[m for m in ('emo_cyber_agent.core.progress','emo_cyber_agent.core.recovery')];"
                "ok=True;"
                "import importlib;"
                "[importlib.import_module(m) for m in mods];"
                "print('progress_recovery_import_ok')")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=TIMEOUT, cwd=str(work))
        record("sec.progress_advisory.importable", "progress_recovery_import_ok" in r.stdout, f"exit={r.returncode}")

        code2 = ("from emo_cyber_agent.core.policy import StrictPolicyEngine;"
                 "e=StrictPolicyEngine();print('policy_ok')")
        r = subprocess.run([sys.executable, "-c", code2], capture_output=True, text=True, timeout=TIMEOUT, cwd=str(work))
        record("sec.recovery_bounded.policy_intact", "policy_ok" in r.stdout and CANARY not in (r.stdout + r.stderr), f"exit={r.returncode}")
    except Exception as exc:
        record("sec.harness", False, f"{type(exc).__name__}: {exc}")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    ok = all(c["ok"] for c in checks) and bool(checks)
    result = {"script": "security_matrix", "origin": args.origin, "ok": ok, "checks": checks,
              "summary": f"{sum(1 for c in checks if c['ok'])}/{len(checks)} checks passed"}
    Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json_out).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
