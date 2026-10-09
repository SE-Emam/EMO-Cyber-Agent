"""O5 runtime-parity: cli_matrix.py — drive the INSTALLED cyber-agent console script.

Covers --version/--help/doctor/status(unknown-id)/audit+review+verify+report on
a temp fixture dir (one TEST-ONLY fake secret; asserts redaction/presence-only),
human + JSON modes (stdout parses as JSON, stderr separation, exit codes 0/1/2).
No real secrets. Stdlib only, cross-platform (sys.executable-based).
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

TIMEOUT = 120
# TEST-ONLY canary: never a real secret; used to prove redaction/presence-only.
FAKE_SECRET = "TEST-ONLY-FAKE-SECRET-emo-parity-abc123-NOT-REAL"


def _cli_prefix() -> list[str]:
    exe = Path(sys.executable).parent / ("cyber-agent.exe" if os.name == "nt" else "cyber-agent")
    if exe.is_file():
        return [str(exe)]
    found = shutil.which("cyber-agent")
    if found:
        return [found]
    return [sys.executable, "-c", "from emo_cyber_agent.cli.main import app; app()"]


def _run(prefix: list[str], args: list[str], cwd: Path, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run([*prefix, *args], capture_output=True, text=True, timeout=TIMEOUT, cwd=str(cwd), env=env)


def main() -> int:
    ap = argparse.ArgumentParser(description="CLI matrix against the installed cyber-agent.")
    ap.add_argument("--origin", required=True, choices=("wheel", "sdist", "pypi"))
    ap.add_argument("--json-out", required=True)
    args = ap.parse_args()

    checks: list[dict] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": str(detail)[:600]})

    prefix = _cli_prefix()
    record("cli.resolvable", True, " ".join(prefix)[:200])
    work = Path(tempfile.mkdtemp(prefix="emo-cli-matrix-"))
    try:
        (work / "app.py").write_text("def hello():\n    return 'hi'\n", encoding="utf-8")
        (work / "leak.txt").write_text(f"token={FAKE_SECRET}\n", encoding="utf-8")

        p = _run(prefix, ["--version"], work)
        record("cli.version", p.returncode == 0 and p.stdout.strip() != "", f"exit={p.returncode} out={p.stdout.strip()[:120]}")

        p = _run(prefix, ["--help"], work)
        record("cli.help", p.returncode == 0 and "audit" in p.stdout.lower(), f"exit={p.returncode}")

        p = _run(prefix, ["doctor", "--format", "json"], work)
        try:
            body = json.loads(p.stdout)
            ok = p.returncode == 0 and isinstance(body.get("checks"), dict)
            leak = FAKE_SECRET in p.stdout or FAKE_SECRET in p.stderr
            record("cli.doctor.json", ok and not leak, f"exit={p.returncode} keys={len(body.get('checks', {})) if ok else 0}")
        except Exception as exc:
            record("cli.doctor.json", False, f"unparseable: {exc}")

        p = _run(prefix, ["doctor"], work)
        record("cli.doctor.human", p.returncode == 0 and "doctor" in p.stdout.lower(), f"exit={p.returncode}")

        p = _run(prefix, ["status", "unknown-audit-zzz", "--format", "json"], work)
        try:
            body = json.loads(p.stdout)
            record("cli.status.unknown_json", p.returncode == 1 and body.get("status") == "unknown-audit", f"exit={p.returncode}")
        except Exception as exc:
            record("cli.status.unknown_json", False, f"unparseable: {exc}")
        p2 = _run(prefix, ["status", "unknown-audit-zzz"], work)
        record("cli.status.unknown_human", p2.returncode == 1 and "unknown-audit" in p2.stdout, f"exit={p2.returncode}")

        p = _run(prefix, ["audit", ".", "--format", "json"], work)
        try:
            body = json.loads(p.stdout)
            ok = p.returncode == 0 and body.get("status") == "ok" and body["result"].get("target") == "."
            record("cli.audit.json", ok and FAKE_SECRET not in p.stdout, f"exit={p.returncode}")
        except Exception as exc:
            record("cli.audit.json", False, f"unparseable: {exc}")
        ph = _run(prefix, ["audit", ".", "--format", "human"], work)
        record("cli.audit.human", ph.returncode == 0 and "audit_id" in ph.stdout and FAKE_SECRET not in ph.stdout, f"exit={ph.returncode}")

        p = _run(prefix, ["review", "app.py", "--format", "json"], work)
        try:
            body = json.loads(p.stdout)
            record("cli.review.json", p.returncode == 0 and body.get("status") == "ok" and FAKE_SECRET not in p.stdout, f"exit={p.returncode}")
        except Exception as exc:
            record("cli.review.json", False, f"unparseable: {exc}")

        cand = {"audit_id": "PARITY-A", "hypothesis": "parity hypothesis", "evidence_ids": ["e1"]}
        cand_path = work / "cand.json"
        cand_path.write_text(json.dumps(cand), encoding="utf-8")
        p = _run(prefix, ["verify", "--candidate", str(cand_path), "--method", "static_confirmation",
                          "--kind", "file", "--locator", "app.py", "--rationale", "parity check",
                          "--audit-id", "PARITY-A", "--format", "json"], work)
        try:
            body = json.loads(p.stdout)
            record("cli.verify.json", p.returncode == 0 and body.get("result", {}).get("plan_id") not in (None, ""), f"exit={p.returncode}")
        except Exception as exc:
            record("cli.verify.json", False, f"unparseable: {exc}")

        findings = [{"finding_id": "f1", "audit_id": "PARITY-A", "title": "T", "description": "D",
                     "category": "authorization", "severity": "high", "confidence": 0.8,
                     "candidate_id": "c1", "evidence_ids": ["e1"], "fingerprint": "fp-f1",
                     "provenance": {"candidate": "c1"}}]
        findings_path = work / "findings.json"
        findings_path.write_text(json.dumps(findings), encoding="utf-8")
        p = _run(prefix, ["report", "--findings", str(findings_path), "--audit-id", "PARITY-A", "--format", "json"], work)
        try:
            json.loads(p.stdout)
            record("cli.report.json", p.returncode == 0, f"exit={p.returncode}")
        except Exception as exc:
            record("cli.report.json", False, f"unparseable: {exc}")

        # Exit-code meanings: 2 == invalid input (bad mode / bad format).
        p = _run(prefix, ["audit", ".", "--mode", "bogus-mode"], work)
        record("cli.exit2.bad_mode", p.returncode == 2, f"exit={p.returncode}")
        p = _run(prefix, ["audit", ".", "--format", "bogus"], work)
        record("cli.exit2.bad_format", p.returncode == 2, f"exit={p.returncode}")
        # stderr separation: JSON mode must print parseable stdout; stderr carries advisories only.
        p = _run(prefix, ["audit", ".", "--format", "json"], work)
        try:
            json.loads(p.stdout)
            record("cli.stderr.separation", FAKE_SECRET not in p.stderr, f"stderr_bytes={len(p.stderr)}")
        except Exception as exc:
            record("cli.stderr.separation", False, f"stdout unparseable: {exc}")
        # Presence-only: doctor must never echo a real-valued canary even if configured.
        p = _run(prefix, ["doctor", "--format", "json"], work, env_extra={"EMO_TEST_SECRET_CANARY": FAKE_SECRET})
        record("cli.redaction.canary", FAKE_SECRET not in (p.stdout + p.stderr), f"exit={p.returncode}")
    except subprocess.TimeoutExpired as exc:
        record("cli.no_hang", False, f"timeout: {exc}")
    except Exception as exc:
        record("cli.harness", False, f"{type(exc).__name__}: {exc}")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    ok = all(c["ok"] for c in checks) and bool(checks)
    result = {"script": "cli_matrix", "origin": args.origin, "ok": ok, "checks": checks,
              "summary": f"{sum(1 for c in checks if c['ok'])}/{len(checks)} checks passed"}
    Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json_out).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
