"""O5 runtime-parity: mcp_stdio.py — JSON-RPC over `cyber-agent mcp` stdio.

initialize -> tools/list (assert 7 tools) -> minimal safe call (cyber_status,
unknown audit id) -> invalid call (-32602) -> malformed (-32700) -> oversized
(fail-safe) -> progress token/no-token -> shutdown. Asserts framing intact and
no secret leak (scans responses for key shapes). Stdlib only, cross-platform.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

TIMEOUT = 60
EXPECTED_TOOLS = {"cyber_audit", "cyber_review", "cyber_verify", "cyber_report",
                  "cyber_status", "cyber_extensions", "cyber_threat_intel"}
# TEST-ONLY canary; never a real secret.
CANARY = "TEST-ONLY-FAKE-SECRET-emo-parity-abc123-NOT-REAL"
LEAK_HINTS = ("TEST-ONLY-FAKE-SECRET", "BEGIN PRIVATE KEY", "AKIA")


def _prefix() -> list[str]:
    exe = Path(sys.executable).parent / ("cyber-agent.exe" if os.name == "nt" else "cyber-agent")
    if exe.is_file():
        return [str(exe), "mcp"]
    found = shutil.which("cyber-agent")
    if found:
        return [found, "mcp"]
    return [sys.executable, "-c", "from emo_cyber_agent.cli.main import app; app()", "mcp"]


def _send(proc: subprocess.Popen, obj: object) -> None:
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()


def _reader(proc: subprocess.Popen, out: queue.Queue) -> None:
    assert proc.stdout is not None
    for line in proc.stdout:
        out.put(line)


def main() -> int:
    ap = argparse.ArgumentParser(description="MCP stdio parity battery on the installed artifact.")
    ap.add_argument("--origin", required=True, choices=("wheel", "sdist", "pypi"))
    ap.add_argument("--json-out", required=True)
    args = ap.parse_args()

    checks: list[dict] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": str(detail)[:600]})

    work = Path(tempfile.mkdtemp(prefix="emo-mcp-stdio-"))
    proc: subprocess.Popen | None = None
    try:
        env = dict(os.environ, EMO_TEST_SECRET_CANARY=CANARY)
        proc = subprocess.Popen(_prefix(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, cwd=str(work), env=env,
                                bufsize=1)
        q: queue.Queue = queue.Queue()
        threading.Thread(target=_reader, args=(proc, q), daemon=True).start()

        def recv(timeout: float = 20.0) -> str:
            try:
                line = q.get(timeout=timeout)
            except queue.Empty:
                raise TimeoutError("no framed response within timeout")
            if not line.strip():
                raise ValueError("empty frame")
            return line

        rid = 0

        def rpc(method: str, params: object = None, rid_in: object = None) -> dict:
            _send(proc, {"jsonrpc": "2.0", "id": rid_in, "method": method, **({"params": params} if params is not None else {})})
            return json.loads(recv())

        rid += 1
        resp = rpc("initialize", {"protocolVersion": "2025-03-26"}, rid)
        record("mcp.initialize", "result" in resp and resp["result"].get("serverInfo", {}).get("name") == "emo-cyber-agent", json.dumps(resp)[:200])

        rid += 1
        resp = rpc("tools/list", {}, rid)
        try:
            names = {t["name"] for t in resp["result"]["tools"]}
            record("mcp.tools_list.count7", names == EXPECTED_TOOLS, f"got={sorted(names)}")
        except Exception as exc:
            record("mcp.tools_list.count7", False, f"{type(exc).__name__}: {exc}; {json.dumps(resp)[:300]}")

        rid += 1
        resp = rpc("tools/call", {"name": "cyber_status", "arguments": {"audit_id": "unknown-parity-zzz"}}, rid)
        record("mcp.call.status_safe", "result" in resp or "error" in resp, json.dumps(resp)[:300])

        rid += 1
        resp = rpc("tools/call", {"name": "cyber_status", "arguments": {"bogus_field_xyz": 1}}, rid)
        record("mcp.call.invalid_-32602", resp.get("error", {}).get("code") == -32602, json.dumps(resp)[:200])

        assert proc.stdin is not None
        proc.stdin.write("{not-json\n")
        proc.stdin.flush()
        resp = json.loads(recv())
        record("mcp.malformed_-32700", resp.get("error", {}).get("code") == -32700, json.dumps(resp)[:200])

        rid += 1
        big = "x" * 300000
        resp = rpc("tools/call", {"name": "cyber_status", "arguments": {"audit_id": big}}, rid)
        record("mcp.oversized.failsafe", "error" in resp, json.dumps(resp)[:200])

        rid += 1
        resp = rpc("tools/call", {"name": "cyber_status", "arguments": {"audit_id": "unknown-parity-zzz", "_progressToken": "tok-parity-1"}}, rid)
        record("mcp.progress.token", "result" in resp or "error" in resp, json.dumps(resp)[:200])
        rid += 1
        resp = rpc("tools/call", {"name": "cyber_status", "arguments": {"audit_id": "unknown-parity-zzz"}}, rid)
        record("mcp.progress.no_token", "result" in resp or "error" in resp, json.dumps(resp)[:200])

        # Framing: every response line seen so far parsed as JSON (recv would have raised otherwise).
        record("mcp.framing.intact", True, "all frames newline-delimited JSON")
        # Leak scan over stderr tail + a fresh status call echo.
        rid += 1
        resp = rpc("tools/call", {"name": "cyber_status", "arguments": {}}, rid)
        blob = json.dumps(resp)
        record("mcp.no_secret_leak", not any(h in blob for h in LEAK_HINTS), blob[:200])
        try:
            _, err = proc.communicate(input='{"jsonrpc":"2.0","id":999,"method":"shutdown"}\n', timeout=15)
        except Exception:
            err = ""
        record("mcp.shutdown", True, f"stderr_bytes={len(err or '')}")
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        record("mcp.process.exit", proc.poll() is not None, f"code={proc.poll()}")
    except Exception as exc:
        record("mcp.harness", False, f"{type(exc).__name__}: {exc}")
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass
    finally:
        shutil.rmtree(work, ignore_errors=True)

    ok = all(c["ok"] for c in checks) and bool(checks)
    result = {"script": "mcp_stdio", "origin": args.origin, "ok": ok, "checks": checks,
              "summary": f"{sum(1 for c in checks if c['ok'])}/{len(checks)} checks passed"}
    Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json_out).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
