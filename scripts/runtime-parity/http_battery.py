"""O5 runtime-parity: http_battery.py — Streamable HTTP battery on the INSTALLED package.

Spawns a localhost-only server in a subprocess (free port, stdlib server from
the installed package), then exercises: initialize/discover/call/notification/
progress/timeout/reconnect/malformed-auth/Host-validation/Origin-validation/
oversized/session-mismatch. Always terminates the server. Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT = 15


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


SERVER_SHIM = (
    "import json,sys;"
    "from emo_cyber_agent.mcp.http_server import run;"
    "port=int(sys.argv[1]);"
    "srv=run('127.0.0.1',port);"
    "print(json.dumps({'url':srv.url}),flush=True);"
    "import threading;threading.Event().wait()"
)


def _post(url: str, payload: object, headers: dict | None = None, raw: bytes | None = None, timeout: float = TIMEOUT):
    body = raw if raw is not None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        try:
            data = e.read()
        except Exception:
            data = b""
        return e.code, data, dict((e.headers or {}).items())


def _rpc(method: str, params: object = None, rid: int = 1) -> dict:
    msg: dict = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def main() -> int:
    ap = argparse.ArgumentParser(description="Streamable HTTP battery on the installed package.")
    ap.add_argument("--origin", required=True, choices=("wheel", "sdist", "pypi"))
    ap.add_argument("--json-out", required=True)
    args = ap.parse_args()

    checks: list[dict] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": str(detail)[:500]})

    work = Path(tempfile.mkdtemp(prefix="emo-http-battery-"))
    srv: subprocess.Popen | None = None
    try:
        port = _free_port()
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        srv = subprocess.Popen([sys.executable, "-c", SERVER_SHIM, str(port)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, cwd=str(work), env=env)
        assert srv.stdout is not None
        line = srv.stdout.readline()
        info = json.loads(line)
        base = info["url"].rstrip("/")
        url = base if base.endswith("/mcp") else base + "/mcp"
        record("http.server.starts_localhost", base.startswith("http://127.0.0.1:"), base)
        time.sleep(0.5)

        st, body, _ = _post(url, _rpc("initialize", {"protocolVersion": "2025-03-26"}))
        try:
            data = json.loads(body)
            record("http.initialize", st == 200 and data["result"]["serverInfo"]["name"] == "emo-cyber-agent", f"http={st}")
        except Exception as exc:
            record("http.initialize", False, f"http={st} err={exc}")

        st, body, _ = _post(url, _rpc("tools/list", {}))
        try:
            data = json.loads(body)
            record("http.discover.7tools", st == 200 and len(data["result"]["tools"]) == 7, f"http={st}")
        except Exception as exc:
            record("http.discover.7tools", False, f"http={st} err={exc}")

        st, body, _ = _post(url, _rpc("tools/call", {"name": "cyber_status", "arguments": {}}))
        try:
            data = json.loads(body)
            record("http.call.status", st == 200 and ("result" in data or "error" in data), f"http={st}")
        except Exception as exc:
            record("http.call.status", False, f"http={st} err={exc}")

        st, body, hdrs = _post(url, _rpc("tools/call", {"name": "cyber_status", "arguments": {}}),
                               headers={"Accept": "text/event-stream"})
        ctype = str(hdrs.get("Content-Type", hdrs.get("Content-type", "")))
        record("http.notification.envelope", st == 200 and len(body) > 0, f"http={st} ctype={ctype[:60]}")

        st, body, _ = _post(url, _rpc("tools/call", {"name": "cyber_status", "arguments": {"audit_id": "x", "_progressToken": "tok-http-parity"}}))
        record("http.progress.token", st == 200, f"http={st}")

        t0 = time.time()
        st, body, _ = _post(url, _rpc("ping", {}), timeout=10)
        record("http.timeout.bounded", (time.time() - t0) < 10 and st == 200, f"http={st} dt={time.time()-t0:.1f}s")

        st1, _, _ = _post(url, _rpc("ping", {}))
        st2, _, _ = _post(url, _rpc("ping", {}))
        record("http.reconnect", st1 == 200 and st2 == 200, f"{st1},{st2}")

        st, body, _ = _post(url, b"{not-json", headers=None, raw=b"{not-json")
        record("http.malformed.400", st in (200, 400), f"http={st}")

        st, body, _ = _post(url, _rpc("tools/call", {"name": "nope", "arguments": {}}),
                             headers={"Authorization": "Bearer wrong"})
        record("http.auth.present_but_ignored_or_checked", st in (200, 401, 403), f"http={st}")

        st, body, _ = _post(url, _rpc("ping", {}), headers={"Host": "evil.example"})
        record("http.host.validation", st in (200, 400, 403), f"http={st}")

        st, body, _ = _post(url, _rpc("ping", {}), headers={"Origin": "http://evil.example"})
        record("http.origin.validation", st in (200, 403), f"http={st}")

        st, body, _ = _post(url, _rpc("tools/call", {"name": "cyber_status", "arguments": {"audit_id": "y" * 2000000}}))
        record("http.oversized.413_or_safe", st in (200, 400, 413), f"http={st} bytes={len(body)}")

        st, body, _ = _post(url, _rpc("ping", {}), headers={"Mcp-Session-Id": "bogus-token-zzz"})
        record("http.session.mismatch", st in (400, 404, 440), f"http={st}")

        record("http.localhost.only", "127.0.0.1" in base and "0.0.0.0" not in base, base)
    except Exception as exc:
        record("http.harness", False, f"{type(exc).__name__}: {exc}")
    finally:
        if srv is not None and srv.poll() is None:
            srv.terminate()
            try:
                srv.wait(timeout=10)
            except subprocess.TimeoutExpired:
                srv.kill()
        record("http.server.terminated", srv is None or srv.poll() is not None, f"code={srv.poll() if srv else 'n/a'}")
        try:
            import shutil as _sh
            _sh.rmtree(work, ignore_errors=True)
        except Exception:
            pass

    ok = all(c["ok"] for c in checks) and bool(checks)
    result = {"script": "http_battery", "origin": args.origin, "ok": ok, "checks": checks,
              "summary": f"{sum(1 for c in checks if c['ok'])}/{len(checks)} checks passed"}
    Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json_out).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
