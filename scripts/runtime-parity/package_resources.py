"""O5 runtime-parity: package_resources.py — data presence from the INSTALLED package.

Asserts `emo_cyber_agent.__file__` is NOT under a repo `src/` tree (i.e. we are
inspecting the installed artifact), then checks skills/tasks/playbooks/
templates/threat_intel/subagent/checklists/schemas data resolve and load.
Stdlib only, cross-platform.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

TIMEOUT = 120

PROBE = """import json
import emo_cyber_agent as pkg
from pathlib import Path
root = Path(pkg.__file__).resolve().parent
out = {"file": str(Path(pkg.__file__).resolve()), "version": getattr(pkg, "__version__", "?"), "probes": []}
def probe(name, ok, detail=""):
    out["probes"].append({"name": name, "ok": bool(ok), "detail": str(detail)[:300]})
parts = Path(pkg.__file__).resolve().parts
probe("installed.not_under_repo_src", "src" not in parts or "site-packages" in str(Path(pkg.__file__).resolve()), str(Path(pkg.__file__).resolve()))
try:
    from emo_cyber_agent.core.resources import official_catalog_path, resource_origin
    cat = Path(official_catalog_path()); probe("resources.catalog_exists", cat.is_dir(), str(cat))
    probe("resources.origin", True, str(resource_origin()))
except Exception as e:
    probe("resources.catalog_exists", False, f"{type(e).__name__}: {e}")
for mod, fn, label in [
    ("emo_cyber_agent.skills.builtin", "load_builtin_registry", "skills"),
    ("emo_cyber_agent.tasks.library", "load_official_registry", "tasks"),
    ("emo_cyber_agent.playbooks.library", "load_official_registry", "playbooks"),
    ("emo_cyber_agent.report_templates.library", "load_official_registry", "templates"),
    ("emo_cyber_agent.tools.packs.catalog", "load_official_tool_packs", "toolpacks"),
    ("emo_cyber_agent.threat_intel.triage", None, "threat_intel"),
    ("emo_cyber_agent.subagent.session", "SubagentSession", "subagent"),
    ("emo_cyber_agent.core.checklists", None, "checklists"),
]:
    try:
        m = __import__(mod, fromlist=["*"])
        if fn is None:
            probe(f"data.{label}.importable", True, mod)
        else:
            probe(f"data.{label}.has_{fn}", hasattr(m, fn), mod)
    except Exception as e:
        probe(f"data.{label}", False, f"{type(e).__name__}: {e}")
try:
    from emo_cyber_agent.core.resources import official_catalog_path
    schemas = list((Path(official_catalog_path()).rglob("*.json"))[:5])
    probe("data.schemas.present", len(schemas) > 0, f"{len(schemas)} json files")
except Exception as e:
    probe("data.schemas.present", False, f"{type(e).__name__}: {e}")
try:
    from emo_cyber_agent.core.resources import validate_packaged_schemas
    validate_packaged_schemas(); probe("data.schemas.valid", True, "validate_packaged_schemas ok")
except Exception as e:
    probe("data.schemas.valid", False, f"{type(e).__name__}: {e}")
print(json.dumps(out))
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="Installed-package resource presence checks.")
    ap.add_argument("--origin", required=True, choices=("wheel", "sdist", "pypi"))
    ap.add_argument("--json-out", required=True)
    args = ap.parse_args()

    checks: list[dict] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": str(detail)[:500]})

    try:
        proc = subprocess.run([sys.executable, "-c", PROBE], capture_output=True, text=True,
                              timeout=TIMEOUT)
        record("resources.probe_ran", proc.returncode == 0, f"exit={proc.returncode} stderr={proc.stderr[-300:]}")
        if proc.returncode == 0:
            try:
                out = json.loads(proc.stdout)
            except Exception as exc:
                record("resources.probe_json", False, f"unparseable: {exc}")
                out = {"probes": []}
            record("resources.installed_file", True, str(out.get("file", ""))[:200])
            for p in out.get("probes", []):
                record(str(p.get("name", "probe")), bool(p.get("ok")), str(p.get("detail", ""))[:300])
        else:
            record("resources.probe_json", False, proc.stderr[-500:])
    except subprocess.TimeoutExpired:
        record("resources.probe_ran", False, "timeout")
    except Exception as exc:
        record("resources.harness", False, f"{type(exc).__name__}: {exc}")

    ok = all(c["ok"] for c in checks) and bool(checks)
    result = {"script": "package_resources", "origin": args.origin, "ok": ok, "checks": checks,
              "summary": f"{sum(1 for c in checks if c['ok'])}/{len(checks)} checks passed"}
    Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json_out).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
