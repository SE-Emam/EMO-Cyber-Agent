"""O5 runtime-parity: verify_artifact.py — fail-closed sha256 check of built artifacts.

Compares recomputed sha256 digests of files in --artifacts-dir against the
hashes pinned in --manifest (parity-manifest.json written by the build step).
Fail closed: missing file, extra file, digest mismatch, or unreadable manifest
all fail. Stdlib only, cross-platform.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

CHUNK = 65536


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _load_manifest(manifest: Path) -> dict[str, str]:
    """Accept several manifest shapes; normalize to {filename: sha256}."""
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    if isinstance(raw, dict) and isinstance(raw.get("artifacts"), list):
        out: dict[str, str] = {}
        for entry in raw["artifacts"]:
            if isinstance(entry, dict) and "filename" in entry and "sha256" in entry:
                out[str(entry["filename"])] = str(entry["sha256"])
        return out
    if isinstance(raw, dict) and isinstance(raw.get("files"), dict):
        return {str(k): str(v) for k, v in raw["files"].items()}
    if isinstance(raw, dict) and all(isinstance(v, str) for v in raw.values()):
        return {str(k): str(v) for k, v in raw.items()}
    raise ValueError("unrecognized parity-manifest.json shape")


def main() -> int:
    ap = argparse.ArgumentParser(description="Fail-closed sha256 verification of release artifacts.")
    ap.add_argument("--origin", required=True, choices=("wheel", "sdist", "pypi"))
    ap.add_argument("--json-out", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--artifacts-dir", required=True)
    args = ap.parse_args()

    checks: list[dict] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": str(detail)[:500]})

    manifest = Path(args.manifest)
    artifacts_dir = Path(args.artifacts_dir)
    try:
        expected = _load_manifest(manifest)
        record("manifest.readable", True, f"{len(expected)} entries")
    except Exception as exc:  # fail closed
        record("manifest.readable", False, f"{type(exc).__name__}: {exc}")
        expected = {}

    record("artifacts_dir.exists", artifacts_dir.is_dir(), str(artifacts_dir))
    if expected and artifacts_dir.is_dir():
        for filename, want in sorted(expected.items()):
            target = artifacts_dir / filename
            if not target.is_file():
                record(f"artifact.present:{filename}", False, "missing file (fail closed)")
                continue
            record(f"artifact.present:{filename}", True, f"{target.stat().st_size} bytes")
            try:
                got = _sha256(target)
            except Exception as exc:
                record(f"artifact.sha256:{filename}", False, f"unreadable: {exc}")
                continue
            record(
                f"artifact.sha256:{filename}",
                got.lower() == want.lower(),
                "match" if got.lower() == want.lower() else "MISMATCH (fail closed)",
            )
        # Extra-file check is advisory but recorded (wheels/sdists are the pinned set).
        # Exclude the manifest itself: it ships inside --artifacts-dir but is not a pinned artifact.
        try:
            manifest_resolved = manifest.resolve()
        except Exception:
            manifest_resolved = manifest.absolute()
        actual = {p.name for p in artifacts_dir.iterdir() if p.is_file() and p.resolve() != manifest_resolved}
        extras = sorted(actual - set(expected))
        record("artifacts.no_unpinned_extras", not extras, "none" if not extras else f"extras: {extras}")
    else:
        if not expected:
            record("manifest.nonempty", False, "no pinned entries; cannot verify (fail closed)")

    # Origin sanity: at least one pinned artifact kind matches the origin under test.
    names = list(expected)
    if args.origin == "wheel":
        record("origin.coverage", any(n.endswith(".whl") for n in names), "wheel pinned" if any(n.endswith(".whl") for n in names) else "no .whl pinned")
    elif args.origin == "sdist":
        record("origin.coverage", any(n.endswith(".tar.gz") for n in names), "sdist pinned" if any(n.endswith(".tar.gz") for n in names) else "no .tar.gz pinned")
    else:
        record("origin.coverage", True, "pypi origin: manifest pins authoritative digests")

    ok = all(c["ok"] for c in checks) and bool(checks)
    result = {"script": "verify_artifact", "origin": args.origin, "ok": ok, "checks": checks,
              "summary": f"{sum(1 for c in checks if c['ok'])}/{len(checks)} checks passed"}
    Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json_out).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
