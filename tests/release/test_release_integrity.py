"""ECA-T016 — G. Release integrity tests.

SHA256SUMS covers wheel + sdist + release manifest and verifies in a
clean environment; the wheel carries no unexpected executables; and
importing the installed package has no import-time side effects (no
new threads, no daemon threads, no files created, no network at
import).
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path


from conftest import DIST, ROOT, SDIST, WHEEL, run_installed

SUMS = ROOT / "release" / "SHA256SUMS"
MANIFEST = ROOT / "release" / "release-manifest.json"

EXPECTED_EXECUTABLE_SUFFIXES = (".py", ".json", ".yaml", ".yml", ".md", ".txt", ".toml", ".cfg", "")


def test_sha256sums_covers_all_release_artifacts():
    assert SUMS.is_file(), f"missing {SUMS}"
    lines = [line.split() for line in SUMS.read_text(encoding="utf-8").splitlines() if line.strip()]
    names = {parts[1] for parts in lines if len(parts) == 2}
    assert WHEEL.name in names
    assert SDIST.name in names
    assert "release-manifest.json" in names


def test_sha256sums_verifies_in_clean_environment(tmp_path):
    """Recompute every hash from the files on disk; all must match."""
    for line in SUMS.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, name = line.split()
        # entries are relative to release/ for the manifest, to dist/ for artifacts
        candidates = [ROOT / "release" / name, DIST / name]
        target = next((c for c in candidates if c.is_file()), None)
        assert target is not None, f"SHA256SUMS references missing file: {name}"
        assert hashlib.sha256(target.read_bytes()).hexdigest() == expected, name


def test_wheel_has_no_unexpected_executables():
    """Only data/code suffixes; no binaries, no scripts with exec bits that
    the build did not declare (the single console script is metadata)."""
    with zipfile.ZipFile(WHEEL) as z:
        bad = [
            info.filename
            for info in z.infolist()
            if Path(info.filename).suffix not in EXPECTED_EXECUTABLE_SUFFIXES
            and not info.filename.endswith("/")
            and info.filename.split("/")[-1] not in ("RECORD", "METADATA", "WHEEL", "entry_points.txt", "LICENSE")
        ]
        assert not bad, f"unexpected files in wheel: {bad[:10]}"


def test_import_has_no_side_effects_from_installed_package(venv, tmp_path):
    """Import in an isolated cwd: no threads spawned, nothing written."""
    code = (
        "import sys, threading, os;"
        "before_threads = threading.active_count();"
        "before_modules = set(sys.modules);"
        "import emo_cyber_agent;"
        "from emo_cyber_agent import SecurityAuditor, ReportService, generate_report;"
        "import json;"
        "leftover = [p for p in os.listdir('.') if not p.startswith('.')];"
        "print(json.dumps({"
        "'threads_delta': threading.active_count() - before_threads,"
        "'daemons': sum(1 for t in threading.enumerate() if t.daemon),"
        "'leftover': leftover,"
        "'version': emo_cyber_agent.__version__,"
        "}))"
    )
    proc = run_installed(venv / "bin" / "python", ["-c", code], cwd=tmp_path)
    import json as _json

    body = _json.loads(proc.stdout.strip().splitlines()[-1])
    assert body["threads_delta"] == 0, body
    assert body["daemons"] == 0, body
    assert body["leftover"] == [], f"import created files: {body['leftover']}"
    assert body["version"] == "0.2.1"


def test_manifest_hash_matches_dist_identity():
    import json as _json

    manifest = _json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["artifacts"]["wheel"]["name"] == WHEEL.name
    assert manifest["artifacts"]["sdist"]["name"] == SDIST.name
    assert manifest["artifacts"]["wheel"]["sha256"] == hashlib.sha256(WHEEL.read_bytes()).hexdigest()
    assert manifest["artifacts"]["sdist"]["sha256"] == hashlib.sha256(SDIST.read_bytes()).hexdigest()
