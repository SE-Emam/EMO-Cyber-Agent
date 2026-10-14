"""Release artifact verifier scripts resolve paths from their location."""

import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_NAMES = ("verify_artifacts.py", "verify_artifacts_final.py")


def _make_synthetic_release(repo_root: Path) -> None:
    dist = repo_root / "dist"
    dist.mkdir(parents=True)
    (repo_root / "release").mkdir()
    wheel = dist / "emo_cyber-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("emo_cyber_agent/cli/main.py", "# fixture\n")
        archive.writestr("emo_cyber_agent/mcp/server.py", "# fixture\n")
        archive.writestr("emo_cyber_agent/extensions/__init__.py", "# fixture\n")
        archive.writestr("emo_cyber_agent/tools/__init__.py", "# fixture\n")
        archive.writestr("emo_cyber_agent/skills/__init__.py", "# fixture\n")
        archive.writestr("fixture.dist-info/METADATA", "Name: fixture\n")
        archive.writestr("fixture.dist-info/entry_points.txt", "[console_scripts]\n")
    with tarfile.open(dist / "emo_cyber-0.1.0.tar.gz", "w:gz"):
        pass


def test_release_verifiers_use_script_repo_root_outside_checkout_cwd(tmp_path):
    outside_cwd = tmp_path / "unrelated-working-directory"
    outside_cwd.mkdir()

    for name in SCRIPT_NAMES:
        fixture_repo = tmp_path / Path(name).stem
        script_dir = fixture_repo / "scripts" / "release"
        script_dir.mkdir(parents=True)
        shutil.copyfile(REPOSITORY_ROOT / "scripts" / "release" / name, script_dir / name)
        _make_synthetic_release(fixture_repo)

        result = subprocess.run(
            [sys.executable, str(script_dir / name)],
            cwd=outside_cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )

        assert result.returncode == 0, result.stderr
        assert (fixture_repo / "release" / "effective_artifact_verification.json").is_file()
        assert (
            fixture_repo / "reports" / "development" / "ECA-T016-artifact-verification.md"
        ).is_file()
        assert not (fixture_repo / "scripts" / "release" / "release").exists()
        assert not (fixture_repo / "scripts" / "release" / "reports").exists()
