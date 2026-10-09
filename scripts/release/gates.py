"""Release gate orchestration — ECA-T016.

Invokes the authoritative existing suites (security, evaluation,
invariants, schemas) and the release-specific artifact checks, then
normalizes every result into release evidence. This module contains no
security predicates of its own: every correctness or security decision
stays with its owner suite (see the test ownership map in
docs/evidence/ECA-T016-release-security-assessment.md).

Usage:
    python scripts/release/gates.py                # run every gate
    python scripts/release/gates.py --gate security
    python scripts/release/gates.py --json release/gate-results.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
PACKAGE = "emo-cyber-agent"
WHEEL = f"{PACKAGE}-{VERSION}-py3-none-any.whl"
SDIST = f"{PACKAGE}-{VERSION}.tar.gz"

# ---------------------------------------------------------------------------
# Test ownership map — every major security domain has exactly one owner
# suite. Release gates invoke owners; they never re-implement predicates.
# ---------------------------------------------------------------------------

OWNER_SUITES: dict[str, tuple[str, ...]] = {
    "policy-security": (
        "tests/unit/test_hardening.py",
        "tests/unit/test_toolchain.py",
        "tests/unit/test_repository.py",
        "tests/unit/test_correlation.py",
        "tests/unit/test_findings.py",
        "tests/unit/test_reasoning.py",
    ),
    "agent-mcp-security": (
        "tests/unit/test_mcp_security.py",
        "tests/unit/test_agent_security.py",
        "tests/unit/test_agent_security_adversarial.py",
        "tests/unit/test_agent_security_isolation.py",
        "tests/unit/test_attack_surface.py",
    ),
    "verification": (
        "tests/unit/test_verification.py",
        "tests/unit/test_verification_adapters.py",
        "tests/unit/test_verification_adversarial.py",
        "tests/unit/test_verification_regression.py",
        "tests/unit/test_verification_security.py",
        "tests/unit/test_verification_adapter_contract.py",
        "tests/unit/test_verification_strategies.py",
    ),
    "knowledge": (
        "tests/unit/test_security_knowledge.py",
        "tests/unit/test_security_knowledge_adversarial.py",
        "tests/unit/test_security_knowledge_isolation.py",
        "tests/unit/test_security_knowledge_regression.py",
    ),
    "extensions": (
        "tests/unit/test_extensions.py",
        "tests/unit/test_extension_adversarial.py",
        "tests/unit/test_extension_compatibility.py",
        "tests/unit/test_extension_discovery.py",
        "tests/unit/test_extension_provenance.py",
        "tests/unit/test_extension_registry.py",
        "tests/unit/test_extension_security.py",
    ),
    "evaluation": (
        "tests/unit/test_evaluation_spec.py",
        "tests/unit/test_evaluation_datasets.py",
        "tests/unit/test_evaluation_sut.py",
        "tests/unit/test_evaluation_oracles_metrics_gates.py",
        "tests/unit/test_evaluation_runner.py",
        "tests/unit/test_evaluation_e2e.py",
    ),
    "content": (
        "tests/unit/test_skills.py",
        "tests/unit/test_security_skill_packs.py",
        "tests/unit/test_tasks.py",
        "tests/unit/test_playbooks.py",
        "tests/unit/test_report_templates.py",
        "tests/unit/test_tool_packs.py",
        "tests/unit/test_tool_pack_security.py",
        "tests/unit/test_threat_modeling.py",
        "tests/unit/test_threat_security.py",
        "tests/unit/test_change_analysis.py",
        "tests/unit/test_change_security.py",
        "tests/unit/test_code_intelligence.py",
        "tests/unit/test_reporting.py",
    ),
}

# Release-specific suites (ECA-T016 owners: packaging/install/runtime).
RELEASE_SUITES: dict[str, tuple[str, ...]] = {
    "build": ("tests/release/test_build.py",),
    "artifacts": ("tests/release/test_artifacts.py",),
    "installation": ("tests/release/test_installation.py",),
    "entrypoints": ("tests/release/test_entrypoints.py",),
    "packaged-resources": ("tests/release/test_packaged_resources.py",),
    "release-manifest": ("tests/release/test_release_manifest.py",),
    "release-integrity": ("tests/release/test_release_integrity.py",),
    "release-smoke": ("tests/release/test_release_smoke.py",),
}

INVARIANT_MATRIX_TEST = "tests/unit/test_hardening.py::test_invariant_regression_matrix"


@dataclass
class ReleaseEvidence:
    """Normalized result of one gate. No verdict logic beyond PASS/FAIL."""

    gate: str
    status: str  # PASS | FAIL | BLOCKED
    summary: str
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "gate": self.gate,
            "status": self.status,
            "summary": self.summary,
            "details": self.details,
        }


class ReleaseGate:
    """Base gate: run something, normalize the result into evidence."""

    name = "base"

    def run(self) -> ReleaseEvidence:  # pragma: no cover - interface
        raise NotImplementedError


def _run_pytest(paths: list[str], *, timeout: int = 1800) -> tuple[int, str]:
    """Run existing suites with the project's pytest options."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *paths, "-o", "addopts=", "-q"],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(ROOT),
    )
    return proc.returncode, proc.stdout + proc.stderr


def _pytest_evidence(gate: str, paths: list[str], timeout: int = 1800) -> ReleaseEvidence:
    """Invoke an owner suite and normalize its result. No predicates here."""
    try:
        code, output = _run_pytest(paths, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ReleaseEvidence(gate, "FAIL", "suite timed out", {})
    except FileNotFoundError as exc:
        return ReleaseEvidence(gate, "FAIL", f"suite unavailable: {exc}", {})
    tail = output.strip().splitlines()[-1] if output.strip() else "no output"
    if code == 0:
        return ReleaseEvidence(gate, "PASS", tail, {"suites": list(paths), "output_tail": tail})
    return ReleaseEvidence(gate, "FAIL", tail, {"suites": list(paths), "output_tail": tail})


class SecurityGate(ReleaseGate):
    """Authoritative security/invariant gate (T003/T015 + POST-RC owners)."""

    name = "security"

    def run(self) -> ReleaseEvidence:
        paths = [p for suite in OWNER_SUITES.values() for p in suite]
        return _pytest_evidence(self.name, paths)


class InvariantGate(ReleaseGate):
    """The 12-invariant matrix — owned by test_hardening.py."""

    name = "invariants"

    def run(self) -> ReleaseEvidence:
        return _pytest_evidence(self.name, [INVARIANT_MATRIX_TEST])


class EvaluationGate(ReleaseGate):
    """POST-RC-013 evaluation owner suite (correctness, not packaging)."""

    name = "evaluation"

    def run(self) -> ReleaseEvidence:
        return _pytest_evidence(self.name, list(OWNER_SUITES["evaluation"]))


class SchemaGate(ReleaseGate):
    """36/36 schemas — owned by scripts/validate_schemas.py."""

    name = "schemas"

    def run(self) -> ReleaseEvidence:
        proc = subprocess.run(
            [sys.executable, "scripts/validate_schemas.py"],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(ROOT),
        )
        ok_lines = [line for line in proc.stdout.splitlines() if line.startswith("OK ")]
        if proc.returncode == 0 and len(ok_lines) == 36:
            return ReleaseEvidence(self.name, "PASS", f"{len(ok_lines)}/36 schemas valid", {"count": len(ok_lines)})
        return ReleaseEvidence(
            self.name,
            "FAIL",
            f"{len(ok_lines)}/36 schemas valid",
            {"count": len(ok_lines), "output_tail": proc.stdout[-500:]},
        )


class PackageGate(ReleaseGate):
    """Build + artifact checks — owned by tests/release/test_build.py and test_artifacts.py."""

    name = "package"

    def run(self) -> ReleaseEvidence:
        return _pytest_evidence(self.name, list(RELEASE_SUITES["build"]) + list(RELEASE_SUITES["artifacts"]))


class InstallGate(ReleaseGate):
    """Clean pip/pipx install — owned by tests/release/test_installation.py."""

    name = "install"

    def run(self) -> ReleaseEvidence:
        return _pytest_evidence(self.name, list(RELEASE_SUITES["installation"]))


class InterfaceParityGate(ReleaseGate):
    """One canonical smoke per surface from the installed artifact."""

    name = "interface-parity"

    def run(self) -> ReleaseEvidence:
        return _pytest_evidence(self.name, list(RELEASE_SUITES["release-smoke"]))


class ArtifactIntegrityGate(ReleaseGate):
    """Checksums + manifest match — owned by tests/release/test_release_integrity.py."""

    name = "artifact-integrity"

    def run(self) -> ReleaseEvidence:
        return _pytest_evidence(
            self.name,
            list(RELEASE_SUITES["release-integrity"]) + list(RELEASE_SUITES["release-manifest"]),
        )


GATES: dict[str, ReleaseGate] = {
    "security": SecurityGate(),
    "invariants": InvariantGate(),
    "evaluation": EvaluationGate(),
    "schemas": SchemaGate(),
    "package": PackageGate(),
    "install": InstallGate(),
    "interface-parity": InterfaceParityGate(),
    "artifact-integrity": ArtifactIntegrityGate(),
}


def run_all() -> dict:
    """Run every gate and assemble the machine-readable release decision."""
    evidence = [gate.run() for gate in GATES.values()]
    blocked = [item.gate for item in evidence if item.status != "PASS"]
    decision = {
        "package": PACKAGE,
        "version": VERSION,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "gates": {item.gate: item.to_dict() for item in evidence},
        "release_status": "BLOCKED" if blocked else "PASS",
        "blocked_by": blocked,
    }
    return decision


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ECA-T016 release gates")
    parser.add_argument("--gate", choices=sorted(GATES), help="run a single gate")
    parser.add_argument("--json", type=Path, help="write full decision JSON to this path")
    args = parser.parse_args(argv)

    if args.gate:
        result = GATES[args.gate].run()
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0 if result.status == "PASS" else 1

    decision = run_all()
    text = json.dumps(decision, indent=2, sort_keys=True)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if decision["release_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
