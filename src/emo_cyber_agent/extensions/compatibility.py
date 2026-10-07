"""Extension compatibility — POST-RC-014.

Compatibility is an explicit, deterministic contract between a manifest
and a host profile. There is no "latest compatible guess": a resolver
either finds a declared match or refuses. Feature negotiation is also
explicit and never authorizes anything — declaring
``requires_feature=CODEINTEL.DATA_FLOW`` means the extension will not
work correctly without that host feature, nothing more.
"""

from __future__ import annotations


from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.extensions.spec import (
    SCHEMA_VERSION,
    ExtensionManifest,
    split_constraint,
)

from emo_cyber_agent.extensions.spec import (
    ExtensionDependencyType,
    ExtensionEntrypointKind,
    NetworkRequirement,
    ProcessRequirement,
)

__all__ = [
    "CompatibilityResult",
    "HostProfile",
    "check_compatibility",
    "host_profile",
    "python_satisfies",
    "satisfies",
    "supports_api",
]

_OPERATORS = (">=", "<=", "==", "!=", ">", "<", "~=")


def _segments(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _compare(left: tuple[int, ...], right: tuple[int, ...], operator: str) -> bool:
    size = max(len(left), len(right))
    padded_left = left + (0,) * (size - len(left))
    padded_right = right + (0,) * (size - len(right))
    if operator == "==":
        return padded_left == padded_right
    if operator == "!=":
        return padded_left != padded_right
    if operator == ">=":
        return padded_left >= padded_right
    if operator == "<=":
        return padded_left <= padded_right
    if operator == ">":
        return padded_left > padded_right
    if operator == "<":
        return padded_left < padded_right
    if operator == "~=":
        # PEP 440 style compatible release: ~=X.Y means >=X.Y, ==X.*
        # The prefix comes from the *declared* operand, before padding,
        # so ~=1.2 keeps matching 1.5.0 and never 2.0.0.
        if len(right) < 2:
            return padded_left[: len(right)] == right
        prefix = right[:-1]
        return padded_left[: len(prefix)] == prefix and padded_left >= padded_right
    return False


def satisfies(version: str, constraint: str) -> bool:
    """Deterministic constraint check. ``*`` matches every version."""
    text = (constraint or "").strip()
    if not text or text == "*":
        return True
    try:
        actual = _segments(version)
    except ValueError:
        return False
    for part in text.split(","):
        operator, operand = split_constraint(part)
        if operator not in _OPERATORS:
            return False
        try:
            if operator == "~=":
                expected = _segments(operand) if operand.count(".") == 1 else _segments(operand)
            else:
                expected = _segments(operand)
        except ValueError:
            return False
        if not _compare(actual, expected, operator):
            return False
    return True


def supports_api(api_version: str, manifest: ExtensionManifest) -> bool:
    """Host API version must fall inside the declared window."""
    try:
        host = _segments(api_version)
    except ValueError:
        return False
    minimum = _segments(manifest.compatibility.emo_api_min)
    if host < minimum:
        return False
    if manifest.compatibility.emo_api_max:
        maximum = _segments(manifest.compatibility.emo_api_max)
        if host > maximum:
            return False
    for constraint in manifest.supported_emo_versions:
        if constraint.strip() == "*":
            continue
        if not satisfies(api_version, _loosen(constraint)):
            return False
    return True


def _loosen(constraint: str) -> str:
    """Allow ``X.Y`` operands to match host ``X.Y`` versions."""
    parts: list[str] = []
    for part in constraint.split(","):
        operator, operand = split_constraint(part)
        parts.append(f"{operator}{operand}")
    return ",".join(parts)


def python_satisfies(current: str, specifier: str) -> bool:
    """Tiny subset of PEP 440: ``>=``, ``>``, ``<=``, ``<``, ``==``, ``,``."""
    text = (specifier or "").strip()
    if not text or text == "*":
        return True
    try:
        actual = _segments(current)
    except ValueError:
        return False
    for part in text.split(","):
        operator, operand = split_constraint(part)
        if operator == "~=":
            operand = operand + ".*"
            operator = ">="
        if operand.endswith(".*"):
            operand = operand[:-2]
        if operator not in _OPERATORS:
            return False
        try:
            expected = _segments(operand)
        except ValueError:
            return False
        if not _compare(actual, expected, operator):
            return False
    return True


class HostProfile(BaseModel):
    """Host capabilities. Supplied by Core, never by an extension."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    emo_api_version: str = Field(default="1.0", max_length=16)
    schema_version: str = Field(default=SCHEMA_VERSION, max_length=16)
    python_version: str = Field(default="3.11", max_length=32)
    platform: str = Field(default="darwin", max_length=32)
    features: tuple[str, ...] = Field(default_factory=tuple)

    @property
    def contract_version(self) -> str:
        from emo_cyber_agent.extensions.spec import CONTRACT_VERSION

        return CONTRACT_VERSION


class CompatibilityResult(BaseModel):
    """Frozen outcome plus machine-readable reasons and checks."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    compatible: bool = False
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    checks: tuple[str, ...] = Field(default_factory=tuple)


def host_profile(**overrides: object) -> HostProfile:
    """Host profile with the current interpreter defaults."""
    import platform as _platform
    import sys as _sys

    base: dict[str, object] = {
        "python_version": f"{_sys.version_info.major}.{_sys.version_info.minor}.{_sys.version_info.micro}",
        "platform": _platform.system().lower(),
        "features": (),
    }
    base.update(overrides)
    return HostProfile(**base)  # type: ignore[arg-type]


def check_compatibility(manifest: ExtensionManifest, host: HostProfile) -> CompatibilityResult:
    """Explicit compatibility verdict. Every reason is machine-readable."""
    reasons: list[str] = []
    checks: list[str] = []

    checks.append("api")
    if not supports_api(host.emo_api_version, manifest):
        reasons.append(
            f"api-window:needs>={manifest.compatibility.emo_api_min}"
            + (f",<={manifest.compatibility.emo_api_max}" if manifest.compatibility.emo_api_max else "")
            + f",host={host.emo_api_version}"
        )

    checks.append("python")
    if not python_satisfies(host.python_version, manifest.compatibility.python_requires):
        reasons.append(f"python-not-satisfied:needs={manifest.compatibility.python_requires},host={host.python_version}")

    checks.append("platform")
    # Platform vocabulary differs by source: manifests default to
    # sys.platform tokens ("win32") while host_profile() emits
    # platform.system().lower() ("windows"). Normalize both sides so a
    # default manifest evaluates compatible on Windows (POST-T020 G7).
    _PLATFORM_ALIASES = {"win32": "windows", "windows": "win32"}
    declared = {p.lower() for p in manifest.compatibility.platforms}
    declared |= {_PLATFORM_ALIASES[p] for p in declared if p in _PLATFORM_ALIASES}
    if host.platform and manifest.compatibility.platforms and host.platform.lower() not in declared:
        reasons.append(f"platform-unsupported:needs={','.join(manifest.compatibility.platforms)},host={host.platform}")

    checks.append("schema")
    declared_schemas = manifest.compatibility.schema_versions
    if declared_schemas and host.schema_version not in declared_schemas:
        reasons.append(f"schema-version-unsupported:needs={','.join(declared_schemas)},host={host.schema_version}")

    checks.append("features")
    for feature in manifest.compatibility.required_features:
        if feature not in host.features:
            reasons.append(f"feature-missing:{feature}")

    checks.append("entry-contract")
    entrypoint = manifest.entrypoint_metadata
    if entrypoint.kind.value == "implementation" and entrypoint.contract:
        contract_major = entrypoint.contract.rsplit(".", 1)[-1]
        if contract_major.isdigit() and contract_major != host.contract_version.split(".")[0]:
            reasons.append(f"contract-major-mismatch:needs={entrypoint.contract},host={host.contract_version}")

    checks.append("security-profile")
    profile = manifest.security_metadata
    if profile.declared_process == "shell" or profile.declared_process == "arbitrary_process":
        reasons.append(f"runtime-incompatible:process={profile.declared_process}")
    if profile.declared_network == "required":
        reasons.append("runtime-incompatible:network=required is never satisfied during offline loading")

    return CompatibilityResult(compatible=not reasons, reasons=tuple(reasons), checks=tuple(checks))
