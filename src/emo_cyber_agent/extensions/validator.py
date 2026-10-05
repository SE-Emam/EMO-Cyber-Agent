"""Extension validation — POST-RC-014.

Content validation never raises: it returns a frozen, machine-readable
result whose error strings carry a stable prefix (``digest-mismatch:``,
``declaration-forbidden:...``), the same convention as the tool pack and
skill pack validators. Two different checks are deliberately separate:

* structural authority claims — a declared capability, process, network
  or secret value outside the closed vocabulary is refused outright;
* free-text authority language — scanned with identifier-aware matching
  so ``code.execute``-style dotted identifiers stay data while a
  standalone ``grant`` in prose is refused.

Validation never imports extension code and never grants anything: a
valid manifest is still an untrusted manifest.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.extensions.spec import (
    ALLOWED_DECLARED_CAPABILITIES,
    CAPABILITY_ALLOWED_FOR,
    DATA_ACCESS_TOKENS,
    DECLARATIVE_TYPES,
    EXECUTABLE_TYPES,
    EXTENSION_API_VERSION,
    EXTENSION_TYPES,
    FORBIDDEN_DECLARATIONS,
    FORBIDDEN_PROCESS_DECLARATIONS,
    FORBIDDEN_SECRET_DECLARATIONS,
    NetworkRequirement,
    ProcessRequirement,
    SecretDeclaration,
    ExtensionEntrypointKind,
    ExtensionManifest,
    ExtensionResource,
)

__all__ = [
    "ExtensionValidation",
    "ExtensionValidator",
    "flag_authority_language",
    "validate_manifest",
]

_AUTHORITY_SCAN_TOKENS: tuple[str, ...] = tuple(
    sorted(FORBIDDEN_DECLARATIONS | FORBIDDEN_SECRET_DECLARATIONS | FORBIDDEN_PROCESS_DECLARATIONS)
)

#: Entrypoint kinds a given extension type may declare.
_ENTRY_ALLOWED_KINDS: dict[str, frozenset[str]] = {
    "tool_pack": frozenset({ExtensionEntrypointKind.DECLARATIVE.value, ExtensionEntrypointKind.IMPLEMENTATION.value}),
    "verification_strategy": frozenset(
        {ExtensionEntrypointKind.DECLARATIVE.value, ExtensionEntrypointKind.IMPLEMENTATION.value}
    ),
    "verification_adapter": frozenset({ExtensionEntrypointKind.IMPLEMENTATION.value}),
}
for _type in EXTENSION_TYPES:
    _ENTRY_ALLOWED_KINDS.setdefault(_type, frozenset({ExtensionEntrypointKind.DECLARATIVE.value}))


def flag_authority_language(*texts: str) -> tuple[str, ...]:
    """Identifier-aware authority scan over free text.

    Standalone tokens are claims; dotted, slashed or hyphen-qualified
    identifiers (``code.execute``, ``repo/write``) are data. Never
    raises: the caller decides how a hit becomes an error."""
    hits: set[str] = set()
    for text in texts:
        lowered = (text or "").lower()
        for token in _AUTHORITY_SCAN_TOKENS:
            if re.search(rf"(?<![\w.:/-]){re.escape(token)}(?![\w-])", lowered):
                hits.add(token)
    return tuple(sorted(hits))


class ExtensionValidation(BaseModel):
    """Frozen validation verdict. ``errors`` are machine-readable."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    valid: bool = False
    errors: tuple[str, ...] = Field(default_factory=tuple)
    warnings: tuple[str, ...] = Field(default_factory=tuple)
    digest_bound: bool = False

    @property
    def authority_rejection(self) -> bool:
        """Authority/declaration failures reject instead of quarantine."""
        return any(
            error.startswith(("declaration-forbidden:", "authority-declared:", "entrypoint-invalid:"))
            for error in self.errors
        )


class ExtensionValidator:
    """Deterministic manifest validator. Stateless, import-free, offline."""

    def __init__(self, *, schema: dict[str, Any] | None = None, check_schema: bool = True) -> None:
        self._schema = schema
        self._check_schema = check_schema

    def validate(self, manifest: ExtensionManifest, *, raw: dict[str, Any] | None = None) -> ExtensionValidation:
        errors: list[str] = []
        warnings: list[str] = []

        if self._check_schema:
            if raw is None:
                raw = manifest.model_dump(mode="json")
            errors.extend(self._schema_errors(raw))

        errors.extend(self._structural_errors(manifest))
        errors.extend(self._authority_errors(manifest))
        warnings.extend(self._warnings(manifest))

        digest_bound = bool(manifest.digest) and manifest.digest == manifest.identity_digest
        if manifest.digest and not digest_bound:
            errors.append(f"digest-mismatch:declared={manifest.digest[:12]}")
        if not manifest.digest:
            warnings.append("digest-unbound:manifest carries no identity digest")

        # de-duplicate deterministically while preserving order
        errors = list(dict.fromkeys(errors))
        warnings = list(dict.fromkeys(warnings))
        return ExtensionValidation(
            valid=not errors,
            errors=tuple(errors),
            warnings=tuple(warnings),
            digest_bound=digest_bound,
        )

    # -- schema -----------------------------------------------------------

    def _schema_errors(self, raw: dict[str, Any]) -> tuple[str, ...]:
        from emo_cyber_agent.extensions.manifest import validate_against_schema

        try:
            validate_against_schema(raw, self._schema)
        except Exception as exc:  # noqa: BLE001 - typed ExtensionError or jsonschema noise
            return (f"schema:{str(exc)[:220]}",)
        return ()

    # -- structure --------------------------------------------------------

    def _structural_errors(self, manifest: ExtensionManifest) -> list[str]:
        errors: list[str] = []
        type_value = manifest.type_value

        if type_value not in EXTENSION_TYPES:
            errors.append(f"type-unknown:{type_value}")
            return errors

        if manifest.api_version.split(".")[0] != EXTENSION_API_VERSION.split(".")[0]:
            errors.append(f"api-version-unsupported:{manifest.api_version}")

        declared = manifest.declared_capabilities
        for capability in declared:
            if capability not in ALLOWED_DECLARED_CAPABILITIES:
                errors.append(f"declaration-forbidden:capability:{capability}")
            elif capability not in CAPABILITY_ALLOWED_FOR.get(type_value, ()):
                errors.append(f"declaration-forbidden:capability-for-type:{type_value}:{capability}")

        profile = manifest.security_metadata
        if profile.declared_network not in tuple(member.value for member in NetworkRequirement):
            errors.append(f"declaration-forbidden:network:{profile.declared_network}")
        if profile.declared_process not in tuple(member.value for member in ProcessRequirement):
            marker = "forbidden" if profile.declared_process in FORBIDDEN_PROCESS_DECLARATIONS else "unknown"
            errors.append(f"declaration-forbidden:process:{marker}:{profile.declared_process}")
        for secret in profile.declared_credentials:
            allowed = tuple(member.value for member in SecretDeclaration)
            if secret not in allowed:
                marker = "forbidden" if secret in FORBIDDEN_SECRET_DECLARATIONS else "unknown"
                errors.append(f"declaration-forbidden:secret:{marker}:{secret}")
        for access in profile.declared_data_access:
            if access not in DATA_ACCESS_TOKENS:
                errors.append(f"declaration-forbidden:data-access:{access}")

        errors.extend(self._entrypoint_errors(manifest))
        errors.extend(self._dependency_errors(manifest))

        if tuple(manifest.compatibility.required_features) != tuple(manifest.requires):
            errors.append("requires-mismatch:requires != compatibility.required_features")
        if manifest.license and manifest.source_provenance.license and manifest.license != manifest.source_provenance.license:
            errors.append("license-mismatch:manifest vs provenance")

        classification = manifest.dataset_classification.value
        if type_value != "evaluation_dataset" and classification in ("blind", "holdout"):
            errors.append(f"classification-not-applicable:{type_value}:{classification}")

        artifact = manifest.artifact_identity.artifact_digest
        provenance_digest = manifest.source_provenance.artifact_digest
        if artifact and provenance_digest and artifact != provenance_digest:
            errors.append("artifact-digest-inconsistent:artifact_identity vs source_provenance")

        seen: set[str] = set()
        for dependency in (*manifest.dependencies, *manifest.optional_dependencies):
            if dependency.extension_id == manifest.extension_id:
                errors.append("self-dependency:extension depends on itself")
            elif dependency.extension_id in seen:
                errors.append(f"duplicate-dependency:{dependency.extension_id}")
            seen.add(dependency.extension_id)

        for resource in manifest.resources:
            errors.extend(self._resource_errors(resource))
        return errors

    def _entrypoint_errors(self, manifest: ExtensionManifest) -> list[str]:
        errors: list[str] = []
        entrypoint = manifest.entrypoint_metadata
        kind = entrypoint.kind.value
        allowed = _ENTRY_ALLOWED_KINDS.get(manifest.type_value, frozenset())
        if kind not in allowed:
            errors.append(f"entrypoint-invalid:{manifest.type_value}:{kind}")
        if kind == ExtensionEntrypointKind.IMPLEMENTATION.value:
            if not entrypoint.target:
                errors.append("entrypoint-invalid:implementation without target")
            if not entrypoint.contract:
                errors.append("entrypoint-invalid:implementation without contract")
        if manifest.type_value in DECLARATIVE_TYPES and kind == ExtensionEntrypointKind.IMPLEMENTATION.value:
            errors.append(f"entrypoint-invalid:declarative type must not ship code:{manifest.type_value}")
        if manifest.type_value in EXECUTABLE_TYPES and kind == ExtensionEntrypointKind.DECLARATIVE.value:
            if manifest.type_value == "verification_adapter":
                errors.append("entrypoint-invalid:verification adapter requires an implementation")
        return errors

    def _dependency_errors(self, manifest: ExtensionManifest) -> list[str]:
        errors: list[str] = []
        for dependency in manifest.dependencies:
            if dependency.dependency_type.value == "implementation" and manifest.type_value in DECLARATIVE_TYPES:
                errors.append(f"declaration-forbidden:implementation-dependency:{dependency.extension_id}")
            if not dependency.required:
                errors.append(f"dependency-list-mismatch:required list holds optional:{dependency.extension_id}")
        for dependency in manifest.optional_dependencies:
            if dependency.required:
                errors.append(f"dependency-list-mismatch:optional list holds required:{dependency.extension_id}")
        return errors

    def _resource_errors(self, resource: ExtensionResource) -> list[str]:
        errors: list[str] = []
        path = resource.path
        if path.startswith("/") or "\\" in path or ".." in path.split("/"):
            errors.append(f"resource-denied:{resource.resource_id}")
        if "\x00" in path:
            errors.append(f"resource-denied:null-byte:{resource.resource_id}")
        return errors

    # -- authority --------------------------------------------------------

    def _authority_errors(self, manifest: ExtensionManifest) -> list[str]:
        hits = flag_authority_language(*manifest.textual_fields())
        return [f"declaration-forbidden:text:{token}" for token in hits]

    # -- warnings ---------------------------------------------------------

    def _warnings(self, manifest: ExtensionManifest) -> list[str]:
        warnings: list[str] = []
        if not manifest.artifact_identity.artifact_digest:
            warnings.append("artifact-digest-unset:artifact identity carries no digest")
        if not manifest.source_provenance.distribution_name:
            warnings.append("provenance-partial:no distribution recorded")
        if not manifest.source_provenance.publisher_identity:
            warnings.append("provenance-partial:no publisher identity")
        if not manifest.supported_emo_versions:
            warnings.append("supported-versions-unset:only emo_api_min/max applies")
        if not manifest.compatibility.schema_versions:
            warnings.append("schema-versions-unset:no schema pin declared")
        return warnings


def validate_manifest(
    manifest: ExtensionManifest,
    *,
    raw: dict[str, Any] | None = None,
    schema: dict[str, Any] | None = None,
    check_schema: bool = True,
) -> ExtensionValidation:
    """Convenience wrapper: one manifest, one frozen verdict."""
    return ExtensionValidator(schema=schema, check_schema=check_schema).validate(manifest, raw=raw)
