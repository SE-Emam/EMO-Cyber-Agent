"""Extension error surface — POST-RC-014.

Closed error codes for the extension layer. Discovery, validation,
compatibility, provenance and trust failures are all typed: an
extension never fails silently and never fails open. Messages pass
credential redaction at construction because manifests carry source
URLs, publisher identities and host-configuration strings.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["ExtensionErrorCode", "ExtensionError"]


class ExtensionErrorCode(StrEnum):
    """Closed extension error vocabulary (EXTENSION_* prefix)."""

    TYPE_UNKNOWN = "EXTENSION_TYPE_UNKNOWN"
    MANIFEST_MISSING = "EXTENSION_MANIFEST_MISSING"
    MANIFEST_INVALID = "EXTENSION_MANIFEST_INVALID"
    SCHEMA_INVALID = "EXTENSION_SCHEMA_INVALID"
    IDENTITY_INVALID = "EXTENSION_IDENTITY_INVALID"
    VERSION_INVALID = "EXTENSION_VERSION_INVALID"
    VERSION_NOT_FOUND = "EXTENSION_VERSION_NOT_FOUND"
    VERSION_AMBIGUOUS = "EXTENSION_VERSION_AMBIGUOUS"
    COMPATIBILITY_UNKNOWN = "EXTENSION_COMPATIBILITY_UNKNOWN"
    INCOMPATIBLE = "EXTENSION_INCOMPATIBLE"
    PROVENANCE_MISSING = "EXTENSION_PROVENANCE_MISSING"
    PROVENANCE_INVALID = "EXTENSION_PROVENANCE_INVALID"
    DIGEST_MISMATCH = "EXTENSION_DIGEST_MISMATCH"
    DECLARATION_FORBIDDEN = "EXTENSION_DECLARATION_FORBIDDEN"
    AUTHORITY_DECLARED = "EXTENSION_AUTHORITY_DECLARED"
    RESOURCE_DENIED = "EXTENSION_RESOURCE_DENIED"
    ENTRYPOINT_INVALID = "EXTENSION_ENTRYPOINT_INVALID"
    UNTRUSTED = "EXTENSION_UNTRUSTED"
    QUARANTINED = "EXTENSION_QUARANTINED"
    REJECTED = "EXTENSION_REJECTED"
    DUPLICATE = "EXTENSION_DUPLICATE"
    CONFLICT = "EXTENSION_CONFLICT"
    DEPENDENCY_MISSING = "EXTENSION_DEPENDENCY_MISSING"
    DEPENDENCY_INCOMPATIBLE = "EXTENSION_DEPENDENCY_INCOMPATIBLE"
    DEPENDENCY_CYCLE = "EXTENSION_DEPENDENCY_CYCLE"
    NOT_FOUND = "EXTENSION_NOT_FOUND"
    LOAD_REFUSED = "EXTENSION_LOAD_REFUSED"
    LOAD_FAILED = "EXTENSION_LOAD_FAILED"
    LOADER_UNAVAILABLE = "EXTENSION_LOADER_UNAVAILABLE"
    LIFECYCLE_INVALID = "EXTENSION_LIFECYCLE_INVALID"
    QUERY_UNKNOWN = "EXTENSION_QUERY_UNKNOWN"
    INSTALL_DENIED = "EXTENSION_INSTALL_DENIED"
    ISOLATION_BREACH = "EXTENSION_ISOLATION_BREACH"
    INTERNAL = "EXTENSION_INTERNAL"


class ExtensionError(Exception):
    """Typed extension failure. The message is redacted at construction."""

    def __init__(self, code: ExtensionErrorCode, message: str) -> None:
        from emo_cyber_agent.core.repository import redact_credentials

        try:
            from emo_cyber_agent.core.supabase import redact_supabase_secrets

            clean = redact_supabase_secrets(redact_credentials(str(message)))
        except Exception:  # noqa: BLE001 - redaction must never raise
            clean = redact_credentials(str(message))
        super().__init__(f"{code.value}: {clean[:500]}")
        self.code = code
        self.message = clean[:500]
