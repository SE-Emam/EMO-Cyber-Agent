"""Security policy primitives placeholder."""

from enum import StrEnum


class PermissionProfile(StrEnum):
    READ_ONLY = "read_only"
    VERIFY = "verify"
    REMEDIATE = "remediate"
