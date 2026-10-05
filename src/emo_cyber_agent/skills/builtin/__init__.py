"""Built-in skill catalog (official, versioned, read-only data)."""

from .catalog import BUILTIN_INDEX, BUILTIN_SKILLS, load_builtin_registry

__all__ = ["BUILTIN_INDEX", "BUILTIN_SKILLS", "load_builtin_registry"]
