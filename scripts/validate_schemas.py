"""Validate local JSON schema files syntactically.

Full cross-schema validation is added with the schema test suite in Phase 0/1.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "docs" / "schemas"

for path in sorted(SCHEMA_DIR.glob("*.json")):
    with path.open(encoding="utf-8") as fh:
        json.load(fh)
    print(f"OK {path.relative_to(ROOT)}")
