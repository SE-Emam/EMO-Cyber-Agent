#!/usr/bin/env python3
"""Parse pytest summary from a log file for the release workflow.

Prints shell-assignable lines:
    SUMMARY="<N> passed, <M> skipped"
    COUNT="<N>"
Exits nonzero (after dumping the log tail) when no summary is found,
so CI fails loudly instead of publishing with empty counts.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/unit.log")
    try:
        log = path.read_text(errors="replace")
    except OSError as exc:
        print(f"cannot read log: {path}: {exc}", file=sys.stderr)
        return 1
    match = re.search(r"(\d+) passed, (\d+) skipped", log)
    if not match:
        print("--- unit.log tail (summary not found) ---", file=sys.stderr)
        print("\n".join(log.splitlines()[-15:]), file=sys.stderr)
        return 1
    print(f'SUMMARY="{match.group(1)} passed, {match.group(2)} skipped"')
    print(f"COUNT={match.group(1)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
