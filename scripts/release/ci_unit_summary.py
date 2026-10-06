#!/usr/bin/env python3
"""Parse pytest results for the release workflow.

Prefers machine-readable JUnit XML (argv[2]); falls back to the human
summary in the text log (argv[1]). Prints shell-assignable lines:
    SUMMARY="<N> passed, <M> skipped"
    COUNT="<N>"
Exits nonzero when results show failures/errors or no summary is found,
so CI fails loudly instead of publishing with empty counts.
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _from_junit(path: Path) -> tuple[str, str] | None:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    if suite is None:
        return None
    try:
        total = int(suite.get("tests", "0"))
        errors = int(suite.get("errors", "0"))
        failures = int(suite.get("failures", "0"))
        skipped = int(suite.get("skipped", "0"))
    except ValueError:
        return None
    if errors or failures:
        print(
            f"unit suite has failures: {errors} errors, {failures} failures",
            file=sys.stderr,
        )
        return None
    if total <= 0:
        return None
    passed = total - errors - failures - skipped
    return f"{passed} passed, {skipped} skipped", str(passed)


def _from_text(path: Path) -> tuple[str, str] | None:
    try:
        log = path.read_text(errors="replace")
    except OSError as exc:
        print(f"cannot read log: {path}: {exc}", file=sys.stderr)
        return None
    # Accept "<N> passed" with optional ", <M> skipped" (skip counts vary
    # by environment), but fail closed on any failure/error signal.
    match = re.search(r"(\d+) passed(?:, (\d+) skipped)?", log)
    if not match:
        print("--- unit.log tail (summary not found) ---", file=sys.stderr)
        print("\n".join(log.splitlines()[-15:]), file=sys.stderr)
        return None
    summary_line = next(
        (line for line in log.splitlines() if "passed" in line), ""
    )
    if re.search(r"(\d+) failed|(\d+) error", summary_line):
        print(f"unit suite has failures: {summary_line}", file=sys.stderr)
        return None
    skipped = match.group(2) or "0"
    return f"{match.group(1)} passed, {skipped} skipped", match.group(1)


def main() -> int:
    log_path = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/unit.log")
    xml_path = Path(sys.argv[2] if len(sys.argv) > 2 else "/tmp/unit.xml")
    result = _from_junit(xml_path) or _from_text(log_path)
    if result is None:
        return 1
    summary, count = result
    print(f'SUMMARY="{summary}"')
    print(f"COUNT={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
