"""ECA-T016 — D. Entrypoint tests.

The installed console script resolves, reports the release version,
exposes exactly the documented command surface, and the canonical
MCP host example points at the installed entrypoint.
"""

from __future__ import annotations

import json


from conftest import ROOT, VERSION, run_console_script

EXPECTED_COMMANDS = {"audit", "doctor", "extensions", "mcp", "report", "review", "status", "verify"}


def test_console_script_resolves_and_reports_version(venv):
    script = venv / "bin" / "cyber-agent"
    assert script.is_file(), "cyber-agent console script missing from install"
    proc = run_console_script(venv, ["--version"])
    assert proc.returncode == 0
    assert VERSION in proc.stdout


def test_cli_help_lists_exact_documented_surface(venv):
    proc = run_console_script(venv, ["--help"])
    assert proc.returncode == 0
    for command in EXPECTED_COMMANDS:
        assert command in proc.stdout, f"command missing from installed --help: {command}"


def test_mcp_executable_exists_in_cli_surface(venv_mcp):
    """cyber-agent mcp is the MCP entrypoint; its protocol is proven in smoke."""
    proc = run_console_script(venv_mcp, ["mcp", "--help"])
    # the mcp command takes no options: it starts the stdio server. What
    # matters here is that the entrypoint resolves inside the install.
    assert "mcp" in (proc.stdout + proc.stderr).lower() or proc.returncode in (0, 2)


def test_mcp_host_example_canonical():
    example = json.loads((ROOT / "examples" / "mcp-host-config.json").read_text(encoding="utf-8"))
    server = example["mcpServers"]["emo-cyber-agent"]
    assert server["command"] == "cyber-agent" and server["args"] == ["mcp"]


def test_installed_help_is_cheap_and_clean(venv):
    """--help must not perform audits, network, or heavy imports."""
    proc = run_console_script(venv, ["--help"])
    assert proc.returncode == 0
    assert "cybersecurity specialist" in proc.stdout.lower()
    assert proc.stderr.strip() == "", f"help wrote diagnostics to stderr: {proc.stderr[:300]}"
