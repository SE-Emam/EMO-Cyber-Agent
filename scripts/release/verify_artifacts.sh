#!/usr/bin/env bash
set -Eeuo pipefail

# ECA-T016 Final Artifact Verification Script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo "$SCRIPT_DIR/.." || pwd)"

print_header() {
    echo "=== $1 ==="
}

print_mandatory() {
    echo "[MANDATORY] $1"
}

print_optional() {
    echo "[OPTIONAL] $1"
}

print_pass() {
    echo "[PASS] $1"
}

print_fail() {
    echo "[FAIL] $1"
}

print_blocked() {
    echo "[BLOCKED] $1"
}

main() {
    print_header "ECA-T016 Final Artifact Verification"
    
    WHEEL_PATH=""
    SDIST_PATH=""
    
    if [[ -f "$REPO_ROOT/dist/emo_cyber_agent-0.1.0-py3-none-any.whl" ]]; then
        WHEEL_PATH="$REPO_ROOT/dist/emo_cyber_agent-0.1.0-py3-none-any.whl"
    elif [[ -f "/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent/dist/emo_cyber_agent-0.1.0-py3-none-any.whl" ]]; then
        WHEEL_PATH="/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent/dist/emo_cyber_agent-0.1.0-py3-none-any.whl"
    else
        WHEEL_PATH=$(find "$REPO_ROOT" -name "emo_cyber_agent-0.1.0-py3-none-any.whl" -type f 2>/dev/null | head -1)
        if [[ -z "$WHEEL_PATH" ]]; then
            print_blocked "Wheel artifact not found"
            exit 1
        fi
        echo "Found wheel at: $WHEEL_PATH"
    fi
    
    if [[ -f "$REPO_ROOT/dist/emo_cyber_agent-0.1.0.tar.gz" ]]; then
        SDIST_PATH="$REPO_ROOT/dist/emo_cyber_agent-0.1.0.tar.gz"
    elif [[ -f "/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent/dist/emo_cyber_agent-0.1.0.tar.gz" ]]; then
        SDIST_PATH="/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent/dist/emo_cyber_agent-0.1.0.tar.gz"
    else
        SDIST_PATH=$(find "$REPO_ROOT" -name "emo_cyber_agent-0.1.0.tar.gz" -type f 2>/dev/null | head -1)
        if [[ -z "$SDIST_PATH" ]]; then
            print_blocked "Sdist artifact not found"
            exit 1
        fi
        echo "Found sdist at: $SDIST_PATH"
    fi
    
    print_mandatory "Wheel detected: $WHEEL_PATH"
    print_mandatory "Sdist detected: $SDIST_PATH"
    
    EXPECTED_WHEEL="emo_cyber_agent-0.1.0-py3-none-any.whl"
    
    if [[ "$(basename "$WHEEL_PATH")" != "$EXPECTED_WHEEL" ]]; then
        print_fail "Wheel name mismatch: expected $EXPECTED_WHEEL, got $(basename "$WHEEL_PATH")"
        exit 1
    fi
    
    print_pass "Artifact name validation passed"
    
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT
    
    VENV_PATH="$TMP_DIR/venv"
    print_mandatory "Creating virtual environment..."
    python3 -m venv "$VENV_PATH"
    
    print_mandatory "Installing package from wheel..."
    "$VENV_PATH/bin/python" -m pip install --no-index "$WHEEL_PATH"
    
    print_mandatory "Testing Python API..."
    "$VENV_PATH/bin/python" -c "import emo_cyber_agent; print('Python API import successful')"
    
    if ! "$VENV_PATH/bin/python" -c "from emo_cyber_agent import __version__; print('Version:', __version__)" 2>/dev/null | grep -q "0.1.0"; then
        print_fail "Python API version mismatch"
        exit 1
    fi
    
    print_mandatory "Testing CLI..."
    if ! "$VENV_PATH/bin/cyber-agent" --version 2>/dev/null | grep -q "0.1.0"; then
        print_fail "CLI version test failed"
        exit 1
    fi
    
    if ! "$VENV_PATH/bin/cyber-agent" --help 2>/dev/null | grep -q "Commands:"; then
        print_fail "CLI help test failed"
        exit 1
    fi
    
    if ! "$VENV_PATH/bin/cyber-agent" status 2>/dev/null | grep -q "CONFIGURED\\|MISSING\\|UNKNOWN"; then
        print_fail "CLI status test failed"
        exit 1
    fi
    
    print_mandatory "Testing MCP..."
    if ! "$VENV_PATH/bin/python" -c "
import sys
sys.path.insert(0, '')
from emo_cyber_agent.mcp.tools import TOOLS, validate_arguments
print(f'MCP tools available: {len(TOOLS)}')
" 2>/dev/null | grep -q "MCP tools available: 6"; then
        print_pass "MCP tools present"
    else
        print_fail "MCP test failed"
        exit 1
    fi
    
    print_mandatory "Testing package resources..."
    if ! "$VENV_PATH/bin/python" -c "
import os
import emo_cyber_agent

if not os.path.exists(os.path.join(os.path.dirname(emo_cyber_agent.__file__), 'data', 'schemas')):
    print('Schemas directory: NOT FOUND')
    exit(1)

if not os.path.exists(os.path.join(os.path.dirname(emo_cyber_agent.__file__), 'data', 'policies')):
    print('Policies directory: NOT FOUND')
    exit(1)

if not os.path.exists(os.path.join(os.path.dirname(emo_cyber_agent.__file__), 'data', 'official')):
    print('Official directory: NOT FOUND')
    exit(1)

print('Package resources test passed')
" 2>/dev/null; then
        print_fail "Package resources test failed"
        exit 1
    fi
    
    print_mandatory "Testing extension smoke..."
    if ! "$VENV_PATH/bin/cyber-agent" extensions --action list --format json 2>/dev/null | grep -q '"action": "list"'; then
        print_fail "Extension discovery test failed"
        exit 1
    fi
    
    if ! "$VENV_PATH/bin/cyber-agent" extensions --action resolve --provide verification_adapter --format json 2>/dev/null | grep -q '"eligible": false'; then
        print_fail "Extension resolution test failed"
        exit 1
    fi
    
    rm -rf "$TMP_DIR"
    
    print_header "FINAL MANDATORY STATUS: PASS"
    echo "All mandatory verification tests completed successfully."
    echo "Wheel: $WHEEL_PATH"
    echo "Sdist: $SDIST_PATH"
    echo ""
    echo "Release artifacts are ready for production deployment."
    
    exit 0
}

main "$@"
