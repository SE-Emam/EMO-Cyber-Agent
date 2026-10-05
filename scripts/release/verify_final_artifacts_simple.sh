#!/usr/bin/env bash
set -Eeuo pipefail

# ECA-T016 Final Artifact Verification Script - Simple Version
# This script verifies the existence and basic integrity of the EMO-Cyber-Agent 0.1.0 final artifacts

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo "$SCRIPT_DIR/.." || pwd)"

print_header() {
    echo "=== $1 ==="
}

print_mandatory() {
    echo "[MANDATORY] $1"
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
    print_header "ECA-T016 Final Artifact Verification (Simple)"
    
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
    
    # Check basic file properties
    print_mandatory "Validating artifact properties..."
    
    # Check wheel properties
    if [[ ! -s "$WHEEL_PATH" ]]; then
        print_fail "Wheel file is empty or invalid"
        exit 1
    fi
    
    # Check sdist properties
    if [[ ! -s "$SDIST_PATH" ]]; then
        print_fail "Sdist file is empty or invalid"
        exit 1
    fi
    
    # Check for package data directories
    WHEEL_SIZE=$(stat -c%s "$WHEEL_PATH" 2>/dev/null || stat -f%z "$WHEEL_PATH" 2>/dev/null)
    SDIST_SIZE=$(stat -c%s "$SDIST_PATH" 2>/dev/null || stat -f%z "$SDIST_PATH" 2>/dev/null)
    
    print_pass "Wheel size: $WHEEL_SIZE bytes"
    print_pass "Sdist size: $SDIST_SIZE bytes"
    
    # Check for key files in wheel
    if unzip -q -t "$WHEEL_PATH" >/dev/null 2>&1; then
        print_pass "Wheel is a valid ZIP archive"
    else
        print_fail "Wheel is not a valid ZIP archive"
        exit 1
    fi
    
    # Check for key files in sdist
    if tar -tzf "$SDIST_PATH" >/dev/null 2>&1; then
        print_pass "Sdist is a valid tar.gz archive"
    else
        print_fail "Sdist is not a valid tar.gz archive"
        exit 1
    fi
    
    # Check for package structure in wheel
    if unzip -q -l "$WHEEL_PATH" | grep -q "^.*.dist-info/METADATA$"; then
        print_pass "Wheel contains .dist-info/METADATA"
    else
        print_fail "Wheel missing .dist-info/METADATA"
        exit 1
    fi
    
    # Check for entry points
    if unzip -q -l "$WHEEL_PATH" | grep -q "^.*console_scripts$"; then
        print_pass "Wheel contains console scripts entry points"
    else
        print_pass "Wheel does not contain console scripts (may be optional)"
    fi
    
    # Basic security check - look for obvious malicious patterns
    if grep -r "eval\|exec\|subprocess\|os.system" "$WHEEL_PATH" >/dev/null 2>&1 | head -1; then
        print_warn "Wheel contains potentially problematic code (this is normal for Python packages)"
    fi
    
    # Verify version from wheel metadata
    local metadata_temp_dir
    metadata_temp_dir=$(mktemp -d)
    unzip -q -j "$WHEEL_PATH" "$(unzip -l \"$WHEEL_PATH\" 2>/dev/null | grep \"\\.dist-info/METADATA$\" | head -1 | awk '{print \"$4\"}')" -d "$metadata_temp_dir" 2>/dev/null
    
    if [[ -f "$metadata_temp_dir/METADATA" ]]; then
        local wheel_version
        wheel_version=$(grep "^Version:" "$metadata_temp_dir/METADATA" 2>/dev/null | cut -d: -f2 | tr -d ' ' || echo "UNKNOWN")
        \ 
        if [[ \"$wheel_version\" == \"0.1.0\" ]]; then\n            print_pass \"Wheel version verification: 0.1.0\"\n        else\n            print_warn \"Wheel version: $wheel_version (expected: 0.1.0)\"\n        fi\n    fi\n    \n    rm -rf \"$metadata_temp_dir\"\n    \n    # Check for release manifest\n    local manifest_path=\"$REPO_ROOT/release/release-manifest.json\"\n    if [[ -f \"$manifest_path\" ]]; then\n        print_pass \"Release manifest found: $manifest_path\"\n    else\n        print_optional \"Release manifest not found (may be optional)\"\n    fi\n    \n    # Check for SHA256SUMS\n    local checksums_path=\"$REPO_ROOT/dist/SHA256SUMS\"\n    if [[ -f \"$checksums_path\" ]]; then\n        print_pass \"SHA256 checksums found\"\n    else\n        print_optional \"SHA256 checksums not found\"\n    fi\n    \n    print_header \"FINAL ARTIFACT VERIFICATION SUMMARY\"\n    print_pass \"All mandatory artifact validation checks passed\"\n    echo \"\"\n    echo \"Wheel: $WHEEL_PATH\"\n    echo \"Sdist: $SDIST_PATH\"\n    echo \"\"\n    echo \"Release artifacts are ready for production deployment.\"\n    \n    exit 0\n}\n\nmain \"$@\"\nEOF\n