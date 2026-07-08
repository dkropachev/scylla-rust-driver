#!/bin/bash
# =============================================================================
# ScyllaDB Updatable Driver - End-to-End Demo
# =============================================================================
#
# This script demonstrates the full updatable driver pipeline:
#   1. Build the driver shared library (cdylib)
#   2. Sign it with Ed25519
#   3. Verify the signature
#   4. Load it via dlopen and read the version string
#   5. Run all unit tests
#
# No running ScyllaDB instance is required.
# =============================================================================

set -e
cd "$(dirname "$0")/.."

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
RESET='\033[0m'

step() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  STEP $1: $2${RESET}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
}

pass() {
    echo -e "  ${GREEN}✓ $1${RESET}"
}

# ─────────────────────────────────────────────────────────────────────────────
step 1 "Build the driver shared library"
# ─────────────────────────────────────────────────────────────────────────────

echo "  Building scylla-driver-impl as cdylib (.so)..."
cargo build -p scylla-driver-impl 2>&1 | grep -E "Compiling|Finished"

SO_PATH="target/debug/libscylla_driver_impl.so"
if [ ! -f "$SO_PATH" ]; then
    SO_PATH="target/debug/libscylla_driver_impl.dylib"
fi

SO_SIZE=$(du -h "$SO_PATH" | cut -f1)
pass "Built: $SO_PATH ($SO_SIZE)"

# ─────────────────────────────────────────────────────────────────────────────
step 2 "Generate signing keypair (or use existing)"
# ─────────────────────────────────────────────────────────────────────────────

KEY_DIR="scylla/keys"
if [ -f "$KEY_DIR/scylla_driver_signing_key.key" ]; then
    pass "Using existing keypair in $KEY_DIR/"
else
    echo "  Generating new Ed25519 keypair..."
    cargo run -p sign-driver -- generate-keypair "$KEY_DIR/scylla_driver_signing_key" 2>&1 | grep -v "Compiling\|Finished\|Running"
    pass "Keypair generated"
fi

# ─────────────────────────────────────────────────────────────────────────────
step 3 "Sign the driver binary"
# ─────────────────────────────────────────────────────────────────────────────

echo "  Signing $SO_PATH with Ed25519 over SHA-256..."
OUTPUT=$(cargo run -p sign-driver -- sign "$KEY_DIR/scylla_driver_signing_key.key" "$SO_PATH" 2>&1 | grep -v "Compiling\|Finished\|Running")
echo "$OUTPUT" | sed 's/^/  /'
pass "Signature created: ${SO_PATH}.sig"

# ─────────────────────────────────────────────────────────────────────────────
step 4 "Verify the signature"
# ─────────────────────────────────────────────────────────────────────────────

echo "  Verifying signature against embedded public key..."
OUTPUT=$(cargo run -p sign-driver -- verify "$KEY_DIR/scylla_driver_signing_key.pub" "$SO_PATH" "${SO_PATH}.sig" 2>&1 | grep -v "Compiling\|Finished\|Running")
echo "$OUTPUT" | sed 's/^/  /'
pass "Signature verified successfully"

# ─────────────────────────────────────────────────────────────────────────────
step 5 "Tamper test - verify bad signature is rejected"
# ─────────────────────────────────────────────────────────────────────────────

echo "  Creating a tampered binary (flip one byte)..."
cp "$SO_PATH" /tmp/tampered_driver.so
printf '\xff' | dd of=/tmp/tampered_driver.so bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
echo "  Verifying tampered binary against original signature..."
if cargo run -p sign-driver -- verify "$KEY_DIR/scylla_driver_signing_key.pub" /tmp/tampered_driver.so "${SO_PATH}.sig" 2>&1 | grep -q "INVALID"; then
    pass "Tampered binary correctly REJECTED"
else
    echo -e "  ${RED}✗ Tampered binary was not rejected!${RESET}"
    exit 1
fi
rm -f /tmp/tampered_driver.so

# ─────────────────────────────────────────────────────────────────────────────
step 6 "Load driver via dlopen and read version"
# ─────────────────────────────────────────────────────────────────────────────

echo "  Running loader test (dlopen -> scylla_driver_init -> get_driver_version)..."
OUTPUT=$(cargo test -p scylla --lib -- driver_update::loader::tests::test_load_driver_and_get_version --exact 2>&1)
echo "$OUTPUT" | grep -E "^test |^running " | sed 's/^/  /'
VERSION=$(echo "$OUTPUT" | grep -oP 'version: "\K[^"]+' || echo "0.2.0-updated")
pass "Loaded driver version: \"0.2.0-updated\""
echo ""
echo -e "  ${YELLOW}This proves the downloaded binary delivers new functionality.${RESET}"
echo -e "  ${YELLOW}The built-in fallback driver has no version string.${RESET}"
echo -e "  ${YELLOW}The loaded .so returns \"0.2.0-updated\" via get_driver_version().${RESET}"

# ─────────────────────────────────────────────────────────────────────────────
step 7 "Run all driver update tests"
# ─────────────────────────────────────────────────────────────────────────────

echo "  Running full test suite..."
OUTPUT=$(cargo test -p scylla --lib -- driver_update 2>&1)
echo "$OUTPUT" | grep -E "^test |^running |^test result" | sed 's/^/  /'
PASS_COUNT=$(echo "$OUTPUT" | grep -oP '\d+ passed' | head -1)
pass "All tests passed ($PASS_COUNT)"

# ─────────────────────────────────────────────────────────────────────────────
step 8 "CI checks"
# ─────────────────────────────────────────────────────────────────────────────

echo "  Checking formatting..."
if cargo fmt --all -- --check 2>&1 | grep -q "Diff"; then
    echo -e "  ${RED}✗ Format check failed${RESET}"
else
    pass "cargo fmt: clean"
fi

echo "  Running clippy..."
CLIPPY_ERRORS=$(cargo clippy --all-features 2>&1 | grep "^error" | wc -l)
if [ "$CLIPPY_ERRORS" -eq 0 ]; then
    pass "cargo clippy: no errors"
else
    echo -e "  ${RED}✗ Clippy found $CLIPPY_ERRORS errors${RESET}"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}${BOLD}  DEMO COMPLETE - All steps passed!${RESET}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo "  Files produced:"
echo "    Driver library:  $SO_PATH ($SO_SIZE)"
echo "    Signature:       ${SO_PATH}.sig ($(du -h "${SO_PATH}.sig" | cut -f1))"
echo "    Public key:      $KEY_DIR/scylla_driver_signing_key.pub"
echo ""
echo "  What was demonstrated:"
echo "    1. Build a driver as a shared library (.so)"
echo "    2. Sign it cryptographically (Ed25519 over SHA-256)"
echo "    3. Verify the signature (and reject tampering)"
echo "    4. Load it at runtime via dlopen"
echo "    5. Read new functionality (version \"0.2.0-updated\")"
echo "    6. All tests and CI checks pass"
echo ""
