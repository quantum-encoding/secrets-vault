#!/bin/bash
# Sign the `secrets` CLI with Developer ID + the keychain-access-groups
# entitlement, so the biometric-gated Keychain master key binds to this binary's
# code signature. Re-run after every `cargo build` (the signature lives on the
# binary; rebuilding strips it). The access group string is stable across
# rebuilds, so previously-stored items stay reachable.
#
# Usage:  ./sign.sh [path-to-binary]    (defaults to target/release/secrets)
set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="${1:-$SCRIPT_DIR/target/release/secrets}"

# Prefer the Developer ID Application cert (stable, distributable); fall back to
# Apple Development for local-only testing.
IDENTITY=$(security find-identity -v -p codesigning | grep "Developer ID Application: Quantum Encoding Ltd" | head -1 | sed 's/.*"\(.*\)".*/\1/')
[ -z "$IDENTITY" ] && IDENTITY=$(security find-identity -v -p codesigning | grep "Apple Development" | head -1 | sed 's/.*"\(.*\)".*/\1/')

if [ -z "$IDENTITY" ]; then echo -e "${RED}No signing identity found.${NC}"; exit 1; fi
if [ ! -f "$BINARY" ]; then echo -e "${RED}Binary not found: $BINARY${NC} (run 'cargo build --release')"; exit 1; fi

echo -e "${CYAN}Signing${NC} $BINARY"
echo -e "${CYAN}Identity:${NC} $IDENTITY"

# Developer ID signature WITH the keychain-access-groups entitlement — REQUIRED
# for the biometric Keychain item (proven: without it SecItemAdd → -34018). The
# team-prefixed group is profile-free, so no provisioning profile is needed.
ENTITLEMENTS="$SCRIPT_DIR/secrets.entitlements"
[ -f "$ENTITLEMENTS" ] || { echo -e "${RED}Missing $ENTITLEMENTS${NC}"; exit 1; }
codesign --sign "$IDENTITY" \
    --entitlements "$ENTITLEMENTS" \
    --options runtime \
    --force --timestamp \
    "$BINARY"

echo -e "${CYAN}Verifying…${NC}"
codesign --verify --strict --verbose=2 "$BINARY"

echo -e "${GREEN}Signed.${NC} Biometric Keychain access is bound to this Developer ID signature."
