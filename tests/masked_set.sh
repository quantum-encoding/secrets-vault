#!/usr/bin/env bash
# End-to-end test of the masked interactive `secrets set` prompt, via an `expect`
# PTY. Verifies two properties:
#   1. Masking      — the plaintext value is never echoed (only bullets).
#   2. Capture      — the typed value, including a mid-word Backspace edit,
#                     round-trips through the vault byte-for-byte.
#
# Runs against a throwaway SECRETS_DIR + SECRETS_PASSPHRASE, so it never touches
# the real vault and needs no Touch ID (get_passphrase honours SECRETS_PASSPHRASE
# before the Keychain). Skips cleanly if `expect` isn't installed.
#
#   cargo build --release && tests/masked_set.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${SECRETS_BIN:-$ROOT/target/release/secrets}"

command -v expect >/dev/null 2>&1 || { echo "SKIP: expect not installed"; exit 0; }
[ -x "$BIN" ] || { echo "FAIL: binary not found at $BIN (run: cargo build --release)"; exit 1; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export SECRETS_BIN="$BIN"
export SECRETS_DIR="$TMP"
export SECRETS_PASSPHRASE="masked-test-$$"

# 1. Drive the interactive prompt; assert the value was masked (not echoed).
expect "$ROOT/tests/masked_set.exp"

# 2. Round-trip: "topX" + Backspace + "-secret" must have captured "top-secret".
GOT="$("$BIN" get MASKED_TEST)"
if [ "$GOT" = "top-secret" ]; then
  echo "PASS: masked prompt + backspace edit round-tripped to 'top-secret'"
else
  echo "FAIL: round-trip mismatch — got '$GOT', want 'top-secret'"
  exit 1
fi
