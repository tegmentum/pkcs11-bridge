#!/usr/bin/env bash
# Phase 4.6 verification driver.
#
# Composes pkcs11-bridge + pkcs11-provider + softhsm2.component into
# a single wasm, then runs the native harness which loads it under
# wasmtime, calls tegmentum:key-backend.key.new(URI) + key.sign +
# key.public_key_info, and verifies the returned signature against
# the returned SPKI using openssl-rs.
#
# Pre-reqs:
#   ~/git/pkcs11-bridge/target/wasm32-wasip2/release/pkcs11_bridge.wasm
#   ~/git/softhsm-wasm/pkcs11-provider/target/wasm32-wasip2/release/pkcs11_provider.wasm
#   ~/git/softhsm-wasm/artifacts/softhsm2.component.wasm
#
# Token provisioning: this script does NOT yet auto-provision a token
# (Phase 4.6 TODO). To run end-to-end you need a pre-initialized
# SoftHSM token + at least one EC or RSA private-key object with the
# label matching the URI's object= attribute. The keystore-pkcs11
# harness in ~/git/softhsm-wasm is the easiest way to bootstrap one.

set -euo pipefail
cd "$(dirname "$0")"

BRIDGE_WASM="$(cd .. && pwd)/target/wasm32-wasip2/release/pkcs11_bridge.wasm"
PROVIDER_WASM="$HOME/git/softhsm-wasm/pkcs11-provider/target/wasm32-wasip2/release/pkcs11_provider.wasm"
SOFTHSM_WASM="$HOME/git/softhsm-wasm/artifacts/softhsm2.component.wasm"
STACK_WASM="/tmp/pkcs11-bridge-stack.wasm"

for w in "$BRIDGE_WASM" "$PROVIDER_WASM" "$SOFTHSM_WASM"; do
  if [ ! -f "$w" ]; then
    echo "ERROR: missing wasm: $w" >&2
    exit 2
  fi
done

# Compose bridge + provider + softhsm => stack.
wac plug "$BRIDGE_WASM" --plug "$PROVIDER_WASM" -o /tmp/bridge-with-provider.wasm
wac plug /tmp/bridge-with-provider.wasm --plug "$SOFTHSM_WASM" -o "$STACK_WASM"
echo "composed $STACK_WASM ($(stat -f%z "$STACK_WASM" 2>/dev/null || stat -c%s "$STACK_WASM") bytes)"

# Run.
cargo run --release --quiet -- \
  "$STACK_WASM" \
  softhsm2-wasi.conf \
  "${URI:-pkcs11:slot-id=0;object=phase-4-key;pin-value=1234}"
