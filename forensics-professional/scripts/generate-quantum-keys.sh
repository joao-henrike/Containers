#!/usr/bin/env bash
# ==============================================================================
# generate-quantum-keys.sh — convenience wrapper for forensics.quantum.keygen
# ==============================================================================
# Usage:
#   sudo forensics-health      # ensure liboqs is present
#   /opt/forensics/bin/generate-quantum-keys.sh
#
# Output:
#   /opt/forensics/quantum-keys/dilithium_private.key.enc
#   /opt/forensics/quantum-keys/dilithium_public.key
# ==============================================================================

set -euo pipefail

KEYS_DIR="${FORENSICS_KEYS:-/opt/forensics/quantum-keys}"

if ! python3 -c 'import oqs' >/dev/null 2>&1; then
    cat >&2 <<EOF
liboqs-python is not installed. Rebuild the container image, or install
manually with:
    pip3 install liboqs-python
This requires liboqs.so to be available system-wide (provided by the
Dockerfile's pqc-builder stage).
EOF
    exit 1
fi

mkdir -p "${KEYS_DIR}"
exec python3 -m forensics.quantum.keygen --out-dir "${KEYS_DIR}"
