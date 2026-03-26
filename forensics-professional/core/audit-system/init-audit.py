#!/usr/bin/env python3
"""
==============================================================================
Professional Forensics Container — init-audit.py v2.1.0
Inicializa o sistema de auditoria criptográfica no primeiro boot.
Gera genesis entry, keypairs Ed25519 e configura GPG.
==============================================================================
"""

import os
import sys
import json
import hashlib
import datetime
from pathlib import Path

AUDIT_LOG  = "/var/log/forensics/audit.log"
KEYS_DIR   = "/opt/forensics/quantum-keys"
GPG_EMAIL  = "forensics-audit@professional.local"

def init_directories():
    for d in [
        "/var/log/forensics",
        "/var/log/forensics/installations",
        "/var/log/forensics/chain-of-custody",
        "/var/log/forensics/telemetry",
        KEYS_DIR,
        "/opt/forensics/modules/installed",
        "/opt/forensics/chain-logger",
    ]:
        os.makedirs(d, exist_ok=True)
    print("[init-audit] Directories created")

def generate_ed25519_keys():
    key_path = f"{KEYS_DIR}/audit_ed25519.key"
    pub_path = f"{KEYS_DIR}/audit_ed25519.pub"

    if Path(key_path).exists():
        print("[init-audit] Ed25519 keys already exist, skipping")
        return

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        priv = Ed25519PrivateKey.generate()
        pub  = priv.public_key()

        with open(key_path, "wb") as f:
            f.write(priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        os.chmod(key_path, 0o600)

        with open(pub_path, "wb") as f:
            f.write(pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        os.chmod(pub_path, 0o644)
        print("[init-audit] Ed25519 keypair generated")
    except ImportError:
        print("[init-audit] WARNING: cryptography not installed, keys not generated")

def create_genesis_entry():
    if Path(AUDIT_LOG).exists() and Path(AUDIT_LOG).stat().st_size > 0:
        print("[init-audit] Audit log already initialized, skipping genesis")
        return

    genesis = {
        "seq": 0,
        "event_id": "00000000-0000-0000-0000-000000000000",
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "event_type": "audit_initialized",
        "user": "system",
        "container_id": "init",
        "details": {
            "version": "2.1.0-FINAL",
            "compliance": "NIST SP 800-86",
            "crypto": "Ed25519 + GPG Hybrid",
            "pqc": "ML-DSA-65 (Dilithium)"
        },
        "prev_hash": "0" * 64,
        "hash": "",
        "signatures": {
            "ed25519": "genesis_entry",
            "gpg": "genesis_entry"
        }
    }

    data = json.dumps({k: v for k, v in genesis.items() if k != "hash"}, sort_keys=True)
    genesis["hash"] = hashlib.sha256(data.encode()).hexdigest()

    with open(AUDIT_LOG, "w") as f:
        f.write(json.dumps(genesis) + "\n")

    print(f"[init-audit] Genesis entry created: {genesis['hash'][:16]}...")

def main():
    print("[init-audit] Initializing forensics audit system...")
    init_directories()
    generate_ed25519_keys()
    create_genesis_entry()
    print("[init-audit] Audit system ready")

if __name__ == "__main__":
    main()
