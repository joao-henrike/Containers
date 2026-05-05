"""Generate an ML-DSA-65 (Dilithium) keypair for quantum-root.

This was the missing piece in the previous version: ``quantum-root.sh``
expected ``dilithium_private.key.enc`` to exist, but no code path
actually produced one. This module fixes that.

The private key is encrypted with AES-256-GCM (authenticated encryption)
using a key derived from the user's passphrase via Argon2id. The
ciphertext layout is::

    magic     [4 bytes]   "MDSA"
    version   [1 byte]    1
    salt      [16 bytes]  Argon2id salt
    nonce     [12 bytes]  GCM nonce
    ct + tag  [N+16 bytes] ML-DSA-65 secret key + GCM tag

Total file size ≈ 4 + 1 + 16 + 12 + 4032 + 16 = 4081 bytes for ML-DSA-65.

This is intentionally simpler than libsodium's ``crypto_secretbox`` so
that ``openssl`` can decrypt it during incident response if Python is
unavailable on the analysis host (with a known-good libsodium binary).
"""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys
from pathlib import Path

# AES-256-GCM via cryptography (always available — required by the package)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Argon2id KDF
try:
    from argon2.low_level import Type, hash_secret_raw
    HAVE_ARGON2 = True
except ImportError:
    HAVE_ARGON2 = False

# liboqs-python — optional, only needed for actual key generation.
try:
    import oqs  # type: ignore[import-not-found]
    HAVE_OQS = True
except ImportError:
    HAVE_OQS = False


MAGIC = b"MDSA"
FORMAT_VERSION = 1
SALT_BYTES = 16
NONCE_BYTES = 12
ARGON2_TIME_COST = 3        # iterations
ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 2
KEY_BYTES = 32               # AES-256


def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
    if HAVE_ARGON2:
        return hash_secret_raw(
            secret=passphrase,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_KIB,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_BYTES,
            type=Type.ID,
        )
    # Fallback: scrypt via cryptography (still strong, more widely available).
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=KEY_BYTES, n=2 ** 17, r=8, p=1).derive(passphrase)


def encrypt_secret(secret_key: bytes, passphrase: str) -> bytes:
    """Encrypt *secret_key* into the on-disk container format."""
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    key = _derive_key(passphrase.encode("utf-8"), salt)
    ciphertext = AESGCM(key).encrypt(nonce, secret_key, associated_data=MAGIC)

    # Wipe key locally — best-effort in CPython (immutable bytes; new alloc).
    del key

    blob = (
        MAGIC
        + bytes([FORMAT_VERSION])
        + salt
        + nonce
        + ciphertext
    )
    return blob


def decrypt_secret(blob: bytes, passphrase: str) -> bytes:
    """Inverse of :func:`encrypt_secret`. Raises on failure."""
    if blob[:4] != MAGIC:
        raise ValueError("not a quantum-root key file")
    if blob[4] != FORMAT_VERSION:
        raise ValueError(f"unsupported format version {blob[4]}")
    salt = blob[5 : 5 + SALT_BYTES]
    nonce = blob[5 + SALT_BYTES : 5 + SALT_BYTES + NONCE_BYTES]
    ct = blob[5 + SALT_BYTES + NONCE_BYTES :]
    key = _derive_key(passphrase.encode("utf-8"), salt)
    return AESGCM(key).decrypt(nonce, ct, associated_data=MAGIC)


def generate(out_dir: Path, passphrase: str) -> tuple[Path, Path]:
    """Generate a fresh ML-DSA-65 keypair under *out_dir*.

    Returns ``(encrypted_private_path, public_path)``.
    """
    if not HAVE_OQS:
        raise RuntimeError(
            "liboqs-python is not installed. Build the container image, "
            "or install via: pip install liboqs-python"
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    priv_path = out_dir / "dilithium_private.key.enc"
    pub_path  = out_dir / "dilithium_public.key"

    if priv_path.exists():
        raise FileExistsError(f"{priv_path} already exists; remove it first")

    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    enc = encrypt_secret(secret_key, passphrase)

    # Atomic write with strict perms.
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, enc)
    finally:
        os.close(fd)

    pub_path.write_bytes(public_key)
    pub_path.chmod(0o644)

    return priv_path, pub_path


# ── CLI ──────────────────────────────────────────────────────────────────────

def _read_passphrase(confirm: bool) -> str:
    pw = getpass.getpass("ML-DSA-65 key passphrase: ")
    if confirm:
        pw2 = getpass.getpass("confirm: ")
        if pw != pw2:
            raise SystemExit("passphrases differ")
    if len(pw) < 12:
        raise SystemExit("passphrase must be at least 12 characters")
    return pw


def _cli(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="quantum-keygen",
        description="Generate a passphrase-encrypted ML-DSA-65 keypair "
                    "for quantum-root authentication.",
    )
    p.add_argument("--out-dir", type=Path,
                   default=Path("/opt/forensics/quantum-keys"),
                   help="Where to write the keypair.")
    p.add_argument("--passphrase-file", type=Path,
                   help="Read passphrase from this file (otherwise prompt).")
    args = p.parse_args(argv)

    if args.passphrase_file:
        passphrase = args.passphrase_file.read_text(encoding="utf-8").strip()
    else:
        passphrase = _read_passphrase(confirm=True)

    try:
        priv, pub = generate(args.out_dir, passphrase)
    except Exception as exc:
        sys.stderr.write(f"key generation failed: {exc}\n")
        return 1

    print(f"private (encrypted): {priv}")
    print(f"public:              {pub}")
    print()
    print("Keep the passphrase outside this container. There is NO recovery.")
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
