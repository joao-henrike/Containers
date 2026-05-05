"""Challenge-response authentication using ML-DSA-65.

The flow is:

    1. The verifier generates a random 32-byte challenge.
    2. The user supplies the passphrase that decrypts the private key.
    3. The challenge is signed with the decrypted private key.
    4. The signature is verified against the public key.
    5. On success, the caller is granted a privileged shell.

There is **no** "fallback success" path. If liboqs-python isn't available
or the keys are missing, authentication fails — explicitly.

The module is designed to be invoked from a shell wrapper (``quantum-root``)
that handles the actual privilege escalation via ``sudo``. This separation
keeps the cryptography in Python (where it is testable) and the OS-level
privilege drop in the shell (where it must be).
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import oqs  # type: ignore[import-not-found]
    HAVE_OQS = True
except ImportError:
    HAVE_OQS = False

from forensics.config import get_config
from forensics.quantum.keygen import decrypt_secret


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log_attempt(result: str, *, user: str, detail: str = "") -> None:
    """Append an attempt record to /var/log/forensics/auth/quantum-root.log."""
    log_dir = Path("/var/log/forensics/auth")
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        with (log_dir / "quantum-root.log").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "timestamp": _utcnow(),
                "event":     "quantum_root_attempt",
                "user":      user,
                "result":    result,
                "detail":    detail,
            }) + "\n")
    except OSError:
        pass

    # Also tag the main audit trail (best effort).
    try:
        from forensics.audit.logger import log_event
        log_event(
            "privilege_escalation_attempt",
            {
                "method":    "quantum_root",
                "algorithm": "ML-DSA-65",
                "result":    result,
                "detail":    detail,
            },
            user=user,
        )
    except Exception:
        pass


def authenticate(*, passphrase: str | None = None) -> bool:
    """Perform a challenge-response authentication. Returns True on success.

    *passphrase*: if supplied, used directly (mostly for tests). Otherwise the
    function reads it from the controlling tty using :func:`getpass.getpass`.
    """
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown"
    cfg = get_config()
    priv_path = Path(cfg.quantum.private_key)
    pub_path  = Path(cfg.quantum.public_key)

    if not HAVE_OQS:
        _log_attempt("FAIL_NO_LIBOQS", user=user)
        sys.stderr.write(
            "liboqs-python is not installed. Quantum authentication is "
            "disabled. Install via: pip install liboqs-python\n")
        return False

    if not priv_path.exists() or not pub_path.exists():
        _log_attempt("FAIL_NO_KEY", user=user, detail=str(priv_path))
        sys.stderr.write(
            f"keypair not found at {priv_path.parent}.\n"
            "Generate with: quantum-keygen\n")
        return False

    if passphrase is None:
        passphrase = getpass.getpass("ML-DSA-65 passphrase: ")

    # Decrypt private key
    try:
        secret_key = decrypt_secret(priv_path.read_bytes(), passphrase)
    except Exception as exc:
        # Generic message so timing/error doesn't leak whether the file is
        # corrupt vs. the passphrase wrong.
        _log_attempt("FAIL_DECRYPT", user=user, detail=type(exc).__name__)
        time.sleep(0.5)  # mild timing-attack mitigation
        sys.stderr.write("authentication failed\n")
        return False

    public_key = pub_path.read_bytes()

    # Generate fresh challenge & sign-and-verify
    challenge = secrets.token_bytes(32)
    try:
        with oqs.Signature("ML-DSA-65", secret_key=secret_key) as signer:
            signature = signer.sign(challenge)
        with oqs.Signature("ML-DSA-65") as verifier:
            valid = verifier.verify(challenge, signature, public_key)
    except Exception as exc:
        _log_attempt("FAIL_SIG_OP", user=user, detail=type(exc).__name__)
        sys.stderr.write("authentication failed\n")
        return False
    finally:
        # Best-effort wipe (Python bytes are immutable; we just drop the ref)
        del secret_key

    if not valid:
        _log_attempt("FAIL_BAD_SIG", user=user)
        sys.stderr.write("authentication failed\n")
        return False

    _log_attempt("SUCCESS", user=user)
    return True


def _cli(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="quantum-auth",
        description="Run a quantum-root authentication challenge.",
    )
    p.add_argument("--passphrase-file", type=Path,
                   help="Read passphrase from file (otherwise prompt).")
    args = p.parse_args(argv)

    pw = None
    if args.passphrase_file:
        pw = args.passphrase_file.read_text(encoding="utf-8").strip()

    return 0 if authenticate(passphrase=pw) else 1


if __name__ == "__main__":
    sys.exit(_cli())
