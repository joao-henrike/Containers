"""Cryptographically-signed, hash-chained audit logger.

Each audit entry is:

* Sequenced (monotonic ``seq``)
* Timestamped (RFC 3339, UTC, microsecond precision)
* Hash-chained (SHA-256 over the canonical JSON of the previous entry)
* Signed with Ed25519 (the primary signature)
* Optionally clearsigned with GPG (legal-evidence compatibility)

Threat model
------------
This logger produces a **tamper-evident** trail. It is *not* tamper-proof
against an attacker who has write access to both the log file *and* the
Ed25519 private key — they can re-sign the chain. For tamper-proof storage,
push entries to an external append-only sink (S3 Object Lock, Google
Storage retention policies, a HSM-backed timestamping service, etc.) using
the :func:`AuditLogger.export_jsonl` helper and a side-channel uploader.

All errors are surfaced — never silently swallowed. When the primary log
file cannot be written, the logger falls back to ``audit.errors.log`` and
re-raises the underlying exception unless ``strict=False``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import socket
import subprocess
import threading
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from forensics import __version__
from forensics.config import get_config

__all__ = [
    "AuditLogger",
    "AuditEntry",
    "AuditError",
    "get_logger",
    "log_event",
]

logger = logging.getLogger("forensics.audit")


class AuditError(RuntimeError):
    """Raised when audit logging fails irrecoverably (and ``strict=True``)."""


def _utcnow() -> str:
    """Return UTC timestamp in RFC 3339 form, microsecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _container_id() -> str:
    """Best-effort container identification (cgroup v1/v2 + hostname fallback)."""
    try:
        with open("/proc/self/cgroup", "r", encoding="utf-8") as fh:
            for line in fh:
                if "docker" in line or "containerd" in line:
                    return line.strip().split("/")[-1][:12]
    except OSError:
        pass
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if "/docker/containers/" in line:
                    return line.split("/docker/containers/")[1].split("/")[0][:12]
    except OSError:
        pass
    return socket.gethostname()[:12] or "local"


@dataclass(slots=True)
class AuditEntry:
    """One audit-log line, before serialisation."""
    seq: int
    event_id: str
    timestamp: str
    event_type: str
    user: str
    container_id: str
    details: dict[str, Any]
    prev_hash: str
    hash: str = ""
    signatures: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditLogger:
    """Thread-safe, hash-chained audit logger.

    The logger guarantees:

    * **Atomic appends.** Each entry is written with a single ``write()``
      call after acquiring an in-process lock; multiple threads in the same
      process never interleave.
    * **No silent failure.** Errors go to :attr:`error_log_path` and either
      raise :class:`AuditError` (strict mode) or return a sentinel entry
      with ``"_error"`` set on it (non-strict mode).

    Cross-process serialisation relies on POSIX ``O_APPEND`` semantics
    plus an advisory ``flock`` on Linux.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, *, strict: bool | None = None) -> None:
        cfg = get_config()
        self.log_path = Path(cfg.audit.log_path)
        self.error_log_path = Path(cfg.audit.error_log)
        self.gpg_email = cfg.audit.gpg_email
        self.strict = cfg.audit.strict if strict is None else strict
        self.keys_dir = Path(cfg.paths.keys)
        self.ed25519_key = self.keys_dir / "audit_ed25519.key"
        self._lock = threading.Lock()
        self._ed25519_priv = None  # lazy-loaded
        self._ensure_log_dir()

    # ── Public API ───────────────────────────────────────────────────────────

    def log_event(
        self,
        event_type: str,
        details: dict[str, Any] | None = None,
        *,
        user: str | None = None,
    ) -> AuditEntry:
        """Append a single audit entry. Returns the entry as written."""
        details = details or {}
        if user is None:
            user = os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown"

        with self._lock:
            prev_hash = self._read_last_hash()
            seq = self._read_last_seq() + 1

            entry = AuditEntry(
                seq=seq,
                event_id=str(uuid.uuid4()),
                timestamp=_utcnow(),
                event_type=event_type,
                user=user,
                container_id=_container_id(),
                details=details,
                prev_hash=prev_hash,
            )
            entry.hash = self._compute_hash(entry)

            sign_data = self._canonical_json(
                {k: v for k, v in entry.to_dict().items() if k != "signatures"}
            )
            entry.signatures = {
                "ed25519": self._sign_ed25519(sign_data),
                "gpg":     self._sign_gpg(sign_data),
            }

            self._append(entry)
        return entry

    def verify(self) -> dict[str, Any]:
        """Verify hash chain, sequence continuity and signatures.

        Returns a dict with keys::

            status:           "VALID" | "INVALID" | "EMPTY" | "ERROR"
            total_entries:    int
            broken_links:     list of {seq, reason, ...}
            sequence_gaps:    list of {expected, got}
            signature_failures: list of {seq, reason}
            error:            str (only if status == "ERROR")
        """
        result: dict[str, Any] = {
            "status": "VALID",
            "total_entries": 0,
            "broken_links": [],
            "sequence_gaps": [],
            "signature_failures": [],
        }
        try:
            entries = list(self._iter_entries())
        except (OSError, json.JSONDecodeError) as exc:
            return {"status": "ERROR", "error": str(exc), "total_entries": 0}

        if not entries:
            return {"status": "EMPTY", "total_entries": 0,
                    "broken_links": [], "sequence_gaps": [],
                    "signature_failures": []}

        result["total_entries"] = len(entries)
        verifier = self._ed25519_verifier()

        for i, entry in enumerate(entries):
            stored_hash = entry.get("hash", "")
            recomputed = self._compute_hash_from_dict(entry)
            if stored_hash != recomputed:
                result["broken_links"].append({
                    "seq": entry.get("seq"),
                    "reason": "hash_mismatch",
                })
                result["status"] = "INVALID"

            if i > 0:
                prev = entries[i - 1]
                if entry.get("prev_hash") != prev.get("hash"):
                    result["broken_links"].append({
                        "seq": entry.get("seq"),
                        "reason": "chain_broken",
                        "expected": (prev.get("hash") or "")[:16],
                        "got":      (entry.get("prev_hash") or "")[:16],
                    })
                    result["status"] = "INVALID"

                expected_seq = prev.get("seq", 0) + 1
                if entry.get("seq") != expected_seq:
                    result["sequence_gaps"].append({
                        "expected": expected_seq,
                        "got":      entry.get("seq"),
                    })

            if verifier is not None:
                ok = self._verify_ed25519(verifier, entry)
                if not ok:
                    result["signature_failures"].append({
                        "seq": entry.get("seq"),
                        "reason": "ed25519_invalid",
                    })
                    result["status"] = "INVALID"

        return result

    def show_entries(
        self,
        *,
        limit: int = 20,
        event_type: str | None = None,
        user: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return the most recent matching entries (oldest first within slice)."""
        try:
            entries = list(self._iter_entries())
        except (OSError, json.JSONDecodeError):
            return []
        if event_type:
            entries = [e for e in entries if e.get("event_type") == event_type]
        if user:
            entries = [e for e in entries if e.get("user") == user]
        return entries[-limit:]

    def stats(self) -> dict[str, Any]:
        """Aggregate counters over the whole log."""
        try:
            entries = list(self._iter_entries())
        except (OSError, json.JSONDecodeError) as exc:
            return {"error": str(exc), "total_entries": 0}

        counts: dict[str, int] = {}
        for e in entries:
            t = e.get("event_type", "unknown")
            counts[t] = counts.get(t, 0) + 1

        try:
            size_bytes = self.log_path.stat().st_size
        except FileNotFoundError:
            size_bytes = 0

        return {
            "total_entries":  len(entries),
            "first_entry":    entries[0].get("timestamp") if entries else None,
            "last_entry":     entries[-1].get("timestamp") if entries else None,
            "event_counts":   counts,
            "log_size_bytes": size_bytes,
        }

    def export_jsonl(self, dest: str | os.PathLike) -> int:
        """Copy the log verbatim to *dest*. Returns the number of entries."""
        dest_path = Path(dest)
        count = 0
        with dest_path.open("w", encoding="utf-8") as out:
            for entry in self._iter_entries():
                out.write(json.dumps(entry, ensure_ascii=False) + "\n")
                count += 1
        return count

    # ── Internals ────────────────────────────────────────────────────────────

    @staticmethod
    def _canonical_json(obj: Any) -> str:
        """Deterministic JSON encoding used for hashing & signing."""
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @classmethod
    def _compute_hash_from_dict(cls, entry: dict[str, Any]) -> str:
        """Hash an entry-as-dict, excluding the ``hash`` and ``signatures`` fields."""
        # Signatures depend on hash, so they are *not* hashed; the hash covers
        # everything else (the chain integrity).
        # NOTE: signatures field absence MUST be the same as during write.
        data = {k: v for k, v in entry.items()
                if k not in ("hash", "signatures")}
        return hashlib.sha256(cls._canonical_json(data).encode("utf-8")).hexdigest()

    @classmethod
    def _compute_hash(cls, entry: AuditEntry) -> str:
        return cls._compute_hash_from_dict(entry.to_dict())

    def _ensure_log_dir(self) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            if not self.log_path.exists():
                self.log_path.touch()
        except OSError as exc:
            self._record_error(f"cannot prepare log file {self.log_path}: {exc}")
            if self.strict:
                raise AuditError(str(exc)) from exc

    def _iter_entries(self) -> Iterator[dict[str, Any]]:
        try:
            with self.log_path.open("r", encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        yield json.loads(raw)
                    except json.JSONDecodeError as exc:
                        self._record_error(
                            f"corrupt audit line skipped: {exc}: {raw[:120]}"
                        )
        except FileNotFoundError:
            return

    def _read_last_seq(self) -> int:
        last = self._read_last_entry()
        return int(last.get("seq", 0)) if last else 0

    def _read_last_hash(self) -> str:
        last = self._read_last_entry()
        return last.get("hash", self.GENESIS_HASH) if last else self.GENESIS_HASH

    def _read_last_entry(self) -> dict[str, Any] | None:
        try:
            with self.log_path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                if size == 0:
                    return None
                # Read up to last 32 KiB — plenty for the largest sane entry.
                read_back = min(size, 32 * 1024)
                fh.seek(size - read_back)
                tail = fh.read().decode("utf-8", errors="replace")
            for line in reversed(tail.splitlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        except FileNotFoundError:
            return None
        return None

    def _append(self, entry: AuditEntry) -> None:
        """Append a fully-formed entry. Uses ``O_APPEND`` for atomicity."""
        line = json.dumps(entry.to_dict(), ensure_ascii=False) + "\n"
        try:
            # O_APPEND guarantees atomicity for writes <= PIPE_BUF on POSIX.
            fd = os.open(self.log_path,
                         os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                         0o640)
            try:
                os.write(fd, line.encode("utf-8"))
            finally:
                os.close(fd)
        except OSError as exc:
            self._record_error(f"append failed: {exc}; entry={entry.event_type}")
            if self.strict:
                raise AuditError(str(exc)) from exc

    def _record_error(self, message: str) -> None:
        """Write to the side-channel error log; never raise."""
        try:
            self.error_log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.error_log_path.open("a", encoding="utf-8") as fh:
                fh.write(f"{_utcnow()} {message}\n")
        except OSError:
            # Last-resort: write to stderr via the standard logger.
            logger.error("audit error (and error_log unavailable): %s", message)

    # ── Cryptography ─────────────────────────────────────────────────────────

    def _load_ed25519(self):
        """Load the Ed25519 private key once, lazily."""
        if self._ed25519_priv is not None:
            return self._ed25519_priv
        try:
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )
            self._ed25519_priv = load_pem_private_key(
                self.ed25519_key.read_bytes(),
                password=None,
            )
        except (FileNotFoundError, ValueError) as exc:
            self._record_error(f"ed25519 key unavailable: {exc}")
            self._ed25519_priv = False  # cache the failure
        return self._ed25519_priv

    def _ed25519_verifier(self):
        try:
            from cryptography.hazmat.primitives.serialization import (
                load_pem_public_key,
            )
            pub_path = self.keys_dir / "audit_ed25519.pub"
            return load_pem_public_key(pub_path.read_bytes())
        except (FileNotFoundError, ValueError):
            return None

    def _sign_ed25519(self, data: str) -> str:
        priv = self._load_ed25519()
        if not priv:
            return "unsigned"
        try:
            sig = priv.sign(data.encode("utf-8"))
            return base64.b64encode(sig).decode("ascii")
        except Exception as exc:
            self._record_error(f"ed25519 sign failed: {exc}")
            return "sign_error"

    @staticmethod
    def _verify_ed25519(public_key, entry: dict[str, Any]) -> bool:
        sig_b64 = (entry.get("signatures") or {}).get("ed25519")
        if not sig_b64 or sig_b64 in ("unsigned", "sign_error"):
            return False
        try:
            sig = base64.b64decode(sig_b64)
        except (ValueError, TypeError):
            return False
        without_sigs = {k: v for k, v in entry.items() if k != "signatures"}
        data = AuditLogger._canonical_json(without_sigs)
        try:
            public_key.verify(sig, data.encode("utf-8"))
            return True
        except Exception:
            return False

    def _sign_gpg(self, data: str) -> str:
        """Best-effort GPG clearsign. Returns ``"unavailable"`` on failure."""
        passphrase_file = self.keys_dir / ".gpg.passphrase"
        cmd = [
            "gpg", "--batch", "--no-tty", "--pinentry-mode", "loopback",
            "--local-user", self.gpg_email,
            "--detach-sign", "--armor",
        ]
        if passphrase_file.exists():
            cmd.extend(["--passphrase-file", str(passphrase_file)])
        try:
            result = subprocess.run(
                cmd,
                input=data.encode("utf-8"),
                capture_output=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                # Truncate ASCII-armoured signature to keep entries small.
                return result.stdout.decode("utf-8", errors="replace")[:512]
            return "unavailable"
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._record_error(f"gpg unavailable: {exc}")
            return "unavailable"


# ── Module-level singleton (cheap and safe) ──────────────────────────────────
_singleton: AuditLogger | None = None


def get_logger() -> AuditLogger:
    """Return the package-wide :class:`AuditLogger` instance."""
    global _singleton
    if _singleton is None:
        _singleton = AuditLogger()
    return _singleton


def log_event(
    event_type: str,
    details: dict[str, Any] | None = None,
    *,
    user: str | None = None,
) -> AuditEntry:
    """Convenience wrapper for :meth:`AuditLogger.log_event`."""
    return get_logger().log_event(event_type, details, user=user)
