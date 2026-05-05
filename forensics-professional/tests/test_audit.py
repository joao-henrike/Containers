"""Tests for forensics.audit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_genesis_and_chain(tmp_audit_env):
    from forensics.audit.logger import AuditLogger

    log = AuditLogger(strict=True)
    e1 = log.log_event("test_one", {"a": 1}, user="alice")
    e2 = log.log_event("test_two", {"b": 2}, user="bob")
    e3 = log.log_event("test_three", {}, user="charlie")

    assert e1.seq == 1
    assert e2.seq == 2
    assert e3.seq == 3

    # Chain links correctly
    assert e2.prev_hash == e1.hash
    assert e3.prev_hash == e2.hash

    # Verify says VALID
    result = log.verify()
    assert result["status"] == "VALID"
    assert result["total_entries"] == 3
    assert result["broken_links"] == []


def test_tamper_detected(tmp_audit_env):
    from forensics.audit.logger import AuditLogger
    log = AuditLogger(strict=False)
    log.log_event("evt_a", {})
    log.log_event("evt_b", {})

    log_file = Path(log.log_path)
    lines = log_file.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["details"]["tampered"] = True
    lines[0] = json.dumps(entry)
    log_file.write_text("\n".join(lines) + "\n")

    result = log.verify()
    assert result["status"] == "INVALID"
    assert any(b["reason"] == "hash_mismatch" for b in result["broken_links"])


def test_signatures_present(tmp_audit_env):
    from forensics.audit.logger import AuditLogger
    log = AuditLogger(strict=True)
    entry = log.log_event("signed_event", {})
    assert entry.signatures.get("ed25519")
    assert entry.signatures["ed25519"] not in ("", "unsigned", "sign_error")


def test_signature_failure_detected(tmp_audit_env):
    """Modifying the signature itself must fail signature verification."""
    from forensics.audit.logger import AuditLogger
    log = AuditLogger(strict=True)
    log.log_event("evt_one", {})
    log.log_event("evt_two", {})

    log_file = Path(log.log_path)
    lines = log_file.read_text().splitlines()
    entry = json.loads(lines[1])
    # Replace the ed25519 signature with garbage of the same length.
    entry["signatures"]["ed25519"] = "A" * len(entry["signatures"]["ed25519"])
    lines[1] = json.dumps(entry)
    log_file.write_text("\n".join(lines) + "\n")

    result = log.verify()
    assert result["status"] == "INVALID"
    assert any(s["seq"] == entry["seq"] for s in result["signature_failures"])


def test_show_filters(tmp_audit_env):
    from forensics.audit.logger import AuditLogger
    log = AuditLogger(strict=True)
    log.log_event("type_a", {}, user="alice")
    log.log_event("type_b", {}, user="bob")
    log.log_event("type_a", {}, user="alice")

    a_only = log.show_entries(event_type="type_a")
    assert len(a_only) == 2
    assert all(e["event_type"] == "type_a" for e in a_only)

    bob_only = log.show_entries(user="bob")
    assert len(bob_only) == 1
    assert bob_only[0]["user"] == "bob"


def test_stats_output(tmp_audit_env):
    from forensics.audit.logger import AuditLogger
    log = AuditLogger(strict=True)
    log.log_event("type_a", {})
    log.log_event("type_b", {})
    log.log_event("type_a", {})

    stats = log.stats()
    assert stats["total_entries"] == 3
    assert stats["event_counts"]["type_a"] == 2
    assert stats["event_counts"]["type_b"] == 1


def test_empty_log_status(tmp_audit_env):
    from forensics.audit.logger import AuditLogger
    log = AuditLogger(strict=True)
    result = log.verify()
    assert result["status"] == "EMPTY"
    assert result["total_entries"] == 0
