"""Shared pytest fixtures."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Make the in-tree package importable regardless of where pytest is invoked.
_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "core"))


@pytest.fixture()
def tmp_audit_env(tmp_path: Path, monkeypatch):
    """Provide an isolated audit environment under *tmp_path*.

    Uses environment overrides + reload to avoid touching production paths.
    """
    keys_dir = tmp_path / "keys"
    log_dir = tmp_path / "logs"
    keys_dir.mkdir()
    log_dir.mkdir()

    monkeypatch.setenv("FORENSICS_CONFIG_FILE", "/nonexistent")
    monkeypatch.setenv("FORENSICS_HOME", str(tmp_path))

    # Reload config singleton with the temp paths.
    from forensics import config as fc
    fc._singleton = None
    fc._DEFAULTS["audit"]["log_path"] = str(log_dir / "audit.log")
    fc._DEFAULTS["audit"]["error_log"] = str(log_dir / "audit.errors.log")
    fc._DEFAULTS["paths"]["keys"] = str(keys_dir)
    fc._DEFAULTS["modules"]["installed_dir"] = str(tmp_path / "installed")
    fc._DEFAULTS["modules"]["install_log_dir"] = str(tmp_path / "install-logs")

    # Generate Ed25519 keys so the audit logger can sign.
    from forensics.audit.keygen import generate_ed25519
    generate_ed25519(keys_dir)

    # Reset audit logger singleton too.
    from forensics.audit import logger as al
    al._singleton = None

    yield {"tmp_path": tmp_path, "keys_dir": keys_dir, "log_dir": log_dir}

    # Cleanup
    fc._singleton = None
    al._singleton = None
