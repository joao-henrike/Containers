"""Professional Forensics Container — Python package.

This package contains the core libraries that power the forensic-pro CLI tools:

- :mod:`forensics.audit`     — immutable audit logging with cryptographic signatures
- :mod:`forensics.chain`     — automatic shell-command chain-of-custody capture
- :mod:`forensics.modules`   — modular tool installer and registry manager
- :mod:`forensics.quantum`   — post-quantum (ML-DSA-65) authentication helpers
- :mod:`forensics.health`    — runtime health probes and telemetry

The package version is read from a single source of truth: the ``VERSION`` file
at the project root. Do not hard-code the version anywhere else.
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["__version__", "PACKAGE_NAME"]

PACKAGE_NAME = "forensics-professional"


def _read_version() -> str:
    """Return the project version, looked up from the ``VERSION`` file."""
    candidates = []
    fh = os.environ.get("FORENSICS_HOME")
    if fh:
        candidates.append(Path(fh) / "VERSION")

    here = Path(__file__).resolve()
    for parent in here.parents:
        candidates.append(parent / "VERSION")

    for candidate in candidates:
        try:
            text = candidate.read_text(encoding="utf-8").strip()
            if text:
                return text
        except (OSError, UnicodeDecodeError):
            continue
    return "unknown"


__version__ = _read_version()
