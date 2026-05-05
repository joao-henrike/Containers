"""Audit bootstrap — runs from the container entrypoint.

This module is invoked as ``python3 -m forensics.audit.bootstrap``. It is
deliberately small: it exists to keep startup logic out of the entrypoint
shell script (where bugs are silent) and inside Python (where they aren't).

Subcommands:

    genesis     Append the very first entry (sequence 0) when the log is empty.
    log-start   Append a 'container_started' event each container start.
"""

from __future__ import annotations

import argparse
import sys

from forensics.audit.logger import get_logger


def cmd_genesis(args: argparse.Namespace) -> int:
    """Write the initial entry of an empty log."""
    log = get_logger()
    if log.stats().get("total_entries", 0) > 0:
        return 0  # Already initialised; idempotent.

    log.log_event(
        "audit_initialised",
        {
            "version":     args.version,
            "compliance":  "NIST SP 800-86",
            "primary_sig": "Ed25519",
            "legal_sig":   "GPG (RSA-4096)",
            "pq_sig":      "ML-DSA-65 (optional)",
        },
        user="system",
    )
    return 0


def cmd_log_start(args: argparse.Namespace) -> int:
    """Record the container-start event."""
    log = get_logger()
    log.log_event(
        "container_started",
        {
            "version":      args.version,
            "user_session": "sherlock",
        },
        user="system",
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="forensics-audit-bootstrap",
        description="One-shot audit-log bootstrap helpers for the entrypoint.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("genesis", help="Initialise an empty audit log.")
    g.add_argument("--version", default="unknown")
    g.set_defaults(fn=cmd_genesis)

    s = sub.add_parser("log-start", help="Record a container_started event.")
    s.add_argument("--version", default="unknown")
    s.set_defaults(fn=cmd_log_start)

    args = p.parse_args(argv)
    return int(args.fn(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
