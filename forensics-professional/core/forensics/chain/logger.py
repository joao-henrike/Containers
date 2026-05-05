"""Chain-of-custody recorder — captures shell commands.

This module is invoked **once per command** from ``bash-hooks.sh``
(asynchronously, in a backgrounded subshell). It must therefore be:

* **Fast** — adds no noticeable latency to the analyst's prompt.
* **Resilient** — never propagates errors back into the parent shell.
* **Filtering** — high-frequency, non-investigative commands (``ls``,
  ``cd``, ``pwd``, the prompt itself…) are dropped to keep the log
  signal-to-noise high.

The logger reads its inputs from environment variables set by
``bash-hooks.sh``. See ``post`` in this module for the contract.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Commands that produce noise but no forensic value.
NOISY_PREFIXES: frozenset[str] = frozenset({
    "ls", "cd", "pwd", "clear", "history", "echo", "alias",
    "export", "unset", "type", "which", "command", "set",
    "true", "false", ":", "exit", "logout", "tput",
    "forensics_precmd", "forensics_preexec", "PROMPT_COMMAND",
})

# Commands that, conversely, MUST always be logged regardless of NOISY_PREFIXES.
ALWAYS_LOG: frozenset[str] = frozenset({
    "dd", "cat", "rm", "mv", "cp", "mount", "umount", "mkfs",
    "tcpdump", "tshark", "wireshark", "vol.py", "volatility",
    "vol3", "tsk_recover", "fls", "icat", "ils", "mmls", "mmcat",
    "fsstat", "blkls", "blkcat", "foremost", "scalpel", "photorec",
    "log2timeline.py", "psort.py", "plaso",
    "yara", "clamscan", "freshclam",
    "adb", "fastboot", "frida",
    "openssl", "gpg", "shred", "wipe",
})


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _is_noisy(cmd: str) -> bool:
    """Return True if *cmd* should be dropped (no forensic value)."""
    if not cmd:
        return True
    head = cmd.strip().split(maxsplit=1)[0]
    # basename() so "/usr/bin/ls" still hits the noise list
    head_base = os.path.basename(head)
    if head_base in ALWAYS_LOG or head in ALWAYS_LOG:
        return False
    return head_base in NOISY_PREFIXES or head in NOISY_PREFIXES


def record_command() -> int:
    """Record a single command captured by bash-hooks.sh.

    Inputs (read from environment):
        FORENSICS_CMD            full command string
        FORENSICS_EXIT_CODE      integer
        FORENSICS_START_TIME     RFC3339 string (best effort, optional)
        FORENSICS_END_TIME       RFC3339 string (best effort, optional)
        FORENSICS_PWD            working directory at command start
        FORENSICS_TTY            controlling terminal
        FORENSICS_SESSION        $$ from the parent shell
    """
    cmd = os.environ.get("FORENSICS_CMD", "").strip()
    if _is_noisy(cmd):
        return 0

    try:
        exit_code = int(os.environ.get("FORENSICS_EXIT_CODE", "-1"))
    except ValueError:
        exit_code = -1

    details = {
        "command":     cmd[:1024],          # cap length to bound log growth
        "exit_code":   exit_code,
        "started_at":  os.environ.get("FORENSICS_START_TIME") or _utcnow_iso(),
        "ended_at":    os.environ.get("FORENSICS_END_TIME") or _utcnow_iso(),
        "cwd":         os.environ.get("FORENSICS_PWD", ""),
        "tty":         os.environ.get("FORENSICS_TTY", ""),
        "session":     os.environ.get("FORENSICS_SESSION", ""),
    }

    # Late import — keeps cold-start time low when nothing matches.
    try:
        from forensics.audit.logger import get_logger
        get_logger().log_event(
            "command_executed",
            details,
            user=os.environ.get("USER") or "sherlock",
        )
    except Exception:
        # NEVER propagate — but record it for post-mortem.
        try:
            log_dir = Path("/var/log/forensics/chain-of-custody")
            log_dir.mkdir(parents=True, exist_ok=True)
            err_log = log_dir / "errors.log"
            with err_log.open("a", encoding="utf-8") as fh:
                fh.write(f"{_utcnow_iso()} {details['command']!r}\n")
        except Exception:
            pass
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Accepts a single positional 'post' for clarity.

    Backwards-compat with the legacy invocation ``logger.py post``.
    """
    args = argv if argv is not None else sys.argv[1:]
    if args and args[0] != "post":
        # We accept other future verbs; for now just reject loudly.
        sys.stderr.write(f"unknown verb: {args[0]}\n")
        return 2
    return record_command()


if __name__ == "__main__":
    raise SystemExit(main())
