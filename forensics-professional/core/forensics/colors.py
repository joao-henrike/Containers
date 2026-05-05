"""ANSI colours and small output helpers.

All CLI output goes through :func:`stylize` so terminal capability detection
stays in one place. ``NO_COLOR`` (https://no-color.org) is honoured.
"""

from __future__ import annotations

import os
import sys
from typing import IO

__all__ = [
    "RED", "GREEN", "YELLOW", "BLUE", "CYAN", "BOLD", "DIM", "NC",
    "stylize", "supports_colour", "ok", "warn", "fail", "info",
]


def supports_colour(stream: IO[str] | None = None) -> bool:
    """Return ``True`` if *stream* (default: stdout) likely supports colour."""
    if "NO_COLOR" in os.environ:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    stream = stream or sys.stdout
    return hasattr(stream, "isatty") and stream.isatty()


_USE_COLOUR = supports_colour()

# Raw ANSI escape sequences (only emitted when colour is supported).
RED    = "\033[0;31m" if _USE_COLOUR else ""
GREEN  = "\033[0;32m" if _USE_COLOUR else ""
YELLOW = "\033[1;33m" if _USE_COLOUR else ""
BLUE   = "\033[0;34m" if _USE_COLOUR else ""
CYAN   = "\033[0;36m" if _USE_COLOUR else ""
BOLD   = "\033[1m"    if _USE_COLOUR else ""
DIM    = "\033[2m"    if _USE_COLOUR else ""
NC     = "\033[0m"    if _USE_COLOUR else ""


def stylize(text: str, *codes: str) -> str:
    """Wrap *text* with *codes*, resetting at the end."""
    if not _USE_COLOUR or not codes:
        return text
    return "".join(codes) + text + NC


def ok(msg: str)   -> None: print(f"{GREEN}✓{NC}  {msg}")
def info(msg: str) -> None: print(f"{CYAN}ℹ{NC}  {msg}")
def warn(msg: str) -> None: print(f"{YELLOW}!{NC}  {msg}", file=sys.stderr)
def fail(msg: str) -> None: print(f"{RED}✗{NC}  {msg}", file=sys.stderr)
