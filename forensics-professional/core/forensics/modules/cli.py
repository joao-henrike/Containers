"""``forensics.modules.cli`` — entry point for ``pip install``-friendly CLI.

The actual CLI implementation lives in
``core/module-manager/forensics-modules`` (a script, no ``.py`` extension —
it ships in the container at ``/opt/forensics/core/module-manager/`` and is
symlinked into ``/usr/local/bin``).

This module exists so the ``[project.scripts]`` entry-point in
``pyproject.toml`` resolves cleanly when the package is installed via pip on
a host machine (e.g. for unit tests, lint runs, or local development). It
imports the CLI's argument parser from the script with :mod:`runpy`, then
forwards ``main()``.

Keeping a single source of truth means changes to the CLI only have to
land in one place; this shim follows automatically.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path
from typing import Callable

__all__ = ["main"]


def _load_legacy_main() -> Callable[[list[str] | None], int]:
    """Import the script-style CLI and return its ``main`` callable."""
    # core/module-manager/forensics-modules
    here = Path(__file__).resolve()
    # forensics/modules/cli.py -> forensics/modules -> forensics -> core -> repo
    repo_or_install_root = here.parent.parent.parent.parent
    candidates = [
        repo_or_install_root / "core" / "module-manager" / "forensics-modules",
        repo_or_install_root / "module-manager" / "forensics-modules",
        Path("/opt/forensics/core/module-manager/forensics-modules"),
    ]
    for c in candidates:
        if c.exists():
            ns = runpy.run_path(str(c), run_name="__forensics_cli__")
            fn = ns.get("main")
            if callable(fn):
                return fn
    raise SystemExit(
        "forensics-modules CLI script not found. Expected one of: "
        + ", ".join(str(c) for c in candidates)
    )


def main(argv: list[str] | None = None) -> int:
    return int(_load_legacy_main()(argv) or 0)


if __name__ == "__main__":
    sys.exit(main())
