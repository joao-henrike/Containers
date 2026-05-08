"""``forensics.health.cli`` — entry point for ``pip install``-friendly CLI.

Thin shim around ``scripts/forensics-health``. See ``forensics.modules.cli``
for the rationale.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path
from typing import Callable

__all__ = ["main"]


def _load_legacy_main() -> Callable[[list[str] | None], int]:
    here = Path(__file__).resolve()
    repo_or_install_root = here.parent.parent.parent.parent
    candidates = [
        repo_or_install_root / "scripts" / "forensics-health",
        Path("/opt/forensics/bin/forensics-health"),
    ]
    for c in candidates:
        if c.exists():
            ns = runpy.run_path(str(c), run_name="__forensics_cli__")
            fn = ns.get("main")
            if callable(fn):
                return fn
    raise SystemExit(
        "forensics-health CLI script not found. Expected one of: "
        + ", ".join(str(c) for c in candidates)
    )


def main(argv: list[str] | None = None) -> int:
    return int(_load_legacy_main()(argv) or 0)


if __name__ == "__main__":
    sys.exit(main())
