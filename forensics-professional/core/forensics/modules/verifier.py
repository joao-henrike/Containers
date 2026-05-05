"""Post-install verification.

For each ``SubmoduleSpec.verify`` hint, check whether the named
binary/module/file is now present. The verifier:

* never raises — it always returns a structured result
* is fast (sub-second per module)
* is the only place that decides "installed vs not" after an install run
"""

from __future__ import annotations

import importlib.util
import shutil
from dataclasses import dataclass
from pathlib import Path

from forensics.modules.registry import ModuleSpec, SubmoduleSpec


@dataclass(frozen=True, slots=True)
class CheckResult:
    submodule: str
    ok: bool
    findings: tuple[tuple[str, bool], ...]   # ((hint, satisfied), ...)


def check_hint(hint: str) -> bool:
    """Resolve a single verify hint. See :class:`SubmoduleSpec.verify`.

    Always returns a bool — never raises. ``ModuleNotFoundError`` for an
    intermediate package (eg ``py:foo.bar`` when ``foo`` is missing) is
    caught and treated as a negative match.
    """
    if hint.startswith("py:"):
        try:
            return importlib.util.find_spec(hint[3:]) is not None
        except (ModuleNotFoundError, ValueError, ImportError):
            return False
    if hint.startswith("file:"):
        return Path(hint[5:]).exists()
    return shutil.which(hint) is not None


def check_submodule(spec: SubmoduleSpec) -> CheckResult:
    if not spec.verify:
        # No hints — assume success but mark as 'unverified'.
        return CheckResult(submodule=spec.name, ok=True, findings=())
    findings = tuple((hint, check_hint(hint)) for hint in spec.verify)
    # ALL hints must succeed: a submodule typically corresponds to one tool +
    # its python helper, both of which should land.
    return CheckResult(
        submodule=spec.name,
        ok=all(satisfied for _, satisfied in findings),
        findings=findings,
    )


def check_module(spec: ModuleSpec, *, only: list[str] | None = None) -> dict[str, CheckResult]:
    """Verify the listed submodules of a module. Returns submodule -> result."""
    results: dict[str, CheckResult] = {}
    targets = spec.submodules
    if only:
        wanted = set(only)
        targets = tuple(s for s in spec.submodules if s.name in wanted)
    for sm in targets:
        results[sm.name] = check_submodule(sm)
    return results
