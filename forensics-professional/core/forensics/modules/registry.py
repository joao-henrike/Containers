"""Module registry — typed access to ``modules/registry.json``.

Each module is described by:

    * a category, a stable version, an estimated size
    * a list of submodules; each submodule has a name and a verifier hint
      (a binary or python module that proves the install actually landed)
    * optional dependency declarations
    * known-issues notes (carried over to the user-facing output)

The registry is loaded once at startup; callers should fetch the singleton
via :func:`Registry.load`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from forensics.config import get_config


@dataclass(frozen=True, slots=True)
class SubmoduleSpec:
    """Description of a single submodule within a module."""
    name: str
    verify: tuple[str, ...] = field(default_factory=tuple)
    """Commands or binaries whose presence indicates the install succeeded.

    Each entry is one of:
        - bare name             : checked via ``shutil.which()``
        - "py:module.path"      : checked via ``importlib.util.find_spec``
        - "file:/abs/path"      : checked via ``Path.exists``
    """
    notes: str = ""


@dataclass(frozen=True, slots=True)
class ModuleSpec:
    name: str
    category: str
    description: str
    stable_version: str
    estimated_size_mb: int
    tool_count: int
    submodules: tuple[SubmoduleSpec, ...]
    dependencies: tuple[str, ...] = field(default_factory=tuple)
    known_issues: dict[str, str] = field(default_factory=dict)
    experimental: bool = False
    tools_overview: tuple[str, ...] = field(default_factory=tuple)


class Registry:
    """Container for parsed module specs."""

    def __init__(self, modules: dict[str, ModuleSpec], categories: dict[str, str]):
        self._modules = modules
        self._categories = categories

    # ── Lookup ───────────────────────────────────────────────────────────────
    def __contains__(self, name: str) -> bool:
        return name in self._modules

    def __getitem__(self, name: str) -> ModuleSpec:
        return self._modules[name]

    def get(self, name: str) -> ModuleSpec | None:
        return self._modules.get(name)

    def names(self) -> list[str]:
        return sorted(self._modules.keys())

    def by_category(self, category: str) -> list[ModuleSpec]:
        return [m for m in self._modules.values() if m.category == category]

    def categories(self) -> dict[str, str]:
        return dict(self._categories)

    def all(self) -> Iterable[ModuleSpec]:
        return self._modules.values()

    # ── Loading ──────────────────────────────────────────────────────────────
    @classmethod
    def load(cls, path: str | Path | None = None) -> Registry:
        if path is None:
            path = Path(get_config().modules.registry)
        else:
            path = Path(path)

        with path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)

        categories = dict(raw.get("categories", {}))
        modules: dict[str, ModuleSpec] = {}
        for name, info in raw.get("modules", {}).items():
            submodules = tuple(
                SubmoduleSpec(
                    name=sm["name"],
                    verify=tuple(sm.get("verify", ())),
                    notes=sm.get("notes", ""),
                )
                for sm in info.get("submodules", [])
            )
            modules[name] = ModuleSpec(
                name=name,
                category=info.get("category", "uncategorised"),
                description=info.get("description", ""),
                stable_version=info.get("stable_version") or info.get("version", "0.0.0"),
                estimated_size_mb=int(info.get("estimated_size_mb", 0)),
                tool_count=int(info.get("tool_count", 0)),
                submodules=submodules,
                dependencies=tuple(info.get("dependencies", [])),
                known_issues=dict(info.get("known_issues", {})),
                experimental=bool(info.get("experimental", False)),
                tools_overview=tuple(info.get("tools_overview", [])),
            )
        return cls(modules, categories)
