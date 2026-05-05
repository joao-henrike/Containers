"""Forensic-tool installer & registry manager."""

from forensics.modules.registry import Registry, ModuleSpec, SubmoduleSpec
from forensics.modules.manager import ModuleManager, InstallResult

__all__ = [
    "Registry",
    "ModuleSpec",
    "SubmoduleSpec",
    "ModuleManager",
    "InstallResult",
]
