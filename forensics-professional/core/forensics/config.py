"""Configuration loading and access.

Configuration sources, in order of precedence (highest first):

    1. Environment variables matching keys in the schema below.
    2. ``/etc/forensics/config.yaml`` (the deployment config).
    3. The compiled-in defaults in :data:`_DEFAULTS`.

Access via the singleton :func:`get_config`. Mutations from code paths are
not supported — re-mount a different config file instead.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Mapping

import yaml

__all__ = ["Config", "get_config", "ConfigError"]


class ConfigError(RuntimeError):
    """Raised when a config file is present but unparseable."""


_DEFAULTS: dict[str, Any] = {
    "audit": {
        "log_path": "/var/log/forensics/audit.log",
        "strict": False,
        "error_log": "/var/log/forensics/audit.errors.log",
        "gpg_email": "forensics-audit@professional.local",
        "rotate_size_mib": 256,
    },
    "modules": {
        "installed_dir": "/opt/forensics/modules/installed",
        "registry": "/opt/forensics/modules/registry.json",
        "install_log_dir": "/var/log/forensics/installations",
        "parallel_jobs": 1,
        "command_timeout": 900,
        "stream_output": True,
    },
    "quantum": {
        "private_key": "/opt/forensics/quantum-keys/dilithium_private.key.enc",
        "public_key": "/opt/forensics/quantum-keys/dilithium_public.key",
        "allow_demo_fallback": False,
    },
    "paths": {
        "evidence": "/evidence",
        "cases": "/cases",
        "reports": "/reports",
        "keys": "/opt/forensics/quantum-keys",
        "tools": "/opt/forensics/tools",
    },
}


@dataclass(frozen=True, slots=True)
class AuditCfg:
    log_path: str
    strict: bool
    error_log: str
    gpg_email: str
    rotate_size_mib: int


@dataclass(frozen=True, slots=True)
class ModulesCfg:
    installed_dir: str
    registry: str
    install_log_dir: str
    parallel_jobs: int
    command_timeout: int
    stream_output: bool


@dataclass(frozen=True, slots=True)
class QuantumCfg:
    private_key: str
    public_key: str
    allow_demo_fallback: bool


@dataclass(frozen=True, slots=True)
class PathsCfg:
    evidence: str
    cases: str
    reports: str
    keys: str
    tools: str


@dataclass(frozen=True, slots=True)
class Config:
    audit: AuditCfg
    modules: ModulesCfg
    quantum: QuantumCfg
    paths: PathsCfg

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _deep_merge(base: dict, overlay: Mapping) -> dict:
    """Return a new dict with *overlay* merged on top of *base* (recursive)."""
    out = dict(base)
    for k, v in overlay.items():
        if isinstance(v, Mapping) and isinstance(out.get(k), Mapping):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _apply_env_overrides(cfg: dict[str, Any]) -> dict[str, Any]:
    """Apply environment variable overrides for a curated subset of keys."""
    env_map: dict[tuple[str, str], type] = {
        ("audit", "log_path"):              str,
        ("audit", "strict"):                bool,
        ("modules", "parallel_jobs"):       int,
        ("modules", "command_timeout"):     int,
        ("modules", "stream_output"):       bool,
        ("quantum", "allow_demo_fallback"): bool,
    }
    for (section, key), caster in env_map.items():
        env_key = f"FORENSICS_{section.upper()}_{key.upper()}"
        raw = os.environ.get(env_key)
        if raw is None:
            continue
        if caster is bool:
            cfg[section][key] = raw.lower() in ("1", "true", "yes", "on")
        else:
            try:
                cfg[section][key] = caster(raw)
            except (TypeError, ValueError):
                continue
    return cfg


def _load_file(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        return {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, Mapping):
        raise ConfigError(f"{path} must be a mapping")
    return dict(data)


_singleton: Config | None = None


def get_config(*, reload: bool = False) -> Config:
    """Return the shared :class:`Config` instance (lazy, cached)."""
    global _singleton
    if _singleton is not None and not reload:
        return _singleton

    config_path = Path(os.environ.get(
        "FORENSICS_CONFIG_FILE",
        "/etc/forensics/config.yaml",
    ))
    file_overlay = _load_file(config_path) if config_path.exists() else {}
    merged = _deep_merge(_DEFAULTS, file_overlay)
    merged = _apply_env_overrides(merged)

    _singleton = Config(
        audit=AuditCfg(**merged["audit"]),
        modules=ModulesCfg(**merged["modules"]),
        quantum=QuantumCfg(**merged["quantum"]),
        paths=PathsCfg(**merged["paths"]),
    )
    return _singleton
