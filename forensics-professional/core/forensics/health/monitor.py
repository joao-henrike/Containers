"""Health & diagnostic checks.

The monitor is split into a handful of self-contained probes (each returns
a :class:`Probe`) so new checks can be added without rearchitecting the
runner. The runner itself produces:

    * structured output (a list of :class:`Probe`)
    * a single overall verdict (HEALTHY / DEGRADED / FAILED)
    * a non-zero exit code on FAILED so CI can rely on it
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from forensics.colors import BOLD, CYAN, DIM, GREEN, NC, RED, YELLOW

# Verdict levels — increasing severity.
STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"


@dataclass(slots=True)
class Probe:
    label: str
    status: str        # ok | warn | fail
    detail: str = ""

    @property
    def is_failure(self) -> bool:
        return self.status == STATUS_FAIL


@dataclass(slots=True)
class Section:
    title: str
    probes: list[Probe] = field(default_factory=list)


# ── Probe implementations ────────────────────────────────────────────────────

def _exists(path: str) -> bool:
    return Path(path).exists()


def probe_directories() -> Section:
    section = Section("Directories")
    required = [
        ("/evidence",                                "evidence (read-only)"),
        ("/cases",                                   "cases"),
        ("/reports",                                 "reports"),
        ("/var/log/forensics",                       "log dir"),
        ("/opt/forensics/modules/installed",         "module manifests"),
        ("/opt/forensics/quantum-keys",              "key store"),
        ("/etc/forensics",                           "config"),
    ]
    for path, label in required:
        if _exists(path):
            section.probes.append(Probe(label, STATUS_OK, path))
        else:
            section.probes.append(Probe(label, STATUS_FAIL, f"missing: {path}"))
    return section


def probe_audit() -> Section:
    section = Section("Audit System")
    audit_log = "/var/log/forensics/audit.log"
    if not _exists(audit_log):
        section.probes.append(Probe("audit log", STATUS_FAIL, "missing"))
        return section

    size = Path(audit_log).stat().st_size
    section.probes.append(Probe(
        "audit log present", STATUS_OK,
        f"{size:,} bytes",
    ))

    # chattr +a (best effort, host-dependent)
    try:
        out = subprocess.run(
            ["lsattr", audit_log],
            capture_output=True, text=True, timeout=2,
        )
        flags = (out.stdout.split(" ", 1)[0]) if out.stdout else ""
        section.probes.append(Probe(
            "append-only attribute",
            STATUS_OK if "a" in flags else STATUS_WARN,
            "active" if "a" in flags else "not enforced (host filesystem)",
        ))
    except (OSError, subprocess.TimeoutExpired):
        section.probes.append(Probe("append-only attribute", STATUS_WARN,
                                    "lsattr unavailable"))

    # Entry count
    try:
        with open(audit_log, "r", encoding="utf-8") as fh:
            count = sum(1 for line in fh if line.strip())
        section.probes.append(Probe(
            "audit entries", STATUS_OK, f"{count} entries",
        ))
    except OSError as exc:
        section.probes.append(Probe("audit entries", STATUS_FAIL, str(exc)))

    # Keys
    ed25519 = _exists("/opt/forensics/quantum-keys/audit_ed25519.key")
    section.probes.append(Probe(
        "Ed25519 signing key",
        STATUS_OK if ed25519 else STATUS_WARN,
        "present" if ed25519 else "missing — events unsigned",
    ))

    pqc = _exists("/opt/forensics/quantum-keys/dilithium_private.key.enc")
    section.probes.append(Probe(
        "ML-DSA-65 keypair",
        STATUS_OK if pqc else STATUS_WARN,
        "present" if pqc else "not generated (run quantum-keygen)",
    ))
    return section


def probe_modules() -> Section:
    from forensics.modules.manager import ModuleManager
    section = Section("Modules")

    try:
        mgr = ModuleManager()
    except Exception as exc:
        section.probes.append(Probe("registry load", STATUS_FAIL, str(exc)))
        return section

    section.probes.append(Probe(
        "registry loaded", STATUS_OK,
        f"{len(list(mgr.registry.all()))} modules available",
    ))
    installed = mgr.installed_modules()
    section.probes.append(Probe(
        "modules installed", STATUS_OK,
        ", ".join(installed) if installed else "(none yet)",
    ))

    cli = shutil.which("forensics-modules")
    section.probes.append(Probe(
        "forensics-modules in PATH",
        STATUS_OK if cli else STATUS_FAIL,
        cli or "not found",
    ))
    return section


def probe_resources() -> Section:
    section = Section("Resources")

    section.probes.append(Probe(
        "CPU cores", STATUS_OK, f"{os.cpu_count() or 0}",
    ))

    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            mem = {
                k.strip(): v.strip()
                for line in fh
                for k, v in [line.split(":", 1)]
            }
        total_kb = int(mem["MemTotal"].split()[0])
        avail_kb = int(mem.get("MemAvailable", "0 kB").split()[0])
        free_gib = avail_kb / 1024 / 1024
        total_gib = total_kb / 1024 / 1024
        used_pct = (1 - avail_kb / total_kb) * 100 if total_kb else 0
        if free_gib < 1.0:
            status = STATUS_FAIL
        elif free_gib < 2.0:
            status = STATUS_WARN
        else:
            status = STATUS_OK
        section.probes.append(Probe(
            "memory",
            status,
            f"{free_gib:.1f}/{total_gib:.1f} GiB free ({used_pct:.0f}% used)",
        ))
    except (OSError, KeyError, ValueError) as exc:
        section.probes.append(Probe("memory", STATUS_WARN, str(exc)))

    try:
        usage = shutil.disk_usage("/")
        free_gib = usage.free / 1024**3
        total_gib = usage.total / 1024**3
        used_pct = usage.used / usage.total * 100 if usage.total else 0
        if free_gib < 5.0:
            status = STATUS_FAIL
        elif free_gib < 10.0:
            status = STATUS_WARN
        else:
            status = STATUS_OK
        section.probes.append(Probe(
            "disk (/)",
            status,
            f"{free_gib:.1f}/{total_gib:.1f} GiB free ({used_pct:.0f}% used)",
        ))
    except OSError as exc:
        section.probes.append(Probe("disk", STATUS_WARN, str(exc)))

    return section


def probe_tools() -> Section:
    """Verify a small set of tools that the rest of the system depends on."""
    section = Section("Core Tools")
    expected: list[tuple[str, str]] = [
        ("python3",  "Python interpreter"),
        ("openssl",  "OpenSSL"),
        ("gpg",      "GnuPG"),
        ("git",      "git"),
        ("curl",     "curl"),
        ("jq",       "jq"),
        ("sudo",     "sudo (restricted by /etc/sudoers.d/sherlock-forensics)"),
        ("gosu",     "gosu (privilege drop)"),
    ]
    for cmd, label in expected:
        path = shutil.which(cmd)
        section.probes.append(Probe(
            label,
            STATUS_OK if path else STATUS_FAIL,
            path or "not found",
        ))
    return section


_FULL_PROBES: list[Callable[[], Section]] = [
    probe_directories,
    probe_audit,
    probe_modules,
    probe_resources,
    probe_tools,
]


# ── Public runner / monitor ──────────────────────────────────────────────────

class HealthMonitor:
    """Compose probes and aggregate verdicts."""

    def __init__(self, probes: list[Callable[[], Section]] | None = None) -> None:
        self.probes = probes or _FULL_PROBES

    def run(self) -> list[Section]:
        return [p() for p in self.probes]

    @staticmethod
    def overall(sections: list[Section]) -> str:
        seen = {p.status for s in sections for p in s.probes}
        if STATUS_FAIL in seen:
            return "failed"
        if STATUS_WARN in seen:
            return "degraded"
        return "healthy"


# ── CLI helpers ──────────────────────────────────────────────────────────────

def _render(sections: list[Section]) -> None:
    icons = {STATUS_OK: f"{GREEN}✓{NC}",
             STATUS_WARN: f"{YELLOW}!{NC}",
             STATUS_FAIL: f"{RED}✗{NC}"}
    print(f"\n{CYAN}{'═' * 64}{NC}")
    print(f"{BOLD}  Forensics Health Check{NC}")
    print(f"  {DIM}{dt.datetime.now(dt.timezone.utc).isoformat()}{NC}")
    print(f"{CYAN}{'═' * 64}{NC}")
    for section in sections:
        print(f"\n  {BOLD}{section.title}{NC}")
        for probe in section.probes:
            icon = icons[probe.status]
            print(f"    {icon}  {probe.label:<40} {DIM}{probe.detail}{NC}")
    print()


def run_check(*, output_json: bool = False) -> int:
    sections = HealthMonitor().run()
    overall = HealthMonitor.overall(sections)
    if output_json:
        print(json.dumps({
            "overall": overall,
            "sections": [
                {"title": s.title,
                 "probes": [{"label": p.label, "status": p.status,
                             "detail": p.detail} for p in s.probes]}
                for s in sections
            ],
        }, indent=2))
    else:
        _render(sections)
        print(f"  Overall: {overall.upper()}\n")
    return 0 if overall != "failed" else 1


def quick_check(*, silent: bool = False) -> int:
    """Lightweight liveness check used by Docker HEALTHCHECK."""
    needed = [
        "/evidence", "/cases", "/var/log/forensics/audit.log",
        "/opt/forensics/modules/registry.json",
    ]
    failures = [p for p in needed if not _exists(p)]
    if not silent:
        if failures:
            print(f"degraded — missing: {', '.join(failures)}")
        else:
            print("healthy")
    return 0 if not failures else 1
