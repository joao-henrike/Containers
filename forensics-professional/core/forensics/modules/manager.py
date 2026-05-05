"""ModuleManager — the orchestration layer behind ``forensics-modules``.

Public surface mirrors the legacy CLI:

    list       — show available modules
    info       — show details for one module
    install    — install (or partially install) a module
    remove     — uninstall a module (real apt/pip removal where possible)
    status     — list installed modules
    verify     — re-run verifier hints against installed modules
    repair     — rerun installers for any submodule whose verifier fails

Improvements over the original:

* **Idempotent.** ``install`` skips submodules whose verifier hints all pass.
* **Real verification.** Uses :mod:`forensics.modules.verifier` (registry hints),
  not just "marker file present".
* **Real remove.** Calls apt/pip uninstall declared in REMOVERS.
* **Streaming.** sub-process output is shown live (not buffered).
* **Parallel.** Independent submodules can install in parallel via --jobs.
* **Manifested.** Each install is recorded with a SHA-256 digest of the
  manifest (so the registry can be tamper-evident).
* **Dry-run.** ``--dry-run`` prints what would happen, runs nothing.
* **Audit-aware.** Every action emits an audit-log event.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable

from forensics.audit.logger import log_event as audit_log
from forensics.colors import (
    BOLD, CYAN, DIM, GREEN, NC, RED, YELLOW, info, ok as ok_msg, warn,
)
from forensics.config import get_config
from forensics.modules.installers import (
    INSTALLERS,
    REMOVERS,
    CommandRunner,
)
from forensics.modules.registry import ModuleSpec, Registry, SubmoduleSpec
from forensics.modules.verifier import CheckResult, check_hint, check_module

logger = logging.getLogger("forensics.modules.manager")


# ============================================================================
# Result types
# ============================================================================

@dataclass(slots=True)
class SubmoduleResult:
    name: str
    status: str        # "installed" | "skipped" | "failed" | "verified" | "removed"
    detail: str = ""
    findings: tuple[tuple[str, bool], ...] = ()


@dataclass(slots=True)
class InstallResult:
    module: str
    submodules: list[SubmoduleResult] = field(default_factory=list)
    log_file: str = ""
    aborted: bool = False

    @property
    def success_count(self) -> int:
        return sum(1 for s in self.submodules if s.status in ("installed", "verified"))

    @property
    def failure_count(self) -> int:
        return sum(1 for s in self.submodules if s.status == "failed")

    @property
    def overall(self) -> str:
        if self.aborted:
            return "aborted"
        total = len(self.submodules)
        if total == 0:
            return "noop"
        if self.success_count == total:
            return "success"
        if self.success_count == 0:
            return "failed"
        return "partial"


# ============================================================================
# Manifest (per-module install record)
# ============================================================================

@dataclass(slots=True)
class Manifest:
    """On-disk record of what was installed and how the install verified."""
    module: str
    version: str
    installed_at: str
    submodules: dict[str, dict]
    digest: str = ""

    @classmethod
    def build(cls, module: str, version: str,
              results: Iterable[SubmoduleResult]) -> Manifest:
        sm_map = {
            r.name: {
                "status":   r.status,
                "detail":   r.detail,
                "findings": [list(f) for f in r.findings],
            }
            for r in results
        }
        m = cls(
            module=module,
            version=version,
            installed_at=dt.datetime.now(dt.timezone.utc).isoformat() + "Z",
            submodules=sm_map,
        )
        m.digest = m._compute_digest()
        return m

    def _compute_digest(self) -> str:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


# ============================================================================
# Manager
# ============================================================================

class ModuleManager:
    """High-level operations against the module registry."""

    def __init__(self, registry: Registry | None = None) -> None:
        self.cfg = get_config()
        self.registry = registry or Registry.load()
        self.installed_dir = Path(self.cfg.modules.installed_dir)
        self.install_log_dir = Path(self.cfg.modules.install_log_dir)
        self.installed_dir.mkdir(parents=True, exist_ok=True)
        self.install_log_dir.mkdir(parents=True, exist_ok=True)

    # ── Read-only inspection ────────────────────────────────────────────────

    def list_modules(self, *, category: str | None = None) -> list[ModuleSpec]:
        modules = list(self.registry.all())
        if category:
            modules = [m for m in modules if m.category == category]
        return sorted(modules, key=lambda m: m.name)

    def get(self, name: str) -> ModuleSpec | None:
        return self.registry.get(name)

    def is_marked_installed(self, name: str) -> bool:
        return (self.installed_dir / f"{name}.json").exists()

    def load_manifest(self, name: str) -> dict | None:
        p = self.installed_dir / f"{name}.json"
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def installed_modules(self) -> list[str]:
        return sorted(p.stem for p in self.installed_dir.glob("*.json"))

    # ── Install ──────────────────────────────────────────────────────────────

    def install(
        self,
        name: str,
        *,
        only: list[str] | None = None,
        skip: list[str] | None = None,
        jobs: int | None = None,
        dry_run: bool = False,
        force: bool = False,
    ) -> InstallResult:
        """Install (or finish installing) a module.

        - *only*: restrict to these submodule names.
        - *skip*: omit these submodule names.
        - *jobs*: parallel installer threads (default: configured value).
        - *dry_run*: print plan without running anything.
        - *force*: reinstall even if verifier hints currently pass.
        """
        spec = self.registry.get(name)
        if spec is None:
            raise KeyError(f"unknown module: {name}")

        targets = self._resolve_submodules(spec, only=only, skip=skip)
        if not targets:
            warn(f"no matching submodules to install for {name}")
            return InstallResult(module=name)

        log_path = self._new_log_path(name)
        result = InstallResult(module=name, log_file=str(log_path))
        result.submodules = []

        self._print_plan(spec, targets, force=force, dry_run=dry_run)
        if dry_run:
            return result

        audit_log("module_install_started", {
            "module": name, "version": spec.stable_version,
            "submodules": [t.name for t in targets], "force": force,
        })

        runner = CommandRunner(
            log_path=log_path,
            stream=self.cfg.modules.stream_output,
            timeout=self.cfg.modules.command_timeout,
        )

        # Decide which submodules need work (idempotency)
        to_run, skipped = self._partition_idempotent(targets, force=force)
        for sm in skipped:
            result.submodules.append(SubmoduleResult(
                name=sm.name, status="verified",
                detail="already installed (verifier hints pass)",
            ))

        if not to_run:
            self._finalise(spec, result)
            return result

        # Sequential or parallel?
        n_jobs = jobs or self.cfg.modules.parallel_jobs
        if n_jobs <= 1 or len(to_run) == 1:
            for sm in to_run:
                result.submodules.append(self._run_one(spec, sm, runner))
        else:
            # Each parallel installer needs its own log file to avoid
            # interleaving inside a single file.
            with ThreadPoolExecutor(max_workers=n_jobs) as pool:
                futures = {}
                for sm in to_run:
                    sub_log = self._new_log_path(f"{name}-{sm.name}")
                    sub_runner = CommandRunner(
                        log_path=sub_log,
                        stream=False,            # avoid garbled console
                        timeout=self.cfg.modules.command_timeout,
                    )
                    futures[pool.submit(self._run_one, spec, sm, sub_runner)] = sm.name

                for fut in as_completed(futures):
                    sm_name = futures[fut]
                    try:
                        result.submodules.append(fut.result())
                    except Exception as exc:
                        result.submodules.append(SubmoduleResult(
                            name=sm_name, status="failed", detail=str(exc),
                        ))

        self._finalise(spec, result)
        return result

    # ── Remove ───────────────────────────────────────────────────────────────

    def remove(self, name: str, *, dry_run: bool = False) -> InstallResult:
        spec = self.registry.get(name)
        if spec is None:
            raise KeyError(f"unknown module: {name}")

        result = InstallResult(module=name)
        log_path = self._new_log_path(f"{name}-remove")
        result.log_file = str(log_path)

        runner = CommandRunner(
            log_path=log_path,
            stream=self.cfg.modules.stream_output,
            timeout=self.cfg.modules.command_timeout,
        )

        manifest = self.load_manifest(name) or {}
        installed = list((manifest.get("submodules") or {}).keys()) or [
            sm.name for sm in spec.submodules
        ]

        print(f"\n{CYAN}{'═' * 64}{NC}")
        print(f"{BOLD}  Removing {name}{NC}")
        print(f"{CYAN}{'═' * 64}{NC}")

        for sm_name in installed:
            cmds = REMOVERS.get(name, {}).get(sm_name)
            if not cmds:
                result.submodules.append(SubmoduleResult(
                    name=sm_name, status="skipped",
                    detail="no remover defined — tools remain on disk",
                ))
                print(f"  {YELLOW}~{NC}  {sm_name}: no automatic remover")
                continue

            if dry_run:
                for c in cmds:
                    print(f"  [dry-run] $ {' '.join(c)}")
                result.submodules.append(SubmoduleResult(
                    name=sm_name, status="skipped", detail="dry-run",
                ))
                continue

            try:
                for c in cmds:
                    runner.run(c, ignore_failure=True)
                result.submodules.append(SubmoduleResult(
                    name=sm_name, status="removed",
                ))
                print(f"  {GREEN}✓{NC}  {sm_name} removed")
            except Exception as exc:
                result.submodules.append(SubmoduleResult(
                    name=sm_name, status="failed", detail=str(exc),
                ))
                print(f"  {RED}✗{NC}  {sm_name}: {exc}")

        # Clear the manifest if every entry that had a remover succeeded.
        all_done = all(s.status in ("removed", "skipped") for s in result.submodules)
        if all_done and not dry_run:
            mp = self.installed_dir / f"{name}.json"
            if mp.exists():
                mp.unlink()
            audit_log("module_removed", {"module": name})

        return result

    # ── Verify / Repair ─────────────────────────────────────────────────────

    def verify(self, name: str | None = None) -> dict[str, dict[str, CheckResult]]:
        """Verify installed modules against their registry hints."""
        if name:
            specs = [self.registry[name]] if name in self.registry else []
        else:
            specs = [self.registry[n] for n in self.installed_modules()
                     if n in self.registry]

        return {spec.name: check_module(spec) for spec in specs}

    def repair(self, name: str) -> InstallResult:
        """Re-install only the submodules whose verifier currently fails."""
        spec = self.registry[name]
        results = check_module(spec)
        broken = [sm for sm in spec.submodules
                  if not results[sm.name].ok and sm.verify]
        if not broken:
            info(f"{name}: nothing to repair")
            return InstallResult(module=name)
        return self.install(name, only=[sm.name for sm in broken], force=True)

    # ── Internals ────────────────────────────────────────────────────────────

    def _resolve_submodules(
        self,
        spec: ModuleSpec,
        *,
        only: list[str] | None,
        skip: list[str] | None,
    ) -> list[SubmoduleSpec]:
        all_sms = list(spec.submodules)
        if only:
            wanted = set(only)
            all_sms = [s for s in all_sms if s.name in wanted]
            unknown = wanted - {s.name for s in spec.submodules}
            if unknown:
                warn(f"unknown submodules ignored: {', '.join(sorted(unknown))}")
        if skip:
            skip_set = set(skip)
            all_sms = [s for s in all_sms if s.name not in skip_set]
        return all_sms

    def _partition_idempotent(
        self,
        targets: list[SubmoduleSpec],
        *,
        force: bool,
    ) -> tuple[list[SubmoduleSpec], list[SubmoduleSpec]]:
        if force:
            return targets, []
        to_run, skip = [], []
        for sm in targets:
            if sm.verify and all(check_hint(h) for h in sm.verify):
                skip.append(sm)
            else:
                to_run.append(sm)
        return to_run, skip

    def _run_one(
        self,
        spec: ModuleSpec,
        sm: SubmoduleSpec,
        runner: CommandRunner,
    ) -> SubmoduleResult:
        installer = INSTALLERS.get(spec.name, {}).get(sm.name)
        if installer is None:
            return SubmoduleResult(
                name=sm.name, status="skipped",
                detail="no installer registered",
            )

        # Honour known-issues / experimental marker by warning loudly.
        note = spec.known_issues.get(sm.name, "")
        if note:
            warn(f"{sm.name}: {note}")

        print(f"  {CYAN}→{NC}  installing {sm.name} …")
        try:
            installer(runner)
        except Exception as exc:
            audit_log("submodule_install_failed", {
                "module": spec.name, "submodule": sm.name,
                "error":  str(exc),
            })
            print(f"  {RED}✗{NC}  {sm.name}: {exc}")
            return SubmoduleResult(name=sm.name, status="failed", detail=str(exc))

        # Verify (idempotency-friendly second check)
        check = check_module(spec, only=[sm.name])[sm.name]
        if check.ok:
            print(f"  {GREEN}✓{NC}  {sm.name} verified")
            audit_log("submodule_installed", {
                "module": spec.name, "submodule": sm.name,
            })
            return SubmoduleResult(
                name=sm.name, status="installed",
                findings=check.findings,
            )

        # Installer ran without error but verifier failed — frequently a path
        # or PPA issue. Surface the specifics rather than a generic OK/FAIL.
        missing = ", ".join(h for h, satisfied in check.findings if not satisfied)
        print(f"  {YELLOW}!{NC}  {sm.name} installed but missing: {missing}")
        audit_log("submodule_install_unverified", {
            "module": spec.name, "submodule": sm.name, "missing": missing,
        })
        return SubmoduleResult(
            name=sm.name, status="failed",
            detail=f"verification failed: {missing}",
            findings=check.findings,
        )

    def _finalise(self, spec: ModuleSpec, result: InstallResult) -> None:
        # Write/refresh the manifest if anything succeeded.
        if result.success_count > 0:
            manifest = Manifest.build(spec.name, spec.stable_version,
                                      result.submodules)
            mp = self.installed_dir / f"{spec.name}.json"
            mp.write_text(manifest.to_json(), encoding="utf-8")

        audit_log("module_install_finished", {
            "module":   spec.name,
            "version":  spec.stable_version,
            "result":   result.overall,
            "succeeded": [s.name for s in result.submodules
                          if s.status in ("installed", "verified")],
            "failed":    [s.name for s in result.submodules
                          if s.status == "failed"],
        })

        # Per-result console summary.
        n_total = len(result.submodules)
        n_ok = result.success_count
        n_fail = result.failure_count
        symbol_color = (
            (GREEN, "✓") if result.overall == "success"
            else (RED, "✗") if result.overall == "failed"
            else (YELLOW, "~")
        )
        print(f"\n{symbol_color[0]}{symbol_color[1]}{NC}  "
              f"{spec.name}: {n_ok}/{n_total} OK"
              f"{f', {n_fail} failed' if n_fail else ''}")
        print(f"{DIM}   log: {result.log_file}{NC}\n")

    def _new_log_path(self, name: str) -> Path:
        ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S")
        return self.install_log_dir / f"{name}_{ts}.log"

    def _print_plan(
        self,
        spec: ModuleSpec,
        targets: list[SubmoduleSpec],
        *,
        force: bool,
        dry_run: bool,
    ) -> None:
        print(f"\n{CYAN}{'═' * 64}{NC}")
        print(f"{BOLD}  {'[dry-run] ' if dry_run else ''}"
              f"Install plan: {spec.name} v{spec.stable_version}{NC}")
        if spec.experimental:
            print(f"  {YELLOW}⚠ marked experimental{NC}")
        print(f"  Submodules: {', '.join(t.name for t in targets)}")
        if force:
            print(f"  {YELLOW}force=True (skip idempotency check){NC}")
        print(f"{CYAN}{'═' * 64}{NC}")
