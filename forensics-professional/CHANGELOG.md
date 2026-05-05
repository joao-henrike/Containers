# Changelog

All notable changes to this project follow the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] — 2026-05-03

This release is a near-complete rewrite. Most behaviour stays the same
from the analyst's point of view, but internals are reorganised and
several promises that the previous version did not actually keep are now
either kept properly or removed.

### Added
- `core/forensics/` — proper Python package replacing the loose scripts
  under `core/`.
  - `forensics.audit` — thread-safe `AuditLogger` with atomic `O_APPEND`
    writes and Ed25519/GPG signatures.
  - `forensics.chain.logger` — chain-of-custody command capture
    (the file `bash-hooks.sh` was importing but did not exist before).
  - `forensics.modules.manager.ModuleManager` — install/remove/verify/
    repair with **real** verification, idempotent installs, parallel
    submodule support, dry-run, and per-install manifests with SHA-256
    digests.
  - `forensics.quantum.keygen` — actually generates the ML-DSA-65 keypair
    that `quantum-root` needs (using AES-256-GCM + Argon2id).
  - `forensics.quantum.auth` — real challenge-response authentication;
    no fallback success path.
  - `forensics.health.monitor` — structured probes, JSON output, exit
    codes for CI.
- `gosu` is now installed and GPG-verified during build.
- `sudo` is now installed and restricted via
  `config/sudoers.d-sherlock` (no shell escalation).
- `USER sherlock` directive — container default user is now the analyst
  account, not root.
- `HEALTHCHECK` directive — Docker now reports unhealthy containers.
- Streaming subprocess output during installs (no more 10-minute silent
  installs).
- Idempotent installs: re-running `install <module>` skips submodules
  whose verifier hints already pass.
- `repair <module>` command for re-installing only the broken submodules.
- Manifest digests in `modules/installed/<name>.json` so install records
  are tamper-evident at the filesystem layer too.
- Per-submodule `verify` hints in `modules/registry.json`.
- `.dockerignore` to keep evidence/keys/logs out of the build context.
- `requirements.txt` and `requirements-dev.txt` with pinned versions.
- `pyproject.toml` for proper packaging metadata.
- `Makefile` for the common host-side targets.
- Test suite under `tests/`.
- `docs/examples/first-case.md` — happy-path tutorial.
- `docs/PRIVILEGED_MODE.md` — explicit guide for the rare cases you need
  `--privileged`.

### Changed (breaking)
- **Container default user is now `sherlock`**, not root. `docker exec`
  without `-u` lands in the analyst account.
- **Audit log file format adds a `signatures` key.** Old logs without
  this key are still readable, but `forensics-audit verify` will refuse
  them with a clear error rather than silently treating them as valid.
  Migration: re-import old logs as evidence files; do not append to them.
- **`forensics-modules remove` now actually uninstalls.** Previously it
  only deleted a marker file. Existing scripts that relied on the marker
  going away should still work; ones that relied on the package staying
  installed will break.
- **`quantum-root` no longer falls through to "success" when the binary
  is missing.** The previous behaviour made any password accept root
  if `quantum_verify` was not compiled. To use `quantum-root`, run
  `/opt/forensics/bin/generate-quantum-keys.sh` first.
- **Hardcoded password `sherlock:forensics` removed.** The user has no
  password (`passwd -d`); use `docker exec` to enter the container.
- **Module registry schema bumped to v2.** Submodules are now objects
  with `name`, `verify`, and optional `notes`. Auto-migration from v1 is
  not provided — regenerate from `modules/registry.json`.
- **`rekall` removed from `memory-forensics`.** It has been broken on
  Python ≥ 3.10 for years and the upstream project is unmaintained.
  Volatility 3 is the documented replacement.
- All version strings now read from `VERSION` at the project root.

### Fixed
- `gosu` is verified and installed (entrypoint relied on it but it was
  missing).
- `audit-logger.py` → `audit_logger.py` rename so Python can actually
  import it. Was always being silently swallowed by `except: pass`.
- `bash-hooks.sh` previously referenced
  `/opt/forensics/chain-logger/logger.py`, which did not exist. The
  hook now invokes `python3 -m forensics.chain.logger post`.
- Command injection via `os.system(f'...')` in the audit logger.
- Health check no longer crashes when `lsattr` is unavailable.
- Module list and registry sizes now agree.
- README placeholders (`YOUR-USERNAME`, `support@your-org.com`) replaced.
- GPG private-key generation no longer uses `%no-protection`; a random
  passphrase is stored in `keys/.gpg.passphrase` (mode 0400).

### Removed
- `privileged: true` from default `docker-compose.yml`. Use
  `docker-compose.override.yml` if you genuinely need it (see
  `docs/PRIVILEGED_MODE.md`).
- `core/init-environment.sh` (replaced by entrypoint logic).
- `init-audit.py` and `init-keys.sh` (logic moved into Python helpers).
- `scripts/install-modules.sh` (functionality merged into
  `forensics-modules`).
- `validation-scripts/FBI_VALIDATION_CLEAN.sh` and
  `ULTIMATE_VALIDATION_FIXED.sh` (replaced by `scripts/validate.sh`).

### Security
- Sudoers policy is now whitelist-only with explicit argument matching.
- `chattr +a` only allowed on the canonical audit-log path.
- Container runs without privileged mode by default.
- `no-new-privileges:true` set on the container.
- All Python dependencies pinned.

## [2.1.0] — 2026-03-25 (legacy)

Previous release. The first public version. See git history for changes.

[3.0.0]: https://github.com/joao-henrike/Containers/compare/v2.1.0...v3.0.0
[2.1.0]: https://github.com/joao-henrike/Containers/releases/tag/v2.1.0
