# Architecture

This document explains how the pieces fit together and why each one
exists. If you only want to use the container, [`README.md`](README.md)
and [`QUICKSTART.md`](QUICKSTART.md) are enough. Read this when you want
to extend it or audit it.

## Map of the territory

```
┌──────────────────────────────────────────────────────────────────┐
│                         Docker host                              │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │              forensics-workstation (container)             │  │
│  │                                                            │  │
│  │  ┌──────────────────┐    ┌──────────────────┐              │  │
│  │  │ Bash shell       │───▶│ bash-hooks.sh    │              │  │
│  │  │ (sherlock)       │    │ (DEBUG trap)     │              │  │
│  │  └──────────────────┘    └────────┬─────────┘              │  │
│  │           │                       │                        │  │
│  │           ▼                       ▼                        │  │
│  │  ┌──────────────────┐    ┌──────────────────┐              │  │
│  │  │ forensics-       │    │ forensics.chain  │              │  │
│  │  │   modules CLI    │    │   .logger        │              │  │
│  │  └────────┬─────────┘    └────────┬─────────┘              │  │
│  │           │                       │                        │  │
│  │           ▼                       │                        │  │
│  │  ┌──────────────────┐             │                        │  │
│  │  │ ModuleManager    │             │                        │  │
│  │  │  - install       │             │                        │  │
│  │  │  - remove        │             │                        │  │
│  │  │  - verify        │             │                        │  │
│  │  └────────┬─────────┘             │                        │  │
│  │           │                       │                        │  │
│  │           ▼                       ▼                        │  │
│  │  ┌────────────────────────────────────────────┐            │  │
│  │  │      forensics.audit.AuditLogger           │            │  │
│  │  │      (Ed25519-signed, hash-chained)        │            │  │
│  │  └────────────────┬───────────────────────────┘            │  │
│  │                   ▼                                        │  │
│  │  ┌────────────────────────────────────────────┐            │  │
│  │  │  /var/log/forensics/audit.log  (chattr +a) │            │  │
│  │  └────────────────────────────────────────────┘            │  │
│  │                                                            │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Bind mounts: ./evidence (ro)  ./cases  ./logs  ./keys  ./reports│
└──────────────────────────────────────────────────────────────────┘
```

## Lifecycles

### Container start

1. `tini` (PID 1) execs `docker-entrypoint.sh` as root.
2. Entrypoint creates log directories, generates Ed25519 + GPG keys
   (only on first boot), bootstraps the audit-log genesis entry, marks
   the log append-only, and writes `/home/sherlock/.bashrc`.
3. Entrypoint records a `container_started` audit event.
4. Entrypoint exec's `gosu sherlock <CMD>`. The default CMD is `bash`.
5. Bash sources `.bashrc`, which sources `bash-hooks.sh`.
6. The DEBUG trap and PROMPT_COMMAND are now armed.

### A user runs a command

1. Bash fires the DEBUG trap → `__forensics_preexec` records
   `BASH_COMMAND`, start time, cwd, tty.
2. The command runs as usual.
3. Before drawing the next prompt, Bash runs `__forensics_precmd`,
   which spawns a backgrounded subshell:

   ```bash
   ( FORENSICS_CMD=… python3 -m forensics.chain.logger post & )
   disown
   ```
4. The subshell calls `record_command()`. After the noise filter,
   the command becomes a `command_executed` audit event.
5. The audit logger acquires its in-process lock, computes the next
   hash, signs with Ed25519, and appends with `os.write(O_APPEND)`.

This is fire-and-forget: the analyst's prompt returns immediately.

### A module install

1. `forensics-modules install memory-forensics --only volatility`
2. CLI loads `Registry`, looks up the module spec, and prints the plan.
3. After confirmation, ModuleManager:
   - Records a `module_install_started` audit event.
   - Computes the idempotency partition: which submodules already pass
     their verifier hints (skipped) vs which need work.
   - For each remaining submodule:
     - Calls the corresponding installer function from
       `forensics.modules.installers.INSTALLERS`.
     - Streams sub-process output to both stdout and a per-install log
       file under `/var/log/forensics/installations/`.
     - Re-runs the verifier — only "verifier passes" counts as
       installed.
     - Records a per-submodule audit event.
   - Writes the manifest to `modules/installed/<name>.json` with a
     SHA-256 digest of the entry.
   - Records a `module_install_finished` audit event.

### `quantum-root`

1. `quantum-root` is the shell wrapper; it shows the banner and execs
   `python3 -m forensics.quantum.auth`.
2. The Python module:
   - Refuses immediately if `liboqs` or the keypair is missing.
   - Prompts for the passphrase.
   - Decrypts the private key with AES-256-GCM (Argon2id-derived key).
   - Generates a random 32-byte challenge.
   - Signs it with the decrypted key (ML-DSA-65).
   - Verifies the signature against the public key.
   - Logs success or specific failure mode.
3. The shell wrapper exec's `sudo -i` on success, exits non-zero
   otherwise.

## Why each piece exists

### Why a Python package, not loose scripts?

The original project had ~15 standalone scripts in different languages
that interpreted the same data structures slightly differently. A single
typo in a category name caused silent skips. The Python package gives
one source of truth: the registry is parsed once into typed dataclasses
and shared by all CLIs. Name typos are caught at load time.

### Why `gosu` instead of `su`?

`su` re-executes a login shell, which alters the environment in ways
that matter for analyst tools (PATH, PYTHONPATH, etc.). It also doesn't
forward signals reliably. `gosu` is the standard pick: it's a static
Go binary that does *exactly* what `setuid; setgid; setgroups; exec`
would do — nothing more.

### Why the package up front, with the CLIs as wrappers?

CLIs are trivially testable when they wrap a library: you can call
`ModuleManager().install(...)` from a unit test without spawning a
subprocess. The opposite — putting logic in the CLI — leaves you no
seam for tests at all.

### Why per-submodule verifier hints?

In the previous version, "module installed" meant "marker file
exists". A failed install that wrote the marker anyway looked
identical to a real install. The verifier checks for the *evidence*
that the install worked — `which volatility3`, `import yara`, etc.
This also makes `repair` possible: rerun only the submodules whose
hints currently fail.

### Why streaming subprocess output?

Most installs touch the network for hundreds of MB. Buffering until
`subprocess.run()` returns means a 10-minute wait with no feedback,
during which the user assumes it's hung and Ctrl-C's. Streaming via
`Popen` lets us write each line to both stdout and the install log as
it happens.

### Why a SHA-256 digest in each manifest?

The manifest itself can be tampered with. The digest is computed over
the canonical JSON of the rest of the manifest. Combined with the
audit log's own hash chain, this gives a cross-check: the audit log
says "module X installed at T", and the manifest's digest matches the
canonical form recorded in the audit event.

### Why no automatic Rekall removal?

Rekall has been broken on Python ≥ 3.10 for years. Trying to install
it pulls in `urllib3` downgrades that break other tools. The previous
version "skipped" it by writing nothing, but listed it in the
registry, which led to confusing partial installs. Now it's not in
the registry at all. Volatility 3 is its documented replacement.

### Why is the audit-log signing key in the same container?

Convenience. For genuine non-repudiation, the key would live on a HSM
or a separate logging host. We document this trade-off in
[`SECURITY.md`](SECURITY.md). The architecture supports moving the
keystore out: `forensics.audit.logger` reads its key path from
`Config.paths.keys`, so mounting an HSM-backed PKCS#11 store at that
path is a small change.

## Extension points

### Adding a module

1. Add an entry to `modules/registry.json` (with `submodules` and
   `verify` hints).
2. Add installer functions to `core/forensics/modules/installers.py`
   and register them in `INSTALLERS`.
3. (Optional) Add removal commands to `REMOVERS`.
4. Run `forensics-modules info <name>` and `forensics-modules install
   <name> --dry-run` to sanity-check.

### Adding a health probe

1. Implement a function returning a `Section` in
   `core/forensics/health/monitor.py`.
2. Append it to `_FULL_PROBES`.
3. Done — `forensics-health` will pick it up.

### Adding a custom audit event

```python
from forensics.audit.logger import log_event
log_event("custom_event", {"detail": "..."}, user="sherlock")
```

The hash chain and signatures are handled for you.

### Replacing the keystore with a HSM

Implement `_load_ed25519` and `_sign_ed25519` in your subclass of
`AuditLogger`, then instantiate it in your CLI entry points. The rest
of the package depends only on the `AuditLogger` interface.
