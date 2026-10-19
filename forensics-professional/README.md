# Forensics Professional

[![Docker Build & Security Scan](https://github.com/joao-henrike/Containers/actions/workflows/docker-build.yml/badge.svg)](https://github.com/joao-henrike/Containers/actions/workflows/docker-build.yml)
[![Lint](https://github.com/joao-henrike/Containers/actions/workflows/lint.yml/badge.svg)](https://github.com/joao-henrike/Containers/actions/workflows/lint.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![NIST SP 800-86](https://img.shields.io/badge/Aligned%20with-NIST%20SP%20800--86-blue)](https://csrc.nist.gov/publications/detail/sp/800-86/final)

A reproducible Docker workstation for digital forensics with auditable
evidence handling, modular tool installs, and **tamper-evident** logging.

> **Tamper-evident, not tamper-proof.** Read [SECURITY.md](SECURITY.md) for
> the full threat model. The audit log is signed and hash-chained; an
> attacker with both root and the signing key can still rewrite it.
> External append-only storage (S3 Object Lock, etc.) is required for legal
> non-repudiation.

---

## Why this exists

Most "forensics distros" install everything by default, take 20 GB, and
leave you to manage tool versions yourself. This project takes a different
approach:

- **Modular installs.** 14 module categories, install only what you need.
- **Real verification.** Every install is verified against a registry hint
  (binary on PATH, Python module importable, file on disk).
- **Audited operations.** Every install/remove and every shell command run
  by the analyst is captured in a signed, hash-chained log.
- **Restricted privilege model.** The image defaults to `sherlock`. Sudo
  grants access only to a root-owned helper that validates a fixed APT package
  allowlist and one fixed audit-log append-only operation. Python tools install
  into a sherlock-owned virtualenv; no runtime APT source/key edits, `pip` as
  root, arbitrary file placement as root, or root shell are allowed.

## Quickstart

```bash
git clone https://github.com/joao-henrike/Containers.git
cd Containers/forensics-professional

# Prepare bind mounts as the current host user (do not run this as root)
export HOST_UID="$(id -u)"
mkdir -p evidence cases logs keys reports

# Build with sherlock mapped to your non-root host UID, then start
docker compose build
docker compose up -d

# Drop into the analyst shell
docker compose exec --user sherlock forensics bash

# Inside the container
forensics-modules list
forensics-modules install memory-forensics
forensics-audit verify
```

For a guided tour with sample evidence, see
[`docs/examples/first-case.md`](docs/examples/first-case.md).

## Module catalogue

| Module                | Category   | Submodules                                            | Size (MB) |
| :-------------------- | :--------- | :---------------------------------------------------- | --------: |
| cloud-forensics       | cloud      | aws-tools, azure-tools, gcp-tools, generic-cloud      |       900 |
| memory-forensics      | memory     | volatility, lime, avml                                |       480 |
| disk-forensics        | disk       | sleuthkit, testdisk, foremost, scalpel                |       220 |
| network-forensics     | network    | wireshark, zeek, tcpdump, ngrep                       |       740 |
| mobile-forensics      | mobile     | android-tools, ios-tools, backup-extractors           |       580 |
| malware-analysis      | malware    | yara, radare2, ghidra, clamav                         |     2 048 |
| windows-forensics     | windows    | regripper, plaso, evtx-parser, prefetch-parser        |       590 |
| linux-forensics       | linux      | auditd-tools, log-parsers, ext4-tools                 |       315 |
| container-forensics   | container  | docker-forensics, kubernetes-tools                    |       430 |
| database-forensics    | database   | mysql-tools, postgresql-tools, mongodb-tools          |       650 |
| email-forensics       | email      | pst-parser, eml-parser, header-analyzer               |       260 |
| osint-tools           | osint      | social-media, email-osint, domain-recon, phone-osint  |       450 |
| threat-intelligence ⚠ | threat     | ioc-feeds, threat-hunting, misp-integration, opencti  |       320 |
| web-recon             | recon      | subdomain-enum, web-scraping, dns-recon               |       280 |

⚠ = `experimental` — APIs/tooling change frequently upstream.

`forensics-modules info <name>` shows submodule details, dependencies, and
known issues.

## Common operations

```bash
# Inspect a module
forensics-modules info malware-analysis

# Install with a subset of submodules
forensics-modules install osint-tools --only social-media,email-osint

# Show plan without doing the work
forensics-modules install memory-forensics --dry-run

# Re-run only the broken submodules of a partially-installed module
forensics-modules repair malware-analysis

# Tear down a module (apt remove + pip uninstall where defined)
forensics-modules remove network-forensics

# Audit log
forensics-audit verify
forensics-audit show --limit 50
forensics-audit show --event-type module_installed --user sherlock
forensics-audit export --output evidence/audit-2026-05-03.jsonl --format jsonl

# Health
forensics-health
forensics-health quick-check         # used by Docker HEALTHCHECK
```

## Privileged operations (post-quantum auth)

The repository includes a `quantum-root` challenge-response flow using ML-DSA-65,
but the final sudo handoff is not implemented and validated; it fails closed
and must not be considered a working root shell. Key generation and everyday
analysis run as `sherlock` without sudo. The only sudo permission is the
root-owned validating helper used for allowlisted package operations and the
fixed audit-log append-only bit. See [`docs/PRIVILEGED_MODE.md`](docs/PRIVILEGED_MODE.md)
for the intended design and remaining limitations.

## Configuration

Defaults live in [`config/config.yaml`](config/config.yaml). Override
per-deployment by mounting a different YAML at `/etc/forensics/config.yaml`,
or by setting environment variables:

| Variable                                  | Effect                                  |
| :---------------------------------------- | :-------------------------------------- |
| `FORENSICS_AUDIT_STRICT=true`             | Audit-write failures abort the action.  |
| `FORENSICS_MODULES_PARALLEL_JOBS=4`       | Install N submodules in parallel.       |
| `FORENSICS_MODULES_STREAM_OUTPUT=false`   | Buffer install output (CI-friendly).    |
| `FORENSICS_QUANTUM_ALLOW_DEMO_FALLBACK=true` | (Demos only — do not set in prod.)   |

## Repository layout

```
forensics-professional/
├── Dockerfile                      # multi-stage build, gosu-based entrypoint drop
├── docker-compose.yml              # cap_drop ALL + cap_add specifics
├── docker-entrypoint.sh            # tini-wrapped, gosu-based privilege drop
├── VERSION                         # single source of truth
├── requirements.txt                # pinned Python deps
├── config/
│   ├── config.yaml                 # default deployment config
│   ├── sudoers/sherlock            # single root-helper rule
│   └── forensics-privileged        # input-validating root helper
├── core/
│   ├── audit-system/               # forensics-audit, quantum-root, hooks
│   ├── module-manager/             # forensics-modules
│   └── forensics/                  # Python package (audit, chain, modules,
│                                   #   quantum, health)
├── modules/
│   ├── registry.json               # module catalogue
│   └── installed/                  # per-install manifests (digest + status)
├── scripts/
│   ├── forensics-health
│   ├── generate-quantum-keys.sh
│   └── validate.sh                 # smoke test (used in CI)
├── docs/                           # SECURITY, INSTALL, ARCHITECTURE, …
└── tests/                          # pytest suite
```

## Building & testing

```bash
# Build
docker compose build

# Smoke test (inside the container)
docker compose run --rm forensics /opt/forensics/bin/validate.sh

# Lint & unit tests (host side)
pip install -r requirements-dev.txt
ruff check core/
mypy core/
pytest -v
```

## Demonstration scenarios

Six end-to-end attack/defend scenarios live under
[`docs/scenarios/`](docs/scenarios/README.md). Each scenario includes
a self-contained docker-compose lab, exact red-team commands to
compromise the target, and a complete blue-team workflow inside the
forensics-professional container. They are designed for classroom
demos and CTF-style exercises:

1. [Apache web compromise](docs/scenarios/01-apache-web-attack.md) — SQLi → webshell → defacement
2. [DNS tunneling exfiltration](docs/scenarios/02-dns-tunneling.md) — iodine + Zeek/tshark analysis
3. [Container ransomware](docs/scenarios/03-ransomware-container.md) — YARA + radare2 + recovery
4. [Linux privilege escalation](docs/scenarios/04-privilege-escalation.md) — PATH hijack + auditd attribution
5. [C2 beacon detection](docs/scenarios/05-c2-beaconing.md) — statistical traffic analysis
6. [Credential leak → DB intrusion](docs/scenarios/06-credential-leak.md) — git history + MySQL query-log replay

> ⚠️ The scenarios use intentionally vulnerable images and synthetic
> malware for **educational purposes only**. Run them only on isolated
> lab infrastructure you own.

## Compliance

Aligned with **NIST SP 800-86: Guide to Integrating Forensic Techniques
into Incident Response**. Specifically:

- **Section 4.1 (Data Collection)** — read-only evidence mounts.
- **Section 4.2 (Examination)** — modular tool installs, reproducible
  versions.
- **Section 4.3 (Analysis)** — auditable operations.
- **Section 4.4 (Reporting)** — exportable, signed audit trail.

This alignment is operational, not certified. For a court-defensible
deployment you also need: external append-only log storage, a chain-of-
custody form, and a documented analyst training record.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Bug reports and module additions
are very welcome — open an issue first to discuss anything non-trivial.

## License

MIT. See [`LICENSE`](LICENSE).

## Maintainer

[@joao-henrike](https://github.com/joao-henrike) — issues and PRs welcome.
