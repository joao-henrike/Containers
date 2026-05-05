# Security & Threat Model

This document describes what Forensics Professional **does** and **does not**
protect against. It is intentionally honest about the limits of the
guarantees so you can decide whether the design fits your use case.

## TL;DR

| Property                                   | Status                       |
| :----------------------------------------- | :--------------------------- |
| Read-only evidence mounts                  | Yes (enforced by Docker)     |
| Audit log is append-only on the host       | Best-effort (filesystem-dep) |
| Audit log is **tamper-evident**            | Yes (hash chain + Ed25519)   |
| Audit log is **tamper-proof**              | **No** — see below           |
| `sherlock` cannot escalate via sudo        | Yes (sudoers explicit list)  |
| Privileged ops require PQC challenge       | Yes (`quantum-root`)         |
| Cryptographic non-repudiation in court     | **No** — see below           |
| Zero-trust against the analyst             | **No** — by design           |

## Roles

### `sherlock` — the analyst

The analyst account. Owns `/cases`, `/reports`, `/var/log/forensics`, and
`/opt/forensics/quantum-keys`. Permitted to:

- Run any forensic tool installed in the container.
- Use `sudo` for the specific apt/pip commands listed in
  [`config/sudoers.d-sherlock`](../config/sudoers.d-sherlock).
- Append to the audit log.
- Authenticate to `quantum-root` to obtain a privileged shell (when the
  PQC keypair has been generated and the passphrase is known).

Explicitly **not** permitted:

- `sudo bash`, `sudo su`, `sudo -i`, `sudo -s`, or any other path to a
  generic root shell. The sudoers policy is whitelist-only with explicit
  argument patterns.
- Editing `/etc/passwd`, `/etc/shadow`, or the sudoers files.
- Generic `chattr` on arbitrary paths.

### `root` — locked

The container's `root` account is **password-locked** (`passwd -l`). It is
reachable only via:

1. The Docker daemon (`docker exec -u root` from the host).
2. `quantum-root` (after a successful ML-DSA-65 challenge).

There is no in-container path from `sherlock` to `root` without PQC
authentication or daemon-level access.

## Tamper-evident vs tamper-proof

**Tamper-evident** means: if someone modifies a past audit-log entry, you
will be able to *detect* the modification by re-running
`forensics-audit verify`. The hash chain breaks and the Ed25519 signature
on every subsequent entry stops verifying.

**Tamper-proof** would mean: a past entry cannot be modified at all. We
do not claim that, because:

1. The Ed25519 *signing key* is stored in the container, in
   `/opt/forensics/quantum-keys/audit_ed25519.key`. An attacker who has
   both root in the container and access to that key can rewrite the
   entire log: regenerate hashes, re-sign every entry, and produce a
   chain that verifies cleanly.
2. The append-only attribute (`chattr +a`) is best-effort. Bind mounts
   on overlay/btrfs/macOS-via-VM frequently don't support it. Even when
   they do, root inside the container can `chattr -a` first.

For court-defensible non-repudiation you must combine this log with
**external** append-only storage:

- AWS S3 with [Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) in compliance mode
- Google Cloud Storage with [retention policies](https://cloud.google.com/storage/docs/bucket-lock)
- An RFC 3161 timestamping service applied to every entry
- A dedicated logging host that the analyst cannot administer

The `forensics-audit export` command produces a JSONL file suitable for
upload to any of the above.

## Privilege model details

The runtime container runs with:

- `cap_drop: [ALL]`
- `cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID, NET_RAW,
  NET_ADMIN, SYS_PTRACE, LINUX_IMMUTABLE]`
- `security_opt: [no-new-privileges:true]`

`privileged: true` is **off by default**. Enable it only if you need to
mount disk images via loop devices for live analysis (e.g., for
`losetup`). See [`PRIVILEGED_MODE.md`](PRIVILEGED_MODE.md) for the
trade-off.

## Cryptographic primitives

| Use                       | Algorithm        | Notes                                |
| :------------------------ | :--------------- | :----------------------------------- |
| Audit chain               | SHA-256          | One hash per entry; chains the prev. |
| Audit signature           | Ed25519          | Generated at first boot.             |
| Audit legal signature     | RSA-4096 + GPG   | Best-effort; falls back to Ed25519.  |
| Privileged-shell auth     | ML-DSA-65        | NIST FIPS 204 (Dilithium).           |
| PQC private-key wrap      | AES-256-GCM      | Key derived via Argon2id.            |

Why Argon2id (and not just PBKDF2)? Argon2id is the OWASP-recommended KDF
since 2015 and resists GPU/ASIC attacks far better. Falls back to scrypt
if `argon2-cffi` is unavailable.

## Reporting a vulnerability

1. **Do not** open a public issue.
2. Email `joao-henrike` via the address in the GitHub profile.
3. Include reproducer steps and impact.
4. Expect an acknowledgement within 7 days; coordinated disclosure
   timeline negotiated thereafter.

## Trust boundaries

```
   Host operator (root on host)                trusted
       │
       ▼
   Docker daemon                                trusted
       │
       ▼
┌────────────────────────────┐
│  Container                  │
│                             │
│   root (locked)             │  trusted (only Docker reaches it)
│      │                      │
│      │  via quantum-root    │
│      ▼                      │
│   sherlock (analyst)        │  semi-trusted
│      │                      │
│      ▼                      │
│   Audit log                 │  tamper-evident
│      │                      │
└──────┼──────────────────────┘
       ▼
   External append-only sink   trusted (out of band)
```

The "semi-trusted analyst" boundary is deliberate: forensic operations
need broad capabilities (run arbitrary parsers, read all evidence). The
goal is a **legible** record of what they did, not preventing them from
acting. If you need adversarial isolation against the analyst, run them
in a separate container with no audit-key access.
