# Installation

## Requirements

| Component        | Minimum               | Notes                                    |
| :--------------- | :-------------------- | :--------------------------------------- |
| Docker Engine    | 24.0                  | Older versions lack BuildKit defaults.   |
| Docker Compose   | v2 (plugin form)      | `docker compose`, not `docker-compose`.  |
| Linux kernel     | 5.10+                 | For up-to-date capability semantics.     |
| Disk             | 12 GB free            | Image + 2 GB working room for evidence.  |
| RAM              | 4 GB available        | More if you run memory analysis.         |
| CPU architecture | x86_64                | ARM64 builds work but most modules ship  |
|                  |                       | x86_64 binaries only.                    |

> macOS and Windows users: Docker Desktop works for everything except
> kernel-level memory acquisition (LiME) and disk loop-mounting. For
> those, run on a Linux host.

## 1. Clone

```bash
git clone https://github.com/joao-henrike/Containers.git
cd Containers/forensics-professional
```

## 2. Build

```bash
docker compose build
```

Build time depends on network speed; expect 10–20 minutes on a fresh
machine. The slowest step is compiling liboqs (the post-quantum library)
in the builder stage.

To pin the host UID/GID to your local user (so files written into
`./cases` aren't owned by 1000 if you happen to use a different ID):

```bash
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose build
```

## 3. Start

```bash
docker compose up -d
```

The container performs first-boot setup automatically:

1. Creates `/var/log/forensics/audit.log` with the genesis entry.
2. Generates an Ed25519 audit-signing keypair under
   `/opt/forensics/quantum-keys/`.
3. Generates a passphrase-protected GPG key.
4. Marks the audit log as append-only (`chattr +a`) when the host
   filesystem supports it.

## 4. Enter the container

```bash
docker compose exec forensics bash
```

You'll land in the `sherlock` account. Verify everything is healthy:

```bash
forensics-health
```

## 5. (Optional) Set up post-quantum authentication

If you want `quantum-root` to actually gate privilege escalation:

```bash
# Inside the container
sudo /opt/forensics/bin/generate-quantum-keys.sh
```

You'll be prompted for a passphrase; it's used to AES-encrypt the
ML-DSA-65 private key. Store the passphrase outside the container —
**there is no recovery** if you lose it.

## 6. Install your first module

```bash
forensics-modules list
forensics-modules install memory-forensics --only volatility,avml
forensics-modules verify memory-forensics
```

## Updating

```bash
git pull
docker compose build
docker compose down
docker compose up -d
```

The audit log, keys, and case files are stored in bind mounts (`./logs`,
`./keys`, `./cases`) — they survive container rebuilds.

## Uninstalling

```bash
docker compose down
docker rmi forensics-professional:3.0.0
```

To wipe persisted data too:

```bash
rm -rf logs/* keys/* cases/* reports/* modules/installed/*
```

> Wiping the keys directory permanently invalidates all past audit-log
> signatures. Only do this if you intend to start a new investigation
> chain.

## Troubleshooting

### Build fails on `liboqs` compile

The PQC builder stage needs ~2 GB RAM. If your build machine has less,
or if you're behind a strict proxy:

```bash
# Skip PQC entirely (quantum-root will be unavailable)
docker compose build --build-arg LIBOQS_REF=skip
```

### `chattr: Operation not supported`

Your host filesystem doesn't support `chattr +a` (common with overlayfs,
btrfs subvolumes, tmpfs, NFS, macOS, Windows). The audit log stays
tamper-evident via signatures; you just lose the host-level append-only
guarantee. Move the bind mount onto an ext4 partition to get it back.

### `sudo: command not found` inside the container

This indicates an old image. Rebuild from scratch:

```bash
docker compose build --no-cache
```

### Container says "healthy" but `forensics-modules list` is empty

The registry didn't load. Inspect the logs:

```bash
docker compose logs forensics
```

Common cause: a bind-mounted `modules/registry.json` overriding the
container's copy with a malformed JSON file. Either fix the JSON or
remove the override from `docker-compose.override.yml`.
