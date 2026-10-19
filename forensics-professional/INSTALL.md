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

## 2. Prepare bind mounts and build

The default image runs as the non-root `sherlock` user. Prepare host directories
as your normal host user first; Compose will reject missing bind-mount paths.
Do not run the quickstart as root, or the directories may not be writable by
the container user.

```bash
export HOST_UID="$(id -u)"
mkdir -p evidence cases logs keys reports
docker compose build
```

The image's `sherlock` UID is set to `HOST_UID`, so new case, log, key, and
report files are normally owned by your host user. `HOST_GID` is not used by
the image build. If these directories come from an older root-running image,
check their ownership; only for legacy directories that are root-owned, fix
them once on the host with `sudo chown -R "$(id -u):$(id -g)" cases logs keys reports`.

Build time depends on network speed; the slowest step is compiling liboqs
(the post-quantum library) in the builder stage.

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

The Dockerfile's default runtime user is `sherlock`; `docker compose exec`
therefore opens a non-root shell. Verify everything is healthy:

```bash
forensics-health
```

## 5. (Optional) Generate a post-quantum authentication keypair

The ML-DSA-65 challenge module can record whether a key-authentication
challenge succeeds, but `quantum-root` does **not** grant a root shell: its
sudo handoff is not implemented and is intentionally fail-closed. Generate a
keypair as `sherlock` without sudo:

```bash
/opt/forensics/bin/generate-quantum-keys.sh
```

You'll be prompted for a passphrase used to encrypt the ML-DSA-65 private key.
Store it outside the container — **there is no recovery** if you lose it.

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
