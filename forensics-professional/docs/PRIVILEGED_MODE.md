# When (and how) to use `privileged: true`

## TL;DR

You almost certainly don't need it. The container has every capability
the standard forensic workflow requires. Use `privileged: true` only if
you need to **`losetup` an evidence image** for live mounting.

## What's already enabled

`docker-compose.yml` ships with these capabilities:

| Capability         | Why                                          |
| :----------------- | :------------------------------------------- |
| `CHOWN`            | Fix ownership on bind-mounted volumes.       |
| `DAC_OVERRIDE`     | Read evidence regardless of file perms.      |
| `FOWNER`           | chmod on owned files.                        |
| `SETGID` / `SETUID`| `gosu` privilege drop.                       |
| `NET_RAW`          | tcpdump, raw sockets.                        |
| `NET_ADMIN`        | Interface configuration for capture.         |
| `SYS_PTRACE`       | strace, ltrace for live analysis.            |
| `LINUX_IMMUTABLE`  | `chattr +a` on the audit log.                |

Plus `security_opt: [no-new-privileges:true]` to block any sneaky path
to higher caps.

## When you actually need `privileged: true`

The kernel-level operations that *can't* be done via specific caps are:

1. **Loop-mounting a disk image** — `losetup /dev/loop0 evidence.dd`.
   Requires access to `/dev/loop-control`, which is a host device, not
   a capability.
2. **Loading a kernel module** — `insmod` for LiME memory acquisition
   on the host. (Building LiME inside the container works fine without
   privileged mode; loading it on the host is what needs it.)
3. **Direct device access** — manipulating `/dev/sda*` block devices
   that are bind-mounted in.

Most analysts never do (1)–(3) inside the container. They do them on
the **host** (which has the right kernel) and bring the resulting
images/dumps into `/evidence` (read-only) for analysis.

## How to enable it (per deployment)

Don't edit `docker-compose.yml`. Create
`docker-compose.override.yml` next to it:

```yaml
services:
  forensics:
    privileged: true
    devices:
      - /dev/loop-control:/dev/loop-control
```

`docker compose up -d` automatically merges the override.

## Trade-offs

`privileged: true`:

- Disables most of the container's isolation.
- Bypasses `cap_drop: ALL`.
- Makes `no-new-privileges: true` irrelevant for this container.
- Allows escape via `cgroup` notify_on_release tricks (and many others).

If you're handling adversarial evidence (malware samples, threat
actor infrastructure dumps), **never** use privileged mode. Run a
plain analysis pass first to verify the evidence is what you think it
is, then pivot to privileged mode in a separate, network-isolated
deployment if you need the loop mount.

## A safer alternative for loop mounting

Mount the loop device on the **host**, then bind-mount the resulting
mount point read-only into the container:

```bash
# On the host
mkdir -p /mnt/case-2026-001
sudo losetup -P /dev/loop10 /path/to/evidence.dd
sudo mount -o ro,noexec /dev/loop10p1 /mnt/case-2026-001
```

```yaml
# docker-compose.override.yml
services:
  forensics:
    volumes:
      - type: bind
        source: /mnt/case-2026-001
        target: /evidence/case-2026-001
        read_only: true
```

You get full read-only access to a real filesystem from inside a
non-privileged container. The loop device and its risks stay on the
host where you can audit them.
