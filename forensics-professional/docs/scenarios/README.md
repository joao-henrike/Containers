# Demonstration Scenarios

Six end-to-end scenarios for demonstrating Forensics Professional in
realistic attack/defend exercises. Each scenario includes:

1. **Lab setup** — `docker compose` files and configs to spin up a
   vulnerable target.
2. **The attack** — exact red-team commands to compromise the target.
3. **The investigation** — blue-team workflow inside the
   forensics-professional container.
4. **Expected findings** — the IoCs you should be able to recover.
5. **Cleanup** — how to reset the lab between runs.

> **Read this first.** Every scenario assumes a **disposable, isolated
> network**. Run on a workstation you own or a dedicated VM. Don't
> point any of these tools at infrastructure you don't have written
> permission to test. The DNS-tunneling and C2 scenarios in particular
> generate traffic patterns that *will* show up on your ISP's or
> corporate IDS dashboards.

## Scenario index

| # | Scenario | Focus | Difficulty |
|---|----------|-------|------------|
| [1](01-apache-web-attack.md) | Apache web compromise (SQLi → webshell) | Web-server logs, file timeline | ★★☆☆☆ |
| [2](02-dns-tunneling.md) | Data exfiltration via DNS tunneling     | Network forensics, PCAP analysis | ★★★☆☆ |
| [3](03-ransomware-container.md) | Container ransomware infection   | Malware analysis, YARA, reverse engineering | ★★★★☆ |
| [4](04-privilege-escalation.md) | Linux privilege escalation       | Process auditing, system logs | ★★☆☆☆ |
| [5](05-c2-beaconing.md) | C2 beacon detection                       | Traffic statistics, anomaly detection | ★★★☆☆ |
| [6](06-credential-leak.md) | Leaked credentials → DB intrusion      | Git history, DB log analysis | ★★★☆☆ |

## Common lab requirements

All scenarios assume you have:

- Docker 24+ and Docker Compose v2
- 8 GB RAM available
- ~20 GB free disk
- A Linux host (preferred) or macOS/Windows with Docker Desktop
- The `forensics-professional` container already built:

```bash
cd forensics-professional
docker compose build
```

## Recommended workflow

For a classroom demo, the following sequence works well:

```
┌──────────────────────────────────────────────────────────────────┐
│  T-15  Spin up the lab (per-scenario instructions)               │
│  T-10  Run the attack (red-team narrative)                       │
│   T-0  Pretend the analyst is just arriving on shift             │
│   T+5  Acquire artefacts into /evidence (forensics container)    │
│  T+10  Triage with forensics-modules + audit log                 │
│  T+25  Reconstruct timeline                                      │
│  T+30  forensics-audit verify → "VALID" closes the loop          │
│  T+35  Tear down with `docker compose down -v`                   │
└──────────────────────────────────────────────────────────────────┘
```

## Network topology (conceptual)

```
          ┌─────────────────────────────┐
          │   forensics-net (172.30.0/24)│
          └─────────────────────────────┘
              │           │          │
              ▼           ▼          ▼
        ┌─────────┐ ┌──────────┐ ┌──────────┐
        │ target  │ │ attacker │ │ forensics│
        │ (vict.) │ │ (kali-   │ │ (analyst)│
        │         │ │  like)   │ │          │
        └─────────┘ └──────────┘ └──────────┘
```

Per-scenario `docker-compose.lab.yml` files live in
`docs/scenarios/labs/<n>-<name>/`. They share a common Docker network
named `forensics-net` so the attacker and victim can reach each other,
but the network is bridged with `internal: true` so it cannot reach the
host LAN.

## Evidence handoff

When a scenario asks you to "copy artefacts into the forensics
container," use the analyst's `/evidence` mount:

```bash
# On the host, after the attack finishes
docker cp <victim-container>:/var/log/apache2 ./evidence/case-X/apache-logs/

# Inside forensics-professional
ls /evidence/case-X/
```

The bind mount at `/evidence` is **read-only** inside the container —
analysts cannot accidentally modify the original artefacts.

## Audit-trail demonstrations

Every scenario ends with verifying the audit trail. The killer demo
moment is:

```bash
# Inside forensics-professional after the investigation
forensics-audit verify
# → STATUS: VALID

# Now have a participant tamper with the log on the host
echo '{"hello":"world"}' >> ./logs/audit.log

# Re-run inside the container
forensics-audit verify
# → STATUS: COMPROMISED
#   ↳ seq 47: hash_mismatch
```

That single contrast — the chain catches one byte of tampering — is
what separates "logging" from "auditable forensics."

## Reset between scenarios

Each scenario directory has a `reset.sh` that:

1. `docker compose -f docker-compose.lab.yml down -v`
2. removes any artefacts under `evidence/case-N/`
3. resets the forensics container's working dirs (`cases/`, `reports/`)
   if you want a clean state.

The audit log is **not** reset by default — you typically want it to
survive across scenarios so you can demonstrate one continuous chain
covering an entire investigation week.
