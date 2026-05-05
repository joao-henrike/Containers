# Quickstart

> **Goal:** from a fresh clone to your first analyzed memory dump in
> under 15 minutes.

## 1. Clone and build (5 min)

```bash
git clone https://github.com/joao-henrike/Containers.git
cd Containers/forensics-professional
docker compose build
docker compose up -d
docker compose exec forensics bash
```

## 2. Verify the environment (30 s)

```bash
forensics-health
```

Expect every probe to be ✓ except **ML-DSA-65 keypair** (warns until
you generate it; this is fine for normal use).

## 3. Install a module (2–3 min)

```bash
forensics-modules install memory-forensics --only volatility -y
```

Output streams in real time. You'll see `apt-get` and `pip` calls. When
it's done you'll see:

```
✓  memory-forensics: 1/1 OK
```

## 4. Acquire some evidence

For this walk-through, grab a small public memory image:

```bash
cd /cases
mkdir tutorial && cd tutorial
curl -L -o win7.vmem.lzma \
    https://downloads.volatilityfoundation.org/volatility3/images/win-10.lzma
unxz win7.vmem.lzma
```

Real evidence would arrive on a write-blocked drive and be mounted at
`/evidence` (read-only).

## 5. Analyse it

```bash
vol -f win7.vmem windows.info
vol -f win7.vmem windows.pslist
vol -f win7.vmem windows.netscan
```

Each `vol` call is auto-logged. Confirm:

```bash
forensics-audit show --event-type command_executed --limit 10
```

## 6. Verify the audit chain

```bash
forensics-audit verify
```

Expect:

```
STATUS: VALID
Hash chain intact, signatures verified.
```

## 7. Export for handover

```bash
forensics-audit export \
    --output /reports/case-tutorial-audit.jsonl \
    --format jsonl
```

Hand that file to whatever long-term storage your organisation uses
(S3 Object Lock, etc.).

## What now?

- [Full module catalogue](README.md#module-catalogue)
- [Detailed example: a real case](docs/examples/first-case.md)
- [Architecture overview](ARCHITECTURE.md)
- [Threat model](SECURITY.md)
