# A First Case — End-to-End Walk-Through

This tutorial walks you through a complete (small) investigation:
acquiring evidence, analysing it, and producing an exportable audit
trail. Total time: about 30 minutes.

We'll investigate a fictional incident: **"a developer reports their
machine running slowly; suspect malware."** The evidence is a memory
dump.

## Setup (5 min)

If you haven't yet:

```bash
git clone https://github.com/joao-henrike/Containers.git
cd Containers/forensics-professional
docker compose up -d
docker compose exec forensics bash
```

You're now in the container as `sherlock`.

## 1. Open a case (1 min)

Forensic cases are tracked under `/cases/`. Convention:
`/cases/<incident-id>-<short-tag>`.

```bash
mkdir -p /cases/INC-2026-042-slow-laptop
cd /cases/INC-2026-042-slow-laptop
```

Record the case-open event explicitly:

```bash
python3 - <<'PY'
from forensics.audit.logger import log_event
log_event("case_opened", {
    "case_id": "INC-2026-042",
    "summary": "Slow laptop, suspected malware",
    "analyst": "sherlock",
})
PY
```

This is the audit-log event your future self (or auditor) will look for
to anchor the timeline.

## 2. Install the modules you need (3 min)

For a memory-dump triage you typically want Volatility 3 and YARA.

```bash
forensics-modules install memory-forensics --only volatility -y
forensics-modules install malware-analysis --only yara -y
```

Watch the streamed output. When done, verify:

```bash
forensics-modules verify
```

## 3. Stage the evidence (5 min)

In a real case the dump arrives via your evidence-handling process. For
the tutorial, fetch a sample:

```bash
mkdir -p /cases/INC-2026-042-slow-laptop/evidence
cd /cases/INC-2026-042-slow-laptop/evidence

# A small public memory image from the Volatility Foundation
curl -fsSL -o win.vmem.gz \
    https://downloads.volatilityfoundation.org/volatility3/images/win.vmem.gz
gunzip win.vmem.gz

# Compute the working hash
sha256sum win.vmem | tee win.vmem.sha256
```

Record the acquisition:

```bash
python3 - <<'PY'
import hashlib
from pathlib import Path
from forensics.audit.logger import log_event

p = Path("win.vmem")
log_event("evidence_acquired", {
    "case_id":  "INC-2026-042",
    "filename": str(p),
    "size":     p.stat().st_size,
    "sha256":   hashlib.sha256(p.read_bytes()).hexdigest(),
    "source":   "volatilityfoundation.org/sample",
})
PY
```

## 4. Triage (10 min)

A reasonable first pass for a Windows memory dump:

```bash
# What OS / build?
vol -f win.vmem windows.info

# Process listing
vol -f win.vmem windows.pslist > pslist.txt
wc -l pslist.txt

# Network state at capture time
vol -f win.vmem windows.netscan > netscan.txt

# Process tree
vol -f win.vmem windows.pstree > pstree.txt

# Suspicious DLLs
vol -f win.vmem windows.dlllist | grep -iE 'temp|appdata' > suspicious-dlls.txt
```

Each `vol` run is logged automatically by the chain-of-custody hook.

## 5. Hunt for known-bad (5 min)

Use YARA against process memory:

```bash
# Pull a public ruleset
git clone --depth 1 https://github.com/Yara-Rules/rules /tmp/yara-rules

# Dump a suspicious process's memory and scan
vol -f win.vmem windows.memmap --pid 4 --dump
yara -r /tmp/yara-rules/malware/ pid.4.dmp > yara-hits.txt
```

If you get hits, log them:

```bash
python3 - <<'PY'
from forensics.audit.logger import log_event
with open("yara-hits.txt") as f:
    hits = [line.strip() for line in f if line.strip()]
log_event("yara_hits_recorded", {
    "case_id": "INC-2026-042",
    "count":   len(hits),
    "samples": hits[:10],
})
PY
```

## 6. Export the audit trail (1 min)

```bash
mkdir -p /reports/INC-2026-042
forensics-audit verify
forensics-audit export \
    --output /reports/INC-2026-042/audit.jsonl \
    --format jsonl
forensics-audit stats
```

## 7. Hand-off package

A typical hand-off package contains:

```
/reports/INC-2026-042/
├── audit.jsonl                # signed audit trail
├── evidence-hashes.txt         # SHA-256 of every evidence file
├── analysis-notes.md           # written summary
└── artefacts/
    ├── pslist.txt
    ├── netscan.txt
    ├── pstree.txt
    └── yara-hits.txt
```

```bash
cd /cases/INC-2026-042-slow-laptop
sha256sum evidence/* > /reports/INC-2026-042/evidence-hashes.txt
cp evidence/*.txt /reports/INC-2026-042/artefacts/
echo "Analyst: sherlock\nDate: $(date -u)\nSummary: ..." \
    > /reports/INC-2026-042/analysis-notes.md
```

## 8. Verify before close

Before closing the case:

```bash
forensics-audit verify
```

Status must be `VALID`. If it isn't, **stop and investigate** — the
audit chain has been disturbed and the case is no longer
court-defensible without external timestamping evidence.

## Lessons

- Every shell command was logged automatically.
- Module installs were logged with their submodule manifest digests.
- The case timeline is reconstructable from a single JSONL file.
- The evidence file was never modified — it sat under `/cases/...` and
  was opened read-only by every tool.

For a deeper dive into how the chain works, see
[`ARCHITECTURE.md`](../../ARCHITECTURE.md).
