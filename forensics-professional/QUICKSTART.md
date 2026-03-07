# Quick Start Guide - Professional Forensics Container

Get started in under 5 minutes!

## ⚡ Prerequisites

- Docker 20.10+ installed
- Docker Compose 1.29+ installed
- 8GB RAM minimum (16GB recommended)
- 50GB free disk space

## 🚀 Installation

### 1. Build the Container (2 minutes)

```bash
cd forensics-professional
docker-compose build
```

### 2. Start the Container (30 seconds)

```bash
docker-compose up -d
```

### 3. Access the Shell (instant)

```bash
docker exec -it forensics-workstation bash
```

You'll see the professional forensics banner!

## 🎯 First Steps Inside the Container

### Verify System Health

```bash
forensics-health check
```

Expected output:
```
✅ Evidence directory: OK
✅ Cases directory: OK
✅ Cryptographic keys: OK
✅ Audit log: IMMUTABLE
✅ CPU cores: 8
✅ Memory: 16.0GB total, 12.5GB available
```

### Check Audit Log

```bash
forensics-audit verify
```

Expected output:
```
🔍 Verifying audit log integrity...
✅ VALID: Verified 1 entries successfully
```

### List Available Modules

```bash
forensics-modules list
```

You'll see all 11 available forensic tool modules.

### Install Your First Module

```bash
# Example: Install disk forensics tools
forensics-modules install disk-forensics
```

This installs: sleuthkit, autopsy, testdisk, foremost, scalpel

## 📁 Working with Evidence

### Add Evidence (on host machine)

```bash
# Copy your evidence to the evidence directory
cp /path/to/disk.img forensics-professional/evidence/
```

### Access Evidence (inside container)

```bash
# Evidence is at /evidence (read-only)
ls /evidence

# Try to delete (will fail - protected!)
rm /evidence/disk.img
# Permission denied: Evidence is immutable
```

## 🔬 Start Analyzing

### Create Case Working Directory

```bash
# Inside container
cd /cases
mkdir CASE-2026-001
cd CASE-2026-001
```

### Hash Evidence

```bash
# Compute hashes
sha256sum /evidence/disk.img > disk.img.sha256

# This action is logged in audit trail
forensics-audit show --limit 5
```

### Analyze with Installed Tools

```bash
# If you installed disk-forensics:
mmls /evidence/disk.img           # List partitions
fls -r /evidence/disk.img          # List files
icat /evidence/disk.img 128 > file.txt  # Extract file
```

## 📊 View Audit Trail

```bash
# Show recent actions
forensics-audit show

# Show statistics
forensics-audit stats

# Export for reporting
forensics-audit export --output audit.json
```

## 🔧 Troubleshooting

### Container won't start

```bash
# Check Docker status
docker ps -a

# View logs
docker-compose logs

# Rebuild
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Permission issues

```bash
# Inside container
whoami
# Should output: sherlock

# Check evidence is protected
ls -la /evidence
# Should show root:forensics-ro and read-only
```

### Module installation fails

```bash
# Check system health
forensics-health check

# Try again with verbose output
forensics-modules install disk-forensics
```

## 📖 Next Steps

- Read full [README.md](README.md)
- Install more modules as needed
- Explore modular sub-module installation
- Set up automated workflows

## 💡 Pro Tips

1. **Install only what you need** - keeps container lean
2. **Always verify audit log** - `forensics-audit verify`
3. **Use parallel cores** - analysis is multi-threaded by default
4. **Evidence is protected** - you cannot delete it (by design)
5. **Everything is logged** - check `forensics-audit show`

## 🎓 Example Workflow

```bash
# 1. Start container
docker-compose up -d
docker exec -it forensics-workstation bash

# 2. Install tools
forensics-modules install disk-forensics memory-forensics

# 3. Navigate to cases
cd /cases/CASE-001

# 4. Analyze evidence
mmls /evidence/suspect.img
fls -r /evidence/suspect.img > filelist.txt

# 5. Check audit trail
forensics-audit show

# 6. Generate report
# (create report manually or use forensics-report when implemented)
```

## ⚠️ Remember

- All actions are logged (immutable audit trail)
- Evidence cannot be deleted or modified
- Modules install from internet (ensure connectivity)
- Root access is encrypted (owner only)

---

**Ready to investigate!** 🔍

For help: Run any command with `--help`
