---
name: Bug Report
about: Report a bug or issue with the forensics container
title: '[BUG] '
labels: bug
assignees: ''
---

## 🐛 Bug Description

A clear and concise description of the bug.

## 🔄 Steps to Reproduce

1. Clone repository
2. Run command '...'
3. See error '...'

## ✅ Expected Behavior

What should have happened.

## ❌ Actual Behavior

What actually happened.

## 🖥️ Environment

**Host System:**
- OS: [e.g., Ubuntu 22.04, Kali Linux 2024.1, Windows 11 WSL2]
- Docker Version: [run `docker --version`]
- Docker Compose Version: [run `docker-compose --version`]

**Container:**
- Container Version: [e.g., 2.0.0]
- Running in: [VM / Bare Metal / WSL2]
- Virtualization: [VirtualBox / VMware / Hyper-V / None]

**Resources:**
- CPU Cores: [e.g., 8]
- RAM: [e.g., 16GB]
- Disk Space Available: [e.g., 100GB]

## 📋 Logs

<details>
<summary>Container Logs</summary>

```bash
# Output of: docker-compose logs
[Paste logs here]
```

</details>

<details>
<summary>Health Check</summary>

```bash
# Output of: docker exec forensics-workstation forensics-health check
[Paste output here]
```

</details>

## 📸 Screenshots

If applicable, add screenshots to help explain the problem.

## 🔍 Additional Context

Any other information that might be helpful:
- Were you installing a specific module?
- Did this work before?
- Any customizations made?
- Error messages in browser console (if web UI)?

## ✔️ Checklist

- [ ] I searched existing issues before creating this one
- [ ] I included all relevant logs
- [ ] I specified my environment details
- [ ] I can reproduce this consistently
- [ ] This is not a security vulnerability (use security@your-org.com instead)
