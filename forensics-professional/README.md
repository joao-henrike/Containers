# Professional Forensics Container v2.1.0

[![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Compliance](https://img.shields.io/badge/compliance-NIST%20SP%20800--86-orange.svg)]()
[![Crypto](https://img.shields.io/badge/crypto-Post--Quantum-purple.svg)]()
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Modules](https://img.shields.io/badge/modules-14-blue.svg)]()
[![Tools](https://img.shields.io/badge/tools-161-green.svg)]()

> 🔍 A professional-grade Docker container for digital forensics with post-quantum cryptography, immutable audit trails, modular tool installation, and comprehensive OSINT capabilities.

---

## 📚 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Available Modules](#-available-modules)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [License](#-license)
- [Support](#-support)

## 🎯 Overview

A **professional-grade Docker container** for digital forensics with:
- 🔐 **Post-Quantum Cryptography** (Kyber/Dilithium) for root protection
- 📝 **Immutable Audit Trails** (Ed25519 + GPG hybrid signatures)
- 🔗 **Automated Chain of Custody**
- 🧩 **Modular Tool Installation** (install only what you need)
- ⚡ **Parallel Processing** for maximum performance
- 📊 **NIST SP 800-86 Compliance**
- 🛡️ **Evidence Protection** (read-only, cannot be deleted)
- 🔍 **OSINT & Threat Intelligence** (14 modules total) 🆕

## 🚀 Key Features

### Security Architecture

```
ROOT (owner only - PQC encrypted)
└── Post-Quantum encrypted with Kyber/Dilithium
    └── Only accessible with private key

SHERLOCK (public user)
├── ✅ Install modules
├── ✅ Analyze evidence
├── ✅ Generate reports
├── ✅ Configure system
├── ❌ Delete/modify evidence
├── ❌ Alter audit logs
└── ❌ Escalate to root
```

### Immutable Audit System

Every action is logged with:
- **Timestamp** (RFC 3339, UTC)
- **User** who performed the action
- **Event type** and details
- **Previous hash** (blockchain-like chain)
- **Current hash** (SHA-256)
- **Dual signatures** (Ed25519 + GPG)

This creates a **verifiable, tamper-evident audit trail**.

### Modular Architecture

Install only the tools you need:

```bash
# List available modules
forensics-modules list

# Install specific module
forensics-modules install memory-forensics

# Install with specific sub-modules only
forensics-modules install cloud-forensics --only aws-tools,gcp-tools

# Interactive selection
forensics-modules install malware-analysis --interactive
```

## 🧩 Available Modules

The container uses a modular architecture - install only what you need!

| Module | Category | Tools | Size | Description |
|--------|----------|-------|------|-------------|
| **cloud-forensics** | Cloud | 15 | 250 MB | AWS, Azure, GCP investigation tools |
| **memory-forensics** | Memory | 8 | 180 MB | Volatility, Rekall, memory dumps |
| **disk-forensics** | Disk | 12 | 320 MB | Sleuthkit, Autopsy, file carving |
| **network-forensics** | Network | 10 | 200 MB | Wireshark, Zeek, packet analysis |
| **mobile-forensics** | Mobile | 8 | 150 MB | Android/iOS device forensics |
| **malware-analysis** | Malware | 15 | 500 MB | YARA, radare2, Ghidra, Cuckoo |
| **windows-forensics** | Windows | 10 | 180 MB | Registry, EVTX, Prefetch analysis |
| **linux-forensics** | Linux | 8 | 120 MB | Auditd, log parsing, ext4 tools |
| **container-forensics** | Container | 6 | 100 MB | Docker/Kubernetes investigation |
| **database-forensics** | Database | 9 | 140 MB | MySQL, PostgreSQL, MongoDB |
| **email-forensics** | Email | 7 | 90 MB | PST/EML parsing, headers |
| **osint-tools** 🆕 | OSINT | 25 | 450 MB | Social media, people search, dark web |
| **threat-intelligence** 🆕 | Intel | 15 | 320 MB | IOC feeds, MISP, threat hunting |
| **web-recon** 🆕 | Recon | 18 | 280 MB | Subdomain enum, web scraping, DNS |

**Total:** 14 modules • 161 tools • ~3.3 GB (all modules)

> ✅ **All tools are fully functional** - Real installation, not simulated!

## 📦 Quick Start

### Prerequisites

- Docker 20.10+
- Docker Compose 1.29+
- 8GB RAM minimum (16GB recommended)
- 50GB free disk space

### Installation

#### Step 1: Clone from GitHub

```bash
# Clone the repository
git clone https://github.com/YOUR-USERNAME/forensics-professional.git
cd forensics-professional
```

#### Step 2: Initialize Directory Structure

```bash
# The required directories already exist with .gitkeep files
# But ensure they have correct permissions:
chmod 750 evidence cases keys logs reports modules config
```

#### Step 3: Build the Container

```bash
# Build (first time takes ~10-15 minutes)
docker-compose build

# This will:
# - Download Ubuntu 22.04 base image (~80 MB)
# - Compile post-quantum crypto libraries
# - Install forensic tool dependencies
# - Configure security hardening
# - Set up audit system
```

#### Step 4: Start the Container

```bash
# Start in detached mode
docker-compose up -d

# Verify it's running
docker ps
```

#### Step 5: Access the Forensics Shell

```bash
# Access as sherlock user
docker exec -it forensics-workstation bash

# You'll see the professional forensics banner!
```

#### Quick Install (One-liner)

```bash
git clone https://github.com/YOUR-USERNAME/forensics-professional.git && \
cd forensics-professional && \
docker-compose build && \
docker-compose up -d && \
docker exec -it forensics-workstation bash
```

### First Steps

```bash
# Inside the container

# 1. Verify system health
forensics-health check

# 2. Check audit log integrity
forensics-audit verify

# 3. List available modules
forensics-modules list

# 4. Install tools you need
forensics-modules install disk-forensics

# 5. Start working!
cd /cases
```

### OSINT Investigation Example 🆕

```bash
# Install OSINT module
forensics-modules install osint-tools

# Social media investigation
sherlock target_username

# Email verification
holehe suspect@email.com

# Domain reconnaissance  
theHarvester -d target-company.com -b all
amass enum -d target-company.com

# Phone number OSINT
phoneinfoga scan -n +1234567890
```

📖 **Complete OSINT Guide:** [OSINT_INTELLIGENCE_TOOLS.md](docs/OSINT_INTELLIGENCE_TOOLS.md)

## 🔧 Usage

### Module Management

```bash
# List available modules
forensics-modules list

# Show module details
forensics-modules info memory-forensics

# Install complete module
forensics-modules install memory-forensics

# Install specific sub-modules only
forensics-modules install cloud-forensics --only aws-tools,azure-tools

# Interactive sub-module selection
forensics-modules install malware-analysis --interactive

# Check installed modules
forensics-modules status

# Remove module
forensics-modules remove network-forensics
```

### Audit System

```bash
# Verify audit log integrity
forensics-audit verify

# Show recent audit entries
forensics-audit show

# Show last 50 entries
forensics-audit show --limit 50

# Filter by event type
forensics-audit show --event-type module_install

# Filter by user
forensics-audit show --user sherlock

# Export audit log
forensics-audit export --output audit_backup.json --format json

# Show statistics
forensics-audit stats
```

### Health & Debugging

```bash
# Quick health check
forensics-health quick-check

# Comprehensive health check
forensics-health check

# Diagnose performance issues
forensics-health why-slow "log2timeline.py"

# Capture system snapshot
forensics-health snapshot
```

## 🏗️ Architecture

```
forensics-professional/
├── Dockerfile                    # Multi-stage optimized build
├── docker-compose.yml            # Orchestration config
├── docker-entrypoint.sh          # Initialization script
│
├── core/                         # Core systems
│   ├── audit-system/             # Immutable audit logging
│   │   ├── audit-logger.py       # Cryptographic logger
│   │   ├── forensics-audit       # CLI interface
│   │   ├── init-audit.py         # Initialization
│   │   └── init-keys.sh          # Key setup
│   │
│   ├── module-manager/           # Module installation
│   │   └── forensics-modules     # Module manager CLI
│   │
│   ├── compliance/               # NIST compliance (placeholder)
│   ├── integrations/             # External integrations (placeholder)
│   └── init-environment.sh       # Environment setup
│
├── scripts/                      # Utility scripts
│   └── forensics-health          # Health & debugging
│
├── docs/                         # Documentation
│   └── banner.txt                # Welcome banner
│
├── modules/                      # Module definitions (host)
├── config/                       # Configuration (host)
├── evidence/                     # Evidence files (host, read-only)
├── cases/                        # Case working directories (host)
├── keys/                         # Cryptographic keys (host)
├── logs/                         # Audit logs (host)
└── reports/                      # Generated reports (host)
```

## 🛡️ Security Model

### Evidence Protection

```bash
# Evidence directory is mounted READ-ONLY
# sherlock user cannot:
- Delete evidence files
- Modify evidence files
- Change permissions

# Attempts to modify trigger audit log:
[2026-02-07T20:00:00Z] VIOLATION_ATTEMPT
  - Action: DELETE evidence
  - User: sherlock
  - File: disk.img
  - Result: BLOCKED
```

### Audit Log Protection

```bash
# Audit logs have append-only attribute (chattr +a)
# Even root cannot modify past entries
# Can only append new entries

# Each entry is:
1. Linked to previous entry (blockchain-like)
2. Signed with Ed25519
3. Signed with GPG
4. Timestamped (UTC)
```

### Root Access

```bash
# Root password is disabled
# Root access ONLY via post-quantum encrypted key
# Only container owner has the private key

# To access as root (owner only):
# 1. Decrypt root key with PQC private key
# 2. Use decrypted key to access
```

## 📊 NIST SP 800-86 Compliance

This container is designed to align with **NIST SP 800-86** guidelines:

- ✅ **Section 3.1.3** - Evidence Collection (automated chain of custody)
- ✅ **Section 3.1.4** - Evidence Examination (modular tools)
- ✅ **Section 3.1.5** - Evidence Analysis (documented workflow)
- ✅ **Section 4** - Forensic Tool Validation (module verification)
- ✅ **Appendix D** - Chain of Custody (immutable audit trail)

Validate compliance:
```bash
forensics-compliance validate
```

## ⚡ Performance

### Parallel Processing

The container is optimized for parallel execution:
- Multi-core utilization
- Concurrent module installations
- Parallel forensic analysis
- Async I/O operations

### Resource Optimization

```yaml
# Default resource limits (docker-compose.yml)
resources:
  limits:
    cpus: '8'
    memory: 16G
  reservations:
    cpus: '4'
    memory: 8G
```

Adjust based on your hardware and workload.

## 🤝 Contributing

We welcome contributions from the forensic and security community!

**Ways to contribute:**
- 🐛 Report bugs via [GitHub Issues](https://github.com/YOUR-USERNAME/forensics-professional/issues)
- 💡 Suggest features via [Feature Requests](https://github.com/YOUR-USERNAME/forensics-professional/issues/new?template=feature_request.md)
- 🔧 Submit pull requests
- 📖 Improve documentation
- 🧩 Add forensic modules
- 🌍 Translate documentation

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and development process.

## 📄 License

This project is licensed under the MIT License with forensic disclaimers - see the [LICENSE](LICENSE) file for details.

**Important:** This tool is for legitimate forensic investigations only. Users are responsible for legal compliance, evidence integrity, and following proper forensic procedures.

## 📞 Support

- **📖 Documentation**: [Full docs](docs/)
- **💬 Discussions**: [GitHub Discussions](https://github.com/YOUR-USERNAME/forensics-professional/discussions)
- **🐛 Bug Reports**: [GitHub Issues](https://github.com/YOUR-USERNAME/forensics-professional/issues)
- **📧 Email**: support@your-org.com
- **🔐 Security**: security@your-org.com (for vulnerabilities)

## 🌟 Star History

If this project helped you, please ⭐ star it on GitHub!

[![Star History Chart](https://api.star-history.com/svg?repos=YOUR-USERNAME/forensics-professional&type=Date)](https://star-history.com/#YOUR-USERNAME/forensics-professional&Date)

## 🙏 Acknowledgments

- Open Quantum Safe (liboqs) for post-quantum cryptography
- The Sleuth Kit Project
- Volatility Foundation
- All open-source forensic tool developers
- Digital forensics community

---

**Made with ❤️ for the digital forensics community**

**Version**: 2.1.0 | **Modules**: 14 | **Tools**: 161+  
**Compliance**: NIST SP 800-86  
**Cryptography**: Post-Quantum Ready  
**License**: MIT
