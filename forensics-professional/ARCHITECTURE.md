# Architecture Documentation

## System Overview

Professional Forensics Container v2.0.0 is a modular, security-hardened digital forensics environment built on:

- **Base OS**: Ubuntu 22.04 LTS
- **Cryptography**: Post-Quantum (liboqs), Ed25519, GPG
- **Architecture**: Multi-stage Docker build
- **Compliance**: NIST SP 800-86
- **License**: MIT

## Security Model

### User Hierarchy

```
┌─────────────────────────────────────┐
│ ROOT (PQC Encrypted)                │
│ - Post-quantum cryptography         │
│ - Owner only (private key required) │
│ - Full system access                │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│ SHERLOCK (Public User)              │
│ - UID 1000                          │
│ - Full forensic capabilities        │
│ - CANNOT: delete evidence           │
│ - CANNOT: modify audit logs         │
│ - CANNOT: escalate to root          │
└─────────────────────────────────────┘
```

### Evidence Protection

```
/evidence (mounted read-only)
├── Ownership: root:forensics-ro
├── Permissions: 750 (rwxr-x---)
├── sherlock: read access via forensics-ro group
└── Deletion/modification: BLOCKED

Attempts to modify trigger:
→ audit log entry (violation attempt)
→ operation fails
→ forensics-audit show displays attempt
```

### Audit Log Protection

```
/var/log/forensics/audit.log
├── Attribute: chattr +a (append-only)
├── Even root cannot modify past entries
├── Each entry:
│   ├── Linked to previous (blockchain-like)
│   ├── Signed with Ed25519
│   ├── Signed with GPG
│   └── SHA-256 hash
└── Verification: forensics-audit verify
```

## Cryptographic Systems

### Post-Quantum Cryptography (Root Protection)

**Library**: liboqs (Open Quantum Safe)
**Algorithms**:
- Key Encapsulation: Kyber (NIST standardized)
- Digital Signatures: Dilithium (NIST standardized)

**Purpose**: Protect root access from quantum computer attacks

### Hybrid Signature System (Audit Logs)

**Primary**: Ed25519 (modern, fast, secure)
- Key size: 32 bytes
- Signature size: 64 bytes
- Speed: ~70,000 signatures/sec

**Secondary**: GPG/RSA 4096 (compatibility, legal standards)
- Key size: 4096 bits
- Widely accepted in legal contexts
- Interoperable with existing tools

**Why Hybrid?**
- Ed25519: Modern cryptography, performance
- GPG: Legal acceptability, compatibility
- Both: Defense in depth

### Chain of Custody (Blockchain-like)

```json
Entry N-1:
{
  "seq": 100,
  "hash": "abc123...",
  "..."
}

Entry N:
{
  "seq": 101,
  "prev_hash": "abc123...",  ← Links to Entry N-1
  "hash": "def456...",
  "signatures": {
    "ed25519": "...",
    "gpg": "..."
  }
}
```

**Properties**:
- Tamper-evident: changing any entry breaks the chain
- Verifiable: forensics-audit verify checks entire chain
- Immutable: chattr +a prevents modification

## Module System

### Architecture

```
Module Registry (JSON)
├── Central registry of all modules
├── Metadata: version, submodules, size
└── Stable version tracking

Module Manager (Python)
├── forensics-modules CLI
├── Parallel installation
├── Conflict detection
├── Audit logging
└── Sub-module selection

Module Structure:
cloud-forensics/
├── manifest.json (metadata)
├── submodules/
│   ├── aws-tools.json
│   ├── azure-tools.json
│   └── gcp-tools.json
└── install scripts
```

### Installation Flow

```
User runs: forensics-modules install cloud-forensics --only aws-tools

1. Load registry.json
2. Validate module exists
3. Parse submodules
4. Check dependencies
5. Detect conflicts (if any)
6. Confirm with user
7. Download & install (parallel)
8. Verify installation
9. Log to audit trail
10. Mark as installed
```

### Conflict Resolution

```
Module A requires: yara v4.0.0 (installed)
Module B requires: yara v4.2.0 (newer)

System detects conflict:
⚠️  CONFLICT DETECTED

Module 'malware-analysis' requires:
  yara v4.2.0

Currently installed (by 'disk-forensics'):
  yara v4.0.0

Upgrade affects:
  ✓ disk-forensics (compatible)
  ✗ custom-script (may break)

User decides: [y/N]
```

## Performance Optimization

### Parallel Processing

```python
# Module installation
with ThreadPoolExecutor(max_workers=4) as executor:
    futures = [executor.submit(install_submodule, sm) 
               for sm in submodules]
    
# Analysis
GNU Parallel for batch processing
async/await for I/O operations
Multi-threading for CPU-bound tasks
```

### Resource Management

```yaml
docker-compose.yml:
  resources:
    limits:
      cpus: '8'      # Use all cores
      memory: 16G    # Generous for analysis
    reservations:
      cpus: '4'      # Minimum guaranteed
      memory: 8G
```

### Optimizations

- Compiled binaries (not scripts) where possible
- Memory-mapped files for large datasets
- Efficient data structures
- Minimal dependencies in base image

## Debugging System (Flight Recorder)

### Telemetry Collection

```python
Automatic capture:
- CPU usage
- Memory usage
- Disk I/O
- Network I/O
- Process count
- System calls (strace-like)

Stored in: /var/log/forensics/telemetry/
```

### Time-Travel Debugging

```
Concept: Record system state before each action

forensics-debug replay --last-error
→ Replays last 100 actions
→ Shows state at each step
→ Identifies failure point
```

### Performance Analysis

```bash
forensics-health why-slow "log2timeline.py"

Output:
Profiling log2timeline.py execution...
Bottleneck detected:
  - 85% time in I/O (reading disk.img)
  - Recommendation: Use SSD or increase buffer size
  - Suggested: log2timeline.py --buffer-size 1024M
```

## NIST SP 800-86 Compliance

### Section Mapping

| NIST Section | Implementation |
|--------------|----------------|
| 3.1.3 Evidence Collection | Automated chain of custody |
| 3.1.4 Evidence Examination | Modular tools |
| 3.1.5 Evidence Analysis | Documented workflow |
| 4 Tool Validation | Module verification |
| Appendix D Chain of Custody | Immutable audit trail |

### Validation

```bash
forensics-compliance validate

Checks:
✓ Evidence handling: COMPLIANT
✓ Chain of custody: COMPLIANT
✓ Cryptographic integrity: COMPLIANT
✓ Audit trail: COMPLIANT
✓ Report format: COMPLIANT
✓ Digital signatures: COMPLIANT
```

## Data Flow

### Evidence Acquisition

```
External Storage → Host System
                 ↓
         forensics-professional/evidence/
                 ↓
         Container: /evidence (read-only)
                 ↓
         sherlock can READ
                 ↓
         Analysis in /cases/
                 ↓
         Results in /reports/
```

### Audit Trail

```
Action occurs (e.g., module install)
         ↓
audit-logger.py called
         ↓
1. Get last hash
2. Create event data
3. Compute current hash
4. Sign with Ed25519
5. Sign with GPG
6. Append to log
         ↓
Log entry written (append-only)
         ↓
Available via forensics-audit show
```

## Container Lifecycle

### Build Time

```
1. Stage 1: Build post-quantum crypto
   - liboqs
   - oqs-provider

2. Stage 2: Build forensic tools
   - Volatility3
   - Others

3. Stage 3: Runtime environment
   - Copy from previous stages
   - Install system packages
   - Create users
   - Set permissions
   - Configure security
```

### Runtime

```
docker-compose up
        ↓
docker-entrypoint.sh runs
        ↓
1. Initialize as root:
   - Set chattr +a on logs
   - Secure evidence directory
   - Initialize keys (if needed)
   - Initialize audit system
   - Log container_started

2. Switch to sherlock user

3. Load environment

4. Display banner

5. Drop to shell
```

### Shutdown

```
User exits → Container stops
              ↓
Volumes persist:
- /evidence
- /cases
- /keys
- /logs
- /reports
- /modules

Next start → Data intact
```

## File System Layout

```
Container Filesystem:
/
├── evidence/          (read-only volume)
├── cases/             (read-write volume)
├── keys/              (protected volume)
├── var/log/forensics/ (append-only volume)
├── reports/           (read-write volume)
├── opt/forensics/     (core system)
│   ├── core/
│   │   ├── audit-system/
│   │   ├── module-manager/
│   │   ├── compliance/
│   │   └── integrations/
│   ├── modules/       (module metadata)
│   └── bin/           (utility scripts)
├── etc/forensics/     (configuration)
└── home/sherlock/     (user home)
```

## Network Architecture

```
Default: Bridge network (172.26.0.0/16)
         ↓
Internet access: YES (for module downloads)
         ↓
Can be changed to:
- Host network (full host network access)
- None (air-gapped)
- Custom (user-defined)
```

## Extension Points

### Adding New Modules

1. Create manifest in `modules/manifests/new-module/`
2. Define submodules
3. Add to registry.json
4. Implement install scripts
5. Test installation
6. Document

### Adding Integrations

```python
/opt/forensics/integrations/
├── siem_connector.py
├── case_mgmt_api.py
└── cloud_uploader.py

Each implements standard interface:
- connect()
- send_data()
- disconnect()
```

### Custom Compliance Checks

```python
/opt/forensics/core/compliance/
├── nist_validator.py (implemented)
├── iso27037_validator.py (future)
└── custom_validator.py (user-defined)
```

## Technology Stack

**Base**:
- Ubuntu 22.04 LTS
- Docker multi-stage build
- Python 3.10+
- Bash scripting

**Cryptography**:
- liboqs (post-quantum)
- PyNaCl (Ed25519)
- python-gnupg (GPG)
- OpenSSL 3.0

**Forensics** (modules):
- Volatility, Rekall (memory)
- Sleuthkit, Autopsy (disk)
- Wireshark, Zeek (network)
- YARA, radare2 (malware)
- And many more...

**Utilities**:
- psutil (system monitoring)
- tabulate (formatting)
- rich (CLI output)
- click (CLI framework)

## Future Enhancements

1. **Web Interface**: Case management dashboard
2. **AI/ML**: Automated artifact detection
3. **Distributed**: Multi-node analysis
4. **Cloud Native**: Kubernetes deployment
5. **Real-time**: Live system analysis
6. **Collaboration**: Multi-user workflows

---

**Architecture Version**: 2.0.0
**Last Updated**: 2026-02-07
**Maintained By**: Forensics Community
