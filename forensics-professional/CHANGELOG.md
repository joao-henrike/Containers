# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-02-07

### Added
- **OSINT Tools Module** (`osint-tools`) with 25+ tools
  - Social media investigation (Sherlock, Twint, InstagramOSINT)
  - Domain reconnaissance (Amass, theHarvester, Sublist3r)
  - People search (Holehe, Maigret, Phoneinfoga)
  - Geolocation tools (GeoSpy, ExifTool, Creepy)
  - Dark web investigation (OnionSearch, TorBot, DarkDump)
  
- **Threat Intelligence Module** (`threat-intelligence`) with 15+ tools
  - IOC feed aggregation (MISP, AlienVault OTX, ThreatFox)
  - Threat hunting (YARA, Sigma, Hayabusa, Chainsaw)
  - MISP integration (PyMISP, MISP CLI)
  - OpenCTI tools (pycti, connectors)
  
- **Web Reconnaissance Module** (`web-recon`) with 18+ tools
  - Subdomain enumeration (Assetfinder, Subfinder, Findomain)
  - Web scraping (HTTrack, Scrapy, Selenium)
  - Wayback Machine analysis (waybackpy, waybackurls)
  - DNS reconnaissance (dnsenum, Fierce, dnstwist, dnsx)

- Comprehensive OSINT documentation (`docs/OSINT_INTELLIGENCE_TOOLS.md`)
- Legal and ethical usage guidelines for OSINT tools
- Module count increased from 11 to 14
- Tool count increased from ~136 to 161+

### Changed
- Updated README.md with OSINT modules table
- Enhanced module registry with new categories
- Improved documentation structure

### Security
- Added ethical usage warnings for OSINT tools
- Documented privacy considerations (GDPR, CCPA compliance)
- Included responsible disclosure practices

## [2.0.0] - 2026-02-07

### Added
- **Post-Quantum Cryptography** (Kyber/Dilithium via liboqs)
- **Immutable Audit Logs** with hybrid signatures (Ed25519 + GPG)
- **Blockchain-like Chain of Custody** with hash linking
- **Modular Architecture** - 11 forensic tool modules
- **NIST SP 800-86 Compliance** framework
- **Professional User Model** (sherlock user with restricted privileges)
- **Evidence Protection** (read-only mounts, deletion prevention)
- **GitHub Actions CI/CD** pipeline
- **Comprehensive Documentation** (9 markdown files)

### Modules (Initial Release)
1. cloud-forensics - AWS, Azure, GCP tools
2. memory-forensics - Volatility, Rekall
3. disk-forensics - Sleuthkit, Autopsy
4. network-forensics - Wireshark, Zeek
5. mobile-forensics - Android/iOS tools
6. malware-analysis - YARA, radare2, Ghidra
7. windows-forensics - Registry, EVTX analysis
8. linux-forensics - Auditd, log parsing
9. container-forensics - Docker/Kubernetes
10. database-forensics - MySQL, PostgreSQL, MongoDB
11. email-forensics - PST/EML parsing

### Security
- Multi-stage Docker build with security hardening
- Append-only audit logs (`chattr +a`)
- No root password (PQC encrypted access only)
- Principle of least privilege enforcement
- Evidence integrity verification

### Documentation
- README.md - Project overview
- QUICKSTART.md - 5-minute setup guide
- INSTALL.md - Detailed installation instructions
- ARCHITECTURE.md - Technical architecture
- CONTRIBUTING.md - Contribution guidelines
- CODE_OF_CONDUCT.md - Community standards
- SECURITY.md - Security policy
- LICENSE - MIT with forensic disclaimers

### Infrastructure
- Docker multi-stage build optimization
- GitHub Actions workflow for testing
- Issue templates (bug report, feature request)
- Comprehensive .gitignore for data protection

---

## Version History

- **2.1.0** (2026-02-07) - OSINT & Threat Intelligence modules added
- **2.0.0** (2026-02-07) - Initial public release

---

[2.1.0]: https://github.com/YOUR-USERNAME/forensics-professional/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/YOUR-USERNAME/forensics-professional/releases/tag/v2.0.0
