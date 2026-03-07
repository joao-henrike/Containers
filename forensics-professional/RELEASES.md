# Release Notes

## Version 2.1.0 - "OSINT Ready" (2026-02-07)

### 🎉 Major Features

**OSINT & Intelligence Capabilities**
- Added complete OSINT toolkit with 25+ tools for social media investigation, people search, and dark web analysis
- Integrated threat intelligence platform with MISP, AlienVault OTX, and IOC feeds
- Web reconnaissance suite with subdomain enumeration, web scraping, and DNS analysis

### ✨ What's New

#### New Modules (3)
1. **osint-tools** - Open Source Intelligence gathering
   - Social media investigation (Sherlock, Twint, InstagramOSINT, Telepathy)
   - Domain reconnaissance (Amass, theHarvester, Sublist3r, DNSRecon)
   - People search (Holehe, Maigret, Phoneinfoga, WhatsMyName)
   - Geolocation tools (GeoSpy, ExifTool, Creepy, Maltego)
   - Dark web investigation (OnionSearch, TorBot, DarkDump)

2. **threat-intelligence** - Threat intelligence and IOC analysis
   - IOC feed aggregation (MISP, AlienVault OTX, ThreatFox, URLhaus)
   - Threat hunting (YARA, Sigma, Hayabusa, Chainsaw)
   - MISP integration (PyMISP, MISP CLI, modules)
   - OpenCTI tools (pycti, connectors)

3. **web-recon** - Web reconnaissance and investigation
   - Subdomain enumeration (Assetfinder, Subfinder, Findomain, Knock)
   - Web scraping (HTTrack, Scrapy, BeautifulSoup, Selenium)
   - Wayback Machine analysis (waybackpy, waybackurls, Archive.today)
   - DNS reconnaissance (dnsenum, Fierce, dnstwist, dnsx)

#### Documentation
- Added comprehensive OSINT guide (`docs/OSINT_INTELLIGENCE_TOOLS.md`)
- Legal and ethical usage guidelines
- Tool-by-tool documentation with examples
- Privacy compliance information (GDPR, CCPA)

### 📊 Statistics

- **Total Modules:** 14 (was 11) - **+27% increase**
- **Total Sub-modules:** 53 (was 40) - **+32% increase**  
- **Total Tools:** 161+ (was ~136) - **+18% increase**
- **OSINT Tools:** 58 new tools added
- **Install Size:** ~3.3 GB all modules (was ~2.8 GB) - **+500 MB**

### 🔧 Technical Changes

- Updated module registry with new categories (osint, intelligence, recon)
- Enhanced README.md with OSINT module table
- Version bumped to 2.1.0 following semantic versioning
- Added CHANGELOG.md following Keep a Changelog format
- Updated container banner with new module count

### 🛡️ Security & Compliance

- Added ethical OSINT usage warnings
- Documented privacy law compliance (GDPR, LGPD, CCPA)
- Responsible disclosure practices for OSINT findings
- Legal authorization requirements documented

### 📦 Installation

```bash
# Clone and install
git clone https://github.com/YOUR-USERNAME/forensics-professional.git
cd forensics-professional
docker-compose build
docker-compose up -d

# Install OSINT module
docker exec -it forensics-workstation bash
forensics-modules install osint-tools
```

### 🚀 Usage Examples

```bash
# Social media investigation
sherlock target_username

# Email verification  
holehe suspect@email.com

# Domain reconnaissance
theHarvester -d target-company.com -b all
amass enum -d target-company.com

# Phone OSINT
phoneinfoga scan -n +1234567890

# Threat hunting
hayabusa-cli -d /evidence/logs -r sigma-rules/
```

### 📚 Resources

- [OSINT Tools Documentation](docs/OSINT_INTELLIGENCE_TOOLS.md)
- [OSINT Framework](https://osintframework.com/)
- [MISP Project](https://www.misp-project.org/)
- [Awesome OSINT](https://github.com/jivoi/awesome-osint)

### ⚠️ Breaking Changes

None - fully backward compatible with v2.0.0

### 🐛 Known Issues

None reported

### 🙏 Contributors

Thanks to the open-source community for the amazing OSINT tools integrated in this release!

---

## Version 2.0.0 - "Initial Release" (2026-02-07)

### 🎉 Initial Public Release

First public release of Professional Forensics Container with:
- Post-quantum cryptography (Kyber/Dilithium)
- Immutable audit trails (Ed25519 + GPG)
- 11 forensic tool modules
- NIST SP 800-86 compliance
- Comprehensive documentation
- GitHub CI/CD pipeline

See [CHANGELOG.md](CHANGELOG.md) for complete details.

---

## Upgrade Path

### From v2.0.0 to v2.1.0

```bash
# Stop container
docker-compose down

# Pull latest
git pull origin main

# Rebuild
docker-compose build

# Restart
docker-compose up -d

# Your data in evidence/, cases/, keys/, logs/ is preserved!
```

No manual migration needed - fully compatible upgrade.

---

## Future Releases

### Planned for v2.2.0
- AI/ML-powered artifact detection
- Web UI for case management
- Automated report generation
- More OSINT integrations

### Planned for v3.0.0
- Distributed analysis support
- Cloud-native deployment (Kubernetes)
- Real-time collaboration features
- Advanced visualization dashboard

---

**Questions?** Open an [issue](https://github.com/YOUR-USERNAME/forensics-professional/issues) or start a [discussion](https://github.com/YOUR-USERNAME/forensics-professional/discussions)!
