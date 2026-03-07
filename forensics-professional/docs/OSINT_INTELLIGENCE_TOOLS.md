# OSINT & Intelligence Tools - Module Documentation

## 📋 Overview

This document details the OSINT (Open Source Intelligence) and Threat Intelligence modules available in the Professional Forensics Container.

---

## 🔍 Module 1: osint-tools

### Description
Open Source Intelligence gathering and analysis tools for investigating individuals, organizations, domains, and online presence.

### Sub-modules

#### 1. **social-media** (Social Media Investigation)

**Tools included:**
- **Sherlock** - Hunt down social media accounts by username
  - GitHub: https://github.com/sherlock-project/sherlock
  - Usage: `sherlock username`
  - Searches 300+ social networks

- **Social-Analyzer** - API and web app for analyzing social media
  - GitHub: https://github.com/qeeqbox/social-analyzer
  - Features: Profile detection, username availability

- **Twint** - Twitter scraping (no API needed)
  - GitHub: https://github.com/twintproject/twint
  - Usage: `twint -u username`
  - Scrapes tweets, followers, etc.

- **InstagramOSINT** - Instagram investigation
  - GitHub: https://github.com/sc1341/InstagramOSINT
  - Extracts posts, followers, metadata

- **Telepathy** - Telegram OSINT
  - Collects Telegram data
  - Channel/group analysis

**Installation size:** ~80 MB

---

#### 2. **domain-recon** (Domain Reconnaissance)

**Tools included:**
- **Amass** - In-depth attack surface mapping
  - GitHub: https://github.com/OWASP/Amass
  - Usage: `amass enum -d domain.com`
  - DNS enumeration, subdomain discovery

- **Sublist3r** - Fast subdomain enumeration
  - GitHub: https://github.com/aboul3la/Sublist3r
  - Usage: `sublist3r -d domain.com`

- **theHarvester** - Email, subdomain, people discovery
  - GitHub: https://github.com/laramies/theHarvester
  - Usage: `theHarvester -d domain.com -b all`
  - Multiple search engines

- **DNSRecon** - DNS enumeration
  - GitHub: https://github.com/darkoperator/dnsrecon
  - Zone transfers, cache snooping

- **MassDNS** - High-performance DNS resolver
  - GitHub: https://github.com/blechschmidt/massdns
  - Resolves millions of domains

**Installation size:** ~120 MB

---

#### 3. **people-search** (People Investigation)

**Tools included:**
- **Holehe** - Check email accounts on sites
  - GitHub: https://github.com/megadose/holehe
  - Usage: `holehe email@example.com`
  - Checks 120+ websites

- **WhatsMyName** - Username enumeration
  - GitHub: https://github.com/WebBreacher/WhatsMyName
  - 500+ sites database

- **Socialscan** - Email/username checker
  - GitHub: https://github.com/iojw/socialscan
  - Fast, accurate checking

- **Phoneinfoga** - Phone number OSINT
  - GitHub: https://github.com/sundowndev/phoneinfoga
  - Scanners for phone numbers

- **Maigret** - Collect dossier on person
  - GitHub: https://github.com/soxoj/maigret
  - 2500+ sites support

**Installation size:** ~100 MB

---

#### 4. **geolocation** (Geolocation & Mapping)

**Tools included:**
- **GeoSpy** - Geolocation from images
  - GitHub: https://github.com/GeoSpy/GeoSpy
  - AI-powered location detection

- **ExifTool** - Metadata extraction
  - Extracts GPS coordinates from images
  - Already included in base system

- **Creepy** - Geolocation information gatherer
  - Twitter, Instagram geolocation
  - Map visualization

- **Maltego** - Link analysis (community edition)
  - Visual investigation platform
  - Entity relationships

**Installation size:** ~80 MB

---

#### 5. **darkweb-tools** (Dark Web Investigation)

**Tools included:**
- **OnionSearch** - Onion search engine scraper
  - GitHub: https://github.com/megadose/OnionSearch
  - Scrapes .onion sites

- **TorBot** - Dark web crawler
  - GitHub: https://github.com/DedSecInside/TorBot
  - Crawls .onion domains

- **Hunchly** - Web capture for investigations
  - Captures pages with timestamps
  - Evidence preservation

- **DarkDump** - Dark web scraper
  - GitHub: https://github.com/josh0xA/darkdump
  - Multiple dark web search engines

**Installation size:** ~70 MB

---

## 🎯 Module 2: threat-intelligence

### Description
Threat intelligence collection, analysis, and correlation tools for identifying and tracking threats.

### Sub-modules

#### 1. **ioc-feeds** (IOC Feed Aggregation)

**Tools included:**
- **MISP Feed Manager** - MISP feed consumer
  - Connects to MISP instances
  - IOC ingestion and correlation

- **AlienVault OTX Client** - OTX API client
  - GitHub: https://github.com/AlienVault-OTX/OTX-Python-SDK
  - Threat pulse data

- **ThreatFox** - IOC repository client
  - Abuse.ch ThreatFox integration
  - Malware IOCs

- **URLhaus** - Malicious URL tracker
  - Abuse.ch URLhaus integration
  - URL/payload IOCs

**Installation size:** ~80 MB

---

#### 2. **threat-hunting** (Threat Hunting Tools)

**Tools included:**
- **YARA** - Pattern matching
  - Already in malware-analysis
  - Rule-based detection

- **Sigma** - Generic signature format
  - GitHub: https://github.com/SigmaHQ/sigma
  - Convert to SIEM queries

- **Hayabusa** - Windows event log analyzer
  - GitHub: https://github.com/Yamato-Security/hayabusa
  - Threat hunting in EVTX

- **Chainsaw** - Forensic analysis of Windows events
  - GitHub: https://github.com/WithSecureLabs/chainsaw
  - Sigma rule matching

**Installation size:** ~100 MB

---

#### 3. **misp-integration** (MISP Platform)

**Tools included:**
- **PyMISP** - MISP Python library
  - GitHub: https://github.com/MISP/PyMISP
  - API interactions

- **MISP CLI** - Command-line tools
  - Event creation/management
  - Attribute search

- **MISP Modules** - Expansion modules
  - Enrichment services
  - Import/export

**Installation size:** ~60 MB

---

#### 4. **opencti-tools** (OpenCTI Integration)

**Tools included:**
- **pycti** - OpenCTI Python client
  - GitHub: https://github.com/OpenCTI-Platform/client-python
  - CTI operations

- **OpenCTI Connectors** - Data connectors
  - MITRE ATT&CK
  - Threat feeds integration

**Installation size:** ~80 MB

---

## 🌐 Module 3: web-recon

### Description
Web reconnaissance, OSINT, and digital footprint analysis tools.

### Sub-modules

#### 1. **subdomain-enum** (Subdomain Enumeration)

**Tools included:**
- **Assetfinder** - Find domains and subdomains
  - GitHub: https://github.com/tomnomnom/assetfinder
  - Fast, multiple sources

- **Subfinder** - Passive subdomain discovery
  - GitHub: https://github.com/projectdiscovery/subfinder
  - 40+ sources

- **Findomain** - Fastest subdomain enumerator
  - GitHub: https://github.com/Findomain/Findomain
  - Cross-platform

- **Knock** - Subdomain scanner
  - GitHub: https://github.com/guelfoweb/knock
  - Wordlist-based

**Installation size:** ~70 MB

---

#### 2. **web-scraping** (Web Data Extraction)

**Tools included:**
- **HTTrack** - Website copier
  - Offline browsing
  - Evidence preservation

- **Scrapy** - Web scraping framework
  - Python-based
  - Scalable crawling

- **BeautifulSoup** - HTML/XML parser
  - Already in base (Python lib)
  - Data extraction

- **Selenium** - Browser automation
  - JavaScript rendering
  - Dynamic content

**Installation size:** ~90 MB

---

#### 3. **wayback-analysis** (Archive Analysis)

**Tools included:**
- **waybackpy** - Wayback Machine API
  - GitHub: https://github.com/akamhy/waybackpy
  - Historical snapshots

- **Waybackurls** - Fetch URLs from archive
  - GitHub: https://github.com/tomnomnom/waybackurls
  - Historical URL discovery

- **Archive.today scraper** - Archive.today integration
  - Alternative web archive
  - Snapshot retrieval

**Installation size:** ~40 MB

---

#### 4. **dns-recon** (DNS Investigation)

**Tools included:**
- **dnsenum** - DNS enumeration
  - Zone transfers
  - Brute forcing

- **Fierce** - DNS reconnaissance
  - GitHub: https://github.com/mschwager/fierce
  - Non-recursive scanning

- **dnstwist** - Domain permutation scanner
  - GitHub: https://github.com/elceef/dnstwist
  - Typosquatting detection

- **dnsx** - Fast DNS toolkit
  - GitHub: https://github.com/projectdiscovery/dnsx
  - Multiple DNS queries

**Installation size:** ~80 MB

---

## 📊 Total Installation Sizes

```
osint-tools:          ~450 MB
threat-intelligence:  ~320 MB
web-recon:            ~280 MB
───────────────────────────
TOTAL:              ~1.050 GB (1.05 GB)
```

---

## 🚀 Usage Examples

### OSINT Investigation

```bash
# 1. Install OSINT module
forensics-modules install osint-tools

# 2. Social media investigation
sherlock target_username
holehe target@email.com

# 3. Domain reconnaissance
amass enum -d target.com
theHarvester -d target.com -b all

# 4. People search
maigret target_username
phoneinfoga scan -n +1234567890
```

### Threat Intelligence

```bash
# 1. Install threat intel module
forensics-modules install threat-intelligence

# 2. Fetch IOCs from feeds
# (requires MISP/OTX API keys)

# 3. Threat hunting
hayabusa-cli -d /evidence/logs -r sigma-rules/

# 4. Sigma rule conversion
sigmac -t splunk rule.yml
```

### Web Reconnaissance

```bash
# 1. Install web recon module
forensics-modules install web-recon

# 2. Subdomain enumeration
subfinder -d target.com -o subdomains.txt
assetfinder target.com

# 3. Wayback analysis
waybackurls target.com > historical_urls.txt

# 4. DNS reconnaissance
dnstwist target.com
dnsx -l domains.txt -resp
```

---

## ⚠️ Legal & Ethical Considerations

### IMPORTANT WARNINGS

**These tools are for:**
✅ Authorized investigations
✅ Security research (with permission)
✅ Red team exercises (authorized)
✅ OSINT from public sources only

**DO NOT use for:**
❌ Stalking or harassment
❌ Unauthorized access
❌ Privacy violations
❌ Illegal surveillance
❌ Social engineering attacks

### Best Practices

1. **Always obtain authorization** before investigating
2. **Respect privacy laws** (GDPR, CCPA, etc.)
3. **Use responsibly** - OSINT can be invasive
4. **Document your methodology** for legal compliance
5. **Follow ethical guidelines** (OSINT Framework)

---

## 📚 Resources

- **OSINT Framework**: https://osintframework.com/
- **MITRE ATT&CK**: https://attack.mitre.org/
- **MISP Project**: https://www.misp-project.org/
- **Awesome OSINT**: https://github.com/jivoi/awesome-osint
- **Threat Intelligence Reading**: https://www.recordedfuture.com/threat-intelligence

---

**Last Updated**: 2026-02-07
**Module Versions**: osint-tools v1.0.0, threat-intelligence v1.0.0, web-recon v1.0.0
