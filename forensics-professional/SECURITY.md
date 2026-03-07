# Security Policy

## 🔐 Reporting Security Vulnerabilities

**We take security seriously.** If you discover a security vulnerability, please follow responsible disclosure practices.

### ⚠️ DO NOT:

- ❌ Open a public GitHub issue for security vulnerabilities
- ❌ Discuss the vulnerability publicly before it's fixed
- ❌ Exploit the vulnerability maliciously

### ✅ DO:

1. **Email us privately**: security@your-org.com
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
   - Your contact information (for follow-up)
3. **Wait** for our response (within 48 hours)
4. **Coordinate** disclosure timeline with us

### Our Response Process

1. **Acknowledgment** (within 48 hours)
2. **Investigation** (1-7 days)
3. **Fix Development** (varies by severity)
4. **Security Advisory** (coordinated with reporter)
5. **Public Disclosure** (after fix is released)

## 🏆 Security Researcher Recognition

We appreciate security researchers who help us improve! We will:
- Credit you in release notes (if you wish)
- Mention you in security advisory
- List you in our Hall of Fame (with permission)

## 🛡️ Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | ✅ Yes            |
| < 2.0   | ❌ No             |

We only provide security updates for the latest major version.

## 🔍 Security Features

### Container Security

**Post-Quantum Cryptography:**
- Root access protected with Kyber/Dilithium (NIST PQC standards)
- Future-proof against quantum computing attacks

**Immutable Audit Logs:**
- Hybrid signatures (Ed25519 + GPG)
- Blockchain-like chain of custody
- Tamper-evident design
- `chattr +a` attribute (append-only)

**Evidence Protection:**
- Read-only mounts prevent deletion/modification
- Automatic violation logging
- Permission enforcement at filesystem level

**User Isolation:**
- Non-root execution (sherlock user)
- Capability dropping
- Minimal attack surface

### Known Security Considerations

**Privileged Mode:**
- Container requires `privileged: true` for `chattr +a` on logs
- This is necessary for immutable audit trail
- Alternative: Run without privilege but lose log immutability

**Internet Access:**
- Modules download from internet during installation
- Verify package sources and checksums
- Option to use offline bundle (future feature)

**Volume Mounts:**
- Host directories mounted into container
- Use proper host filesystem permissions
- Encrypt sensitive volumes if needed

## 🔒 Security Best Practices

### For Users

**Host Security:**
```bash
# Ensure host is secure
sudo apt update && sudo apt upgrade
ufw enable  # or your firewall
```

**Volume Encryption:**
```bash
# Encrypt sensitive volumes (optional but recommended)
# Example with LUKS:
cryptsetup luksFormat /dev/sdX
cryptsetup open /dev/sdX forensics_encrypted
mkfs.ext4 /dev/mapper/forensics_encrypted
mount /dev/mapper/forensics_encrypted /path/to/evidence
```

**Key Protection:**
```bash
# Protect cryptographic keys
chmod 700 /path/to/keys
# Consider hardware security module (HSM) for production
```

**Network Isolation:**
```bash
# For air-gapped investigations:
# Set network_mode: none in docker-compose.yml
```

### For Contributors

**Code Review:**
- All PRs require review
- Security-sensitive changes need extra scrutiny
- Use static analysis tools

**Dependencies:**
- Pin versions in Dockerfile
- Regularly update to patched versions
- Scan for known vulnerabilities

**Secrets:**
- Never commit credentials
- Use .gitignore for sensitive files
- Check before pushing

## 🚨 Security Vulnerabilities (CVE)

We will create CVEs for:
- Remote code execution
- Privilege escalation
- Authentication bypass
- Data exfiltration
- Cryptographic failures

## 🔐 Cryptographic Standards

**Algorithms Used:**
- **Post-Quantum**: Kyber-1024 (KEM), Dilithium3 (signatures)
- **Traditional**: Ed25519, RSA-4096, SHA-256
- **Why Hybrid?** Defense in depth + legal acceptance

**Key Management:**
- Keys stored in protected volume
- Filesystem permissions enforce access control
- Future: HSM integration for enterprise

## 📋 Security Checklist

Before deploying in production:

- [ ] Review and understand security implications
- [ ] Encrypt host filesystem (especially keys/)
- [ ] Set strong host firewall rules
- [ ] Use dedicated forensics workstation
- [ ] Regular security updates
- [ ] Monitor audit logs
- [ ] Implement backup strategy
- [ ] Test disaster recovery
- [ ] Document incident response plan
- [ ] Train users on security practices

## 🛠️ Security Tools

We recommend:

**Vulnerability Scanning:**
```bash
# Scan container image
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image forensics-professional:2.0.0
```

**Audit Log Verification:**
```bash
# Regular integrity checks
docker exec forensics-workstation forensics-audit verify
```

**Health Monitoring:**
```bash
# Continuous monitoring
docker exec forensics-workstation forensics-health check
```

## 📚 Security Resources

- [NIST SP 800-86](https://csrc.nist.gov/publications/detail/sp/800-86/final) - Digital Forensics Guide
- [OWASP Docker Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

## 📞 Contact

- **Security Issues**: security@your-org.com
- **PGP Key**: [Link to PGP public key]
- **Response Time**: Within 48 hours

## 🙏 Acknowledgments

We thank the following security researchers (with permission):
- [Name] - [Vulnerability found] - [Date]
- Your name here? Help us improve security!

---

**Last Updated**: 2026-02-07  
**Security Contact**: security@your-org.com
