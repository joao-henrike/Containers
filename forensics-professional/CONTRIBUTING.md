# Contributing to Professional Forensics Container

Thank you for your interest in contributing! This project is community-driven and welcomes contributions from forensic professionals, developers, and security researchers.

## 🎯 Ways to Contribute

### 1. Report Bugs
- Use GitHub Issues
- Include detailed steps to reproduce
- Specify your environment (OS, Docker version)
- Include logs if applicable

### 2. Suggest Features
- Open a GitHub Issue with label `enhancement`
- Describe the use case
- Explain why it's valuable for forensic investigations

### 3. Add Forensic Modules
- Create module manifests (see `modules/registry.json`)
- Document installation steps
- Ensure tools are open-source or freely available
- Test thoroughly before submitting

### 4. Improve Documentation
- Fix typos, clarify instructions
- Add examples and use cases
- Translate to other languages
- Create tutorials and guides

### 5. Submit Code
- Follow the development guidelines below
- Write tests when applicable
- Update documentation
- Follow security best practices

## 🔧 Development Guidelines

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/YOUR-ORG/forensics-professional.git
cd forensics-professional

# Create development branch
git checkout -b feature/your-feature-name

# Build container
docker-compose build

# Test changes
docker-compose up -d
docker exec -it forensics-workstation bash
```

### Code Style

**Python:**
- Follow PEP 8
- Use type hints where applicable
- Add docstrings to functions
- Keep functions focused and small

**Bash:**
- Use shellcheck for validation
- Add comments for complex logic
- Handle errors appropriately
- Use `set -e` for safety

**Docker:**
- Minimize layers
- Use multi-stage builds
- Clean up in same RUN command
- Pin versions for reproducibility

### Adding a New Module

1. **Create module manifest:**
```json
// modules/manifests/new-module/manifest.json
{
  "name": "new-module",
  "version": "1.0.0",
  "description": "Description of module",
  "category": "category-name",
  "stable_version": "1.0.0",
  "submodules": ["sub1", "sub2"]
}
```

2. **Add to registry:**
```json
// modules/registry.json
"new-module": {
  "name": "new-module",
  "version": "1.0.0",
  ...
}
```

3. **Create installation scripts if needed**

4. **Test installation:**
```bash
forensics-modules install new-module
# Verify all tools work
```

5. **Document:**
- Add to README.md module list
- Create module-specific documentation if complex

### Testing

Before submitting:

```bash
# Verify container builds
docker-compose build

# Run health checks
docker exec forensics-workstation forensics-health check

# Verify audit system
docker exec forensics-workstation forensics-audit verify

# Test module installation
docker exec forensics-workstation forensics-modules list
```

## 📋 Pull Request Process

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes**
4. **Test thoroughly**
5. **Commit with clear messages**:
   ```
   feat: Add malware analysis module
   
   - Adds YARA rules support
   - Includes radare2 integration
   - Updates documentation
   ```
6. **Push to your fork** (`git push origin feature/amazing-feature`)
7. **Open a Pull Request**

### PR Requirements

- [ ] Description explains what and why
- [ ] Tests pass (if applicable)
- [ ] Documentation updated
- [ ] No merge conflicts
- [ ] Follows code style guidelines
- [ ] Security considerations addressed

## 🔐 Security

### Reporting Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email: security@your-org.com
2. Include detailed description
3. Steps to reproduce
4. Potential impact
5. Suggested fix (if any)

We will respond within 48 hours.

### Security Best Practices

When contributing:
- Never commit credentials or keys
- Validate all user inputs
- Use secure defaults
- Follow principle of least privilege
- Document security implications
- Use up-to-date dependencies

## 📜 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of:
- Experience level
- Gender identity and expression
- Sexual orientation
- Disability
- Personal appearance
- Race or ethnicity
- Age
- Religion
- Nationality

### Expected Behavior

- Be respectful and professional
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards others
- Use welcoming and inclusive language

### Unacceptable Behavior

- Harassment or discriminatory language
- Trolling or insulting comments
- Publishing others' private information
- Other conduct that would be inappropriate in a professional setting

### Enforcement

Violations may result in:
1. Warning
2. Temporary ban
3. Permanent ban

Report violations to: conduct@your-org.com

## 🎓 Learning Resources

New to forensics? Check out:
- [NIST SP 800-86](https://csrc.nist.gov/publications/detail/sp/800-86/final)
- [Digital Forensics Framework](https://www.dff-framework.org/)
- [SANS Digital Forensics](https://www.sans.org/cyber-security-courses/digital-forensics-essentials/)

New to Docker?
- [Docker Documentation](https://docs.docker.com/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)

## 📞 Contact

- **GitHub Issues**: For bugs and features
- **Discussions**: For questions and ideas
- **Email**: contribute@your-org.com

## 🏆 Contributors

Contributors will be recognized in:
- README.md (Contributors section)
- Release notes
- GitHub contributors graph

Thank you for making digital forensics more accessible! 🔍

---

**Happy Contributing!**
