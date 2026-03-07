# Installation Guide

Complete installation instructions for Professional Forensics Container.

## 📋 Prerequisites

### System Requirements

**Minimum:**
- CPU: 4 cores
- RAM: 8 GB
- Disk: 50 GB free space
- OS: Any Linux distribution with kernel 3.10+

**Recommended:**
- CPU: 8+ cores
- RAM: 16 GB
- Disk: 100 GB free space (SSD preferred)
- OS: Ubuntu 22.04, Debian 12, or Kali Linux 2024+

### Software Requirements

- **Docker Engine** 20.10 or higher
- **Docker Compose** 1.29 or higher
- **Git** (for cloning repository)

---

## 🐧 Installation by Operating System

### Ubuntu / Debian

```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install Docker
sudo apt install -y docker.io docker-compose git

# 3. Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# 4. Add your user to docker group
sudo usermod -aG docker $USER

# 5. Logout and login again (or run: newgrp docker)

# 6. Verify Docker works
docker run hello-world
```

### Kali Linux

```bash
# Docker usually pre-installed, but if not:
sudo apt update
sudo apt install -y docker.io docker-compose git

# Start service
sudo systemctl start docker
sudo systemctl enable docker

# Add user to group
sudo usermod -aG docker $USER

# Logout/login, then verify
docker run hello-world
```

### Fedora / CentOS / Rocky Linux

```bash
# Fedora
sudo dnf install -y docker docker-compose git
sudo systemctl start docker
sudo systemctl enable docker

# CentOS/Rocky
sudo yum install -y docker docker-compose git
sudo systemctl start docker
sudo systemctl enable docker

# Add user to group
sudo usermod -aG docker $USER

# Logout/login, then verify
docker run hello-world
```

### Arch Linux

```bash
# Install Docker
sudo pacman -S docker docker-compose git

# Start service
sudo systemctl start docker
sudo systemctl enable docker

# Add user to group
sudo usermod -aG docker $USER

# Logout/login, then verify
docker run hello-world
```

### Windows (WSL2)

```bash
# 1. Install Docker Desktop for Windows from:
#    https://www.docker.com/products/docker-desktop/

# 2. Enable WSL2 integration in Docker Desktop settings

# 3. In WSL2 terminal (Ubuntu/Debian):
sudo apt update
sudo apt install -y git

# Docker is managed by Docker Desktop
# Verify:
docker run hello-world
```

### macOS

```bash
# 1. Install Docker Desktop for Mac from:
#    https://www.docker.com/products/docker-desktop/

# 2. Install Homebrew (if not installed):
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 3. Install git (if not installed):
brew install git

# Docker is managed by Docker Desktop
# Verify:
docker run hello-world
```

---

## 📦 Installing the Forensics Container

### Method 1: Quick Install (Recommended)

```bash
# One-liner installation
git clone https://github.com/YOUR-USERNAME/forensics-professional.git && \
cd forensics-professional && \
docker-compose build && \
docker-compose up -d && \
echo "✅ Installation complete! Access with: docker exec -it forensics-workstation bash"
```

### Method 2: Step-by-Step

```bash
# 1. Clone repository
git clone https://github.com/YOUR-USERNAME/forensics-professional.git
cd forensics-professional

# 2. Verify directory structure
ls -la
# Should see: Dockerfile, docker-compose.yml, core/, scripts/, etc.

# 3. Build the container (takes 10-15 minutes first time)
docker-compose build

# Expected output:
# Step 1/50 : FROM ubuntu:22.04
# Step 2/50 : LABEL maintainer...
# ...
# Successfully built abc123def456
# Successfully tagged forensics-professional:2.0.0

# 4. Start the container
docker-compose up -d

# Expected output:
# Creating network "forensics-professional_default" with driver "bridge"
# Creating forensics-workstation ... done

# 5. Verify it's running
docker ps

# Expected output:
# CONTAINER ID   IMAGE                              STATUS
# abc123def456   forensics-professional:2.0.0       Up 10 seconds

# 6. Access the shell
docker exec -it forensics-workstation bash

# You should see the forensics banner!
```

---

## 🔍 Verification

### After Installation

```bash
# Inside the container (after docker exec -it forensics-workstation bash)

# 1. Check health
forensics-health check

# Expected output:
# ✅ Evidence directory: OK
# ✅ Cases directory: OK
# ✅ Cryptographic keys: OK
# ✅ Audit log: IMMUTABLE
# ...

# 2. Verify audit system
forensics-audit verify

# Expected output:
# ✅ VALID: Verified 1 entries successfully

# 3. List available modules
forensics-modules list

# Expected output: Table with 11 modules

# 4. Check user
whoami
# Expected: sherlock

# 5. Try to access evidence (should fail - good!)
touch /evidence/test.txt
# Expected: Permission denied
```

---

## 🛠️ Troubleshooting

### Issue: "docker: command not found"

```bash
# Docker not installed or not in PATH
# Solution: Install Docker (see OS-specific instructions above)
```

### Issue: "permission denied while trying to connect to Docker daemon"

```bash
# User not in docker group
# Solution:
sudo usermod -aG docker $USER
# Then logout/login

# Or temporarily:
newgrp docker
```

### Issue: "Cannot connect to Docker daemon at unix:///var/run/docker.sock"

```bash
# Docker service not running
# Solution:
sudo systemctl start docker
sudo systemctl enable docker
```

### Issue: Build fails with "no space left on device"

```bash
# Not enough disk space
# Solution:
# 1. Check available space:
df -h

# 2. Clean Docker cache:
docker system prune -a

# 3. Free up at least 50 GB
```

### Issue: Build is very slow

```bash
# Normal on first build (10-15 minutes)
# On subsequent builds, Docker uses cache (~2-3 minutes)

# To speed up:
# - Use SSD
# - Allocate more CPU cores to Docker
# - Check internet connection (downloads packages)
```

### Issue: Container exits immediately

```bash
# Check logs:
docker-compose logs

# Common causes:
# - Syntax error in scripts
# - Missing dependencies
# - Permission issues

# Try rebuilding:
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

---

## 🔄 Updating

### Update to Latest Version

```bash
# 1. Stop container
docker-compose down

# 2. Pull latest changes
git pull origin main

# 3. Rebuild
docker-compose build

# 4. Restart
docker-compose up -d

# 5. Your data in evidence/, cases/, keys/, logs/ is preserved!
```

---

## 🗑️ Uninstallation

### Remove Container (Keep Data)

```bash
cd forensics-professional
docker-compose down

# Data in evidence/, cases/, keys/, logs/ is preserved
```

### Complete Removal (Including Data)

```bash
cd forensics-professional

# Stop and remove container
docker-compose down -v

# Remove images
docker rmi forensics-professional:2.0.0

# Remove repository
cd ..
rm -rf forensics-professional

# CAUTION: This deletes ALL your cases and evidence!
```

---

## 💾 Backup

### Backup Your Work

```bash
# From host machine:
cd forensics-professional

# Backup cases
tar -czf cases-backup-$(date +%Y%m%d).tar.gz cases/

# Backup keys (IMPORTANT!)
tar -czf keys-backup-$(date +%Y%m%d).tar.gz keys/

# Backup logs
tar -czf logs-backup-$(date +%Y%m%d).tar.gz logs/

# Store backups securely!
```

---

## 🎓 Next Steps

After successful installation:

1. **Read** [QUICKSTART.md](QUICKSTART.md) for basic usage
2. **Install** forensic modules you need
3. **Add** your evidence to `evidence/` directory
4. **Create** your first case in `cases/`
5. **Start** investigating!

---

## 📞 Support

**Installation Issues:**
- Check [Troubleshooting](#troubleshooting) section above
- Search [GitHub Issues](https://github.com/YOUR-USERNAME/forensics-professional/issues)
- Open a new issue if problem persists

**Questions:**
- Use [GitHub Discussions](https://github.com/YOUR-USERNAME/forensics-professional/discussions)

---

**Happy Investigating! 🔍**
