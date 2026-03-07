#!/bin/bash
# ==============================================================================
# FORENSICS CONTAINER ENTRY POINT
# Initializes security, audit system, and immutable logs
# ==============================================================================

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Professional Forensics Container - Initializing...       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"

# ==============================================================================
# Initialize system as root (before dropping privileges)
# ==============================================================================

if [ "$(id -u)" -eq 0 ]; then
    echo -e "${GREEN}[INIT]${NC} Running initial setup as root..."
    
    # Set append-only attribute on audit logs (immutable)
    if [ -f "/var/log/forensics/audit.log" ]; then
        chattr +a /var/log/forensics/audit.log 2>/dev/null || \
            echo -e "${YELLOW}[WARN]${NC} Could not set append-only on audit.log (requires privileged container)"
    fi
    
    if [ -f "/var/log/forensics/custody.log" ]; then
        chattr +a /var/log/forensics/custody.log 2>/dev/null || \
            echo -e "${YELLOW}[WARN]${NC} Could not set append-only on custody.log"
    fi
    
    # Ensure evidence directory is read-only for sherlock
    if [ -d "/evidence" ]; then
        chmod 750 /evidence
        chown root:forensics-ro /evidence
        echo -e "${GREEN}[INIT]${NC} Evidence directory secured (read-only)"
    fi
    
    # Initialize keys if not present
    if [ ! -d "/keys" ] || [ -z "$(ls -A /keys 2>/dev/null)" ]; then
        echo -e "${YELLOW}[INIT]${NC} Initializing cryptographic keys..."
        /opt/forensics/core/audit-system/init-keys.sh
    fi
    
    # Initialize audit system
    if [ ! -f "/var/log/forensics/.initialized" ]; then
        echo -e "${GREEN}[INIT]${NC} Initializing audit system..."
        python3 /opt/forensics/core/audit-system/init-audit.py
        touch /var/log/forensics/.initialized
    fi
    
    # Record container start in audit log
    python3 /opt/forensics/core/audit-system/audit-logger.py \
        --event "container_started" \
        --details "Forensics container initialized" \
        --user "system" 2>/dev/null || true
    
    echo -e "${GREEN}[INIT]${NC} System initialization complete"
    
    # If running as root and CMD is bash, switch to sherlock
    if [ "$1" = "/bin/bash" ] || [ "$1" = "bash" ]; then
        echo -e "${GREEN}[INIT]${NC} Switching to user sherlock..."
        exec su - sherlock
    fi
fi

# ==============================================================================
# Running as sherlock user
# ==============================================================================

echo -e "${GREEN}[INFO]${NC} Running as user: $(whoami)"

# Load forensics environment
if [ -f "/opt/forensics/core/init-environment.sh" ]; then
    source /opt/forensics/core/init-environment.sh
fi

# Run health check
if command -v forensics-health &> /dev/null; then
    forensics-health quick-check --silent 2>/dev/null || \
        echo -e "${YELLOW}[WARN]${NC} Health check completed with warnings"
fi

# Execute command
exec "$@"
