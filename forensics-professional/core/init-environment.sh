#!/bin/bash
# ==============================================================================
# FORENSICS ENVIRONMENT INITIALIZATION
# Loaded on user shell startup
# ==============================================================================

# Set forensics environment variables
export FORENSICS_VERSION="2.0.0"
export FORENSICS_HOME="/opt/forensics"

# Color definitions for forensics commands
export FORENSICS_COLOR_SUCCESS='\033[0;32m'
export FORENSICS_COLOR_ERROR='\033[0;31m'
export FORENSICS_COLOR_WARNING='\033[1;33m'
export FORENSICS_COLOR_INFO='\033[0;34m'
export FORENSICS_COLOR_RESET='\033[0m'

# Helper functions
forensics_log() {
    echo -e "${FORENSICS_COLOR_INFO}[FORENSICS]${FORENSICS_COLOR_RESET} $1"
}

# Check if first-time setup is needed
if [ ! -f "$HOME/.forensics_initialized" ]; then
    forensics_log "Welcome to Professional Forensics Container v${FORENSICS_VERSION}"
    forensics_log "Run 'forensics-modules list' to see available tools"
    touch "$HOME/.forensics_initialized"
fi

# Quick health check (silent)
if command -v forensics-health &>/dev/null; then
    forensics-health quick-check --silent 2>/dev/null || true
fi
