#!/usr/bin/env bash
# ==============================================================================
# validate.sh — end-to-end smoke test for the Forensics Professional container
# ==============================================================================
# Run inside the container after `docker compose up -d`:
#     docker exec forensics-workstation /opt/forensics/bin/validate.sh
#
# Exit codes:
#   0   all checks passed
#   1   one or more soft failures (warnings)
#   2   one or more hard failures
# ==============================================================================

set -uo pipefail

if [[ -t 1 ]]; then
    GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; RED=$'\033[0;31m'
    CYN=$'\033[0;36m'; BLD=$'\033[1m'; NC=$'\033[0m'
else
    GRN=''; YLW=''; RED=''; CYN=''; BLD=''; NC=''
fi

PASS=0; WARN=0; FAIL=0

ok()   { printf '  %s✓%s  %s\n' "${GRN}" "${NC}" "$*"; PASS=$((PASS+1)); }
soft() { printf '  %s!%s  %s\n' "${YLW}" "${NC}" "$*"; WARN=$((WARN+1)); }
bad()  { printf '  %s✗%s  %s\n' "${RED}" "${NC}" "$*"; FAIL=$((FAIL+1)); }

section() { printf '\n%s%s%s\n' "${CYN}${BLD}" "── $* ──" "${NC}"; }

# ── Container identity ──────────────────────────────────────────────────────
section "Container identity"
[[ -f /opt/forensics/VERSION ]] && \
    ok "VERSION file present ($(cat /opt/forensics/VERSION))" \
    || bad "VERSION file missing"

[[ "$(whoami)" == "sherlock" ]] && \
    ok "running as sherlock" || bad "expected sherlock, got $(whoami)"

# ── Tooling ────────────────────────────────────────────────────────────────
section "CLI tools"
for tool in forensics-modules forensics-audit forensics-health quantum-root; do
    if command -v "${tool}" >/dev/null 2>&1; then
        ok "${tool} found at $(command -v ${tool})"
    else
        bad "${tool} not in PATH"
    fi
done

# ── Privilege model ─────────────────────────────────────────────────────────
section "Privilege model"
if command -v gosu >/dev/null 2>&1; then
    ok "gosu installed"
else
    bad "gosu missing — entrypoint relies on it"
fi
if command -v sudo >/dev/null 2>&1; then
    ok "sudo installed"
else
    bad "sudo missing — module installers will fail"
fi
if [[ -r /etc/sudoers.d/sherlock-forensics ]]; then
    ok "sudoers fragment present"
else
    bad "/etc/sudoers.d/sherlock-forensics missing"
fi

# Sherlock must NOT be able to get a generic shell via sudo.
if sudo -ln bash 2>/dev/null | grep -q "^/bin/bash"; then
    bad "sudo grants bash — sudoers too permissive"
else
    ok "sudo does not grant bash"
fi

# ── Audit system ────────────────────────────────────────────────────────────
section "Audit system"
[[ -f /var/log/forensics/audit.log ]] && \
    ok "audit log exists" || bad "audit log missing"
forensics-audit verify >/dev/null 2>&1 && \
    ok "audit chain valid" || soft "audit-verify reports issues"

# ── Modules ────────────────────────────────────────────────────────────────
section "Module manager"
if forensics-modules list --json >/dev/null 2>&1; then
    ok "registry parseable"
else
    bad "registry parsing failed"
fi

# ── Python health ──────────────────────────────────────────────────────────
section "Health monitor"
forensics-health quick-check --silent && \
    ok "quick-check OK" || soft "quick-check reports issues"

# ── Summary ────────────────────────────────────────────────────────────────
printf '\n%sSummary:%s  %s%d passed%s   %s%d warnings%s   %s%d failures%s\n' \
    "${BLD}" "${NC}" \
    "${GRN}" "${PASS}" "${NC}" \
    "${YLW}" "${WARN}" "${NC}" \
    "${RED}" "${FAIL}" "${NC}"

if [[ "${FAIL}" -gt 0 ]]; then exit 2; fi
if [[ "${WARN}" -gt 0 ]]; then exit 1; fi
exit 0
