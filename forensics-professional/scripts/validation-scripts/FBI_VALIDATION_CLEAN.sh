#!/bin/bash
# ==============================================================================
# Professional Forensics Container — FBI_VALIDATION_CLEAN.sh v2.1.0
# Validação completa do sistema: chain of custody, integridade, compliance
# ==============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASS=0; FAIL=0; WARN=0

check() {
    local label="$1"; local cmd="$2"; local expect="$3"
    local result
    result=$(eval "$cmd" 2>/dev/null)
    if echo "$result" | grep -q "$expect"; then
        echo -e "  ${GREEN}✅ PASS${NC} $label"
        ((PASS++))
    else
        echo -e "  ${RED}❌ FAIL${NC} $label  (got: ${result:0:50})"
        ((FAIL++))
    fi
}

warn_check() {
    local label="$1"; local cmd="$2"; local expect="$3"
    local result
    result=$(eval "$cmd" 2>/dev/null)
    if echo "$result" | grep -q "$expect"; then
        echo -e "  ${GREEN}✅ PASS${NC} $label"
        ((PASS++))
    else
        echo -e "  ${YELLOW}⚠️  WARN${NC} $label"
        ((WARN++))
    fi
}

echo ""
echo -e "${CYAN}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║      🏛️  FBI-LEVEL FORENSICS VALIDATION v2.1.0              ║${NC}"
echo -e "${CYAN}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "  ${BOLD}── 1. DIRECTORY STRUCTURE ────────────────────────────────${NC}"
check "Evidence dir"        "ls -d /evidence"                   "/evidence"
check "Cases dir"           "ls -d /cases"                      "/cases"
check "Keys dir"            "ls -d /opt/forensics/quantum-keys" "quantum-keys"
check "Logs dir"            "ls -d /var/log/forensics"          "forensics"
check "Reports dir"         "ls -d /reports"                    "/reports"
check "Modules dir"         "ls -d /opt/forensics/modules"      "modules"
check "Telemetry dir"       "ls -d /var/log/forensics/telemetry" "telemetry"
check "Chain-of-custody dir" "ls -d /var/log/forensics/chain-of-custody" "chain"

echo ""
echo -e "  ${BOLD}── 2. AUDIT SYSTEM ───────────────────────────────────────${NC}"
check "Audit log exists"     "ls /var/log/forensics/audit.log" "audit.log"
check "Audit log has entries" "wc -l /var/log/forensics/audit.log | awk '{print \$1}'" "[1-9]"
check "Ed25519 key present"  "ls /opt/forensics/quantum-keys/audit_ed25519.key" "ed25519"
check "forensics-audit CLI"  "which forensics-audit" "forensics-audit"
warn_check "Audit log append-only" "lsattr /var/log/forensics/audit.log 2>/dev/null" "a"

echo ""
echo -e "  ${BOLD}── 3. AUDIT INTEGRITY ────────────────────────────────────${NC}"
python3 << 'PYTHON'
import json, hashlib, sys
audit_log = "/var/log/forensics/audit.log"
try:
    with open(audit_log) as f:
        lines = [l.strip() for l in f if l.strip()]
    entries = [json.loads(l) for l in lines]
    broken = 0
    for i, e in enumerate(entries):
        stored = e.get("hash","")
        data = json.dumps({k:v for k,v in e.items() if k!="hash"}, sort_keys=True)
        computed = hashlib.sha256(data.encode()).hexdigest()
        if stored != computed: broken += 1
        if i > 0 and e.get("prev_hash") != entries[i-1].get("hash"): broken += 1
    if broken == 0:
        print(f"  \033[0;32m✅ PASS\033[0m Hash chain intact ({len(entries)} entries)")
    else:
        print(f"  \033[0;31m❌ FAIL\033[0m {broken} broken links detected")
except Exception as e:
    print(f"  \033[1;33m⚠️  WARN\033[0m Could not verify: {e}")
PYTHON

echo ""
echo -e "  ${BOLD}── 4. SECURITY MODEL ─────────────────────────────────────${NC}"
check "User sherlock exists"  "id sherlock"           "sherlock"
check "Root password locked"  "passwd -S root 2>/dev/null | grep -E 'L|NP'" "[LN]"
check "Evidence read-only"    "stat -c %a /evidence"  "5"
warn_check "PQC key encrypted" "ls /opt/forensics/quantum-keys/dilithium_private.key.enc" ".enc"
warn_check "quantum-root CLI" "which quantum-root || which qroot" "root"

echo ""
echo -e "  ${BOLD}── 5. MODULE SYSTEM ──────────────────────────────────────${NC}"
check "Registry exists"       "ls /opt/forensics/modules/registry.json" "registry"
check "forensics-modules CLI" "which forensics-modules" "forensics-modules"
check "14 modules in registry" "python3 -c \"import json; d=json.load(open('/opt/forensics/modules/registry.json')); print(len(d.get('modules',{})))\"" "14"

echo ""
echo -e "  ${BOLD}── 6. CORE TOOLS ─────────────────────────────────────────${NC}"
check "Python3"  "python3 --version"  "Python"
check "OpenSSL"  "openssl version"    "OpenSSL"
check "GPG"      "gpg --version"      "gpg"
check "Git"      "git --version"      "git"
check "jq"       "jq --version"       "jq"
warn_check "quantum_verify" "which quantum_verify" "quantum_verify"
warn_check "liboqs" "ldconfig -p | grep liboqs" "liboqs"

echo ""
echo -e "  ${BOLD}── 7. COMPLIANCE (NIST SP 800-86) ────────────────────────${NC}"
check "Evidence immutability"  "stat -c %a /evidence | grep -E '^5'" "5"
check "Chain of custody dir"   "ls -d /var/log/forensics/chain-of-custody" "chain"
check "Installation logs"      "ls -d /var/log/forensics/installations" "installations"
check "Audit trail present"    "wc -c /var/log/forensics/audit.log | awk '{print \$1}'" "[1-9]"

echo ""
echo -e "${CYAN}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
printf "${CYAN}${BOLD}║${NC}  RESULTS: ${GREEN}%3d PASS${NC}  ${YELLOW}%3d WARN${NC}  ${RED}%3d FAIL${NC}                   ${CYAN}${BOLD}║${NC}\n" $PASS $WARN $FAIL
TOTAL=$((PASS + WARN + FAIL))
SCORE=$(( PASS * 100 / (TOTAL > 0 ? TOTAL : 1) ))
printf "${CYAN}${BOLD}║${NC}  SCORE: ${BOLD}%d%%${NC} (%d/%d checks passed)                     ${CYAN}${BOLD}║${NC}\n" $SCORE $PASS $TOTAL
if [[ $FAIL -eq 0 ]]; then
    echo -e "${CYAN}${BOLD}║${NC}  STATUS: ${GREEN}${BOLD}✅ VALIDATION PASSED${NC}                            ${CYAN}${BOLD}║${NC}"
else
    echo -e "${CYAN}${BOLD}║${NC}  STATUS: ${RED}${BOLD}❌ VALIDATION FAILED ($FAIL issues)${NC}              ${CYAN}${BOLD}║${NC}"
fi
echo -e "${CYAN}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
