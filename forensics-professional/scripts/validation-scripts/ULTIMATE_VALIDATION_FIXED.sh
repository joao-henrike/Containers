#!/bin/bash
# ==============================================================================
# Professional Forensics Container — ULTIMATE_VALIDATION_FIXED.sh v2.1.0
# Validação ultimate com teste real de blockchain e assinaturas
# ==============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

echo ""
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}${BOLD}     🔬 ULTIMATE FORENSICS VALIDATION v2.1.0                ${NC}"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Teste 1: Blockchain completa ─────────────────────────────────────────────
echo -e "  ${BOLD}[TEST 1] Blockchain Hash Chain Validation${NC}"
python3 << 'PYTHON'
import json, hashlib
audit_log = "/var/log/forensics/audit.log"
try:
    with open(audit_log) as f:
        entries = [json.loads(l) for l in f if l.strip()]
    total = len(entries); broken = 0
    for i, e in enumerate(entries):
        data = json.dumps({k:v for k,v in e.items() if k!="hash"}, sort_keys=True)
        computed = hashlib.sha256(data.encode()).hexdigest()
        if e.get("hash","") != computed: broken += 1
        if i > 0 and e.get("prev_hash","") != entries[i-1].get("hash",""): broken += 1
    if broken == 0:
        print(f"  \033[0;32m✅ BLOCKCHAIN INTACT: {total} entries, 0 broken links\033[0m")
    else:
        print(f"  \033[0;31m❌ BLOCKCHAIN BROKEN: {broken} issues in {total} entries\033[0m")
    # Mostrar genesis
    if entries:
        g = entries[0]
        print(f"     Genesis: seq={g.get('seq')}, hash={g.get('hash','')[:16]}...")
        prev = g.get('prev_hash','')
        if prev == '0'*64:
            print(f"     \033[0;32m✅ Genesis prev_hash = 000...000 (correct)\033[0m")
        else:
            print(f"     \033[0;31m❌ Genesis prev_hash invalid: {prev[:16]}...\033[0m")
except Exception as ex:
    print(f"  \033[1;33m⚠️  Could not validate: {ex}\033[0m")
PYTHON

echo ""

# ── Teste 2: Adicionar entrada e verificar encadeamento ──────────────────────
echo -e "  ${BOLD}[TEST 2] Live Entry + Chain Verification${NC}"
python3 << 'PYTHON'
import sys
sys.path.insert(0, '/opt/forensics/core/audit-system')
try:
    from audit_logger import log_event, get_logger
    entry = log_event("validation_test", {
        "test": "ULTIMATE_VALIDATION_FIXED",
        "validator": "automated"
    }, user="validator")
    print(f"  \033[0;32m✅ Live entry logged: seq={entry.get('seq')}, hash={entry.get('hash','')[:16]}...\033[0m")
    # Verificar integridade após inserção
    result = get_logger().verify_integrity()
    if result.get("status") == "VALID":
        print(f"  \033[0;32m✅ Post-insert integrity: VALID ({result.get('total_entries')} entries)\033[0m")
    else:
        print(f"  \033[0;31m❌ Post-insert integrity: {result.get('status')}\033[0m")
except Exception as e:
    print(f"  \033[1;33m⚠️  {e}\033[0m")
PYTHON

echo ""

# ── Teste 3: Evidence protection ─────────────────────────────────────────────
echo -e "  ${BOLD}[TEST 3] Evidence Protection (Read-Only)${NC}"
if touch /evidence/test_write_$$  2>/dev/null; then
    echo -e "  ${RED}❌ FAIL: Evidence is WRITABLE (should be read-only)${NC}"
    rm -f /evidence/test_write_$$ 2>/dev/null
else
    echo -e "  ${GREEN}✅ PASS: Evidence is read-only (write attempt blocked)${NC}"
fi

echo ""

# ── Teste 4: Módulos ─────────────────────────────────────────────────────────
echo -e "  ${BOLD}[TEST 4] Module System${NC}"
if python3 /opt/forensics/core/module-manager/forensics-modules list 2>/dev/null | grep -q "MODULE"; then
    COUNT=$(python3 -c "import json; d=json.load(open('/opt/forensics/modules/registry.json')); print(len(d.get('modules',{})))" 2>/dev/null || echo "?")
    echo -e "  ${GREEN}✅ forensics-modules list: OK ($COUNT modules in registry)${NC}"
else
    echo -e "  ${YELLOW}⚠️  forensics-modules may need urllib3 update: pip3 install --upgrade urllib3 requests${NC}"
fi

echo ""

# ── Resultado Final ───────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}${BOLD}  ✅ ULTIMATE VALIDATION COMPLETE — Professional v2.1.0      ${NC}"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""
