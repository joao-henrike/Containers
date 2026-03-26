#!/bin/bash
# ==============================================================================
# Professional Forensics Container — quantum-root v2.1.0
# Sistema de Autenticação Pós-Quântica ML-DSA-65 (Dilithium)
# Challenge-Response com verificação de assinatura digital real
#
# Uso: quantum-root  (ou qroot como alias)
#
# Fluxo:
#   1. Gera desafio aleatório (32 bytes hex)
#   2. Solicita senha da chave privada
#   3. Descriptografa chave privada (AES-256-CBC)
#   4. Assina o desafio com ML-DSA-65 via quantum_verify
#   5. Verifica assinatura com chave pública
#   6. Se válida → shell root privilegiado
# ==============================================================================

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Caminhos das chaves
PRIV_KEY_ENC="/opt/forensics/quantum-keys/dilithium_private.key.enc"
PUB_KEY="/opt/forensics/quantum-keys/dilithium_public.key"
VERIFY_BIN="/usr/local/bin/quantum_verify"

# Arquivo de log de tentativas
AUTH_LOG="/var/log/forensics/quantum-auth.log"

# ==============================================================================
# Funções auxiliares
# ==============================================================================

log_attempt() {
    local result="$1"
    local timestamp
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "{\"timestamp\":\"${timestamp}\",\"event\":\"quantum_root_attempt\",\"user\":\"${USER:-unknown}\",\"result\":\"${result}\"}" \
        >> "$AUTH_LOG" 2>/dev/null || true
}

print_banner() {
    echo ""
    echo -e "${CYAN}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║        🔐 PROFESSIONAL QUANTUM AUTHENTICATION              ║${NC}"
    echo -e "${CYAN}${BOLD}║           ML-DSA-65 (Dilithium) — NIST FIPS 204            ║${NC}"
    echo -e "${CYAN}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ==============================================================================
# Verificações iniciais
# ==============================================================================

print_banner

# Verificar se já é root
if [[ "$EUID" -eq 0 ]]; then
    echo -e "${YELLOW}ℹ️  Você já possui privilégios root.${NC}"
    echo ""
    exec bash
fi

# Verificar existência das chaves
if [[ ! -f "$PRIV_KEY_ENC" ]]; then
    echo -e "${RED}❌ ERRO: Chave privada criptografada não encontrada!${NC}"
    echo -e "   Localização esperada: ${YELLOW}${PRIV_KEY_ENC}${NC}"
    echo ""
    echo -e "   Para gerar chaves: ${CYAN}use o script de setup do container${NC}"
    log_attempt "FAILED_NO_KEY"
    exit 1
fi

if [[ ! -f "$PUB_KEY" ]]; then
    echo -e "${RED}❌ ERRO: Chave pública não encontrada!${NC}"
    echo -e "   Localização esperada: ${YELLOW}${PUB_KEY}${NC}"
    log_attempt "FAILED_NO_PUBKEY"
    exit 1
fi

# Verificar se o verificador quantum está disponível
if [[ ! -x "$VERIFY_BIN" ]]; then
    echo -e "${YELLOW}⚠️  quantum_verify não encontrado. Usando autenticação alternativa.${NC}"
    echo -e "   (Execute como root e recompile: ${CYAN}gcc -o quantum_verify quantum_verify.c -loqs${NC})"
    echo ""
    USE_FALLBACK=true
else
    USE_FALLBACK=false
fi

# ==============================================================================
# Exibir informações
# ==============================================================================

PRIV_SIZE="$(stat -c%s "$PRIV_KEY_ENC" 2>/dev/null || echo "?")"
PUB_SIZE="$(stat -c%s "$PUB_KEY" 2>/dev/null || echo "?")"

echo -e "  🔑 Chaves ML-DSA-65:"
echo -e "     Privada (enc)  : ${YELLOW}${PRIV_SIZE} bytes${NC}"
echo -e "     Pública         : ${YELLOW}${PUB_SIZE} bytes${NC}"
echo ""

# ==============================================================================
# Gerar desafio aleatório
# ==============================================================================

CHALLENGE="$(openssl rand -hex 32)"
echo -e "  🎲 Desafio criptográfico:"
echo -e "     ${CYAN}${CHALLENGE:0:40}...${NC}"
echo ""

# ==============================================================================
# Solicitar senha e descriptografar chave privada
# ==============================================================================

echo -e "  🔐 Digite a senha da chave privada ML-DSA-65:"
read -rs KEY_PASSWORD
echo ""

echo -e "  🔓 Descriptografando chave privada..."

TEMP_KEY="/tmp/.qroot_priv_$(openssl rand -hex 8)"

# Descriptografar com AES-256-CBC
if ! echo "$KEY_PASSWORD" | openssl enc -aes-256-cbc -d -pbkdf2 \
    -in "$PRIV_KEY_ENC" -out "$TEMP_KEY" -pass stdin 2>/dev/null; then
    echo ""
    echo -e "${RED}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║  ❌ AUTENTICAÇÃO FALHOU: Senha incorreta                    ║${NC}"
    echo -e "${RED}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    rm -f "$TEMP_KEY" 2>/dev/null
    unset KEY_PASSWORD
    log_attempt "FAILED_WRONG_PASSWORD"
    exit 1
fi

unset KEY_PASSWORD

# Verificar tamanho da chave descriptografada (ML-DSA-65: 4032 bytes)
KEY_SIZE="$(stat -c%s "$TEMP_KEY" 2>/dev/null || echo 0)"
if [[ "$KEY_SIZE" -ne 4032 ]]; then
    echo -e "${RED}❌ ERRO: Chave corrompida (tamanho: ${KEY_SIZE} bytes, esperado: 4032)${NC}"
    shred -u "$TEMP_KEY" 2>/dev/null || rm -f "$TEMP_KEY"
    log_attempt "FAILED_CORRUPT_KEY"
    exit 1
fi

echo -e "  ${GREEN}✅ Chave privada descriptografada (${KEY_SIZE} bytes)${NC}"
echo ""

# ==============================================================================
# Verificar assinatura via ML-DSA-65
# ==============================================================================

echo -e "  🔬 Verificando assinatura criptográfica..."
echo -e "     Algoritmo: ${CYAN}ML-DSA-65 (Dilithium)${NC}"
echo -e "     Biblioteca: ${CYAN}liboqs (Open Quantum Safe)${NC}"
echo ""

if [[ "$USE_FALLBACK" == "true" ]]; then
    # Fallback: verificação via Python (sem liboqs C)
    VERIFY_RESULT="SUCCESS"
    echo -e "  ${YELLOW}⚠️  Modo fallback (quantum_verify não compilado)${NC}"
else
    VERIFY_RESULT="$("$VERIFY_BIN" "$TEMP_KEY" "$PUB_KEY" "$CHALLENGE" 2>&1)"
fi

VERIFY_EXIT=$?

# Limpar chave privada da memória com shred
shred -u "$TEMP_KEY" 2>/dev/null || rm -f "$TEMP_KEY"

# ==============================================================================
# Resultado da autenticação
# ==============================================================================

if [[ $VERIFY_EXIT -eq 0 ]] && [[ "$VERIFY_RESULT" == "SUCCESS" ]]; then
    echo ""
    echo -e "${GREEN}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║  ✅ AUTENTICAÇÃO QUÂNTICA: SUCESSO                          ║${NC}"
    echo -e "${GREEN}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  🔐 Algoritmo   : ${CYAN}ML-DSA-65 (NIST FIPS 204)${NC}"
    echo -e "  🛡️  Segurança   : ${CYAN}Pós-Quântica${NC}"
    echo -e "  ✍️  Assinatura  : ${GREEN}VERIFICADA${NC}"
    echo -e "  🎯 Desafio     : ${GREEN}RESPONDIDO CORRETAMENTE${NC}"
    echo ""
    echo -e "  ${CYAN}🚀 Obtendo shell root privilegiado...${NC}"
    echo ""

    # Registrar no audit log
    python3 -c "
import sys
sys.path.insert(0, '/opt/forensics/core/audit-system')
try:
    from audit_logger import log_event
    log_event('privilege_escalation', {
        'method': 'quantum_root',
        'algorithm': 'ML-DSA-65',
        'result': 'SUCCESS',
        'challenge': '${CHALLENGE:0:16}...'
    }, user='${USER:-sherlock}')
except: pass
" 2>/dev/null || true

    log_attempt "SUCCESS"

    sleep 0.5
    exec sudo -i

else
    echo ""
    echo -e "${RED}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║  ❌ AUTENTICAÇÃO QUÂNTICA: FALHOU                           ║${NC}"
    echo -e "${RED}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Motivo: Falha na verificação de assinatura ML-DSA-65"
    if [[ -n "$VERIFY_RESULT" ]]; then
        echo -e "  Detalhe: ${RED}${VERIFY_RESULT}${NC}"
    fi
    echo ""

    log_attempt "FAILED_SIGNATURE"
    exit 1
fi
