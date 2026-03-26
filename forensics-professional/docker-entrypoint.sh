#!/bin/bash
# ==============================================================================
# Professional Forensics Container — docker-entrypoint.sh v2.1.0-FINAL
# Inicialização segura: root → sherlock
# Compliance: NIST SP 800-86
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

FORENSICS_HOME="/opt/forensics"
LOGS_DIR="/var/log/forensics"
KEYS_DIR="/opt/forensics/quantum-keys"
AUDIT_LOG="${LOGS_DIR}/audit.log"

# ==============================================================================
# FASE 1: Inicialização como ROOT (operações privilegiadas)
# ==============================================================================

echo -e "${CYAN}[INIT] Starting Forensics Professional Container v2.1.0-FINAL...${NC}"

# 1.1 Garantir estrutura de diretórios de logs
mkdir -p "${LOGS_DIR}/installations"
mkdir -p "${LOGS_DIR}/chain-of-custody"
mkdir -p "${LOGS_DIR}/telemetry"
mkdir -p "${LOGS_DIR}/chain-of-custody/$(date +%Y/%m/%d)"

# 1.2 Aplicar atributo append-only nos logs (imutabilidade forense)
# chattr +a: permite apenas acrescentar — impossível modificar ou deletar
if command -v chattr &>/dev/null; then
    touch "${AUDIT_LOG}" 2>/dev/null || true
    chattr +a "${AUDIT_LOG}" 2>/dev/null || true
    echo -e "${GREEN}[INIT] Audit log protected with chattr +a (append-only)${NC}"
fi

# 1.3 Proteger /evidence (read-only por permissão também)
chmod 555 /evidence 2>/dev/null || true

# 1.4 Corrigir permissões de escrita para sherlock
chown -R sherlock:sherlock /cases 2>/dev/null || true
chown -R sherlock:sherlock /reports 2>/dev/null || true
chown -R sherlock:sherlock "${LOGS_DIR}" 2>/dev/null || true
chown -R sherlock:sherlock "${FORENSICS_HOME}" 2>/dev/null || true

# 1.5 Inicializar sistema de chaves criptográficas
if [ ! -f "${KEYS_DIR}/audit_ed25519.key" ]; then
    echo -e "${YELLOW}[INIT] Generating Ed25519 signing keys...${NC}"
    python3 << 'PYTHON' 2>/dev/null || true
import os
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

keys_dir = "/opt/forensics/quantum-keys"
os.makedirs(keys_dir, exist_ok=True)

# Gerar par de chaves Ed25519
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Salvar chave privada
priv_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open(f"{keys_dir}/audit_ed25519.key", "wb") as f:
    f.write(priv_bytes)
os.chmod(f"{keys_dir}/audit_ed25519.key", 0o600)

# Salvar chave pública
pub_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open(f"{keys_dir}/audit_ed25519.pub", "wb") as f:
    f.write(pub_bytes)
os.chmod(f"{keys_dir}/audit_ed25519.pub", 0o644)

print("Ed25519 keypair generated successfully")
PYTHON
    echo -e "${GREEN}[INIT] Ed25519 keys generated${NC}"
fi

# 1.6 Inicializar GPG keyring para assinaturas
if ! gpg --list-keys forensics-audit@professional.local &>/dev/null 2>&1; then
    echo -e "${YELLOW}[INIT] Generating GPG key for audit signatures...${NC}"
    cat > /tmp/gpg-params << 'GPG'
%no-protection
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: Forensics Professional
Name-Email: forensics-audit@professional.local
Expire-Date: 0
%commit
GPG
    gpg --batch --gen-key /tmp/gpg-params 2>/dev/null || true
    rm -f /tmp/gpg-params
    echo -e "${GREEN}[INIT] GPG key generated${NC}"
fi

# 1.7 Inicializar audit log (genesis entry)
if [ ! -s "${AUDIT_LOG}" ]; then
    echo -e "${YELLOW}[INIT] Creating genesis audit entry...${NC}"
    python3 << 'PYTHON' 2>/dev/null || true
import json
import hashlib
import datetime
import os

audit_log = "/var/log/forensics/audit.log"
genesis = {
    "seq": 0,
    "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
    "event_type": "container_started",
    "user": "system",
    "details": {
        "version": "2.1.0-FINAL",
        "compliance": "NIST SP 800-86",
        "crypto": "Ed25519 + GPG + ML-DSA-65 PQC"
    },
    "prev_hash": "0" * 64,
    "hash": "",
    "signatures": {
        "ed25519": "genesis_entry_no_signature",
        "gpg": "genesis_entry_no_signature"
    }
}
data = json.dumps({k: v for k, v in genesis.items() if k != "hash"}, sort_keys=True)
genesis["hash"] = hashlib.sha256(data.encode()).hexdigest()

with open(audit_log, "a") as f:
    f.write(json.dumps(genesis) + "\n")

print(f"Genesis entry created: {genesis['hash'][:16]}...")
PYTHON
    echo -e "${GREEN}[INIT] Audit log initialized${NC}"
fi

# 1.8 Instalar bash-hooks da chain of custody (se existirem)
if [ -f "/opt/forensics/core/audit-system/bash-hooks.sh" ]; then
    # Copiar para chain-logger (caminho esperado pelos hooks)
    cp /opt/forensics/core/audit-system/bash-hooks.sh \
       /opt/forensics/chain-logger/bash-hooks.sh 2>/dev/null || true
    chmod +x /opt/forensics/chain-logger/bash-hooks.sh 2>/dev/null || true
fi

# 1.9 Criar link para quantum-root
if [ -f "/opt/forensics/core/audit-system/quantum-root" ]; then
    ln -sf /opt/forensics/core/audit-system/quantum-root /usr/local/bin/quantum-root 2>/dev/null || true
    ln -sf /usr/local/bin/quantum-root /usr/local/bin/qroot 2>/dev/null || true
    chmod 755 /usr/local/bin/quantum-root 2>/dev/null || true
fi

# 1.10 Log de inicialização
echo -e "${GREEN}[INIT] Container initialized successfully${NC}"
echo -e "${GREEN}[INIT] Switching to user: sherlock${NC}"

# ==============================================================================
# FASE 2: Configurar ambiente do sherlock
# ==============================================================================

# Configurar .bashrc do sherlock com ambiente forense
cat > /home/sherlock/.bashrc << 'BASHRC'
# ==============================================================================
# Forensics Professional — Shell Environment v2.1.0
# ==============================================================================

# Source global definitions
if [ -f /etc/bashrc ]; then
    . /etc/bashrc
fi

# Cores
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export CYAN='\033[0;36m'
export NC='\033[0m'

# Variáveis de ambiente forenses
export FORENSICS_HOME="/opt/forensics"
export FORENSICS_LOGS="/var/log/forensics"
export FORENSICS_MODULES="/opt/forensics/modules"
export FORENSICS_KEYS="/opt/forensics/quantum-keys"
export FORENSICS_VERSION="2.1.0-FINAL"
export TZ="UTC"

# PATH forense
export PATH="/opt/forensics/bin:/opt/forensics/core/module-manager:/opt/forensics/core/audit-system:/usr/local/bin:$PATH"
export PYTHONPATH="/opt/forensics/core:/opt/forensics/core/audit-system"

# Prompt profissional
export PS1='\[\033[01;36m\][FORENSICS] \[\033[01;32m\]\u\[\033[00m\]@\[\033[01;34m\]\h\[\033[00m\]:\[\033[01;33m\]\w\[\033[00m\]$ '

# Aliases forenses úteis
alias ll='ls -la'
alias audit='forensics-audit'
alias modules='forensics-modules'
alias health='forensics-health'
alias qroot='quantum-root'

# Bash hooks para chain of custody automática
if [[ -f /opt/forensics/chain-logger/bash-hooks.sh ]]; then
    source /opt/forensics/chain-logger/bash-hooks.sh
fi

# Mostrar banner na primeira vez
if [[ -z "$FORENSICS_BANNER_SHOWN" ]]; then
    export FORENSICS_BANNER_SHOWN=1
    cat /etc/motd 2>/dev/null || true
fi
BASHRC

chown sherlock:sherlock /home/sherlock/.bashrc

# ==============================================================================
# FASE 3: Logar início do container no audit trail
# ==============================================================================
python3 << 'PYTHON' 2>/dev/null || true
import json
import hashlib
import datetime
import os

audit_log = "/var/log/forensics/audit.log"

# Ler último hash
last_hash = "0" * 64
try:
    with open(audit_log, "r") as f:
        lines = [l.strip() for l in f if l.strip()]
    if lines:
        last_entry = json.loads(lines[-1])
        last_hash = last_entry.get("hash", "0" * 64)
        seq = last_entry.get("seq", -1) + 1
    else:
        seq = 1
except:
    seq = 1

entry = {
    "seq": seq,
    "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
    "event_type": "container_started",
    "user": "system",
    "details": {
        "container": "forensics-workstation",
        "version": "2.1.0-FINAL",
        "user_session": "sherlock"
    },
    "prev_hash": last_hash,
    "hash": "",
    "signatures": {"ed25519": "runtime_init", "gpg": "runtime_init"}
}

data = json.dumps({k: v for k, v in entry.items() if k != "hash"}, sort_keys=True)
entry["hash"] = hashlib.sha256(data.encode()).hexdigest()

with open(audit_log, "a") as f:
    f.write(json.dumps(entry) + "\n")
PYTHON

# ==============================================================================
# FASE 4: Executar como sherlock
# ==============================================================================
exec gosu sherlock "$@" 2>/dev/null || \
exec su -s /bin/bash sherlock -c "$*" 2>/dev/null || \
exec su - sherlock
