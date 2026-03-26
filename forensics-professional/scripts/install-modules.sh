#!/bin/bash
# ==============================================================================
# Professional Forensics Container — install-modules.sh v2.1.0
# Script alternativo de instalação de módulos (quando forensics-modules quebra)
#
# Contexto: quando "forensics-modules remove" era executado, ele removia
# dependências Python (urllib3), quebrando o forensics-modules. Este script
# é o fallback confiável sem dependências externas complexas.
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ Execute como root: quantum-root${NC}"
    exit 1
fi

print_banner() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         🔧 FORENSICS MODULES INSTALLER v2.1.0              ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_banner

echo "  Módulos disponíveis:"
echo ""
echo "   1. Memory Forensics   (Volatility3)"
echo "   2. Disk Forensics     (Sleuthkit, TestDisk, Foremost)"
echo "   3. Malware Analysis   (YARA, ClamAV, Rizin)"
echo "   4. Network Forensics  (Wireshark/tshark, Zeek)"
echo "   5. Cloud Forensics    (AWS CLI, boto3)"
echo "   6. Mobile Forensics   (ADB, libimobiledevice)"
echo "   7. OSINT Tools        (theHarvester, Sherlock, Holehe)"
echo "   8. Threat Intel       (MISP, Sigma, OTX)"
echo "   9. Windows Forensics  (RegRipper, python-evtx)"
echo "  10. Linux Forensics    (auditd, extundelete)"
echo "  11. Email Forensics    (readpst, eml-parser)"
echo "  12. Container Forensics (dive, kubectl)"
echo "  13. Database Forensics (mysql-client, pymongo)"
echo "  14. TODOS              (instalar tudo, 20-30 min)"
echo ""
read -p "  Escolha (1-14): " CHOICE

log_event() {
    local module="$1"
    local result="$2"
    python3 -c "
import sys
sys.path.insert(0, '/opt/forensics/core/audit-system')
try:
    from audit_logger import log_event
    log_event('module_install', {'module': '${module}', 'result': '${result}', 'installer': 'install-modules.sh'})
except: pass
" 2>/dev/null || true
}

install_memory() {
    echo -e "\n${YELLOW}[⏳] Instalando Memory Forensics...${NC}"
    pip3 install volatility3 --no-cache-dir
    git clone --depth 1 https://github.com/volatilityfoundation/volatility \
        /opt/forensics/tools/volatility2 2>/dev/null || true
    echo -e "${GREEN}[✅] Memory Forensics instalado!${NC}"
    log_event "memory-forensics" "success"
}

install_disk() {
    echo -e "\n${YELLOW}[⏳] Instalando Disk Forensics...${NC}"
    apt-get update -qq
    apt-get install -y sleuthkit testdisk foremost dcfldd ddrescue
    echo -e "${GREEN}[✅] Disk Forensics instalado!${NC}"
    log_event "disk-forensics" "success"
}

install_malware() {
    echo -e "\n${YELLOW}[⏳] Instalando Malware Analysis...${NC}"
    apt-get update -qq
    apt-get install -y yara clamav rizin
    pip3 install yara-python --no-cache-dir
    freshclam 2>/dev/null || true
    echo -e "${GREEN}[✅] Malware Analysis instalado!${NC}"
    log_event "malware-analysis" "success"
}

install_network() {
    echo -e "\n${YELLOW}[⏳] Instalando Network Forensics...${NC}"
    echo 'wireshark-common wireshark-common/install-setuid boolean false' \
        | debconf-set-selections
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y tshark tcpdump ngrep tcpflow
    echo -e "${GREEN}[✅] Network Forensics instalado!${NC}"
    log_event "network-forensics" "success"
}

install_cloud() {
    echo -e "\n${YELLOW}[⏳] Instalando Cloud Forensics (AWS CLI)...${NC}"
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" \
        -o /tmp/awscliv2.zip
    unzip -q /tmp/awscliv2.zip -d /tmp
    /tmp/aws/install --update
    rm -rf /tmp/aws /tmp/awscliv2.zip
    pip3 install boto3 --no-cache-dir
    echo -e "${GREEN}[✅] Cloud Forensics instalado!${NC}"
    log_event "cloud-forensics" "success"
}

install_mobile() {
    echo -e "\n${YELLOW}[⏳] Instalando Mobile Forensics...${NC}"
    apt-get update -qq
    apt-get install -y android-tools-adb android-tools-fastboot \
        libimobiledevice-utils default-jdk sqlite3 git
    pip3 install androguard --no-cache-dir
    # ABE - Android Backup Extractor
    rm -rf /tmp/abe
    git clone --depth 1 https://github.com/nelenkov/android-backup-extractor /tmp/abe
    cd /tmp/abe && ./gradlew && \
        cp build/libs/abe-all.jar /opt/forensics/tools/abe.jar
    rm -rf /tmp/abe
    echo -e "${GREEN}[✅] Mobile Forensics instalado!${NC}"
    echo -e "     ABE: java -jar /opt/forensics/tools/abe.jar unpack backup.ab out.tar"
    log_event "mobile-forensics" "success"
}

install_osint() {
    echo -e "\n${YELLOW}[⏳] Instalando OSINT Tools...${NC}"
    pip3 install theHarvester sherlock-project holehe --no-cache-dir
    echo -e "${GREEN}[✅] OSINT Tools instalado!${NC}"
    log_event "osint-tools" "success"
}

install_threat() {
    echo -e "\n${YELLOW}[⏳] Instalando Threat Intelligence...${NC}"
    pip3 install pymisp OTXv2 sigma-cli pysigma pycti --no-cache-dir
    echo -e "${GREEN}[✅] Threat Intelligence instalado!${NC}"
    log_event "threat-intelligence" "success"
}

install_windows() {
    echo -e "\n${YELLOW}[⏳] Instalando Windows Forensics...${NC}"
    pip3 install python-evtx --no-cache-dir
    git clone --depth 1 https://github.com/keydet89/RegRipper3.0 \
        /opt/forensics/tools/regripper 2>/dev/null || true
    echo -e "${GREEN}[✅] Windows Forensics instalado!${NC}"
    log_event "windows-forensics" "success"
}

install_linux() {
    echo -e "\n${YELLOW}[⏳] Instalando Linux Forensics...${NC}"
    apt-get update -qq
    apt-get install -y auditd audispd-plugins extundelete logwatch
    echo -e "${GREEN}[✅] Linux Forensics instalado!${NC}"
    log_event "linux-forensics" "success"
}

install_email() {
    echo -e "\n${YELLOW}[⏳] Instalando Email Forensics...${NC}"
    apt-get install -y readpst libpst-dev 2>/dev/null || true
    pip3 install eml_parser mail-parser --no-cache-dir
    echo -e "${GREEN}[✅] Email Forensics instalado!${NC}"
    log_event "email-forensics" "success"
}

install_container() {
    echo -e "\n${YELLOW}[⏳] Instalando Container Forensics...${NC}"
    wget -q https://github.com/wagoodman/dive/releases/latest/download/dive_linux_amd64.tar.gz \
        -O /tmp/dive.tar.gz && \
    tar -xzf /tmp/dive.tar.gz -C /usr/local/bin dive && \
    rm -f /tmp/dive.tar.gz || true
    echo -e "${GREEN}[✅] Container Forensics instalado!${NC}"
    log_event "container-forensics" "success"
}

install_database() {
    echo -e "\n${YELLOW}[⏳] Instalando Database Forensics...${NC}"
    apt-get install -y default-mysql-client postgresql-client sqlite3
    pip3 install pymongo --no-cache-dir
    echo -e "${GREEN}[✅] Database Forensics instalado!${NC}"
    log_event "database-forensics" "success"
}

case "$CHOICE" in
    1) install_memory ;;
    2) install_disk ;;
    3) install_malware ;;
    4) install_network ;;
    5) install_cloud ;;
    6) install_mobile ;;
    7) install_osint ;;
    8) install_threat ;;
    9) install_windows ;;
   10) install_linux ;;
   11) install_email ;;
   12) install_container ;;
   13) install_database ;;
   14)
      echo -e "\n${YELLOW}Instalando TUDO (20-30 min)...${NC}"
      install_disk
      install_malware
      install_network
      install_mobile
      install_osint
      install_threat
      install_windows
      install_linux
      install_email
      install_container
      install_database
      # Memory e Cloud por último (mais pesados)
      install_memory
      install_cloud
      ;;
    *)
      echo -e "${RED}❌ Opção inválida: $CHOICE${NC}"
      exit 1
      ;;
esac

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ✅ Instalação concluída!                                   ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
