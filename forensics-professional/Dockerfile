# ==============================================================================
# Professional Forensics Container - Dockerfile v2.1.0-FINAL
# Autor: joao-henrike | Compliance: NIST SP 800-86
# ==============================================================================
#
# CORREÇÕES CRÍTICAS INCORPORADAS (extraídas da bateria de testes):
#
#  [FIX-1] openssl rand -base64 32 → echo "sherlock:forensics" | chpasswd
#           Causa: erro de subshell (exit code 1) ao criar senha do usuário
#
#  [FIX-2] Pacote 'yq' REMOVIDO do apt-get
#           Causa: não possui installation candidate no Ubuntu 22.04 (exit code 100)
#
#  [FIX-3] Pacote 'hashlib' REMOVIDO do pip3
#           Causa: módulo nativo do Python, causava legacy-install-failure
#
#  [FIX-4] Pacote 'requests' ADICIONADO ao pip3
#           Causa: ModuleNotFoundError ao invocar forensics-modules
#
#  [FIX-5] /var/log/forensics/telemetry CRIADO explicitamente
#           Causa: PermissionError no Flight Recorder (telemetry collector)
#
#  [FIX-6] chown -R sherlock:sherlock /cases
#           Causa: Permission denied ao criar arquivos de análise em /cases
#
#  [FIX-7] software-properties-common ADICIONADO
#           Causa: add-apt-repository necessário para Plaso via PPA
#
#  [FIX-8] Conflito urllib3/Python 3.10 → pip3 install --upgrade urllib3 requests
#           Causa: ImportError: cannot import name 'Mapping' from 'collections'
#
#  [FIX-9] COPY config/ → diretório deve existir no host (criado via .gitkeep)
#           Causa: "failed to compute cache key: /config not found"
#
#  [FIX-10] asyncio REMOVIDO do pip3 (módulo nativo desde Python 3.4)
#            Causa: pip ignorava silenciosamente, mas gerava warnings
#
#  [FIX-11] tabulate, rich, psutil ADICIONADOS
#            Causa: ImportError em forensics-modules list e forensics-health
#
#  [FEAT-1] attr ADICIONADO (necessário para chattr +a nos logs)
#  [FEAT-2] default-jdk ADICIONADO (necessário para ABE - Android Backup Extractor)
#  [FEAT-3] Symlinks automáticos para PATH do sistema
#  [FEAT-4] PYTHONPATH configurado para /opt/forensics/core
#  [FEAT-5] passwd -l root (desabilita login direto de root)
# ==============================================================================

# ==============================================================================
# STAGE 1: PQC Builder — Criptografia Pós-Quântica (liboqs)
# Compila Kyber (KEM) + ML-DSA-65/Dilithium (assinatura digital)
# ==============================================================================
FROM ubuntu:22.04 AS pqc-builder

LABEL stage="pqc-builder"

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    cmake \
    git \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/build

# Open Quantum Safe — biblioteca pós-quântica NIST-aprovada
RUN git clone --depth 1 --branch main \
    https://github.com/open-quantum-safe/liboqs.git

WORKDIR /opt/build/liboqs/build

RUN cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DOQS_USE_OPENSSL=ON \
    -DBUILD_SHARED_LIBS=ON \
    .. \
    && ninja \
    && ninja install

# ==============================================================================
# STAGE 2: Runtime Forensics — Imagem Final
# ==============================================================================
FROM ubuntu:22.04

LABEL maintainer="joao-henrike" \
      version="2.1.0-FINAL" \
      description="Professional Forensics Container — Post-Quantum Cryptography" \
      compliance="NIST SP 800-86" \
      cryptography="Post-Quantum ML-DSA-65 (Dilithium) + Ed25519 + GPG"

# ==============================================================================
# 1. USUÁRIO ANALISTA (sherlock)
# ==============================================================================
# FIX-1: openssl rand gerava exit code 1. Substituído por chpasswd.
RUN groupadd -r sherlock -g 1000 \
    && useradd -r -g sherlock -u 1000 -m -s /bin/bash sherlock \
    && echo "sherlock:forensics" | chpasswd

# Grupo forense read-only — protege evidências de escrita acidental
RUN groupadd -r forensics-ro -g 1001 \
    && usermod -aG forensics-ro sherlock

# ==============================================================================
# 2. ESTRUTURA DE DIRETÓRIOS
# ==============================================================================
# FIX-5: /var/log/forensics/telemetry precisa existir para o Flight Recorder
# FIX-6: /cases precisa de permissão de escrita para o sherlock desde o build
RUN mkdir -p \
    /evidence \
    /cases \
    /keys \
    /logs \
    /reports \
    /config \
    /var/log/forensics \
    /var/log/forensics/telemetry \
    /var/log/forensics/installations \
    /var/log/forensics/chain-of-custody \
    /opt/forensics/tools \
    /opt/forensics/bin \
    /opt/forensics/core \
    /opt/forensics/modules/installed \
    /opt/forensics/modules/manifests \
    /opt/forensics/quantum-keys \
    /opt/forensics/chain-logger \
    /opt/quantum-crypto

# FIX-6: sherlock precisa de escrita em /cases e /reports desde o build
RUN chown -R sherlock:sherlock /cases \
    && chown -R sherlock:sherlock /reports \
    && chown -R sherlock:sherlock /opt/forensics \
    && chown -R sherlock:sherlock /var/log/forensics

# ==============================================================================
# 3. DEPENDÊNCIAS BASE (APT)
# ==============================================================================
# FIX-2: 'yq' removido (não existe no Ubuntu 22.04 padrão)
# FIX-7: software-properties-common adicionado (add-apt-repository para Plaso)
# FEAT-1: attr adicionado (chattr +a para imutabilidade dos logs)
# FEAT-2: default-jdk adicionado (ABE - Android Backup Extractor compila com Gradle)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    # Shell e utilitários base
    bash-completion \
    vim \
    nano \
    tmux \
    screen \
    # Controle de versão e rede
    git \
    curl \
    wget \
    # Processamento de dados
    jq \
    parallel \
    # Monitoramento e diagnóstico
    htop \
    tree \
    rsync \
    sysstat \
    iotop \
    nethogs \
    # Python runtime
    python3 \
    python3-pip \
    python3-venv \
    python-is-python3 \
    # Criptografia
    openssl \
    gnupg \
    gpg \
    # Análise binária
    file \
    binutils \
    strace \
    ltrace \
    # Compressão
    unzip \
    p7zip-full \
    gzip \
    bzip2 \
    xz-utils \
    # Rede
    net-tools \
    iproute2 \
    iputils-ping \
    dnsutils \
    # Repositórios dinâmicos (Plaso, ferramentas externas)
    software-properties-common \
    # Atributos de filesystem (chattr +a para logs imutáveis)
    attr \
    # Java (ABE - Android Backup Extractor)
    default-jdk \
    # SQLite (backup-extractors)
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# ==============================================================================
# 4. INJEÇÃO DA CRIPTOGRAFIA PÓS-QUÂNTICA (liboqs)
# ==============================================================================
COPY --from=pqc-builder /usr/local/lib/liboqs.so*    /usr/local/lib/
COPY --from=pqc-builder /usr/local/include/oqs       /usr/local/include/oqs/

RUN ldconfig

# ==============================================================================
# 5. DEPENDÊNCIAS PYTHON (PIP)
# ==============================================================================
# FIX-3: 'hashlib' removido — nativo do Python, quebrava o pip
# FIX-4: 'requests' adicionado — necessário para forensics-modules
# FIX-8: urllib3 e requests atualizados para corrigir ImportError no Python 3.10
#        (collections.Mapping → collections.abc.Mapping)
# FIX-10: 'asyncio' removido — nativo do Python desde 3.4
# FIX-11: tabulate, rich, psutil adicionados — necessários para forensics-modules list
RUN pip3 install --no-cache-dir \
    cryptography \
    pycryptodome \
    PyNaCl \
    pefile \
    python-magic \
    yara-python \
    aiofiles \
    python-dateutil \
    requests \
    urllib3 \
    tabulate \
    rich \
    psutil \
    androguard \
    pymisp \
    OTXv2 \
    sigma-cli

# ==============================================================================
# 6. INJEÇÃO DA ESTRUTURA DO REPOSITÓRIO
# ==============================================================================
# FIX-9: config/ deve existir no host (garantido via config/.gitkeep)
COPY core/                             /opt/forensics/core/
COPY scripts/                          /opt/forensics/bin/
COPY config/                           /etc/forensics/
COPY docs/banner.txt                   /etc/motd
COPY modules/registry.json             /opt/forensics/modules/registry.json
COPY docker-entrypoint.sh              /usr/local/bin/

# ==============================================================================
# 7. PERMISSÕES E SYMLINKS
# ==============================================================================
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && find /opt/forensics/bin  -type f -exec chmod +x {} \; \
    && find /opt/forensics/core -name "*.sh" -exec chmod +x {} \; \
    && find /opt/forensics/core -name "forensics-*" -exec chmod +x {} \;

# Symlinks para PATH global — permite chamar sem prefixo de caminho
RUN ln -sf /opt/forensics/core/module-manager/forensics-modules \
           /usr/local/bin/forensics-modules \
    && ln -sf /opt/forensics/core/audit-system/forensics-audit \
              /usr/local/bin/forensics-audit \
    && ln -sf /opt/forensics/bin/forensics-health \
              /usr/local/bin/forensics-health

# Compilar verificador de assinatura ML-DSA-65 (se código C existir)
# Este binário é usado pelo quantum-root para autenticação pós-quântica
RUN if [ -f "/opt/forensics/core/audit-system/quantum_verify.c" ]; then \
    gcc -o /usr/local/bin/quantum_verify \
        /opt/forensics/core/audit-system/quantum_verify.c \
        -loqs -I/usr/local/include -L/usr/local/lib \
    && chmod 755 /usr/local/bin/quantum_verify; \
    fi

# ==============================================================================
# 8. SEGURANÇA FINAL
# ==============================================================================
# Desabilitar login direto de root (acesso somente via quantum-root + PQC key)
RUN passwd -l root

# Append-only nos logs de auditoria (imutabilidade via chattr)
# Não pode ser feito no build — depende do filesystem do host em runtime
# É executado no docker-entrypoint.sh com privileged mode

# ==============================================================================
# 9. VARIÁVEIS DE AMBIENTE
# ==============================================================================
ENV FORENSICS_VERSION="2.1.0-FINAL" \
    FORENSICS_USER="sherlock" \
    FORENSICS_HOME="/opt/forensics" \
    FORENSICS_LOGS="/var/log/forensics" \
    FORENSICS_MODULES="/opt/forensics/modules" \
    FORENSICS_KEYS="/opt/forensics/quantum-keys" \
    PYTHONPATH="/opt/forensics/core:/opt/forensics/core/audit-system" \
    PATH="/opt/forensics/bin:/opt/forensics/core/module-manager:/opt/forensics/core/audit-system:/usr/local/bin:$PATH" \
    TZ="UTC" \
    LANG="en_US.UTF-8" \
    DEBIAN_FRONTEND="noninteractive"

# ==============================================================================
# 10. ENTRYPOINT
# ==============================================================================
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["bash"]
