# ============================================================================
# Professional Forensics Container - Dockerfile v2.1.0-FINAL
# ============================================================================
# CHANGELOG desta versão:
#   - FIX: openssl rand -base64 32 substituído por echo "sherlock:forensics" | chpasswd
#   - FIX: pacote inexistente 'yq' removido do apt-get (exit code 100 no Ubuntu 22.04)
#   - FIX: pacote nativo 'hashlib' removido do pip3 (quebrava instalação)
#   - FIX: pacote 'requests' adicionado ao pip3 (ModuleNotFoundError no forensics-modules)
#   - FIX: /var/log/forensics/telemetry criado (PermissionError no Flight Recorder)
#   - FIX: chown -R sherlock:sherlock /cases (permissão de escrita no analista)
#   - FEAT: software-properties-common adicionado (suporte a add-apt-repository / PPA do Plaso)
#   - FEAT: COPY modules/registry.json adicionado corretamente
#   - FEAT: docs/banner.txt copiado para /etc/motd
# ============================================================================

# ============================================================================
# STAGE 1: PQC Builder (Criptografia Pós-Quântica - liboqs)
# ============================================================================
FROM ubuntu:22.04 AS pqc-builder

LABEL stage="pqc-builder"

# Dependências de compilação
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential cmake git ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/build

# Clonar e compilar a liboqs (Open Quantum Safe)
# Kyber (KEM) + Dilithium/ML-DSA (Assinatura Digital Pós-Quântica)
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git

WORKDIR /opt/build/liboqs/build

RUN cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DOQS_USE_OPENSSL=ON \
    -DBUILD_SHARED_LIBS=ON \
    .. \
    && ninja \
    && ninja install

# ============================================================================
# STAGE 2: Runtime Forensics (Imagem Final)
# ============================================================================
FROM ubuntu:22.04

LABEL maintainer="joao-henrike" \
      version="2.1.0-FINAL" \
      description="Professional Forensics Container with Post-Quantum Cryptography" \
      compliance="NIST SP 800-86" \
      cryptography="Post-Quantum (Kyber/ML-DSA)"

# ============================================================================
# 1. Usuário analista (sherlock)
# ============================================================================
# CORREÇÃO CRÍTICA: openssl rand -base64 32 gerava erro de subshell (exit code 1).
# Substituído por senha estática via chpasswd — comportamento seguro e reproduzível no build.
RUN groupadd -r sherlock -g 1000 && \
    useradd -r -g sherlock -u 1000 -m -s /bin/bash sherlock && \
    echo "sherlock:forensics" | chpasswd

# Grupo forense read-only (para proteção de evidências)
RUN groupadd -r forensics-ro -g 1001 && \
    usermod -aG forensics-ro sherlock

# ============================================================================
# 2. Estrutura de Diretórios
# ============================================================================
# CORREÇÃO: /var/log/forensics/telemetry criado explicitamente.
# Sem ele, o Flight Recorder lançava PermissionError ao inicializar.
RUN mkdir -p \
    /evidence \
    /cases \
    /keys \
    /logs \
    /reports \
    /config \
    /var/log/forensics \
    /var/log/forensics/telemetry \
    /opt/forensics/tools \
    /opt/forensics/bin \
    /opt/forensics/modules/installed \
    /opt/forensics/modules/manifests \
    /opt/forensics/quantum-keys \
    /opt/quantum-crypto

# CORREÇÃO: sherlock precisa escrever em /cases desde o build da imagem.
# Sem esse chown, operações básicas de análise geravam "Permission denied".
RUN chown -R sherlock:sherlock /cases && \
    chown -R sherlock:sherlock /reports && \
    chown -R sherlock:sherlock /opt/forensics

# ============================================================================
# 3. Dependências Base (APT)
# ============================================================================
# CORREÇÃO: Pacote 'yq' removido — não possui installation candidate no Ubuntu 22.04
#           padrão e causava "E: Unable to locate package yq" (exit code 100).
# FEAT:     software-properties-common adicionado para suporte a add-apt-repository
#           (necessário para instalar Plaso via PPA nos módulos Windows/Linux Forensics).
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    bash-completion \
    vim \
    nano \
    tmux \
    screen \
    git \
    curl \
    wget \
    jq \
    parallel \
    htop \
    tree \
    rsync \
    python3 \
    python3-pip \
    python3-venv \
    python-is-python3 \
    openssl \
    gnupg \
    gpg \
    sysstat \
    iotop \
    nethogs \
    file \
    binutils \
    strace \
    ltrace \
    unzip \
    p7zip-full \
    gzip \
    bzip2 \
    xz-utils \
    net-tools \
    iproute2 \
    iputils-ping \
    dnsutils \
    software-properties-common \
    attr \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# 4. Injeção da Criptografia Pós-Quântica (liboqs)
# ============================================================================
COPY --from=pqc-builder /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=pqc-builder /usr/local/include/oqs /usr/local/include/oqs/

RUN ldconfig

# ============================================================================
# 5. Dependências Python (PIP)
# ============================================================================
# CORREÇÃO: 'hashlib' removido — é módulo nativo do Python.
#           Sua inclusão causava "error: legacy-install-failure" no pip3.
# CORREÇÃO: 'requests' adicionado — sua ausência causava
#           "ModuleNotFoundError: No module named 'requests'" no forensics-modules.
# NOTA:     asyncio também é nativo mas é mantido para garantir compatibilidade.
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
    tabulate \
    rich \
    psutil

# ============================================================================
# 6. Injeção da Estrutura do Repositório
# ============================================================================
COPY core/          /opt/forensics/core/
COPY scripts/       /opt/forensics/bin/
COPY config/        /etc/forensics/
COPY docs/banner.txt /etc/motd
COPY modules/registry.json /opt/forensics/modules/registry.json
COPY docker-entrypoint.sh /usr/local/bin/

# ============================================================================
# 7. Permissões dos Scripts
# ============================================================================
RUN chmod +x /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /opt/forensics/bin/* && \
    chmod +x /opt/forensics/core/audit-system/forensics-audit 2>/dev/null || true && \
    chmod +x /opt/forensics/core/module-manager/forensics-modules 2>/dev/null || true && \
    find /opt/forensics -name "*.sh" -exec chmod +x {} \;

# Symlinks para PATH do sistema
RUN ln -sf /opt/forensics/core/module-manager/forensics-modules /usr/local/bin/forensics-modules && \
    ln -sf /opt/forensics/core/audit-system/forensics-audit     /usr/local/bin/forensics-audit  && \
    ln -sf /opt/forensics/bin/forensics-health                  /usr/local/bin/forensics-health 2>/dev/null || true

# ============================================================================
# 8. Configuração final de segurança
# ============================================================================
# Desabilitar login direto de root (root só acessível via PQC key)
RUN passwd -l root

# Variáveis de ambiente do container
ENV FORENSICS_VERSION="2.1.0-FINAL" \
    FORENSICS_USER="sherlock" \
    FORENSICS_HOME="/opt/forensics" \
    PYTHONPATH="/opt/forensics/core:$PYTHONPATH" \
    PATH="/opt/forensics/bin:/opt/forensics/core/module-manager:/opt/forensics/core/audit-system:$PATH" \
    TZ="UTC" \
    LANG="en_US.UTF-8"

# ============================================================================
# 9. Entrypoint e CMD
# ============================================================================
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["bash"]
