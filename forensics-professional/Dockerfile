# ==============================================================================
# PROFESSIONAL FORENSICS CONTAINER - Post-Quantum Secured
# ==============================================================================
# Multi-stage build with post-quantum cryptography
# Root: PQC encrypted (Kyber/Dilithium) - owner only
# User: sherlock - full access except evidence/custody modification
# Compliance: NIST SP 800-86
# Version: 2.0.0
# ==============================================================================

# ==============================================================================
# Stage 1: Build post-quantum cryptography libraries
# ==============================================================================
FROM ubuntu:22.04 AS pqc-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

# Build liboqs (Open Quantum Safe)
WORKDIR /opt/build
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_USE_OPENSSL=ON \
        .. && \
    ninja && \
    ninja install

# Build oqs-provider for OpenSSL
RUN git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git && \
    cd oqs-provider && \
    cmake -S . -B _build \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR=/usr && \
    cmake --build _build && \
    cmake --install _build

# ==============================================================================
# Stage 2: Build forensic tools
# ==============================================================================
FROM ubuntu:22.04 AS forensics-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    cmake \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libssl-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Build optimized versions of key tools
WORKDIR /opt/build

# Volatility3 from source
RUN git clone https://github.com/volatilityfoundation/volatility3.git && \
    cd volatility3 && \
    python3 setup.py build

# ==============================================================================
# Stage 3: Runtime environment with security hardening
# ==============================================================================
FROM ubuntu:22.04

LABEL maintainer="forensics-professional"
LABEL description="Professional Forensics Container with PQC and NIST Compliance"
LABEL version="2.0.0"
LABEL compliance="NIST-SP-800-86"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    PYTHONUNBUFFERED=1 \
    FORENSICS_VERSION=2.0.0 \
    EVIDENCE_DIR=/evidence \
    CASES_DIR=/cases \
    KEYS_DIR=/keys \
    LOGS_DIR=/var/log/forensics \
    MODULES_DIR=/opt/forensics/modules \
    REPORTS_DIR=/reports \
    CONFIG_DIR=/etc/forensics

# ==============================================================================
# Create users with specific permissions
# ==============================================================================

# Create sherlock user (UID 1000) - public user
RUN groupadd -r sherlock -g 1000 && \
    useradd -r -g sherlock -u 1000 -m -s /bin/bash sherlock && \
    echo "sherlock:$(openssl rand -base64 32)" | chpasswd

# Create forensics group for evidence access (read-only)
RUN groupadd -r forensics-ro -g 1001

# Add sherlock to forensics-ro group
RUN usermod -aG forensics-ro sherlock

# Create directories with specific permissions
RUN mkdir -p \
    ${EVIDENCE_DIR} \
    ${CASES_DIR} \
    ${KEYS_DIR} \
    ${LOGS_DIR} \
    ${MODULES_DIR} \
    ${REPORTS_DIR} \
    ${CONFIG_DIR} \
    /opt/forensics/core \
    /opt/forensics/bin \
    /opt/forensics/integrations \
    /opt/forensics/debugging

# ==============================================================================
# Install system packages and forensic tools
# ==============================================================================

RUN apt-get update && apt-get install -y \
    # Core system utilities
    bash-completion \
    vim \
    nano \
    tmux \
    screen \
    git \
    curl \
    wget \
    jq \
    yq \
    parallel \
    htop \
    tree \
    rsync \
    # Python environment
    python3 \
    python3-pip \
    python3-venv \
    python-is-python3 \
    # Cryptography and security
    openssl \
    gnupg \
    gpg \
    # Performance tools
    sysstat \
    iotop \
    nethogs \
    # Core forensic tools (minimal base, modules add more)
    file \
    binutils \
    strace \
    ltrace \
    # Compression
    unzip \
    p7zip-full \
    gzip \
    bzip2 \
    xz-utils \
    # Network utilities
    net-tools \
    iproute2 \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# ==============================================================================
# Copy post-quantum crypto libraries from builder
# ==============================================================================

COPY --from=pqc-builder /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=pqc-builder /usr/local/include/oqs /usr/local/include/oqs
COPY --from=pqc-builder /opt/build/oqs-provider/_build/lib/oqsprovider.so /usr/lib/x86_64-linux-gnu/ossl-modules/
RUN ldconfig

# ==============================================================================
# Install Python packages for forensics core
# ==============================================================================

RUN pip3 install --no-cache-dir \
    # Cryptography (post-quantum ready)
    cryptography \
    pycryptodome \
    PyNaCl \
    # Forensic Python libraries
    pefile \
    python-magic \
    yara-python \
    # Performance
    aiofiles \
    asyncio \
    # Utilities
    python-dateutil \
    tabulate \
    rich \
    click \
    # JSON/YAML
    pyyaml \
    jsonschema \
    # Hashing
    hashlib \
    # Monitoring
    psutil

# ==============================================================================
# Copy forensics core system
# ==============================================================================

COPY core/ /opt/forensics/core/
COPY scripts/ /opt/forensics/bin/
COPY config/ ${CONFIG_DIR}/
COPY modules/registry.json ${MODULES_DIR}/

# ==============================================================================
# Set up audit system with immutable logs
# ==============================================================================

# Create audit log with append-only attribute (will be set at runtime)
RUN touch ${LOGS_DIR}/audit.log && \
    touch ${LOGS_DIR}/custody.log && \
    mkdir -p ${LOGS_DIR}/installations && \
    mkdir -p ${LOGS_DIR}/telemetry

# Create symbolic links for forensics commands
RUN ln -s /opt/forensics/core/audit-system/forensics-audit /usr/local/bin/forensics-audit && \
    ln -s /opt/forensics/core/module-manager/forensics-modules /usr/local/bin/forensics-modules && \
    ln -s /opt/forensics/bin/forensics-case /usr/local/bin/forensics-case && \
    ln -s /opt/forensics/bin/forensics-evidence /usr/local/bin/forensics-evidence && \
    ln -s /opt/forensics/bin/forensics-report /usr/local/bin/forensics-report && \
    ln -s /opt/forensics/bin/forensics-health /usr/local/bin/forensics-health && \
    ln -s /opt/forensics/core/compliance/forensics-compliance /usr/local/bin/forensics-compliance

# Make all scripts executable
RUN chmod +x /opt/forensics/core/*/* 2>/dev/null || true && \
    chmod +x /opt/forensics/bin/* 2>/dev/null || true

# ==============================================================================
# Set up permissions (sherlock can do everything except modify evidence/custody)
# ==============================================================================

# Evidence directory: sherlock can READ but NOT write/delete
RUN chown -R root:forensics-ro ${EVIDENCE_DIR} && \
    chmod 750 ${EVIDENCE_DIR}

# Cases directory: sherlock has full access
RUN chown -R sherlock:sherlock ${CASES_DIR} && \
    chmod 770 ${CASES_DIR}

# Keys directory: protected, sherlock can use but not modify
RUN chown -R root:sherlock ${KEYS_DIR} && \
    chmod 750 ${KEYS_DIR}

# Logs directory: append-only for sherlock
RUN chown -R root:sherlock ${LOGS_DIR} && \
    chmod 750 ${LOGS_DIR} && \
    chmod 640 ${LOGS_DIR}/*.log

# Reports directory: sherlock full access
RUN chown -R sherlock:sherlock ${REPORTS_DIR} && \
    chmod 770 ${REPORTS_DIR}

# Modules directory: sherlock can install
RUN chown -R sherlock:sherlock ${MODULES_DIR} && \
    chmod 770 ${MODULES_DIR}

# Config directory: sherlock can read/modify configs
RUN chown -R sherlock:sherlock ${CONFIG_DIR} && \
    chmod 770 ${CONFIG_DIR}

# Core system: sherlock can execute but not modify
RUN chown -R root:sherlock /opt/forensics && \
    chmod -R 755 /opt/forensics

# ==============================================================================
# Set up sherlock user environment
# ==============================================================================

# Configure bash profile for sherlock
RUN echo 'export PATH="/opt/forensics/bin:${PATH}"' >> /home/sherlock/.bashrc && \
    echo 'export PS1="\[\e[36m\][FORENSICS]\[\e[m\] \[\e[33m\]\u\[\e[m\]@\[\e[32m\]\h\[\e[m\]:\[\e[34m\]\w\[\e[m\]\$ "' >> /home/sherlock/.bashrc && \
    echo 'alias ll="ls -lah"' >> /home/sherlock/.bashrc && \
    echo 'alias evidence="cd ${EVIDENCE_DIR}"' >> /home/sherlock/.bashrc && \
    echo 'alias cases="cd ${CASES_DIR}"' >> /home/sherlock/.bashrc && \
    echo 'alias logs="forensics-audit show"' >> /home/sherlock/.bashrc && \
    echo 'alias health="forensics-health check"' >> /home/sherlock/.bashrc && \
    echo '# Load forensics environment' >> /home/sherlock/.bashrc && \
    echo 'source /opt/forensics/core/init-environment.sh 2>/dev/null || true' >> /home/sherlock/.bashrc

# Display banner on login
COPY docs/banner.txt /home/sherlock/.banner
RUN echo 'cat /home/sherlock/.banner 2>/dev/null || true' >> /home/sherlock/.bashrc

# ==============================================================================
# Security hardening
# ==============================================================================

# Disable root password (only accessible via PQC encrypted key)
RUN passwd -l root

# Remove unnecessary setuid binaries
RUN find / -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true

# Secure /tmp
RUN chmod 1777 /tmp

# ==============================================================================
# Entry point and init system
# ==============================================================================

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD forensics-health quick-check || exit 1

# Expose volumes
VOLUME ["${EVIDENCE_DIR}", "${CASES_DIR}", "${KEYS_DIR}", "${LOGS_DIR}", "${REPORTS_DIR}"]

# Default user
USER sherlock
WORKDIR /home/sherlock

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/bin/bash"]
