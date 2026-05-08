# syntax=docker/dockerfile:1.7
# ==============================================================================
# Professional Forensics Container — Dockerfile
# ==============================================================================
# Build:  docker buildx build --tag forensics-professional:3.0.0 .
# Run:    docker compose up -d
# ==============================================================================
#
# Design notes
# ------------
# • Multi-stage: builder compiles liboqs (post-quantum), runtime stays slim.
# • Honest privilege model: sherlock runs everything; sudo restricted to
#   apt-get/pip via /etc/sudoers.d/sherlock-forensics (no shell escalation).
# • gosu is installed and verified — the entrypoint relies on it.
# • USER sherlock is the default; root is disabled (passwd -l).
# • HEALTHCHECK exposes liveness to docker/compose orchestration.
# • All Python deps are pinned in requirements.txt.
#
# IMPORTANT — apt-get install
# ---------------------------
# Do NOT add bash-style `# comments` *inside* the multi-line `apt-get install`
# continuation. /bin/sh treats the `#` as start-of-comment which truncates the
# entire logical line, leaving apt-get with zero packages and turning the next
# physical line into a stand-alone command (e.g. `tini` -> "tini: not found").
# This was the original v3.0.0 build failure. Group packages with blank-line
# breaks instead, or leave a comment ABOVE the RUN block.
# ==============================================================================

ARG UBUNTU_VERSION=22.04
ARG GOSU_VERSION=1.17

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 1 — Post-Quantum Cryptography builder (liboqs)
# ──────────────────────────────────────────────────────────────────────────────
FROM ubuntu:${UBUNTU_VERSION} AS pqc-builder

LABEL stage="pqc-builder"

ARG LIBOQS_REF=0.11.0

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        libssl-dev \
        ninja-build \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/build

# Pin liboqs to a known-good release tag.
RUN git clone --depth 1 --branch "${LIBOQS_REF}" \
        https://github.com/open-quantum-safe/liboqs.git

WORKDIR /opt/build/liboqs/build

RUN cmake -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DOQS_USE_OPENSSL=ON \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        .. \
 && ninja -j"$(nproc)" \
 && ninja install


# ──────────────────────────────────────────────────────────────────────────────
# STAGE 2 — Runtime image
# ──────────────────────────────────────────────────────────────────────────────
FROM ubuntu:${UBUNTU_VERSION}

ARG GOSU_VERSION
ARG VERSION=3.0.0

LABEL org.opencontainers.image.title="forensics-professional" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.description="Digital forensics workstation with auditable evidence handling" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/joao-henrike/Containers" \
      org.opencontainers.image.authors="joao-henrike" \
      forensics.compliance="NIST-SP-800-86" \
      forensics.crypto="Ed25519 + GPG; optional ML-DSA-65"

# ──────────────────────────────────────────────────────────────────────────────
# 1. Base packages
# ──────────────────────────────────────────────────────────────────────────────
# Package groups (kept here for review only — DO NOT inline as # comments):
#
#   init/privilege:  tini, sudo, ca-certificates
#   shell utils:     bash-completion, less, nano, tmux, vim-tiny
#   vcs+net:         curl, git, openssh-client, wget
#   data tools:      jq, parallel
#   sys monitor:     htop, iotop, nethogs, procps, rsync, sysstat, tree
#   python:          python3, python3-pip, python3-venv, python-is-python3
#   crypto:          gnupg, openssl
#   bin analysis:    binutils, file, ltrace, strace
#   compression:     bzip2, gzip, p7zip-full, unzip, xz-utils
#   network basic:   dnsutils, iproute2, iputils-ping, net-tools
#   apt helpers:     gpg-agent, software-properties-common
#   filesystem:      attr
#   java:            default-jre-headless
#   sqlite (mobile): sqlite3
#   misc:            cron
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        attr \
        bash-completion \
        binutils \
        bzip2 \
        ca-certificates \
        cron \
        curl \
        default-jre-headless \
        dnsutils \
        file \
        git \
        gnupg \
        gpg-agent \
        gzip \
        htop \
        iproute2 \
        iotop \
        iputils-ping \
        jq \
        less \
        ltrace \
        nano \
        net-tools \
        nethogs \
        openssh-client \
        openssl \
        p7zip-full \
        parallel \
        procps \
        python-is-python3 \
        python3 \
        python3-pip \
        python3-venv \
        rsync \
        software-properties-common \
        sqlite3 \
        strace \
        sudo \
        sysstat \
        tini \
        tmux \
        tree \
        unzip \
        vim-tiny \
        wget \
        xz-utils \
 && rm -rf /var/lib/apt/lists/*

# ──────────────────────────────────────────────────────────────────────────────
# 2. gosu — verified install (https://github.com/tianon/gosu)
# ──────────────────────────────────────────────────────────────────────────────
RUN set -eux; \
    arch="$(dpkg --print-architecture | awk -F- '{print $NF}')"; \
    curl -fsSL -o /usr/local/bin/gosu \
        "https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${arch}"; \
    curl -fsSL -o /tmp/gosu.asc \
        "https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${arch}.asc"; \
    GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; \
    gpg --batch --keyserver hkps://keys.openpgp.org \
        --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4 \
     || gpg --batch --keyserver hkps://keyserver.ubuntu.com \
        --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4; \
    gpg --batch --verify /tmp/gosu.asc /usr/local/bin/gosu; \
    rm -rf "$GNUPGHOME" /tmp/gosu.asc; \
    chmod +x /usr/local/bin/gosu; \
    gosu --version; \
    gosu nobody true

# ──────────────────────────────────────────────────────────────────────────────
# 3. Liboqs from builder stage
# ──────────────────────────────────────────────────────────────────────────────
COPY --from=pqc-builder /usr/local/lib/liboqs.so*    /usr/local/lib/
COPY --from=pqc-builder /usr/local/include/oqs       /usr/local/include/oqs/
RUN ldconfig

# ──────────────────────────────────────────────────────────────────────────────
# 4. Python dependencies
# ──────────────────────────────────────────────────────────────────────────────
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages \
        --upgrade pip setuptools wheel \
 && pip3 install --no-cache-dir --break-system-packages \
        -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

# ──────────────────────────────────────────────────────────────────────────────
# 5. Users & groups
# ──────────────────────────────────────────────────────────────────────────────
# • sherlock (uid 1000)        — analyst account, runs everything
# • forensics-ro (gid 1001)    — read-only group for evidence access
# • Root password disabled. Sherlock has no password (set via `passwd -d`),
#   sudoers rules below explicitly restrict what it may run with privilege.
RUN groupadd -r -g 1000 sherlock \
 && useradd  -r -g sherlock -u 1000 -m -s /bin/bash sherlock \
 && passwd   -d sherlock \
 && groupadd -r -g 1001 forensics-ro \
 && usermod  -aG forensics-ro sherlock \
 && passwd   -l root

# Sudoers rule — explicit commands only, no shell escalation.
# Note: sudoers fragment lives in config/sudoers/sherlock (NOT inside config/
# top-level, to avoid collision with the runtime /etc/forensics bind mount).
COPY config/sudoers/sherlock /etc/sudoers.d/sherlock-forensics
RUN chmod 0440 /etc/sudoers.d/sherlock-forensics \
 && visudo -cf /etc/sudoers.d/sherlock-forensics

# ──────────────────────────────────────────────────────────────────────────────
# 6. Filesystem layout
# ──────────────────────────────────────────────────────────────────────────────
RUN mkdir -p \
        /evidence \
        /cases \
        /keys \
        /reports \
        /etc/forensics \
        /var/log/forensics \
        /var/log/forensics/installations \
        /var/log/forensics/chain-of-custody \
        /var/log/forensics/telemetry \
        /var/log/forensics/auth \
        /opt/forensics/bin \
        /opt/forensics/core \
        /opt/forensics/tools \
        /opt/forensics/modules/installed \
        /opt/forensics/modules/manifests \
        /opt/forensics/quantum-keys \
        /opt/forensics/chain-logger \
 && chown -R sherlock:sherlock \
        /cases \
        /reports \
        /var/log/forensics \
        /opt/forensics \
 && chmod 0750 /opt/forensics/quantum-keys

# ──────────────────────────────────────────────────────────────────────────────
# 7. Application files
# ──────────────────────────────────────────────────────────────────────────────
COPY --chown=sherlock:sherlock core/                /opt/forensics/core/
COPY --chown=sherlock:sherlock scripts/             /opt/forensics/bin/
COPY --chown=sherlock:sherlock modules/registry.json /opt/forensics/modules/registry.json
COPY --chown=sherlock:sherlock config/config.yaml   /etc/forensics/config.yaml
COPY --chown=sherlock:sherlock docs/banner.txt      /etc/motd
COPY --chown=sherlock:sherlock VERSION              /opt/forensics/VERSION
COPY docker-entrypoint.sh                           /usr/local/bin/docker-entrypoint.sh

# Permissions & PATH-friendly symlinks
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
 && find /opt/forensics/bin  -type f -exec chmod +x {} + \
 && find /opt/forensics/core -name "*.sh" -exec chmod +x {} + \
 && find /opt/forensics/core -name "forensics-*" -exec chmod +x {} + \
 && ln -sf /opt/forensics/core/module-manager/forensics-modules /usr/local/bin/forensics-modules \
 && ln -sf /opt/forensics/core/audit-system/forensics-audit     /usr/local/bin/forensics-audit \
 && ln -sf /opt/forensics/bin/forensics-health                  /usr/local/bin/forensics-health \
 && ln -sf /opt/forensics/core/audit-system/quantum-root        /usr/local/bin/quantum-root \
 && ln -sf /opt/forensics/core/audit-system/quantum-root        /usr/local/bin/qroot

# ──────────────────────────────────────────────────────────────────────────────
# 8. Environment
# ──────────────────────────────────────────────────────────────────────────────
ENV FORENSICS_HOME="/opt/forensics" \
    FORENSICS_LOGS="/var/log/forensics" \
    FORENSICS_MODULES="/opt/forensics/modules" \
    FORENSICS_KEYS="/opt/forensics/quantum-keys" \
    FORENSICS_CONFIG="/etc/forensics" \
    PYTHONPATH="/opt/forensics/core" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/forensics/bin:/opt/forensics/core/module-manager:/opt/forensics/core/audit-system:/usr/local/bin:${PATH}" \
    TZ=UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# ──────────────────────────────────────────────────────────────────────────────
# 9. Healthcheck
# ──────────────────────────────────────────────────────────────────────────────
HEALTHCHECK --interval=60s --timeout=10s --start-period=20s --retries=3 \
    CMD forensics-health quick-check --silent || exit 1

# ──────────────────────────────────────────────────────────────────────────────
# 10. Entrypoint
# ──────────────────────────────────────────────────────────────────────────────
# tini is PID 1 → forwards signals & reaps zombies.
# docker-entrypoint.sh runs as root (privileged init), then drops to sherlock.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["bash"]
