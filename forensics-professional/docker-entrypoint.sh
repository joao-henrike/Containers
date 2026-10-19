#!/usr/bin/env bash
# ==============================================================================
# Forensics Professional — Container Entrypoint
# ==============================================================================
# Default mode runs as sherlock and bootstraps only user-owned paths.
# Explicit root override retains legacy directory ownership setup, then drops
# privileges to sherlock via gosu before executing the requested command.
#
# This script is invoked by tini (PID 1). Signals are forwarded properly.
# ==============================================================================

set -euo pipefail

# ── Constants ────────────────────────────────────────────────────────────────
readonly FORENSICS_HOME="${FORENSICS_HOME:-/opt/forensics}"
readonly LOGS_DIR="${FORENSICS_LOGS:-/var/log/forensics}"
readonly KEYS_DIR="${FORENSICS_KEYS:-/opt/forensics/quantum-keys}"
readonly AUDIT_LOG="${LOGS_DIR}/audit.log"
readonly VERSION_FILE="${FORENSICS_HOME}/VERSION"
readonly RUN_USER="sherlock"

# Colours (only when stdout is a TTY)
if [[ -t 1 ]]; then
    readonly C_RED=$'\033[0;31m'
    readonly C_GRN=$'\033[0;32m'
    readonly C_YLW=$'\033[1;33m'
    readonly C_CYN=$'\033[0;36m'
    readonly C_NC=$'\033[0m'
else
    readonly C_RED='' C_GRN='' C_YLW='' C_CYN='' C_NC=''
fi

# ── Logging ──────────────────────────────────────────────────────────────────
log()  { printf '%s[init]%s %s\n' "${C_CYN}" "${C_NC}" "$*"; }
ok()   { printf '%s[ ok ]%s %s\n' "${C_GRN}" "${C_NC}" "$*"; }
warn() { printf '%s[warn]%s %s\n' "${C_YLW}" "${C_NC}" "$*" >&2; }
die()  { printf '%s[fail]%s %s\n' "${C_RED}" "${C_NC}" "$*" >&2; exit 1; }

VERSION="$(cat "${VERSION_FILE}" 2>/dev/null || echo 'unknown')"

# ── Startup mode ────────────────────────────────────────────────────────────
# Images run as sherlock by default. Keep root-init support for explicit
# operator overrides, but never rely on it for a normal startup.
if [[ "${EUID}" -eq 0 ]]; then
    readonly ROOT_MODE=1
    log "Forensics Professional v${VERSION} — privileged bootstrap"
else
    readonly ROOT_MODE=0
    log "Forensics Professional v${VERSION} — unprivileged startup as $(id -un)"
fi

run_as_user() {
    if [[ "${ROOT_MODE}" -eq 1 ]]; then
        gosu "${RUN_USER}" "$@"
    else
        "$@"
    fi
}

# ── 1. Filesystem layout for mounted volumes ────────────────────────────────
mkdir -p \
    "${LOGS_DIR}/installations" \
    "${LOGS_DIR}/chain-of-custody/$(date -u +%Y/%m/%d)" \
    "${LOGS_DIR}/telemetry" \
    "${LOGS_DIR}/auth" \
    "${KEYS_DIR}"

if [[ "${ROOT_MODE}" -eq 1 ]]; then
    chown -R "${RUN_USER}:${RUN_USER}" "${LOGS_DIR}" "${KEYS_DIR}" /cases /reports
else
    for writable_dir in "${LOGS_DIR}" "${KEYS_DIR}" /cases /reports; do
        [[ -w "${writable_dir}" ]] || die "${writable_dir} is not writable by UID $(id -u). Prepare the host bind-mount directory for HOST_UID before starting the container."
    done
fi
chmod 0750 "${KEYS_DIR}" || die "cannot secure key directory permissions"

# Evidence is read-only by mount; avoid mutating permissions from an
# unprivileged entrypoint. Docker enforces the read-only mount itself.
if [[ "${ROOT_MODE}" -eq 1 ]]; then
    chmod 0555 /evidence 2>/dev/null || true
fi

# ── 2. Audit log bootstrap ───────────────────────────────────────────────────
init_audit_log() {
    if [[ ! -f "${AUDIT_LOG}" ]]; then
        : > "${AUDIT_LOG}"
        if [[ "${ROOT_MODE}" -eq 1 ]]; then
            chown "${RUN_USER}:${RUN_USER}" "${AUDIT_LOG}"
        fi
        chmod 0640 "${AUDIT_LOG}"
    fi

    # Genesis entry only if the log is empty.
    if [[ ! -s "${AUDIT_LOG}" ]]; then
        run_as_user python3 -m forensics.audit.bootstrap genesis \
            --version "${VERSION}" \
            || warn "genesis entry skipped (audit module unavailable)"
    fi

    # Append-only attribute. Best-effort: not all host filesystems support it.
    if [[ "${ROOT_MODE}" -eq 1 ]]; then
        if chattr +a "${AUDIT_LOG}" 2>/dev/null; then
            ok "audit log marked append-only (chattr +a)"
        else
            warn "chattr +a not supported on this filesystem — host must enforce immutability"
        fi
    elif sudo -n /usr/local/sbin/forensics-privileged audit-append-only 2>/dev/null; then
        ok "audit log marked append-only (restricted helper)"
    else
        warn "append-only attribute unavailable — host must enforce immutability"
    fi
}
init_audit_log

# ── 3. Cryptographic key bootstrap ───────────────────────────────────────────
init_ed25519() {
    if [[ -f "${KEYS_DIR}/audit_ed25519.key" ]]; then
        return 0
    fi
    log "generating Ed25519 audit-signing keypair"
    run_as_user python3 -m forensics.audit.keygen ed25519 \
        --out-dir "${KEYS_DIR}" \
        || die "failed to generate Ed25519 keypair"
    ok "Ed25519 keypair generated"
}

init_gpg() {
    # GPG key, protected by a randomly-generated passphrase stored in keys/.
    local pass_file="${KEYS_DIR}/.gpg.passphrase"
    local keyring_dir="/home/${RUN_USER}/.gnupg"

    mkdir -p "${keyring_dir}"
    if [[ "${ROOT_MODE}" -eq 1 ]]; then
        chown "${RUN_USER}:${RUN_USER}" "${keyring_dir}"
    elif [[ ! -w "${keyring_dir}" ]]; then
        die "${keyring_dir} is not writable; check the home directory ownership"
    fi
    chmod 0700 "${keyring_dir}"

    if run_as_user gpg --list-keys forensics-audit@professional.local \
            >/dev/null 2>&1; then
        return 0
    fi

    if [[ ! -f "${pass_file}" ]]; then
        # 32 random bytes, base64 — strong enough for the local keyring.
        ( umask 077 && openssl rand -base64 32 > "${pass_file}" )
        if [[ "${ROOT_MODE}" -eq 1 ]]; then
            chown "${RUN_USER}:${RUN_USER}" "${pass_file}"
        fi
        chmod 0400 "${pass_file}"
    fi

    log "generating GPG signing key (RSA-4096)"
    local passphrase
    passphrase="$(cat "${pass_file}")"
    run_as_user bash -c "cat <<-EOF | gpg --batch --gen-key
%echo Generating audit signing key
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: Forensics Audit
Name-Email: forensics-audit@professional.local
Expire-Date: 0
Passphrase: ${passphrase}
%commit
%echo done
EOF" >/dev/null 2>&1 || warn "GPG key generation failed (legal-signature column will say 'unavailable')"
}

init_ed25519 || true
init_gpg || true

# ── 4. Sherlock shell environment ────────────────────────────────────────────
write_bashrc() {
    local rc="/home/${RUN_USER}/.bashrc"
    cat > "${rc}" <<'BASHRC'
# Forensics Professional — analyst shell
# Auto-generated; edit /etc/forensics/bashrc.d/*.sh for permanent changes.

[[ -f /etc/bashrc ]] && . /etc/bashrc

export FORENSICS_HOME=/opt/forensics
export FORENSICS_LOGS=/var/log/forensics
export FORENSICS_MODULES=/opt/forensics/modules
export FORENSICS_KEYS=/opt/forensics/quantum-keys
export FORENSICS_CONFIG=/etc/forensics
export PATH="/opt/forensics/venv/bin:/opt/forensics/bin:/opt/forensics/core/module-manager:/opt/forensics/core/audit-system:/usr/local/bin:${PATH}"
export PYTHONPATH="/opt/forensics/core:/opt/forensics/core/audit-system:/opt/forensics/core/module-manager"
export TZ=UTC

PS1='\[\033[01;36m\][forensics]\[\033[00m\] \[\033[01;32m\]\u\[\033[00m\]@\[\033[01;34m\]\h\[\033[00m\]:\[\033[01;33m\]\w\[\033[00m\]\$ '

alias ll='ls -la'
alias audit='forensics-audit'
alias modules='forensics-modules'
alias health='forensics-health'

# Chain-of-custody hooks
[[ -f /opt/forensics/core/audit-system/bash-hooks.sh ]] && \
    source /opt/forensics/core/audit-system/bash-hooks.sh

# Per-deployment hooks
if [[ -d /etc/forensics/bashrc.d ]]; then
    for f in /etc/forensics/bashrc.d/*.sh; do
        [[ -r "$f" ]] && source "$f"
    done
    unset f
fi

# Banner (once per session)
if [[ -z "${FORENSICS_BANNER_SHOWN:-}" ]]; then
    export FORENSICS_BANNER_SHOWN=1
    [[ -f /etc/motd ]] && cat /etc/motd
fi
BASHRC
    if [[ "${ROOT_MODE}" -eq 1 ]]; then
        chown "${RUN_USER}:${RUN_USER}" "${rc}"
    fi
}
write_bashrc

# ── 5. Log container start as an audit event ─────────────────────────────────
run_as_user python3 -m forensics.audit.bootstrap log-start \
    --version "${VERSION}" \
    >/dev/null 2>&1 || warn "could not append container_started audit event"

ok "initialisation complete — switching to ${RUN_USER}"

# ── 6. Drop privileges and exec user CMD ─────────────────────────────────────
# If no command supplied, default to interactive bash.
if [[ $# -eq 0 ]]; then
    if [[ "${ROOT_MODE}" -eq 1 ]]; then
        exec gosu "${RUN_USER}" bash
    fi
    exec bash
fi

if [[ "${ROOT_MODE}" -eq 1 ]]; then
    exec gosu "${RUN_USER}" "$@"
fi
exec "$@"
