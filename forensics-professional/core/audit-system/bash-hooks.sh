# shellcheck shell=bash
# ==============================================================================
# Forensics Professional — bash command-capture hooks
# ==============================================================================
# Sourced from /home/sherlock/.bashrc to capture every command the analyst
# runs into the cryptographic audit log. The hook offloads the actual write
# to a backgrounded Python process so the prompt stays responsive.
#
# Disabled automatically for root, for the chain-logger itself, and for
# the noise list maintained in forensics.chain.logger.
# ==============================================================================

# Idempotent
[[ -n "${FORENSICS_HOOKS_LOADED:-}" ]] && return 0
export FORENSICS_HOOKS_LOADED=1

# Don't capture root sessions.
if [[ "${EUID}" -eq 0 ]]; then
    return 0
fi

# Don't capture if the chain-logger Python module is unavailable.
if ! python3 -c 'import forensics.chain.logger' >/dev/null 2>&1; then
    return 0
fi

# ── Pre-exec — runs before each command ─────────────────────────────────────
__forensics_preexec() {
    case "${BASH_COMMAND}" in
        __forensics_preexec*|__forensics_precmd*|PROMPT_COMMAND*) return ;;
        '') return ;;
    esac
    local now tty_dev
    now="$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ 2>/dev/null \
           || date -u +%Y-%m-%dT%H:%M:%SZ)"
    tty_dev="$(tty 2>/dev/null || echo unknown)"
    export FORENSICS_LAST_CMD="${BASH_COMMAND}"
    export FORENSICS_START_TIME="${now}"
    export FORENSICS_PWD_AT_CMD="${PWD}"
    export FORENSICS_TTY_AT_CMD="${tty_dev}"
    export FORENSICS_SESSION_ID="$$"
}

# ── Post-exec — runs before each prompt is drawn ────────────────────────────
__forensics_precmd() {
    local exit_code=$?
    [[ -z "${FORENSICS_LAST_CMD:-}" ]] && return 0

    local end_time
    end_time="$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ 2>/dev/null \
                || date -u +%Y-%m-%dT%H:%M:%SZ)"

    (
        FORENSICS_CMD="${FORENSICS_LAST_CMD}" \
        FORENSICS_EXIT_CODE="${exit_code}" \
        FORENSICS_START_TIME="${FORENSICS_START_TIME}" \
        FORENSICS_END_TIME="${end_time}" \
        FORENSICS_PWD="${FORENSICS_PWD_AT_CMD}" \
        FORENSICS_TTY="${FORENSICS_TTY_AT_CMD}" \
        FORENSICS_SESSION="${FORENSICS_SESSION_ID}" \
        python3 -m forensics.chain.logger post >/dev/null 2>&1
    ) &
    disown $! 2>/dev/null || true

    unset FORENSICS_LAST_CMD FORENSICS_START_TIME \
          FORENSICS_PWD_AT_CMD FORENSICS_TTY_AT_CMD
    return "${exit_code}"
}

trap '__forensics_preexec' DEBUG
PROMPT_COMMAND="__forensics_precmd${PROMPT_COMMAND:+;${PROMPT_COMMAND}}"
