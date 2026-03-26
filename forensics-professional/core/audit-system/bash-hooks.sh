#!/bin/bash
# ==============================================================================
# Professional Forensics Container — Bash Hooks v2.1.0
# Captura automática de comandos para a cadeia de custódia
# Ativado via .bashrc do usuário sherlock
# ==============================================================================
#
# FUNCIONAMENTO:
#   1. forensics_preexec() — chamado ANTES de cada comando (via trap DEBUG)
#      - Captura o comando, cwd, tty, timestamp de início
#   2. forensics_precmd()  — chamado DEPOIS de cada comando (via PROMPT_COMMAND)
#      - Captura exit code, timestamp de fim
#      - Envia dados para o chain-of-custody logger
#
# NOTA: Não captura se usuário for root (evita loop nos logs de auditoria)
# ==============================================================================

# Não ativar se já estiver ativo
if [[ -n "$FORENSICS_HOOKS_LOADED" ]]; then
    return 0
fi
export FORENSICS_HOOKS_LOADED=1

# Não ativar para root (evita loop ao modificar logs)
if [[ "$EUID" -eq 0 ]] || [[ "$USER" == "root" ]]; then
    return 0
fi

# Diretório dos logs de chain of custody
CHAIN_COC_DIR="/var/log/forensics/chain-of-custody"
LOGGER_SCRIPT="/opt/forensics/chain-logger/logger.py"

# ==============================================================================
# Hook ANTES de cada comando
# ==============================================================================
function forensics_preexec() {
    # Ignorar comandos internos do próprio logger
    case "$BASH_COMMAND" in
        forensics_precmd*|forensics_preexec*|PROMPT_COMMAND*|"trap "*) return ;;
        "") return ;;
    esac

    export FORENSICS_LAST_CMD="$BASH_COMMAND"
    export FORENSICS_START_TIME="$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ 2>/dev/null)"
    export FORENSICS_START_UNIX="$(date +%s%N 2>/dev/null)"
    export FORENSICS_PWD_AT_CMD="$PWD"
    export FORENSICS_TTY_AT_CMD="$(tty 2>/dev/null)"
    export FORENSICS_SESSION_ID="$$"
}

# ==============================================================================
# Hook DEPOIS de cada comando
# ==============================================================================
function forensics_precmd() {
    local exit_code=$?

    # Não processar se não houve comando capturado
    [[ -z "$FORENSICS_LAST_CMD" ]] && return 0

    # Capturar tempo de fim
    local end_time end_unix
    end_time="$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ 2>/dev/null)"
    end_unix="$(date +%s%N 2>/dev/null)"

    # Passar para o logger Python (assíncrono para não bloquear o shell)
    if [[ -x "$LOGGER_SCRIPT" ]]; then
        (
            FORENSICS_CMD="$FORENSICS_LAST_CMD"         \
            FORENSICS_EXIT_CODE="$exit_code"             \
            FORENSICS_START_TIME="$FORENSICS_START_TIME" \
            FORENSICS_END_TIME="$end_time"               \
            FORENSICS_START_UNIX="$FORENSICS_START_UNIX" \
            FORENSICS_END_UNIX="$end_unix"               \
            FORENSICS_PWD="$FORENSICS_PWD_AT_CMD"        \
            FORENSICS_TTY="$FORENSICS_TTY_AT_CMD"        \
            FORENSICS_SESSION="$FORENSICS_SESSION_ID"    \
            python3 "$LOGGER_SCRIPT" post 2>/dev/null
        ) &
        disown $! 2>/dev/null
    fi

    # Limpar variáveis
    unset FORENSICS_LAST_CMD FORENSICS_START_TIME FORENSICS_START_UNIX
    unset FORENSICS_PWD_AT_CMD FORENSICS_TTY_AT_CMD

    return $exit_code
}

# ==============================================================================
# Ativar hooks no shell atual
# ==============================================================================
trap 'forensics_preexec' DEBUG
PROMPT_COMMAND="forensics_precmd${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
