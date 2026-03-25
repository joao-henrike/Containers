# Changelog

Todas as mudanças significativas neste projeto são documentadas aqui.

O formato segue [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
e este projeto segue [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0-FINAL] - 2026-03-25

### 🔧 Correções Críticas (Dockerfile)

- **FIX:** `openssl rand -base64 32` substituído por `echo "sherlock:forensics" | chpasswd`
  - Causa: erro de subshell (exit code 1) ao criar a senha do usuário durante o build
- **FIX:** Pacote `yq` removido da lista do `apt-get`
  - Causa: não possui `installation candidate` no Ubuntu 22.04 padrão (exit code 100)
- **FIX:** Pacote `hashlib` removido do `pip3 install`
  - Causa: módulo nativo do Python, causava `legacy-install-failure` no pip
- **FIX:** Pacote `requests` adicionado ao `pip3 install`
  - Causa: sua ausência causava `ModuleNotFoundError: No module named 'requests'` ao invocar o `forensics-modules`
- **FIX:** Diretório `/var/log/forensics/telemetry` criado explicitamente no Dockerfile
  - Causa: `PermissionError` no Flight Recorder ao tentar gravar métricas de telemetria
- **FIX:** `chown -R sherlock:sherlock /cases` adicionado ao build
  - Causa: analista não conseguia escrever em `/cases` sem escalar privilégio
- **FEAT:** `software-properties-common` adicionado às dependências APT
  - Motivo: necessário para `add-apt-repository` nos módulos `windows-forensics` e `linux-forensics` (instalação do Plaso via PPA)
- **FEAT:** `attr` adicionado às dependências APT (suporte ao `chattr +a` para logs)

### 🔧 Correções Críticas (docker-compose.yml)

- **FIX:** Tag `version:` removida do topo do arquivo
  - Causa: aviso `the attribute version is obsolete, it will be ignored` no Docker Compose V2
- **FIX:** Bloco `deploy > resources` com `cpus: '8'` e `memory: 16G` removido
  - Causa: erro fatal em hosts com menos de 8 núcleos ou 16 GB RAM disponíveis
  - Solução: recursos agora são dinâmicos — o container usa tudo o que o host oferece
- **FIX:** Volume de chaves corrigido de `./keys:/keys` para `./keys:/opt/forensics/quantum-keys`
  - Causa: o script de autenticação PQC (ML-DSA-65) busca as chaves neste caminho exato
- **FEAT:** `restart: unless-stopped` adicionado para resiliência do container
- **FEAT:** Labels de metadados adicionadas (versão, compliance, crypto, usuário)

### 🔧 Correções (README.md)

- **FIX:** Todos os links `YOUR-USERNAME` substituídos por `joao-henrike`
- **FIX:** Comandos `docker-compose` atualizados para `docker compose` (V2)
- **FIX:** Tabela de módulos atualizada com tamanhos reais calculados
- **FEAT:** Seção de OSINT adicionada (3 novos módulos: osint-tools, threat-intelligence, web-recon)
- **FEAT:** Seção de performance documentada (sem limites estáticos)
- **FEAT:** Arquitetura expandida com novos arquivos criados durante validação

### ➕ Novos Arquivos

- `scripts/validation-scripts/FBI_VALIDATION_CLEAN.sh`
- `scripts/validation-scripts/ULTIMATE_VALIDATION_FIXED.sh`
- `scripts/install-modules.sh`
- `docs/CRIPTOGRAFIA_QUANTICA_EXPLICACAO.md`
- `docs/CADEIA_CUSTODIA_EXPLICACAO.md`
- `core/audit-system/quantum_verify.c`
- `core/audit-system/root-monitor.py`
- `core/audit-system/crypto_signer.py`
- `core/audit-system/bash-hooks.sh`
- `core/audit-system/quantum-root`

---

## [2.0.0] - 2026-02-07

### 🎉 Lançamento Inicial

- Container Docker profissional para forense digital (Linux)
- Criptografia pós-quântica para root (Kyber/Dilithium via liboqs)
- Sistema de auditoria imutável (Ed25519 + GPG, cadeia blockchain-like)
- Chain of custody automatizada
- Arquitetura modular: 11 módulos forenses iniciais
- Gerenciador `forensics-modules` com sub-módulos
- Registry central em JSON (`modules/registry.json`)
- Sistema de resolução de conflitos de dependências
- Retry automático com backoff em falhas de rede
- Paralelismo agressivo (todos os cores do host)
- Flight Recorder: telemetria, time-travel debugging, health monitoring
- Compliance NIST SP 800-86
- Assinatura digital de relatórios (Ed25519 + GPG)
- Timestamps certificados (UTC, RFC 3339)
- Usuário `sherlock` com permissões controladas (não pode deletar evidências)
- Evidências protegidas (read-only por design)
- GitHub Actions (CI/CD automático)
- Documentação completa: README, QUICKSTART, INSTALL, ARCHITECTURE, CONTRIBUTING, SECURITY, LICENSE, CODE_OF_CONDUCT
