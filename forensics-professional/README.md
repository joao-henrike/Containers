# Professional Forensics Container v2.1.0

[![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)](https://github.com/joao-henrike/Containers/tree/main/forensics-professional)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/joao-henrike/Containers/blob/main/forensics-professional/LICENSE)
[![Compliance](https://img.shields.io/badge/compliance-NIST%20SP%20800--86-orange.svg)](https://github.com/joao-henrike/Containers/blob/main/forensics-professional)
[![Crypto](https://img.shields.io/badge/crypto-Post--Quantum-purple.svg)](https://github.com/joao-henrike/Containers/blob/main/forensics-professional)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://github.com/joao-henrike/Containers/blob/main/forensics-professional)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/joao-henrike/Containers/blob/main/forensics-professional/CONTRIBUTING.md)
[![Modules](https://img.shields.io/badge/modules-14-blue.svg)](https://github.com/joao-henrike/Containers/blob/main/forensics-professional)
[![Tools](https://img.shields.io/badge/tools-161%2B-green.svg)](https://github.com/joao-henrike/Containers/blob/main/forensics-professional)

> 🔍 Container Docker profissional para forense digital com criptografia pós-quântica, audit trails imutáveis, instalação modular de ferramentas e capacidades completas de OSINT.

---

## 📚 Índice

- [Visão Geral](#-visão-geral)
- [Funcionalidades Principais](#-funcionalidades-principais)
- [Quick Start](#-quick-start)
- [Instalação](#-instalação)
- [Uso](#-uso)
- [Módulos Disponíveis](#-módulos-disponíveis)
- [Documentação](#-documentação)
- [Contribuindo](#-contribuindo)
- [Licença](#-licença)
- [Suporte](#-suporte)

---

## 🎯 Visão Geral

Um **container Docker de nível profissional** para forense digital com:

- 🔐 **Criptografia Pós-Quântica** (Kyber/ML-DSA-65) para proteção do root
- 📝 **Audit Trails Imutáveis** (assinaturas híbridas Ed25519 + GPG)
- 🔗 **Chain of Custody Automatizada** — cada ação é registrada e assinada
- 🧩 **Instalação Modular** — instale só o que você precisa
- ⚡ **Paralelismo Agressivo** — máxima performance com todos os cores disponíveis
- 📊 **Compliance NIST SP 800-86** — pronto para uso profissional e legal
- 🛡️ **Evidências Protegidas** — read-only, impossível deletar por design
- 🔍 **OSINT & Threat Intelligence** — 14 módulos no total

---

## 🚀 Funcionalidades Principais

### Arquitetura de Segurança

```
ROOT (somente o proprietário — PQC criptografado)
└── Protegido por criptografia pós-quântica Kyber/ML-DSA-65
    └── Acessível apenas com a chave privada do proprietário

SHERLOCK (usuário público)
├── ✅ Instalar módulos
├── ✅ Analisar evidências
├── ✅ Gerar relatórios
├── ✅ Configurar o sistema
├── ❌ Deletar/modificar evidências
├── ❌ Alterar audit logs / chain of custody
└── ❌ Escalar para root
```

### Sistema de Auditoria Imutável

Cada ação é registrada com:

- **Timestamp** (RFC 3339, UTC)
- **Usuário** que executou a ação
- **Tipo de evento** e detalhes
- **Hash anterior** (cadeia blockchain-like)
- **Hash atual** (SHA-256)
- **Assinaturas duplas** (Ed25519 + GPG)

Resultado: **audit trail verificável e à prova de adulteração**.

### Arquitetura Modular

Instale apenas as ferramentas que você precisa:

```bash
# Listar módulos disponíveis
forensics-modules list

# Instalar módulo completo
forensics-modules install memory-forensics

# Instalar sub-módulos específicos
forensics-modules install cloud-forensics --only aws-tools,gcp-tools

# Seleção interativa
forensics-modules install malware-analysis --interactive
```

---

## 🧩 Módulos Disponíveis

O container usa arquitetura modular — instale só o que precisa!

| Módulo | Categoria | Ferramentas | Tamanho | Descrição |
|--------|-----------|-------------|---------|-----------|
| **cloud-forensics** | Cloud | 15 | 900 MB | AWS, Azure, GCP — investigação de ambientes cloud |
| **memory-forensics** | Memória | 8 | 755 MB | Volatility 2/3, Rekall, LiME, AVML |
| **disk-forensics** | Disco | 12 | 1.0 GB | Sleuthkit, Autopsy, TestDisk, Foremost, Scalpel |
| **network-forensics** | Rede | 10 | 740 MB | Wireshark, Zeek, tcpdump, ngrep |
| **mobile-forensics** | Mobile | 8 | 580 MB | ADB, libimobiledevice, JADX, Frida |
| **malware-analysis** | Malware | 15 | 2.0 GB | YARA, radare2, Ghidra, Cuckoo Sandbox |
| **windows-forensics** | Windows | 10 | 590 MB | RegRipper, Plaso, evtx-parser, prefetch-parser |
| **linux-forensics** | Linux | 8 | 315 MB | auditd, log-parsers, ext4-tools |
| **container-forensics** | Container | 6 | 430 MB | Docker/Kubernetes investigation, dive, kubeshark |
| **database-forensics** | Banco de Dados | 9 | 650 MB | MySQL, PostgreSQL, MongoDB forensics |
| **email-forensics** | Email | 7 | 260 MB | PST/EML parsing, header analysis |
| **osint-tools** 🆕 | OSINT | 25 | 450 MB | Sherlock, Holehe, theHarvester, Amass |
| **threat-intelligence** 🆕 | Inteligência | 15 | 320 MB | MISP, IOC feeds, threat hunting |
| **web-recon** 🆕 | Recon | 18 | 280 MB | Subdomain enum, web scraping, DNS |

**Total:** 14 módulos • 161+ ferramentas • ~9.3 GB (todos os módulos instalados)

> ✅ **Todas as ferramentas são funcionais** — instalação real, não simulada!

---

## 📦 Quick Start

### Pré-requisitos

- Docker 20.10+
- Docker Compose V2 (plugin integrado ao Docker)
- 8 GB RAM mínimo (16 GB recomendado)
- 50 GB de espaço livre em disco

### Instalação

#### Passo 1: Clonar o repositório

```bash
git clone https://github.com/joao-henrike/Containers.git
cd Containers/forensics-professional
```

#### Passo 2: Garantir permissões corretas

```bash
chmod 750 evidence cases keys logs reports modules config
```

#### Passo 3: Build do container

```bash
# O build leva ~10-15 minutos na primeira vez
docker compose build
```

#### Passo 4: Iniciar o container

```bash
docker compose up -d

# Verificar se está rodando
docker ps
```

#### Passo 5: Acessar o shell forense

```bash
docker exec -it forensics-workstation bash
# O banner profissional será exibido!
```

#### One-liner (instalação rápida)

```bash
git clone https://github.com/joao-henrike/Containers.git && \
cd Containers/forensics-professional && \
docker compose build && \
docker compose up -d && \
docker exec -it forensics-workstation bash
```

### Primeiros Passos (dentro do container)

```bash
# 1. Verificar saúde do sistema
forensics-health check

# 2. Verificar integridade do audit log
forensics-audit verify

# 3. Listar módulos disponíveis
forensics-modules list

# 4. Instalar as ferramentas necessárias
forensics-modules install disk-forensics

# 5. Começar a trabalhar
cd /cases
```

### Investigação OSINT 🆕

```bash
# Instalar módulo OSINT
forensics-modules install osint-tools

# Busca de perfis em redes sociais
sherlock <target_username>

# Verificação de email
holehe suspect@email.com

# Reconhecimento de domínio
theHarvester -d target-company.com -b all
amass enum -d target-company.com

# OSINT de número de telefone
phoneinfoga scan -n +5511999999999
```

---

## 🔧 Uso

### Gerenciamento de Módulos

```bash
forensics-modules list                                          # Lista módulos
forensics-modules info memory-forensics                        # Detalhes de um módulo
forensics-modules install memory-forensics                     # Instala completo
forensics-modules install cloud-forensics --only aws-tools     # Sub-módulo específico
forensics-modules install malware-analysis --interactive       # Seleção interativa
forensics-modules status                                        # O que está instalado
forensics-modules remove network-forensics                     # Remove módulo
```

### Sistema de Auditoria

```bash
forensics-audit verify                                   # Verifica integridade total
forensics-audit show                                     # Últimas entradas
forensics-audit show --limit 50                          # Últimas 50 entradas
forensics-audit show --event-type module_install         # Filtrar por tipo
forensics-audit show --user sherlock                     # Filtrar por usuário
forensics-audit export --output backup.json --format json # Exportar
forensics-audit stats                                    # Estatísticas
```

### Health & Debugging (Flight Recorder)

```bash
forensics-health check                          # Health check completo
forensics-health quick-check                    # Check rápido
forensics-health why-slow "log2timeline.py"     # Diagnóstico de performance
forensics-health snapshot                       # Captura estado do sistema
```

### Compliance NIST

```bash
forensics-compliance validate         # Valida aderência NIST SP 800-86
forensics-report generate --nist-compliant  # Relatório assinado digitalmente
```

---

## 🏗️ Arquitetura

```
forensics-professional/
├── Dockerfile                        # Multi-stage build otimizado (v2.1.0-FINAL)
├── docker-compose.yml                # Orquestração com recursos dinâmicos
├── docker-entrypoint.sh              # Init seguro: root → sherlock
│
├── core/                             # Sistemas core
│   ├── audit-system/                 # Auditoria imutável
│   │   ├── audit-logger.py           # Logger criptográfico Ed25519+GPG
│   │   ├── forensics-audit           # CLI de auditoria
│   │   ├── init-audit.py             # Inicialização (genesis entry)
│   │   ├── init-keys.sh              # Setup de chaves
│   │   ├── quantum-root              # Autenticação PQC para root
│   │   ├── quantum_verify.c          # Validador PQC em C
│   │   ├── crypto_signer.py          # Assinador digital de relatórios
│   │   ├── root-monitor.py           # Monitor de tentativas de escalonamento
│   │   └── bash-hooks.sh             # Hooks de shell para auditoria automática
│   │
│   ├── module-manager/               # Gerenciador de módulos
│   │   └── forensics-modules         # CLI principal (Python)
│   │
│   ├── compliance/                   # NIST SP 800-86
│   ├── integrations/                 # SIEM, TheHive, MISP, Cloud
│   └── init-environment.sh           # Setup do ambiente forense
│
├── scripts/                          # Utilitários
│   ├── forensics-health              # Health check + Flight Recorder
│   ├── install-modules.sh            # Instalador auxiliar de módulos
│   └── validation-scripts/           # Scripts de validação forense
│       ├── FBI_VALIDATION_CLEAN.sh
│       └── ULTIMATE_VALIDATION_FIXED.sh
│
├── docs/                             # Documentação
│   ├── banner.txt                    # Banner do container
│   ├── OSINT_INTELLIGENCE_TOOLS.md
│   ├── CRIPTOGRAFIA_QUANTICA_EXPLICACAO.md
│   └── CADEIA_CUSTODIA_EXPLICACAO.md
│
├── modules/                          # Definições de módulos
│   └── registry.json                 # Registry central (JSON organizado)
│
├── config/                           # Configurações (.gitkeep)
├── evidence/                         # Evidências (read-only, .gitkeep)
├── cases/                            # Casos de trabalho (.gitkeep)
├── keys/                             # Chaves PQC (.gitkeep)
├── logs/                             # Audit logs (.gitkeep)
└── reports/                          # Relatórios (.gitkeep)
```

---

## 🛡️ Modelo de Segurança

### Proteção de Evidências

```
# /evidence montado como READ-ONLY
# O usuário sherlock NÃO pode:
#   - Deletar evidências
#   - Modificar evidências
#   - Alterar permissões

# Tentativas são automaticamente bloqueadas e registradas:
[2026-03-25T12:00:00Z] VIOLATION_ATTEMPT
  - Action: DELETE evidence
  - User: sherlock
  - File: disk.img
  - Result: BLOCKED
  - Signature: Ed25519+GPG
```

### Proteção dos Logs

```
# Logs têm atributo append-only (chattr +a)
# Mesmo root não pode modificar entradas passadas
# Cada entrada está:
#   1. Encadeada à entrada anterior (blockchain-like)
#   2. Assinada com Ed25519
#   3. Assinada com GPG
#   4. Timestampada (UTC, RFC 3339)
```

### Acesso Root

```
# Senha do root desabilitada (passwd -l root)
# Acesso root SOMENTE via chave pós-quântica (ML-DSA-65)
# Somente o proprietário do container possui a chave privada
```

---

## 📊 Compliance NIST SP 800-86

Container alinhado com as diretrizes do **NIST SP 800-86**:

- ✅ **Seção 3.1.3** — Coleta de evidências (chain of custody automatizada)
- ✅ **Seção 3.1.4** — Exame de evidências (ferramentas modulares)
- ✅ **Seção 3.1.5** — Análise de evidências (workflow documentado)
- ✅ **Seção 4** — Validação de ferramentas forenses (verificação de módulos)
- ✅ **Apêndice D** — Chain of Custody (audit trail imutável)

```bash
# Validar compliance
forensics-compliance validate
```

---

## ⚡ Performance

O container é otimizado para máxima performance:

- **Paralelismo agressivo** — usa todos os cores disponíveis do host automaticamente
- **Multi-threading** nas instalações de módulos
- **Async I/O** para operações de leitura de evidências grandes
- **Memory-mapped files** para análise de datasets pesados
- **Sem limites estáticos de CPU/RAM** — escala com o hardware disponível

---

## 🤝 Contribuindo

Contribuições da comunidade forense são bem-vindas!

- 🐛 Reporte bugs via [GitHub Issues](https://github.com/joao-henrike/Containers/issues)
- 💡 Sugira funcionalidades via [Feature Requests](https://github.com/joao-henrike/Containers/issues/new)
- 🔧 Envie Pull Requests
- 📖 Melhore a documentação
- 🧩 Adicione novos módulos forenses

Leia o [CONTRIBUTING.md](CONTRIBUTING.md) para detalhes.

---

## 📄 Licença

Este projeto está licenciado sob a MIT License com disclaimers forenses — veja o arquivo [LICENSE](LICENSE) para detalhes.

**Importante:** Esta ferramenta é destinada exclusivamente a investigações forenses legítimas. Os usuários são responsáveis pelo cumprimento das leis locais, integridade das evidências e seguimento dos procedimentos forenses corretos.

---

## 📞 Suporte

- **📖 Documentação:** [/docs](docs/)
- **💬 Discussões:** [GitHub Discussions](https://github.com/joao-henrike/Containers/discussions)
- **🐛 Bug Reports:** [GitHub Issues](https://github.com/joao-henrike/Containers/issues)
- **🔐 Segurança:** Abra uma Issue privada para vulnerabilidades

---

## 🙏 Agradecimentos

- [Open Quantum Safe (liboqs)](https://openquantumsafe.org/) — criptografia pós-quântica
- [The Sleuth Kit Project](https://www.sleuthkit.org/)
- [Volatility Foundation](https://volatilityfoundation.org/)
- Toda a comunidade de forense digital open source

---

**Made with ❤️ for the digital forensics community**

**Versão:** 2.1.0-FINAL | **Módulos:** 14 | **Ferramentas:** 161+
**Compliance:** NIST SP 800-86 | **Criptografia:** Post-Quantum Ready | **Licença:** MIT
