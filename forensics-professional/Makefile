# ==============================================================================
# Forensics Professional — common development tasks
# ==============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

VERSION       := $(shell cat VERSION)
IMAGE         := forensics-professional:$(VERSION)
COMPOSE       := docker compose
COMPOSE_EXEC  := $(COMPOSE) exec forensics

# ── Help ────────────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help.
	@echo "Forensics Professional — v$(VERSION)"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

# ── Build & run ─────────────────────────────────────────────────────────────

.PHONY: build
build: ## Build the Docker image.
	$(COMPOSE) build

.PHONY: build-no-cache
build-no-cache: ## Build the image with --no-cache (slow, full rebuild).
	$(COMPOSE) build --no-cache

.PHONY: up
up: ## Start the container in the background.
	$(COMPOSE) up -d

.PHONY: down
down: ## Stop and remove the container.
	$(COMPOSE) down

.PHONY: restart
restart: down up ## Stop, then start the container.

.PHONY: shell
shell: ## Open an interactive shell as sherlock.
	$(COMPOSE_EXEC) bash

.PHONY: root-shell
root-shell: ## Open a shell as root (host-side privilege).
	$(COMPOSE) exec -u root forensics bash

.PHONY: logs
logs: ## Tail container logs.
	$(COMPOSE) logs -f

# ── Validation ──────────────────────────────────────────────────────────────

.PHONY: smoke
smoke: ## Run the in-container smoke test.
	$(COMPOSE_EXEC) /opt/forensics/bin/validate.sh

.PHONY: health
health: ## Run a full health check.
	$(COMPOSE_EXEC) forensics-health

.PHONY: audit-verify
audit-verify: ## Verify the audit log integrity.
	$(COMPOSE_EXEC) forensics-audit verify

# ── Host-side dev ───────────────────────────────────────────────────────────

.PHONY: lint
lint: ## Lint Python code with ruff and mypy.
	ruff check core/ tests/
	mypy core/forensics

.PHONY: format
format: ## Auto-format Python code.
	ruff format core/ tests/

.PHONY: test
test: ## Run pytest suite.
	pytest

.PHONY: test-cov
test-cov: ## Run pytest with coverage.
	pytest --cov=forensics --cov-report=term-missing

# ── Releases ────────────────────────────────────────────────────────────────

.PHONY: clean
clean: ## Remove generated artefacts.
	find . -type d \( -name __pycache__ -o -name .pytest_cache \
	                  -o -name .mypy_cache -o -name .ruff_cache \) \
		-exec rm -rf {} +
	rm -rf build dist *.egg-info .coverage htmlcov

.PHONY: tag
tag: ## Print the image tag for the current VERSION.
	@echo "$(IMAGE)"
