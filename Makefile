# OryxID Makefile

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Variables
COMPOSE := docker compose
BACKEND_DIR := backend
FRONTEND_DIR := frontend

.PHONY: help
help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

# Setup
.PHONY: setup
setup: env keys ## Initial setup (create .env and generate keys)
	@echo "Setup complete. Run 'make up' to start services."

.PHONY: env
env: ## Create .env from example if not exists
	@[ -f .env ] || cp .env.example .env && echo "Created .env file"

.PHONY: keys
keys: ## Generate RSA keys for JWT signing
	@mkdir -p certs
	@[ -f certs/private_key.pem ] || openssl genrsa -out certs/private_key.pem 4096 2>/dev/null
	@[ -f certs/public_key.pem ] || openssl rsa -in certs/private_key.pem -pubout -out certs/public_key.pem 2>/dev/null
	@echo "Keys generated in certs/"

# Docker commands
.PHONY: up
up: ## Start all services
	@$(COMPOSE) up -d
	@echo "Services started. Access at http://localhost:8080"

.PHONY: down
down: ## Stop all services
	@$(COMPOSE) down

.PHONY: restart
restart: ## Restart all services
	@$(COMPOSE) restart

.PHONY: build
build: ## Build all Docker images
	@$(COMPOSE) build

.PHONY: build-no-cache
build-no-cache: ## Build images without cache
	@$(COMPOSE) build --no-cache

.PHONY: logs
logs: ## Show logs from all services
	@$(COMPOSE) logs -f

.PHONY: logs-backend
logs-backend: ## Show backend logs
	@$(COMPOSE) logs -f backend

.PHONY: logs-frontend
logs-frontend: ## Show frontend logs
	@$(COMPOSE) logs -f frontend

.PHONY: ps
ps: ## Show running containers
	@$(COMPOSE) ps

.PHONY: status
status: ## Show service health status
	@echo "Container Status:"
	@$(COMPOSE) ps --format "table {{.Name}}\t{{.Status}}\t{{.State}}"
	@echo ""
	@echo "Health Checks:"
	@curl -sf http://localhost:9000/health >/dev/null && echo "  Backend:  OK" || echo "  Backend:  FAIL"
	@curl -sf http://localhost:3000/health >/dev/null && echo "  Frontend: OK" || echo "  Frontend: FAIL"
	@curl -sf http://localhost:8080/health >/dev/null && echo "  Nginx:    OK" || echo "  Nginx:    FAIL"

# Development
.PHONY: dev
dev: ## Start in development mode
	@FRONTEND_BUILD_TARGET=development $(COMPOSE) up -d
	@echo "Development mode started"

.PHONY: dev-backend
dev-backend: ## Run backend locally (requires postgres/redis)
	@$(COMPOSE) up -d postgres redis
	@cd $(BACKEND_DIR) && go run cmd/server/main.go

.PHONY: dev-frontend
dev-frontend: ## Run frontend locally
	@cd $(FRONTEND_DIR) && npm run dev

# Testing
.PHONY: test
test: test-backend test-frontend ## Run all tests

.PHONY: test-backend
test-backend: ## Run backend tests
	@cd $(BACKEND_DIR) && go test -v ./...

.PHONY: test-frontend
test-frontend: ## Run frontend tests
	@cd $(FRONTEND_DIR) && npm test

.PHONY: test-integration
test-integration: ## Run integration tests
	@cd $(BACKEND_DIR) && go test -v ./tests/integration/...

.PHONY: test-coverage
test-coverage: ## Generate test coverage report
	@cd $(BACKEND_DIR) && go test -coverprofile=coverage.out ./...
	@cd $(BACKEND_DIR) && go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: $(BACKEND_DIR)/coverage.html"

# Linting
.PHONY: lint
lint: lint-backend lint-frontend ## Run all linters

.PHONY: lint-backend
lint-backend: ## Lint backend code
	@cd $(BACKEND_DIR) && golangci-lint run || echo "Install: https://golangci-lint.run"

.PHONY: lint-frontend
lint-frontend: ## Lint frontend code
	@cd $(FRONTEND_DIR) && npm run lint

.PHONY: fmt
fmt: ## Format all code
	@cd $(BACKEND_DIR) && go fmt ./...
	@cd $(FRONTEND_DIR) && npm run format || true

# Database
.PHONY: db-shell
db-shell: ## Open PostgreSQL shell
	@$(COMPOSE) exec postgres psql -U $$(grep DB_USER .env | cut -d '=' -f2) $$(grep DB_NAME .env | cut -d '=' -f2)

.PHONY: db-backup
db-backup: ## Backup database
	@mkdir -p backups
	@$(COMPOSE) exec postgres pg_dump -U $$(grep DB_USER .env | cut -d '=' -f2) $$(grep DB_NAME .env | cut -d '=' -f2) > backups/backup-$$(date +%Y%m%d-%H%M%S).sql
	@echo "Backup saved to backups/"

.PHONY: db-restore
db-restore: ## Restore from latest backup
	@LATEST=$$(ls -t backups/*.sql 2>/dev/null | head -1); \
	[ -n "$$LATEST" ] && $(COMPOSE) exec -T postgres psql -U $$(grep DB_USER .env | cut -d '=' -f2) $$(grep DB_NAME .env | cut -d '=' -f2) < $$LATEST || echo "No backup found"

.PHONY: redis-shell
redis-shell: ## Open Redis CLI
	@$(COMPOSE) exec redis redis-cli -a $$(grep REDIS_PASSWORD .env | cut -d '=' -f2)

# Cleanup
.PHONY: clean
clean: ## Stop and remove containers
	@$(COMPOSE) down --remove-orphans

.PHONY: clean-volumes
clean-volumes: ## Remove containers and volumes (deletes data)
	@echo "This will delete all data. Press Ctrl+C to cancel."
	@sleep 3
	@$(COMPOSE) down -v --remove-orphans

.PHONY: clean-all
clean-all: clean-volumes ## Remove everything including images
	@$(COMPOSE) down --rmi all

.PHONY: prune
prune: ## Prune unused Docker resources
	@docker system prune -f

# Production
.PHONY: prod-build
prod-build: ## Build for production
	@SERVER_MODE=release $(COMPOSE) build

.PHONY: prod-up
prod-up: ## Start in production mode
	@SERVER_MODE=release $(COMPOSE) up -d

# Utilities
.PHONY: shell-backend
shell-backend: ## Open shell in backend container
	@$(COMPOSE) exec backend /bin/sh

.PHONY: shell-frontend
shell-frontend: ## Open shell in frontend container
	@$(COMPOSE) exec frontend /bin/sh

.PHONY: version
version: ## Show version information
	@echo "Git: $$(git rev-parse --short HEAD 2>/dev/null || echo 'N/A')"
	@echo "Docker: $$(docker --version)"

.PHONY: info
info: ## Show environment info
	@echo "Frontend: http://localhost:$$(grep FRONTEND_PORT .env | cut -d '=' -f2)"
	@echo "Backend:  http://localhost:$$(grep SERVER_PORT .env | cut -d '=' -f2)"
	@echo "Proxy:    http://localhost:$$(grep HTTP_PORT .env | cut -d '=' -f2)"
