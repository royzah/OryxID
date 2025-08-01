# OryxID Makefile

# Default shell
SHELL := /bin/bash

# Colors for pretty output
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

.PHONY: help
help: ## Show this help message
	@echo ''
	@echo '${CYAN}OryxID${RESET} - ${WHITE}OAuth2/OpenID Connect Server${RESET}'
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Quick Start:'
	@echo '  ${YELLOW}make setup${RESET}     # First time setup (generates keys)'
	@echo '  ${YELLOW}make up${RESET}        # Start all services'
	@echo '  ${YELLOW}make down${RESET}      # Stop all services'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  ${YELLOW}%-15s${RESET} %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ==================== QUICK COMMANDS ====================

.PHONY: up
up: ## Start all services (frontend + backend + database)
	@echo "${GREEN}Starting OryxID...${RESET}"
	@docker-compose up -d
	@echo ""
	@echo "${GREEN}✅ OryxID is running!${RESET}"
	@echo ""
	@echo "  ${CYAN}Admin Panel:${RESET} http://localhost:3000"
	@echo "  ${CYAN}API Server:${RESET}  http://localhost:9000"
	@echo ""
	@echo "  ${YELLOW}Login:${RESET} Check ADMIN_USERNAME and ADMIN_PASSWORD in .env"
	@echo ""

.PHONY: down
down: ## Stop all services
	@echo "${YELLOW}Stopping OryxID...${RESET}"
	@docker-compose down
	@echo "${GREEN}✅ All services stopped${RESET}"

.PHONY: restart
restart: down up ## Restart all services

.PHONY: logs
logs: ## Show logs from all services
	@docker-compose logs -f

.PHONY: logs-backend
logs-backend: ## Show backend logs only
	@docker-compose logs -f backend

.PHONY: logs-frontend
logs-frontend: ## Show frontend logs only
	@docker-compose logs -f frontend

.PHONY: status
status: ## Show status of all services
	@docker-compose ps

# ==================== SETUP & INITIALIZATION ====================

.PHONY: setup
setup: env-check generate-keys ## Complete initial setup
	@echo "${GREEN}✅ Setup complete!${RESET}"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Review and update ${CYAN}.env${RESET} file"
	@echo "  2. Run ${YELLOW}make up${RESET} to start services"

.PHONY: env-check
env-check: ## Check and create .env file if needed
	@if [ ! -f .env ]; then \
		echo "${YELLOW}Creating .env file from example...${RESET}"; \
		cp .env.example .env; \
		echo "${GREEN}✅ Created .env file${RESET}"; \
		echo "${YELLOW}⚠️  Please update the default passwords in .env${RESET}"; \
	else \
		echo "${GREEN}✅ .env file exists${RESET}"; \
	fi

.PHONY: generate-keys
generate-keys: ## Generate RSA keys for JWT signing
	@echo "${CYAN}Generating RSA keys...${RESET}"
	@mkdir -p certs
	@if [ ! -f certs/private_key.pem ]; then \
		openssl genrsa -out certs/private_key.pem 4096 2>/dev/null && \
		echo "${GREEN}✅ Generated private key${RESET}"; \
	else \
		echo "${YELLOW}⚠️  Private key already exists${RESET}"; \
	fi
	@if [ ! -f certs/public_key.pem ]; then \
		openssl rsa -in certs/private_key.pem -pubout -out certs/public_key.pem 2>/dev/null && \
		echo "${GREEN}✅ Generated public key${RESET}"; \
	else \
		echo "${YELLOW}⚠️  Public key already exists${RESET}"; \
	fi

# ==================== DOCKER MANAGEMENT ====================

.PHONY: build
build: ## Build all Docker images
	@echo "${CYAN}Building Docker images...${RESET}"
	@docker-compose build
	@echo "${GREEN}✅ Build complete${RESET}"

.PHONY: build-no-cache
build-no-cache: ## Build all Docker images without cache
	@echo "${CYAN}Building Docker images (no cache)...${RESET}"
	@docker-compose build --no-cache
	@echo "${GREEN}✅ Build complete${RESET}"

.PHONY: pull
pull: ## Pull all Docker images
	@echo "${CYAN}Pulling Docker images...${RESET}"
	@docker-compose pull
	@echo "${GREEN}✅ Pull complete${RESET}"

.PHONY: ps
ps: ## Show running containers
	@docker-compose ps

# ==================== CLEANUP & MAINTENANCE ====================

.PHONY: clean
clean: ## Stop services and remove containers
	@echo "${YELLOW}Cleaning up containers...${RESET}"
	@docker-compose down --remove-orphans
	@echo "${GREEN}✅ Containers removed${RESET}"

.PHONY: clean-volumes
clean-volumes: ## Stop services and remove containers AND volumes (WARNING: Deletes data!)
	@echo "${YELLOW}⚠️  WARNING: This will delete all data!${RESET}"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		docker-compose down -v --remove-orphans && \
		echo "${GREEN}✅ Containers and volumes removed${RESET}"; \
	else \
		echo "${YELLOW}Cancelled${RESET}"; \
	fi

.PHONY: clean-all
clean-all: clean-volumes ## Remove everything including images
	@echo "${YELLOW}Removing Docker images...${RESET}"
	@docker-compose down --rmi all
	@echo "${GREEN}✅ All images removed${RESET}"

.PHONY: prune
prune: ## Prune Docker system (remove unused data)
	@echo "${YELLOW}Pruning Docker system...${RESET}"
	@docker system prune -f
	@echo "${GREEN}✅ System pruned${RESET}"

.PHONY: prune-all
prune-all: ## Prune everything including volumes (WARNING: Aggressive cleanup!)
	@echo "${YELLOW}⚠️  WARNING: This will remove ALL unused Docker data!${RESET}"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		docker system prune -a --volumes -f && \
		echo "${GREEN}✅ Complete prune finished${RESET}"; \
	else \
		echo "${YELLOW}Cancelled${RESET}"; \
	fi

# ==================== DATABASE OPERATIONS ====================

.PHONY: db-shell
db-shell: ## Open PostgreSQL shell
	@docker-compose exec postgres psql -U $$(grep DB_USER .env | cut -d '=' -f2) $$(grep DB_NAME .env | cut -d '=' -f2)

.PHONY: db-backup
db-backup: ## Backup database
	@echo "${CYAN}Backing up database...${RESET}"
	@mkdir -p backups
	@docker-compose exec postgres pg_dump -U $$(grep DB_USER .env | cut -d '=' -f2) $$(grep DB_NAME .env | cut -d '=' -f2) > backups/oryxid-backup-$$(date +%Y%m%d-%H%M%S).sql
	@echo "${GREEN}✅ Database backed up to backups/${RESET}"

.PHONY: db-restore
db-restore: ## Restore database from latest backup
	@echo "${CYAN}Restoring database from latest backup...${RESET}"
	@if [ -z "$$(ls -A backups/*.sql 2>/dev/null)" ]; then \
		echo "${YELLOW}No backup files found${RESET}"; \
	else \
		LATEST_BACKUP=$$(ls -t backups/*.sql | head -1); \
		echo "Restoring from: $$LATEST_BACKUP"; \
		docker-compose exec -T postgres psql -U $$(grep DB_USER .env | cut -d '=' -f2) $$(grep DB_NAME .env | cut -d '=' -f2) < $$LATEST_BACKUP && \
		echo "${GREEN}✅ Database restored${RESET}"; \
	fi

.PHONY: redis-shell
redis-shell: ## Open Redis CLI
	@docker-compose exec redis redis-cli -a $$(grep REDIS_PASSWORD .env | cut -d '=' -f2)

# ==================== DEVELOPMENT COMMANDS ====================

.PHONY: dev
dev: ## Start in development mode with hot-reload
	@echo "${GREEN}Starting in development mode...${RESET}"
	@FRONTEND_BUILD_TARGET=development docker-compose up -d
	@echo "${GREEN}✅ Development mode active${RESET}"

.PHONY: dev-backend
dev-backend: ## Run only backend in development
	@docker-compose up -d postgres redis
	@cd backend && go run cmd/server/main.go

.PHONY: dev-frontend
dev-frontend: ## Run only frontend in development
	@cd frontend && npm run dev

.PHONY: test
test: test-backend test-frontend ## Run all tests

.PHONY: test-backend
test-backend: ## Run backend tests
	@echo "${CYAN}Running backend tests...${RESET}"
	@cd backend && go test -v ./...

.PHONY: test-frontend
test-frontend: ## Run frontend tests
	@echo "${CYAN}Running frontend tests...${RESET}"
	@cd frontend && npm test

.PHONY: lint
lint: lint-backend lint-frontend ## Run all linters

.PHONY: lint-backend
lint-backend: ## Lint backend code
	@echo "${CYAN}Linting backend...${RESET}"
	@cd backend && golangci-lint run || echo "${YELLOW}Install golangci-lint: https://golangci-lint.run/usage/install/${RESET}"

.PHONY: lint-frontend
lint-frontend: ## Lint frontend code
	@echo "${CYAN}Linting frontend...${RESET}"
	@cd frontend && npm run lint

# ==================== MONITORING & DEBUGGING ====================

.PHONY: health
health: ## Check health of all services
	@echo "${CYAN}Checking service health...${RESET}"
	@echo ""
	@echo "Backend:  $$(curl -s http://localhost:9000/health 2>/dev/null && echo '${GREEN}✅ Healthy${RESET}' || echo '${YELLOW}❌ Unhealthy${RESET}')"
	@echo "Frontend: $$(curl -s http://localhost:3000/health 2>/dev/null && echo '${GREEN}✅ Healthy${RESET}' || echo '${YELLOW}❌ Unhealthy${RESET}')"
	@echo ""

.PHONY: metrics
metrics: ## Show backend metrics
	@curl -s http://localhost:9000/metrics | head -20

.PHONY: shell-backend
shell-backend: ## Open shell in backend container
	@docker-compose exec backend /bin/sh

.PHONY: shell-frontend
shell-frontend: ## Open shell in frontend container
	@docker-compose exec frontend /bin/sh

# ==================== PRODUCTION COMMANDS ====================

.PHONY: prod-build
prod-build: ## Build for production
	@echo "${CYAN}Building for production...${RESET}"
	@SERVER_MODE=release docker-compose build
	@echo "${GREEN}✅ Production build complete${RESET}"

.PHONY: prod-up
prod-up: ## Start in production mode
	@echo "${GREEN}Starting in production mode...${RESET}"
	@SERVER_MODE=release docker-compose up -d
	@echo "${GREEN}✅ Production mode active${RESET}"

# ==================== UTILITY COMMANDS ====================

.PHONY: version
version: ## Show version information
	@echo "${CYAN}OryxID Version Information${RESET}"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "Git commit:  $$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
	@echo "Git branch:  $$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
	@echo "Docker:      $$(docker --version)"
	@echo "Compose:     $$(docker-compose --version)"

.PHONY: info
info: ## Show environment information
	@echo "${CYAN}OryxID Environment${RESET}"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "Admin Panel:  http://localhost:$$(grep FRONTEND_PORT .env | cut -d '=' -f2)"
	@echo "API Server:   http://localhost:$$(grep SERVER_PORT .env | cut -d '=' -f2)"
	@echo "Admin User:   $$(grep ADMIN_USERNAME .env | cut -d '=' -f2)"
	@echo "Environment:  $$(grep SERVER_MODE .env | cut -d '=' -f2)"

# Default target
.DEFAULT_GOAL := help
