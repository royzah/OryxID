# OryxID Makefile
# Enhanced with Docker integration and streamlined commands

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
	@echo '${RED}Common Issues:${RESET}'
	@echo '  ${YELLOW}make fix-deps${RESET}  # Fix npm dependency errors (run if build fails)'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  ${YELLOW}%-15s${RESET} %s\n", $1, $2}' $(MAKEFILE_LIST)

# ==================== QUICK COMMANDS ====================

.PHONY: up
up: ## Start all services (frontend + backend + database)
	@echo "${GREEN}Starting OryxID...${RESET}"
	@docker-compose up -d; \
	exit_code=$$?; \
	if [ $$exit_code -ne 0 ]; then \
		echo ""; \
		echo "${YELLOW}⚠️  Build failed. This might be due to npm dependency issues.${RESET}"; \
		echo "${YELLOW}   Try running: ${CYAN}make fix-deps${YELLOW} then ${CYAN}make up${RESET}"; \
		echo ""; \
		exit 1; \
	fi
	@echo ""
	@echo "${GREEN}✅ OryxID is running!${RESET}"
	@echo ""
	@echo "  ${CYAN}🌐 Application:${RESET} http://localhost:8080"
	@echo "  ${CYAN}📡 API Direct:${RESET}  http://localhost:9000 (for testing)"
	@echo "  ${CYAN}⚛️  Frontend Direct:${RESET} http://localhost:3000 (dev only)"
	@echo ""
	@echo "  ${YELLOW}👤 Login:${RESET} Check ADMIN_USERNAME and ADMIN_PASSWORD in .env"
	@echo "  ${YELLOW}💡 Tip:${RESET} Access via http://localhost:8080 (Nginx proxy)"
	@echo ""

.PHONY: down
down: ## Stop all services
	@echo "${YELLOW}Stopping OryxID...${RESET}"
	@docker-compose down
	@echo "${GREEN}✅ All services stopped${RESET}"

.PHONY: restart
restart: ## Restart all services
	@echo "${YELLOW}Restarting OryxID...${RESET}"
	@docker-compose restart
	@echo "${GREEN}✅ All services restarted${RESET}"

.PHONY: restart-backend
restart-backend: ## Restart just the backend service
	@echo "${YELLOW}Restarting backend...${RESET}"
	@docker-compose up -d backend
	@sleep 3
	@echo "${GREEN}✅ Backend restarted${RESET}"

.PHONY: restart-nginx
restart-nginx: ## Restart just the nginx service
	@echo "${YELLOW}Restarting nginx...${RESET}"
	@docker-compose restart nginx
	@sleep 2
	@echo "${GREEN}✅ Nginx restarted${RESET}"

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
status: ## Show detailed status of all services
	@echo "${CYAN}OryxID Service Status${RESET}"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo ""
	@echo "Container Status:"
	@docker-compose ps --format "table {{.Name}}\t{{.Status}}\t{{.State}}"
	@echo ""
	@echo "Health Checks:"
	@echo -n "  Backend API: "
	@curl -s http://localhost:9000/health >/dev/null 2>&1 && echo "${GREEN}✅ Healthy${RESET}" || echo "${RED}❌ Unhealthy${RESET}"
	@echo -n "  Frontend:    "
	@curl -s http://localhost:3000 >/dev/null 2>&1 && echo "${GREEN}✅ Accessible${RESET}" || echo "${RED}❌ Not accessible${RESET}"
	@echo -n "  Nginx Proxy: "
	@curl -s http://localhost:8080/health >/dev/null 2>&1 && echo "${GREEN}✅ Healthy${RESET}" || echo "${RED}❌ Unhealthy${RESET}"
	@echo ""
	@if ! curl -s http://localhost:9000/health >/dev/null 2>&1; then \
		echo "${YELLOW}⚠️  Backend is not healthy. Try:${RESET}"; \
		echo "    ${CYAN}make fix-running${RESET} - Fix and restart services"; \
		echo "    ${CYAN}make logs-backend${RESET} - Check backend logs"; \
	fi

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

# ==================== TESTING ====================

.PHONY: test
test: test-unit test-integration ## Run all tests (unit + integration)

.PHONY: test-all
test-all: test-unit test-integration test-security test-e2e ## Run all tests including security and e2e

.PHONY: test-unit
test-unit: test-backend test-frontend ## Run unit tests

.PHONY: test-backend
test-backend: ## Run backend unit tests
	@echo "${CYAN}Running backend unit tests...${RESET}"
	@cd backend && go test -v ./internal/... ./pkg/...
	@echo "${GREEN}✅ Backend tests completed${RESET}"

.PHONY: test-frontend
test-frontend: ## Run frontend unit tests
	@echo "${CYAN}Running frontend unit tests...${RESET}"
	@cd frontend && npm test -- --watchAll=false
	@echo "${GREEN}✅ Frontend tests completed${RESET}"

.PHONY: test-handlers
test-handlers: ## Run handler tests
	@echo "${CYAN}Running handler tests...${RESET}"
	@cd backend && go test -v ./internal/handlers/...
	@echo "${GREEN}✅ Handler tests completed${RESET}"

.PHONY: test-integration
test-integration: ## Run integration tests (requires services to be running)
	@echo "${CYAN}Running integration tests...${RESET}"
	@if ! docker-compose ps | grep -q "Up"; then \
		echo "${YELLOW}⚠️  Services not running. Starting services...${RESET}"; \
		make up; \
		sleep 10; \
	fi
	@echo "${CYAN}Setting up test credentials...${RESET}"
	@chmod +x backend/scripts/get_test_credentials.sh
	@eval $$(backend/scripts/get_test_credentials.sh) && \
		cd backend && \
		TEST_CLIENT_ID=$$TEST_CLIENT_ID TEST_CLIENT_SECRET=$$TEST_CLIENT_SECRET \
		go test -v ./tests/integration/...
	@echo "${GREEN}✅ Integration tests completed${RESET}"

.PHONY: test-security
test-security: ## Run security tests
	@echo "${CYAN}Running security tests...${RESET}"
	@cd backend && go test -v ./tests/security/...
	@echo "${GREEN}✅ Security tests completed${RESET}"

.PHONY: test-e2e
test-e2e: ## Run E2E tests with Playwright
	@echo "${CYAN}Running E2E tests...${RESET}"
	@if ! docker-compose ps | grep -q "Up"; then \
		echo "${YELLOW}⚠️  Services not running. Starting services...${RESET}"; \
		make up; \
		sleep 10; \
	fi
	@cd tests/e2e && npx playwright test
	@echo "${GREEN}✅ E2E tests completed${RESET}"

.PHONY: test-e2e-ui
test-e2e-ui: ## Run E2E tests in UI mode
	@echo "${CYAN}Running E2E tests in UI mode...${RESET}"
	@cd tests/e2e && npx playwright test --ui

.PHONY: test-e2e-headed
test-e2e-headed: ## Run E2E tests with browser visible
	@echo "${CYAN}Running E2E tests with browser visible...${RESET}"
	@cd tests/e2e && npx playwright test --headed

.PHONY: test-coverage
test-coverage: ## Generate test coverage report
	@echo "${CYAN}Generating coverage report...${RESET}"
	@cd backend && go test -coverprofile=coverage.out ./internal/... ./pkg/...
	@cd backend && go tool cover -html=coverage.out -o coverage.html
	@echo "${GREEN}✅ Coverage report generated: backend/coverage.html${RESET}"

.PHONY: test-coverage-func
test-coverage-func: ## Show coverage by function
	@echo "${CYAN}Coverage by function:${RESET}"
	@cd backend && go test -coverprofile=coverage.out ./internal/... ./pkg/...
	@cd backend && go tool cover -func=coverage.out

.PHONY: test-race
test-race: ## Run tests with race detector
	@echo "${CYAN}Running tests with race detector...${RESET}"
	@cd backend && go test -race -short ./internal/... ./pkg/...
	@echo "${GREEN}✅ Race detector tests completed${RESET}"

.PHONY: test-bench
test-bench: ## Run benchmark tests
	@echo "${CYAN}Running benchmark tests...${RESET}"
	@cd backend && go test -bench=. -benchmem ./internal/... ./pkg/...
	@echo "${GREEN}✅ Benchmark tests completed${RESET}"

# ==================== PERFORMANCE TESTING ====================

.PHONY: test-performance
test-performance: test-load ## Run all performance tests

.PHONY: test-load
test-load: ## Run k6 load tests
	@echo "${CYAN}Running load tests...${RESET}"
	@if ! command -v k6 >/dev/null 2>&1; then \
		echo "${YELLOW}⚠️  k6 not installed. Install from: https://k6.io/docs/getting-started/installation/${RESET}"; \
		exit 1; \
	fi
	@if ! docker-compose ps | grep -q "Up"; then \
		echo "${YELLOW}⚠️  Services not running. Starting services...${RESET}"; \
		make up; \
		sleep 10; \
	fi
	@k6 run tests/performance/load_test.js
	@echo "${GREEN}✅ Load tests completed${RESET}"

.PHONY: test-stress
test-stress: ## Run k6 stress tests
	@echo "${CYAN}Running stress tests...${RESET}"
	@if ! command -v k6 >/dev/null 2>&1; then \
		echo "${YELLOW}⚠️  k6 not installed. Install from: https://k6.io/docs/getting-started/installation/${RESET}"; \
		exit 1; \
	fi
	@k6 run tests/performance/stress_test.js
	@echo "${GREEN}✅ Stress tests completed${RESET}"

.PHONY: test-spike
test-spike: ## Run k6 spike tests
	@echo "${CYAN}Running spike tests...${RESET}"
	@if ! command -v k6 >/dev/null 2>&1; then \
		echo "${YELLOW}⚠️  k6 not installed. Install from: https://k6.io/docs/getting-started/installation/${RESET}"; \
		exit 1; \
	fi
	@k6 run tests/performance/spike_test.js
	@echo "${GREEN}✅ Spike tests completed${RESET}"

# ==================== LINTING ====================

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

.PHONY: fmt
fmt: fmt-backend fmt-frontend ## Format all code

.PHONY: fmt-backend
fmt-backend: ## Format backend code
	@echo "${CYAN}Formatting backend code...${RESET}"
	@cd backend && go fmt ./...
	@cd backend && goimports -w . || echo "${YELLOW}Install goimports: go install golang.org/x/tools/cmd/goimports@latest${RESET}"

.PHONY: fmt-frontend
fmt-frontend: ## Format frontend code
	@echo "${CYAN}Formatting frontend code...${RESET}"
	@cd frontend && npm run format || echo "${YELLOW}No format script found in package.json${RESET}"

# ==================== MONITORING & DEBUGGING ====================

.PHONY: check-ports
check-ports: ## Check if required ports are available
	@echo "${CYAN}Checking port availability...${RESET}"
	@echo ""
	@for port in 3000 8080 9000; do \
		if lsof -i :$port >/dev/null 2>&1; then \
			echo "  Port $port: ${RED}❌ IN USE${RESET}"; \
			lsof -i :$port | grep LISTEN | head -1; \
		else \
			echo "  Port $port: ${GREEN}✅ Available${RESET}"; \
		fi; \
	done
	@echo ""

.PHONY: health
health: ## Check health of all services
	@echo "${CYAN}Checking service health...${RESET}"
	@echo ""
	@echo "Backend:  $(curl -s http://localhost:9000/health 2>/dev/null && echo '${GREEN}✅ Healthy${RESET}' || echo '${YELLOW}❌ Unhealthy${RESET}')"
	@echo "Frontend: $(curl -s http://localhost:3000/health 2>/dev/null && echo '${GREEN}✅ Healthy${RESET}' || echo '${YELLOW}❌ Unhealthy${RESET}')"
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
