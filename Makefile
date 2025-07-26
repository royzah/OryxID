# OryxID Makefile
# Provides convenient commands for development and deployment

.PHONY: help
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ==================== SETUP ====================

.PHONY: setup
setup: generate-keys install-deps ## Initial setup - generate keys and install dependencies
	@echo "✅ Setup complete! Run 'make dev' to start development environment"

.PHONY: generate-keys
generate-keys: ## Generate RSA keys for JWT signing
	@echo "🔐 Generating RSA keys..."
	@mkdir -p docker/certs backend/certs
	@openssl genrsa -out docker/certs/private_key.pem 4096
	@openssl rsa -in docker/certs/private_key.pem -pubout -out docker/certs/public_key.pem
	@cp docker/certs/*.pem backend/certs/
	@echo "✅ RSA keys generated"

.PHONY: install-deps
install-deps: ## Install all dependencies
	@echo "📦 Installing backend dependencies..."
	@cd backend && go mod download
	@echo "📦 Installing frontend dependencies..."
	@cd frontend && npm install
	@echo "✅ Dependencies installed"

# ==================== DEVELOPMENT ====================

.PHONY: dev
dev: ## Start development environment with Docker Compose
	@echo "🚀 Starting development environment..."
	@docker-compose --env-file .env -f docker/docker-compose.yml up -d
	@echo "✅ Development environment started"
	@echo "   Admin Panel: http://localhost:3000"
	@echo "   API Server:  http://localhost:9000"
	@echo "   Default login: admin / admin123"

.PHONY: dev-logs
dev-logs: ## Show development container logs
	@docker-compose --env-file .env -f docker/docker-compose.yml logs -f

.PHONY: dev-stop
dev-stop: ## Stop development environment
	@docker-compose --env-file .env -f docker/docker-compose.yml down
	@echo "✅ Development environment stopped"

.PHONY: dev-clean
dev-clean: ## Stop and remove all containers, volumes
	@docker-compose --env-file .env -f docker/docker-compose.yml down -v
	@echo "✅ Development environment cleaned"

# ==================== BACKEND ====================

.PHONY: backend-run
backend-run: ## Run backend server locally
	@cd backend && go run cmd/server/main.go

.PHONY: backend-build
backend-build: ## Build backend binary
	@echo "🔨 Building backend..."
	@cd backend && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags="-w -s -X main.Version=$$(git describe --tags --always)" \
		-o bin/oryxid cmd/server/main.go
	@echo "✅ Backend built: backend/bin/oryxid"

.PHONY: backend-test
backend-test: ## Run backend tests
	@echo "🧪 Running backend tests..."
	@cd backend && go test -v -race -coverprofile=coverage.out ./...

.PHONY: backend-coverage
backend-coverage: backend-test ## Run tests and show coverage report
	@cd backend && go tool cover -html=coverage.out -o coverage.html
	@echo "📊 Coverage report: backend/coverage.html"

.PHONY: backend-lint
backend-lint: ## Run backend linter
	@echo "🔍 Linting backend code..."
	@cd backend && golangci-lint run

.PHONY: backend-fmt
backend-fmt: ## Format backend code
	@echo "✨ Formatting backend code..."
	@cd backend && go fmt ./...

# ==================== FRONTEND ====================

.PHONY: frontend-run
frontend-run: ## Run frontend development server
	@cd frontend && npm run dev

.PHONY: frontend-build
frontend-build: ## Build frontend for production
	@echo "🔨 Building frontend..."
	@cd frontend && npm run build
	@echo "✅ Frontend built: frontend/dist/"

.PHONY: frontend-test
frontend-test: ## Run frontend tests
	@echo "🧪 Running frontend tests..."
	@cd frontend && npm test

.PHONY: frontend-test-watch
frontend-test-watch: ## Run frontend tests in watch mode
	@cd frontend && npm run test:watch

.PHONY: frontend-lint
frontend-lint: ## Run frontend linter
	@echo "🔍 Linting frontend code..."
	@cd frontend && npm run lint

.PHONY: frontend-format
frontend-format: ## Format frontend code
	@echo "✨ Formatting frontend code..."
	@cd frontend && npm run format

.PHONY: frontend-type-check
frontend-type-check: ## Run TypeScript type checking
	@echo "🔍 Checking TypeScript types..."
	@cd frontend && npm run type-check

# ==================== DATABASE ====================

.PHONY: db-migrate
db-migrate: ## Run database migrations
	@echo "🗄️  Running migrations..."
	@cd backend && go run cmd/migrate/main.go up

.PHONY: db-rollback
db-rollback: ## Rollback last migration
	@echo "🗄️  Rolling back migration..."
	@cd backend && go run cmd/migrate/main.go down

.PHONY: db-reset
db-reset: ## Reset database (drop all tables)
	@echo "⚠️  Resetting database..."
	@cd backend && go run cmd/migrate/main.go reset

.PHONY: db-seed
db-seed: ## Seed database with test data
	@echo "🌱 Seeding database..."
	@cd backend && go run cmd/seed/main.go

.PHONY: db-backup
db-backup: ## Backup database
	@echo "💾 Backing up database..."
	@docker exec oryxid-postgres pg_dump -U oryxid oryxid > backup-$$(date +%Y%m%d-%H%M%S).sql
	@echo "✅ Database backed up"

# ==================== DOCKER ====================

.PHONY: docker-build
docker-build: ## Build all Docker images
	@echo "🐳 Building Docker images..."
	@docker build -t oryxid-backend:latest ./backend
	@docker build -t oryxid-frontend:latest ./frontend
	@echo "✅ Docker images built"

.PHONY: docker-push
docker-push: ## Push Docker images to registry
	@echo "📤 Pushing Docker images..."
	@docker push oryxid-backend:latest
	@docker push oryxid-frontend:latest

.PHONY: docker-up
docker-up: ## Start all containers
	@docker-compose -f docker/docker-compose.yml up -d

.PHONY: docker-down
docker-down: ## Stop all containers
	@docker-compose -f docker/docker-compose.yml down

.PHONY: docker-logs
docker-logs: ## Show container logs
	@docker-compose -f docker/docker-compose.yml logs -f

.PHONY: docker-ps
docker-ps: ## Show running containers
	@docker-compose -f docker/docker-compose.yml ps

# ==================== PRODUCTION ====================

.PHONY: prod-build
prod-build: ## Build for production
	@echo "🏗️  Building for production..."
	@make backend-build
	@make frontend-build
	@make docker-build
	@echo "✅ Production build complete"

.PHONY: prod-deploy
prod-deploy: prod-build ## Deploy to production (customize this)
	@echo "🚀 Deploying to production..."
	# Add your deployment commands here
	# Examples:
	# - kubectl apply -f k8s/
	# - docker-compose -f docker-compose.prod.yml up -d
	# - aws ecs update-service ...
	@echo "✅ Deployment complete"

# ==================== KUBERNETES ====================

.PHONY: k8s-deploy
k8s-deploy: ## Deploy to Kubernetes
	@echo "☸️  Deploying to Kubernetes..."
	@kubectl apply -f k8s/

.PHONY: k8s-delete
k8s-delete: ## Delete from Kubernetes
	@echo "☸️  Deleting from Kubernetes..."
	@kubectl delete -f k8s/

.PHONY: k8s-logs
k8s-logs: ## Show Kubernetes pod logs
	@kubectl logs -f -l app=oryxid-backend

.PHONY: k8s-status
k8s-status: ## Show Kubernetes deployment status
	@kubectl get all -l app=oryxid

# ==================== TESTING ====================

.PHONY: test
test: backend-test frontend-test ## Run all tests

.PHONY: test-integration
test-integration: ## Run integration tests
	@echo "🧪 Running integration tests..."
	@cd backend && go test -v -tags=integration ./tests/integration/...

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests
	@echo "🧪 Running e2e tests..."
	@cd frontend && npm run test:e2e

.PHONY: test-oauth
test-oauth: ## Test OAuth flow
	@echo "🔐 Testing OAuth flow..."
	@./scripts/test-oauth.sh

# ==================== UTILITIES ====================

.PHONY: clean
clean: ## Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf backend/bin backend/coverage.* backend/vendor
	@rm -rf frontend/dist frontend/coverage
	@rm -rf docker/certs/*.pem backend/certs/*.pem
	@echo "✅ Clean complete"

.PHONY: check
check: backend-lint backend-test frontend-lint frontend-type-check frontend-test ## Run all checks

.PHONY: fmt
fmt: backend-fmt frontend-format ## Format all code

.PHONY: update-deps
update-deps: ## Update all dependencies
	@echo "📦 Updating backend dependencies..."
	@cd backend && go get -u ./... && go mod tidy
	@echo "📦 Updating frontend dependencies..."
	@cd frontend && npm update
	@echo "✅ Dependencies updated"

.PHONY: version
version: ## Show version information
	@echo "OryxID Version Information:"
	@echo "  Git commit: $$(git rev-parse --short HEAD)"
	@echo "  Git branch: $$(git rev-parse --abbrev-ref HEAD)"
	@echo "  Go version: $$(go version)"
	@echo "  Node version: $$(node --version)"
	@echo "  NPM version: $$(npm --version)"

.PHONY: env-example
env-example: ## Create example environment files
	@cp backend/.env.example backend/.env
	@cp frontend/.env.example frontend/.env
	@echo "✅ Created .env files from examples"

# ==================== MONITORING ====================

.PHONY: monitor-health
monitor-health: ## Check health endpoints
	@echo "❤️  Checking health..."
	@curl -s http://localhost:9000/health | jq . || echo "Backend not available"
	@curl -s http://localhost:3000/health || echo "Frontend not available"

.PHONY: monitor-metrics
monitor-metrics: ## Show metrics
	@curl -s http://localhost:9000/metrics | head -20

# Default target
.DEFAULT_GOAL := help
