# OryxID - Modern OAuth2/OpenID Connect Server

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)
![React Version](https://img.shields.io/badge/React-18+-61DAFB?style=for-the-badge&logo=react)
![TypeScript Version](https://img.shields.io/badge/TypeScript-5+-3178C6?style=for-the-badge&logo=typescript)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

A modern, high-performance OAuth2 and OpenID Connect server built with Go and React. OryxID provides enterprise-grade authentication and authorization services with a beautiful admin interface.

## 🌟 Features

- **🔐 OAuth 2.0 & OpenID Connect**: Full implementation with PKCE support
- **🎨 Modern Admin UI**: Beautiful React-based dashboard for easy management
- **⚡ High Performance**: Built with Go for exceptional speed and low resource usage
- **🔑 JWT Tokens**: RS256 signed tokens with customizable claims
- **🏢 Multi-tenancy**: Support for multiple applications and API audiences
- **🔍 Audit Logging**: Comprehensive activity tracking and monitoring
- **🐳 Cloud Native**: Docker and Kubernetes ready with health checks
- **🛡️ Security First**: CSRF protection, rate limiting, and secure defaults

## 📸 Screenshots

### Dashboard

Clean overview of your OAuth infrastructure

### Applications Management

Easy OAuth client configuration

### Scope Management

Fine-grained permission control

## 🏗️ Architecture

OryxID consists of two main components that work together:

```text
┌─────────────────────────────────────────────────────────────┐
│                         Frontend (React)                    │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │   Pages     │  │  Components  │  │  State (Zustand) │    │
│  └──────┬──────┘  └───────┬──────┘  └────────┬─────────┘    │
│         └─────────────────┴──────────────────┘              │
│                           │                                 │
│                    Axios + TanStack Query                   │
└───────────────────────────┬─────────────────────────────────┘
                            │ HTTPS/REST API
┌───────────────────────────┴─────────────────────────────────┐
│                      Backend (Go + Gin)                     │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │   Handlers  │  │  OAuth2 Core │  │   Middleware     │    │
│  └──────┬──────┘  └───────┬──────┘  └────────┬─────────┘    │
│         └─────────────────┴──────────────────┘              │
│                           │                                 │
│                    GORM + PostgreSQL                        │
└───────────────────────────┬─────────────────────────────────┘
                            │
                   ┌────────┴────────┐
                   │   PostgreSQL    │
                   │   Redis Cache   │
                   └─────────────────┘
```

### Component Interaction

1. **Frontend → Backend API**

   - Admin authentication via `/auth/login`
   - Resource management via `/api/v1/*` endpoints
   - Real-time token validation

2. **OAuth Clients → Backend**

   - Authorization via `/oauth/authorize`
   - Token exchange via `/oauth/token`
   - Token introspection via `/oauth/introspect`

3. **Backend → Database**
   - User and application storage in PostgreSQL
   - Session management in Redis
   - Audit logging for compliance

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- Git
- Make (optional, for convenience commands)

### One-Command Setup

```bash
# Clone the repository
git clone https://github.com/tiiuae/oryxid.git
cd oryxid

# Generate RSA keys and start everything
make setup && make dev
```

The application will be available at:

- **Admin Panel**: [http://localhost:3000](http://localhost:3000)
- **OAuth Server**: [http://localhost:9000](http://localhost:9000)

Default credentials:

- Username: `admin`
- Password: `admin123`

## 📦 Local Development

### Using Docker Compose (Recommended)

```bash
# Start all services
docker-compose -f docker/docker-compose.yml up -d

# View logs
docker-compose -f docker/docker-compose.yml logs -f

# Stop services
docker-compose -f docker/docker-compose.yml down
```

### Manual Setup

#### Backend Setup

```bash
# Navigate to backend
cd backend

# Install dependencies
go mod download

# Set up environment
cp .env.example .env
# Edit .env with your database credentials

# Generate RSA keys
mkdir -p certs
openssl genrsa -out certs/private_key.pem 4096
openssl rsa -in certs/private_key.pem -pubout -out certs/public_key.pem

# Run database migrations
go run cmd/migrate/main.go up

# Start the server
go run cmd/server/main.go
```

#### Frontend Setup

```bash
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Set up environment
cp .env.example .env
# Edit .env with your API URL

# Start development server
npm run dev
```

### Using Make Commands

```bash
# Backend commands
make backend-run      # Run backend server
make backend-test     # Run backend tests
make backend-build    # Build backend binary

# Frontend commands
make frontend-run     # Run frontend dev server
make frontend-build   # Build frontend for production
make frontend-test    # Run frontend tests

# Database commands
make db-migrate       # Run migrations
make db-rollback      # Rollback last migration
make db-seed          # Seed test data

# Docker commands
make docker-build     # Build all images
make docker-up        # Start all containers
make docker-down      # Stop all containers
```

## 🔧 Configuration

### Backend Configuration

Create `backend/.env`:

```env
# Server
SERVER_PORT=9000
SERVER_MODE=debug

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=oryxid
DB_PASSWORD=your_password
DB_NAME=oryxid

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# OAuth
OAUTH_ISSUER=http://localhost:9000

# Security
JWT_PRIVATE_KEY_PATH=./certs/private_key.pem
JWT_PUBLIC_KEY_PATH=./certs/public_key.pem
```

### Frontend Configuration

Create `frontend/.env`:

```env
VITE_API_URL=http://localhost:9000
```

## 🧪 Testing

### Test OAuth Flow

```bash
# Run the OAuth test script
./scripts/test-oauth.sh

# Or manually test:
# 1. Create an application in the admin panel
# 2. Note the client_id and client_secret
# 3. Test authorization code flow:
curl "http://localhost:9000/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:8080/callback&scope=openid profile"
```

### Run Tests

```bash
# Backend tests
cd backend && go test ./...

# Frontend tests
cd frontend && npm test
```

## 🚢 Production Deployment

### Docker Deployment

1. **Build Production Images**

   ```bash
   # Build both frontend and backend
   make prod-build

   # Or individually:
   docker build -t oryxid-backend:latest ./backend
   docker build -t oryxid-frontend:latest ./frontend
   ```

2. **Run with Docker Compose**

   ```yaml
   # docker-compose.prod.yml
   version: "3.8"

   services:
     postgres:
       image: postgres:16-alpine
       environment:
         POSTGRES_PASSWORD: ${DB_PASSWORD}
       volumes:
         - postgres_data:/var/lib/postgresql/data
       restart: unless-stopped

     redis:
       image: redis:7-alpine
       command: redis-server --requirepass ${REDIS_PASSWORD}
       restart: unless-stopped

     backend:
       image: oryxid-backend:latest
       environment:
         - SERVER_MODE=release
         - DB_HOST=postgres
         - REDIS_HOST=redis
       depends_on:
         - postgres
         - redis
       restart: unless-stopped

     frontend:
       image: oryxid-frontend:latest
       depends_on:
         - backend
       ports:
         - "80:80"
       restart: unless-stopped

   volumes:
     postgres_data:
   ```

### Kubernetes Deployment

1. **Create Namespace and Secrets**

   ```bash
   kubectl create namespace oryxid
   kubectl create secret generic oryxid-secrets \
     --from-literal=db-password=your-password \
     --from-literal=redis-password=your-password \
     -n oryxid
   ```

2. **Apply Manifests**

   ```bash
   kubectl apply -f k8s/ -n oryxid
   ```

3. **Check Deployment**

   ```bash
   kubectl get pods -n oryxid
   kubectl get svc -n oryxid
   ```

### Cloud Deployment Options

#### AWS ECS

```bash
# Build and push to ECR
aws ecr get-login-password | docker login --username AWS --password-stdin $ECR_REGISTRY
docker tag oryxid-backend:latest $ECR_REGISTRY/oryxid-backend:latest
docker push $ECR_REGISTRY/oryxid-backend:latest

# Deploy with ECS CLI or Terraform
```

#### Google Cloud Run

```bash
# Build and push to GCR
gcloud builds submit --tag gcr.io/$PROJECT_ID/oryxid-backend
gcloud builds submit --tag gcr.io/$PROJECT_ID/oryxid-frontend

# Deploy
gcloud run deploy oryxid-backend --image gcr.io/$PROJECT_ID/oryxid-backend
gcloud run deploy oryxid-frontend --image gcr.io/$PROJECT_ID/oryxid-frontend
```

#### Azure Container Instances

```bash
# Push to ACR
az acr build --registry $ACR_NAME --image oryxid-backend:latest ./backend
az acr build --registry $ACR_NAME --image oryxid-frontend:latest ./frontend

# Deploy
az container create --resource-group $RG --name oryxid --image $ACR_NAME.azurecr.io/oryxid-backend:latest
```

## 📊 Monitoring

### Health Checks

```bash
# Backend health
curl http://localhost:9000/health

# Frontend health (through nginx)
curl http://localhost:3000/health
```

### Metrics

The backend exposes Prometheus metrics at `/metrics`:

```bash
curl http://localhost:9000/metrics
```

### Logging

- Backend logs in JSON format (production)
- Frontend logs to browser console
- All logs include correlation IDs for tracing

## 🤝 API Integration

### For OAuth Clients

1. **Register your application** in the admin panel
2. **Implement OAuth flow**:

```javascript
// Authorization request
const authUrl = `https://auth.yourdomain.com/oauth/authorize?
  response_type=code&
  client_id=${CLIENT_ID}&
  redirect_uri=${REDIRECT_URI}&
  scope=openid profile email&
  state=${STATE}`;

// Token exchange
const tokenResponse = await fetch("https://auth.yourdomain.com/oauth/token", {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
    Authorization: `Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`,
  },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code: authorizationCode,
    redirect_uri: REDIRECT_URI,
  }),
});
```

### For Resource Servers

Validate tokens using introspection:

```go
resp, err := http.Post("https://auth.yourdomain.com/oauth/introspect",
    "application/x-www-form-urlencoded",
    strings.NewReader("token=" + accessToken))
```

## 🛠️ Troubleshooting

### Common Issues

1. **Cannot connect to database**

   - Check PostgreSQL is running: `docker ps`
   - Verify credentials in `.env`
   - Check network connectivity

2. **Frontend can't reach backend**

   - Verify `VITE_API_URL` is correct
   - Check CORS settings in backend
   - Ensure backend is running on expected port

3. **JWT errors**
   - Ensure RSA keys are generated
   - Check file permissions on key files
   - Verify key paths in configuration

### Debug Mode

Enable debug logging:

```bash
# Backend
export ORYXID_SERVER_MODE=debug

# Frontend
export VITE_ENABLE_DEBUG=true
```

## 📚 Documentation

- [Backend Documentation](./backend/README.md) - Detailed backend architecture and API reference
- [Frontend Documentation](./frontend/README.md) - Frontend development guide and component library
- [API Reference](./docs/api/README.md) - Complete API documentation with examples
- [Security Guide](./docs/security/README.md) - Security best practices and configurations

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Run tests: `make test`
5. Commit: `git commit -m 'Add amazing feature'`
6. Push: `git push origin feature/amazing-feature`
7. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Gin Web Framework](https://gin-gonic.com/) for the excellent Go web framework
- [React](https://react.dev/) for the UI library
- [Tailwind CSS](https://tailwindcss.com/) for the utility-first CSS framework
- [Radix UI](https://www.radix-ui.com/) for accessible component primitives
