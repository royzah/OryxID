# OryxID - OAuth2/OpenID Connect Server

Production-ready OAuth2 and OpenID Connect server with enterprise-grade security and modern admin interface.

## Architecture

```mermaid
graph TB
    Client[Client Application]
    Browser[Web Browser]
    Nginx[Nginx Reverse Proxy<br/>Port 8080]
    Frontend[React Frontend<br/>Port 3000]
    Backend[Go Backend<br/>Port 9000]
    DB[(PostgreSQL<br/>Port 5432)]
    Redis[(Redis Cache<br/>Port 6379)]

    Browser --> Nginx
    Client --> Nginx
    Nginx --> Frontend
    Nginx --> Backend
    Backend --> DB
    Backend --> Redis
    Frontend --> Backend

    style Nginx fill:#4CAF50
    style Backend fill:#00ADD8
    style Frontend fill:#61DAFB
    style DB fill:#336791
    style Redis fill:#DC382D
```

## OAuth2 Flows

```mermaid
sequenceDiagram
    participant Client
    participant Auth as Authorization Server
    participant Resource as Resource Server

    Note over Client,Resource: Authorization Code Flow with PKCE

    Client->>Client: Generate code_verifier & code_challenge
    Client->>Auth: GET /oauth/authorize?response_type=code&client_id=X&code_challenge=Y
    Auth->>Client: Authorization Code
    Client->>Auth: POST /oauth/token (code + code_verifier)
    Auth->>Client: Access Token + Refresh Token + ID Token
    Client->>Resource: API Request (Bearer Token)
    Resource->>Auth: Validate Token (Introspection)
    Auth->>Resource: Token Valid
    Resource->>Client: Protected Resource
```

```mermaid
sequenceDiagram
    participant Client
    participant Auth as Authorization Server

    Note over Client,Auth: Pushed Authorization Request (PAR)

    Client->>Auth: POST /oauth/par (all params + PKCE)
    Auth->>Client: request_uri + expires_in
    Client->>Client: Redirect user to authorization
    Client->>Auth: GET /oauth/authorize?client_id=X&request_uri=urn:...
    Auth->>Auth: Load params from PAR
    Auth->>Client: Authorization Code
    Client->>Auth: POST /oauth/token
    Auth->>Client: Tokens
```

## Security Features

### OAuth 2.1 Compliance
- PKCE with S256 (plain method rejected)
- Refresh token rotation (old tokens immediately revoked)
- Access token revocation enforcement
- No implicit flow
- Secure token storage (bcrypt hashing)

### OpenID Connect 1.0
- ID tokens with all required claims
- email_verified claim support
- UserInfo endpoint
- Discovery endpoint (/.well-known/openid-configuration)
- JWKS endpoint (/.well-known/jwks.json)

### Advanced Security
- **PAR (RFC 9126)**: Pushed Authorization Requests prevent parameter tampering
- **private_key_jwt (RFC 7523)**: Asymmetric client authentication
- **Scope Downscaling**: Request fewer permissions on token refresh
- **Rate Limiting**: Configurable per-endpoint protection
- **CSRF Protection**: Token-based protection for admin interface

## Port Configuration

| Service | Internal Port | External Port | Purpose |
|---------|--------------|---------------|---------|
| Nginx | 80 | 8080 | Reverse proxy (main entry point) |
| Backend | 9000 | 9000 | API server (direct access for testing) |
| Frontend | 3000 | 3000 | React dev server (development only) |
| PostgreSQL | 5432 | 5432 | Database |
| Redis | 6379 | 6379 | Cache |

**Production Access**: Use http://localhost:8080 (Nginx proxy)
**Development API**: http://localhost:9000 (backend direct)
**Development UI**: http://localhost:3000 (frontend direct)

## Testing Locally

### Prerequisites
- Go 1.21+
- Node.js 20+
- PostgreSQL 16+
- Redis 7+

### Backend Testing

```bash
# Install dependencies
cd backend
go mod download

# Run unit tests
go test -v ./...

# Run tests with coverage
go test -v ./... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Run specific package tests
go test -v ./internal/oauth/...

# Run with race detection
go test -race ./...

# Benchmark tests
go test -bench=. ./...
```

### Frontend Testing

```bash
cd frontend

# Install dependencies
npm install

# Run unit tests
npm test

# Run tests with coverage
npm test -- --coverage

# Run in watch mode
npm test -- --watch

# E2E tests (if configured)
npm run test:e2e
```

### Integration Testing

```bash
# Start all services
make dev

# Run integration tests
make test-integration

# Test OAuth flows
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_SECRET"
```

## Testing with Docker

### Quick Test

```bash
# Build and run all services
make setup
make dev

# Check service health
make health

# View logs
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f nginx
```

### Test Endpoints

```bash
# Test discovery endpoint
curl http://localhost:8080/.well-known/openid-configuration | jq

# Test JWKS endpoint
curl http://localhost:8080/.well-known/jwks.json | jq

# Test PAR endpoint
curl -X POST http://localhost:8080/oauth/par \
  -u "client_id:client_secret" \
  -d "response_type=code" \
  -d "redirect_uri=https://example.com/callback" \
  -d "scope=openid profile" \
  -d "code_challenge=CHALLENGE" \
  -d "code_challenge_method=S256"

# Test token introspection
curl -X POST http://localhost:8080/oauth/introspect \
  -u "client_id:client_secret" \
  -d "token=ACCESS_TOKEN"

# Test token revocation
curl -X POST http://localhost:8080/oauth/revoke \
  -u "client_id:client_secret" \
  -d "token=REFRESH_TOKEN"
```

### Docker Compose Profiles

```bash
# Development mode (hot reload enabled)
FRONTEND_BUILD_TARGET=development docker-compose up -d

# Production mode (optimized builds)
FRONTEND_BUILD_TARGET=production docker-compose up -d

# Rebuild specific service
docker-compose build backend
docker-compose up -d backend

# Clean rebuild
docker-compose down -v
make clean
make setup
make dev
```

## Cloud Deployment

### Architecture Best Practices

```mermaid
graph TB
    LB[Load Balancer<br/>AWS ALB / GCP LB]
    CDN[CDN<br/>CloudFront / CloudFlare]

    subgraph "Compute Tier"
        App1[OryxID Instance 1]
        App2[OryxID Instance 2]
        App3[OryxID Instance N]
    end

    subgraph "Data Tier"
        RDS[(Managed PostgreSQL<br/>RDS / Cloud SQL)]
        Cache[(Managed Redis<br/>ElastiCache / Memorystore)]
    end

    subgraph "Storage"
        S3[Object Storage<br/>S3 / GCS]
    end

    LB --> CDN
    CDN --> App1
    CDN --> App2
    CDN --> App3

    App1 --> RDS
    App2 --> RDS
    App3 --> RDS

    App1 --> Cache
    App2 --> Cache
    App3 --> Cache

    App1 --> S3
    App2 --> S3
    App3 --> S3

    style LB fill:#FF9800
    style CDN fill:#2196F3
    style RDS fill:#336791
    style Cache fill:#DC382D
```

### AWS Deployment

#### Option 1: ECS Fargate (Recommended)

```yaml
# task-definition.json
{
  "family": "oryxid",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [
    {
      "name": "backend",
      "image": "YOUR_ECR_REPO/oryxid-backend:latest",
      "portMappings": [{"containerPort": 9000}],
      "environment": [
        {"name": "DATABASE_URL", "value": "postgres://..."},
        {"name": "REDIS_URL", "value": "redis://..."}
      ],
      "secrets": [
        {"name": "JWT_PRIVATE_KEY", "valueFrom": "arn:aws:secretsmanager:..."}
      ]
    }
  ]
}
```

**Infrastructure Requirements**:
- VPC with private and public subnets
- Application Load Balancer
- RDS PostgreSQL (Multi-AZ)
- ElastiCache Redis (Cluster mode)
- ECR for container images
- Secrets Manager for sensitive data
- CloudWatch for logging/monitoring

**Scaling Configuration**:
```bash
# Auto-scaling based on CPU
aws application-autoscaling put-scaling-policy \
  --service-namespace ecs \
  --scalable-dimension ecs:service:DesiredCount \
  --resource-id service/oryxid-cluster/oryxid-service \
  --policy-name cpu-scaling \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration file://scaling-policy.json
```

#### Option 2: EKS (Kubernetes)

```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oryxid-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: oryxid-backend
  template:
    metadata:
      labels:
        app: oryxid-backend
    spec:
      containers:
      - name: backend
        image: YOUR_ECR_REPO/oryxid-backend:latest
        ports:
        - containerPort: 9000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: oryxid-secrets
              key: database-url
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 9000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 9000
          initialDelaySeconds: 10
          periodSeconds: 5
```

### GCP Deployment

#### Cloud Run (Serverless)

```bash
# Build and push
gcloud builds submit --tag gcr.io/PROJECT_ID/oryxid-backend

# Deploy backend
gcloud run deploy oryxid-backend \
  --image gcr.io/PROJECT_ID/oryxid-backend \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars DATABASE_URL=postgresql://... \
  --set-secrets JWT_PRIVATE_KEY=jwt-key:latest \
  --min-instances 1 \
  --max-instances 10 \
  --cpu 2 \
  --memory 2Gi

# Deploy frontend
gcloud run deploy oryxid-frontend \
  --image gcr.io/PROJECT_ID/oryxid-frontend \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated

# Setup load balancer
gcloud compute backend-services create oryxid-backend-service \
  --global \
  --load-balancing-scheme=EXTERNAL
```

**Infrastructure**:
- Cloud SQL (PostgreSQL)
- Memorystore (Redis)
- Cloud Storage (static assets)
- Secret Manager (credentials)
- Cloud Monitoring & Logging

### Azure Deployment

#### Container Instances

```bash
# Create resource group
az group create --name oryxid-rg --location eastus

# Create container registry
az acr create --resource-group oryxid-rg --name oryxidacr --sku Basic

# Build and push
az acr build --registry oryxidacr --image oryxid-backend:latest ./backend

# Deploy to Container Instances
az container create \
  --resource-group oryxid-rg \
  --name oryxid-backend \
  --image oryxidacr.azurecr.io/oryxid-backend:latest \
  --cpu 2 \
  --memory 4 \
  --registry-login-server oryxidacr.azurecr.io \
  --registry-username $(az acr credential show --name oryxidacr --query username -o tsv) \
  --registry-password $(az acr credential show --name oryxidacr --query passwords[0].value -o tsv) \
  --dns-name-label oryxid-backend \
  --ports 9000 \
  --environment-variables \
    DATABASE_URL=postgresql://... \
    REDIS_URL=redis://... \
  --secure-environment-variables \
    JWT_PRIVATE_KEY=$(cat private_key.pem)
```

### Environment Variables

```bash
# Required
DATABASE_URL=postgresql://user:pass@host:5432/oryxid
REDIS_URL=redis://host:6379
JWT_PRIVATE_KEY_PATH=/app/certs/private_key.pem
JWT_PUBLIC_KEY_PATH=/app/certs/public_key.pem
BASE_URL=https://auth.yourdomain.com

# Optional
PORT=9000
FRONTEND_PORT=3000
SECURITY_RATE_LIMIT_ENABLED=true
SECURITY_RATE_LIMIT_REQUESTS_PER_MINUTE=60
SECURITY_CSRF_ENABLED=true
LOG_LEVEL=info
```

### SSL/TLS Configuration

#### Let's Encrypt with Certbot

```bash
# Install certbot
apt-get install certbot python3-certbot-nginx

# Obtain certificate
certbot --nginx -d auth.yourdomain.com

# Auto-renewal (add to crontab)
0 0 * * * certbot renew --quiet
```

#### Nginx SSL Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://frontend:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/ {
        proxy_pass http://backend:9000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /oauth/ {
        proxy_pass http://backend:9000/oauth/;
        proxy_set_header Host $host;
    }
}
```

### Monitoring & Observability

```bash
# Prometheus metrics endpoint
curl http://localhost:9000/metrics

# Health check endpoint
curl http://localhost:9000/health

# Readiness check
curl http://localhost:9000/ready
```

#### CloudWatch Alarms (AWS)

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name oryxid-high-cpu \
  --alarm-description "Alert when CPU exceeds 80%" \
  --metric-name CPUUtilization \
  --namespace AWS/ECS \
  --statistic Average \
  --period 300 \
  --evaluation-periods 2 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold
```

### Backup Strategy

```bash
# PostgreSQL backup (daily)
pg_dump -h localhost -U oryxid oryxid > backup_$(date +%Y%m%d).sql

# Upload to S3
aws s3 cp backup_$(date +%Y%m%d).sql s3://oryxid-backups/

# Retention policy (keep 30 days)
aws s3 ls s3://oryxid-backups/ | while read -r line; do
    createDate=$(echo $line|awk {'print $1" "$2'})
    createDate=$(date -d "$createDate" +%s)
    olderThan=$(date -d "30 days ago" +%s)
    if [[ $createDate -lt $olderThan ]]; then
        fileName=$(echo $line|awk {'print $4'})
        aws s3 rm s3://oryxid-backups/$fileName
    fi
done
```

### Performance Optimization

```bash
# Database connection pooling
MAX_OPEN_CONNS=100
MAX_IDLE_CONNS=10
CONN_MAX_LIFETIME=1h

# Redis connection pooling
REDIS_POOL_SIZE=10
REDIS_MIN_IDLE_CONNS=5

# Enable Gzip compression in Nginx
gzip on;
gzip_vary on;
gzip_min_length 1024;
gzip_types text/plain text/css application/json application/javascript;

# HTTP/2 Server Push
location / {
    http2_push /static/css/main.css;
    http2_push /static/js/main.js;
}
```

## Future Roadmap

### Key Rotation Management
**Status**: Database models ready, API implementation pending
**Complexity**: Medium
**Timeline**: 2-3 weeks

Enables zero-downtime RSA key rotation for JWT signing:
- Multiple active signing keys
- Automatic key expiration
- JWKS endpoint serves all valid public keys
- Gradual rollover process (new key signs, old keys verify)
- Admin UI for key lifecycle management

**Implementation**:
```go
// Rotate to new key
POST /api/v1/keys/rotate
{
  "algorithm": "RS256",
  "expires_in_days": 90
}

// List all keys
GET /api/v1/keys

// Revoke compromised key
POST /api/v1/keys/{kid}/revoke
```

### DPoP Token Binding (RFC 9449)
**Status**: Not started
**Complexity**: High
**Timeline**: 4-6 weeks

Binds tokens to specific devices using proof-of-possession:
- Prevents token replay attacks
- Mobile app and SPA security enhancement
- Client generates key pair per device
- Tokens bound to public key fingerprint
- Server validates DPoP proof on each request

**Benefits**:
- Stolen tokens unusable without private key
- Network eavesdropping protection
- Phishing attack mitigation

**Implementation**:
```http
POST /oauth/token
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik...

Response:
{
  "access_token": "...",
  "token_type": "DPoP",
  "expires_in": 3600
}

GET /api/resource
Authorization: DPoP ACCESS_TOKEN
DPoP: PROOF_JWT
```

### Client Initiated Backchannel Authentication (CIBA)
**Status**: Not started
**Complexity**: High
**Timeline**: 6-8 weeks

Out-of-band authentication for decoupled devices:
- QR code scanning
- Mobile app push notifications
- Banking-grade authentication
- Ping, poll, and push modes

**Use Cases**:
- Smart TV login via phone
- ATM authentication
- Point-of-sale authorization
- Secure transaction approval

**Flow**:
```mermaid
sequenceDiagram
    participant Client as Consumption Device
    participant Auth as Auth Server
    participant App as Authentication Device

    Client->>Auth: POST /backchannel/authenticate
    Auth->>App: Push notification
    Auth->>Client: auth_req_id
    Client->>Auth: Poll for result
    App->>Auth: User approves
    Auth->>Client: Tokens
```

### Device Authorization Flow (RFC 8628)
**Status**: Not started
**Complexity**: Medium
**Timeline**: 3-4 weeks

For input-constrained devices (smart TVs, IoT):
- Display short user code
- User visits verification URL
- Polls for authorization
- No redirect required

**Implementation**:
```http
POST /oauth/device
{
  "client_id": "smart_tv_app"
}

Response:
{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://auth.example.com/device",
  "expires_in": 1800,
  "interval": 5
}
```

### Additional Testing
**Status**: In progress (70% coverage)
**Complexity**: Medium
**Timeline**: Ongoing

**Planned Test Suites**:

1. **Handler Tests** (0% coverage)
   - HTTP endpoint testing
   - Request/response validation
   - Error handling verification
   - Authentication middleware tests

2. **Integration Tests** (0% coverage)
   - Full OAuth flows end-to-end
   - Database interaction tests
   - Redis caching tests
   - Multi-service integration

3. **Security Tests**
   - PKCE validation comprehensive suite
   - Token replay prevention
   - Rate limiting effectiveness
   - CSRF protection validation
   - SQL injection prevention
   - XSS prevention

4. **Performance Tests**
   - Load testing (1000+ req/s)
   - Concurrent user simulation
   - Memory leak detection
   - Database query optimization

5. **E2E Tests**
   - Browser automation (Playwright/Cypress)
   - Complete user journeys
   - Admin interface testing
   - Mobile responsiveness

**Testing Tools**:
- Unit: Go testing, testify
- Integration: Ginkgo, Gomega
- HTTP: httptest, gin test mode
- Database: testcontainers-go
- Load: k6, vegeta
- E2E: Playwright

## Make Commands Reference

```bash
# Setup & Development
make setup          # Initialize project (generate certs, download deps)
make dev            # Start development environment
make prod           # Start production environment
make stop           # Stop all containers
make restart        # Restart all containers
make clean          # Remove containers, volumes, and generated files

# Building
make build          # Build all Docker images
make build-backend  # Build backend only
make build-frontend # Build frontend only
make rebuild        # Clean build all images
make rebuild-backend # Clean build backend

# Database
make db-migrate     # Run database migrations
make db-seed        # Seed database with sample data
make db-reset       # Reset database (drop + migrate + seed)
make db-shell       # Open PostgreSQL shell
make db-backup      # Backup database
make db-restore     # Restore database from backup

# Testing
make test           # Run all tests
make test-backend   # Run backend tests
make test-frontend  # Run frontend tests
make test-integration # Run integration tests
make coverage       # Generate coverage report

# Logs & Monitoring
make logs           # Show all logs
make logs-backend   # Show backend logs
make logs-frontend  # Show frontend logs
make logs-db        # Show database logs
make health         # Check service health

# Maintenance
make lint           # Run linters
make fmt            # Format code
make security-scan  # Run security scanners
make deps-update    # Update dependencies
make certs-renew    # Regenerate JWT certificates
```

## License

Apache License 2.0

## Contributing

Contributions welcome. Please follow standard Go and React conventions.

## Support

For issues and questions, open a GitHub issue.
