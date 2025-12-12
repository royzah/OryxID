# OryxID TODO

## Essential Security
- [ ] Account lockout after failed login attempts
- [x] MFA/2FA support (TOTP)
- [ ] Password policies (complexity, expiration)

## Production Readiness
- [ ] OpenAPI/Swagger documentation
- [ ] Prometheus metrics endpoint
- [x] Helm chart for Kubernetes
- [x] TLS/HTTPS with Let's Encrypt support

## Quality
- [ ] Increase test coverage to >80%
- [x] Fix TypeScript errors in authorize and device pages

## Completed
- [x] OAuth 2.1 compliance (removed deprecated Implicit flow)
- [x] Docker Compose setup
- [x] Kubernetes Helm chart with PostgreSQL/Redis dependencies
- [x] Self-signed SSL for development
- [x] Let's Encrypt certificate automation
- [x] MFA with TOTP and backup codes
