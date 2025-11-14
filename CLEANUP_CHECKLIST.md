# OryxID Cleanup Checklist

## Phase 1: Critical Issues (Immediate)

- [ ] **Remove unused App.css**
  - File: `/home/user/OryxID/frontend/src/App.css`
  - Action: Delete file entirely
  - Impact: No visual changes (unused styles)
  - Command: `rm frontend/src/App.css`

- [ ] **Consolidate certificate files**
  - Action: Keep only `/certs/` directory
  - Delete: `/backend/certs/` and `/docker/certs/`
  - Update: `docker-compose.yml` volume mounts
  - Commands:
    ```bash
    rm -rf backend/certs docker/certs
    # Then update docker-compose.yml line 93:
    # volumes:
    #   - ./certs:/app/certs:ro
    ```

- [ ] **Add basic unit tests**
  - Backend: Add tests for `internal/auth/` and `internal/tokens/`
  - Frontend: Add tests for authentication store
  - Example: `backend/internal/auth/middleware_test.go`

- [ ] **Merge .env.example files**
  - Action: Update root `.env.example` with all variables
  - Delete: `backend/.env.example`
  - Ensure: Clear documentation of what each variable does
  - Keep structure clear with section comments

- [ ] **Fix backend health check**
  - Issue: Docker compose calls `/oryxid --health` but no implementation
  - Options:
    A. Implement actual `--health` flag in backend
    B. Change health check to call `/health` endpoint
    C. Remove health check from docker-compose for backend

## Phase 2: High Priority (This Sprint)

- [ ] **Deprecate setup.sh**
  - Action: Add note in README directing to `make setup`
  - Keep file but mark as deprecated
  - Consider: Delete in next major version

- [ ] **Fix Dockerfile fallback**
  - File: `/frontend/Dockerfile` line 35
  - Current: `RUN npx vite build || npm run build`
  - Change to: `RUN npm run build`
  - Reason: `npm run build` already calls `tsc -b && vite build`

- [ ] **Refactor CSS utilities**
  - File: `/frontend/src/index.css`
  - Remove custom classes that duplicate Tailwind:
    - `.bg-background`, `.text-foreground`, `.bg-card`, etc.
  - Keep: Custom animations, scrollbar, focus styles
  - Alternative: Move to Tailwind config if needed frequently

- [ ] **Create CONTRIBUTING.md**
  - Include: Development workflow, git conventions
  - Include: How to run tests, linting
  - Include: PR process and review guidelines
  - Template available in many repos

- [ ] **Fix environment variable inconsistency**
  - Review actual environment variables used in:
    - `/backend/internal/config/config.go`
    - `/frontend/.env` handling
  - Document naming convention clearly
  - Update examples accordingly

## Phase 3: Medium Priority (Nice to Have)

- [ ] **Add ESLint/Prettier pre-commit hooks**
  - Tool: `husky` for git hooks
  - Implementation:
    ```bash
    npm install husky -D
    npx husky install
    npx husky add .husky/pre-commit "npm run lint:fix && npm run format"
    ```

- [ ] **Create documentation directory**
  - Structure:
    ```
    docs/
    ├── API.md (endpoint reference)
    ├── ARCHITECTURE.md (system design)
    ├── SECURITY.md (best practices)
    ├── DEPLOYMENT.md (production guide)
    └── TROUBLESHOOTING.md (common issues)
    ```

- [ ] **Add test configuration**
  - Frontend: Set up Vitest or Jest
  - Backend: Document test running
  - CI/CD: Configure to run tests

- [ ] **Create CHANGELOG.md**
  - Track: Version history, features, bugs
  - Format: Keep a Changelog standard
  - Automation: Consider auto-generation from git tags

## Phase 4: Low Priority (Optimization)

- [ ] **Optimize Docker images**
  - Frontend: Consider multi-stage with better caching
  - Backend: Already well-optimized with `scratch`
  - Measure: Compare image sizes before/after

- [ ] **Add Swagger/OpenAPI**
  - Tool: `github.com/swaggo/swag` for Go
  - Benefit: Interactive API documentation
  - Location: `/swagger/*` endpoint

- [ ] **Improve error handling**
  - Standardize: Error response format
  - Document: Common error codes
  - Frontend: Consistent error display

- [ ] **Add monitoring/telemetry**
  - Backend: Already has `/metrics` endpoint
  - Consider: Adding trace IDs, request logging
  - Tools: Prometheus, OpenTelemetry

## Files to Review/Update

### Core Files
- [ ] `/home/user/OryxID/README.md` - Link to new docs
- [ ] `/home/user/OryxID/.env.example` - Consolidate variables
- [ ] `/home/user/OryxID/docker-compose.yml` - Update volume mounts
- [ ] `/home/user/OryxID/Makefile` - Already comprehensive

### Frontend
- [ ] `/frontend/src/App.css` - DELETE
- [ ] `/frontend/src/index.css` - Refactor CSS utilities
- [ ] `/frontend/package.json` - Already clean
- [ ] `/frontend/vite.config.ts` - Already clean

### Backend
- [ ] `/backend/.env.example` - DELETE (merge to root)
- [ ] `/backend/Dockerfile` - Minor improvements
- [ ] `/backend/cmd/server/main.go` - Add health check logic
- [ ] `/backend/internal/config/config.go` - Ensure all vars documented

### Docker
- [ ] `/docker-compose.yml` - Update certificate mounts
- [ ] `/docker/nginx/conf.d/default.conf` - Already good
- [ ] `/backend/certs/` - DELETE
- [ ] `/docker/certs/` - DELETE

## Success Criteria

- [ ] No unused CSS in frontend
- [ ] All certificate files in single location
- [ ] 100% environment variables consistency
- [ ] At least one test file created
- [ ] Documentation structure clear
- [ ] No deprecation warnings in build
- [ ] docker-compose health checks work
- [ ] Setup is only done via `make setup`

## Time Estimates

| Phase | Tasks | Estimated Time |
|-------|-------|-----------------|
| Phase 1 | 5 items | 4-6 hours |
| Phase 2 | 5 items | 6-8 hours |
| Phase 3 | 4 items | 6-10 hours |
| Phase 4 | 4 items | 8-12 hours |
| **Total** | **18 items** | **24-36 hours** |

## Notes

- Do Phase 1 in one sitting to avoid conflicts
- Phase 2 can be split across sprint(s)
- Phase 3 & 4 are ongoing improvements
- Always commit each logical change separately
- Run full test suite after major changes
- Update PR template if any is added

