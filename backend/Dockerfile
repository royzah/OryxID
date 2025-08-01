# syntax=docker/dockerfile:1

###############################################################################
# ——— Builder Stage: Go 1.21.13 on Debian Bullseye-Slim ————————————
###############################################################################
FROM golang:1.21.13-bullseye-slim AS builder

# Install build deps: git, certs, timezone data
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache modules install when go.mod/go.sum change
COPY go.mod go.sum ./
RUN go mod download

# Copy code and compile static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o oryxid ./cmd/server

###############################################################################
# ——— (Optional) Vulnerability Scan Stage ————————————————————————————
###############################################################################
FROM aquasec/trivy:latest AS trivy_scan
COPY --from=builder /build/oryxid /app/oryxid
# Fail build on any new CRITICAL or HIGH findings
RUN trivy fs --exit-code 1 --severity CRITICAL,HIGH --no-progress /app/oryxid

###############################################################################
# ——— Production Stage: Scratch —————————————————————————————————————
###############################################################################
FROM scratch AS production

# Copy CA certs so your app can make TLS calls if needed
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy only the static binary
COPY --from=builder /build/oryxid /oryxid

# Run as non-root (uid 65534 = nobody)
USER 65534:65534

# Expose your app port & add simple exec-style healthcheck
EXPOSE 9000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/oryxid", "--health"] || exit 1

ENTRYPOINT ["/oryxid"]
