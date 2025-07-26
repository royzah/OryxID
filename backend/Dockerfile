# Build stage
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -extldflags '-static'" \
    -o oryxid ./cmd/server

# Runtime stage
FROM alpine:latest

# Copy certificates from the builder stage
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy the binary from the builder stage to a system path
COPY --from=builder /build/oryxid /usr/local/bin/oryxid

# Switch to the non-root user
USER appuser

# Set the working directory (still useful for relative paths if any)
WORKDIR /app

# Expose the application port
EXPOSE 9000

# Run the application from its new location
ENTRYPOINT ["oryxid"]