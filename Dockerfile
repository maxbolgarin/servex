# Multi-stage build for optimal production image
FROM golang:1.26-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
ARG VERSION=dev
ARG BUILD_TIME
ARG GIT_COMMIT
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}" \
    -o servex ./cmd/servex

# Production image
FROM alpine:3.21

LABEL org.opencontainers.image.title="Servex" \
      org.opencontainers.image.description="Production-ready HTTP server, reverse proxy, and API gateway" \
      org.opencontainers.image.source="https://github.com/maxbolgarin/servex" \
      org.opencontainers.image.licenses="MIT"

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata curl

# Create non-root user
RUN addgroup -g 1000 servex && \
    adduser -D -s /bin/sh -u 1000 -G servex servex

# Create standard directories
RUN mkdir -p /etc/servex /etc/servex/certs /var/www/html /opt/servex && \
    chown -R servex:servex /etc/servex /var/www/html /opt/servex

# Copy binary from builder
COPY --from=builder /app/servex /usr/local/bin/servex

# Switch to non-root user
USER servex

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose default ports
EXPOSE 8080 8443

# Volumes for config and static files
VOLUME ["/etc/servex", "/var/www/html"]

# Environment variables with defaults
ENV SERVEX_SERVER_HTTP=":8080" \
    SERVEX_SERVER_HTTPS="" \
    SERVEX_SERVER_ENABLE_HEALTH_ENDPOINT="true"

# Default command — reads config from /etc/servex/servex.yaml
# If no config is mounted, falls back to environment variables
ENTRYPOINT ["servex", "-config", "/etc/servex/servex.yaml", "-daemon"]
