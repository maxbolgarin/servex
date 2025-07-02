# Multi-stage build for optimal production image
FROM golang:1.24-alpine AS builder

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
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}" \
    -o servex ./cmd/servex

# Production image
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata curl

# Create non-root user
RUN addgroup -g 1000 servex && \
    adduser -D -s /bin/sh -u 1000 -G servex servex

RUN mkdir -p /opt/servex && chown -R servex:servex /opt/servex


# Copy binary from builder
COPY --from=builder /app/servex /usr/local/bin/servex

# Switch to non-root user
USER servex

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose default ports
EXPOSE 8080 8443

# Environment variables with defaults
ENV SERVEX_SERVER_HTTP=":8080" \
    SERVEX_SERVER_HTTPS="" \
    SERVEX_SERVER_ENABLE_HEALTH_ENDPOINT="true"

# Default command
ENTRYPOINT ["servex"] 