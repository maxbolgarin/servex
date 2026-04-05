# Servex Standalone Server

Use servex as a standalone HTTP server, reverse proxy, and API gateway — no Go code required. Configure everything with YAML and environment variables, like Caddy or Nginx.

For using servex as a Go library, see the main [README](../README.md).

## Installation

### Go Install

```bash
go install github.com/maxbolgarin/servex/v2/cmd/servex@latest
```

### Docker

```bash
docker pull maxbolgarin/servex
```

### Build from Source

```bash
git clone https://github.com/maxbolgarin/servex.git
cd servex
make build
# Binary: bin/servex
```

## Quick Start

```bash
# Start with a built-in preset — no config file needed
servex -preset production -port 8080

# Serve a static site / SPA
servex -preset spa -static-dir ./dist -port 8080

# Start an API server with CORS, rate limiting, compression
servex -preset api -port 3000

# Or use a config file
servex -config server.yaml

# Generate a sample config to customize
servex -generate
```

## CLI Reference

```
servex [OPTIONS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `-config` | `-c` | `servex.yaml` | Path to configuration file |
| `-env-file` | | | Path to `.env` file |
| `-port` | `-p` | | HTTP port override |
| `-https-port` | | | HTTPS port override |
| `-preset` | | | Use a built-in preset (see Presets below) |
| `-static-dir` | | `/var/www/html` | Static files directory (for `spa`/`static` presets) |
| `-log-level` | | | Log level: `debug`, `info`, `warn`, `error` |
| `-log-format` | | | Log format: `json`, `text` |
| `-version` | `-v` | | Show version information |
| `-validate` | | | Validate configuration and exit |
| `-generate` | `-g` | | Generate sample configuration |
| `-type` | | `yaml` | Config type for generation: `yaml`, `env` |
| `-dry-run` | | | Show configuration without starting |
| `-health-check` | | | Perform health check and exit |
| `-verbose` | | | Enable verbose output |
| `-daemon` | | | Run as daemon (disable interactive features) |

### Commands

```bash
# Start with a preset (no config needed)
servex -preset production -port 8080
servex -preset api -port 3000
servex -preset spa -static-dir ./dist -port 8080

# Preset + config (preset as base, config overrides on top)
servex -preset production -config overrides.yaml

# Start with config file
servex -config production.yaml

# Validate config without starting
servex -validate -config production.yaml

# Preview what would run
servex -dry-run -config production.yaml

# Generate sample configs
servex -generate -type yaml    # creates servex.yaml
servex -generate -type env     # creates .env.example

# Health check (useful for Docker/k8s probes)
servex -health-check
```

### Config File Search Order

When no `-config` flag is provided, servex searches for:

1. `servex.yaml`
2. `servex.yml`
3. `server.yaml`
4. `server.yml`
5. `config.yaml`
6. `config.yml`

If no file is found, servex falls back to environment variables only.

## Presets

Start a production-ready server instantly with `-preset` — no config file required:

```bash
servex -preset production -port 8080
```

| Preset | Aliases | What You Get |
|--------|---------|-------------|
| `production` | `prod` | Strict security headers, CSRF, rate limiting (100 rps), compression, health/metrics, audit logging |
| `api` | | CORS, rate limiting (1000 rpm, burst 50), compression, 10 MB body / 1 MB JSON limits, API caching (5 min) |
| `webapp` | `web` | Strict security, CSRF, web-friendly CSP, 50 MB uploads, compression, rate limiting (50 rps) |
| `microservice` | `micro` | Fast timeouts (5s read, 30s idle), basic security, 5 MB body limit, 200 rps rate limiting |
| `security` | `secure` | Strict security, CSRF, bot filtering, aggressive rate limiting (20 rps, burst 5), full audit logging |
| `spa` | | SPA mode (index.html fallback), compression, 1-year asset cache, security headers, rate limiting |
| `static` | | Static file server, compression, 1-year asset cache, security headers |
| `scanner` | | Block vulnerability scanners, dotfile probes, and common attack paths. Combine with other presets. |

All presets include health endpoint (`/health`) and metrics (`/metrics`).

### Combining Presets with Config

Presets provide the base, YAML config overrides on top:

```bash
# Start with production preset, customize rate limiting via config
servex -preset production -config overrides.yaml
```

```yaml
# overrides.yaml — only set what you want to change
rate_limit:
  requests_per_interval: 500
  interval: "1m"

cors:
  enabled: true
  allow_origins:
    - "https://myapp.com"
```

### Scanner / Probe Blocking

Block common vulnerability scanners and attack paths:

```yaml
# Scanner / probe blocking via YAML config
filter:
  blocked_path_prefixes:
    - "/."
    - "/wp-"
    - "/actuator"
    - "/cgi-bin"
    - "/xmlrpc.php"
  blocked_path_patterns:
    - "(?i)/phpmyadmin"
  status_code: 404
  message: ""
```

### Docker with Presets

```bash
# Production API — zero config
docker run -p 8080:8080 -e SERVEX_SERVER_HTTP=:8080 maxbolgarin/servex servex -preset api -port 8080

# SPA with mounted files
docker run -p 8080:8080 -v ./dist:/var/www/html:ro maxbolgarin/servex servex -preset spa -port 8080
```

## Configuration

### Configuration Sources

Configuration is loaded from multiple sources with this precedence (highest first):

1. **CLI flags** — `-port`, `-https-port`
2. **Environment variables** — `SERVEX_*` prefix
3. **YAML config file**
4. **Defaults**

### Environment Variables

All config fields have corresponding environment variables. The pattern is `SERVEX_SECTION_FIELD`:

```bash
# Server
SERVEX_SERVER_HTTP=":8080"
SERVEX_SERVER_HTTPS=":8443"
SERVEX_SERVER_CERT_FILE="/path/to/cert.pem"
SERVEX_SERVER_KEY_FILE="/path/to/key.pem"
SERVEX_SERVER_READ_TIMEOUT="30s"
SERVEX_SERVER_IDLE_TIMEOUT="120s"
SERVEX_SERVER_ENABLE_HEALTH_ENDPOINT="true"
SERVEX_SERVER_ENABLE_DEFAULT_METRICS="true"

# Auth
SERVEX_AUTH_ENABLED="true"
SERVEX_AUTH_JWT_ACCESS_SECRET="hex-encoded-32-byte-key"
SERVEX_AUTH_JWT_REFRESH_SECRET="hex-encoded-32-byte-key"
SERVEX_AUTH_USE_MEMORY_DATABASE="true"

# Rate limiting
SERVEX_RATE_LIMIT_ENABLED="true"
SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL="100"
SERVEX_RATE_LIMIT_INTERVAL="1m"
SERVEX_RATE_LIMIT_BURST_SIZE="20"

# Security
SERVEX_SECURITY_ENABLED="true"

# Compression
SERVEX_COMPRESSION_ENABLED="true"
```

For the complete list of environment variables, see [server_docs.yaml](server_docs.yaml).

### YAML Configuration Sections

The YAML config has 13 top-level sections. Each section is optional — only configure what you need.

| Section | Description |
|---------|-------------|
| `server` | HTTP/HTTPS listeners, timeouts, size limits, health/metrics endpoints |
| `auth` | JWT authentication, email verification, password reset, OAuth, 2FA |
| `rate_limit` | Per-IP rate limiting with burst, path exclusions |
| `filter` | Request filtering by IP, User-Agent, headers, query params |
| `security` | Security headers (CSP, HSTS, X-Frame-Options), CSRF protection |
| `cache` | Cache-Control, ETag, Last-Modified headers |
| `compression` | Gzip compression with level, min size, content type filters |
| `logging` | Request logging fields, client error suppression |
| `cors` | Cross-Origin Resource Sharing |
| `static_files` | Static file serving, SPA mode, per-extension caching |
| `proxy` | Reverse proxy with load balancing, health checks, traffic dumping |
| `swagger` | Swagger UI for OpenAPI spec |
| `websocket` | WebSocket connection parameters |

For the full YAML reference with all fields, defaults, and environment variable names, see [server_docs.yaml](server_docs.yaml).

### Default Values

| Setting | Default |
|---------|---------|
| Read timeout | 60s |
| Idle timeout | 180s |
| Max header size | 1 MB |
| Health path | `/health` |
| Metrics path | `/metrics` |
| Proxy global timeout | 30s |
| Proxy max idle conns | 100 |
| Rate limit status code | 429 |
| WebSocket max message | 32 KB |
| WebSocket ping interval | 30s |
| CORS max age | 3600s |
| Access token duration | 5m |
| Refresh token duration | 7d |

## Examples

### Reverse Proxy / API Gateway

Route requests to backend services with load balancing:

```yaml
server:
  http: ":8080"
  enable_health_endpoint: true

rate_limit:
  enabled: true
  requests_per_interval: 1000
  interval: "1m"
  burst_size: 50

compression:
  enabled: true
  level: 6

proxy:
  enabled: true
  global_timeout: "30s"
  health_check:
    enabled: true
    default_interval: "30s"
  rules:
    - name: "api"
      path_prefix: "/api/"
      strip_prefix: "/api"
      load_balancing: "round_robin"
      backends:
        - url: "http://api-server-1:3000"
          health_check_path: "/health"
        - url: "http://api-server-2:3000"
          health_check_path: "/health"
    - name: "auth"
      path_prefix: "/auth/"
      strip_prefix: "/auth"
      backends:
        - url: "http://auth-service:4000"
```

Load balancing strategies: `round_robin`, `weighted_round_robin`, `least_connections`, `random`, `weighted_random`, `ip_hash`.

Full example: [examples/standalone/reverse-proxy.yaml](../examples/standalone/reverse-proxy.yaml)

### Static File Server / SPA

Serve a React/Vue/Angular app with SPA routing:

```yaml
server:
  http: ":8080"

compression:
  enabled: true
  level: 6

static_files:
  enabled: true
  dir: "/var/www/html"
  spa_mode: true
  index_file: "index.html"
  cache_max_age: 3600
  cache_rules:
    ".js": 31536000     # 1 year for hashed assets
    ".css": 31536000
    "index.html": 0     # never cache entry point
```

Full example: [examples/standalone/static-site.yaml](../examples/standalone/static-site.yaml)

### API Server with Auth

JWT authentication with built-in endpoints:

```yaml
server:
  http: ":8080"
  enable_request_size_limits: true
  max_json_body_size: 1048576

auth:
  enabled: true
  use_memory_database: true
  # Set via env: SERVEX_AUTH_JWT_ACCESS_SECRET, SERVEX_AUTH_JWT_REFRESH_SECRET
  access_token_duration: "15m"
  refresh_token_duration: "720h"
  base_path: "/api/v1/auth"
  initial_roles: ["user"]

rate_limit:
  enabled: true
  requests_per_interval: 100
  interval: "1m"

security:
  enabled: true
  x_frame_options: "DENY"
  x_content_type_options: "nosniff"
```

This auto-registers auth endpoints at `/api/v1/auth/`:
- `POST /register` — create user
- `POST /login` — authenticate
- `POST /refresh` — refresh token
- `POST /logout` — invalidate session
- `GET /me` — current user info

> **Note:** Standalone mode uses an in-memory database. Data is lost on restart. For persistent storage, implement `AuthDatabase` in Go using the library API.

### Combined Setup

See [examples/standalone/full-server.yaml](../examples/standalone/full-server.yaml) for a complete configuration combining reverse proxy, static files, auth, rate limiting, security headers, CORS, and compression.

## Docker Usage

### Quick Start

```bash
# Run with defaults (health endpoint on :8080)
docker run -p 8080:8080 maxbolgarin/servex

# Run with your config
docker run -p 8080:8080 \
  -v ./my-config.yaml:/etc/servex/servex.yaml:ro \
  maxbolgarin/servex

# Run with static files
docker run -p 8080:8080 \
  -v ./config.yaml:/etc/servex/servex.yaml:ro \
  -v ./dist:/var/www/html:ro \
  maxbolgarin/servex
```

### Building a Custom Image

Use servex as a base image, like `FROM nginx`:

```dockerfile
FROM maxbolgarin/servex:latest

# Copy your config
COPY servex.yaml /etc/servex/servex.yaml

# Copy static files (if serving a frontend)
COPY dist/ /var/www/html/

# Copy TLS certificates (if using HTTPS)
# COPY certs/ /etc/servex/certs/
```

Build and run:

```bash
docker build -t my-app .
docker run -p 8080:8080 my-app
```

### Docker Compose

**Reverse proxy:**

```yaml
services:
  servex:
    image: maxbolgarin/servex:latest
    ports:
      - "8080:8080"
    volumes:
      - ./servex.yaml:/etc/servex/servex.yaml:ro
    restart: unless-stopped
```

**Static site:**

```yaml
services:
  servex:
    image: maxbolgarin/servex:latest
    ports:
      - "8080:8080"
    volumes:
      - ./servex.yaml:/etc/servex/servex.yaml:ro
      - ./dist:/var/www/html:ro
    restart: unless-stopped
```

**Full setup with backend:**

```yaml
services:
  servex:
    image: maxbolgarin/servex:latest
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - ./servex.yaml:/etc/servex/servex.yaml:ro
      - ./dist:/var/www/html:ro
      - ./certs:/etc/servex/certs:ro
    environment:
      - SERVEX_AUTH_JWT_ACCESS_SECRET=your-hex-key
      - SERVEX_AUTH_JWT_REFRESH_SECRET=your-hex-key
    depends_on:
      backend:
        condition: service_healthy
    restart: unless-stopped

  backend:
    image: your-backend:latest
    expose:
      - "3000"
    restart: unless-stopped
```

Complete docker-compose examples: [examples/standalone/](../examples/standalone/)

### Container Directory Layout

| Path | Purpose |
|------|---------|
| `/usr/local/bin/servex` | Server binary |
| `/etc/servex/servex.yaml` | Configuration file (mount your config here) |
| `/etc/servex/certs/` | TLS certificates |
| `/var/www/html/` | Static files |
| `/opt/servex/` | Working directory |

### Environment-Only Configuration

You can skip the config file entirely and configure via environment variables:

```yaml
services:
  servex:
    image: maxbolgarin/servex:latest
    ports:
      - "8080:8080"
    environment:
      - SERVEX_SERVER_HTTP=:8080
      - SERVEX_SERVER_ENABLE_HEALTH_ENDPOINT=true
      - SERVEX_RATE_LIMIT_ENABLED=true
      - SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL=100
      - SERVEX_RATE_LIMIT_INTERVAL=1m
      - SERVEX_SECURITY_ENABLED=true
      - SERVEX_COMPRESSION_ENABLED=true
```

## Standalone vs Go Library

| Feature | Standalone (YAML) | Go Library |
|---------|:-----------------:|:----------:|
| Reverse proxy / load balancing | Yes | Yes |
| Static files / SPA | Yes | Yes |
| Rate limiting | Yes | Yes |
| Security headers / CSRF | Yes | Yes |
| CORS | Yes | Yes |
| Compression | Yes | Yes |
| Request filtering | Yes | Yes |
| Health / metrics endpoints | Yes | Yes |
| JWT auth (memory DB) | Yes | Yes |
| JWT auth (custom DB) | - | Yes |
| Email verification / password reset | Yes | Yes |
| OAuth providers | Yes | Yes |
| Two-factor auth | Yes | Yes |
| Swagger UI | Yes | Yes |
| Audit logging | Auto | Configurable |
| Custom route handlers | - | Yes |
| Custom middleware | - | Yes |
| WebSocket handlers | - | Yes |
| Custom metrics backend | - | Yes |
| Custom logger implementation | - | Yes |

## Signal Handling

Servex handles `SIGINT` and `SIGTERM` for graceful shutdown:

1. Stop accepting new connections
2. Wait up to 30 seconds for active requests to complete
3. Close all connections and exit

In Docker, `docker stop` sends `SIGTERM` — servex shuts down gracefully within the default 10-second Docker stop timeout.

## Logging and Monitoring

### Logs

Servex logs to stdout/stderr in a structured format. Control verbosity with:

```bash
servex -log-level debug    # debug, info, warn, error
servex -log-format json    # json or text
```

Or via config:

```yaml
logging:
  log_fields:
    - "method"
    - "url"
    - "status"
    - "duration_ms"
    - "ip"
    - "user_agent"
```

### Health Endpoint

```bash
curl http://localhost:8080/health
# 200 OK
```

Configure the path:

```yaml
server:
  enable_health_endpoint: true
  health_path: "/healthz"
```

### Prometheus Metrics

```bash
curl http://localhost:8080/metrics
```

Metrics include: request count, duration histogram, active connections, status code distribution, per-path stats, and WebSocket metrics (when active).

```yaml
server:
  enable_default_metrics: true
  metrics_path: "/metrics"
```

## Troubleshooting

**Port already in use:**
```
Server error: listen tcp :8080: bind: address already in use
```
Change the port with `-port 3000` or in the config file.

**Config file not found:**
```
Configuration file 'servex.yaml' not found
```
Servex falls back to environment variables. Specify the file with `-config /path/to/config.yaml`.

**TLS certificate errors:**
```
HTTPS requires both cert_file and key_file
```
Ensure both `cert_file` and `key_file` point to valid files. Validate with `servex -validate`.

**Proxy backend unreachable:**
Enable health checks in the proxy config to automatically route around failed backends:
```yaml
proxy:
  health_check:
    enabled: true
    default_interval: "30s"
    retry_count: 3
```

**Validate before deploying:**
```bash
servex -validate -config production.yaml
servex -dry-run -config production.yaml
```

See [Caddy Migration Guide](CADDY_MIGRATION.md) for translating Caddy configs to servex.
