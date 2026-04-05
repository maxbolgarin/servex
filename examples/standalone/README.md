# Standalone Server & Docker Examples

Run servex as a standalone binary or Docker container — no Go code required. Configure everything with YAML files or CLI presets.

## Quick Start

### With Presets (Zero Config)

```bash
# Production server with security, rate limiting, compression
servex -preset production -port 8080

# API server with CORS, rate limiting, caching
servex -preset api -port 3000

# Serve a React/Vue/Angular app
servex -preset spa -static-dir ./dist -port 8080

# Static file server
servex -preset static -static-dir ./public -port 8080
```

### With Config Files

```bash
# Reverse proxy / API gateway
servex -config reverse-proxy.yaml

# Static site with SPA routing
servex -config static-site.yaml

# Full-featured server (proxy + static + auth)
servex -config full-server.yaml
```

## Config Files

### [reverse-proxy.yaml](reverse-proxy.yaml)

API gateway that routes requests to backend services:
- 3 proxy rules (API, auth, WebSocket) with load balancing
- Health checks for automatic failover
- Rate limiting at 1000 req/min
- Gzip compression and security headers

```bash
servex -config reverse-proxy.yaml
curl http://localhost:8080/health
```

### [static-site.yaml](static-site.yaml)

Serves static files with SPA support:
- `spa_mode: true` — all routes fall back to `index.html`
- Per-extension cache rules (1 year for hashed assets, no cache for index.html)
- Gzip compression for text, JS, CSS, SVG
- Security headers with web-friendly CSP

```bash
servex -config static-site.yaml
# Place your files in /var/www/html (or change the dir in config)
```

### [full-server.yaml](full-server.yaml)

Combined reverse proxy, static files, JWT auth, and security:
- Auth with in-memory DB (endpoints at `/api/v1/auth/*`)
- Proxy rule for `/api/` to backend service
- Static files from `/var/www/html` with SPA mode
- Rate limiting, CORS, CSRF, security headers, compression

```bash
# Set auth secrets via environment variables
export SERVEX_AUTH_JWT_ACCESS_SECRET=$(openssl rand -hex 32)
export SERVEX_AUTH_JWT_REFRESH_SECRET=$(openssl rand -hex 32)
servex -config full-server.yaml
```

## Docker Usage

### Reverse Proxy

```bash
docker compose up -d
```

Uses [docker-compose.yaml](docker-compose.yaml) — mounts `reverse-proxy.yaml` and starts on port 8080.

### Static Site

```bash
# Place your site files in ./site/
docker compose -f docker-compose-static.yaml up -d
```

Uses [docker-compose-static.yaml](docker-compose-static.yaml) — mounts config + `./site` directory.

### Full Stack

```bash
docker compose -f docker-compose-full.yaml up -d
```

Uses [docker-compose-full.yaml](docker-compose-full.yaml) — servex + backend service, with TLS certificates and auth secrets via environment.

### Custom Docker Image

```dockerfile
FROM maxbolgarin/servex:latest
COPY my-config.yaml /etc/servex/servex.yaml
COPY dist/ /var/www/html/
```

### Docker with Presets

```bash
# No config file needed
docker run -p 8080:8080 maxbolgarin/servex servex -preset api -port 8080

# SPA with mounted files
docker run -p 8080:8080 -v ./dist:/var/www/html:ro maxbolgarin/servex servex -preset spa -port 8080
```

## Available Presets

| Preset | What You Get |
|--------|-------------|
| `production` | Security headers, CSRF, 100 rps rate limiting, compression, audit logging |
| `api` | CORS, 1000 rpm rate limiting, 10 MB body limit, API caching |
| `webapp` | Strict security, CSRF, web CSP, 50 MB uploads, compression |
| `microservice` | Fast timeouts (5s), minimal security, 200 rps |
| `security` | Strict security, bot filtering, 20 rps, audit logging |
| `spa` | SPA with index.html fallback, 1-year asset cache, compression |
| `static` | Static file server, 1-year cache, compression |

Combine preset + config for customization:

```bash
servex -preset production -config overrides.yaml
```

## Container Directory Layout

| Path | Purpose |
|------|---------|
| `/etc/servex/servex.yaml` | Config file |
| `/etc/servex/certs/` | TLS certificates |
| `/var/www/html/` | Static files |
| `/opt/servex/` | Working directory |

## Further Reading

- [Full standalone documentation](../../docs/STANDALONE.md)
- [Complete YAML config reference](../../docs/server_docs.yaml)
- [Go library documentation](../../README.md)
