# Migrating from Caddy to Servex

## Overview

Servex can replace Caddy for reverse proxy, static file serving, and security header use cases. There are a few key differences to keep in mind:

- **Deployment model.** Caddy is a standalone binary only. Servex is both a Go library you embed in your own applications and a standalone binary (`cmd/servex`).
- **TLS.** Caddy provides automatic ACME/Let's Encrypt certificate management out of the box. Servex requires you to supply certificate files (`cert_file` / `key_file`) or terminate TLS at a load balancer or reverse proxy in front of it.
- **Configuration format.** Caddy uses its own Caddyfile syntax. Servex uses YAML files with environment variable overrides.

## Quick Mapping Table

| Caddy Directive | Servex Equivalent |
|---|---|
| `reverse_proxy backend:8080` | `proxy.rules[].backends[].url` |
| `header { ... }` | `security` section |
| `encode gzip zstd` | `compression.enabled: true` |
| `file_server` | `static_files` section |
| `log { ... }` | Built-in request logging (enabled by default) |
| `tls /path/cert /path/key` | `server.cert_file` + `server.key_file` |
| `respond 404` | `filter.blocked_path_prefixes` with `status_code: 404` |
| `uri strip_prefix /admin` | `proxy.rules[].strip_prefix: "/admin"` |
| `try_files {path} /index.html` | `static_files.spa_mode: true` |
| `import block_scanners` | `ScannerBlockPreset()` or equivalent YAML `filter` block |
| `root * /var/www` | `static_files.dir: "/var/www"` |

## Example 1: Reverse Proxy with Security Headers

### Caddyfile

```
{
    email admin@example.com
}

(block_scanners) {
    @blocked path /. /_all_dbs /actuator /api-docs /cgi-bin /debug /ecp /info.php
    @blocked2 path /login.action /owa /server-status /swagger /swagger-ui /telescope
    @blocked3 path /v2/api-docs /v3/api-docs /webjars /wp-* /xmlrpc.php
    @blocked_ci path_regexp (?i)/phpmyadmin
    respond @blocked 404
    respond @blocked2 404
    respond @blocked3 404
    respond @blocked_ci 404
}

(security_headers) {
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        X-XSS-Protection "0"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
    }
}

example.com {
    import block_scanners
    import security_headers
    encode gzip

    handle /api/v1/ws/* {
        reverse_proxy bff:8080
    }

    handle /api/* {
        reverse_proxy bff:8080
    }

    handle /admin/* {
        uri strip_prefix /admin
        reverse_proxy admin-spa:80
    }

    handle {
        reverse_proxy spa:80
    }
}
```

### servex.yaml

```yaml
server:
  http: ":80"

security:
  enabled: true
  x_content_type_options: "nosniff"
  x_frame_options: "DENY"
  x_xss_protection: "0"
  strict_transport_security: "max-age=63072000; includeSubDomains; preload"
  referrer_policy: "strict-origin-when-cross-origin"
  permissions_policy: "camera=(), microphone=(), geolocation=()"

compression:
  enabled: true

filter:
  blocked_path_prefixes:
    - "/."
    - "/_all_dbs"
    - "/actuator"
    - "/api-docs"
    - "/cgi-bin"
    - "/debug"
    - "/ecp"
    - "/info.php"
    - "/login.action"
    - "/owa"
    - "/server-status"
    - "/swagger"
    - "/swagger-ui"
    - "/telescope"
    - "/v2/api-docs"
    - "/v3/api-docs"
    - "/webjars"
    - "/wp-"
    - "/xmlrpc.php"
  blocked_path_patterns:
    - "(?i)/phpmyadmin"
  status_code: 404
  message: ""

proxy:
  enabled: true
  rules:
    - name: "websocket"
      path_prefix: "/api/v1/ws/"
      backends:
        - url: "http://bff:8080"

    - name: "api"
      path_prefix: "/api/"
      backends:
        - url: "http://bff:8080"

    - name: "admin"
      path_prefix: "/admin/"
      strip_prefix: "/admin"
      backends:
        - url: "http://admin-spa:80"

    - name: "spa"
      path_prefix: "/"
      backends:
        - url: "http://spa:80"
```

**Notes:**

- Proxy rules are evaluated in order. Place more specific prefixes (like `/api/v1/ws/`) before broader ones (like `/api/`).
- Setting `message: ""` with `status_code: 404` returns an empty body, matching Caddy's `respond 404` behavior.
- The `ScannerBlockPreset()` Go function produces the same filter list shown above, plus blocks common scanner User-Agents.

## Example 2: Static File Server

### Caddyfile

```
example.com {
    root * /var/www/html
    file_server
    encode gzip
    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options nosniff
    }
}
```

### servex.yaml

```yaml
server:
  https: ":443"
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"

static_files:
  enabled: true
  dir: "/var/www/html"
  url_prefix: "/"

compression:
  enabled: true

security:
  enabled: true
  strict_transport_security: "max-age=31536000"
  x_content_type_options: "nosniff"
```

**Notes:**

- Unlike Caddy, servex does not manage TLS certificates automatically. You must provide `cert_file` and `key_file`, or terminate TLS upstream.
- `url_prefix` defaults to `"/"` when omitted, serving files at the root.

## Example 3: SPA with API Proxy

### Caddyfile

```
example.com {
    handle /api/* {
        reverse_proxy backend:3000
    }
    handle {
        root * /var/www/app
        try_files {path} /index.html
        file_server
    }
    encode gzip
}
```

### servex.yaml

```yaml
server:
  https: ":443"
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"

compression:
  enabled: true

proxy:
  enabled: true
  rules:
    - name: "api"
      path_prefix: "/api/"
      backends:
        - url: "http://backend:3000"

static_files:
  enabled: true
  dir: "/var/www/app"
  spa_mode: true
  index_file: "index.html"
  exclude_paths:
    - "/api/"
```

**Notes:**

- `spa_mode: true` is equivalent to Caddy's `try_files {path} /index.html`. When a requested file is not found, servex serves `index_file` instead of returning 404.
- `exclude_paths` prevents the static file handler from intercepting API requests. The proxy middleware runs before static files in the middleware chain, so this is typically handled automatically, but explicit exclusion makes the intent clear.

## Example 4: Go Library Version

The same configurations can be expressed as Go code using servex option functions. This is useful when you want to embed servex in your own application.

### Reverse Proxy with Security Headers (Example 1 as Go)

```go
package main

import (
    "log"

    "github.com/maxbolgarin/servex"
)

func main() {
    server, err := servex.NewServer(
        servex.WithAddr(":80"),

        // Security headers
        servex.WithSecurityHeaders(),
        servex.WithHSTSHeader(63072000, true, true),
        servex.WithSecurityConfig(servex.SecurityConfig{
            Enabled:           true,
            PermissionsPolicy: "camera=(), microphone=(), geolocation=()",
        }),

        // Compression
        servex.WithCompression(),

        // Proxy rules
        servex.WithProxyConfig(servex.ProxyConfiguration{
            Enabled: true,
            Rules: []servex.ProxyRule{
                {
                    Name:       "websocket",
                    PathPrefix: "/api/v1/ws/",
                    Backends:   []servex.Backend{{URL: "http://bff:8080"}},
                },
                {
                    Name:       "api",
                    PathPrefix: "/api/",
                    Backends:   []servex.Backend{{URL: "http://bff:8080"}},
                },
                {
                    Name:        "admin",
                    PathPrefix:  "/admin/",
                    StripPrefix: "/admin",
                    Backends:    []servex.Backend{{URL: "http://admin-spa:80"}},
                },
                {
                    Name:       "spa",
                    PathPrefix: "/",
                    Backends:   []servex.Backend{{URL: "http://spa:80"}},
                },
            },
        }),
    )
    if err != nil {
        log.Fatal(err)
    }

    // ScannerBlockPreset applies the same filter rules shown in Example 1 YAML
    server.Apply(servex.ScannerBlockPreset()...)

    if err := server.Start(); err != nil {
        log.Fatal(err)
    }
}
```

### SPA with API Proxy (Example 3 as Go)

```go
server, err := servex.NewServer(
    servex.WithTLSAddr(":443", "/path/to/cert.pem", "/path/to/key.pem"),
    servex.WithCompression(),
    servex.WithProxyConfig(servex.ProxyConfiguration{
        Enabled: true,
        Rules: []servex.ProxyRule{
            {
                Name:       "api",
                PathPrefix: "/api/",
                Backends:   []servex.Backend{{URL: "http://backend:3000"}},
            },
        },
    }),
    servex.WithSPAMode("/var/www/app", "index.html"),
)
```

## What Caddy Does That Servex Doesn't

- **Automatic ACME/Let's Encrypt certificates.** Caddy handles certificate issuance and renewal automatically. With servex, you must provide certificates manually or use a TLS terminator (nginx, cloud load balancer, etc.).
- **zstd compression.** Caddy supports both gzip and zstd. Servex currently supports gzip only.
- **Automatic HTTP/3 (QUIC).** Caddy enables HTTP/3 by default when TLS is configured. Servex uses standard HTTP/1.1 and HTTP/2.
- **On-the-fly config reload via API.** Caddy exposes a REST API for live configuration changes. Servex requires a restart to apply configuration changes.
- **Automatic HTTPS redirect.** Caddy redirects HTTP to HTTPS automatically. Servex supports this via `server.https_redirect.enabled: true`, but it must be configured explicitly.

## What Servex Does That Caddy Doesn't

- **Embeddable Go library.** Use servex as a package in your own Go application. Register your own handlers, middleware, and business logic alongside proxy and static file serving.
- **JWT authentication with email verification, OAuth, and 2FA.** Full auth system with user registration, login, token refresh, email verification (code or token mode), OAuth providers (Google, GitHub, etc.), and TOTP two-factor authentication.
- **WebSocket support with rooms and broadcasting.** High-level WebSocket API with connection management, room-based messaging, and hub broadcasting.
- **Request filtering by headers, query params, and user agents.** Fine-grained filtering with allow/block lists, regex patterns, and per-path location-based filter configs.
- **Built-in metrics and audit logging.** Prometheus-compatible metrics endpoint and structured audit logging for security events.
- **Scanner blocking preset.** One-line `ScannerBlockPreset()` that blocks common vulnerability scanners, bot probes, and attack paths. Includes both path prefixes and known scanner User-Agent patterns.
