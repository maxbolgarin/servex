# Servex - Production-Ready HTTP Server for Go

[![Go Version][version-img]][doc] [![GoDoc][doc-img]][doc] [![Build][ci-img]][ci] [![Coverage][coverage-img]][coverage] [![GoReport][report-img]][report] [![MIT][mit-img]][mit]

**Servex** eliminates HTTP server boilerplate in Go. Focus on business logic while getting production-ready features out of the box.

## Features

- 🚀 **Zero Boilerplate** - Configure once, code business logic
- 🔒 **Security First** - JWT auth, rate limiting, request filtering, security headers, audit logging
- 🔄 **Reverse Proxy / API Gateway** - Load balancing, health checks, traffic analysis
- ⚡ **Native Compatibility** - Works seamlessly with existing `net/http` code

## Quick Start

```shell
go get -u github.com/maxbolgarin/servex/v2
```

### Basic Server

```go
server, _ := servex.New(servex.ProductionPreset()...)
server.HandleFunc("/hello", helloHandler)
server.StartWithWaitSignals(context.Background(), ":8080", "")
```

### Context Helper

```go
func handler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)

    request, err := servex.ReadJSON[Request](r)
    if err != nil {
        ctx.BadRequest(err, "invalid request")
        return
    }

    ctx.Response(http.StatusOK, response)
}
```

## Presets

Quick configurations for common scenarios:

| Preset | Use Case |
|--------|----------|
| `DevelopmentPreset()` | Development with minimal setup |
| `ProductionPreset()` | Production with security, rate limiting, monitoring |
| `APIServerPreset()` | REST APIs |
| `WebAppPreset()` | Web applications with security headers |
| `MicroservicePreset()` | Fast timeouts, minimal security |
| `HighSecurityPreset()` | Maximum security features |
| `QuickTLSPreset(cert, key)` | Production + SSL |

## Features & Configuration

| Feature | Configuration Options |
|---------|----------------------|
| **Authentication** | `WithAuth(config)` - Full JWT auth with database<br>`WithAuthToken(token)` - Simple bearer token<br>`WithAuthMemoryDatabase()` - In-memory user storage<br>`WithAuthKey(accessKey, refreshKey)` - Custom JWT keys<br>`WithAuthTokensDuration(access, refresh)` - Token lifetimes<br>`WithAuthIssuer(issuer)` - JWT issuer<br>`WithAuthBasePath(path)` - Auth routes prefix<br>`WithAuthInitialRoles(roles...)` - Default user roles |
| **Rate Limiting** | `WithRPM(requests)` - Requests per minute<br>`WithRPS(requests)` - Requests per second<br>`WithRequestsPerInterval(requests, interval)` - Custom interval<br>`WithBurstSize(size)` - Burst allowance<br>`WithRateLimitConfig(config)` - Full configuration<br>`WithRateLimitExcludePaths(paths...)` - Exclude paths<br>`WithRateLimitIncludePaths(paths...)` - Include only paths |
| **Request Filtering** | `WithBlockedIPs(ips...)` - Block IP ranges<br>`WithAllowedIPs(ips...)` - Allow only IPs<br>`WithBlockedUserAgents(agents...)` - Block user agents<br>`WithBlockedUserAgentsRegex(patterns...)` - Block by regex<br>`WithAllowedHeaders(headers)` - Allow headers<br>`WithBlockedHeaders(headers)` - Block headers<br>`WithAllowedQueryParams(params)` - Allow query params<br>`WithBlockedQueryParams(params)` - Block query params<br>`WithFilterConfig(config)` - Full configuration |
| **Security Headers** | `WithSecurityHeaders()` - Basic headers<br>`WithStrictSecurityHeaders()` - Strict CSP, HSTS<br>`WithContentSecurityPolicy(policy)` - Custom CSP<br>`WithHSTSHeader(maxAge, includeSubdomains, preload)` - HSTS config<br>`WithSecurityConfig(config)` - Full configuration |
| **CSRF Protection** | `WithCSRFProtection()` - Enable CSRF<br>`WithCSRFTokenName(name)` - Token header name<br>`WithCSRFCookieName(name)` - Cookie name<br>`WithCSRFCookieHttpOnly(httpOnly)` - HttpOnly flag<br>`WithCSRFCookieSecure(secure)` - Secure flag<br>`WithCSRFTokenEndpoint(endpoint)` - Token endpoint |
| **CORS** | `WithCORS()` - Enable with defaults<br>`WithCORSAllowOrigins(origins...)` - Allowed origins<br>`WithCORSAllowMethods(methods...)` - Allowed methods<br>`WithCORSAllowHeaders(headers...)` - Allowed headers<br>`WithCORSAllowCredentials()` - Allow credentials<br>`WithCORSMaxAge(seconds)` - Preflight cache<br>`WithCORSConfig(config)` - Full configuration |
| **Compression** | `WithCompression()` - Enable gzip<br>`WithCompressionLevel(level)` - Level 1-9<br>`WithCompressionMinSize(size)` - Min size to compress<br>`WithCompressionTypes(types...)` - Content types<br>`WithCompressionConfig(config)` - Full configuration |
| **Caching** | `WithCachePublic(maxAge)` - Public cache<br>`WithCachePrivate(maxAge)` - Private cache<br>`WithCacheStaticAssets(maxAge)` - Static file cache<br>`WithCacheNoCache()` - Disable caching<br>`WithCacheControl(control)` - Custom Cache-Control<br>`WithCacheConfig(config)` - Full configuration |
| **Static Files / SPA** | `WithStaticFiles(dir, prefix)` - Serve static files<br>`WithSPAMode(dir, indexFile)` - SPA mode<br>`WithStaticFileConfig(config)` - Full configuration<br>`WithStaticFileCache(maxAge, rules...)` - Cache rules |
| **Reverse Proxy** | `WithProxyConfig(config)` - Full proxy configuration<br>Supports load balancing, health checks, path rewriting |
| **HTTPS / TLS** | `WithCertificate(cert)` - TLS certificate<br>`WithCertificateFromFile(cert, key)` - Load from files<br>`WithHTTPSRedirect()` - Redirect HTTP to HTTPS<br>`WithHTTPSRedirectTemporary()` - 307 redirect<br>`WithHTTPSRedirectConfig(config)` - Full redirect config |
| **Logging & Monitoring** | `WithLogger(logger)` - Custom logger<br>`WithDefaultAuditLogger()` - Security audit logs<br>`WithAuditLogger(logger)` - Custom audit logger<br>`WithDisableRequestLogging()` - Disable request logs<br>`WithNoLogClientErrors()` - Skip 4xx errors<br>`WithLogFields(fields...)` - Additional log fields |
| **Health & Metrics** | `WithHealthEndpoint()` - Enable `/health`<br>`WithHealthPath(path)` - Custom health path<br>`WithDefaultMetrics(path)` - Prometheus metrics<br>`WithMetrics(metrics)` - Custom metrics<br>`WithDisableHealthEndpoint()` - Disable health |
| **Server Timeouts** | `WithReadTimeout(duration)` - Request read timeout<br>`WithReadHeaderTimeout(duration)` - Header read timeout<br>`WithIdleTimeout(duration)` - Keep-alive timeout<br>`WithMaxHeaderBytes(size)` - Max header size |
| **Request Size Limits** | `WithMaxRequestBodySize(size)` - Max body size<br>`WithMaxJSONBodySize(size)` - Max JSON size<br>`WithMaxFileUploadSize(size)` - Max file size<br>`WithMaxMultipartMemory(size)` - Multipart memory<br>`WithRequestSizeLimits()` - Enable defaults<br>`WithStrictRequestSizeLimits()` - Strict limits |

## Core Features

### Authentication

Built-in JWT authentication with user management:

```go
server, _ := servex.New(
    servex.WithAuth(servex.AuthConfig{
        Database:            authDB,
        RolesOnRegister:     []servex.UserRole{"user"},
        AccessTokenDuration: 15 * time.Minute,
    }),
)

// Auto-registers: /auth/login, /auth/register, /auth/refresh, /auth/logout
server.HandleFuncWithAuth("/admin", adminHandler, "admin")
```

### Rate Limiting

Protect all your APIs:

```go
server, _ := servex.New(servex.WithRPM(100)) // 100 requests per minute
```

Or per-endpoint limits via register after server creation:

```go
locationConfigs := []servex.LocationRateLimitConfig{
    {
        PathPatterns: []string{"/auth/login"},
        Config: servex.RateLimitConfig{
            RequestsPerInterval: 5,
            Interval: time.Minute,
        },
    },
}
servex.RegisterLocationBasedRateLimitMiddleware(server.Router(), locationConfigs)
```

### Request Filtering

Block malicious traffic:

```go
server, _ := servex.New(
    servex.WithBlockedIPs("192.0.2.0/24"),
    servex.WithBlockedUserAgentsRegex(`(?i).*(bot|crawler).*`),
)
```

### Reverse Proxy

L7 reverse proxy with load balancing:

```go
proxyConfig := servex.ProxyConfiguration{
    Enabled: true,
    Rules: []servex.ProxyRule{
        {
            PathPrefix: "/api/",
            Backends: []servex.Backend{
                {URL: "http://backend1:8080", Weight: 2},
                {URL: "http://backend2:8080", Weight: 1},
            },
            LoadBalancing: servex.WeightedRoundRobinStrategy,
            StripPrefix:   "/api",
        },
    },
}

server, _ := servex.New(servex.WithProxyConfig(proxyConfig))
```

### Security Headers

```go
server, _ := servex.New(
    servex.WithStrictSecurityHeaders(), // CSP, HSTS, etc.
    servex.WithCSRFProtection(),
)
```

### Audit Logging

Track security events:

```go
server, _ := servex.New(
    servex.WithDefaultAuditLogger(),
    servex.WithAuth(authConfig),
)
// Logs: auth events, rate limits, filter blocks, CSRF violations
```

## Context Helpers

```go
ctx := servex.C(w, r)

// Request
requestID := ctx.RequestID()
apiVersion := ctx.APIVersion()      // Extracts 'v1' from /api/v1/...
userID := ctx.Path("id")            // Path parameter
sort := ctx.Query("sort")           // Query parameter
user, _ := servex.ReadJSON[User](r)

// Response
ctx.Response(http.StatusOK, data)
ctx.BadRequest(err, "invalid input")
ctx.NotFound(err, "not found")
ctx.InternalServerError(err, "error")

// Cookies
cookie, _ := ctx.Cookie("session")
ctx.SetCookie("session", "token", 3600, true, true)
```

## Configuration Options

Servex provides 100+ options via `With...` pattern:

```go
server, _ := servex.New(
    // Server
    servex.WithReadTimeout(30*time.Second),
    servex.WithLogger(slog.Default()),

    // Security
    servex.WithStrictSecurityHeaders(),
    servex.WithRPM(1000),
    servex.WithBlockedIPs("10.0.0.0/8"),

    // Features
    servex.WithHealthEndpoint(),
    servex.WithDefaultMetrics(),
    servex.WithCompression(),
    servex.WithCORS(),

    // Static Files / SPA
    servex.WithSPAMode("build", "index.html"),
)
```

See [Complete Configuration Reference](#complete-configuration-reference) for all options.

## HTTP Method Shortcuts

```go
server.GET("/users", listUsers)
server.POST("/users", createUser)
server.PUT("/users/{id}", updateUser)
server.DELETE("/users/{id}", deleteUser)

// With authentication
server.GetWithAuth("/admin", adminHandler, "admin")
server.PostWithAuth("/api/data", dataHandler, "user")
```

## Server Start Options

```go
// 1. Basic start (non-blocking)
server.Start(":8080", ":8443")

// 2. With automatic shutdown on context cancel
server.StartWithShutdown(ctx, ":8080", "")

// 3. Wait for signals (Ctrl+C) - blocking
server.StartWithWaitSignals(ctx, ":8080", "")

// 4. Separate HTTP/HTTPS
server.StartHTTP(":8080")
server.StartHTTPS(":8443")
```

## Complete Configuration Reference

<details>
<summary>View all configuration options (100+)</summary>

### TLS & Certificates
- `WithCertificate(cert)` - Set TLS certificate
- `WithCertificateFromFile(cert, key)` - Load from files

### Timeouts
- `WithReadTimeout(duration)` - Request read timeout
- `WithIdleTimeout(duration)` - Keep-alive timeout

### Authentication
- `WithAuth(config)` - JWT authentication
- `WithAuthMemoryDatabase()` - In-memory user database
- `WithAuthToken(token)` - Simple bearer token
- `WithAuthTokensDuration(access, refresh)` - Token lifetimes

### Rate Limiting
- `WithRPM(requests)` - Requests per minute
- `WithRPS(requests)` - Requests per second
- `WithBurstSize(size)` - Burst allowance
- `WithRateLimitKeyFunc(func)` - Custom rate limit key

### Request Filtering
- `WithBlockedIPs(ips...)` - Block IP ranges
- `WithAllowedIPs(ips...)` - Allow only specific IPs
- `WithBlockedUserAgents(agents...)` - Block user agents
- `WithBlockedUserAgentsRegex(patterns...)` - Block by regex

### Security
- `WithSecurityHeaders()` - Basic security headers
- `WithStrictSecurityHeaders()` - Strict CSP, HSTS
- `WithCSRFProtection()` - CSRF token validation
- `WithContentSecurityPolicy(policy)` - Custom CSP

### CORS
- `WithCORS()` - Enable with defaults
- `WithCORSAllowOrigins(origins...)` - Allowed origins
- `WithCORSAllowMethods(methods...)` - Allowed methods
- `WithCORSAllowCredentials()` - Allow credentials

### Caching
- `WithCachePublic(maxAge)` - Public cache
- `WithCachePrivate(maxAge)` - Private cache
- `WithCacheStaticAssets(maxAge)` - Cache static files
- `WithCacheNoCache()` - Disable caching

### Logging & Monitoring
- `WithLogger(logger)` - Custom logger
- `WithDefaultAuditLogger()` - Security audit logging
- `WithHealthEndpoint()` - Health check endpoint
- `WithDefaultMetrics()` - Prometheus metrics

### Performance
- `WithCompression()` - Gzip compression
- `WithCompressionLevel(level)` - Compression level (1-9)
- `WithMaxRequestBodySize(size)` - Limit request size

### Static Files
- `WithStaticFiles(dir, prefix)` - Serve static files
- `WithSPAMode(dir, index)` - Single Page Application mode

### Reverse Proxy
- `WithProxyConfig(config)` - Complete proxy configuration

</details>

## Why Servex?

### Before Servex
```go
func handler(w http.ResponseWriter, r *http.Request) {
    bodyBytes, _ := io.ReadAll(r.Body)
    var request Request
    json.Unmarshal(bodyBytes, &request)

    respBytes, _ := json.Marshal(resp)
    w.Header().Set("Content-Type", "application/json")
    w.Write(respBytes)
}
```

### With Servex
```go
func handler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    request, _ := servex.ReadJSON[Request](r)
    ctx.Response(http.StatusOK, resp)
}
```

## Examples

See [examples/](examples/) for complete working examples:
- Basic server
- Authentication
- Rate limiting
- Reverse proxy
- SPA serving

## Contributing

Pull requests and issues welcome! See [LICENSE](LICENSE) for terms.

## License

MIT License - see [LICENSE](LICENSE) file.

---

[version-img]: https://img.shields.io/badge/Go-%3E%3D%201.24-%23007d9c
[doc-img]: https://pkg.go.dev/badge/github.com/maxbolgarin/servex/v2
[doc]: https://pkg.go.dev/github.com/maxbolgarin/servex/v2
[ci-img]: https://github.com/maxbolgarin/servex/actions/workflows/go.yml/badge.svg
[ci]: https://github.com/maxbolgarin/servex/actions
[report-img]: https://goreportcard.com/badge/github.com/maxbolgarin/servex/v2
[report]: https://goreportcard.com/report/github.com/maxbolgarin/servex/v2
[coverage-img]: https://codecov.io/gh/maxbolgarin/servex/branch/v2/graph/badge.svg
[coverage]: https://codecov.io/gh/maxbolgarin/servex/branch/v2
[mit-img]: https://img.shields.io/badge/License-MIT-blue.svg
[mit]: https://github.com/maxbolgarin/servex/blob/v2/LICENSE
