# Servex v2 — Improvement Plan

Prioritized by real user impact. Items that already exist in the codebase are excluded.

---

## Tier 2 — Production Gaps

Matter when deploying at scale or in Kubernetes environments.

### Readiness / Liveness Probes with Dependency Checks
Current `/health` returns static `{"status":"ok"}`. No way to check database connectivity, Redis availability, or downstream service health. Kubernetes can't properly manage instances.

```go
server, _ := servex.NewServer(
    servex.WithHealthChecks(
        servex.HealthCheck("postgres", db.Ping),
        servex.HealthCheck("redis", redis.Ping),
    ),
    servex.WithReadinessPath("/ready"),
    servex.WithLivenessPath("/live"),
)
```

**Files:** `options_health.go`, `servex.go` (endpoint registration)

### OpenTelemetry / Distributed Tracing
No trace context propagation. In a microservice architecture, requests lose their trace ID when they hit servex. This breaks observability across service boundaries.

- W3C Trace Context header propagation (`traceparent`, `tracestate`)
- Optional OTEL middleware for spans
- Trace ID in request logs

**Files:** new `otel.go`, `options_otel.go`; modify `middleware_other.go` (logging)

### Circuit Breaker for Proxy
Proxy has health checks but no circuit breaker. A failing backend keeps receiving traffic until the health check interval fires. Need fast failure detection with automatic recovery.

**Files:** `proxy.go` — add circuit breaker state machine per backend

### Per-Route Middleware
Complement to route groups. Allow attaching middleware to individual routes without creating a group.

```go
server.Get("/admin/dashboard", handler, servex.WithMiddleware(adminOnly, auditLog))
```

**Files:** `router.go`

### Rate Limit Response Headers
No `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` headers. Clients can't implement backoff or show "try again in X seconds" UI.

**Files:** `ratelimit.go` — add headers in middleware response

### Environment Variable Expansion in YAML
Cannot use `${DB_PASSWORD}` in YAML config files. Forces users to use env overlay for every secret, breaking 12-factor app patterns where config files reference env vars.

**Files:** `config.go` — add `os.ExpandEnv()` pass before YAML parsing

---

## Tier 3 — Competitive Features

Nice to have. Differentiate from other libraries.

### Context Response Helpers
- `ctx.XML(code, v)` — XML response (complement to JSON)
- `ctx.Stream(code, contentType, reader)` — chunked transfer from `io.Reader`
- `ctx.Negotiate(code, offers)` — respond based on `Accept` header

### API Key Authentication
Database-backed API keys with scopes. Alternative to JWT for machine-to-machine auth.

```go
servex.WithAPIKeys(apiKeyDB) // implements APIKeyDatabase interface
// Keys carry scopes: "read:users", "write:orders"
```

### Config Hot-Reload
Watch YAML file, apply safe changes (rate limits, CORS origins, filter rules) without restart. Unsafe changes (TLS, auth keys) require restart with a warning log.

### Auto-Generate OpenAPI Spec
Reflect on registered routes to produce a skeleton OpenAPI spec. Not full generation (that needs annotations), but a starting point with paths, methods, and auth requirements.

### Benchmark Suite
Baseline benchmarks for hot paths: middleware chain, JSON serialization, rate limiter lookup, context creation. Track in CI to catch regressions.

### Example Applications
- WebSocket chat room with rooms and auth
- REST API with JWT auth, email verification, and 2FA
- OAuth social login app
- Reverse proxy with load balancing

---

## Tier 4 — Long-Term Vision

### Migrate from gorilla/mux to Go 1.22+ `net/http`
Go 1.22 added method-based routing to the stdlib. Dropping gorilla/mux removes the biggest external dependency and aligns with the Go ecosystem direction. Blocked until Go 1.22 is the minimum supported version.

### ACME / Let's Encrypt Auto-HTTPS
`autocert` or similar for automatic certificate provisioning. Common in production but complex to get right (DNS challenges, rate limits, renewal).

### gRPC Gateway
Serve gRPC and HTTP on the same port. Useful for services that need both REST and gRPC interfaces.

### Plugin System
Allow third-party feature bundles registered as a single option:

```go
servex.NewServer(
    myCompanyPlugin.Options(), // returns []servex.Option
)
```
