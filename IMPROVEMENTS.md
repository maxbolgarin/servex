# Servex v2 — Improvement Plan

Prioritized by real user impact. Items that already exist in the codebase are excluded.

---

## Tier 1 — High Impact

These are the walls users hit first. Each one unlocks a class of use cases or removes daily friction.

### Route Groups with Per-Group Middleware
The #1 ergonomic gap vs Echo/Gin/Fiber. Users cannot scope middleware to a subset of routes without wrapping handlers manually. API versioning, admin panels, and public/private route separation all need this.

```go
api := server.Group("/api/v1")
api.Use(authMiddleware, rateLimitMiddleware)
api.Get("/users", listUsers)
api.Post("/users", createUser)/u

public := server.Group("/public")
public.Get("/health", healthCheck) // no auth
```

**Files:** `router.go` — add `Group` type wrapping `mux.Router.Subrouter()`

### Server-Sent Events (SSE)
Real-time data push without WebSocket complexity. Chat notifications, live dashboards, progress bars — SSE covers 80% of real-time use cases with simpler client code (`EventSource` API).

```go
server.SSE("/events/{channel}", func(sse *servex.SSEConn) {
    for msg := range updates {
        sse.Send("update", msg)
    }
})
```

**Files:** new `sse.go`, `options_sse.go`; integrate with `servex.go` lifecycle

### Remove `Enabled` Flags — Lazy Initialization
9 config structs require `Enabled: true` even when all other fields are set. This is the most common source of "why isn't X working?" confusion. Features should activate when configured, not when a boolean is flipped.

**Affected configs:**
- `CompressionConfig` — enable when `Level > 0` or any option set
- `RateLimitConfig` — enable when `RequestsPerInterval > 0`
- `SecurityConfig` — enable when any header configured
- `CORSConfig` — enable when `AllowedOrigins` non-empty
- `CacheConfig` — enable when any cache directive set
- `CSRFEnabled` — enable when CSRF cookie/token configured
- `StaticFileConfig` — enable when `Directory` non-empty
- `HTTPSRedirectConfig` — enable when cert provided
- `AuthConfig` — enable when `Database` non-nil

**Files:** `options_core.go`, `servex.go` (middleware registration checks)

### Testing Utilities
Zero test helpers exist. Users must manually construct `httptest` servers, build requests, generate auth tokens. This is the biggest DX gap — every other Go framework ships test utilities.

```go
// Test server with auto-cleanup
ts := servex.TestServer(t, servex.WithAuthMemoryDatabase())
defer ts.Close()

// Request builder
resp := ts.Request("POST", "/api/users").
    WithJSON(map[string]string{"name": "alice"}).
    WithAuth(ts.TokenFor("admin")).
    Do()

// WebSocket test client
ws := ts.WSClient("/ws/chat")
ws.WriteJSON(msg)
got, _ := ws.ReadJSON()
```

**Files:** new `testing.go` (build-tagged `//go:build !release` or in test helper package)

### Custom Error Handler
Error response format is hardcoded as `{"message": "..."}` in `ctx.Error()`. Users cannot wrap errors in their own format, add error codes, or log to external systems.

```go
server, _ := servex.NewServer(
    servex.WithErrorHandler(func(ctx *servex.Context, err error, code int, msg string) {
        ctx.Response(code, map[string]any{
            "error": map[string]any{
                "code":    code,
                "message": msg,
                "traceID": ctx.RequestID(),
            },
        })
    }),
)
```

**Files:** `options_core.go` (add `ErrorHandler` field), `context_response.go` (call hook in `Error()`)

### Finish WebSocket Integration
WebSocket code is feature-complete but not wired into config loading.

- [ ] Add `websocket:` section to YAML config parsing in `config.go`
- [ ] Add WebSocket section to CLAUDE.md (done via recent update)

**Files:** `config.go`

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
