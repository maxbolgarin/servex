# Servex - Swiss Army Knife for Go HTTP(S) Server

[![Go Version][version-img]][doc] [![GoDoc][doc-img]][doc] [![Build][ci-img]][ci] [![GoReport][report-img]][report] [![MIT][mit-img]][mit]

![Servex](./.github/assets/pic.png)

**Servex** is the HTTP server package that eliminates boilerplate and lets you focus on what matters—your business logic. Whether you're building APIs, web applications, or need a powerful reverse proxy, Servex provides the technical foundation so you don't have to. It's built using Go's [net/http](https://pkg.go.dev/net/http) and [gorilla/mux](https://github.com/gorilla/mux). This package is designed to easy integrate into existing `net/http` servers.

#### Servex gives you production-ready features out of the box:

🚀 **Zero Boilerplate** - Configure once, code business logic  
🔒 **Security First** - JWT auth, rate limiting, security headers included  
🌐 **Dual Purpose** - Use as a library OR standalone proxy server  
⚡ **Native Compatibility** - Works seamlessly with existing `net/http` code  
🎯 **Gorilla/Mux Powered** - Flexible routing with middleware support 


#### Installation

```shell
go get -u github.com/maxbolgarin/servex/v2
```


## Table of Contents

- [✨ Why Choose Servex?](#-why-choose-servex)
- [Why Servex](#why-servex)
- [Usage](#usage)
  - [Quick Start with Presets](#quick-start-with-presets)
  - [Manual Configuration](#manual-configuration)
  - [Using Context in Handlers](#using-context-in-handlers)
  - [Authentication](#authentication)
  - [Rate Limiting](#rate-limiting)
  - [Request Filtering](#request-filtering)
  - [Reverse Proxy & API Gateway](#reverse-proxy--api-gateway)
  - [Security Headers](#security-headers)
  - [Security Audit Logging](#security-audit-logging)
- [Complete Configuration Reference](#complete-configuration-reference)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)


## Why Servex

Image you have a web appiction with vanila `net/http` handler:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    bodyBytes, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "cannot read request body", http.StatusBadRequest)
        return
    }

    var request Request
    if err := json.Unmarshal(bodyBytes, &request); err != nil {
        http.Error(w, "invalid request body", http.StatusBadRequest)
        return
    }

    // ... do something with request

    respBytes, err := json.Marshal(resp)
    if err != nil {
        http.Error(w, "cannot marshal response", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Content-Length", strconv.Itoa(len(respBytes)))

    if _, err := w.Write(respBytes); err != nil {
        http.Error(w, "cannot write response", http.StatusInternalServerError)
        return
    }
}
```

With **Servex** you can write your handler like this:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)

    request, err := servex.ReadJSON[Request](r)
    if err != nil {
        ctx.BadRequest(err, "invalid request body")
        return
    }

    // ... do something with request

    ctx.Response(http.StatusOK, resp)
}
```

Less code, more focus on business logic. Implement in your handler just by calling `servex.C(w, r)`. Look at the usage examples below to see options for starting a server with **Servex** in easy way.


## Usage

### Quick Start with Presets

The fastest way to get started is using configuration presets:

```go
// Development server - minimal setup for development
server, _ := servex.New(servex.DevelopmentPreset()...)

// Production server - security, rate limiting, monitoring
server, _ := servex.New(servex.ProductionPreset()...)

// REST API server - optimized for APIs
server, _ := servex.New(servex.APIServerPreset()...)

// Web application - security headers for web apps
server, _ := servex.New(servex.WebAppPreset()...)

// Microservice - fast timeouts, minimal security
server, _ := servex.New(servex.MicroservicePreset()...)

// High security - maximum security features
server, _ := servex.New(servex.HighSecurityPreset()...)

// SSL-enabled server - production + SSL certificate
server, _ := servex.New(servex.QuickTLSPreset("cert.pem", "key.pem")...)
```

### Manual Configuration

There are multiple ways to set up a Servex server manually:

#### 1. Using the Server Object

```go
// Initialize and start the server
srv, err := servex.New(
    servex.WithReadTimeout(10*time.Second),
    servex.WithLogger(slog.Default()), 
    servex.WithCertificate(cert),
)
if err != nil {
    log.Fatalf("failed to create server: %v", err)
}

srv.HandleFunc("/hello", helloHandler)
srv.HandleFunc("/world", worldHandler)

// Non-blocking call that starts the server
if err := srv.Start(":8080", ":8443"); err != nil {
    log.Fatalf("failed to start servers: %v", err)
}
defer srv.Shutdown(ctx)

// ... some code ...

```

#### 2. Server with Graceful Shutdown

```go
srv, err := servex.New()
if err != nil {
    log.Fatalf("failed to create server: %v", err)
}

// Register routes
srv.GET("/api/v1/health", healthHandler)
srv.GET("/api/v1/users", usersHandler)

// Start with automatic shutdown on context cancellation
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// Non-blocking call that starts the server and goroutine to wait for context cancellation
if err := srv.StartWithShutdown(ctx, ":8080", ""); err != nil {
    log.Fatalf("failed to start server: %v", err)
}

// Server will shut down automatically when context is canceled
```

#### 3. Server waiting for signals

```go
srv, err := servex.New()
if err != nil {
    log.Fatalf("failed to create server: %v", err)
}

// Register routes
srv.GET("/api/v1/health", healthHandler)
srv.GET("/api/v1/users", usersHandler)

// Blocking call that waits for signals (Ctrl+C) to shutdown the server
if err := srv.StartWithWaitSignals(ctx, ":8080", ""); err != nil {
    log.Fatalf("failed to start server: %v", err)
}

```


### Using Context in Handlers

Servex can be integrated into existing `net/http` servers - you can create `servex.Context` based on the `http.Request` and `http.ResponseWriter` objects and use it in your handlers.

```go
func (app *App) CreateUserHandler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)

    userRequest, err := servex.ReadJSON[User](r)
    if err != nil {
        ctx.BadRequest(err, "invalid user")
        return
    }

    userIDResponse, err := app.CreateUser(ctx, userRequest);
    if err != nil {
        // add 'username' field to error response
        ctx.InternalServerError(err, "cannot create user", "username", userRequest.Name) 
        return
    }

    ctx.Response(http.StatusCreated, userIDResponse)
}
```

With `servex.Context` you can get the experience of working in an HTTP framework like [echo](https://github.com/labstack/echo) inside plain `net/http` servers.

#### Context Helpers

Servex's Context provides many helper methods:

```go
func exampleHandler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.NewContext(w, r)
    
    // Get request information
    requestID := ctx.RequestID()
    apiVersion := ctx.APIVersion() // Extracts 'v1' from paths like /api/v1/...
    userID := ctx.Path("id")       // Path parameters from URL
    sort := ctx.Query("sort")      // Query parameters ?sort=asc
    
    // Read and validate request bodies
    user, err := servex.ReadJSON[User](r)
    // OR with validation if User implements Validate() method
    user, err := servex.ReadAndValidate[User](r)
    
    // Handle cookies
    cookie, _ := ctx.Cookie("session")
    ctx.SetCookie("session", "token123", 3600, true, true)
    
    // Send responses with proper headers
    ctx.Response(http.StatusOK, map[string]string{"status": "success"})
    
    // Or handle errors with consistent formatting
    ctx.BadRequest(err, "invalid input: %s", err.Error())
    ctx.NotFound(err, "user not found")
    ctx.InternalServerError(err, "database error")
}
```

### Authentication

Servex includes a built-in JWT-based authentication system:

#### 1. Setting Up Authentication

```go
// Create an in-memory auth database
memoryDB := servex.NewMemoryAuthDatabase()

// Configure the server with authentication
srv, err := servex.New(
    servex.WithAuth(servex.AuthConfig{
        Database: memoryDB,
        RolesOnRegister: []servex.UserRole{"user"}, // Default roles for new users
        AccessTokenDuration: 15 * time.Minute,
        RefreshTokenDuration: 7 * 24 * time.Hour,
        InitialUsers: []servex.InitialUser{
            {Username: "admin", Password: "admin123", Roles: []servex.UserRole{"admin", "user"}},
        },
    }),
)

// Authentication routes are automatically registered under /auth/...
// - POST /auth/register - Register new user
// - POST /auth/login - Login and get tokens
// - POST /auth/refresh - Refresh access token
// - POST /auth/logout - Logout (invalidate refresh token)
// - GET /auth/me - Get current user info (requires authentication)

// Create protected routes
srv.HandleFuncWithAuth("/admin", adminHandler, "admin") // Only users with "admin" role can access
srv.HFA("/protected", protectedHandler, "user")         // Short form for HandleFuncWithAuth
```

#### 2. Authentication in Existing Handlers

```go
func (app *App) AdminOnlyHandler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    
    // Get user ID from context (set by auth middleware)
    userID, ok := r.Context().Value(servex.UserContextKey{}).(string)
    if !ok {
        ctx.Unauthorized(nil, "authentication required")
        return
    }
    
    // Get user roles 
    roles, _ := ctx.Value(servex.RoleContextKey{}).([]servex.UserRole)
    
    // ... handle the request
    
    ctx.Response(http.StatusOK, result)
}
```

#### 3. Login Flow Example

1. Client sends login request
```text
POST /auth/login
{"username": "user1", "password": "pass123"}
```

2. Server responds with:
```text
200 OK
{
  "id": "user-id-123",
  "username": "user1",
  "roles": ["user"],
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
Set-Cookie: refresh_token=token123; HttpOnly; Secure; SameSite=Strict
```

3. Client uses accessToken in Authorization header
```text
GET /api/protected
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

4. When access token expires, client sends refresh request
```text
POST /auth/refresh
(refresh_token cookie is sent automatically)
```

### Rate Limiting

Servex provides comprehensive rate limiting capabilities to protect your APIs from abuse and ensure fair usage across clients.

#### Basic Rate Limiting

```go
// Simple rate limiting - 100 requests per minute
server, err := servex.New(servex.WithRPM(100))

// Or 10 requests per second
server, err := servex.New(servex.WithRPS(10))

// Custom interval - 500 requests per 5 minutes
server, err := servex.New(servex.WithRequestsPerInterval(500, 5*time.Minute))
```

#### Advanced Rate Limiting Configuration

```go
rateLimitConfig := servex.RateLimitConfig{
    Enabled:             true,
    RequestsPerInterval: 100,
    Interval:            time.Minute,
    BurstSize:           20,        // Allow bursts up to 20 requests
    StatusCode:          429,
    Message:             "Rate limit exceeded. Please slow down.",
    ExcludePaths:        []string{"/health", "/metrics"},
    TrustedProxies:      []string{"10.0.0.0/8"},
}

server, err := servex.New(servex.WithRateLimitConfig(rateLimitConfig))
```

#### Custom Rate Limiting Keys

```go
// Rate limit by API key
apiKeyFunc := func(r *http.Request) string {
    apiKey := r.Header.Get("X-API-Key")
    if apiKey != "" {
        return "api:" + apiKey
    }
    return r.RemoteAddr
}

server, err := servex.New(
    servex.WithRPS(100),
    servex.WithRateLimitKeyFunc(apiKeyFunc),
)
```

#### Location-Based Rate Limiting

Different endpoints can have different rate limits:

```go
locationConfigs := []servex.LocationRateLimitConfig{
    {
        // Strict limits for authentication
        PathPatterns: []string{"/auth/login", "/auth/register"},
        Config: servex.RateLimitConfig{
            Enabled:             true,
            RequestsPerInterval: 5,    // Only 5 attempts per minute
            Interval:            time.Minute,
            BurstSize:           2,
            Message:             "Too many authentication attempts",
        },
    },
    {
        // More relaxed for API endpoints
        PathPatterns: []string{"/api/*"},
        Config: servex.RateLimitConfig{
            Enabled:             true,
            RequestsPerInterval: 100,
            Interval:            time.Minute,
            BurstSize:           20,
        },
    },
}

// Register location-based rate limiting
servex.RegisterLocationBasedRateLimitMiddleware(server.R(), locationConfigs)
```

#### Rate Limiting Features

- **Multiple Strategies**: Per-IP, per-user, per-API-key, or custom
- **Burst Handling**: Allow temporary spikes above the base rate
- **Path Filtering**: Include/exclude specific paths
- **Proxy Support**: Accurate client IP detection behind proxies
- **Custom Messages**: Configurable error responses
- **Memory Efficient**: Automatic cleanup of inactive rate limiters

### Request Filtering

Servex provides powerful request filtering capabilities to block malicious traffic and control access based on IP addresses, User-Agents, headers, and query parameters.

#### IP-Based Filtering

```go
// Allow only specific IP ranges
server, err := servex.New(
    servex.WithAllowedIPs("192.168.1.0/24", "10.0.0.0/8"),
)

// Block specific IPs or ranges
server, err := servex.New(
    servex.WithBlockedIPs("192.0.2.1", "198.51.100.0/24"),
)

// Combine allowed and blocked (blocked takes precedence)
server, err := servex.New(
    servex.WithAllowedIPs("192.168.0.0/16"),    // Allow local network
    servex.WithBlockedIPs("192.168.1.100"),     // But block this specific IP
)
```

#### User-Agent Filtering

```go
// Block known bots and scrapers
server, err := servex.New(
    servex.WithBlockedUserAgents("BadBot/1.0", "Scraper/2.0"),
    servex.WithBlockedUserAgentsRegex(`(?i).*(bot|crawler|spider|scraper).*`),
)

// Allow only specific user agents
server, err := servex.New(
    servex.WithAllowedUserAgentsRegex(`^MyApp/.*`, `^Mozilla/.*Chrome.*`),
)
```

#### Header and Query Parameter Filtering

```go
filterConfig := servex.FilterConfig{
    // Require specific API key in header
    AllowedHeaders: map[string][]string{
        "X-API-Key": {"valid-key-1", "valid-key-2"},
    },
    
    // Block SQL injection attempts in query params
    BlockedQueryParamsRegex: map[string][]string{
        "search": {`(?i)(union|select|drop|delete|insert|update)`},
        "query":  {`(?i)(union|select|drop|delete|insert|update)`},
    },
    
    // Custom response for blocked requests
    StatusCode: http.StatusForbidden,
    Message:    "Access denied by security policy",
    
    // Don't filter health checks
    ExcludePaths: []string{"/health", "/metrics"},
}

server, err := servex.New(servex.WithFilterConfig(filterConfig))
```

#### Dynamic Filter Management

Filters can be modified at runtime:

```go
// Get filter instance during setup
filter, err := servex.RegisterFilterMiddleware(router, filterConfig)
if err != nil {
    log.Fatal(err)
}

// Later, add/remove rules dynamically
filter.AddBlockedIP("203.0.113.100")
filter.RemoveBlockedIP("192.168.1.50")
filter.AddBlockedUserAgent("NewBadBot/1.0")

// Check if an IP is blocked
if filter.IsIPBlocked("203.0.113.100") {
    log.Println("IP is blocked")
}
```

#### Location-Based Filtering

Different filtering rules for different paths:

```go
locationConfigs := []servex.LocationFilterConfig{
    {
        // Strict filtering for admin area
        PathPatterns: []string{"/admin/*"},
        Config: servex.FilterConfig{
            AllowedIPs:        []string{"10.0.0.0/8"},    // Internal network only
            BlockedUserAgents: []string{"*Bot*", "*Spider*"},
            StatusCode:        http.StatusUnauthorized,
            Message:          "Admin access restricted",
        },
    },
    {
        // API key required for API endpoints
        PathPatterns: []string{"/api/*"},
        Config: servex.FilterConfig{
            AllowedHeaders: map[string][]string{
                "X-API-Key": {"^[a-zA-Z0-9]{32}$"}, // 32-char alphanumeric
            },
            StatusCode: http.StatusForbidden,
            Message:    "Valid API key required",
        },
    },
}

filter, err := servex.RegisterLocationBasedFilterMiddleware(router, locationConfigs)
```

#### Filter Features

- **Multi-Layer Protection**: IP, User-Agent, Headers, Query Parameters
- **Regex Support**: Pattern matching for flexible rules
- **Dynamic Management**: Add/remove rules at runtime
- **Location-Based**: Different rules for different paths
- **Proxy Support**: Accurate client IP detection
- **Performance Optimized**: Efficient compiled regex patterns


### Reverse Proxy & API Gateway

Servex includes a powerful L7 reverse proxy with load balancing, health checking, traffic analysis, and advanced routing capabilities.

#### Basic Proxy Setup

```go
proxyConfig := servex.ProxyConfiguration{
    Enabled: true,
    Rules: []servex.ProxyRule{
        {
            Name:       "api-backend",
            PathPrefix: "/api/",
            Backends: []servex.Backend{
                {URL: "http://backend1:8080", Weight: 2},
                {URL: "http://backend2:8080", Weight: 1},
            },
            LoadBalancing: servex.WeightedRoundRobinStrategy,
            StripPrefix:   "/api",  // Remove /api before forwarding
        },
    },
}

server, err := servex.New(servex.WithProxyConfig(proxyConfig))
```

#### Load Balancing Strategies

```go
rules := []servex.ProxyRule{
    {
        Name: "round-robin-service",
        PathPrefix: "/service1/",
        LoadBalancing: servex.RoundRobinStrategy,
        Backends: []servex.Backend{
            {URL: "http://server1:8080"},
            {URL: "http://server2:8080"},
            {URL: "http://server3:8080"},
        },
    },
    {
        Name: "session-affinity",
        Host: "users.example.com",
        LoadBalancing: servex.IPHashStrategy,  // Same client → same backend
        Backends: []servex.Backend{
            {URL: "http://users1:8080"},
            {URL: "http://users2:8080"},
        },
    },
    {
        Name: "least-connections",
        PathPrefix: "/upload/",
        LoadBalancing: servex.LeastConnectionsStrategy,
        Backends: []servex.Backend{
            {URL: "http://upload1:8080", MaxConnections: 50},
            {URL: "http://upload2:8080", MaxConnections: 100},
        },
    },
}
```

#### Health Checking

```go
proxyConfig := servex.ProxyConfiguration{
    Enabled: true,
    
    // Global health check configuration
    HealthCheck: servex.HealthCheckConfig{
        Enabled:         true,
        DefaultInterval: 30 * time.Second,
        Timeout:         5 * time.Second,
        RetryCount:      3,
    },
    
    Rules: []servex.ProxyRule{
        {
            Name:       "monitored-service",
            PathPrefix: "/api/",
            Backends: []servex.Backend{
                {
                    URL:                 "http://api1:8080",
                    HealthCheckPath:     "/health",
                    HealthCheckInterval: 20 * time.Second,
                    MaxConnections:      100,
                },
                {
                    URL:                 "http://api2:8080", 
                    HealthCheckPath:     "/status",
                    HealthCheckInterval: 30 * time.Second,
                    MaxConnections:      150,
                },
            },
        },
    },
}
```

#### Traffic Analysis & Debugging

```go
proxyConfig := servex.ProxyConfiguration{
    Enabled: true,
    
    // Traffic dumping for analysis
    TrafficDump: servex.TrafficDumpConfig{
        Enabled:     true,
        Directory:   "./traffic_logs",
        MaxFileSize: 100 * 1024 * 1024,  // 100MB files
        MaxFiles:    20,                  // Keep 20 files
        IncludeBody: true,               // Include request/response bodies
        MaxBodySize: 64 * 1024,          // 64KB max body in dumps
        SampleRate:  0.1,                // Sample 10% of traffic
    },
    
    Rules: []servex.ProxyRule{
        {
            Name:              "debug-api",
            PathPrefix:        "/api/",
            EnableTrafficDump: true,      // Enable for this rule
            Backends: []servex.Backend{
                {URL: "http://api:8080"},
            },
        },
    },
}
```

#### Advanced Routing

```go
rules := []servex.ProxyRule{
    {
        // Host-based routing
        Name: "subdomain-routing",
        Host: "api.example.com",
        Backends: []servex.Backend{
            {URL: "http://api-servers:8080"},
        },
    },
    {
        // Method-specific routing
        Name:    "write-operations",
        PathPrefix: "/api/",
        Methods: []string{"POST", "PUT", "DELETE"},
        Backends: []servex.Backend{
            {URL: "http://write-api:8080"},
        },
    },
    {
        // Header-based routing
        Name:       "api-v2",
        PathPrefix: "/api/",
        Headers: map[string]string{
            "X-API-Version": "v2",
        },
        Backends: []servex.Backend{
            {URL: "http://api-v2:8080"},
        },
    },
    {
        // Path manipulation
        Name:        "legacy-service",
        PathPrefix:  "/old-api/",
        StripPrefix: "/old-api",
        AddPrefix:   "/v1",  // /old-api/users → /v1/users
        Backends: []servex.Backend{
            {URL: "http://legacy:8080"},
        },
    },
}
```

#### Production Example

```go
proxyConfig := servex.ProxyConfiguration{
    Enabled:         true,
    GlobalTimeout:   30 * time.Second,
    MaxIdleConns:    200,
    IdleConnTimeout: 90 * time.Second,
    
    HealthCheck: servex.HealthCheckConfig{
        Enabled:         true,
        DefaultInterval: 30 * time.Second,
        Timeout:         5 * time.Second,
        RetryCount:      3,
    },
    
    TrafficDump: servex.TrafficDumpConfig{
        Enabled:    true,
        Directory:  "/var/log/proxy",
        SampleRate: 0.05,  // 5% sampling in production
    },
    
    Rules: []servex.ProxyRule{
        {
            Name:       "main-api",
            PathPrefix: "/api/",
            Backends: []servex.Backend{
                {
                    URL:                 "http://api1.internal:8080",
                    Weight:              3,
                    HealthCheckPath:     "/health",
                    MaxConnections:      200,
                },
                {
                    URL:                 "http://api2.internal:8080",
                    Weight:              2,
                    HealthCheckPath:     "/health", 
                    MaxConnections:      150,
                },
                {
                    URL:                 "http://api3.internal:8080",
                    Weight:              1,
                    HealthCheckPath:     "/health",
                    MaxConnections:      100,
                },
            },
            LoadBalancing: servex.WeightedRoundRobinStrategy,
            StripPrefix:   "/api",
            Timeout:       25 * time.Second,
        },
    },
}

// Combine with security and monitoring
server, err := servex.New(
    servex.WithProxyConfig(proxyConfig),
    servex.WithSecurityHeaders(),
    servex.WithRPM(1000),
    servex.WithHealthEndpoint(),
    servex.WithDefaultMetrics(),
)
```

#### Proxy Features

- **Load Balancing**: 6 strategies (round-robin, weighted, least-connections, random, IP-hash)
- **Health Monitoring**: Automatic backend health checking with failover
- **Traffic Analysis**: Request/response dumping with sampling
- **Advanced Routing**: Host, path, method, and header-based routing
- **Connection Management**: Pooling, limits, and timeout control
- **Path Manipulation**: Strip/add prefixes for backend compatibility
- **Performance**: Efficient connection reuse and memory management


### Security Headers

Servex provides comprehensive security headers middleware to protect your application from common web vulnerabilities:

#### Basic Security Headers

```go
// Enable basic security headers with recommended defaults
srv, err := servex.New(
    servex.WithSecurityHeaders(),
)
```

This applies the following headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `X-Permitted-Cross-Domain-Policies: none`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`

#### Strict Security Headers

```go
// Enable strict security headers for high-security applications
srv, err := servex.New(
    servex.WithStrictSecurityHeaders(),
)
```

This includes all basic headers plus:
- `Content Security Policy (CSP)`
- `HTTP Strict Transport Security (HSTS)`
- `Permissions Policy`
- `Cross-Origin policies`

#### Custom Security Configuration

```go
// Create custom security configuration
srv, err := servex.New(
    servex.WithContentSecurityPolicy("default-src 'self'; script-src 'self' 'unsafe-inline'"),
    servex.WithHSTSHeader(31536000, true, true), // 1 year, includeSubdomains, preload
    
    // Custom headers (separate from security headers)
    servex.WithCustomHeaders(map[string]string{
        "X-API-Version": "v1.0",
        "X-Custom":      "my-value",
    }),
    
    // Header removal (separate from security headers)
    servex.WithRemoveHeaders("Server", "X-Powered-By"), // Remove server info
    
    servex.WithSecurityExcludePaths("/health", "/metrics"), // Exclude monitoring endpoints
)
```


### Security Audit Logging

Servex provides comprehensive security audit logging to track authentication events, rate limiting violations, filter blocks, and other security-related activities for compliance and threat detection.

#### Basic Audit Logging

```go
// Enable default audit logging
server, err := servex.New(
    servex.WithDefaultAuditLogger(),
    servex.WithAuth(authDB),
    servex.WithRPM(100),
    servex.WithBlockedUserAgentsRegex(`(?i).*(bot|crawler).*`),
)

// All security events are automatically logged
```

#### Custom Audit Logger

```go
// Implement custom audit logger for SIEM integration
type SIEMAuditLogger struct {
    client *siem.Client
}

func (s *SIEMAuditLogger) LogSecurityEvent(event servex.AuditEvent) {
    // Send to external SIEM system
    s.client.SendEvent(map[string]interface{}{
        "timestamp":     event.Timestamp,
        "event_type":    event.EventType,
        "severity":      event.Severity,
        "client_ip":     event.ClientIP,
        "user_id":       event.UserID,
        "path":          event.Path,
        "message":       event.Message,
        "details":       event.Details,
    })
}

func (s *SIEMAuditLogger) LogAuthenticationEvent(eventType servex.AuditEventType, r *http.Request, userID string, success bool, details map[string]any) {
    // Handle auth events specifically
    event := servex.AuditEvent{
        EventType: eventType,
        Timestamp: time.Now(),
        ClientIP:  r.RemoteAddr,
        UserID:    userID,
        Path:      r.URL.Path,
        Details:   details,
    }
    s.LogSecurityEvent(event)
}

// ... implement other required methods

server := servex.New(
    servex.WithAuditLogger(&SIEMAuditLogger{client: siemClient}),
    servex.WithAuth(authDB),
)
```

#### Audit Event Types

Servex automatically logs these security events:

**Authentication Events:**
- `auth.login.success` - Successful user login
- `auth.login.failure` - Failed login attempt
- `auth.logout` - User logout
- `auth.token.refresh` - Token refresh
- `auth.token.invalid` - Invalid token usage
- `auth.unauthorized` - Unauthorized access attempt
- `auth.forbidden` - Forbidden access (insufficient permissions)

**Rate Limiting Events:**
- `ratelimit.exceeded` - Rate limit threshold exceeded
- `ratelimit.blocked` - Request blocked by rate limiter

**Filtering Events:**
- `filter.ip.blocked` - Request blocked by IP filter
- `filter.useragent.blocked` - Request blocked by User-Agent filter
- `filter.header.blocked` - Request blocked by header filter
- `filter.query.blocked` - Request blocked by query parameter filter

**CSRF Events:**
- `csrf.token.missing` - CSRF token missing
- `csrf.token.invalid` - Invalid CSRF token
- `csrf.attack.detected` - Potential CSRF attack

#### Audit Configuration

```go
// Configure audit logging with headers (be careful with sensitive data)
server := servex.New(
    servex.WithDefaultAuditLogger(),
    servex.WithAuditLogHeaders(true),  // Include non-sensitive headers
)

// Custom audit logger with detailed configuration
auditLogger := servex.NewDefaultAuditLogger(logger)
auditLogger.IncludeHeaders = true
auditLogger.SensitiveHeaders = []string{
    "Authorization", "Cookie", "X-API-Key", "X-Auth-Token", "X-Secret",
}
auditLogger.MaxDetailSize = 2048  // 2KB max for detail fields

server := servex.New(servex.WithAuditLogger(auditLogger))
```

#### Structured Audit Events

Each audit event contains rich contextual information:

```go
type AuditEvent struct {
    // Core event information
    EventType   string    `json:"event_type"`
    Severity    string    `json:"severity"`     // low, medium, high, critical
    Timestamp   time.Time `json:"timestamp"`
    EventID     string    `json:"event_id"`

    // Request context
    RequestID   string `json:"request_id,omitempty"`
    UserID      string `json:"user_id,omitempty"`
    SessionID   string `json:"session_id,omitempty"`
    ClientIP    string `json:"client_ip"`
    UserAgent   string `json:"user_agent,omitempty"`
    Method      string `json:"method"`
    Path        string `json:"path"`
    Query       string `json:"query,omitempty"`

    // Security context
    BlockedRule      string            `json:"blocked_rule,omitempty"`
    RateLimitKey     string            `json:"ratelimit_key,omitempty"`
    FilterType       string            `json:"filter_type,omitempty"`
    FilterValue      string            `json:"filter_value,omitempty"`
    Headers          map[string]string `json:"headers,omitempty"`

    // Event details
    Message      string         `json:"message"`
    Details      map[string]any `json:"details,omitempty"`
    Error        string         `json:"error,omitempty"`
    StatusCode   int           `json:"status_code,omitempty"`
    ResponseTime int64         `json:"response_time_ms,omitempty"`
}
```

#### Example Audit Logs

```json
{
  "event_type": "auth.login.failure",
  "severity": "high",
  "timestamp": "2024-01-15T10:30:00Z",
  "event_id": "evt_abc123",
  "client_ip": "203.0.113.100",
  "user_agent": "Mozilla/5.0...",
  "method": "POST",
  "path": "/auth/login",
  "message": "User login failed",
  "details": {
    "username": "admin",
    "reason": "invalid password",
    "attempt_count": 3
  },
  "status_code": 401
}

{
  "event_type": "filter.ip.blocked",
  "severity": "high", 
  "timestamp": "2024-01-15T10:35:00Z",
  "client_ip": "192.0.2.50",
  "path": "/api/users",
  "filter_type": "IP",
  "filter_value": "192.0.2.50",
  "blocked_rule": "IP not in allowed list",
  "message": "Request blocked by IP filter",
  "status_code": 403
}

{
  "event_type": "ratelimit.exceeded",
  "severity": "medium",
  "timestamp": "2024-01-15T10:40:00Z",
  "client_ip": "198.51.100.25",
  "path": "/api/data",
  "ratelimit_key": "198.51.100.25",
  "message": "Rate limit exceeded",
  "details": {
    "requests_per_interval": 100,
    "interval_seconds": 60,
    "current_count": 101
  },
  "status_code": 429
}
```

#### Integration Examples

**Elasticsearch/ELK Stack:**
```go
type ElasticsearchAuditLogger struct {
    client *elasticsearch.Client
    index  string
}

func (e *ElasticsearchAuditLogger) LogSecurityEvent(event servex.AuditEvent) {
    doc, _ := json.Marshal(event)
    e.client.Index(e.index, strings.NewReader(string(doc)))
}
```

**Syslog Integration:**
```go
type SyslogAuditLogger struct {
    writer *syslog.Writer
}

func (s *SyslogAuditLogger) LogSecurityEvent(event servex.AuditEvent) {
    msg := fmt.Sprintf("AUDIT %s %s %s %s", 
        event.EventType, event.ClientIP, event.Path, event.Message)
    
    switch event.Severity {
    case "critical", "high":
        s.writer.Alert(msg)
    case "medium":
        s.writer.Warning(msg)
    default:
        s.writer.Info(msg)
    }
}
```

#### Compliance Features

- **SOX Compliance**: Financial transaction audit trails
- **GDPR Compliance**: User access and data modification logging
- **HIPAA Compliance**: Healthcare data access tracking
- **SOC 2**: Security control monitoring
- **ISO 27001**: Information security event logging

#### Audit Features

- **Comprehensive Coverage**: Authentication, authorization, rate limiting, filtering
- **Structured Events**: Rich JSON format with consistent fields
- **Severity Levels**: Automatic severity classification
- **Custom Integration**: Pluggable audit logger interface
- **Performance Optimized**: Asynchronous logging with minimal overhead
- **Privacy Aware**: Automatic sensitive header filtering


## Complete Configuration Reference

Servex provides over 100 configuration options organized by category. All options use the `With...` pattern and can be combined as needed.

### TLS & Certificates

| Option | Description | Example |
|--------|-------------|---------|
| `WithCertificate(cert)` | Set TLS certificate for HTTPS | `servex.WithCertificate(tlsCert)` |
| `WithCertificatePtr(*cert)` | Set TLS certificate pointer | `servex.WithCertificatePtr(&tlsCert)` |
| `WithCertificateFromFile(cert, key)` | Load certificate from files | `servex.WithCertificateFromFile("cert.pem", "key.pem")` |

### Server Timeouts

| Option | Description | Example |
|--------|-------------|---------|
| `WithReadTimeout(duration)` | Maximum time to read request | `servex.WithReadTimeout(30*time.Second)` |
| `WithReadHeaderTimeout(duration)` | Maximum time to read headers | `servex.WithReadHeaderTimeout(10*time.Second)` |
| `WithIdleTimeout(duration)` | Keep-alive timeout | `servex.WithIdleTimeout(120*time.Second)` |

### Authentication & Authorization

| Option | Description | Example |
|--------|-------------|---------|
| `WithAuthToken(token)` | Simple bearer token auth | `servex.WithAuthToken("secret-key")` |
| `WithAuth(db)` | JWT auth with database | `servex.WithAuth(authDB)` |
| `WithAuthMemoryDatabase()` | In-memory auth database | `servex.WithAuthMemoryDatabase()` |
| `WithAuthConfig(config)` | Complete auth configuration | `servex.WithAuthConfig(authConfig)` |
| `WithAuthKey(access, refresh)` | JWT signing keys | `servex.WithAuthKey("access-key", "refresh-key")` |
| `WithAuthIssuer(issuer)` | JWT issuer name | `servex.WithAuthIssuer("my-app")` |
| `WithAuthBasePath(path)` | Auth endpoints base path | `servex.WithAuthBasePath("/auth")` |
| `WithAuthInitialRoles(roles...)` | Default user roles | `servex.WithAuthInitialRoles("user", "member")` |
| `WithAuthRefreshTokenCookieName(name)` | Refresh token cookie name | `servex.WithAuthRefreshTokenCookieName("rt")` |
| `WithAuthTokensDuration(access, refresh)` | Token lifetimes | `servex.WithAuthTokensDuration(15*time.Minute, 7*24*time.Hour)` |
| `WithAuthNotRegisterRoutes(bool)` | Skip auto-route registration | `servex.WithAuthNotRegisterRoutes(true)` |
| `WithAuthInitialUsers(users...)` | Create initial users | `servex.WithAuthInitialUsers(adminUser)` |

### Rate Limiting

| Option | Description | Example |
|--------|-------------|---------|
| `WithRateLimitConfig(config)` | Complete rate limit config | `servex.WithRateLimitConfig(rateLimitConfig)` |
| `WithRPM(requests)` | Requests per minute | `servex.WithRPM(100)` |
| `WithRPS(requests)` | Requests per second | `servex.WithRPS(10)` |
| `WithRequestsPerInterval(req, interval)` | Custom rate limit | `servex.WithRequestsPerInterval(500, 5*time.Minute)` |
| `WithBurstSize(size)` | Burst allowance | `servex.WithBurstSize(20)` |
| `WithRateLimitStatusCode(code)` | Rate limit response code | `servex.WithRateLimitStatusCode(429)` |
| `WithRateLimitMessage(msg)` | Rate limit response message | `servex.WithRateLimitMessage("Too many requests")` |
| `WithRateLimitKeyFunc(func)` | Custom rate limit key | `servex.WithRateLimitKeyFunc(userKeyFunc)` |
| `WithRateLimitExcludePaths(paths...)` | Exclude paths from limiting | `servex.WithRateLimitExcludePaths("/health")` |
| `WithRateLimitIncludePaths(paths...)` | Only limit these paths | `servex.WithRateLimitIncludePaths("/api/*")` |
| `WithRateLimitTrustedProxies(proxies...)` | Trusted proxy IPs | `servex.WithRateLimitTrustedProxies("10.0.0.0/8")` |

### Request Filtering

| Option | Description | Example |
|--------|-------------|---------|
| `WithFilterConfig(config)` | Complete filter configuration | `servex.WithFilterConfig(filterConfig)` |
| `WithAllowedIPs(ips...)` | Allow specific IPs | `servex.WithAllowedIPs("192.168.1.0/24")` |
| `WithBlockedIPs(ips...)` | Block specific IPs | `servex.WithBlockedIPs("203.0.113.0/24")` |
| `WithAllowedUserAgents(agents...)` | Allow specific user agents | `servex.WithAllowedUserAgents("MyApp/1.0")` |
| `WithAllowedUserAgentsRegex(patterns...)` | Allow user agents by regex | `servex.WithAllowedUserAgentsRegex("^MyApp/.*")` |
| `WithBlockedUserAgents(agents...)` | Block specific user agents | `servex.WithBlockedUserAgents("BadBot/1.0")` |
| `WithBlockedUserAgentsRegex(patterns...)` | Block user agents by regex | `servex.WithBlockedUserAgentsRegex(".*[Bb]ot.*")` |
| `WithAllowedHeaders(headers)` | Require specific headers | `servex.WithAllowedHeaders(headerMap)` |
| `WithAllowedHeadersRegex(headers)` | Require headers by regex | `servex.WithAllowedHeadersRegex(regexMap)` |
| `WithBlockedHeaders(headers)` | Block specific headers | `servex.WithBlockedHeaders(headerMap)` |
| `WithBlockedHeadersRegex(headers)` | Block headers by regex | `servex.WithBlockedHeadersRegex(regexMap)` |
| `WithAllowedQueryParams(params)` | Require specific query params | `servex.WithAllowedQueryParams(paramMap)` |
| `WithAllowedQueryParamsRegex(params)` | Require params by regex | `servex.WithAllowedQueryParamsRegex(regexMap)` |
| `WithBlockedQueryParams(params)` | Block specific query params | `servex.WithBlockedQueryParams(paramMap)` |
| `WithBlockedQueryParamsRegex(params)` | Block params by regex | `servex.WithBlockedQueryParamsRegex(regexMap)` |
| `WithFilterExcludePaths(paths...)` | Exclude paths from filtering | `servex.WithFilterExcludePaths("/health")` |
| `WithFilterIncludePaths(paths...)` | Only filter these paths | `servex.WithFilterIncludePaths("/api/*")` |
| `WithFilterStatusCode(code)` | Filter response status code | `servex.WithFilterStatusCode(403)` |
| `WithFilterMessage(msg)` | Filter response message | `servex.WithFilterMessage("Access denied")` |
| `WithFilterTrustedProxies(proxies...)` | Trusted proxy IPs for filters | `servex.WithFilterTrustedProxies("10.0.0.0/8")` |

### Security Headers

| Option | Description | Example |
|--------|-------------|---------|
| `WithSecurityConfig(config)` | Complete security configuration | `servex.WithSecurityConfig(secConfig)` |
| `WithSecurityHeaders()` | Enable basic security headers | `servex.WithSecurityHeaders()` |
| `WithStrictSecurityHeaders()` | Enable strict security headers | `servex.WithStrictSecurityHeaders()` |
| `WithContentSecurityPolicy(policy)` | Set CSP header | `servex.WithContentSecurityPolicy("default-src 'self'")` |
| `WithHSTSHeader(maxAge, subdomains, preload)` | Set HSTS header | `servex.WithHSTSHeader(31536000, true, true)` |
| `WithSecurityExcludePaths(paths...)` | Exclude paths from security headers | `servex.WithSecurityExcludePaths("/health")` |
| `WithSecurityIncludePaths(paths...)` | Only apply headers to these paths | `servex.WithSecurityIncludePaths("/app/*")` |

### CSRF Protection

| Option | Description | Example |
|--------|-------------|---------|
| `WithCSRFProtection()` | Enable CSRF protection | `servex.WithCSRFProtection()` |
| `WithCSRFTokenName(name)` | CSRF token field name | `servex.WithCSRFTokenName("_token")` |
| `WithCSRFCookieName(name)` | CSRF cookie name | `servex.WithCSRFCookieName("csrf_token")` |
| `WithCSRFCookieHttpOnly(httpOnly)` | CSRF cookie HttpOnly flag | `servex.WithCSRFCookieHttpOnly(true)` |
| `WithCSRFCookieSameSite(sameSite)` | CSRF cookie SameSite | `servex.WithCSRFCookieSameSite("Strict")` |
| `WithCSRFCookieSecure(secure)` | CSRF cookie Secure flag | `servex.WithCSRFCookieSecure(true)` |
| `WithCSRFCookiePath(path)` | CSRF cookie path | `servex.WithCSRFCookiePath("/")` |
| `WithCSRFCookieMaxAge(maxAge)` | CSRF cookie lifetime | `servex.WithCSRFCookieMaxAge(3600)` |
| `WithCSRFTokenEndpoint(endpoint)` | CSRF token endpoint | `servex.WithCSRFTokenEndpoint("/csrf-token")` |
| `WithCSRFErrorMessage(msg)` | CSRF error message | `servex.WithCSRFErrorMessage("Invalid CSRF token")` |
| `WithCSRFSafeMethods(methods...)` | CSRF safe methods | `servex.WithCSRFSafeMethods("GET", "HEAD")` |

### CORS Configuration

| Option | Description | Example |
|--------|-------------|---------|
| `WithCORSConfig(config)` | Complete CORS configuration | `servex.WithCORSConfig(corsConfig)` |
| `WithCORS()` | Enable CORS with defaults | `servex.WithCORS()` |
| `WithCORSAllowOrigins(origins...)` | Allowed origins | `servex.WithCORSAllowOrigins("https://example.com")` |
| `WithCORSAllowMethods(methods...)` | Allowed methods | `servex.WithCORSAllowMethods("GET", "POST", "PUT")` |
| `WithCORSAllowHeaders(headers...)` | Allowed headers | `servex.WithCORSAllowHeaders("Content-Type", "Authorization")` |
| `WithCORSExposeHeaders(headers...)` | Exposed headers | `servex.WithCORSExposeHeaders("X-Total-Count")` |
| `WithCORSAllowCredentials()` | Allow credentials | `servex.WithCORSAllowCredentials()` |
| `WithCORSMaxAge(seconds)` | Preflight cache time | `servex.WithCORSMaxAge(3600)` |
| `WithCORSExcludePaths(paths...)` | Exclude paths from CORS | `servex.WithCORSExcludePaths("/internal/*")` |
| `WithCORSIncludePaths(paths...)` | Only apply CORS to these paths | `servex.WithCORSIncludePaths("/api/*")` |

### Cache Control

| Option | Description | Example |
|--------|-------------|---------|
| `WithCacheConfig(config)` | Complete cache configuration | `servex.WithCacheConfig(cacheConfig)` |
| `WithCacheControl(value)` | Set Cache-Control header | `servex.WithCacheControl("public, max-age=3600")` |
| `WithCacheHeaders()` | Enable basic cache headers | `servex.WithCacheHeaders()` |
| `WithCacheExpires(expires)` | Set Expires header | `servex.WithCacheExpires(expireTime)` |
| `WithCacheETag(etag)` | Set ETag header | `servex.WithCacheETag("\"v1.2.3\"")` |
| `WithCacheLastModified(lastMod)` | Set Last-Modified header | `servex.WithCacheLastModified(lastModTime)` |
| `WithCacheVary(vary)` | Set Vary header | `servex.WithCacheVary("Accept-Encoding")` |
| `WithCacheExcludePaths(paths...)` | Exclude paths from caching | `servex.WithCacheExcludePaths("/api/*")` |
| `WithCacheIncludePaths(paths...)` | Only cache these paths | `servex.WithCacheIncludePaths("/static/*")` |
| `WithCacheExpiresTime(time)` | Set expires time | `servex.WithCacheExpiresTime(time.Now().Add(time.Hour))` |
| `WithCacheLastModifiedTime(time)` | Set last modified time | `servex.WithCacheLastModifiedTime(modTime)` |
| `WithCacheETagFunc(func)` | Dynamic ETag generation | `servex.WithCacheETagFunc(etagFunc)` |
| `WithCacheLastModifiedFunc(func)` | Dynamic last modified | `servex.WithCacheLastModifiedFunc(modFunc)` |
| `WithCacheNoCache()` | Disable caching | `servex.WithCacheNoCache()` |
| `WithCacheNoStore()` | Never store in cache | `servex.WithCacheNoStore()` |
| `WithCachePublic(maxAge)` | Public cache with max-age | `servex.WithCachePublic(3600)` |
| `WithCachePrivate(maxAge)` | Private cache with max-age | `servex.WithCachePrivate(900)` |
| `WithCacheStaticAssets(maxAge)` | Cache static assets | `servex.WithCacheStaticAssets(31536000)` |
| `WithCacheAPI(maxAge)` | Cache API responses | `servex.WithCacheAPI(300)` |

### Request Size Limits

| Option | Description | Example |
|--------|-------------|---------|
| `WithMaxRequestBodySize(size)` | Max request body size | `servex.WithMaxRequestBodySize(32<<20)` |
| `WithMaxJSONBodySize(size)` | Max JSON body size | `servex.WithMaxJSONBodySize(1<<20)` |
| `WithMaxFileUploadSize(size)` | Max file upload size | `servex.WithMaxFileUploadSize(100<<20)` |
| `WithMaxMultipartMemory(size)` | Max multipart memory | `servex.WithMaxMultipartMemory(10<<20)` |
| `WithEnableRequestSizeLimits(enable)` | Enable size limits middleware | `servex.WithEnableRequestSizeLimits(true)` |
| `WithRequestSizeLimits()` | Enable with defaults | `servex.WithRequestSizeLimits()` |
| `WithStrictRequestSizeLimits()` | Enable with strict limits | `servex.WithStrictRequestSizeLimits()` |

### Logging & Monitoring

| Option | Description | Example |
|--------|-------------|---------|
| `WithLogger(logger)` | Custom logger | `servex.WithLogger(slog.Default())` |
| `WithRequestLogger(logger)` | Custom request logger | `servex.WithRequestLogger(reqLogger)` |
| `WithNoRequestLog()` | Disable request logging | `servex.WithNoRequestLog()` |
| `WithDisableRequestLogging()` | Disable request logging | `servex.WithDisableRequestLogging()` |
| `WithNoLogClientErrors()` | Don't log 4xx errors | `servex.WithNoLogClientErrors()` |
| `WithSendErrorToClient()` | Send detailed errors to client | `servex.WithSendErrorToClient()` |
| `WithLogFields(fields...)` | Specify log fields | `servex.WithLogFields("method", "url", "status")` |
| `WithAuditLogger(logger)` | Custom audit logger | `servex.WithAuditLogger(auditLogger)` |
| `WithDefaultAuditLogger()` | Enable default audit logging | `servex.WithDefaultAuditLogger()` |
| `WithAuditLogHeaders(include)` | Include headers in audit logs | `servex.WithAuditLogHeaders(true)` |

### Health & Metrics

| Option | Description | Example |
|--------|-------------|---------|
| `WithHealthEndpoint()` | Enable health endpoint | `servex.WithHealthEndpoint()` |
| `WithHealthPath(path)` | Custom health endpoint path | `servex.WithHealthPath("/ping")` |
| `WithMetrics(metrics)` | Custom metrics handler | `servex.WithMetrics(promMetrics)` |
| `WithDefaultMetrics(path...)` | Enable default metrics | `servex.WithDefaultMetrics("/metrics")` |

### HTTPS Redirect

| Option | Description | Example |
|--------|-------------|---------|
| `WithHTTPSRedirect()` | Enable HTTPS redirect | `servex.WithHTTPSRedirect()` |
| `WithHTTPSRedirectTemporary()` | Temporary HTTPS redirect | `servex.WithHTTPSRedirectTemporary()` |
| `WithHTTPSRedirectConfig(config)` | HTTPS redirect configuration | `servex.WithHTTPSRedirectConfig(redirectConfig)` |
| `WithHTTPSRedirectTrustedProxies(proxies...)` | Trusted proxies for HTTPS detection | `servex.WithHTTPSRedirectTrustedProxies("10.0.0.0/8")` |
| `WithHTTPSRedirectExcludePaths(paths...)` | Exclude paths from redirect | `servex.WithHTTPSRedirectExcludePaths("/health")` |
| `WithHTTPSRedirectIncludePaths(paths...)` | Only redirect these paths | `servex.WithHTTPSRedirectIncludePaths("/app/*")` |

### Custom Headers

| Option | Description | Example |
|--------|-------------|---------|
| `WithCustomHeaders(headers)` | Add custom headers | `servex.WithCustomHeaders(map[string]string{"X-API-Version": "v1"})` |
| `WithRemoveHeaders(headers...)` | Remove headers | `servex.WithRemoveHeaders("Server", "X-Powered-By")` |

### Static Files & SPA

| Option | Description | Example |
|--------|-------------|---------|
| `WithStaticFileConfig(config)` | Complete static file config | `servex.WithStaticFileConfig(staticConfig)` |
| `WithStaticFiles(dir, prefix)` | Serve static files | `servex.WithStaticFiles("public", "/static")` |
| `WithSPAMode(dir, index)` | Single Page Application mode | `servex.WithSPAMode("build", "index.html")` |
| `WithStaticFileCache(maxAge, rules)` | Static file caching | `servex.WithStaticFileCache(3600, cacheRules)` |
| `WithStaticFileExclusions(paths...)` | Exclude paths from static serving | `servex.WithStaticFileExclusions("/api/*")` |

### Reverse Proxy

| Option | Description | Example |
|--------|-------------|---------|
| `WithProxyConfig(config)` | Complete proxy configuration | `servex.WithProxyConfig(proxyConfig)` |

### Compression

| Option | Description | Example |
|--------|-------------|---------|
| `WithCompressionConfig(config)` | Complete compression config | `servex.WithCompressionConfig(compConfig)` |
| `WithCompression()` | Enable compression with defaults | `servex.WithCompression()` |
| `WithCompressionLevel(level)` | Compression level (1-9) | `servex.WithCompressionLevel(6)` |
| `WithCompressionMinSize(size)` | Minimum size to compress | `servex.WithCompressionMinSize(1024)` |
| `WithCompressionTypes(types...)` | MIME types to compress | `servex.WithCompressionTypes("text/html", "application/json")` |
| `WithCompressionExcludePaths(paths...)` | Exclude paths from compression | `servex.WithCompressionExcludePaths("/api/binary/*")` |
| `WithCompressionIncludePaths(paths...)` | Only compress these paths | `servex.WithCompressionIncludePaths("/api/*")` |

### Example Configuration

```go
server := servex.New(
    // TLS & Server
    servex.WithCertificateFromFile("cert.pem", "key.pem"),
    servex.WithReadTimeout(30*time.Second),
    servex.WithIdleTimeout(120*time.Second),
    
    // Security
    servex.WithStrictSecurityHeaders(),
    servex.WithCSRFProtection(),
    servex.WithRPM(1000),
    servex.WithBlockedUserAgentsRegex(`(?i).*(bot|crawler|spider).*`),
    
    // Authentication
    servex.WithAuthMemoryDatabase(),
    servex.WithAuthInitialUsers(servex.InitialUser{
        Username: "admin",
        Password: "secure-password",
        Roles:    []servex.UserRole{"admin"},
    }),
    
    // Monitoring
    servex.WithDefaultAuditLogger(),
    servex.WithHealthEndpoint(),
    servex.WithDefaultMetrics(),
    
    // Performance
    servex.WithCompression(),
    servex.WithCachePublic(3600),
    servex.WithCORS(),
)
```


## Roadmap

1. New logging — add logging configuration options, separate `Logger`, `Request logger`, `Error logger`, `Proxy logger`, add log level and logging to file.
2. Better proxy — dynamic rules, callbacks functions to rules, custom selector of backends, better logging and dumping, mTLS and different auth methods.
3. Better auth — more fields and roles, email and phone integration, 2FA, etc.
4. Add native tracing support
5. Add UI and CLI for API gateway and service discovery configuration


## Contributing

If you'd like to contribute to **servex**, submit a pull request or open an issue.

## License

Servex is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

[version-img]: https://img.shields.io/badge/Go-%3E%3D%201.24-%23007d9c
[doc-img]: https://pkg.go.dev/badge/github.com/maxbolgarin/servex/v2
[doc]: https://pkg.go.dev/github.com/maxbolgarin/servex/v2
[ci-img]: https://github.com/maxbolgarin/servex/actions/workflows/go.yml/badge.svg
[ci]: https://github.com/maxbolgarin/servex/actions
[report-img]: https://goreportcard.com/badge/github.com/maxbolgarin/servex/v2
[report]: https://goreportcard.com/report/github.com/maxbolgarin/servex/v2
[mit-img]: https://img.shields.io/badge/License-MIT-blue.svg
[mit]: https://github.com/maxbolgarin/servex/blob/v2/LICENSE