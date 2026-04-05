---
name: servex-app
description: |
  Build production-ready HTTP/HTTPS servers and REST APIs in Go using the servex library
  (github.com/maxbolgarin/servex). Use this skill when creating Go web servers, REST APIs,
  HTTP handlers, or when the user mentions servex, JWT authentication, API keys, rate limiting,
  reverse proxy, request filtering, static file serving, SPA mode, CORS, CSRF, security
  headers, email verification, OAuth login, 2FA/TOTP, SSE/Server-Sent Events, WebSocket,
  W3C trace context, SQL auth database, or any servex With* option function.
---

# Servex Application Development Guide

Complete reference for building HTTP servers and REST APIs in Go using `github.com/maxbolgarin/servex/v2`. Covers server lifecycle, routing, context helpers, authentication (JWT + email + OAuth + 2FA + API keys), SSE, security, rate limiting, filtering, proxy, static files, caching, compression, metrics, logging, audit, Swagger UI, trace context, SQL auth, testing utilities, and presets.

**Use when:** creating a Go HTTP server or REST API with servex, adding middleware or auth, configuring rate limiting or filtering, setting up reverse proxy, serving static files or SPA, or when user mentions any servex feature.

---

## 1. Installation

```bash
go get github.com/maxbolgarin/servex/v2
```

Import:
```go
import "github.com/maxbolgarin/servex/v2"
```

---

## 2. Server Creation & Lifecycle

### Creating a Server

```go
// With options
server, err := servex.NewServer(
    servex.WithHealthEndpoint(),
    servex.WithCompression(),
    servex.WithSecurityHeaders(),
)

// With Options struct
server, err := servex.NewServerWithOptions(servex.Options{...})
```

### Starting the Server

```go
// HTTP only
err := server.StartHTTP(":8080")

// HTTPS only
err := server.StartHTTPS(":8443")

// Both HTTP and HTTPS
err := server.Start(":8080", ":8443")

// With context-based shutdown (blocks until ctx is cancelled)
err := server.StartWithShutdownHTTP(ctx, ":8080")

// With OS signal handling (blocks until signal received, e.g. SIGINT/SIGTERM)
err := server.StartWithWaitSignalsHTTP(ctx, ":8080", syscall.SIGINT, syscall.SIGTERM)
```

### Graceful Shutdown

```go
shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
err := server.Shutdown(shutdownCtx)
```

### Helper Functions

```go
// One-liner: create server, register routes, start, return shutdown func
shutdown, err := servex.StartServer(servex.BaseConfig{
    HTTPAddress: ":8080",
}, func(router *mux.Router) {
    router.HandleFunc("/api/hello", helloHandler).Methods("GET")
}, servex.WithCompression())

defer shutdown(ctx)

// Blocks until ctx done
err := servex.StartServerWithShutdown(ctx, cfg, routeSetter, opts...)
```

### Server Status

```go
server.HTTPAddress()     // ":8080"
server.HTTPSAddress()    // ":8443"
server.IsHTTP()          // true/false
server.IsTLS()           // true/false
server.IsAuthEnabled()   // true/false
server.AuthManager()     // *AuthManager
server.Filter()          // DynamicFilterMethods
```

---

## 3. Router & Route Registration

### Base Path

```go
srv := server.WithBasePath("/api/v1")
// All routes registered on srv will be prefixed with /api/v1
srv.GET("/users", listUsers)   // matches GET /api/v1/users

srv.RemoveBasePath()           // clear base path
```

### Subrouter

```go
apiRouter := server.Router("/api")       // subrouter for /api prefix
server.R("/api")                         // shortcut for Router()
```

### HTTP Method Shortcuts

```go
server.GET("/items", listItems)
server.POST("/items", createItem)
server.PUT("/items/{id}", updateItem)
server.PATCH("/items/{id}", patchItem)
server.DELETE("/items/{id}", deleteItem)
server.OPTIONS("/items", optionsItems)
server.HEAD("/items", headItems)
```

Lowercase aliases also available: `server.Get(...)`, `server.Post(...)`, etc.

### Authenticated Routes

```go
// Any authenticated user
server.GetWithAuth("/profile", profileHandler)

// Role-restricted (any listed role grants access)
server.PostWithAuth("/admin/users", createUserHandler, "admin")
server.DeleteWithAuth("/admin/users/{id}", deleteUserHandler, "admin", "manager")
```

### Generic Registration

```go
server.HandleFunc("/path", handler, "GET", "POST")
server.HF("/path", handler, "GET")            // shortcut
server.HandleFuncWithAuth("/path", handler, "admin")
server.HFA("/path", handler, "admin")         // shortcut

server.Handle("/path", httpHandler, "GET")
server.H("/path", httpHandler, "GET")          // shortcut
server.HandleWithAuth("/path", httpHandler, "admin")
server.HA("/path", httpHandler, "admin")       // shortcut
```

### Middleware

```go
server.Use(loggingMiddleware, recoveryMiddleware)
server.AddMiddlewares(customMiddleware)
```

### Auth Middleware (manual)

```go
auth := server.AuthManager()
protectedHandler := auth.WithAuth(myHandler)                  // any authenticated user
adminHandler := auth.WithAuth(myHandler, "admin")             // admin role required
managerHandler := auth.WithAuth(myHandler, "admin", "manager") // admin OR manager
```

Or use the server shortcut:
```go
server.WithAuth(myHandler, "admin")
```

---

## 4. Context Helpers

### Creating Context

```go
func handler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)          // quick constructor
    // or
    ctx := servex.NewContext(w, r)
    // or from server (uses server's options for size limits etc.)
    ctx := server.C(w, r)
}
```

### Reading Request Data

```go
// Path parameters (gorilla/mux)
id := ctx.Path("id")

// Query parameters
page := ctx.Query("page")
ts, err := ctx.ParseUnixFromQuery("since")

// Headers
token := ctx.Header("X-Custom-Token")

// Cookies
cookie, err := ctx.Cookie("session")

// Form values
name := ctx.FormValue("name")

// Client IP
ip := ctx.ClientIP()
ip := ctx.ClientIPWithTrustedProxies([]string{"10.0.0.0/8"})
addr := ctx.RemoteAddr()

// Raw body
body := ctx.Body()                         // []byte, cached
data, err := ctx.Read()                    // with default size limit
data, err := ctx.ReadWithLimit(1 << 20)    // 1 MB limit
```

### Reading JSON

```go
var req CreateItemRequest
if err := ctx.ReadJSON(&req); err != nil {
    ctx.BadRequest(err, "invalid JSON")
    return
}

// With custom size limit
if err := ctx.ReadJSONWithLimit(&req, 512*1024); err != nil { ... }
```

### Generic JSON Reading (package-level)

```go
req, err := servex.ReadJSON[CreateItemRequest](r)
req, err := servex.ReadJSONWithLimit[CreateItemRequest](r, 1<<20)
```

### Reading & Validating

```go
// Body type must implement Validate() error
type CreateItemRequest struct {
    Name string `json:"name"`
}

func (r *CreateItemRequest) Validate() error {
    if r.Name == "" {
        return fmt.Errorf("name is required")
    }
    return nil
}

// Read + parse + validate in one call
if err := ctx.ReadAndValidate(&req); err != nil {
    ctx.BadRequest(err, "validation failed")
    return
}

// Package-level generic version
req, err := servex.ReadAndValidate[CreateItemRequest](r)
```

### File Uploads

```go
data, header, err := ctx.ReadFile("avatar")
if err != nil {
    ctx.BadRequest(err, "file upload failed")
    return
}
fmt.Println(header.Filename, len(data))

// With limits
data, header, err := ctx.ReadFileWithLimit("avatar", 10<<20, 5<<20)

// Package-level
data, header, err := servex.ReadFile(r, "avatar")
```

### Sending Responses

```go
// JSON response (200 OK)
ctx.JSON(map[string]string{"status": "ok"})

// Custom status + body (auto-detects type: struct/map -> JSON, string -> text, []byte -> detected)
ctx.Response(http.StatusCreated, map[string]string{"id": "123"})
ctx.Response(http.StatusOK, "plain text response")
ctx.Response(http.StatusOK, rawBytes)
ctx.Response(http.StatusNoContent)          // no body

// File download
ctx.ResponseFile("report.pdf", "application/pdf", pdfBytes)
```

### Error Responses

All error methods: `(err error, msg string, fields ...any)` — err is logged, msg is sent to client as `{"message": "..."}`.

```go
ctx.BadRequest(err, "invalid input")           // 400
ctx.Unauthorized(err, "invalid credentials")   // 401
ctx.Forbidden(err, "access denied")            // 403
ctx.NotFound(err, "user not found")            // 404
ctx.MethodNotAllowed()                         // 405
ctx.NotAcceptable(err, "not acceptable")       // 406
ctx.Conflict(err, "already exists")            // 409
ctx.PreconditionFailed(err, "stale data")      // 412
ctx.RequestEntityTooLarge(err, "file too big")  // 413
ctx.UnsupportedMediaType(err, "need JSON")     // 415
ctx.UnprocessableEntity(err, "semantic error")  // 422
ctx.TooManyRequests(err, "slow down")          // 429
ctx.InternalServerError(err, "internal error") // 500
ctx.NotImplemented(err, "not ready")           // 501
ctx.BadGateway(err, "upstream error")          // 502
ctx.ServiceUnavailable(err, "maintenance")     // 503
```

### Redirects

```go
ctx.Redirect("/new-url", http.StatusFound)
ctx.RedirectPermanent("/new-url")              // 301
ctx.RedirectTemporary("/new-url")              // 302
ctx.RedirectSeeOther("/new-url")               // 303
ctx.RedirectNotModified()                      // 304
ctx.RedirectTemporaryPreserveMethod("/new-url") // 307
```

### Response Headers & Cookies

```go
ctx.SetHeader("X-Custom", "value")
ctx.SetContentType("application/xml")
ctx.SetCookie("session", "abc123", 3600, true, true)
ctx.SetRawCookie(&http.Cookie{Name: "k", Value: "v"})
ctx.SetDeleteCookie("session")
```

### Helper Methods

```go
reqID := ctx.RequestID()     // returns or generates X-Request-ID
ver := ctx.APIVersion()      // extracts version from path (e.g. "v1")
ctx.NoLog()                  // suppress request logging for this request
```

### Auth Context

```go
userID := ctx.UserID()       // string from UserContextKey
roles := ctx.UserRoles()     // []UserRole from RoleContextKey
scopes := ctx.APIKeyScopes() // []string from APIKeyScopesContextKey
```

### Trace Context

```go
traceID := ctx.TraceID()     // W3C trace ID (32 hex chars, requires WithTracePropagation)
spanID := ctx.SpanID()       // W3C span ID (16 hex chars, requires WithTracePropagation)
```

---

## 5. Authentication — JWT

### Minimal Setup (development)

```go
server, _ := servex.NewServer(
    servex.WithAuthMemoryDatabase(),
    servex.WithAuthKey(accessKeyHex, refreshKeyHex),   // hex-encoded, >=64 chars (32 bytes)
)
```

### Production Setup

```go
server, _ := servex.NewServer(
    servex.WithAuth(myPostgresDB),  // implements AuthDatabase
    servex.WithAuthKey(os.Getenv("ACCESS_KEY"), os.Getenv("REFRESH_KEY")),
    servex.WithAuthIssuer("my-service"),
    servex.WithAuthTokensDuration(15*time.Minute, 30*24*time.Hour),
    servex.WithAuthInitialRoles("user"),
    servex.WithAuthBasePath("/api/v1/auth"),
    servex.WithAuthRefreshTokenCookieName("_myrt"),
    servex.WithAuthInitialUsers(servex.InitialUser{
        Username: "admin",
        Password: os.Getenv("ADMIN_PASSWORD"),
        Roles:    []servex.UserRole{"admin"},
    }),
)
```

### AuthDatabase Interface

```go
type AuthDatabase interface {
    NewUser(ctx context.Context, username string, passwordHash string, roles ...UserRole) (string, error)
    FindByID(ctx context.Context, id string) (User, bool, error)
    FindByUsername(ctx context.Context, username string) (User, bool, error)
    FindAll(ctx context.Context) ([]User, error)
    UpdateUser(ctx context.Context, id string, diff *UserDiff) error
}
```

User struct fields: `ID`, `Username`, `Roles`, `PasswordHash`, `RefreshTokenHash`, `RefreshTokenExpiresAt`, `Email`, `EmailVerified`, `EmailVerificationCode`, `EmailVerificationExpiry`, `PasswordResetToken`, `PasswordResetExpiry`, `OAuthLinks`, `TwoFactorSecret`, `TwoFactorEnabled`, `TwoFactorBackupCodes`.

UserDiff uses pointer fields for partial updates — only non-nil fields are applied.

DB field constants: `IDDBField`, `UsernameDBField`, `PasswordHashDBField`, `RefreshTokenHashDBField`, `RefreshTokenExpiresAtDBField`.

### Auto-Registered Endpoints (default base: `/api/v1/auth`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/register` | No | Create user, return tokens |
| POST | `/login` | No | Login, return tokens |
| POST | `/refresh` | Cookie | Rotate tokens |
| POST | `/logout` | Cookie | Revoke refresh token |
| GET | `/me` | Bearer | Get current user |

Request: `{"username": "...", "password": "...", "email": "..."}`
Success: `{"id": "...", "username": "...", "roles": [...], "accessToken": "..."}` + HttpOnly refresh cookie.
Error: `{"message": "..."}` with appropriate status code.

### Simple Bearer Auth (no user accounts)

```go
server, _ := servex.NewServer(
    servex.WithAuthToken("my-secret-api-key"),
)
// All requests must include: Authorization: Bearer my-secret-api-key
```

### Extracting User in Handlers

```go
func handler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    userID := ctx.UserID()
    roles := ctx.UserRoles()
    // or directly from context:
    userID, _ := r.Context().Value(servex.UserContextKey{}).(string)
    roles, _ := r.Context().Value(servex.RoleContextKey{}).([]servex.UserRole)
}
```

### AuthManager Direct Usage

```go
auth := server.AuthManager()
auth.RegisterRoutes(router)                          // manual route registration
auth.CreateUser(ctx, "admin", "password", "admin")   // programmatic user creation
```

---

## 6. Email Verification & Password Reset

### Setup with SMTP

```go
server, _ := servex.NewServer(
    servex.WithAuth(myDB),
    servex.WithAuthKey(accessKey, refreshKey),
    servex.WithEmailSMTP(servex.SMTPConfig{
        Host:             "smtp.gmail.com",
        Port:             587,
        Username:         os.Getenv("SMTP_USER"),
        Password:         os.Getenv("SMTP_PASS"),
        From:             "noreply@myapp.com",
        VerificationURL:  "https://myapp.com/verify-email",
        PasswordResetURL: "https://myapp.com/reset-password",
    }),
    servex.WithEmailRequireVerification(true),
)
```

`WithEmailSMTP` sets the sender on all three flows (verification, password reset, 2FA email).

### Email Verification Modes

```go
// Code mode (default) — 6-digit numeric code sent to email
servex.WithEmailVerificationMode(servex.EmailVerificationCodeMode)
servex.WithEmailVerificationCodeDigits(6)
servex.WithEmailVerificationCodeDuration(15 * time.Minute)

// Token mode — long token for clickable verification links
servex.WithEmailVerificationMode(servex.EmailVerificationTokenMode)
servex.WithEmailVerificationTokenDuration(24 * time.Hour)
```

### Custom Email Sender

```go
// Implement VerificationEmailSender
type MyEmailSender struct{}
func (s *MyEmailSender) SendVerificationEmail(ctx context.Context, to, codeOrToken string) error { ... }

servex.WithVerificationEmailSender(&MyEmailSender{})

// Implement PasswordResetEmailSender
type MyResetSender struct{}
func (s *MyResetSender) SendPasswordResetEmail(ctx context.Context, to, token string) error { ... }

servex.WithPasswordResetEmailSender(&MyResetSender{})
```

### Custom Code Generator

```go
servex.WithEmailVerificationCodeGenerator(servex.NewNumericCodeGenerator(8))
```

### Email Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/verify-email` | No | `{"code":"123456","email":"..."}` (code mode) or `{"token":"..."}` (token mode) |
| POST | `/resend-verification` | Bearer | Resend verification email |
| POST | `/forgot-password` | No | `{"email":"..."}` — sends reset token |
| POST | `/reset-password` | No | `{"token":"...","new_password":"..."}` |

### EmailAuthDatabase Extension

Your database must also implement `EmailAuthDatabase` for email lookup:
```go
type EmailAuthDatabase interface {
    FindByEmail(ctx context.Context, email string) (User, bool, error)
}
```

---

## 7. OAuth Social Login

### Setup

```go
server, _ := servex.NewServer(
    servex.WithAuth(myDB),  // must also implement OAuthAuthDatabase
    servex.WithAuthKey(accessKey, refreshKey),
    servex.WithOAuthGoogle(servex.GoogleOAuthConfig{
        ClientID:     os.Getenv("GOOGLE_ID"),
        ClientSecret: os.Getenv("GOOGLE_SECRET"),
        RedirectURL:  "https://myapp.com/api/v1/auth/oauth/google/callback",
    }),
    servex.WithOAuthGitHub(servex.GitHubOAuthConfig{
        ClientID:     os.Getenv("GITHUB_ID"),
        ClientSecret: os.Getenv("GITHUB_SECRET"),
        RedirectURL:  "https://myapp.com/api/v1/auth/oauth/github/callback",
    }),
    servex.WithOAuthStateSigningKey(os.Getenv("OAUTH_STATE_KEY")),
    servex.WithOAuthAutoLink(true),
    servex.WithOAuthFrontendCallbackURL("https://myapp.com/auth/callback"),
)
```

### Available Providers

```go
servex.WithOAuthGoogle(servex.GoogleOAuthConfig{...})
servex.WithOAuthGitHub(servex.GitHubOAuthConfig{...})
servex.WithOAuthApple(servex.AppleOAuthConfig{...})
servex.WithOAuthTelegram(servex.TelegramOAuthConfig{...})
servex.WithOAuthYandex(servex.YandexOAuthConfig{...})
servex.WithOAuthVKID(servex.VKIDOAuthConfig{...})

// Custom provider
servex.WithOAuth(myCustomProvider)  // implements OAuthProvider interface
```

### OAuthAuthDatabase Extension

```go
type OAuthAuthDatabase interface {
    FindByOAuthProvider(ctx context.Context, provider string, providerID string) (User, bool, error)
}
```

### OAuth Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/oauth/{provider}` | No | Redirect to provider |
| GET | `/oauth/{provider}/callback` | No | Handle callback |
| POST | `/oauth/{provider}/link` | Bearer | Link provider to account |
| DELETE | `/oauth/{provider}/link` | Bearer | Unlink provider |

---

## 8. Two-Factor Authentication (2FA/TOTP)

### Setup

```go
server, _ := servex.NewServer(
    servex.WithAuth(myDB),
    servex.WithAuthKey(accessKey, refreshKey),
    servex.WithTwoFactor(os.Getenv("2FA_ENCRYPTION_KEY")),  // hex-encoded, 64 chars
    servex.WithTwoFactorIssuer("MyApp"),
    servex.WithTwoFactorEmailFallback(true),
    servex.WithTwoFactorBackupCodes(10),
    servex.WithTwoFactorMaxAttempts(5),
    servex.WithTwoFactorEmailSMTP(servex.SMTPConfig{...}),
)
```

### 2FA Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/2fa/setup` | Bearer | Generate TOTP secret + QR + backup codes |
| POST | `/2fa/enable` | Bearer | Verify TOTP code, enable 2FA |
| POST | `/2fa/disable` | Bearer | Disable 2FA |
| POST | `/2fa/verify` | Pending token | Complete login with 2FA code |
| POST | `/2fa/send-email-code` | Pending token | Send 2FA code via email |

### Custom 2FA Email Sender

```go
type TwoFactorEmailSender interface {
    SendTwoFactorCodeEmail(ctx context.Context, to string, code string) error
}
servex.WithTwoFactorEmailSender(&mySender{})
```

---

## 9. Security

### Security Headers

```go
// Standard security headers (X-Content-Type-Options, X-Frame-Options, etc.)
servex.WithSecurityHeaders()

// Strict mode (adds HSTS, stricter CSP, etc.)
servex.WithStrictSecurityHeaders()

// Custom Content-Security-Policy
servex.WithContentSecurityPolicy("default-src 'self'; script-src 'self'")

// HSTS
servex.WithHSTSHeader(31536000, true, true) // maxAge, includeSubdomains, preload

// Path filtering
servex.WithSecurityExcludePaths("/health", "/metrics")
servex.WithSecurityIncludePaths("/api/")
```

### CSRF Protection

```go
servex.WithCSRFProtection()
servex.WithCSRFTokenName("X-CSRF-Token")
servex.WithCSRFCookieName("_csrf")
servex.WithCSRFCookieSecure(true)
servex.WithCSRFCookieHttpOnly(true)
servex.WithCSRFCookieSameSite("Strict")
servex.WithCSRFTokenEndpoint("/api/csrf-token")
servex.WithCSRFSafeMethods("GET", "HEAD", "OPTIONS")
```

### Custom/Remove Headers

```go
servex.WithCustomHeaders(map[string]string{
    "X-Powered-By": "MyApp",
    "X-Version":    "1.0",
})
servex.WithRemoveHeaders("Server", "X-Powered-By")
```

### HTTPS Redirect

```go
servex.WithHTTPSRedirect()                          // 301 permanent
servex.WithHTTPSRedirectTemporary()                  // 302 temporary
servex.WithHTTPSRedirectTrustedProxies("10.0.0.0/8")
servex.WithHTTPSRedirectExcludePaths("/health")
```

### TLS Certificate

```go
servex.WithCertificateFromFile("cert.pem", "key.pem")
servex.WithCertificate(tlsCert)

// Utilities
cert, err := servex.ReadCertificateFromFile("cert.pem", "key.pem")
cert, err := servex.ReadCertificate(certPEM, keyPEM)
```

---

## 10. CORS

```go
// Permissive defaults
servex.WithCORS()

// Custom configuration
servex.WithCORSAllowOrigins("https://myapp.com", "https://admin.myapp.com")
servex.WithCORSAllowMethods("GET", "POST", "PUT", "DELETE")
servex.WithCORSAllowHeaders("Authorization", "Content-Type", "X-Custom")
servex.WithCORSExposeHeaders("X-Request-ID")
servex.WithCORSAllowCredentials()
servex.WithCORSMaxAge(3600)
servex.WithCORSExcludePaths("/internal/")
servex.WithCORSIncludePaths("/api/")
```

---

## 11. Rate Limiting

```go
// Simple: requests per second or minute
servex.WithRPS(10)                 // 10 requests/second per client IP
servex.WithRPM(100)                // 100 requests/minute per client IP

// Custom interval
servex.WithRequestsPerInterval(50, 30*time.Second)  // 50 requests per 30s
servex.WithBurstSize(20)                             // allow bursts up to 20

// Customize response
servex.WithRateLimitStatusCode(http.StatusServiceUnavailable) // default: 429
servex.WithRateLimitMessage("Rate limit exceeded, try again later")

// Custom key function (default: client IP)
servex.WithRateLimitKeyFunc(func(r *http.Request) string {
    return r.Header.Get("X-API-Key")  // rate limit per API key
})

// Path filtering
servex.WithRateLimitExcludePaths("/health", "/metrics")
servex.WithRateLimitIncludePaths("/api/")

// Trusted proxies for accurate client IP
servex.WithRateLimitTrustedProxies("10.0.0.0/8", "172.16.0.0/12")

// Full config
servex.WithRateLimitConfig(servex.RateLimitConfig{...})
```

---

## 12. Request Filtering

### IP Filtering

```go
servex.WithAllowedIPs("192.168.1.0/24", "10.0.0.1")
servex.WithBlockedIPs("192.168.1.100", "10.0.0.0/8")
```

### User-Agent Filtering

```go
servex.WithAllowedUserAgents("MyApp/1.0", "MyApp/2.0")
servex.WithBlockedUserAgents("BadBot/1.0")
servex.WithAllowedUserAgentsRegex("^MyApp/.*")
servex.WithBlockedUserAgentsRegex(".*[Bb]ot.*", ".*[Cc]rawler.*", ".*[Ss]craper.*")
```

### Header Filtering

```go
servex.WithAllowedHeaders(map[string][]string{
    "X-API-Version": {"v1", "v2"},
})
servex.WithBlockedHeaders(map[string][]string{
    "X-Malicious": {"true"},
})
servex.WithAllowedHeadersRegex(map[string][]string{
    "Authorization": {"^Bearer .*"},
})
```

### Query Parameter Filtering

```go
servex.WithBlockedQueryParams(map[string][]string{
    "debug": {"true", "1"},
    "admin": {"true"},
})
servex.WithBlockedQueryParamsRegex(map[string][]string{
    "q": {".*<script>.*"},
})
```

### Filter Options

```go
servex.WithFilterStatusCode(403)                     // default response code
servex.WithFilterMessage("Forbidden")                // response message
servex.WithFilterExcludePaths("/health", "/metrics")
servex.WithFilterIncludePaths("/api/")
servex.WithFilterTrustedProxies("10.0.0.0/8")
```

### Dynamic Filtering at Runtime

```go
filter := server.Filter()
filter.AddBlockedIP("1.2.3.4")
filter.RemoveBlockedIP("1.2.3.4")
filter.AddAllowedIP("5.6.7.8")
filter.IsIPBlocked("1.2.3.4")
filter.GetBlockedIPs()
filter.AddBlockedUserAgent("BadBot")
filter.ClearAllBlockedIPs()
```

---

## 13. Reverse Proxy & Load Balancing

```go
server, _ := servex.NewServer(
    servex.WithProxyConfig(servex.ProxyConfiguration{
        Enabled:       true,
        GlobalTimeout: 30 * time.Second,
        HealthCheck: servex.HealthCheckConfig{
            Enabled:         true,
            DefaultInterval: 30 * time.Second,
            Timeout:         5 * time.Second,
            RetryCount:      2,
        },
        TrafficDump: servex.TrafficDumpConfig{
            Enabled:     true,
            Directory:   "./traffic_logs",
            IncludeBody: true,
            MaxBodySize: 32 * 1024,
            SampleRate:  0.5,
        },
        Rules: []servex.ProxyRule{
            {
                Name:          "api-backend",
                PathPrefix:    "/api/",
                StripPrefix:   "/api",
                Timeout:       20 * time.Second,
                LoadBalancing: servex.WeightedRoundRobinStrategy,
                Backends: []servex.Backend{
                    {URL: "http://backend1:8081", Weight: 3},
                    {URL: "http://backend2:8082", Weight: 1},
                },
            },
            {
                Name:          "static-backend",
                PathPrefix:    "/static/",
                LoadBalancing: servex.RoundRobinStrategy,
                Backends: []servex.Backend{
                    {URL: "http://cdn1:9001"},
                    {URL: "http://cdn2:9002"},
                },
            },
        },
    }),
)
```

### Load Balancing Strategies

- `servex.RoundRobinStrategy` — even distribution
- `servex.WeightedRoundRobinStrategy` — weighted distribution
- `servex.LeastConnectionsStrategy` — fewest active connections
- `servex.RandomStrategy` — random selection
- `servex.WeightedRandomStrategy` — weighted random
- `servex.IPHashStrategy` — sticky sessions by client IP

---

## 14. Static Files & SPA

```go
// Serve static files
servex.WithStaticFiles("./public", "/static")  // dir, URL prefix

// SPA mode (unmatched routes serve index.html)
servex.WithSPAMode("./dist", "index.html")

// Cache rules
servex.WithStaticFileCache(86400)                           // 1 day for all
servex.WithStaticFileCache(86400, map[string]int{".js": 604800}) // 7 days for JS

// Exclude paths from static serving
servex.WithStaticFileExclusions("/api/", "/health")

// Full config
servex.WithStaticFileConfig(servex.StaticFileConfig{
    Enabled:    true,
    Dir:        "./public",
    URLPrefix:  "/static",
    SPAMode:    true,
    IndexFile:  "index.html",
    CacheMaxAge: 86400,
})
```

---

## 15. Compression

```go
servex.WithCompression()                      // gzip with defaults
servex.WithCompressionLevel(6)                // 1-9 (1=fastest, 9=best)
servex.WithCompressionMinSize(1024)           // don't compress < 1KB
servex.WithCompressionTypes("application/json", "text/html")
servex.WithCompressionExcludePaths("/health")
servex.WithCompressionIncludePaths("/api/")
```

---

## 16. Cache Control

```go
// Presets
servex.WithCacheNoCache()                     // Cache-Control: no-cache
servex.WithCacheNoStore()                     // Cache-Control: no-store
servex.WithCachePublic(3600)                  // Cache-Control: public, max-age=3600
servex.WithCachePrivate(300)                  // Cache-Control: private, max-age=300
servex.WithCacheStaticAssets(604800)          // 7 days, public, immutable
servex.WithCacheAPI(60)                       // 60s, private, must-revalidate

// Manual headers
servex.WithCacheHeaders()                     // enable cache header middleware
servex.WithCacheControl("public, max-age=3600, s-maxage=7200")
servex.WithCacheExpires("Thu, 01 Dec 2025 16:00:00 GMT")
servex.WithCacheExpiresTime(time.Now().Add(24 * time.Hour))
servex.WithCacheETag("\"abc123\"")
servex.WithCacheETagFunc(func(r *http.Request) string { return computeETag(r) })
servex.WithCacheLastModified("Mon, 01 Jan 2024 00:00:00 GMT")
servex.WithCacheLastModifiedTime(modTime)
servex.WithCacheLastModifiedFunc(func(r *http.Request) time.Time { return getModTime(r) })
servex.WithCacheVary("Accept, Authorization")

// Path filtering
servex.WithCacheExcludePaths("/api/")
servex.WithCacheIncludePaths("/static/")
```

---

## 17. Health & Metrics

```go
// Health endpoint (GET /health returns 200 OK)
servex.WithHealthEndpoint()
servex.WithHealthPath("/healthz")             // custom path
servex.WithDisableHealthEndpoint()            // disable

// Built-in metrics (Prometheus-compatible, GET /metrics)
servex.WithDefaultMetrics()
servex.WithDefaultMetrics("/custom-metrics")  // custom path

// Custom metrics implementation
servex.WithMetrics(myMetrics)                 // implements Metrics interface

// Both custom + default
servex.WithMetricsAndDefault(myMetrics, "/metrics")
```

### Metrics Interface

```go
type Metrics interface {
    HandleRequest(r *http.Request)
    HandleResponse(r *http.Request, w http.ResponseWriter, statusCode int, duration time.Duration)
}
```

---

## 18. Logging & Audit

### Logger

```go
servex.WithLogger(myLogger)       // implements Logger interface

type Logger interface {
    Debug(msg string, fields ...any)
    Info(msg string, fields ...any)
    Error(msg string, fields ...any)
}
```

### Request Logging

```go
servex.WithRequestLogger(myRequestLogger) // implements RequestLogger
servex.WithNoRequestLog()                  // disable request logging
servex.WithDisableRequestLogging()         // alias
servex.WithNoLogClientErrors()             // suppress 4xx error logging
servex.WithLogFields("ip", "url", "method", "status", "duration_ms")
```

Log field constants: `RequestIDLogField`, `IPLogField`, `UserAgentLogField`, `URLLogField`, `MethodLogField`, `ProtoLogField`, `ErrorLogField`, `ErrorMessageLogField`, `StatusLogField`, `DurationLogField`.

### Error Handling

```go
servex.WithSendErrorToClient()   // include error details in response (dev only)
servex.WithDebug()               // debug mode: verbose logging + client errors
```

### Audit Logging

```go
servex.WithAuditLogger(myAuditLogger)  // implements AuditLogger
servex.WithDefaultAuditLogger()        // uses server's Logger
servex.WithAuditLogHeaders(true)       // include request headers in audit events
```

### AuditLogger Interface

```go
type AuditLogger interface {
    LogSecurityEvent(event AuditEvent)
    LogAuthenticationEvent(eventType AuditEventType, r *http.Request, userID string, success bool, details map[string]any)
    LogRateLimitEvent(r *http.Request, key string, details map[string]any)
    LogFilterEvent(eventType AuditEventType, r *http.Request, filterType, filterValue, rule string)
    LogCSRFEvent(eventType AuditEventType, r *http.Request, details map[string]any)
    LogSuspiciousActivity(r *http.Request, activityType string, details map[string]any)
}
```

Audit event types include: auth events (`AuditEventAuthLoginSuccess`, `AuditEventAuthLoginFailure`, etc.), rate limit events, filter events, CSRF events, email/OAuth/2FA events, and suspicious activity events.

Severity levels: `AuditSeverityLow`, `AuditSeverityMedium`, `AuditSeverityHigh`, `AuditSeverityCritical`.

---

## 19. Request Size Limits

```go
servex.WithRequestSizeLimits()              // enable with defaults
servex.WithStrictRequestSizeLimits()        // stricter defaults
servex.WithMaxRequestBodySize(32 << 20)     // 32 MB
servex.WithMaxJSONBodySize(1 << 20)         // 1 MB
servex.WithMaxFileUploadSize(100 << 20)     // 100 MB
servex.WithMaxMultipartMemory(10 << 20)     // 10 MB
```

---

## 20. Server Timeouts

```go
servex.WithReadTimeout(10 * time.Second)
servex.WithReadHeaderTimeout(5 * time.Second)
servex.WithIdleTimeout(120 * time.Second)
servex.WithMaxHeaderBytes(1 << 20)
```

---

## 21. Swagger UI

```go
// From bytes
servex.WithSwaggerUI(specBytes)

// From file
servex.WithSwaggerUIFile("./openapi.yaml")

// Custom path (default: /swagger)
servex.WithSwaggerUIPath("/api-docs")

// Standalone handler (for manual mounting)
handler := servex.SwaggerHandler(specBytes, servex.WithSwaggerTitle("My API"))
http.Handle("/docs/", http.StripPrefix("/docs", handler))
```

Serves: `GET /swagger` (HTML UI), `GET /swagger/spec` (the spec file).

---

## 22. Presets

Pre-configured option sets for common scenarios:

```go
// Development — permissive, no security, debug logging
server, _ := servex.NewServer(servex.DevelopmentPreset()...)

// Production — full security, HTTPS, proper logging
server, _ := servex.NewServer(servex.ProductionPreset(tlsCert)...)

// API server — rate limiting, compression, security headers, CORS, health, metrics
server, _ := servex.NewServer(servex.APIServerPreset()...)

// Web app — static files, SPA mode, security, compression
server, _ := servex.NewServer(servex.WebAppPreset(tlsCert)...)

// Microservice — health, metrics, compression, security headers
server, _ := servex.NewServer(servex.MicroservicePreset()...)

// High security — strict headers, CSRF, HTTPS redirect, rate limiting
server, _ := servex.NewServer(servex.HighSecurityPreset(tlsCert)...)

// TLS only
server, _ := servex.NewServer(servex.TLSPreset("cert.pem", "key.pem")...)

// Merge preset with custom options
opts := servex.MergeWithPreset(servex.APIServerPreset(),
    servex.WithAuth(myDB),
    servex.WithRPM(200),
)
server, _ := servex.NewServer(opts...)

// Merge multiple presets
opts := servex.MergePresets(servex.APIServerPreset(), servex.TLSPreset("c.pem", "k.pem"))
```

---

## 23. YAML Configuration

```go
// Load from file
config, err := servex.LoadConfig("config.yaml")
config, err := servex.LoadConfigFromFile("config.yaml")

// Load from environment only
config, err := servex.LoadConfigFromEnv()

// Create server from config
server, err := servex.NewServerFromConfig(config)

// One-liner: load config + create server + start
shutdown, err := servex.StartServerFromConfig("config.yaml", func(r *mux.Router) {
    r.HandleFunc("/api/items", itemsHandler).Methods("GET")
})
```

Environment variables use `SERVEX_` prefix with underscore-separated paths:
`SERVEX_SERVER_HTTP`, `SERVEX_AUTH_JWT_ACCESS_SECRET`, `SERVEX_RATE_LIMIT_ENABLED`, etc.

### Example YAML

```yaml
server:
  http: ":8080"
  https: ":8443"
  read_timeout: "10s"
  idle_timeout: "120s"

auth:
  enabled: true
  jwt_access_secret: "hex-encoded-32-byte-key"
  jwt_refresh_secret: "hex-encoded-32-byte-key"
  access_token_duration: "15m"
  refresh_token_duration: "720h"
  issuer: "my-service"
  initial_roles: ["user"]
  email_verification:
    enabled: true
    mode: "code"
    code_digits: 6
    smtp:
      host: "smtp.gmail.com"
      port: 587
      username: "user"
      password: "pass"
      from: "noreply@myapp.com"
      verification_url: "https://myapp.com/verify"
  oauth:
    enabled: true
    auto_link_by_email: true
    state_signing_key: "hex-64-chars"
    google:
      client_id: "..."
      client_secret: "..."
      redirect_url: "https://myapp.com/api/v1/auth/oauth/google/callback"
  two_factor:
    enabled: true
    issuer: "MyApp"
    encryption_key: "hex-64-chars"

rate_limit:
  enabled: true
  requests_per_interval: 100
  interval: "1m"
  burst_size: 20

security:
  enabled: true
  content_security_policy: "default-src 'self'"

cors:
  enabled: true
  allow_origins: ["https://myapp.com"]
  allow_credentials: true

compression:
  enabled: true
  level: 6

cache:
  enabled: true
  cache_control: "public, max-age=3600"

static_files:
  enabled: true
  dir: "./public"
  url_prefix: "/static"

swagger:
  enabled: true
  spec_file: "./openapi.yaml"
  path: "/swagger"
```

---

## 24. Standalone Middleware Registration

For advanced use cases, middleware can be registered directly on any `MiddlewareRouter`:

```go
servex.RegisterRateLimitMiddleware(router, rateLimitCfg)
servex.RegisterFilterMiddleware(router, filterCfg)
servex.RegisterSecurityHeadersMiddleware(router, securityCfg)
servex.RegisterCSRFMiddleware(router, securityCfg)
servex.RegisterCacheControlMiddleware(router, cacheCfg)
servex.RegisterCompressionMiddleware(router, compressionCfg)
servex.RegisterCORSMiddleware(router, opts)
servex.RegisterLoggingMiddleware(router, requestLogger, metrics)
servex.RegisterRecoverMiddleware(router, errorLogger)
servex.RegisterStaticFileMiddleware(router, staticCfg)
servex.RegisterProxyMiddleware(router, proxyCfg)
servex.RegisterSimpleAuthMiddleware(router, "api-token")
servex.RegisterHTTPSRedirectMiddleware(router, redirectCfg)
servex.RegisterCustomHeadersMiddleware(router, headers)
servex.RegisterHeaderRemovalMiddleware(router, headersToRemove)
servex.RegisterRequestSizeLimitMiddleware(router, opts)

// Location-based (different configs per path)
servex.RegisterLocationBasedRateLimitMiddleware(router, []servex.LocationRateLimitConfig{...})
servex.RegisterLocationBasedFilterMiddleware(router, []servex.LocationFilterConfig{...})
```

---

## 25. Complete Application Example

```go
package main

import (
    "context"
    "encoding/hex"
    "fmt"
    "net/http"
    "os"
    "syscall"

    "github.com/maxbolgarin/servex/v2"
)

func main() {
    server, err := servex.NewServer(
        // Auth
        servex.WithAuthMemoryDatabase(),
        servex.WithAuthKey(os.Getenv("ACCESS_KEY"), os.Getenv("REFRESH_KEY")),
        servex.WithAuthIssuer("my-api"),
        servex.WithAuthTokensDuration(15*time.Minute, 30*24*time.Hour),
        servex.WithAuthInitialRoles("user"),

        // Security
        servex.WithSecurityHeaders(),
        servex.WithCORS(),

        // Rate limiting
        servex.WithRPM(120),

        // Infrastructure
        servex.WithCompression(),
        servex.WithHealthEndpoint(),
        servex.WithDefaultMetrics(),
        servex.WithDefaultAuditLogger(),
    )
    if err != nil {
        fmt.Fprintf(os.Stderr, "server init: %v\n", err)
        os.Exit(1)
    }

    // Public routes
    srv := server.WithBasePath("/api/v1")
    srv.GET("/items", listItems)
    srv.GET("/items/{id}", getItem)

    // Protected routes
    srv.PostWithAuth("/items", createItem, "user")
    srv.PutWithAuth("/items/{id}", updateItem, "user")
    srv.DeleteWithAuth("/items/{id}", deleteItem, "admin")

    // Start with graceful shutdown
    err = server.StartWithWaitSignalsHTTP(
        context.Background(), ":8080",
        syscall.SIGINT, syscall.SIGTERM,
    )
    if err != nil {
        fmt.Fprintf(os.Stderr, "server error: %v\n", err)
        os.Exit(1)
    }
}

func listItems(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    ctx.JSON([]map[string]string{
        {"id": "1", "name": "Item 1"},
        {"id": "2", "name": "Item 2"},
    })
}

func getItem(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    id := ctx.Path("id")
    ctx.JSON(map[string]string{"id": id, "name": "Item " + id})
}

func createItem(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    var req struct {
        Name string `json:"name"`
    }
    if err := ctx.ReadJSON(&req); err != nil {
        ctx.BadRequest(err, "invalid JSON")
        return
    }
    if req.Name == "" {
        ctx.BadRequest(nil, "name is required")
        return
    }
    ctx.Response(http.StatusCreated, map[string]string{"id": "new-id", "name": req.Name})
}

func updateItem(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    id := ctx.Path("id")
    var req struct {
        Name string `json:"name"`
    }
    if err := ctx.ReadJSON(&req); err != nil {
        ctx.BadRequest(err, "invalid JSON")
        return
    }
    ctx.JSON(map[string]string{"id": id, "name": req.Name})
}

func deleteItem(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    _ = ctx.Path("id")
    ctx.Response(http.StatusNoContent)
}
```

---

## 26. Server-Sent Events (SSE)

SSE support for real-time streaming. Core code in `sse.go`.

### Key Types

- **`SSEHandler`** — `func(sse *SSEConn)`, runs for connection lifetime.
- **`SSEConn`** — thread-safe SSE writer with methods: `Send`, `SendEvent`, `SendEventWithID`, `SendJSON`, `SendEventJSON`, `SendComment`, `SetRetry`. Metadata: `Path`, `Query`, `Header`, `LastEventID`, `UserID`, `UserRoles`, `ClientIP`, `Done`.

### Server Methods

```go
server.SSE(path, handler)                       // Register SSE route
server.SSEWithAuth(path, handler, roles...)      // Register SSE route with auth
```

### Quick Example

```go
server.SSE("/events/{topic}", func(sse *servex.SSEConn) {
    topic := sse.Path("topic")
    for {
        select {
        case <-sse.Done():
            return
        case msg := <-getMessages(topic):
            sse.SendEvent("message", msg)
        }
    }
})
```

---

## 27. API Key Authentication

API keys with SHA-256 hashing, scopes, and expiration. Code in `apikey.go`, options in `options_apikey.go`.

### Setup

```go
server, _ := servex.NewServer(
    servex.WithAuth(myDB),
    servex.WithAuthKey(accessKey, refreshKey),
    servex.WithAPIKeys(myAPIKeyDB),          // implements APIKeyDatabase
    servex.WithAPIKeyPrefix("myapp_"),
    servex.WithAPIKeyScopes("read", "write", "admin"),
    servex.WithAPIKeyMaxPerUser(10),
)

// Or with in-memory database (dev/testing)
servex.WithAPIKeysMemoryDatabase()
```

### APIKeyDatabase Interface

```go
type APIKeyDatabase interface {
    CreateAPIKey(ctx context.Context, key *APIKey) error
    FindAPIKeyByHash(ctx context.Context, keyHash string) (APIKey, bool, error)
    RevokeAPIKey(ctx context.Context, keyID string) error
    ListAPIKeysByUser(ctx context.Context, userID string) ([]APIKey, error)
    UpdateAPIKeyLastUsed(ctx context.Context, keyID string, t time.Time) error
}
```

### APIKey Struct

```go
type APIKey struct {
    ID         string
    UserID     string
    Name       string
    KeyHash    string     // SHA-256 hash
    KeyPrefix  string     // first 12 chars for display
    Scopes     []string
    ExpiresAt  *time.Time
    CreatedAt  time.Time
    LastUsedAt *time.Time
}
```

### Protecting Routes with API Keys

```go
auth := server.AuthManager()
server.GET("/api/data", auth.WithAPIKey(dataHandler, "read"))
server.POST("/api/data", auth.WithAPIKey(createHandler, "write"))
```

Clients send: `X-API-Key: myapp_...` or `Authorization: ApiKey myapp_...`

### Auto-Registered Endpoints (under auth base path)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api-keys` | Bearer (JWT) | Create new API key (returns full key once) |
| GET | `/api-keys` | Bearer (JWT) | List user's API keys (prefix only) |
| DELETE | `/api-keys/{id}` | Bearer (JWT) | Revoke an API key |

### Helper Functions

```go
fullKey, keyHash, keyPrefix, err := servex.GenerateAPIKey("myapp_", 16)
hash := servex.HashAPIKey(key)
```

### YAML Config

```yaml
api_key:
  prefix: "myapp_"
  valid_scopes: ["read", "write", "admin"]
  max_per_user: 10
  key_length: 16
  use_memory_database: false
```

---

## 28. SQL Auth Database

Built-in SQL auth database supporting PostgreSQL, MySQL, and SQLite. Implements `AuthDatabase`, `EmailAuthDatabase`, and `OAuthAuthDatabase`. Code in `auth_sql.go`.

### Setup

```go
// From existing *sql.DB
sqlDB, _ := sql.Open("pgx", "postgres://user:pass@localhost/mydb")
authDB, _ := servex.NewSQLAuthDatabase(sqlDB, "pgx")

server, _ := servex.NewServer(
    servex.WithAuth(authDB),
    servex.WithAuthKey(accessKey, refreshKey),
)

// Or via option
server, _ := servex.NewServer(
    servex.WithAuthSQL(sqlDB, "pgx"),
    servex.WithAuthKey(accessKey, refreshKey),
)

// Or from DSN
server, _ := servex.NewServer(
    servex.WithAuthSQLDSN("pgx", "postgres://user:pass@localhost/mydb"),
    servex.WithAuthKey(accessKey, refreshKey),
)
```

### Supported Drivers

| Driver strings | Database |
|---------------|----------|
| `postgres`, `pgx`, `postgresql` | PostgreSQL |
| `mysql` | MySQL |
| `sqlite3`, `sqlite` | SQLite |

### Options

```go
servex.SQLTablePrefix("myapp_")   // prefix table names
servex.SQLAutoMigrate(true)        // auto-create tables (default: true)
```

Auto-migration creates `users` and `user_oauth_providers` tables with proper indexes.

---

## 29. W3C Trace Context

W3C Trace Context (RFC 9531) propagation for distributed tracing. Code in `trace.go`.

### Setup

```go
server, _ := servex.NewServer(
    servex.WithTracePropagation(),
)
```

### Behavior

- Parses incoming `traceparent` header, generates new trace ID if absent
- Generates a new span ID per request
- Sets `traceparent` and `tracestate` response headers
- Stores trace/span IDs in request context
- Adds `trace_id` and `span_id` to request logs

### Accessing in Handlers

```go
func handler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    traceID := ctx.TraceID()  // 32 hex chars
    spanID := ctx.SpanID()    // 16 hex chars
}
```

---

## 30. Testing Utilities

`TestServer`, `TestRequest`, and `TestResponse` types in `testing.go` for integration testing.

### Quick Example

```go
func TestMyAPI(t *testing.T) {
    ts := servex.NewTestServer(t,
        servex.WithAuthMemoryDatabase(),
        servex.WithAuthKey(accessKey, refreshKey),
    )
    ts.Server.GET("/items", listItems)

    resp := ts.Get("/items").Do()
    if resp.Code != 200 { t.Fatal("expected 200") }

    var items []Item
    resp.JSON(&items)

    resp = ts.Post("/items").
        WithJSON(map[string]string{"name": "test"}).
        WithAuth("bearer-token").
        Do()
}
```

### TestRequest Methods

`WithBody(io.Reader)`, `WithJSON(any)`, `WithHeader(k, v)`, `WithAuth(token)`, `WithCookie(name, value)`, `Do() *TestResponse`

### TestResponse Fields/Methods

`Code int`, `Header http.Header`, `Body []byte`, `JSON(v any) error`, `BodyString() string`

---

## 31. Raw HTTP Utilities

Package-level functions in `rawhttp.go` for constructing raw HTTP bytes:

```go
raw := servex.MakeRawRequest("/path", "example.com:80", headers, body)
raw := servex.MakeRawResponse(200, headers, body)
```

---

## 32. Key Patterns Summary

- **Options pattern**: All configuration via `With*()` functions passed to `NewServer()`
- **Context wrapper**: `servex.C(w, r)` for convenient request/response handling
- **Middleware chain order**: rate limiting -> size limits -> filtering -> security -> CORS -> cache -> compression -> logging -> recovery -> auth -> proxy -> static
- **Interface-based extensibility**: implement `Logger`, `RequestLogger`, `AuditLogger`, `Metrics`, `AuthDatabase`, `APIKeyDatabase`, `VerificationEmailSender`, `PasswordResetEmailSender`, `TwoFactorEmailSender`, `OAuthProvider` for custom behavior
- **Presets for quick start**: `DevelopmentPreset()`, `ProductionPreset()`, `APIServerPreset()`, etc.
- **YAML + env config**: `LoadConfig()` with `SERVEX_` environment variable overrides
