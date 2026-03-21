# Servex - Production-Ready HTTP Server for Go

[![Go Version][version-img]][doc] [![GoDoc][doc-img]][doc] [![Build][ci-img]][ci] [![Coverage][coverage-img]][coverage] [![GoReport][report-img]][report] [![MIT][mit-img]][mit]

**Servex** eliminates HTTP server boilerplate in Go. Focus on business logic while getting production-ready features out of the box.

## Features

- 🚀 **Zero Boilerplate** - Configure once, code business logic
- 🔒 **Security First** - JWT auth, OAuth, 2FA, email verification, rate limiting, request filtering, security headers, audit logging
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
| **Authentication** | `WithAuth(db)` - JWT auth with custom database<br>`WithAuthToken(token)` - Simple bearer token<br>`WithAuthMemoryDatabase()` - In-memory user storage<br>`WithAuthKey(accessKey, refreshKey)` - JWT signing keys<br>`WithAuthTokensDuration(access, refresh)` - Token lifetimes<br>`WithAuthIssuer(issuer)` - JWT issuer<br>`WithAuthBasePath(path)` - Auth routes prefix<br>`WithAuthInitialRoles(roles...)` - Default user roles |
| **Email Verification** | `WithEmailSMTP(cfg)` - SMTP email sender<br>`WithEmailSender(sender)` - Custom email implementation<br>`WithEmailRequireVerification(true)` - Block login until verified<br>`WithEmailTokenDurations(verify, reset)` - Token lifetimes<br>`WithEmailResendCooldown(d)` - Resend rate limit |
| **OAuth Providers** | `WithOAuthGoogle(cfg)` - Google login<br>`WithOAuthGitHub(cfg)` - GitHub login<br>`WithOAuthApple(cfg)` - Apple login<br>`WithOAuthTelegram(cfg)` - Telegram login<br>`WithOAuthYandex(cfg)` - Yandex login<br>`WithOAuth(providers...)` - Custom providers<br>`WithOAuthAutoLink(bool)` - Auto-link by email |
| **Two-Factor Auth** | `WithTwoFactor(encKey)` - Enable TOTP 2FA<br>`WithTwoFactorIssuer(name)` - Authenticator app name<br>`WithTwoFactorEmailFallback(bool)` - Email code fallback<br>`WithTwoFactorBackupCodes(count)` - Backup code count<br>`WithTwoFactorMaxAttempts(n)` - Max verify attempts |
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

Servex provides a complete JWT authentication system with user registration, login, token refresh, logout, and role-based access control.

#### Setup

```go
// Development (in-memory, data lost on restart)
server, _ := servex.NewServer(
    servex.WithAuthMemoryDatabase(),
    servex.WithAuthKey(accessKeyHex, refreshKeyHex), // hex-encoded, ≥64 chars each
)

// Production (custom database)
server, _ := servex.NewServer(
    servex.WithAuth(myDB),                           // your AuthDatabase implementation
    servex.WithAuthKey(os.Getenv("JWT_ACCESS"), os.Getenv("JWT_REFRESH")),
    servex.WithAuthTokensDuration(15*time.Minute, 30*24*time.Hour),
    servex.WithAuthInitialRoles("user"),
    servex.WithAuthInitialUsers(servex.InitialUser{
        Username: "admin",
        Password: os.Getenv("ADMIN_PASS"),
        Roles:    []servex.UserRole{"admin"},
    }),
)
```

Generate secrets: `openssl rand -hex 32` (produces 64 hex characters = 32 bytes).

#### Auto-Registered Endpoints

These endpoints are registered automatically under `AuthBasePath` (default `/api/v1/auth`):

**Core Auth:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/register` | Create user account |
| `POST` | `/login` | Authenticate and get tokens |
| `POST` | `/refresh` | Exchange refresh token for new tokens |
| `POST` | `/logout` | Invalidate refresh token |
| `GET` | `/me` | Get current user (requires auth) |

**Email Verification** (when email is enabled):

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/verify-email` | Verify email with token |
| `POST` | `/resend-verification` | Resend verification email (auth required) |
| `POST` | `/forgot-password` | Request password reset link |
| `POST` | `/reset-password` | Reset password with token |

**OAuth** (when OAuth is enabled):

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/oauth/{provider}` | Redirect to provider login page |
| `GET` | `/oauth/{provider}/callback` | Handle provider callback |
| `POST` | `/oauth/{provider}/link` | Link provider to account (auth required) |
| `DELETE` | `/oauth/{provider}/link` | Unlink provider (auth required) |

**Two-Factor Auth** (when 2FA is enabled):

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/2fa/setup` | Generate TOTP secret + backup codes (auth required) |
| `POST` | `/2fa/enable` | Verify TOTP code and enable 2FA (auth required) |
| `POST` | `/2fa/disable` | Disable 2FA (auth required, requires code) |
| `POST` | `/2fa/verify` | Complete login with 2FA code |
| `POST` | `/2fa/send-email-code` | Send 2FA code via email |

**Register / Login:**
```
POST /api/v1/auth/register
Content-Type: application/json

{"username": "john", "password": "securepass1", "email": "john@example.com"}
```
Response `201 Created` (register) or `200 OK` (login):
```json
{"id": "user-1", "username": "john", "roles": ["user"], "accessToken": "eyJ..."}
```
The refresh token is set as an `HttpOnly` cookie (not in the JSON body). The `email` field is optional.

**Refresh** — `POST /api/v1/auth/refresh` with the cookie. Returns new access token and rotates the refresh token.

**Logout** — `POST /api/v1/auth/logout`. Invalidates the refresh token and clears the cookie. Returns `204`.

#### Protecting Routes

```go
// Any authenticated user
server.HandleFuncWithAuth("/api/profile", profileHandler)

// Require specific role
server.GetWithAuth("/api/admin/users", listUsersHandler, "admin")
server.PostWithAuth("/api/posts", createPostHandler, "user", "editor")

// Or use the middleware directly
server.HandleFunc("/api/data", server.WithAuth(dataHandler, "user"))
```

Clients send the access token in the `Authorization` header:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

#### Accessing User Context

Inside protected handlers:
```go
func handler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    userID := ctx.UserID()            // string
    roles  := ctx.UserRoles()         // []UserRole
    verified := ctx.EmailVerified()   // bool
    has2FA := ctx.TwoFactorEnabled()  // bool
    ctx.Response(200, map[string]string{"user": userID})
}
```

#### How It Works

```
Login/Register
    │
    ├─ [If 2FA enabled] → Returns twoFactorToken (5 min JWT)
    │   └─ Client submits TOTP/backup/email code to /2fa/verify → tokens
    │
    ├─ Access Token (short-lived, default 5m)
    │   - Returned in JSON response
    │   - Sent by client as Authorization: Bearer <token>
    │   - Contains user_id, roles, email_verified, two_factor_enabled
    │   - Signed with HMAC-SHA256 (access secret)
    │
    └─ Refresh Token (long-lived, default 7 days)
        - Stored as HttpOnly/Secure/SameSite=Strict cookie
        - Hashed (bcrypt) and stored in database
        - Rotated on every refresh
        - Revoked on logout by clearing the DB hash
```

Token validation chain (for access tokens):
1. JWT signature verification
2. Token type check (`IsRefresh` must be false)
3. Issuer claim validation
4. Expiry check

Refresh token validation chain:
1. JWT signature verification (refresh secret)
2. User lookup in database
3. Token type check (`IsRefresh` must be true)
4. JWT expiry check
5. Bcrypt hash comparison against stored hash
6. Database-stored expiry check

#### Implementing AuthDatabase

To use auth in production, implement the `AuthDatabase` interface:

```go
type AuthDatabase interface {
    NewUser(ctx context.Context, username, passwordHash string, roles ...UserRole) (id string, err error)
    FindByID(ctx context.Context, id string) (User, bool, error)
    FindByUsername(ctx context.Context, username string) (User, bool, error)
    FindAll(ctx context.Context) ([]User, error)
    UpdateUser(ctx context.Context, id string, diff *UserDiff) error
}
```

**Optional sub-interfaces** (implement these only if you enable the corresponding features):

```go
// Required when Email is enabled
type EmailAuthDatabase interface {
    FindByEmail(ctx context.Context, email string) (User, bool, error)
}

// Required when OAuth is enabled
type OAuthAuthDatabase interface {
    FindByOAuthProvider(ctx context.Context, provider, providerID string) (User, bool, error)
}
```

The `User` struct fields you need to store:

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | Unique user identifier |
| `Username` | `string` | Unique username |
| `Roles` | `[]UserRole` | Assigned roles |
| `PasswordHash` | `string` | Bcrypt-hashed password |
| `RefreshTokenHash` | `string` | Bcrypt hash of current refresh token |
| `RefreshTokenExpiresAt` | `time.Time` | Refresh token expiry |
| `Email` | `string` | User email (optional) |
| `EmailVerified` | `bool` | Whether email is verified |
| `EmailVerifyTokenHash` | `string` | Email verification token hash |
| `EmailVerifyTokenExpiresAt` | `time.Time` | Verification token expiry |
| `PasswordResetTokenHash` | `string` | Password reset token hash |
| `PasswordResetTokenExpiresAt` | `time.Time` | Reset token expiry |
| `OAuthProviders` | `[]OAuthLink` | Linked OAuth provider accounts |
| `TwoFactorEnabled` | `bool` | Whether 2FA is active |
| `TwoFactorSecret` | `string` | Encrypted TOTP secret |
| `TwoFactorBackupCodes` | `[]string` | Bcrypt-hashed backup codes |

`UpdateUser` receives a `UserDiff` with pointer fields — apply only non-nil fields. All slice fields (`OAuthProviders`, `TwoFactorBackupCodes`, `Roles`) are full replacements, not deltas.

DB field name constants are exported for building queries: `servex.IDDBField`, `servex.UsernameDBField`, `servex.EmailDBField`, `servex.EmailVerifiedDBField`, `servex.OAuthProvidersDBField`, `servex.TwoFactorEnabledDBField`, etc.

#### Auth Configuration Options

| Option | Description |
|--------|-------------|
| `WithAuth(db)` | Enable JWT auth with custom database |
| `WithAuthMemoryDatabase()` | Enable with in-memory DB (dev only) |
| `WithAuthConfig(cfg)` | Set full `AuthConfig` at once |
| `WithAuthKey(access, refresh)` | Set JWT signing keys (hex-encoded) |
| `WithAuthTokensDuration(access, refresh)` | Token lifetimes |
| `WithAuthIssuer(name)` | JWT issuer claim |
| `WithAuthBasePath(path)` | Auth endpoint prefix (default `/api/v1/auth`) |
| `WithAuthInitialRoles(roles...)` | Default roles for new users |
| `WithAuthInitialUsers(users...)` | Users created on startup |
| `WithAuthRefreshTokenCookieName(name)` | Cookie name (default `_servexrt`) |
| `WithAuthNotRegisterRoutes(true)` | Skip auto-registering endpoints |

`AuthConfig` fields with defaults:

| Field | Default | Description |
|-------|---------|-------------|
| `MinPasswordLength` | `8` | Minimum password length (0 disables) |
| `ForceSecureCookies` | `false` | Always set Secure flag (use behind TLS proxy) |
| `AccessTokenDuration` | `5m` | Access token validity |
| `RefreshTokenDuration` | `7 days` | Refresh token validity |
| `IssuerNameInJWT` | `"servex"` | JWT issuer claim |
| `AuthBasePath` | `"/api/v1/auth"` | Endpoint base path |
| `RefreshTokenCookieName` | `"_servexrt"` | Refresh token cookie name |

#### Simple Bearer Auth

For APIs that don't need user accounts, use a pre-shared token:

```go
server, _ := servex.NewServer(servex.WithAuthToken("my-secret-api-key"))
// All requests must include: Authorization: Bearer my-secret-api-key
```

This uses constant-time comparison and applies to all routes globally.

#### Email Verification & Password Reset

Enable email features by providing an SMTP configuration or a custom `EmailSender`:

```go
server, _ := servex.New(
    servex.WithAuth(myDB),
    servex.WithAuthKey(accessKey, refreshKey),
    servex.WithEmailSMTP(servex.SMTPConfig{
        Host:            "smtp.gmail.com",
        Port:            587,
        Username:        os.Getenv("SMTP_USER"),
        Password:        os.Getenv("SMTP_PASS"),
        From:            "noreply@myapp.com",
        VerificationURL: "https://myapp.com/verify-email",
        PasswordResetURL: "https://myapp.com/reset-password",
    }),
)
```

This auto-registers four endpoints: `/verify-email`, `/resend-verification`, `/forgot-password`, `/reset-password`.

**Registration with email:** Include `"email": "user@example.com"` in the register request. A verification email is sent automatically.

**Require verification before login:**
```go
servex.WithEmailRequireVerification(true) // users must verify email before logging in
```

**Password reset flow:**
1. Client sends `POST /forgot-password` with `{"identifier": "user@example.com"}` (email or username)
2. Server always returns `200` (timing-safe, never reveals user existence)
3. If user found, a reset email is sent with a token link
4. Client sends `POST /reset-password` with `{"token": "...", "password": "newpass"}`

**Custom email sender:** Implement the `EmailSender` interface for SendGrid, SES, etc.:
```go
type EmailSender interface {
    SendVerificationEmail(ctx context.Context, to string, token string) error
    SendPasswordResetEmail(ctx context.Context, to string, token string) error
    SendTwoFactorCodeEmail(ctx context.Context, to string, code string) error
}

server, _ := servex.New(
    servex.WithEmailSender(myCustomSender),
)
```

#### OAuth (Social Login)

Add social login with one line per provider:

```go
server, _ := servex.New(
    servex.WithAuth(myDB), // must also implement OAuthAuthDatabase
    servex.WithAuthKey(accessKey, refreshKey),
    servex.WithOAuthGoogle(servex.GoogleOAuthConfig{
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        RedirectURL:  "https://myapp.com/api/v1/auth/oauth/google/callback",
    }),
    servex.WithOAuthGitHub(servex.GitHubOAuthConfig{
        ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
        ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
        RedirectURL:  "https://myapp.com/api/v1/auth/oauth/github/callback",
    }),
    servex.WithOAuthStateSigningKey(os.Getenv("OAUTH_STATE_KEY")), // hex-encoded, ≥64 chars
)
```

Generate the state signing key: `openssl rand -hex 32`.

**Built-in providers:** Google, GitHub, Apple, Telegram, Yandex. Each has its own config struct.

**Apple Sign In** requires a private key instead of a client secret:
```go
servex.WithOAuthApple(servex.AppleOAuthConfig{
    ClientID:    os.Getenv("APPLE_CLIENT_ID"),
    TeamID:      os.Getenv("APPLE_TEAM_ID"),
    KeyID:       os.Getenv("APPLE_KEY_ID"),
    PrivateKey:  os.Getenv("APPLE_PRIVATE_KEY"), // PEM-encoded ES256 key
    RedirectURL: "https://myapp.com/api/v1/auth/oauth/apple/callback",
})
```

**OAuth flow:**
1. Frontend redirects user to `GET /api/v1/auth/oauth/google`
2. Servex redirects to Google's OAuth page (CSRF-protected via HMAC state cookie)
3. Google redirects back to `/api/v1/auth/oauth/google/callback`
4. Servex exchanges code for user info, creates/links account, returns tokens

**Auto-linking:** By default, if an OAuth provider returns a verified email matching an existing user, the accounts are linked automatically. Disable with `WithOAuthAutoLink(false)`.

**Custom providers:** Implement the `OAuthProvider` interface:
```go
type OAuthProvider interface {
    Name() string
    AuthURL(state string) string
    Exchange(ctx context.Context, code string) (*OAuthUserInfo, error)
}

server, _ := servex.New(
    servex.WithOAuth(myCustomProvider),
)
```

#### Two-Factor Authentication (2FA)

Enable TOTP-based 2FA (works with Google Authenticator, Authy, etc.):

```go
server, _ := servex.New(
    servex.WithAuth(myDB),
    servex.WithAuthKey(accessKey, refreshKey),
    servex.WithTwoFactor(os.Getenv("2FA_ENCRYPTION_KEY")), // hex-encoded, exactly 64 chars (32 bytes)
    servex.WithTwoFactorIssuer("MyApp"), // shown in authenticator app
)
```

Generate the encryption key: `openssl rand -hex 32`.

**2FA setup flow:**
1. Authenticated user calls `POST /2fa/setup` → receives TOTP secret URI (for QR code) + backup codes
2. User scans QR code in authenticator app
3. User confirms with `POST /2fa/enable` + `{"code": "123456"}` → 2FA is now active

**Login with 2FA:**
1. User sends credentials to `POST /login`
2. Instead of tokens, receives `{"twoFactorToken": "..."}` (short-lived, 5 min)
3. User submits `POST /2fa/verify` with `{"token": "...", "code": "123456"}`
4. On success, receives normal access/refresh tokens

**Backup codes:** Generated during setup (default 10). Each can be used once as an alternative to a TOTP code.

**Email fallback** (enabled by default if email is configured): User can request `POST /2fa/send-email-code` to receive a 6-digit code via email instead of using the authenticator app.

**Configuration:**

| Option | Default | Description |
|--------|---------|-------------|
| `WithTwoFactor(key)` | - | Enable 2FA with AES-256-GCM encryption key |
| `WithTwoFactorIssuer(name)` | `"servex"` | Name shown in authenticator apps |
| `WithTwoFactorEmailFallback(bool)` | `true` | Allow email-based 2FA codes |
| `WithTwoFactorBackupCodes(n)` | `10` | Number of backup codes |
| `WithTwoFactorMaxAttempts(n)` | `5` | Max verify attempts per login |
| `WithTwoFactorCodeDuration(d)` | `10m` | Email code validity |

#### YAML Configuration

All auth features can be configured via YAML:

```yaml
auth:
  enabled: true
  jwt_access_secret: "hex-64-chars"    # env: SERVEX_AUTH_JWT_ACCESS_SECRET
  jwt_refresh_secret: "hex-64-chars"   # env: SERVEX_AUTH_JWT_REFRESH_SECRET
  issuer: "my-service"
  initial_roles: ["user"]

  email:
    enabled: true
    require_verification: false
    verify_token_duration: "24h"
    reset_token_duration: "1h"
    resend_cooldown: "60s"
    smtp:
      host: "smtp.gmail.com"
      port: 587
      username: "..."
      password: "..."                   # env: SERVEX_AUTH_EMAIL_SMTP_PASSWORD
      from: "noreply@myapp.com"
      verification_url: "https://myapp.com/verify-email"
      password_reset_url: "https://myapp.com/reset-password"

  oauth:
    enabled: true
    auto_link_by_email: true
    state_signing_key: "hex-64-chars"   # env: SERVEX_AUTH_OAUTH_STATE_SIGNING_KEY
    google:
      client_id: "..."
      client_secret: "..."             # env: SERVEX_AUTH_OAUTH_GOOGLE_CLIENT_SECRET
      redirect_url: "https://myapp.com/api/v1/auth/oauth/google/callback"
    github:
      client_id: "..."
      client_secret: "..."

  two_factor:
    enabled: true
    issuer: "MyApp"
    email_fallback: true
    backup_codes: 10
    encryption_key: "hex-64-chars"     # env: SERVEX_AUTH_2FA_ENCRYPTION_KEY
    max_verify_attempts: 5
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
- `WithAuth(db)` - JWT auth with custom AuthDatabase
- `WithAuthMemoryDatabase()` - In-memory user database
- `WithAuthToken(token)` - Simple bearer token
- `WithAuthKey(access, refresh)` - JWT signing keys (hex-encoded)
- `WithAuthTokensDuration(access, refresh)` - Token lifetimes

### Email Verification & Password Reset
- `WithEmailSender(sender)` - Custom EmailSender implementation
- `WithEmailSMTP(cfg)` - Built-in SMTP sender
- `WithEmailRequireVerification(bool)` - Block login until verified
- `WithEmailTokenDurations(verify, reset)` - Token lifetimes
- `WithEmailResendCooldown(d)` - Min interval between resends
- `WithEmailConfig(cfg)` - Full email configuration

### OAuth
- `WithOAuth(providers...)` - Enable with custom providers
- `WithOAuthGoogle(cfg)` - Google OAuth
- `WithOAuthGitHub(cfg)` - GitHub OAuth
- `WithOAuthApple(cfg)` - Apple Sign In
- `WithOAuthTelegram(cfg)` - Telegram Login
- `WithOAuthYandex(cfg)` - Yandex OAuth
- `WithOAuthAutoLink(bool)` - Auto-link accounts by email (default: true)
- `WithOAuthBasePath(path)` - OAuth routes suffix (default: `/oauth`)
- `WithOAuthStateSigningKey(key)` - HMAC key for CSRF state
- `WithOAuthConfig(cfg)` - Full OAuth configuration

### Two-Factor Auth
- `WithTwoFactor(encKey)` - Enable TOTP 2FA with encryption key
- `WithTwoFactorIssuer(name)` - Authenticator app issuer name
- `WithTwoFactorEmailFallback(bool)` - Allow email code fallback (default: true)
- `WithTwoFactorBackupCodes(count)` - Number of backup codes (default: 10)
- `WithTwoFactorCodeDuration(d)` - Email code validity (default: 10m)
- `WithTwoFactorMaxAttempts(n)` - Max verify attempts (default: 5)
- `WithTwoFactorConfig(cfg)` - Full 2FA configuration

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
- Authentication (JWT, email verification, OAuth, 2FA)
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
