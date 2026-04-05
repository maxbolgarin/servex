# Servex - Production-Ready HTTP Server for Go

[![Go Version][version-img]][doc] [![GoDoc][doc-img]][doc] [![Build][ci-img]][ci] [![Coverage][coverage-img]][coverage] [![GoReport][report-img]][report] [![MIT][mit-img]][mit]

**Servex** eliminates HTTP server boilerplate in Go. Focus on business logic while getting production-ready features out of the box.

## Features

- 🚀 **Zero Boilerplate** - Configure once, code business logic
- 🔒 **Security First** - JWT auth, OAuth, 2FA, email verification, rate limiting, request filtering, security headers, audit logging
- 🔄 **Reverse Proxy / API Gateway** - Load balancing, health checks, traffic analysis
- 🌐 **WebSocket** - Built-in WebSocket support with rooms, broadcasting, and auth integration
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

### Standalone Binary (No Go Code)

Use servex as a standalone server like Caddy or Nginx — no Go code required:

```bash
# Install
go install github.com/maxbolgarin/servex/v2/cmd/servex@latest

# Start with a preset — no config file needed
servex -preset production -port 8080
servex -preset api -port 3000
servex -preset spa -static-dir ./dist -port 8080

# Or use a config file
servex -config server.yaml

# Docker
docker run -p 8080:8080 maxbolgarin/servex servex -preset production -port 8080
```

Use as a Docker base image:

```dockerfile
FROM maxbolgarin/servex:latest
COPY servex.yaml /etc/servex/servex.yaml
COPY dist/ /var/www/html/
```

Available presets: `production`, `api`, `webapp`, `microservice`, `security`, `spa`, `static`. See the [Standalone Server Guide](docs/STANDALONE.md) for full documentation.

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
| **Email Verification** | `WithEmailSMTP(cfg)` - SMTP sender for all email flows<br>`WithVerificationEmailSender(s)` - Custom verification sender<br>`WithPasswordResetEmailSender(s)` - Custom reset sender<br>`WithEmailRequireVerification(true)` - Block login until verified<br>`WithEmailVerificationMode(mode)` - Code or token mode<br>`WithEmailVerificationCodeDigits(n)` - Code length (default 6)<br>`WithEmailVerificationCodeDuration(d)` - Code validity<br>`WithEmailVerificationTokenDuration(d)` - Token validity<br>`WithEmailResendCooldown(d)` - Resend rate limit<br>`WithPasswordResetTokenDuration(d)` - Reset token lifetime |
| **OAuth Providers** | `WithOAuthGoogle(cfg)` - Google login<br>`WithOAuthGitHub(cfg)` - GitHub login<br>`WithOAuthApple(cfg)` - Apple login<br>`WithOAuthTelegram(cfg)` - Telegram login<br>`WithOAuthYandex(cfg)` - Yandex login<br>`WithOAuth(providers...)` - Custom providers<br>`WithOAuthAutoLink(bool)` - Auto-link by email |
| **Two-Factor Auth** | `WithTwoFactor(encKey)` - Enable TOTP 2FA<br>`WithTwoFactorIssuer(name)` - Authenticator app name<br>`WithTwoFactorEmailFallback(bool)` - Email code fallback<br>`WithTwoFactorEmailSender(s)` - Custom 2FA email sender<br>`WithTwoFactorEmailSMTP(cfg)` - SMTP for 2FA emails<br>`WithTwoFactorBackupCodes(count)` - Backup code count<br>`WithTwoFactorMaxAttempts(n)` - Max verify attempts |
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
| **WebSocket** | `WithWebSocketMaxMessageSize(size)` - Max message size<br>`WithWebSocketPingInterval(d)` - Ping interval<br>`WithWebSocketPongTimeout(d)` - Pong timeout<br>`WithWebSocketAllowedOrigins(origins...)` - Origin control<br>`WithWebSocketCompression()` - Per-message deflate<br>`WithWebSocketConfig(cfg)` - Full configuration |
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

**Email Verification** (when email verification is enabled):

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/verify-email` | Verify email with code or token |
| `POST` | `/resend-verification` | Resend verification email (auth required) |

**Password Reset** (when password reset is enabled):

| Method | Path | Description |
|--------|------|-------------|
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
// Required when email verification or password reset is enabled
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

Email verification and password reset are now configured independently. Enable both with a single SMTP config using `WithEmailSMTP`, or configure each flow separately.

**Verification modes:**

- `EmailVerificationCodeMode` (default) — sends a 6-digit numeric code. The user submits `{"code": "123456", "email": "user@example.com"}` to `POST /verify-email`.
- `EmailVerificationTokenMode` — sends a long token for building a clickable link. The user submits `{"token": "userID:randomHex"}` to `POST /verify-email`. The token encodes the user identity, so no email address is required in the request.

```go
// Both flows using one SMTP config (most common)
server, _ := servex.New(
    servex.WithAuth(myDB),
    servex.WithAuthKey(accessKey, refreshKey),
    servex.WithEmailSMTP(servex.SMTPConfig{
        Host:             "smtp.gmail.com",
        Port:             587,
        Username:         os.Getenv("SMTP_USER"),
        Password:         os.Getenv("SMTP_PASS"),
        From:             "noreply@myapp.com",
        VerificationURL:  "https://myapp.com/verify-email",   // token mode only
        PasswordResetURL: "https://myapp.com/reset-password",
    }),
)

// Use token mode for link-based verification
server, _ := servex.New(
    servex.WithEmailSMTP(smtpCfg),
    servex.WithEmailVerificationMode(servex.EmailVerificationTokenMode),
)

// Custom sender for each flow (e.g. SendGrid for verification, SES for password reset)
server, _ := servex.New(
    servex.WithVerificationEmailSender(myVerifSender),   // VerificationEmailSender
    servex.WithPasswordResetEmailSender(myResetSender),  // PasswordResetEmailSender
)
```

**Require verification before login:**
```go
servex.WithEmailRequireVerification(true) // users must verify email before logging in
```

**Password reset flow:**
1. Client sends `POST /forgot-password` with `{"identifier": "user@example.com"}` (email or username)
2. Server always returns `200` (timing-safe, never reveals user existence)
3. If user found, a reset email is sent with a token link
4. Client sends `POST /reset-password` with `{"token": "...", "password": "newpass"}`

**Email sender interfaces:**

The old single `EmailSender` interface has been replaced by three independent interfaces so each flow can use a different email delivery implementation:

```go
type VerificationEmailSender interface {
    SendVerificationEmail(ctx context.Context, to string, codeOrToken string) error
}

type PasswordResetEmailSender interface {
    SendPasswordResetEmail(ctx context.Context, to string, token string) error
}

type TwoFactorEmailSender interface {
    SendTwoFactorCodeEmail(ctx context.Context, to string, code string) error
}
```

`SMTPEmailSender` implements all three. Use `NewSMTPEmailSender(cfg, mode)` to create one.

**Email verification options:**

| Option | Default | Description |
|--------|---------|-------------|
| `WithEmailSMTP(cfg)` | - | SMTP sender for all three email flows |
| `WithVerificationEmailSender(s)` | - | Custom `VerificationEmailSender` |
| `WithPasswordResetEmailSender(s)` | - | Custom `PasswordResetEmailSender` |
| `WithEmailRequireVerification(bool)` | `false` | Block login until verified |
| `WithEmailVerificationMode(mode)` | `CodeMode` | Code or token verification |
| `WithEmailVerificationCodeDigits(n)` | `6` | Digits in verification code |
| `WithEmailVerificationCodeDuration(d)` | `10m` | Code validity |
| `WithEmailVerificationTokenDuration(d)` | `24h` | Token validity |
| `WithEmailResendCooldown(d)` | `60s` | Min interval between resends |
| `WithEmailVerificationCodeGenerator(g)` | - | Custom `CodeGenerator` |
| `WithEmailVerificationConfig(cfg)` | - | Full `EmailVerificationConfig` |
| `WithPasswordResetTokenDuration(d)` | `1h` | Reset token lifetime |
| `WithPasswordResetConfig(cfg)` | - | Full `PasswordResetConfig` |

**Custom code generator:**
```go
// Use 8-digit codes instead of the default 6
server, _ := servex.New(
    servex.WithEmailSMTP(smtpCfg),
    servex.WithEmailVerificationCodeGenerator(servex.NewNumericCodeGenerator(8)),
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

**Email fallback** — users can receive a code via email instead of TOTP. Configure a separate 2FA email sender:

```go
server, _ := servex.New(
    servex.WithTwoFactor(encKey),
    servex.WithTwoFactorEmailSMTP(servex.SMTPConfig{
        Host: "smtp.gmail.com", Port: 587,
        Username: os.Getenv("SMTP_USER"),
        Password: os.Getenv("SMTP_PASS"),
        From:     "noreply@myapp.com",
    }),
)

// Or reuse the same SMTP config for all email flows:
server, _ := servex.New(
    servex.WithTwoFactor(encKey),
    servex.WithEmailSMTP(smtpCfg), // sets sender for verification, password reset, and 2FA
)
```

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

**2FA configuration:**

| Option | Default | Description |
|--------|---------|-------------|
| `WithTwoFactor(key)` | - | Enable 2FA with AES-256-GCM encryption key |
| `WithTwoFactorIssuer(name)` | `"servex"` | Name shown in authenticator apps |
| `WithTwoFactorEmailFallback(bool)` | `true` | Allow email-based 2FA codes |
| `WithTwoFactorEmailSender(s)` | - | Custom `TwoFactorEmailSender` |
| `WithTwoFactorEmailSMTP(cfg)` | - | SMTP config for 2FA emails |
| `WithTwoFactorBackupCodes(n)` | `10` | Number of backup codes |
| `WithTwoFactorMaxAttempts(n)` | `5` | Max verify attempts per login |
| `WithTwoFactorCodeDuration(d)` | `10m` | Email code validity |
| `WithTwoFactorEmailCodeDigits(n)` | `6` | Digits in email 2FA code |
| `WithTwoFactorEmailCodeGenerator(g)` | - | Custom `CodeGenerator` for email codes |
| `WithTwoFactorConfig(cfg)` | - | Full `TwoFactorConfig` |

#### YAML Configuration

All auth features can be configured via YAML. Note that email settings are now split into `email_verification` and `password_reset` top-level blocks under `auth`:

```yaml
auth:
  enabled: true
  jwt_access_secret: "hex-64-chars"    # env: SERVEX_AUTH_JWT_ACCESS_SECRET
  jwt_refresh_secret: "hex-64-chars"   # env: SERVEX_AUTH_JWT_REFRESH_SECRET
  issuer: "my-service"
  initial_roles: ["user"]

  email_verification:
    enabled: true
    require_verification: false
    mode: "code"                       # "code" (default) or "token"
    code_digits: 6
    code_duration: "10m"
    token_duration: "24h"              # for token mode
    resend_cooldown: "60s"
    smtp:
      host: "smtp.gmail.com"
      port: 587
      username: "..."
      password: "..."                  # env: SERVEX_AUTH_EMAIL_SMTP_PASSWORD
      from: "noreply@myapp.com"
      verification_url: "https://myapp.com/verify-email"   # for token mode

  password_reset:
    enabled: true
    token_duration: "1h"
    smtp:
      host: "smtp.gmail.com"
      port: 587
      username: "..."
      password: "..."
      from: "noreply@myapp.com"
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
    email_smtp:                        # separate SMTP block for 2FA emails
      host: "smtp.gmail.com"
      port: 587
      username: "..."
      password: "..."
      from: "noreply@myapp.com"
```

### Rate Limiting

Rate limiting uses a token bucket algorithm applied per client IP (or a custom key). Clients can burst up to `BurstSize` requests immediately, then are refilled at the configured rate.

```go
// Simple: 100 requests per minute per client
server, _ := servex.New(servex.WithRPM(100))

// With burst: allow up to 20 requests at once, refill at 10/s
server, _ := servex.New(
    servex.WithRPS(10),
    servex.WithBurstSize(20),
)

// Custom interval
server, _ := servex.New(
    servex.WithRequestsPerInterval(500, 5*time.Minute),
)
```

**Per-endpoint rate limits** — apply different limits to different paths using `RegisterLocationBasedRateLimitMiddleware`:

```go
server, _ := servex.New(servex.WithRPM(1000)) // global default

stop := servex.RegisterLocationBasedRateLimitMiddleware(server.Router(), []servex.LocationRateLimitConfig{
    {
        PathPatterns: []string{"/api/v1/auth/login", "/api/v1/auth/register"},
        Config: servex.RateLimitConfig{
            Enabled:             true,
            RequestsPerInterval: 5,
            Interval:            time.Minute,
            BurstSize:           5,
        },
    },
    {
        PathPatterns: []string{"/api/v1/upload/*"},
        Config: servex.RateLimitConfig{
            Enabled:             true,
            RequestsPerInterval: 10,
            Interval:            time.Minute,
        },
    },
})
defer stop()
```

**Custom rate limit key** — rate limit by API key, user ID, or any other request attribute:

```go
server, _ := servex.New(
    servex.WithRPS(50),
    servex.WithRateLimitKeyFunc(func(r *http.Request) string {
        if key := r.Header.Get("X-API-Key"); key != "" {
            return "apikey:" + key
        }
        return r.RemoteAddr
    }),
)
```

**Rate limiting options:**

| Option | Default | Description |
|--------|---------|-------------|
| `WithRPM(n)` | - | n requests per minute |
| `WithRPS(n)` | - | n requests per second |
| `WithRequestsPerInterval(n, d)` | - | Custom interval |
| `WithBurstSize(n)` | = rate | Max burst requests |
| `WithRateLimitStatusCode(code)` | `429` | Response status when limited |
| `WithRateLimitMessage(msg)` | `"Rate limit exceeded..."` | Response body |
| `WithRateLimitKeyFunc(fn)` | IP-based | Request identity function |
| `WithRateLimitExcludePaths(paths...)` | - | Paths exempt from limiting |
| `WithRateLimitIncludePaths(paths...)` | - | Only these paths are limited |
| `WithRateLimitTrustedProxies(ips...)` | - | IPs to trust for X-Forwarded-For |
| `WithRateLimitConfig(cfg)` | - | Full `RateLimitConfig` |

### Request Filtering

Filter requests by IP address, User-Agent, custom headers, or query parameters. Allowed lists and blocked lists can be combined — blocked rules are checked first, then allowed rules.

```go
// Block known bad actors
server, _ := servex.New(
    servex.WithBlockedIPs("192.0.2.0/24", "198.51.100.50"),
    servex.WithBlockedUserAgentsRegex(`(?i).*(bot|crawler|scraper).*`),
)

// Allow only internal traffic
server, _ := servex.New(
    servex.WithAllowedIPs("10.0.0.0/8", "192.168.0.0/16"),
)

// Header-based filtering
server, _ := servex.New(
    servex.WithAllowedHeaders(map[string][]string{
        "X-API-Version": {"v1", "v2"},
    }),
    servex.WithBlockedHeaders(map[string][]string{
        "X-Malicious": {"*"},
    }),
)

// Query parameter filtering
server, _ := servex.New(
    servex.WithBlockedQueryParams(map[string][]string{
        "debug": {"true"},
    }),
)
```

**Location-based filters** — apply different filter rules to different paths:

```go
servex.RegisterLocationBasedFilterMiddleware(server.Router(), []servex.LocationFilterConfig{
    {
        PathPatterns: []string{"/admin/*"},
        Config: servex.FilterConfig{
            AllowedIPs: []string{"10.0.0.0/8"},
        },
    },
    {
        PathPatterns: []string{"/api/*"},
        Config: servex.FilterConfig{
            BlockedUserAgentsRegex: []string{`(?i).*bot.*`},
        },
    },
})
```

**Dynamic filtering** — add or remove rules at runtime without restarting:

```go
filter := server.Filter() // implements DynamicFilterMethods
filter.AddBlockedIP("203.0.113.99")
filter.RemoveBlockedIP("10.0.0.1")
filter.AddBlockedUserAgent("EvilBot/1.0")
```

**Filter options:**

| Option | Description |
|--------|-------------|
| `WithAllowedIPs(ips...)` | Allow-list by IP or CIDR — blocks all others |
| `WithBlockedIPs(ips...)` | Block-list by IP or CIDR |
| `WithAllowedUserAgents(agents...)` | Allow-list by exact User-Agent |
| `WithBlockedUserAgents(agents...)` | Block-list by exact User-Agent |
| `WithAllowedUserAgentsRegex(patterns...)` | Allow-list by User-Agent regex |
| `WithBlockedUserAgentsRegex(patterns...)` | Block-list by User-Agent regex |
| `WithAllowedHeaders(map)` | Allow-list by header name/value |
| `WithBlockedHeaders(map)` | Block-list by header name/value |
| `WithAllowedQueryParams(map)` | Allow-list by query parameter name/value |
| `WithBlockedQueryParams(map)` | Block-list by query parameter name/value |
| `WithFilterTrustedProxies(ips...)` | Trusted proxies for IP detection |
| `WithFilterConfig(cfg)` | Full `FilterConfig` |

### Reverse Proxy / API Gateway

Servex includes a full L7 reverse proxy with multiple load balancing strategies, automatic health checks, traffic dumping, and flexible routing rules.

```go
proxyConfig := servex.ProxyConfiguration{
    Enabled: true,
    Rules: []servex.ProxyRule{
        {
            PathPrefix:    "/api/",
            StripPrefix:   "/api",
            LoadBalancing: servex.WeightedRoundRobinStrategy,
            Backends: []servex.Backend{
                {URL: "http://backend1:8080", Weight: 2},
                {URL: "http://backend2:8080", Weight: 1},
            },
        },
        {
            Host:          "legacy.internal",
            AddPrefix:     "/v1",
            LoadBalancing: servex.RoundRobinStrategy,
            Backends: []servex.Backend{
                {URL: "http://legacy:9000"},
            },
        },
    },
}

server, _ := servex.New(servex.WithProxyConfig(proxyConfig))
```

**Load balancing strategies:**

| Strategy | Constant | Description |
|----------|----------|-------------|
| Round Robin | `RoundRobinStrategy` | Cycles through backends in order |
| Weighted Round Robin | `WeightedRoundRobinStrategy` | Cycles based on `Weight` fields |
| Least Connections | `LeastConnectionsStrategy` | Routes to backend with fewest active connections |
| Random | `RandomStrategy` | Random backend selection |
| Weighted Random | `WeightedRandomStrategy` | Random selection based on weights |
| IP Hash | `IPHashStrategy` | Consistent routing by client IP (session affinity) |

**Routing rule matching** — rules are evaluated in order; first match wins:

| Field | Description |
|-------|-------------|
| `PathPrefix` | Match requests starting with this path prefix |
| `PathRegex` | Match request path using a regular expression |
| `Host` | Match the `Host` request header |
| `Headers` | Match specific request header key/value pairs |
| `Methods` | Restrict to specific HTTP methods |

**Path rewriting:**

```go
// Remove /api prefix before forwarding
servex.ProxyRule{PathPrefix: "/api/", StripPrefix: "/api"}
// GET /api/users → forwarded as GET /users

// Add prefix on forward
servex.ProxyRule{PathPrefix: "/", AddPrefix: "/service-a"}
// GET /users → forwarded as GET /service-a/users
```

**Health checks** — backends are automatically polled and removed from rotation when unhealthy:

```go
proxyConfig := servex.ProxyConfiguration{
    Enabled: true,
    HealthCheck: servex.HealthCheckConfig{
        Enabled:         true,
        DefaultInterval: 30 * time.Second,
        Timeout:         5 * time.Second,
        RetryCount:      3,
    },
    Rules: []servex.ProxyRule{
        {
            PathPrefix:    "/",
            LoadBalancing: servex.LeastConnectionsStrategy,
            Backends: []servex.Backend{
                {
                    URL:                 "http://app1:8080",
                    HealthCheckPath:     "/health",
                    HealthCheckInterval: 15 * time.Second,
                    MaxConnections:      100,
                },
                {
                    URL:             "http://app2:8080",
                    HealthCheckPath: "/health",
                },
            },
        },
    },
}
```

**Traffic dumping** — record request/response bodies for debugging or compliance:

```go
proxyConfig := servex.ProxyConfiguration{
    Enabled: true,
    TrafficDump: servex.TrafficDumpConfig{
        Enabled:     true,
        Directory:   "/var/log/traffic",
        IncludeBody: true,
        MaxBodySize: 64 * 1024, // 64 KB
        MaxFileSize: 100 << 20, // 100 MB per file
        MaxFiles:    10,
        SampleRate:  0.1, // capture 10% of traffic
    },
    Rules: []servex.ProxyRule{...},
}
```

### Security Headers

Security headers protect web applications from common attacks like XSS, clickjacking, and MIME-type sniffing. Two presets are available, or configure individual headers.

```go
// Basic headers (suitable for most applications)
server, _ := servex.New(servex.WithSecurityHeaders())

// Strict headers (high-security environments)
server, _ := servex.New(servex.WithStrictSecurityHeaders())

// Custom CSP with external CDN
server, _ := servex.New(
    servex.WithSecurityHeaders(),
    servex.WithContentSecurityPolicy(
        "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'",
    ),
)

// HSTS with subdomains
server, _ := servex.New(
    servex.WithStrictSecurityHeaders(),
    servex.WithHSTSHeader(31536000, true, false), // 1 year, include subdomains, no preload
)
```

**Headers set by `WithSecurityHeaders()`:**

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |

**Additional headers set by `WithStrictSecurityHeaders()`:**

| Header | Value |
|--------|-------|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |
| `X-Permitted-Cross-Domain-Policies` | `none` |
| `Cross-Origin-Embedder-Policy` | `require-corp` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-site` |

> **Note:** Strict headers may break functionality that depends on external scripts, iframe embedding, or third-party integrations. Test thoroughly and adjust as needed.

**Security header options:**

| Option | Description |
|--------|-------------|
| `WithSecurityHeaders()` | Basic security headers |
| `WithStrictSecurityHeaders()` | Full set of strict headers |
| `WithContentSecurityPolicy(policy)` | Custom `Content-Security-Policy` |
| `WithHSTSHeader(maxAge, subdomains, preload)` | `Strict-Transport-Security` |
| `WithSecurityExcludePaths(paths...)` | Skip headers for these paths |
| `WithSecurityIncludePaths(paths...)` | Apply headers only to these paths |
| `WithSecurityConfig(cfg)` | Full `SecurityConfig` |

### CSRF Protection

CSRF protection uses a double-submit cookie pattern. A random token is issued via a cookie; state-changing requests (`POST`, `PUT`, `DELETE`, `PATCH`) must echo the token in the `X-CSRF-Token` header (or as a form field or query parameter).

```go
server, _ := servex.New(
    servex.WithSecurityHeaders(),
    servex.WithCSRFProtection(),
)
```

**Token flow for SPAs and AJAX applications:**

1. Configure a token endpoint so the SPA can obtain a token:
   ```go
   servex.WithCSRFTokenEndpoint("/api/csrf-token")
   ```
2. On page load, the frontend calls `GET /api/csrf-token`. The response sets the CSRF cookie and returns:
   ```json
   {"csrf_token": "base64-encoded-token"}
   ```
3. The frontend stores the token and sends it as a header on all mutating requests:
   ```
   POST /api/data
   X-CSRF-Token: base64-encoded-token
   ```
4. Safe methods (`GET`, `HEAD`, `OPTIONS`, `TRACE`) are exempt from validation.

**CSRF options:**

| Option | Default | Description |
|--------|---------|-------------|
| `WithCSRFProtection()` | - | Enable CSRF with defaults |
| `WithCSRFTokenName(name)` | `X-CSRF-Token` | Header name for the token |
| `WithCSRFCookieName(name)` | `csrf_token` | Cookie name |
| `WithCSRFCookieHttpOnly(bool)` | `false` | HttpOnly flag on cookie |
| `WithCSRFCookieSecure(bool)` | `false` | Secure flag on cookie |
| `WithCSRFCookieSameSite(s)` | `Lax` | SameSite attribute (`strict`, `lax`, `none`) |
| `WithCSRFCookieMaxAge(seconds)` | session | Cookie expiry |
| `WithCSRFCookiePath(path)` | `/` | Cookie path scope |
| `WithCSRFTokenEndpoint(path)` | - | Path to serve tokens for SPAs |
| `WithCSRFErrorMessage(msg)` | `"CSRF token validation failed"` | Error response body |
| `WithCSRFSafeMethods(methods...)` | GET, HEAD, OPTIONS, TRACE | Methods exempt from validation |

### CORS

Cross-Origin Resource Sharing (CORS) is required when a browser frontend on one origin calls an API on a different origin. Servex registers the CORS headers as middleware.

```go
// Permissive (development)
server, _ := servex.New(servex.WithCORS())

// Production: restrict to known origins
server, _ := servex.New(
    servex.WithCORSAllowOrigins("https://myapp.com", "https://admin.myapp.com"),
    servex.WithCORSAllowMethods("GET", "POST", "PUT", "DELETE", "OPTIONS"),
    servex.WithCORSAllowHeaders("Authorization", "Content-Type", "X-Request-ID"),
    servex.WithCORSAllowCredentials(), // required when sending cookies or Authorization header
    servex.WithCORSMaxAge(86400),      // cache preflight for 24 hours
)
```

`WithCORS()` with no further options sets permissive defaults: all origins, common methods, common headers.

**CORS options:**

| Option | Default | Description |
|--------|---------|-------------|
| `WithCORS()` | - | Enable with permissive defaults |
| `WithCORSAllowOrigins(origins...)` | `*` | Allowed `Origin` values |
| `WithCORSAllowMethods(methods...)` | common methods | Allowed HTTP methods |
| `WithCORSAllowHeaders(headers...)` | common headers | Allowed request headers |
| `WithCORSExposeHeaders(headers...)` | - | Response headers exposed to browser |
| `WithCORSAllowCredentials()` | `false` | Allow credentials (cookies, auth) |
| `WithCORSMaxAge(seconds)` | - | Preflight cache duration |
| `WithCORSExcludePaths(paths...)` | - | Skip CORS for these paths |
| `WithCORSIncludePaths(paths...)` | - | Apply CORS only to these paths |
| `WithCORSConfig(cfg)` | - | Full `CORSConfig` |

> **Note:** `WithCORSAllowCredentials()` requires specifying explicit origins — wildcard `*` is not allowed when credentials are enabled.

### Compression

Gzip compression reduces response size for text-based content. Compression is applied automatically to eligible responses based on content type and minimum size.

```go
// Enable with defaults (gzip, text content types, minimum 1 KB)
server, _ := servex.New(servex.WithCompression())

// Custom settings
server, _ := servex.New(
    servex.WithCompression(),
    servex.WithCompressionLevel(6),      // 1 (fast) – 9 (best), default varies
    servex.WithCompressionMinSize(2048), // only compress responses ≥ 2 KB
    servex.WithCompressionTypes(
        "text/html", "text/css", "application/javascript", "application/json",
    ),
)
```

**Compression options:**

| Option | Description |
|--------|-------------|
| `WithCompression()` | Enable gzip compression with defaults |
| `WithCompressionLevel(level)` | Compression level 1–9 |
| `WithCompressionMinSize(bytes)` | Minimum response size to compress |
| `WithCompressionTypes(types...)` | Content types to compress |
| `WithCompressionExcludePaths(paths...)` | Skip compression for these paths |
| `WithCompressionIncludePaths(paths...)` | Compress only these paths |
| `WithCompressionConfig(cfg)` | Full `CompressionConfig` |

### Caching

Cache-Control headers tell browsers and CDNs how to cache responses. Servex sets these headers as middleware.

```go
// Public cache for 1 hour (CDN-friendly)
server, _ := servex.New(servex.WithCachePublic(3600))

// Private browser cache for 5 minutes (authenticated content)
server, _ := servex.New(servex.WithCachePrivate(300))

// Static assets with long TTL
server, _ := servex.New(servex.WithCacheStaticAssets(86400 * 30)) // 30 days

// Disable caching (e.g. for API responses)
server, _ := servex.New(servex.WithCacheNoCache())

// Custom Cache-Control header
server, _ := servex.New(
    servex.WithCacheControl("public, max-age=3600, stale-while-revalidate=60"),
)
```

**Caching options:**

| Option | Description |
|--------|-------------|
| `WithCachePublic(maxAge)` | `Cache-Control: public, max-age=<n>` |
| `WithCachePrivate(maxAge)` | `Cache-Control: private, max-age=<n>` |
| `WithCacheStaticAssets(maxAge)` | Public cache with immutable hint |
| `WithCacheNoCache()` | `Cache-Control: no-cache` |
| `WithCacheNoStore()` | `Cache-Control: no-store` |
| `WithCacheControl(value)` | Arbitrary `Cache-Control` value |
| `WithCacheHeaders()` | Enable cache header middleware |
| `WithCacheExpires(value)` | Set `Expires` header |
| `WithCacheETag(value)` | Set static `ETag` header |
| `WithCacheETagFunc(fn)` | Dynamic `ETag` computed per request |
| `WithCacheLastModified(value)` | Set static `Last-Modified` header |
| `WithCacheVary(value)` | Set `Vary` header |
| `WithCacheExcludePaths(paths...)` | Skip caching headers for these paths |
| `WithCacheIncludePaths(paths...)` | Apply caching only to these paths |
| `WithCacheConfig(cfg)` | Full `CacheConfig` |

### Static Files & SPA

Serve a directory of static files or a Single Page Application (SPA). Static file serving is integrated as middleware — API routes registered on the server take precedence, and static files fill in for any unmatched paths.

```go
// Serve a static directory under a URL prefix
server, _ := servex.New(
    servex.WithStaticFiles("./public", "/static"),
)

// SPA mode: serve index.html for all unmatched routes (client-side routing)
server, _ := servex.New(
    servex.WithSPAMode("./build", "index.html"),
)

// SPA with custom cache rules
server, _ := servex.New(
    servex.WithSPAMode("./build", "index.html"),
    servex.WithStaticFileCache(
        86400, // default max-age: 1 day
        map[string]int{
            "*.html": 0,          // HTML: no cache (always fresh)
            "*.js":   31536000,   // JS bundles: 1 year (hashed filenames)
            "*.css":  31536000,   // CSS: 1 year
        },
    ),
    servex.WithStaticFileExclusions("/api/*"), // never serve static for /api routes
)
```

In SPA mode, any `GET` request that does not match a registered API route and has no matching file on disk will serve `index.html`. This supports client-side routing frameworks (React Router, Vue Router, etc.).

**Static file options:**

| Option | Description |
|--------|-------------|
| `WithStaticFiles(dir, prefix)` | Serve `dir` at URL `prefix` |
| `WithSPAMode(dir, indexFile)` | SPA fallback to `indexFile` |
| `WithStaticFileCache(maxAge, rules)` | Per-extension cache rules |
| `WithStaticFileExclusions(paths...)` | Paths never served as static files |
| `WithStaticFileConfig(cfg)` | Full `StaticFileConfig` |

### HTTPS / TLS

```go
// Load certificate from files at startup
server, _ := servex.New(
    servex.WithCertificateFromFile("/etc/ssl/certs/server.crt", "/etc/ssl/private/server.key"),
)
server.StartWithWaitSignals(ctx, ":8080", ":8443") // HTTP on 8080, HTTPS on 8443

// Or load a pre-parsed certificate
cert, _ := tls.LoadX509KeyPair("server.crt", "server.key")
server, _ := servex.New(servex.WithCertificate(&cert))

// Redirect all HTTP traffic to HTTPS (permanent 301)
server, _ := servex.New(
    servex.WithCertificateFromFile(certFile, keyFile),
    servex.WithHTTPSRedirect(),
)

// Temporary redirect (307) — useful during migration
server, _ := servex.New(
    servex.WithCertificateFromFile(certFile, keyFile),
    servex.WithHTTPSRedirectTemporary(),
)
```

When both an HTTP and HTTPS address are passed to `Start`, the server listens on both. The HTTPS redirect middleware intercepts HTTP requests and issues a redirect to the equivalent HTTPS URL.

**TLS options:**

| Option | Description |
|--------|-------------|
| `WithCertificate(cert)` | Set a pre-loaded `*tls.Certificate` |
| `WithCertificateFromFile(cert, key)` | Load PEM files at startup |
| `WithHTTPSRedirect()` | Permanent (301) HTTP → HTTPS redirect |
| `WithHTTPSRedirectTemporary()` | Temporary (307) HTTP → HTTPS redirect |
| `WithHTTPSRedirectConfig(cfg)` | Full `HTTPSRedirectConfig` (trusted proxies, exclude paths) |

### Logging & Monitoring

#### Logger Interface

Servex logs server lifecycle events, request errors, and panics through the `Logger` interface. If no logger is provided, a JSON logger writing to stderr is created automatically.

```go
// Use any slog-compatible logger
server, _ := servex.New(
    servex.WithLogger(slog.Default()),
)

// Suppress 4xx errors from log output (reduces noise from bad clients)
server, _ := servex.New(
    servex.WithLogger(slog.Default()),
    servex.WithNoLogClientErrors(),
)

// Log only specific fields
server, _ := servex.New(
    servex.WithLogFields(
        servex.RequestIDLogField,
        servex.IPLogField,
        servex.StatusLogField,
        servex.DurationLogField,
    ),
)

// Disable request logging entirely (when using external access logs)
server, _ := servex.New(servex.WithDisableRequestLogging())
```

**Logger interfaces:**

```go
// Main logger — server lifecycle, errors, panics
type Logger interface {
    Debug(msg string, fields ...any)
    Info(msg string, fields ...any)
    Error(msg string, fields ...any)
}

// Request logger — called after every HTTP request
type RequestLogger interface {
    Log(RequestLogBundle)
}
```

`RequestLogBundle` provides: `Request`, `RequestID`, `Error`, `ErrorMessage`, `StatusCode`, `StartTime`, `NoLogClientErrors`.

**Available log field constants:**

| Constant | Field name | Description |
|----------|-----------|-------------|
| `RequestIDLogField` | `request_id` | Unique request identifier |
| `IPLogField` | `ip` | Client IP address |
| `UserAgentLogField` | `user_agent` | Client User-Agent |
| `URLLogField` | `url` | Full request URL |
| `MethodLogField` | `method` | HTTP method |
| `ProtoLogField` | `proto` | HTTP protocol version |
| `ErrorLogField` | `error` | Error details |
| `ErrorMessageLogField` | `error_message` | Short error message |
| `StatusLogField` | `status` | HTTP status code |
| `DurationLogField` | `duration_ms` | Request duration in ms |

#### Audit Logging

The audit logger records security events in structured form for compliance, threat detection, and forensic investigation.

```go
// Use the built-in audit logger (writes to the main logger)
server, _ := servex.New(
    servex.WithAuth(myDB),
    servex.WithDefaultAuditLogger(),
)

// Custom audit logger
type myAuditLogger struct{}

func (l *myAuditLogger) Log(event servex.AuditEvent) {
    // Write to SIEM, database, or external service
}

server, _ := servex.New(
    servex.WithAuth(myDB),
    servex.WithAuditLogger(&myAuditLogger{}),
)
```

**Audit event types:**

| Category | Events |
|----------|--------|
| Authentication | `auth.login.success`, `auth.login.failure`, `auth.logout`, `auth.token.refresh`, `auth.token.invalid`, `auth.unauthorized`, `auth.forbidden` |
| Rate limiting | `ratelimit.exceeded`, `ratelimit.blocked` |
| Filtering | `filter.ip.blocked`, `filter.useragent.blocked`, `filter.header.blocked`, `filter.query.blocked` |
| CSRF | `csrf.token.missing`, `csrf.token.invalid`, `csrf.attack.detected` |
| Email | `auth.email.verified`, `auth.email.verify_failed` |
| Password reset | `auth.password_reset.requested`, `auth.password_reset.completed`, `auth.password_reset.failed` |
| OAuth | `auth.oauth.login`, `auth.oauth.login_failed`, `auth.oauth.link`, `auth.oauth.unlink` |
| 2FA | `auth.2fa.setup`, `auth.2fa.enabled`, `auth.2fa.disabled`, `auth.2fa.verified`, `auth.2fa.failed`, `auth.2fa.locked`, `auth.2fa.backup_code_used` |
| Security | `security.violation`, `security.anomaly`, `request.too.large`, `request.malicious.payload` |

Each `AuditEvent` includes: `EventType`, `Severity` (low/medium/high/critical), `Timestamp`, `EventID`, `RequestID`, `UserID`, `ClientIP`, `UserAgent`, `Method`, `Path`, `Message`, and optional `Details`.

### Health & Metrics

#### Health Endpoint

```go
// Enable at /health (default)
server, _ := servex.New(servex.WithHealthEndpoint())

// Custom path
server, _ := servex.New(
    servex.WithHealthEndpoint(),
    servex.WithHealthPath("/healthz"),
)
```

The health endpoint returns `200 OK` with body `OK`. It bypasses authentication and all middleware — suitable for load balancer health checks and Kubernetes liveness/readiness probes.

#### Built-in Metrics

```go
// Enable JSON metrics at /metrics (default)
server, _ := servex.New(servex.WithDefaultMetrics("/metrics"))
```

The built-in metrics endpoint returns a JSON snapshot with:

- Request/response counts and error rates
- Average, min, and max response times
- Status code distribution
- Per-method counts
- Top paths by request count
- System metrics: memory usage, goroutine count, GC stats

#### Custom Metrics

Implement the `Metrics` interface to integrate with Prometheus or any other metrics system:

```go
type Metrics interface {
    HandleRequest(r *http.Request)
    HandleResponse(r *http.Request, w http.ResponseWriter, statusCode int, duration time.Duration)
}

type prometheusMetrics struct {
    requestsTotal   *prometheus.CounterVec
    requestDuration *prometheus.HistogramVec
}

func (m *prometheusMetrics) HandleRequest(r *http.Request) {
    // called at request start
}

func (m *prometheusMetrics) HandleResponse(r *http.Request, w http.ResponseWriter, code int, d time.Duration) {
    m.requestsTotal.WithLabelValues(r.Method, strconv.Itoa(code)).Inc()
    m.requestDuration.WithLabelValues(r.Method).Observe(d.Seconds())
}

server, _ := servex.New(servex.WithMetrics(&prometheusMetrics{...}))
```

### Server Timeouts & Size Limits

#### Timeouts

```go
server, _ := servex.New(
    servex.WithReadTimeout(30 * time.Second),
    servex.WithReadHeaderTimeout(5 * time.Second),
    servex.WithIdleTimeout(120 * time.Second),
    servex.WithMaxHeaderBytes(1 << 20), // 1 MB
)
```

| Option | Default | Description |
|--------|---------|-------------|
| `WithReadTimeout(d)` | `60s` | Max duration to read the entire request including body |
| `WithReadHeaderTimeout(d)` | `60s` | Max duration to read request headers only |
| `WithIdleTimeout(d)` | `180s` | Max idle time for keep-alive connections |
| `WithMaxHeaderBytes(n)` | `1 MB` | Max size of request headers |

#### Request Size Limits

```go
// Enable default size limits
server, _ := servex.New(servex.WithRequestSizeLimits())

// Enable strict limits
server, _ := servex.New(servex.WithStrictRequestSizeLimits())

// Custom limits
server, _ := servex.New(
    servex.WithMaxRequestBodySize(10 << 20),  // 10 MB
    servex.WithMaxJSONBodySize(1 << 20),       // 1 MB
    servex.WithMaxFileUploadSize(100 << 20),   // 100 MB
    servex.WithMaxMultipartMemory(10 << 20),   // 10 MB in memory
)
```

| Option | Default | Description |
|--------|---------|-------------|
| `WithMaxRequestBodySize(n)` | `32 MB` | Max request body (all types) |
| `WithMaxJSONBodySize(n)` | `1 MB` | Max JSON request body |
| `WithMaxFileUploadSize(n)` | `100 MB` | Max file upload via multipart |
| `WithMaxMultipartMemory(n)` | `10 MB` | Max multipart memory before spilling to disk |
| `WithRequestSizeLimits()` | - | Enable global size limits with defaults |
| `WithStrictRequestSizeLimits()` | - | Enable strict limits (smaller values) |

### WebSocket

Servex provides built-in WebSocket support with connection management, rooms, broadcasting, and authentication — powered by [coder/websocket](https://github.com/coder/websocket). WebSocket support activates lazily when you register a WS route.

#### Basic Usage

```go
server, _ := servex.New(servex.ProductionPreset()...)

// Echo handler
server.WS("/ws/echo", func(ws *servex.WSConn) {
    for {
        typ, data, err := ws.Read()
        if err != nil {
            return
        }
        ws.Write(typ, data)
    }
})

// JSON handler
server.WS("/ws/json", func(ws *servex.WSConn) {
    for {
        var msg map[string]any
        if err := ws.ReadJSON(&msg); err != nil {
            return
        }
        ws.WriteJSON(map[string]string{"status": "ok"})
    }
})
```

#### Authenticated WebSocket

```go
// Only admin users can connect
server.WSWithAuth("/ws/admin", func(ws *servex.WSConn) {
    userID := ws.UserID()
    roles := ws.UserRoles()
    // ...
}, "admin")

// Any authenticated user
server.WSWithAuth("/ws/user", func(ws *servex.WSConn) {
    // ...
})
```

Auth middleware validates the HTTP upgrade request before upgrading. Clients send the access token as a query parameter or header:
```
ws://localhost:8080/ws/admin?token=eyJ...
```

#### Rooms & Broadcasting

```go
server.WS("/ws/chat/{room}", func(ws *servex.WSConn) {
    room := ws.Path("room")
    ws.JoinRoom(room)
    defer ws.LeaveRoom(room)

    for {
        var msg map[string]string
        if err := ws.ReadJSON(&msg); err != nil {
            return
        }
        // Broadcast to everyone in the room except sender
        server.WSHub().BroadcastRoomExcept(room, ws.ID(), msg)
    }
})

// Send from anywhere (HTTP handler, background task, etc.)
hub := server.WSHub()
hub.BroadcastAll(map[string]string{"event": "update"})           // all connections
hub.BroadcastRoom("general", map[string]string{"msg": "hello"})  // all in room
hub.Send(connID, map[string]string{"personal": "message"})       // specific connection
```

#### WSConn Methods

**Read/Write:**

| Method | Description |
|--------|-------------|
| `Read()` | Read next message (blocks) |
| `Write(typ, data)` | Write message (thread-safe) |
| `ReadJSON(v)` | Read and unmarshal JSON |
| `WriteJSON(v)` | Marshal and write JSON |
| `ReadText()` | Read text message |
| `WriteText(s)` | Write text message |

**Request metadata (from upgrade request):**

| Method | Description |
|--------|-------------|
| `Path(key)` | Path parameter (gorilla/mux) |
| `Query(key)` | URL query parameter |
| `Header(key)` | Request header |
| `UserID()` | Authenticated user ID |
| `UserRoles()` | Authenticated user roles |
| `ClientIP()` | Client IP address |
| `RequestID()` | Request ID |

**Lifecycle:**

| Method | Description |
|--------|-------------|
| `ID()` | Unique connection identifier |
| `Context()` | Connection context (cancelled on close) |
| `Close(code, reason)` | Graceful close with status |
| `CloseNow()` | Immediate close |
| `JoinRoom(room)` | Join a room |
| `LeaveRoom(room)` | Leave a room |
| `Rooms()` | List joined rooms |

#### WSHub Methods

| Method | Description |
|--------|-------------|
| `BroadcastAll(msg)` | Send JSON to all connections |
| `BroadcastRoom(room, msg)` | Send JSON to all in room |
| `BroadcastRoomExcept(room, connID, msg)` | Send to room excluding one |
| `Send(connID, msg)` | Send JSON to specific connection |
| `ConnCount()` | Active connection count |
| `RoomCount(room)` | Connections in room |
| `Rooms()` | All active room names |
| `CloseAll(code, reason)` | Close all connections |

#### Configuration

```go
server, _ := servex.New(
    servex.WithWebSocketMaxMessageSize(64 << 10),    // 64 KB (default 32 KB)
    servex.WithWebSocketPingInterval(20*time.Second), // default 30s
    servex.WithWebSocketPongTimeout(5*time.Second),   // default 10s
    servex.WithWebSocketAllowedOrigins("https://myapp.com", "https://admin.myapp.com"),
    servex.WithWebSocketCompression(),                // RFC 7692
)
```

| Option | Default | Description |
|--------|---------|-------------|
| `WithWebSocketMaxMessageSize(n)` | `32 KB` | Max single message size |
| `WithWebSocketPingInterval(d)` | `30s` | Server ping interval (negative = disable) |
| `WithWebSocketPongTimeout(d)` | `10s` | Pong wait timeout |
| `WithWebSocketAllowedOrigins(origins...)` | all | Origin control (`"*"` = skip check) |
| `WithWebSocketCompression()` | `false` | Per-message deflate |
| `WithWebSocketConfig(cfg)` | - | Full `WebSocketConfig` |

#### YAML Configuration

```yaml
websocket:
  max_message_size: 65536          # 64 KB
  ping_interval: "20s"
  pong_timeout: "5s"
  allowed_origins:
    - "https://myapp.com"
  enable_compression: true
```

Environment variables: `SERVEX_WEBSOCKET_MAX_MESSAGE_SIZE`, `SERVEX_WEBSOCKET_PING_INTERVAL`, `SERVEX_WEBSOCKET_PONG_TIMEOUT`, `SERVEX_WEBSOCKET_ENABLE_COMPRESSION`.

#### Low-Level Upgrade

For advanced use cases, bypass the high-level API and upgrade directly:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    conn, err := ctx.UpgradeWebSocket(nil) // *websocket.Conn from coder/websocket
    if err != nil {
        ctx.BadRequest(err, "upgrade failed")
        return
    }
    defer conn.Close(servex.StatusNormalClosure, "")
    // Use raw coder/websocket API
}
```

#### Metrics

When default metrics are enabled, WebSocket metrics are automatically collected:

| Metric | Type | Description |
|--------|------|-------------|
| `servex_ws_connections_active` | gauge | Current active connections |
| `servex_ws_connections_total` | counter | Total connections opened |
| `servex_ws_disconnections_total` | counter | Total connections closed |
| `servex_ws_messages_sent_total` | counter | Total messages sent |
| `servex_ws_messages_received_total` | counter | Total messages received |
| `servex_ws_errors_total` | counter | Total errors (upgrade failures, read/write errors) |

#### Utility

```go
// Check if an error is a normal close (StatusNormalClosure or StatusGoingAway)
if servex.IsCloseError(err) {
    // connection closed gracefully
}
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
    servex.WithDefaultMetrics("/metrics"),
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
- `WithReadHeaderTimeout(duration)` - Header read timeout
- `WithIdleTimeout(duration)` - Keep-alive timeout
- `WithMaxHeaderBytes(n)` - Max header size

### Authentication
- `WithAuth(db)` - JWT auth with custom AuthDatabase
- `WithAuthMemoryDatabase()` - In-memory user database
- `WithAuthToken(token)` - Simple bearer token
- `WithAuthKey(access, refresh)` - JWT signing keys (hex-encoded)
- `WithAuthTokensDuration(access, refresh)` - Token lifetimes

### Email Verification
- `WithEmailSMTP(cfg)` - SMTP sender for all email flows
- `WithVerificationEmailSender(s)` - Custom `VerificationEmailSender`
- `WithEmailRequireVerification(bool)` - Block login until verified
- `WithEmailVerificationMode(mode)` - Code or token mode
- `WithEmailVerificationCodeDigits(n)` - Code length (default 6)
- `WithEmailVerificationCodeDuration(d)` - Code validity
- `WithEmailVerificationTokenDuration(d)` - Token validity
- `WithEmailResendCooldown(d)` - Min interval between resends
- `WithEmailVerificationCodeGenerator(g)` - Custom `CodeGenerator`
- `WithEmailVerificationConfig(cfg)` - Full `EmailVerificationConfig`

### Password Reset
- `WithPasswordResetEmailSender(s)` - Custom `PasswordResetEmailSender`
- `WithPasswordResetTokenDuration(d)` - Reset token lifetime
- `WithPasswordResetConfig(cfg)` - Full `PasswordResetConfig`

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
- `WithTwoFactorEmailSender(s)` - Custom `TwoFactorEmailSender`
- `WithTwoFactorEmailSMTP(cfg)` - SMTP config for 2FA emails
- `WithTwoFactorBackupCodes(count)` - Number of backup codes (default: 10)
- `WithTwoFactorCodeDuration(d)` - Email code validity (default: 10m)
- `WithTwoFactorEmailCodeDigits(n)` - Digits in email 2FA code (default: 6)
- `WithTwoFactorEmailCodeGenerator(g)` - Custom `CodeGenerator` for email codes
- `WithTwoFactorMaxAttempts(n)` - Max verify attempts (default: 5)
- `WithTwoFactorConfig(cfg)` - Full 2FA configuration

### Rate Limiting
- `WithRPM(requests)` - Requests per minute
- `WithRPS(requests)` - Requests per second
- `WithRequestsPerInterval(n, d)` - Custom interval
- `WithBurstSize(size)` - Burst allowance
- `WithRateLimitKeyFunc(fn)` - Custom rate limit key
- `WithRateLimitStatusCode(code)` - Status when limited
- `WithRateLimitMessage(msg)` - Response body when limited
- `WithRateLimitExcludePaths(paths...)` - Exempt paths
- `WithRateLimitIncludePaths(paths...)` - Only limit these paths
- `WithRateLimitTrustedProxies(ips...)` - Trusted proxy IPs
- `WithRateLimitConfig(cfg)` - Full `RateLimitConfig`

### Request Filtering
- `WithBlockedIPs(ips...)` - Block IP ranges
- `WithAllowedIPs(ips...)` - Allow only specific IPs
- `WithBlockedUserAgents(agents...)` - Block user agents
- `WithAllowedUserAgents(agents...)` - Allow only these user agents
- `WithBlockedUserAgentsRegex(patterns...)` - Block by regex
- `WithAllowedUserAgentsRegex(patterns...)` - Allow by regex
- `WithAllowedHeaders(map)` - Allow only these header values
- `WithBlockedHeaders(map)` - Block these header values
- `WithAllowedQueryParams(map)` - Allow only these query values
- `WithBlockedQueryParams(map)` - Block these query values
- `WithFilterTrustedProxies(ips...)` - Trusted proxy IPs
- `WithFilterConfig(cfg)` - Full `FilterConfig`

### Security Headers
- `WithSecurityHeaders()` - Basic security headers
- `WithStrictSecurityHeaders()` - Strict CSP, HSTS
- `WithContentSecurityPolicy(policy)` - Custom CSP
- `WithHSTSHeader(maxAge, subdomains, preload)` - HSTS
- `WithSecurityExcludePaths(paths...)` - Exempt paths
- `WithSecurityIncludePaths(paths...)` - Only these paths
- `WithSecurityConfig(cfg)` - Full `SecurityConfig`

### CSRF
- `WithCSRFProtection()` - Enable CSRF protection
- `WithCSRFTokenName(name)` - Token header name
- `WithCSRFCookieName(name)` - Cookie name
- `WithCSRFCookieHttpOnly(bool)` - HttpOnly flag
- `WithCSRFCookieSecure(bool)` - Secure flag
- `WithCSRFCookieSameSite(s)` - SameSite attribute
- `WithCSRFCookieMaxAge(seconds)` - Cookie expiry
- `WithCSRFCookiePath(path)` - Cookie path
- `WithCSRFTokenEndpoint(path)` - Token endpoint for SPAs
- `WithCSRFErrorMessage(msg)` - Error response body
- `WithCSRFSafeMethods(methods...)` - Methods exempt from validation

### CORS
- `WithCORS()` - Enable with defaults
- `WithCORSAllowOrigins(origins...)` - Allowed origins
- `WithCORSAllowMethods(methods...)` - Allowed methods
- `WithCORSAllowHeaders(headers...)` - Allowed headers
- `WithCORSExposeHeaders(headers...)` - Exposed response headers
- `WithCORSAllowCredentials()` - Allow credentials
- `WithCORSMaxAge(seconds)` - Preflight cache duration
- `WithCORSExcludePaths(paths...)` - Exempt paths
- `WithCORSIncludePaths(paths...)` - Only these paths
- `WithCORSConfig(cfg)` - Full `CORSConfig`

### Compression
- `WithCompression()` - Enable gzip compression
- `WithCompressionLevel(level)` - Level 1–9
- `WithCompressionMinSize(bytes)` - Minimum response size
- `WithCompressionTypes(types...)` - Content types to compress
- `WithCompressionExcludePaths(paths...)` - Exempt paths
- `WithCompressionIncludePaths(paths...)` - Only these paths
- `WithCompressionConfig(cfg)` - Full `CompressionConfig`

### Caching
- `WithCachePublic(maxAge)` - Public cache with max-age
- `WithCachePrivate(maxAge)` - Private cache with max-age
- `WithCacheStaticAssets(maxAge)` - Cache static files
- `WithCacheNoCache()` - no-cache directive
- `WithCacheNoStore()` - no-store directive
- `WithCacheControl(value)` - Arbitrary Cache-Control
- `WithCacheExpires(value)` - Expires header
- `WithCacheETag(value)` - Static ETag
- `WithCacheETagFunc(fn)` - Dynamic ETag per request
- `WithCacheLastModified(value)` - Last-Modified header
- `WithCacheVary(value)` - Vary header
- `WithCacheExcludePaths(paths...)` - Exempt paths
- `WithCacheIncludePaths(paths...)` - Only these paths
- `WithCacheConfig(cfg)` - Full `CacheConfig`

### Static Files
- `WithStaticFiles(dir, prefix)` - Serve static files
- `WithSPAMode(dir, index)` - Single Page Application mode
- `WithStaticFileCache(maxAge, rules...)` - Per-extension cache rules
- `WithStaticFileExclusions(paths...)` - Never serve as static
- `WithStaticFileConfig(cfg)` - Full `StaticFileConfig`

### Reverse Proxy
- `WithProxyConfig(config)` - Complete proxy configuration

### Logging & Monitoring
- `WithLogger(logger)` - Custom `Logger`
- `WithRequestLogger(logger)` - Custom `RequestLogger`
- `WithDefaultAuditLogger()` - Security audit logging
- `WithAuditLogger(logger)` - Custom `AuditLogger`
- `WithDisableRequestLogging()` - Disable request logs
- `WithNoLogClientErrors()` - Skip 4xx from logs
- `WithLogFields(fields...)` - Select log fields

### Health & Metrics
- `WithHealthEndpoint()` - Enable `/health`
- `WithHealthPath(path)` - Custom health path
- `WithDefaultMetrics(path)` - Built-in JSON metrics
- `WithMetrics(metrics)` - Custom `Metrics` implementation
- `WithDisableHealthEndpoint()` - Disable health endpoint

### WebSocket
- `WithWebSocketMaxMessageSize(n)` - Max message size (default 32 KB)
- `WithWebSocketPingInterval(d)` - Ping interval (default 30s, negative = disable)
- `WithWebSocketPongTimeout(d)` - Pong timeout (default 10s)
- `WithWebSocketAllowedOrigins(origins...)` - Allowed origins
- `WithWebSocketCompression()` - Enable per-message deflate
- `WithWebSocketConfig(cfg)` - Full `WebSocketConfig`

### Request Size Limits
- `WithMaxRequestBodySize(n)` - Max body size
- `WithMaxJSONBodySize(n)` - Max JSON body size
- `WithMaxFileUploadSize(n)` - Max file upload size
- `WithMaxMultipartMemory(n)` - Max multipart memory
- `WithRequestSizeLimits()` - Enable with defaults
- `WithStrictRequestSizeLimits()` - Strict limits

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
