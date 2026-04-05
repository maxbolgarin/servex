# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
make build          # Build binary to bin/servex
make test           # Run tests with race detection, coverage, and tparse formatting
make deps           # Download and verify Go module dependencies
make mod-tidy       # Tidy go modules
make mod-update     # Update all dependencies
make clean          # Remove build artifacts
make docker-build   # Build Docker image
make run-dev        # Build and run development server
```

Run a single test:
```bash
go test -v -run TestFunctionName .
```

CI runs tests against Go 1.23, 1.24, 1.25 with race detection:
```bash
go test -v -race -coverprofile=coverage.txt .
```

## Architecture

Servex is a production-ready HTTP(S) server library built on `net/http` and `gorilla/mux`. All library code lives in the root package (`servex`); there are no internal packages.

### Key Source Files

| Area | Files |
|------|-------|
| Server lifecycle | `servex.go` |
| Router (method shortcuts, base path) | `router.go` |
| Configuration loading (YAML + env vars) | `config.go` |
| Options (100+ `With*` builder functions) | `options_core.go`, `options_*.go` |
| Context helpers (`C(w,r)`) | `context_core.go`, `context_request.go`, `context_response.go`, `context_validation.go`, `context_helpers.go` |
| Middleware core & other | `middleware_core.go`, `middleware_other.go` |
| JWT authentication | `auth.go`, `middleware_auth.go`, `options_auth.go` |
| Email verification & password reset | `auth_email.go`, `options_email.go` |
| OAuth providers | `auth_oauth.go`, `auth_oauth_providers.go`, `options_oauth.go` |
| Two-factor authentication | `auth_2fa.go`, `options_2fa.go` |
| API key authentication | `apikey.go`, `options_apikey.go` |
| SQL auth databases (Postgres/MySQL/SQLite) | `auth_sql.go` |
| Rate limiting | `ratelimit.go` |
| Request filtering (IP/UA/header/query) | `filter.go` |
| Reverse proxy with load balancing | `proxy.go`, `proxy_dns.go` |
| Security headers, CSRF | `middleware_security.go` |
| Static files & SPA | `static.go` |
| Metrics & audit logging | `metrics.go`, `audit.go`, `logging.go` |
| Swagger UI & OpenAPI spec serving | `swagger.go`, `options_swagger.go` |
| WebSocket support | `websocket.go`, `options_websocket.go` |
| Server-Sent Events (SSE) | `sse.go` |
| W3C Trace Context propagation | `trace.go` |
| Raw HTTP utilities | `rawhttp.go` |
| Testing utilities | `testing.go` |
| Presets (Development, Production, etc.) | `presets.go` |
| CLI entry point | `cmd/servex/main.go` |
| Examples (17 demos) | `examples/` |

### Core Design Patterns

- **Options pattern**: Configuration via `With*()` functions passed to `NewServer()`. Options are split across `options_*.go` files by domain.
- **Middleware chain**: Registered in a fixed order in `servex.go` — rate limiting → size limits → filtering → security → CORS → cache → compression → logging → recovery → auth → proxy → static.
- **Context helpers**: `servex.C(w, r)` wraps the standard `http.ResponseWriter` and `*http.Request` to provide convenient JSON reading/writing, parameter extraction, and error responses.
- **Interface-based extensibility**: Provide custom implementations of `Logger`, `RequestLogger`, `AuditLogger`, `Metrics`, `AuthDatabase`, `APIKeyDatabase`, `VerificationEmailSender`, `PasswordResetEmailSender`, `TwoFactorEmailSender`, and `OAuthProvider` interfaces.

### Key Interfaces

- `AuthDatabase` — user storage backend (see `auth.go`)
- `EmailAuthDatabase` — email lookup (optional sub-interface, see `auth_email.go`)
- `OAuthAuthDatabase` — OAuth provider lookup (optional sub-interface, see `auth_oauth.go`)
- `APIKeyDatabase` — API key storage backend (see `apikey.go`)
- `VerificationEmailSender` — sends email verification codes or tokens (see `options_email.go`)
- `PasswordResetEmailSender` — sends password reset tokens (see `options_email.go`)
- `TwoFactorEmailSender` — sends 2FA verification codes via email (see `options_2fa.go`)
- `CodeGenerator` — generates short numeric codes; shared by email verification (code mode) and 2FA email fallback (see `auth_email.go`)
- `OAuthProvider` — OAuth provider flow (see `options_oauth.go`)
- `Metrics` — custom metrics collection (see `metrics.go`)
- `Logger` / `RequestLogger` / `AuditLogger` — logging backends (see `logging.go`, `audit.go`)

## Authentication System

Servex includes a complete JWT-based authentication system with email verification, OAuth social login, and 2FA support. Core auth is in `auth.go` and `middleware_auth.go`. Extended features: `auth_email.go` (email/password reset), `auth_oauth.go` + `auth_oauth_providers.go` (OAuth), `auth_2fa.go` (2FA/TOTP).

### Quick Setup

**Minimal (development with in-memory DB):**
```go
server, _ := servex.NewServer(
    servex.WithAuthMemoryDatabase(),
    servex.WithAuthKey(hex.EncodeToString(randomBytes(32)), hex.EncodeToString(randomBytes(32))),
)
```

**Production setup:**
```go
server, _ := servex.NewServer(
    servex.WithAuth(myPostgresDB),                             // implements AuthDatabase
    servex.WithAuthKey(os.Getenv("ACCESS_KEY"), os.Getenv("REFRESH_KEY")),  // hex-encoded, ≥64 chars
    servex.WithAuthIssuer("my-service-prod"),
    servex.WithAuthTokensDuration(15*time.Minute, 30*24*time.Hour),
    servex.WithAuthInitialRoles("user"),
    servex.WithAuthInitialUsers(servex.InitialUser{
        Username: "admin",
        Password: os.Getenv("ADMIN_PASSWORD"),
        Roles:    []servex.UserRole{"admin"},
    }),
)
```

**Full-featured setup (email + OAuth + 2FA):**
```go
server, _ := servex.NewServer(
    servex.WithAuth(myDB),  // implements AuthDatabase + EmailAuthDatabase + OAuthAuthDatabase
    servex.WithAuthKey(os.Getenv("ACCESS_KEY"), os.Getenv("REFRESH_KEY")),

    // Email verification & password reset — WithEmailSMTP sets sender on all three flows
    servex.WithEmailSMTP(servex.SMTPConfig{
        Host: "smtp.gmail.com", Port: 587,
        Username: os.Getenv("SMTP_USER"), Password: os.Getenv("SMTP_PASS"),
        From: "noreply@myapp.com",
        VerificationURL: "https://myapp.com/verify-email",
        PasswordResetURL: "https://myapp.com/reset-password",
    }),

    // OAuth providers
    servex.WithOAuthGoogle(servex.GoogleOAuthConfig{
        ClientID: os.Getenv("GOOGLE_ID"), ClientSecret: os.Getenv("GOOGLE_SECRET"),
        RedirectURL: "https://myapp.com/api/v1/auth/oauth/google/callback",
    }),
    servex.WithOAuthStateSigningKey(os.Getenv("OAUTH_STATE_KEY")),

    // Two-factor authentication
    servex.WithTwoFactor(os.Getenv("2FA_ENCRYPTION_KEY")),
    servex.WithTwoFactorIssuer("MyApp"),
)
```

**YAML configuration:**
```yaml
auth:
  enabled: true
  jwt_access_secret: "hex-encoded-32+-byte-key"   # env: SERVEX_AUTH_JWT_ACCESS_SECRET
  jwt_refresh_secret: "hex-encoded-32+-byte-key"  # env: SERVEX_AUTH_JWT_REFRESH_SECRET
  access_token_duration: "15m"
  refresh_token_duration: "720h"   # 30 days
  issuer: "my-service"
  base_path: "/api/v1/auth"
  refresh_token_cookie_name: "_servexrt"
  initial_roles: ["user"]
  not_register_routes: false
  use_memory_database: false

  email_verification:
    enabled: true
    require_verification: false
    mode: "code"          # "code" (default, short numeric) or "token" (long link token)
    code_digits: 6        # number of digits when mode=code
    code_duration: "15m"
    token_duration: "24h"
    resend_cooldown: "60s"
    smtp:
      host: "smtp.gmail.com"
      port: 587
      username: "..."
      password: "..."   # env: SERVEX_AUTH_EMAIL_VERIFICATION_SMTP_PASSWORD
      from: "noreply@myapp.com"
      verification_url: "https://myapp.com/verify-email"

  password_reset:
    enabled: true
    token_duration: "1h"
    resend_cooldown: "60s"
    smtp:
      host: "smtp.gmail.com"
      port: 587
      username: "..."
      password: "..."   # env: SERVEX_AUTH_PASSWORD_RESET_SMTP_PASSWORD
      from: "noreply@myapp.com"
      password_reset_url: "https://myapp.com/reset-password"

  oauth:
    enabled: true
    auto_link_by_email: true
    state_signing_key: "hex-64-chars"  # env: SERVEX_AUTH_OAUTH_STATE_SIGNING_KEY
    google:
      client_id: "..."
      client_secret: "..."  # env: SERVEX_AUTH_OAUTH_GOOGLE_CLIENT_SECRET
      redirect_url: "https://myapp.com/api/v1/auth/oauth/google/callback"

  two_factor:
    enabled: true
    issuer: "MyApp"
    email_fallback: true
    backup_codes: 10
    encryption_key: "hex-64-chars"  # env: SERVEX_AUTH_2FA_ENCRYPTION_KEY
    max_verify_attempts: 5
    email_smtp:
      host: "smtp.gmail.com"
      port: 587
      username: "..."
      password: "..."   # env: SERVEX_AUTH_2FA_EMAIL_SMTP_PASSWORD
      from: "noreply@myapp.com"

swagger:
  enabled: true
  path: "/swagger"
  spec_file: "./openapi.yaml"
  title: "API Documentation"

websocket:
  max_message_size: 32768        # 32 KB default
  ping_interval: "30s"
  pong_timeout: "10s"
  allowed_origins:
    - "https://myapp.com"
  enable_compression: false
```

### Swagger UI

Servex can serve an interactive Swagger UI for OpenAPI documentation. The feature exposes a standard `http.Handler`:

```go
// Option 1: Auto-register via server option
server, _ := servex.NewServer(
    servex.WithSwaggerUI(specBytes),              // serves at /swagger
    servex.WithSwaggerUIPath("/api-docs"),         // custom path
)

// Option 2: Load spec from file
server, _ := servex.NewServer(
    servex.WithSwaggerUIFile("./openapi.yaml"),
)

// Option 3: Mount handler manually on any router
handler := servex.SwaggerHandler(specBytes, servex.WithSwaggerTitle("My API"))
http.Handle("/docs/", http.StripPrefix("/docs", handler))
```

The handler serves:
- `GET /` — HTML page with Swagger UI (loaded from CDN)
- `GET /spec` — the OpenAPI spec file (auto-detects JSON/YAML content type)

### Auth Endpoints

When `NotRegisterRoutes` is false (default), these routes are auto-registered under `AuthBasePath` (default `/api/v1/auth`):

**Core endpoints:**

| Method | Path | Handler | Auth | Description |
|--------|------|---------|------|-------------|
| POST | `/register` | `RegisterHandler` | No | Create user, return tokens |
| POST | `/login` | `LoginHandler` | No | Verify credentials, return tokens |
| POST | `/refresh` | `RefreshHandler` | No (cookie) | Exchange refresh token for new tokens |
| POST | `/logout` | `LogoutHandler` | No (cookie) | Invalidate refresh token |
| GET | `/me` | `GetCurrentUserHandler` | Yes (Bearer) | Get current user info |

**Email endpoints** (when `EmailVerification.Enabled` or `PasswordReset.Enabled`):

| Method | Path | Handler | Auth | Description |
|--------|------|---------|------|-------------|
| POST | `/verify-email` | `VerifyEmailHandler` | No | Verify email — body varies by mode (see below) |
| POST | `/resend-verification` | `ResendVerificationHandler` | Yes (Bearer) | Resend verification email |
| POST | `/forgot-password` | `ForgotPasswordHandler` | No | Request password reset |
| POST | `/reset-password` | `ResetPasswordHandler` | No | Reset password with token |

Email verification request body depends on the configured mode:

- **Code mode** (default — `EmailVerificationCodeMode`): `{"code": "123456", "email": "user@example.com"}`
- **Token mode** (`EmailVerificationTokenMode`): `{"token": "userID:randomHex"}`

**OAuth endpoints** (when `OAuth.Enabled`):

| Method | Path | Handler | Auth | Description |
|--------|------|---------|------|-------------|
| GET | `/oauth/{provider}` | `OAuthRedirectHandler` | No | Redirect to provider |
| GET | `/oauth/{provider}/callback` | `OAuthCallbackHandler` | No | Handle provider callback |
| POST | `/oauth/{provider}/link` | `OAuthLinkHandler` | Yes (Bearer) | Link provider to account |
| DELETE | `/oauth/{provider}/link` | `OAuthUnlinkHandler` | Yes (Bearer) | Unlink provider |

**2FA endpoints** (when `TwoFactor.Enabled`):

| Method | Path | Handler | Auth | Description |
|--------|------|---------|------|-------------|
| POST | `/2fa/setup` | `TwoFactorSetupHandler` | Yes (Bearer) | Generate TOTP secret + backup codes |
| POST | `/2fa/enable` | `TwoFactorEnableHandler` | Yes (Bearer) | Verify code, enable 2FA |
| POST | `/2fa/disable` | `TwoFactorDisableHandler` | Yes (Bearer) | Disable 2FA |
| POST | `/2fa/verify` | `TwoFactorVerifyHandler` | Pending token | Complete login with 2FA code |
| POST | `/2fa/send-email-code` | `TwoFactorSendEmailCodeHandler` | Pending token | Send 2FA code via email |

**Request/Response formats:**

Register & Login request:
```json
POST /api/v1/auth/register  (or /login)
{"username": "john", "password": "securepass123", "email": "john@example.com"}
```

Success response (201 for register, 200 for login/refresh):
```json
{
  "id": "user-1",
  "username": "john",
  "roles": ["user"],
  "accessToken": "eyJhbGciOiJIUzI1NiJ9..."
}
```
The refresh token is NOT in the JSON response — it's set as an HttpOnly cookie (`_servexrt`).

Error responses:
```
400: {"message": "password must be at least 8 characters"}
401: {"message": "invalid email or password"}
409: {"message": "username already exists"}
```

### Protecting Routes with Auth Middleware

Use `AuthManager.WithAuth()` to protect any handler:

```go
authManager := server.AuthManager()  // get the AuthManager from server

// Any authenticated user
router.HandleFunc("/api/profile", authManager.WithAuth(profileHandler))

// Only users with "admin" role
router.HandleFunc("/api/admin", authManager.WithAuth(adminHandler, "admin"))

// Multiple roles (any one is sufficient)
router.HandleFunc("/api/manage", authManager.WithAuth(manageHandler, "admin", "manager"))
```

Inside a protected handler, extract user info from context:
```go
func profileHandler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    userID := ctx.UserID()        // string from UserContextKey
    roles := ctx.UserRoles()      // []UserRole from RoleContextKey
    scopes := ctx.APIKeyScopes()  // []string from APIKeyScopesContextKey
    traceID := ctx.TraceID()      // W3C trace ID (requires WithTracePropagation)
    spanID := ctx.SpanID()        // W3C span ID (requires WithTracePropagation)
}
```

Clients must send the access token as: `Authorization: Bearer <accessToken>`

### Token Lifecycle

```
Registration/Login
    │
    ├─ Access Token (JWT, 5 min default)
    │   - Sent in JSON response body
    │   - Client stores in memory (not localStorage)
    │   - Sent as Authorization: Bearer <token>
    │   - Contains: user_id, roles, issuer, expiry
    │   - Signed with access secret (HMAC-SHA256)
    │   - Cannot be revoked (expires naturally)
    │
    └─ Refresh Token (JWT, 7 days default)
        - Set as HttpOnly cookie (not accessible to JS)
        - Cookie: Secure, SameSite=Strict, path=/api/v1/auth
        - Contains: user_id, expiry (no roles — lighter)
        - Signed with refresh secret (different key)
        - First 72 bytes bcrypt-hashed and stored in DB
        - Revoked on logout (hash cleared in DB)
        - Rotated on each refresh (new token + new hash)

Refresh Flow:
    Client → POST /api/v1/auth/refresh (cookie auto-sent)
    Server validates: JWT signature → JWT expiry → bcrypt hash vs DB → DB expiry
    Server generates new access + refresh tokens
    Server stores new refresh hash, sets new cookie
    Client receives new access token in response

Logout:
    Client → POST /api/v1/auth/logout (cookie auto-sent)
    Server clears refresh hash in DB (immediate revocation)
    Server deletes cookie (MaxAge=-1)
    Access token remains valid until natural expiry (5 min max)
```

### AuthDatabase Interface

Implement this interface for your database backend:

```go
type AuthDatabase interface {
    // NewUser creates a user, returns generated ID
    NewUser(ctx context.Context, username string, passwordHash string, roles ...UserRole) (string, error)

    // FindByID returns user by ID
    FindByID(ctx context.Context, id string) (user User, exists bool, err error)

    // FindByUsername returns user by username
    FindByUsername(ctx context.Context, username string) (user User, exists bool, err error)

    // FindAll returns all users
    FindAll(ctx context.Context) ([]User, error)

    // UpdateUser applies partial updates via UserDiff
    UpdateUser(ctx context.Context, id string, diff *UserDiff) error
}
```

The `User` struct your database must store:
```go
type User struct {
    ID                    string     // unique identifier
    Username              string     // unique username
    Roles                 []UserRole // role list
    PasswordHash          string     // bcrypt hash
    RefreshTokenHash      string     // bcrypt hash of refresh token (first 72 bytes)
    RefreshTokenExpiresAt time.Time  // refresh token expiry (for DB-level revocation)
}
```

DB field name constants are exported for building queries: `IDDBField`, `UsernameDBField`, `PasswordHashDBField`, `RefreshTokenHashDBField`, `RefreshTokenExpiresAtDBField`.

`UserDiff` uses pointer fields for partial updates — only non-nil fields are applied:
```go
type UserDiff struct {
    Username              *string
    Roles                 *[]UserRole
    PasswordHash          *string
    RefreshTokenHash      *string
    RefreshTokenExpiresAt *time.Time
}
```

`MemoryAuthDatabase` is provided for development/testing (data lost on restart).

### AuthConfig Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Enabled` | `bool` | `false` | Enable JWT auth |
| `Database` | `AuthDatabase` | required | User storage backend |
| `JWTAccessSecret` | `string` | required | Hex-encoded access key (≥64 hex chars / 32 bytes) |
| `JWTRefreshSecret` | `string` | required | Hex-encoded refresh key (≥64 hex chars / 32 bytes) |
| `AccessTokenDuration` | `time.Duration` | `5m` | Access token validity |
| `RefreshTokenDuration` | `time.Duration` | `7d` | Refresh token validity |
| `IssuerNameInJWT` | `string` | `"servex"` | JWT `iss` claim value |
| `RefreshTokenCookieName` | `string` | `"_servexrt"` | Cookie name for refresh token |
| `AuthBasePath` | `string` | `"/api/v1/auth"` | Base path for auth endpoints |
| `RolesOnRegister` | `[]UserRole` | `nil` | Default roles for new users |
| `InitialUsers` | `[]InitialUser` | `nil` | Users auto-created on startup |
| `MinPasswordLength` | `int` | `8` | Minimum password length (0 = no check) |
| `ForceSecureCookies` | `bool` | `false` | Always set Secure flag on cookies |
| `NotRegisterRoutes` | `bool` | `false` | Skip auto-registering auth routes |
| `EmailVerification` | `EmailVerificationConfig` | — | Email verification settings (replaces old `Email`) |
| `PasswordReset` | `PasswordResetConfig` | — | Password reset settings (replaces old `Email`) |

**`EmailVerificationConfig` fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Enabled` | `bool` | `false` | Enable email verification flow |
| `RequireVerification` | `bool` | `false` | Block login until email is verified |
| `Mode` | `EmailVerificationMode` | `EmailVerificationCodeMode` | `"code"` (short numeric) or `"token"` (long link token) |
| `CodeDigits` | `int` | `6` | Number of digits when `Mode=code` |
| `CodeDuration` | `time.Duration` | `15m` | Validity of code when `Mode=code` |
| `TokenDuration` | `time.Duration` | `24h` | Validity of token when `Mode=token` |
| `ResendCooldown` | `time.Duration` | `60s` | Minimum interval between resend requests |
| `Sender` | `VerificationEmailSender` | — | Custom sender implementation |
| `SMTP` | `*SMTPConfig` | — | Auto-creates `SMTPEmailSender` if no `Sender` set |
| `CodeGenerator` | `CodeGenerator` | built-in | Custom code generator (code mode only) |

**`PasswordResetConfig` fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Enabled` | `bool` | `false` | Enable password reset flow |
| `TokenDuration` | `time.Duration` | `1h` | Validity of reset token |
| `ResendCooldown` | `time.Duration` | `60s` | Minimum interval between resend requests |
| `Sender` | `PasswordResetEmailSender` | — | Custom sender implementation |
| `SMTP` | `*SMTPConfig` | — | Auto-creates `SMTPEmailSender` if no `Sender` set |

**`TwoFactorConfig` additional fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `EmailSender` | `TwoFactorEmailSender` | — | Custom sender for 2FA email codes |
| `SMTP` | `*SMTPConfig` | — | Auto-creates 2FA email sender if `EmailFallback=true` and no `EmailSender` set |

### Option Functions

**Core auth:**

| Function | Sets |
|----------|------|
| `WithAuth(db)` | `Enabled=true`, `Database=db` |
| `WithAuthMemoryDatabase()` | `Enabled=true`, `Database=NewMemoryAuthDatabase()` |
| `WithAuthConfig(cfg)` | Entire `AuthConfig` |
| `WithAuthKey(access, refresh)` | `JWTAccessSecret`, `JWTRefreshSecret` |
| `WithAuthIssuer(name)` | `IssuerNameInJWT` |
| `WithAuthBasePath(path)` | `AuthBasePath` |
| `WithAuthInitialRoles(roles...)` | `RolesOnRegister` |
| `WithAuthRefreshTokenCookieName(name)` | `RefreshTokenCookieName` |
| `WithAuthTokensDuration(access, refresh)` | `AccessTokenDuration`, `RefreshTokenDuration` |
| `WithAuthNotRegisterRoutes(bool)` | `NotRegisterRoutes` |
| `WithAuthInitialUsers(users...)` | `InitialUsers` |
| `WithAuthToken(token)` | Simple bearer auth (not JWT, uses `RegisterSimpleAuthMiddleware`) |

**Email verification:**

| Function | Sets |
|----------|------|
| `WithVerificationEmailSender(s)` | `EmailVerification.Sender` |
| `WithEmailVerificationMode(mode)` | `EmailVerification.Mode` (`EmailVerificationCodeMode` or `EmailVerificationTokenMode`) |
| `WithEmailVerificationCodeDigits(n)` | `EmailVerification.CodeDigits` |
| `WithEmailVerificationCodeDuration(d)` | `EmailVerification.CodeDuration` |
| `WithEmailVerificationTokenDuration(d)` | `EmailVerification.TokenDuration` |
| `WithEmailVerificationCodeGenerator(g)` | `EmailVerification.CodeGenerator` |
| `WithEmailVerificationConfig(cfg)` | Entire `EmailVerificationConfig` |

**Password reset:**

| Function | Sets |
|----------|------|
| `WithPasswordResetEmailSender(s)` | `PasswordReset.Sender` |
| `WithPasswordResetTokenDuration(d)` | `PasswordReset.TokenDuration` |
| `WithPasswordResetConfig(cfg)` | Entire `PasswordResetConfig` |

**Convenience (sets sender on all three flows):**

| Function | Sets |
|----------|------|
| `WithEmailSMTP(cfg)` | Creates `SMTPEmailSender` and assigns it to `EmailVerification.Sender`, `PasswordReset.Sender`, and `TwoFactor.EmailSender` |

**2FA email:**

| Function | Sets |
|----------|------|
| `WithTwoFactorEmailSender(s)` | `TwoFactor.EmailSender` |
| `WithTwoFactorEmailSMTP(cfg)` | `TwoFactor.SMTP` (auto-creates sender) |

### Security Properties

- **Password hashing:** bcrypt with DefaultCost (adaptive, ~100ms/hash)
- **Token signing:** HMAC-SHA256, separate keys for access/refresh
- **Timing attack resistance:** `bcrypt.CompareHashAndPassword` + `subtle.ConstantTimeCompare` for SimpleAuth; same error message for wrong user/wrong password
- **Cookie security:** HttpOnly (no JS access), Secure (HTTPS only), SameSite=Strict (CSRF protection), path-scoped to auth base path
- **Refresh token protection:** bcrypt-hashed in DB, rotated on each refresh, revoked on logout by clearing hash
- **Token type enforcement:** `IsRefresh` flag prevents using refresh token as access token and vice versa
- **Issuer validation:** Access tokens validated against configured issuer
- **Audit logging:** All auth events (login, logout, token validation failures, permission denials) logged via `AuditLogger` interface

### Simple Bearer Auth (alternative)

For APIs that don't need user accounts, use `WithAuthToken`:
```go
server, _ := servex.NewServer(
    servex.WithAuthToken("my-secret-api-key"),
)
```
This registers `RegisterSimpleAuthMiddleware` which checks `Authorization: Bearer <token>` or `Authorization: <token>` on every request using constant-time comparison.

## WebSocket System

Servex includes WebSocket support built on `coder/websocket`. WebSocket activates lazily — no `Enabled` flag; calling `server.WS()` or `server.WSHub()` initializes the hub. Core code is in `websocket.go`, options in `options_websocket.go`.

### Key Types

- **`WSHandler`** — `func(ws *WSConn)`, called after successful upgrade; runs for the connection lifetime.
- **`WSConn`** — wraps `*websocket.Conn` with typed read/write (JSON, text, binary), request metadata access (`Path`, `Query`, `Header`, `UserID`, `UserRoles`, `ClientIP`), room operations (`JoinRoom`, `LeaveRoom`, `Rooms`), and lifecycle methods (`ID`, `Context`, `Close`, `CloseNow`). Thread-safe writes.
- **`WSHub`** — manages all active connections and room membership. Provides `BroadcastAll`, `BroadcastRoom`, `BroadcastRoomExcept`, `Send`, `ConnCount`, `RoomCount`, `Rooms`, `CloseAll`. Thread-safe.
- **`MessageType`** — re-exported: `MessageText`, `MessageBinary`.
- **`StatusCode`** — re-exported: `StatusNormalClosure`, `StatusGoingAway`, `StatusProtocolError`, `StatusPolicyViolation`, `StatusMessageTooBig`, `StatusInternalError`.

### Server Methods

```go
server.WS(path, handler)                        // Register WS route
server.WSWithAuth(path, handler, roles...)       // Register WS route with auth
server.WSHub()                                   // Get or init the hub
```

### Quick Example

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
        server.WSHub().BroadcastRoomExcept(room, ws.ID(), msg)
    }
})
```

### Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `WithWebSocketMaxMessageSize(n)` | `32 KB` | Max message size |
| `WithWebSocketPingInterval(d)` | `30s` | Ping interval (negative = disable) |
| `WithWebSocketPongTimeout(d)` | `10s` | Pong timeout (must be < PingInterval) |
| `WithWebSocketAllowedOrigins(origins...)` | all | Origin control |
| `WithWebSocketCompression()` | `false` | RFC 7692 per-message deflate |
| `WithWebSocketConfig(cfg)` | - | Full `WebSocketConfig` |

### WebSocket Metrics

When default metrics are enabled (`WithDefaultMetrics`), WebSocket metrics are collected automatically:

| Metric | Type | Description |
|--------|------|-------------|
| `servex_ws_connections_active` | gauge | Current active connections |
| `servex_ws_connections_total` | counter | Total connections opened |
| `servex_ws_disconnections_total` | counter | Total connections closed |
| `servex_ws_messages_sent_total` | counter | Messages sent |
| `servex_ws_messages_received_total` | counter | Messages received |
| `servex_ws_errors_total` | counter | Errors (upgrade failures, read/write errors) |

### Low-Level Escape Hatch

For raw `coder/websocket` access without the high-level API:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    conn, err := ctx.UpgradeWebSocket(nil) // returns *websocket.Conn
    if err != nil {
        ctx.BadRequest(err, "upgrade failed")
        return
    }
    defer conn.Close(servex.StatusNormalClosure, "")
}
```

### Design Decisions

- **Lazy initialization**: Hub created on first `WS()` or `WSHub()` call via `sync.Once`.
- **Thread-safe writes**: Mutex serializes concurrent writes per connection.
- **Graceful cleanup**: `sync.Once` ensures cleanup runs exactly once, even on panic.
- **Middleware compatible**: All response writer wrappers (`loggingResponseWriter`, `enhancedUniversalResponseWriter`, `compressionResponseWriter`) implement `http.Hijacker`.
- **Auth integration**: `WSWithAuth` validates the upgrade request with the same auth middleware used for HTTP routes.

## Server-Sent Events (SSE)

Servex includes SSE support for real-time streaming. SSE activates lazily like WebSocket. Core code is in `sse.go`.

### Key Types

- **`SSEHandler`** — `func(sse *SSEConn)`, called after successful upgrade; runs for the connection lifetime.
- **`SSEConn`** — wraps `http.ResponseWriter` for SSE streaming with thread-safe writes. Provides `Send`, `SendEvent`, `SendEventWithID`, `SendJSON`, `SendEventJSON`, `SendComment`, `SetRetry`. Metadata: `Path`, `Query`, `Header`, `LastEventID`, `UserID`, `UserRoles`, `ClientIP`, `Done`.

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

## API Key Authentication

Servex supports API key authentication alongside JWT. API keys are SHA-256 hashed, scope-based, and support expiration. Core code is in `apikey.go`, options in `options_apikey.go`.

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

### Protecting Routes with API Keys

```go
auth := server.AuthManager()
server.GET("/api/data", auth.WithAPIKey(dataHandler, "read"))         // requires "read" scope
server.POST("/api/data", auth.WithAPIKey(createHandler, "write"))     // requires "write" scope
server.DELETE("/api/data/{id}", auth.WithAPIKey(deleteHandler, "admin"))
```

Clients send: `X-API-Key: myapp_...` or `Authorization: ApiKey myapp_...`

### Auto-Registered Endpoints (under auth base path)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api-keys` | Bearer (JWT) | Create new API key (returns full key once) |
| GET | `/api-keys` | Bearer (JWT) | List user's API keys (prefix only) |
| DELETE | `/api-keys/{id}` | Bearer (JWT) | Revoke an API key |

### YAML Config

```yaml
api_key:
  prefix: "myapp_"
  valid_scopes: ["read", "write", "admin"]
  max_per_user: 10
  key_length: 16
  use_memory_database: false
```

## SQL Auth Database

Servex provides a built-in SQL-backed `AuthDatabase` that supports PostgreSQL, MySQL, and SQLite. It implements `AuthDatabase`, `EmailAuthDatabase`, and `OAuthAuthDatabase`. Code is in `auth_sql.go`.

### Setup

```go
// From existing *sql.DB
sqlDB, _ := sql.Open("pgx", "postgres://user:pass@localhost/mydb")
authDB, _ := servex.NewSQLAuthDatabase(sqlDB, "pgx")

server, _ := servex.NewServer(
    servex.WithAuth(authDB),
    servex.WithAuthKey(accessKey, refreshKey),
)

// Or via option (manages connection internally)
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

- `SQLTablePrefix(prefix)` — prefix for table names (e.g. `"myapp_"` → `myapp_users`)
- `SQLAutoMigrate(bool)` — auto-create tables on init (default: `true`)

Auto-migration creates `users` and `user_oauth_providers` tables with proper indexes.

## W3C Trace Context

Servex supports W3C Trace Context (RFC 9531) propagation for distributed tracing. Code is in `trace.go`.

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

## Testing Utilities

Servex provides `TestServer`, `TestRequest`, and `TestResponse` types in `testing.go` for convenient integration testing.

### Quick Example

```go
func TestMyAPI(t *testing.T) {
    ts := servex.NewTestServer(t,
        servex.WithAuthMemoryDatabase(),
        servex.WithAuthKey(accessKey, refreshKey),
    )
    // ts.Server is the *servex.Server — register routes on it
    ts.Server.GET("/items", listItems)

    // Fluent request API
    resp := ts.Get("/items").Do()
    if resp.Code != 200 { t.Fatal("expected 200") }

    var items []Item
    resp.JSON(&items)

    // POST with JSON body and auth
    resp = ts.Post("/items").
        WithJSON(map[string]string{"name": "test"}).
        WithAuth("bearer-token").
        Do()

    // Cleanup is automatic via t.Cleanup
}
```

### TestRequest Methods

`WithBody(io.Reader)`, `WithJSON(any)`, `WithHeader(k, v)`, `WithAuth(token)`, `WithCookie(name, value)`, `Do() *TestResponse`

### TestResponse Fields/Methods

`Code int`, `Header http.Header`, `Body []byte`, `JSON(v any) error`, `BodyString() string`

## Raw HTTP Utilities

Package-level functions in `rawhttp.go` for constructing raw HTTP bytes (useful for testing or low-level proxy work):

```go
raw := servex.MakeRawRequest("/path", "example.com:80", headers, body)
raw := servex.MakeRawResponse(200, headers, body)
```

## Testing Conventions

- All tests use the standard `testing` package — no external assertion libraries.
- Table-driven tests (`tests := []struct{...}`) are the dominant pattern.
- Tests use `httptest.NewRequest` and `httptest.NewRecorder` for HTTP testing.
- Mock implementations (MockLogger, MockAuthDatabase, MockAuditLogger) are defined in the corresponding `_test.go` files.
- Tests run in the same package (not `_test` suffix packages), so they can access unexported symbols.

## Release

Releases use semantic-release with conventional commits (`.releaserc.json`). Commit prefixes: `feat:` (minor), `fix:` / `perf:` / `docs:` / `refactor:` (patch), `breaking:` (major).
