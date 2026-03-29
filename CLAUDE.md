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
| Context helpers (`C(w,r)`) | `context_core.go`, `context_request.go`, `context_response.go`, `context_validation.go` |
| JWT authentication | `auth.go`, `middleware_auth.go` |
| Email verification & password reset | `auth_email.go`, `options_email.go` |
| OAuth providers | `auth_oauth.go`, `auth_oauth_providers.go`, `options_oauth.go` |
| Two-factor authentication | `auth_2fa.go`, `options_2fa.go` |
| Rate limiting | `ratelimit.go` |
| Request filtering (IP/UA/header/query) | `filter.go` |
| Reverse proxy with load balancing | `proxy.go` |
| Security headers, CSRF | `middleware_security.go` |
| Static files & SPA | `static.go` |
| Metrics & audit logging | `metrics.go`, `audit.go`, `logging.go` |
| Presets (Development, Production, etc.) | `presets.go` |
| CLI entry point | `cmd/servex/main.go` |

### Core Design Patterns

- **Options pattern**: Configuration via `With*()` functions passed to `NewServer()`. Options are split across `options_*.go` files by domain.
- **Middleware chain**: Registered in a fixed order in `servex.go` — rate limiting → size limits → filtering → security → CORS → cache → compression → logging → recovery → auth → proxy → static.
- **Context helpers**: `servex.C(w, r)` wraps the standard `http.ResponseWriter` and `*http.Request` to provide convenient JSON reading/writing, parameter extraction, and error responses.
- **Interface-based extensibility**: Provide custom implementations of `Logger`, `RequestLogger`, `AuditLogger`, `Metrics`, `AuthDatabase`, `VerificationEmailSender`, `PasswordResetEmailSender`, `TwoFactorEmailSender`, and `OAuthProvider` interfaces.

### Key Interfaces

- `AuthDatabase` — user storage backend (see `auth.go`)
- `EmailAuthDatabase` — email lookup (optional sub-interface, see `auth_email.go`)
- `OAuthAuthDatabase` — OAuth provider lookup (optional sub-interface, see `auth_oauth.go`)
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
```

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

## Testing Conventions

- All tests use the standard `testing` package — no external assertion libraries.
- Table-driven tests (`tests := []struct{...}`) are the dominant pattern.
- Tests use `httptest.NewRequest` and `httptest.NewRecorder` for HTTP testing.
- Mock implementations (MockLogger, MockAuthDatabase, MockAuditLogger) are defined in the corresponding `_test.go` files.
- Tests run in the same package (not `_test` suffix packages), so they can access unexported symbols.

## Release

Releases use semantic-release with conventional commits (`.releaserc.json`). Commit prefixes: `feat:` (minor), `fix:` / `perf:` / `docs:` / `refactor:` (patch), `breaking:` (major).
