# Auth Expansion Design: Email Verification, Password Reset, OAuth, 2FA

**Date:** 2026-03-21
**Status:** Draft
**Scope:** Extend servex authentication system with email verification, password reset, OAuth (5 providers), and 2FA (TOTP + email fallback).

---

## 1. Overview

Servex currently provides JWT-based authentication with register/login/refresh/logout flows. This design adds four capabilities:

1. **Email verification** — SMTP integration with `EmailSender` interface, verification codes on registration
2. **Password reset** — email-based reset links with random tokens stored in DB
3. **OAuth** — full flow (redirect, callback, token exchange) with `OAuthProvider` interface and 5 built-in providers (Google, GitHub, Apple, Telegram, Yandex)
4. **2FA** — TOTP (authenticator apps) with email code fallback

### Design Decisions

- **EmailSender interface** with default SMTP implementation (consistent with `AuthDatabase`, `Logger`, `Metrics` patterns)
- **OAuthProvider interface** with built-in implementations + auto-registered routes (consistent with current auth route pattern)
- **Email verification configurable**: allow login with `EmailVerified=false` (default) or block until verified
- **Password reset tokens**: random token, bcrypt-hashed in DB (consistent with refresh token pattern)
- **User.Email field**: optional, falls back to Username for email operations
- **OAuth auto-link**: by verified email (default), configurable to require explicit linking. Auto-link only when local user's `EmailVerified=true` or the account was created via OAuth
- **Domain-split files, single AuthManager**: no new manager types, AuthManager coordinates all features
- **Optional sub-interfaces**: new DB methods (`FindByEmail`, `FindByOAuthProvider`) live on opt-in sub-interfaces, not the core `AuthDatabase` — avoids breaking existing implementations

---

## 2. Data Model

### User Struct Extensions

```go
type User struct {
    // Existing
    ID                    string
    Username              string
    Roles                 []UserRole
    PasswordHash          string
    RefreshTokenHash      string
    RefreshTokenExpiresAt time.Time

    // Email
    Email         string
    EmailVerified bool

    // Email verification
    EmailVerifyTokenHash      string
    EmailVerifyTokenExpiresAt time.Time
    EmailVerifyLastSentAt     time.Time // cooldown tracking for resend

    // Password reset
    PasswordResetTokenHash      string
    PasswordResetTokenExpiresAt time.Time

    // OAuth
    OAuthProviders []OAuthLink

    // 2FA
    TwoFactorEnabled     bool
    TwoFactorSecret      string   // encrypted TOTP secret (AES-256-GCM, see §8)
    TwoFactorBackupCodes []string // bcrypt-hashed backup codes
}

type OAuthLink struct {
    Provider   string // "google", "github", "apple", "telegram", "yandex"
    ProviderID string // unique ID from provider
    Email      string // email from provider (if available)
}
```

### UserDiff Extensions

Matching pointer fields for all new User fields, following the existing partial-update pattern. All slice fields (`OAuthProviders`, `TwoFactorBackupCodes`, `Roles`) are **full replacements**, not deltas. Callers must read-modify-write when appending.

### New DB Field Constants

`EmailDBField`, `EmailVerifiedDBField`, `EmailVerifyTokenHashDBField`, `EmailVerifyTokenExpiresAtDBField`, `EmailVerifyLastSentAtDBField`, `PasswordResetTokenHashDBField`, `PasswordResetTokenExpiresAtDBField`, `OAuthProvidersDBField`, `TwoFactorEnabledDBField`, `TwoFactorSecretDBField`, `TwoFactorBackupCodesDBField`.

### AuthDatabase Interface — Unchanged

The core `AuthDatabase` interface remains exactly as-is: `NewUser`, `FindByID`, `FindByUsername`, `FindAll`, `UpdateUser`. This is **not a breaking change**.

### Optional Sub-Interfaces

New lookup methods are defined on opt-in sub-interfaces. `AuthManager` type-asserts at startup and returns an error if the feature is enabled but the DB doesn't implement the required sub-interface.

```go
// EmailAuthDatabase is required when EmailConfig.Enabled = true
type EmailAuthDatabase interface {
    FindByEmail(ctx context.Context, email string) (User, bool, error)
}

// OAuthAuthDatabase is required when OAuthConfig.Enabled = true
type OAuthAuthDatabase interface {
    FindByOAuthProvider(ctx context.Context, provider string, providerID string) (User, bool, error)
}
```

Validation in `NewAuthManager`:
```go
if cfg.Email.Enabled {
    if _, ok := cfg.Database.(EmailAuthDatabase); !ok {
        return nil, errors.New("email auth requires AuthDatabase to implement EmailAuthDatabase")
    }
}
if cfg.OAuth.Enabled {
    if _, ok := cfg.Database.(OAuthAuthDatabase); !ok {
        return nil, errors.New("OAuth auth requires AuthDatabase to implement OAuthAuthDatabase")
    }
}
```

### MemoryAuthDatabase Updates

`MemoryAuthDatabase` implements both `EmailAuthDatabase` and `OAuthAuthDatabase`:
- Add `usersByEmail map[string]User` index for email lookups
- `FindByOAuthProvider` iterates over users (acceptable for in-memory dev use)

### Registration with Email — NewUser Atomicity

`NewUser(ctx, username, passwordHash, roles...)` signature is unchanged. Email is stored via a two-step process:

1. `NewUser` creates the user
2. `UpdateUser` sets `Email`, `EmailVerifyTokenHash`, `EmailVerifyTokenExpiresAt`

If step 2 fails, the user exists without an email (acceptable — email is optional). The verification email is sent only after both steps succeed. The two steps are NOT transactional — implementors who need atomicity can handle it in their `UpdateUser` implementation.

---

## 3. Interfaces

### EmailSender

```go
type EmailSender interface {
    SendVerificationEmail(ctx context.Context, to string, token string) error
    SendPasswordResetEmail(ctx context.Context, to string, token string) error
    SendTwoFactorCodeEmail(ctx context.Context, to string, code string) error
}
```

Default implementation: `SMTPEmailSender` using `net/smtp` stdlib.

### SMTPConfig

```go
type SMTPConfig struct {
    Host     string
    Port     int
    Username string
    Password string
    From     string

    VerificationSubject  string // default: "Verify your email"
    PasswordResetSubject string // default: "Reset your password"
    TwoFactorCodeSubject string // default: "Your verification code"

    VerificationURL  string // e.g. "https://myapp.com/verify-email"
    PasswordResetURL string // e.g. "https://myapp.com/reset-password"
}
```

### OAuthProvider

```go
type OAuthProvider interface {
    Name() string
    AuthURL(state string) string
    Exchange(ctx context.Context, code string) (*OAuthUserInfo, error)
}

type OAuthUserInfo struct {
    ProviderID string
    Email      string
    Username   string
    Verified   bool // whether provider verified the email
}
```

Built-in implementations: `GoogleOAuthProvider`, `GitHubOAuthProvider`, `AppleOAuthProvider`, `TelegramOAuthProvider`, `YandexOAuthProvider`.

---

## 4. Configuration

### AuthConfig Sub-Structs

```go
// Embedded in AuthConfig
Email     EmailConfig
OAuth     OAuthConfig
TwoFactor TwoFactorConfig
```

### EmailConfig

```go
type EmailConfig struct {
    Enabled             bool
    Sender              EmailSender
    SMTP                *SMTPConfig
    RequireVerification bool          // default: false (allow login, flag unverified)
    VerifyTokenDuration time.Duration // default: 24h
    ResetTokenDuration  time.Duration // default: 1h
    ResendCooldown      time.Duration // default: 60s, minimum interval between resends
}
```

### OAuthConfig

```go
type OAuthConfig struct {
    Enabled         bool
    Providers       []OAuthProvider
    AutoLinkByEmail bool   // default: true
    StateSigningKey string // hex-encoded 32-byte key for HMAC-SHA256 state signing
    BasePath        string // default: "/oauth" (relative to AuthBasePath)

    Google   *GoogleOAuthConfig
    GitHub   *GitHubOAuthConfig
    Apple    *AppleOAuthConfig
    Telegram *TelegramOAuthConfig
    Yandex   *YandexOAuthConfig
}
```

When a convenience config (e.g., `Google`) is non-nil, servex auto-creates the provider and appends to `Providers`.

**Provider Configs:**

```go
type GoogleOAuthConfig struct {
    ClientID     string
    ClientSecret string
    RedirectURL  string
    Scopes       []string // default: ["openid", "email", "profile"]
}

type GitHubOAuthConfig struct {
    ClientID     string
    ClientSecret string
    RedirectURL  string
    Scopes       []string // default: ["user:email"]
}

// Apple uses JWT-based client secret generation — no static client_secret
type AppleOAuthConfig struct {
    ClientID   string // Service ID
    TeamID     string // Apple Developer Team ID
    KeyID      string // Key ID from Apple Developer Portal
    PrivateKey string // ES256 private key (PEM-encoded string or file path)
    RedirectURL string
    Scopes     []string // default: ["name", "email"]
}

type TelegramOAuthConfig struct {
    BotToken    string // Telegram bot token
    RedirectURL string
}

type YandexOAuthConfig struct {
    ClientID     string
    ClientSecret string
    RedirectURL  string
    Scopes       []string
}
```

Note: `AppleOAuthProvider.Exchange` internally generates a short-lived JWT client secret from the `TeamID`, `KeyID`, and `PrivateKey` fields, as required by Apple's Sign In With Apple protocol.

### TwoFactorConfig

```go
type TwoFactorConfig struct {
    Enabled        bool
    Issuer         string        // TOTP issuer name in authenticator apps
    EmailFallback  bool          // default: true
    CodeDuration   time.Duration // email code validity, default: 10m
    BackupCodes    int           // number generated, default: 10
    EncryptionKey  string        // hex-encoded 32-byte key for AES-256-GCM encryption of TOTP secrets
    MaxVerifyAttempts int        // max 2FA verify attempts per pending token, default: 5
}
```

`EncryptionKey` is **required** when 2FA is enabled. It is completely independent from the JWT signing secrets. This allows JWT key rotation without affecting stored TOTP secrets.

### With* Options

```go
// Email
WithEmailSender(sender EmailSender)
WithEmailSMTP(cfg SMTPConfig)
WithEmailRequireVerification(bool)
WithEmailTokenDurations(verify, reset time.Duration)
WithEmailResendCooldown(d time.Duration)
WithEmailConfig(cfg EmailConfig)

// OAuth
WithOAuth(providers ...OAuthProvider)
WithOAuthGoogle(cfg GoogleOAuthConfig)
WithOAuthGitHub(cfg GitHubOAuthConfig)
WithOAuthApple(cfg AppleOAuthConfig)
WithOAuthTelegram(cfg TelegramOAuthConfig)
WithOAuthYandex(cfg YandexOAuthConfig)
WithOAuthAutoLink(bool)
WithOAuthBasePath(path string)
WithOAuthStateSigningKey(key string)
WithOAuthConfig(cfg OAuthConfig)

// 2FA
WithTwoFactor(encryptionKey string)
WithTwoFactorIssuer(name string)
WithTwoFactorEmailFallback(bool)
WithTwoFactorBackupCodes(count int)
WithTwoFactorCodeDuration(d time.Duration)
WithTwoFactorMaxAttempts(n int)
WithTwoFactorConfig(cfg TwoFactorConfig)
```

### YAML Mapping

```yaml
auth:
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
      password: "..."   # env: SERVEX_AUTH_EMAIL_SMTP_PASSWORD
      from: "noreply@myapp.com"
      verification_url: "https://myapp.com/verify-email"
      password_reset_url: "https://myapp.com/reset-password"
  oauth:
    enabled: true
    auto_link_by_email: true
    state_signing_key: "hex-encoded-32-byte-key"  # env: SERVEX_AUTH_OAUTH_STATE_SIGNING_KEY
    google:
      client_id: "..."
      client_secret: "..."  # env: SERVEX_AUTH_OAUTH_GOOGLE_CLIENT_SECRET
      redirect_url: "https://myapp.com/api/v1/auth/oauth/google/callback"
    github:
      client_id: "..."
      client_secret: "..."
    apple:
      client_id: "..."
      team_id: "..."
      key_id: "..."
      private_key: "..."  # env: SERVEX_AUTH_OAUTH_APPLE_PRIVATE_KEY (PEM)
      redirect_url: "https://myapp.com/api/v1/auth/oauth/apple/callback"
    telegram:
      bot_token: "..."  # env: SERVEX_AUTH_OAUTH_TELEGRAM_BOT_TOKEN
      redirect_url: "https://myapp.com/api/v1/auth/oauth/telegram/callback"
    yandex:
      client_id: "..."
      client_secret: "..."
  two_factor:
    enabled: true
    issuer: "MyApp"
    email_fallback: true
    code_duration: "10m"
    backup_codes: 10
    encryption_key: "hex-encoded-32-byte-key"  # env: SERVEX_AUTH_2FA_ENCRYPTION_KEY
    max_verify_attempts: 5
```

---

## 5. Endpoints

All paths are relative to `AuthBasePath` (default `/api/v1/auth`). Full example paths shown in parentheses.

### Email Verification

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `{AuthBasePath}/verify-email` (`/api/v1/auth/verify-email`) | No | Verify email with token |
| POST | `{AuthBasePath}/resend-verification` (`/api/v1/auth/resend-verification`) | Yes (Bearer) | Resend verification email (cooldown enforced) |

### Password Reset

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `{AuthBasePath}/forgot-password` (`/api/v1/auth/forgot-password`) | No | Request reset link |
| POST | `{AuthBasePath}/reset-password` (`/api/v1/auth/reset-password`) | No | Reset password with token |

### OAuth

OAuth routes are registered under `{AuthBasePath}/oauth` (configurable via `OAuthConfig.BasePath`). `BasePath` is relative to `AuthBasePath` — the subrouter already has the auth prefix applied.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `{AuthBasePath}/oauth/{provider}` (`/api/v1/auth/oauth/google`) | No | Redirect to provider auth page |
| GET | `{AuthBasePath}/oauth/{provider}/callback` (`/api/v1/auth/oauth/google/callback`) | No | Handle callback, issue tokens |
| POST | `{AuthBasePath}/oauth/{provider}/link` (`/api/v1/auth/oauth/google/link`) | Yes (Bearer) | Link provider to account |
| DELETE | `{AuthBasePath}/oauth/{provider}/link` (`/api/v1/auth/oauth/google/link`) | Yes (Bearer) | Unlink provider from account |

### 2FA

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `{AuthBasePath}/2fa/setup` (`/api/v1/auth/2fa/setup`) | Yes (Bearer) | Generate TOTP secret + backup codes |
| POST | `{AuthBasePath}/2fa/enable` (`/api/v1/auth/2fa/enable`) | Yes (Bearer) | Verify code, enable 2FA |
| POST | `{AuthBasePath}/2fa/disable` (`/api/v1/auth/2fa/disable`) | Yes (Bearer) | Disable 2FA (requires code) |
| POST | `{AuthBasePath}/2fa/verify` (`/api/v1/auth/2fa/verify`) | 2FA pending token | Complete login with 2FA code |
| POST | `{AuthBasePath}/2fa/send-email-code` (`/api/v1/auth/2fa/send-email-code`) | 2FA pending token | Send email 2FA code |

The "2FA pending token" endpoints accept the pending token in the request body (`{token: "...", code: "..."}`), NOT as a Bearer header. The pending token is validated internally with purpose checking (see §6, §8).

### Request/Response Structs

**Register request** (extended):
```go
type RegisterRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
    Email    string `json:"email,omitempty"` // optional
}
```

**Forgot password request:**
```go
type ForgotPasswordRequest struct {
    Identifier string `json:"identifier"` // email address or username
}
```

Lookup logic: if `Identifier` field contains `@`, look up via `FindByEmail`. Otherwise, treat as username and look up via `FindByUsername`, then use the user's stored email address.

**Reset password request:**
```go
type ResetPasswordRequest struct {
    Token    string `json:"token"`
    Password string `json:"password"`
}
```

**2FA verify request:**
```go
type TwoFactorVerifyRequest struct {
    Token string `json:"token"` // 2FA pending token
    Code  string `json:"code"`  // TOTP code, backup code, or email code
}
```

**2FA send email code request:**
```go
type TwoFactorSendEmailCodeRequest struct {
    Token string `json:"token"` // 2FA pending token
}
```

**2FA email code cooldown:** The `/2fa/send-email-code` endpoint enforces its own per-token cooldown of 60 seconds, tracked in the same server-side in-memory map used for attempt counting (keyed by `jti`). If called again within the cooldown window, returns 429.

---

## 6. Flows

### Registration with Email Verification

1. User POSTs to `{AuthBasePath}/register` with `{username, password, email?}`
2. `NewUser(ctx, username, passwordHash, roles...)` creates the user
3. If `email` provided: `UpdateUser` sets `Email`, generates verification token, stores bcrypt hash + expiry, sends email via `EmailSender.SendVerificationEmail`
4. If `RequireVerification=false` (default): issue tokens normally, `EmailVerified=false`
5. If `RequireVerification=true`: return 201 with message "check your email", no tokens
6. User clicks email link, frontend POSTs `{token}` to `/verify-email`
7. Server validates token hash + expiry, sets `EmailVerified=true`, clears token fields

**Resend cooldown:** `/resend-verification` checks `EmailVerifyLastSentAt`. If less than `ResendCooldown` (default 60s) has passed, returns 429. Otherwise, generates a new token and sends.

### Login with 2FA

1. User POSTs credentials to `{AuthBasePath}/login`
2. Credentials validated normally
3. If `TwoFactorEnabled=true`: return 200 with `{twoFactorToken: "..."}` — a short-lived JWT (5 min) with `TokenPurpose: "2fa_pending"`. The JWT contains a unique `jti` (JWT ID) claim for tracking. No access/refresh tokens issued. No attempt count is stored in the JWT (JWTs are immutable).
4. User POSTs `{token, code}` to `{AuthBasePath}/2fa/verify`
5. Server validates: JWT signature → expiry → `TokenPurpose == "2fa_pending"`
6. Server checks attempt count in the **server-side in-memory map** (keyed by `jti`, TTL matching token expiry). If `count >= MaxVerifyAttempts` (default: 5), return 401 "too many attempts, re-authenticate"
7. Server validates TOTP code (or backup code, or email code)
8. If code invalid: increment attempt count in the in-memory map. The JWT itself is unchanged — the server-side map is the sole source of truth for attempt tracking.
9. If code valid: delete the `jti` entry from the map, issue normal access/refresh tokens

### OAuth Login

1. User visits `GET {AuthBasePath}/oauth/google`
2. Servex generates random `state` value, signs it with HMAC-SHA256 using `StateSigningKey`, stores signed value in cookie (`_servex_oauth_state`, Max-Age=600s, HttpOnly, SameSite=Lax, Secure)
3. Redirects to `provider.AuthURL(state)`
4. Provider redirects to `GET {AuthBasePath}/oauth/google/callback?code=...&state=...`
5. Servex reads state cookie, verifies HMAC signature against query param `state`, deletes cookie
6. Calls `provider.Exchange(code)` → `OAuthUserInfo`
7. Lookup by `(provider, providerID)` via `FindByOAuthProvider`
8. If found → issue tokens (with 2FA check if user has 2FA enabled)
9. If not found + `AutoLinkByEmail=true` + `OAuthUserInfo.Verified=true`:
   - Lookup by email via `FindByEmail`
   - If found AND local `User.EmailVerified=true` → link OAuth provider to existing account, issue tokens
   - If found AND local `User.EmailVerified=false` → do NOT link. Return error: "email already registered, verify your email first or log in to link this provider"
   - If not found → create new user with OAuth link, set `EmailVerified=true` (provider verified), issue tokens
10. If `AutoLinkByEmail=false` → create new user with OAuth link, issue tokens (no linking to existing accounts)

**OAuth + RequireVerification interaction:** When a new user is created via OAuth and `OAuthUserInfo.Verified=true`, the user is created with `EmailVerified=true`. This satisfies `RequireVerification` regardless of its setting — tokens are issued immediately. When the provider returns `OAuthUserInfo.Verified=false` (e.g., Telegram, which may not provide a verified email), if `RequireVerification=true`, the server creates the user with `EmailVerified=false` and does NOT issue tokens — the user must verify their email first (a verification email is sent if an email address is available). If `RequireVerification=false` (default), tokens are issued normally with `EmailVerified=false`.

**Two providers, same email:** First-link wins. If user A linked Google with email X, and user B tries GitHub OAuth with the same email X, user B gets linked to user A's account (if auto-link is enabled and both emails are verified). This is standard behavior — the email is the identity anchor.

### Password Reset

1. User POSTs `{identifier: "..."}` to `{AuthBasePath}/forgot-password`
2. Lookup: if `identifier` contains `@`, use `FindByEmail`. Otherwise use `FindByUsername` and get user's email
3. Always returns 200 with `{message: "if the email exists, a reset link has been sent"}` (timing-safe)
4. If user found and has an email: generate random token, bcrypt hash, store hash + expiry (1h default), send email via `EmailSender.SendPasswordResetEmail`
5. User clicks link, frontend POSTs `{token, password}` to `{AuthBasePath}/reset-password`
6. Server iterates approach: the reset token includes user ID as a prefix (`userID:randomToken`). Server extracts user ID, loads user, compares bcrypt hash of token portion, checks expiry
7. If valid: update password hash, clear reset token fields, clear refresh token hash (force re-login)

### OAuth Login + 2FA Interaction

When a user with 2FA enabled logs in via OAuth:
1. OAuth callback resolves to a user with `TwoFactorEnabled=true`
2. Instead of issuing access/refresh tokens, return a redirect to a frontend 2FA page with a `twoFactorToken` as a query parameter
3. User completes 2FA verification via `POST {AuthBasePath}/2fa/verify` as normal

---

## 7. JWT Claims Extension

The existing `jwtClaims` struct gains a `TokenPurpose` field:

```go
type jwtClaims struct {
    UserID       string     `json:"user_id"`
    Roles        []UserRole `json:"roles,omitempty"`
    IsRefresh    bool       `json:"is_refresh,omitempty"`
    TokenPurpose string     `json:"purpose,omitempty"` // "access", "refresh", "2fa_pending"
    jwt.RegisteredClaims                               // includes ID (jti) field
}
```

**2FA pending tokens** include a unique `jti` (JWT ID) claim — a random UUID generated at creation time. This `jti` is used as the key in the server-side in-memory attempt-tracking map.

**Validation rules:**
- `validateAccessToken` rejects tokens where `TokenPurpose != "access"` (or empty for backward compat with existing tokens)
- `validateRefreshToken` rejects tokens where `TokenPurpose != "refresh"` (or empty for backward compat)
- `validate2FAPendingToken` requires `TokenPurpose == "2fa_pending"` and a non-empty `jti`
- `WithAuth` middleware rejects any token that is not a valid access token — a `2fa_pending` token presented to `WithAuth` is treated as an invalid access token and returns **401 Unauthorized** with message `"2FA verification required"`. It does NOT return 403 (which implies authentication succeeded but authorization failed).

Backward compatibility: existing tokens without `TokenPurpose` are treated as access or refresh based on the `IsRefresh` flag (existing behavior preserved).

---

## 8. Security Considerations

### Token Security

- **Password reset tokens**: random 32-byte token, bcrypt-hashed in DB, single-use (cleared after use), time-limited (1h default)
- **Email verification tokens**: random 32-byte token, bcrypt-hashed in DB, time-limited (24h default), resendable with cooldown (60s default)
- **2FA pending tokens**: JWT with `TokenPurpose: "2fa_pending"`, 5 min expiry, rejected by `WithAuth` middleware. Attempt count tracked server-side (in-memory map keyed by `jti`, with TTL matching token expiry). Max 5 attempts (configurable), then invalidated. Eviction strategy: lazy expiration on read (expired entries removed when accessed) plus a background goroutine that sweeps expired entries every minute to bound memory usage from abandoned sessions.
- **Timing safety**: `/forgot-password` always returns 200 regardless of user existence. Same error message for all failure cases.

### TOTP Secret Encryption

TOTP secrets stored in `User.TwoFactorSecret` are encrypted with **AES-256-GCM**:
- Encryption key: `TwoFactorConfig.EncryptionKey` (hex-encoded 32-byte key, **required** when 2FA is enabled)
- Completely independent from JWT signing secrets — JWT key rotation does not affect stored TOTP secrets
- Each record uses a random 12-byte nonce, prepended to the ciphertext
- Format: `base64(nonce + ciphertext + GCM tag)`
- Key rotation: re-encrypt all secrets with new key (consumer responsibility, can be done via `FindAll` + `UpdateUser`)

### OAuth State Protection

- State value: random 32-byte token
- Signed with HMAC-SHA256 using `OAuthConfig.StateSigningKey` (hex-encoded 32-byte key, **required** when OAuth is enabled)
- Stored in cookie: `_servex_oauth_state`, Max-Age=600s (10 min), HttpOnly, SameSite=Lax, Secure (or ForceSecureCookies)
- Callback validates: cookie exists, HMAC signature matches, then deletes cookie
- SameSite=Lax (not Strict) is required for OAuth — the redirect back from the provider is a cross-site navigation

### OAuth Auto-Link Safety

- Auto-link only occurs when:
  1. `AutoLinkByEmail=true` AND
  2. `OAuthUserInfo.Verified=true` (provider confirmed the email) AND
  3. Local `User.EmailVerified=true` (or user was created via OAuth)
- If local `EmailVerified=false`, auto-link is refused — prevents account takeover via unverified email
- Two-providers-same-email: first-link wins (email is the identity anchor)

### Backup Codes

- 10 codes generated (configurable)
- Each code: 8 random alphanumeric characters
- Each code individually bcrypt-hashed before storage
- Single-use: hash removed from `TwoFactorBackupCodes` slice after successful use
- All codes invalidated when 2FA is disabled or re-setup

### Cookie Security (inherited)

All new cookies follow existing patterns: HttpOnly, Secure (HTTPS or ForceSecureCookies), path-scoped to AuthBasePath.

---

## 9. Audit Logging

All new auth-significant events are logged via the existing `AuditLogger` interface. New event type constants:

```go
const (
    AuditEventEmailVerified       AuditEventType = "auth.email.verified"
    AuditEventEmailVerifyFailed   AuditEventType = "auth.email.verify_failed"
    AuditEventPasswordResetReq    AuditEventType = "auth.password_reset.requested"
    AuditEventPasswordResetDone   AuditEventType = "auth.password_reset.completed"
    AuditEventPasswordResetFailed AuditEventType = "auth.password_reset.failed"
    AuditEventOAuthLogin          AuditEventType = "auth.oauth.login"
    AuditEventOAuthLoginFailed    AuditEventType = "auth.oauth.login_failed"
    AuditEventOAuthLink           AuditEventType = "auth.oauth.link"
    AuditEventOAuthUnlink         AuditEventType = "auth.oauth.unlink"
    AuditEvent2FASetup            AuditEventType = "auth.2fa.setup"
    AuditEvent2FAEnabled          AuditEventType = "auth.2fa.enabled"
    AuditEvent2FADisabled         AuditEventType = "auth.2fa.disabled"
    AuditEvent2FAVerified         AuditEventType = "auth.2fa.verified"
    AuditEvent2FAFailed           AuditEventType = "auth.2fa.failed"
    AuditEvent2FALocked           AuditEventType = "auth.2fa.locked"
    AuditEventBackupCodeUsed      AuditEventType = "auth.2fa.backup_code_used"
)
```

Each event includes a details map with context: user ID, provider name (OAuth), IP address, and relevant metadata. Follows the same `auditLogger.Log(event, details)` pattern used by existing handlers.

---

## 10. File Organization

### New Files

| File | Contents |
|------|----------|
| `auth_email.go` | `EmailSender` interface, `SMTPEmailSender`, `EmailAuthDatabase` sub-interface, verification/reset token logic, handlers |
| `auth_oauth.go` | `OAuthProvider` interface, `OAuthUserInfo`, `OAuthAuthDatabase` sub-interface, OAuth flow handlers, state management |
| `auth_oauth_providers.go` | Google, GitHub, Apple, Telegram, Yandex provider implementations |
| `auth_2fa.go` | TOTP setup/verify/disable, email code fallback, backup codes, AES-256-GCM encryption, attempt tracking |
| `options_email.go` | `EmailConfig`, `SMTPConfig`, `With*` email options |
| `options_oauth.go` | `OAuthConfig`, provider configs (incl. `AppleOAuthConfig` with TeamID/KeyID/PrivateKey), `With*` OAuth options |
| `options_2fa.go` | `TwoFactorConfig`, `With*` 2FA options |

### Modified Files

| File | Changes |
|------|---------|
| `auth.go` | User struct new fields, UserDiff new fields, `jwtClaims.TokenPurpose` field, route registration for new endpoints, login 2FA check, audit event constants |
| `options_core.go` | AuthConfig gains Email, OAuth, TwoFactor sub-structs |
| `config.go` | YAML parsing for new config sections |
| `context_request.go` | `EmailVerified()`, `TwoFactorEnabled()` context helpers |
| `servex.go` | Initialize email sender, OAuth providers, 2FA on startup; validate sub-interfaces |

### Test Files

| File | Contents |
|------|----------|
| `auth_email_test.go` | Verification flow, reset flow, token expiry, resend cooldown, `RequireVerification=true` + OAuth interaction, mock EmailSender |
| `auth_oauth_test.go` | OAuth redirect, callback, state HMAC validation, auto-link (verified/unverified/collision), explicit link/unlink, mock OAuthProvider |
| `auth_2fa_test.go` | TOTP setup/enable/disable, login with 2FA, email fallback, backup codes, attempt exhaustion, pending token rejection by WithAuth, 2FA + OAuth combined flow |

### Dependencies

- `github.com/pquerna/otp` — TOTP generation/validation
- No new deps for OAuth (`net/http` + `encoding/json`)
- No new deps for SMTP (`net/smtp` stdlib)
- No new deps for AES-256-GCM (`crypto/aes`, `crypto/cipher` stdlib)
