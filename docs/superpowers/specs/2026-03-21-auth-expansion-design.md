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
- **OAuth auto-link**: by verified email (default), configurable to require explicit linking
- **Domain-split files, single AuthManager**: no new manager types, AuthManager coordinates all features

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

    // Password reset
    PasswordResetTokenHash      string
    PasswordResetTokenExpiresAt time.Time

    // OAuth
    OAuthProviders []OAuthLink

    // 2FA
    TwoFactorEnabled     bool
    TwoFactorSecret      string   // encrypted TOTP secret
    TwoFactorBackupCodes []string // hashed backup codes
}

type OAuthLink struct {
    Provider   string // "google", "github", "apple", "telegram", "yandex"
    ProviderID string // unique ID from provider
    Email      string // email from provider (if available)
}
```

### UserDiff Extensions

Matching pointer fields for all new User fields, following the existing partial-update pattern.

### New DB Field Constants

`EmailDBField`, `EmailVerifiedDBField`, `OAuthProvidersDBField`, `TwoFactorEnabledDBField`, etc.

### AuthDatabase Interface — Two New Methods

```go
FindByEmail(ctx context.Context, email string) (User, bool, error)
FindByOAuthProvider(ctx context.Context, provider string, providerID string) (User, bool, error)
```

Existing methods (`NewUser`, `FindByID`, `FindByUsername`, `FindAll`, `UpdateUser`) remain unchanged. All new fields flow through `UserDiff` via `UpdateUser`.

### MemoryAuthDatabase Updates

- Add `usersByEmail map[string]User` index for email lookups
- `FindByOAuthProvider` iterates over users (acceptable for in-memory dev use)

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
}
```

### OAuthConfig

```go
type OAuthConfig struct {
    Enabled         bool
    Providers       []OAuthProvider
    AutoLinkByEmail bool   // default: true
    BasePath        string // default: AuthBasePath + "/oauth"

    Google   *GoogleOAuthConfig
    GitHub   *GitHubOAuthConfig
    Apple    *AppleOAuthConfig
    Telegram *TelegramOAuthConfig
    Yandex   *YandexOAuthConfig
}
```

When a convenience config (e.g., `Google`) is non-nil, servex auto-creates the provider and appends to `Providers`.

### TwoFactorConfig

```go
type TwoFactorConfig struct {
    Enabled       bool
    Issuer        string        // TOTP issuer name in authenticator apps
    EmailFallback bool          // default: true
    CodeDuration  time.Duration // email code validity, default: 10m
    BackupCodes   int           // number generated, default: 10
}
```

### With* Options

```go
// Email
WithEmailSender(sender EmailSender)
WithEmailSMTP(cfg SMTPConfig)
WithEmailRequireVerification(bool)
WithEmailTokenDurations(verify, reset time.Duration)

// OAuth
WithOAuth(providers ...OAuthProvider)
WithOAuthGoogle(cfg GoogleOAuthConfig)
WithOAuthGitHub(cfg GitHubOAuthConfig)
WithOAuthApple(cfg AppleOAuthConfig)
WithOAuthTelegram(cfg TelegramOAuthConfig)
WithOAuthYandex(cfg YandexOAuthConfig)
WithOAuthAutoLink(bool)
WithOAuthBasePath(path string)

// 2FA
WithTwoFactor()
WithTwoFactorIssuer(name string)
WithTwoFactorEmailFallback(bool)
WithTwoFactorBackupCodes(count int)
```

### YAML Mapping

```yaml
auth:
  email:
    enabled: true
    require_verification: false
    verify_token_duration: "24h"
    reset_token_duration: "1h"
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
    google:
      client_id: "..."
      client_secret: "..."  # env: SERVEX_AUTH_OAUTH_GOOGLE_CLIENT_SECRET
      redirect_url: "https://myapp.com/auth/oauth/google/callback"
    github:
      client_id: "..."
      client_secret: "..."
    # apple, telegram, yandex similarly
  two_factor:
    enabled: true
    issuer: "MyApp"
    email_fallback: true
    backup_codes: 10
```

---

## 5. Endpoints

### Email Verification

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/verify-email` | No | Verify email with token (`{token: "..."}`) |
| POST | `/auth/resend-verification` | Yes (Bearer) | Resend verification email |

### Password Reset

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/forgot-password` | No | Request reset link (`{email: "..."}`) |
| POST | `/auth/reset-password` | No | Reset password (`{token: "...", password: "..."}`) |

### OAuth

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/oauth/{provider}` | No | Redirect to provider auth page |
| GET | `/auth/oauth/{provider}/callback` | No | Handle callback, issue tokens |
| POST | `/auth/oauth/{provider}/link` | Yes (Bearer) | Link provider to account |
| DELETE | `/auth/oauth/{provider}/link` | Yes (Bearer) | Unlink provider from account |

### 2FA

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/2fa/setup` | Yes (Bearer) | Generate TOTP secret + backup codes |
| POST | `/auth/2fa/enable` | Yes (Bearer) | Verify code, enable 2FA |
| POST | `/auth/2fa/disable` | Yes (Bearer) | Disable 2FA (requires code) |
| POST | `/auth/2fa/verify` | No* | Complete login with 2FA code |
| POST | `/auth/2fa/send-email-code` | No* | Send email 2FA code |

*Uses short-lived "2FA pending" token, not full access token.

---

## 6. Flows

### Registration with Email Verification

1. User POSTs to `/register` with `{username, password}` (and optionally `email`)
2. If email config enabled: generate random verification token, bcrypt hash & store in user record, send email via `EmailSender.SendVerificationEmail`
3. If `RequireVerification=false` (default): issue tokens normally, `EmailVerified=false`
4. If `RequireVerification=true`: return 201 with message only, no tokens
5. User clicks email link, frontend POSTs `{token}` to `/verify-email`
6. Server validates token hash + expiry, sets `EmailVerified=true`, clears token

### Login with 2FA

1. User POSTs credentials to `/login`
2. Credentials validated normally
3. If `TwoFactorEnabled=true`: return 200 with `{twoFactorToken: "..."}` (short-lived JWT, 5 min, purpose-flagged) — no access/refresh tokens
4. User POSTs `{token, code}` to `/2fa/verify`
5. Server validates TOTP code (or backup code, or email code)
6. If valid: issue normal access/refresh tokens

### OAuth Login

1. User visits `GET /auth/oauth/google`
2. Servex generates random `state`, stores in short-lived encrypted cookie, redirects to Google
3. Google redirects to `GET /auth/oauth/google/callback?code=...&state=...`
4. Servex validates `state` cookie, calls `provider.Exchange(code)` → `OAuthUserInfo`
5. Lookup by `(provider, providerID)` via `FindByOAuthProvider`
6. If found → issue tokens (with 2FA check if enabled)
7. If not found + `AutoLinkByEmail=true` + email verified by provider → lookup by email, link if found
8. If no user found → create new user with OAuth link, issue tokens
9. State stored in short-lived encrypted cookie (not server-side session)

### Password Reset

1. User POSTs `{email}` to `/forgot-password`
2. Server looks up user by email (or username fallback). Always returns 200 (timing-safe)
3. If user found: generate random token, bcrypt hash, store hash + expiry (1h default), send email
4. User clicks link, frontend POSTs `{token, password}` to `/reset-password`
5. Server finds user, compares bcrypt hash, checks expiry
6. If valid: update password hash, clear reset token, invalidate refresh token (force re-login)

---

## 7. File Organization

### New Files

| File | Contents |
|------|----------|
| `auth_email.go` | `EmailSender` interface, `SMTPEmailSender`, verification/reset token logic |
| `auth_oauth.go` | `OAuthProvider` interface, `OAuthUserInfo`, OAuth flow handlers, state management |
| `auth_oauth_providers.go` | Google, GitHub, Apple, Telegram, Yandex provider implementations |
| `auth_2fa.go` | TOTP setup/verify/disable, email code fallback, backup codes |
| `options_email.go` | `EmailConfig`, `SMTPConfig`, `With*` email options |
| `options_oauth.go` | `OAuthConfig`, provider configs, `With*` OAuth options |
| `options_2fa.go` | `TwoFactorConfig`, `With*` 2FA options |

### Modified Files

| File | Changes |
|------|---------|
| `auth.go` | User struct new fields, UserDiff new fields, AuthDatabase 2 new methods, route registration, login 2FA check |
| `options_core.go` | AuthConfig gains Email, OAuth, TwoFactor sub-structs |
| `config.go` | YAML parsing for new config sections |
| `context_request.go` | `EmailVerified()`, `TwoFactorEnabled()` context helpers |
| `servex.go` | Initialize email sender, OAuth providers, 2FA on startup |

### Test Files

| File | Contents |
|------|----------|
| `auth_email_test.go` | Verification flow, reset flow, token expiry, resend, mock EmailSender |
| `auth_oauth_test.go` | OAuth redirect, callback, auto-link, link/unlink, mock OAuthProvider |
| `auth_2fa_test.go` | TOTP setup/enable/disable, login with 2FA, email fallback, backup codes |

### Dependencies

- `github.com/pquerna/otp` — TOTP generation/validation
- No new deps for OAuth (`net/http` + `encoding/json`)
- No new deps for SMTP (`net/smtp` stdlib)

---

## 8. Security Considerations

- **Password reset tokens**: bcrypt-hashed, single-use (cleared after use), time-limited (1h)
- **Email verification tokens**: bcrypt-hashed, time-limited (24h), resendable
- **OAuth state**: random, stored in short-lived encrypted cookie, validated on callback
- **2FA secrets**: stored encrypted in DB (encryption key derived from access secret)
- **Backup codes**: bcrypt-hashed individually, single-use (removed after use)
- **2FA pending tokens**: short-lived JWT (5 min), purpose-flagged to prevent misuse
- **Timing safety**: `/forgot-password` always returns 200 regardless of user existence
- **Auto-link safety**: only links OAuth accounts when provider confirms email is verified
- **TOTP window**: standard ±1 period tolerance for clock drift
