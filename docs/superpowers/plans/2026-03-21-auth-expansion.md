# Auth Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add email verification, password reset, OAuth (Google/GitHub/Apple/Telegram/Yandex), and 2FA (TOTP + email fallback) to servex's authentication system.

**Architecture:** Domain-split files with a single AuthManager coordinator. New interfaces (EmailSender, OAuthProvider) follow the existing extensibility pattern. Optional sub-interfaces (EmailAuthDatabase, OAuthAuthDatabase) avoid breaking the core AuthDatabase. Config uses nested sub-structs in AuthConfig with matching With* options.

**Tech Stack:** Go stdlib (net/smtp, crypto/aes, crypto/cipher, crypto/hmac), github.com/pquerna/otp (TOTP), github.com/golang-jwt/jwt/v4 (existing), golang.org/x/crypto/bcrypt (existing)

**Spec:** `docs/superpowers/specs/2026-03-21-auth-expansion-design.md`

---

## File Map

### New Files

| File | Responsibility |
|------|---------------|
| `auth_email.go` | EmailSender interface, EmailAuthDatabase sub-interface, SMTPEmailSender, RegisterRequest, ForgotPasswordRequest, ResetPasswordRequest, verification/reset token logic, handlers |
| `auth_oauth.go` | OAuthProvider interface, OAuthAuthDatabase sub-interface, OAuthUserInfo, OAuth flow handlers, HMAC state management |
| `auth_oauth_providers.go` | Google, GitHub, Apple, Telegram, Yandex provider implementations |
| `auth_2fa.go` | TOTP setup/verify/disable, AES-256-GCM encrypt/decrypt, backup codes, email code fallback, attempt tracker, handlers |
| `options_email.go` | EmailConfig, SMTPConfig, With* email options |
| `options_oauth.go` | OAuthConfig, provider configs, With* OAuth options |
| `options_2fa.go` | TwoFactorConfig, With* 2FA options |
| `auth_email_test.go` | Email verification, password reset, resend cooldown, RequireVerification tests |
| `auth_oauth_test.go` | OAuth redirect, callback, state HMAC, auto-link, link/unlink tests |
| `auth_oauth_providers_test.go` | Unit tests for provider implementations (Apple generateClientSecret, etc.) |
| `auth_2fa_test.go` | TOTP setup/enable/disable, 2FA login, backup codes, attempt exhaustion, email fallback tests |

### Modified Files

| File | Changes |
|------|---------|
| `auth.go` | User/UserDiff new fields, OAuthLink, jwtClaims.TokenPurpose, new errors, MemoryAuthDatabase new methods/fields, context keys |
| `audit.go` | New audit event type constants |
| `options_core.go` | AuthConfig gains Email/OAuth/TwoFactor sub-structs |
| `config.go` | AuthConfiguration sub-structs, config-to-options mapping |
| `context_request.go` | EmailVerified(), TwoFactorEnabled() helpers |
| `go.mod` / `go.sum` | Add `github.com/pquerna/otp` dependency |

---

## Task 1: Data Model — User, UserDiff, DB Constants, MemoryAuthDatabase

**Files:**
- Modify: `auth.go`
- Modify: `audit.go`

- [ ] **Step 1: Add OAuthLink struct and new fields to User struct**

In `auth.go`, add `OAuthLink` after `User` struct and extend `User` (line 42-49). **Keep existing struct tags exactly as-is** (do not add/remove omitempty on existing fields):

```go
type User struct {
	ID                    string     `json:"id" bson:"_id" db:"id"`
	Username              string     `json:"username" bson:"username" db:"username"`
	Roles                 []UserRole `json:"roles" bson:"roles" db:"roles"`
	PasswordHash          string     `json:"password_hash" bson:"password_hash" db:"password_hash"`
	RefreshTokenHash      string     `json:"refresh_token_hash" bson:"refresh_token_hash" db:"refresh_token_hash"`
	RefreshTokenExpiresAt time.Time  `json:"refresh_token_expires_at" bson:"refresh_token_expires_at" db:"refresh_token_expires_at"`

	// Email
	Email         string `json:"email,omitempty" bson:"email,omitempty" db:"email"`
	EmailVerified bool   `json:"email_verified" bson:"email_verified" db:"email_verified"`

	// Email verification
	EmailVerifyTokenHash      string    `json:"email_verify_token_hash,omitempty" bson:"email_verify_token_hash,omitempty" db:"email_verify_token_hash"`
	EmailVerifyTokenExpiresAt time.Time `json:"email_verify_token_expires_at,omitempty" bson:"email_verify_token_expires_at,omitempty" db:"email_verify_token_expires_at"`
	EmailVerifyLastSentAt     time.Time `json:"email_verify_last_sent_at,omitempty" bson:"email_verify_last_sent_at,omitempty" db:"email_verify_last_sent_at"`

	// Password reset
	PasswordResetTokenHash      string    `json:"password_reset_token_hash,omitempty" bson:"password_reset_token_hash,omitempty" db:"password_reset_token_hash"`
	PasswordResetTokenExpiresAt time.Time `json:"password_reset_token_expires_at,omitempty" bson:"password_reset_token_expires_at,omitempty" db:"password_reset_token_expires_at"`

	// OAuth
	OAuthProviders []OAuthLink `json:"oauth_providers,omitempty" bson:"oauth_providers,omitempty" db:"oauth_providers"`

	// 2FA
	TwoFactorEnabled     bool     `json:"two_factor_enabled" bson:"two_factor_enabled" db:"two_factor_enabled"`
	TwoFactorSecret      string   `json:"two_factor_secret,omitempty" bson:"two_factor_secret,omitempty" db:"two_factor_secret"`
	TwoFactorBackupCodes []string `json:"two_factor_backup_codes,omitempty" bson:"two_factor_backup_codes,omitempty" db:"two_factor_backup_codes"`
}

// OAuthLink represents a linked OAuth provider account.
type OAuthLink struct {
	Provider   string `json:"provider" bson:"provider" db:"provider"`
	ProviderID string `json:"provider_id" bson:"provider_id" db:"provider_id"`
	Email      string `json:"email,omitempty" bson:"email,omitempty" db:"email"`
}
```

- [ ] **Step 2: Extend UserDiff with matching pointer fields**

Extend `UserDiff` (line 51-57) with pointer fields for all new User fields. Keep existing fields exactly as-is.

- [ ] **Step 3: Add new DB field constants**

After existing constants block (line 59-67), add new constants for all new fields: `EmailDBField`, `EmailVerifiedDBField`, `EmailVerifyTokenHashDBField`, `EmailVerifyTokenExpiresAtDBField`, `EmailVerifyLastSentAtDBField`, `PasswordResetTokenHashDBField`, `PasswordResetTokenExpiresAtDBField`, `OAuthProvidersDBField`, `TwoFactorEnabledDBField`, `TwoFactorSecretDBField`, `TwoFactorBackupCodesDBField`.

- [ ] **Step 4: Add RegisterRequest struct**

Add in `auth_email.go` (will be created in Task 5, but define here for Task 6 to use). For now, add in `auth.go` after `UserLoginRequest`:

```go
// RegisterRequest extends login request with optional email for registration.
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email,omitempty"`
}

// Validate checks if the RegisterRequest is valid.
func (req RegisterRequest) Validate() error {
	if req.Username == "" {
		return errors.New("username is required")
	}
	if req.Password == "" {
		return errors.New("password is required")
	}
	return nil
}
```

- [ ] **Step 5: Add new error variables**

After existing errors (line 814-820), add errors for email, password reset, OAuth, and 2FA.

- [ ] **Step 6: Add context keys**

Extend context keys (line 97-100):

```go
type (
	UserContextKey             struct{}
	RoleContextKey             struct{}
	EmailVerifiedContextKey    struct{}
	TwoFactorEnabledContextKey struct{}
)
```

- [ ] **Step 7: Update MemoryAuthDatabase struct and constructor**

**Do this BEFORE updating UpdateUser.** Add `usersByEmail map[string]User` to the struct (line 889-894) and initialize it in `NewMemoryAuthDatabase` (line 896-901).

- [ ] **Step 8: Update MemoryAuthDatabase.UpdateUser for new fields**

Extend `UpdateUser` (line 951-987) to handle all new UserDiff fields. For `Email`, maintain the `usersByEmail` index (delete old key, set new key). Note: `NewUser` does NOT set Email — email is always added via `UpdateUser` per the spec's two-step creation model.

- [ ] **Step 9: Add FindByEmail and FindByOAuthProvider to MemoryAuthDatabase**

Add after `UpdateUser`:
- `FindByEmail`: lookup in `usersByEmail` map
- `FindByOAuthProvider`: iterate `usersByID`, scan `OAuthProviders` slice

- [ ] **Step 10: Add audit event constants**

In `audit.go`, add after existing constants (line 50): `AuditEventEmailVerified`, `AuditEventEmailVerifyFailed`, `AuditEventPasswordResetReq`, `AuditEventPasswordResetDone`, `AuditEventPasswordResetFailed`, `AuditEventOAuthLogin`, `AuditEventOAuthLoginFailed`, `AuditEventOAuthLink`, `AuditEventOAuthUnlink`, `AuditEvent2FASetup`, `AuditEvent2FAEnabled`, `AuditEvent2FADisabled`, `AuditEvent2FAVerified`, `AuditEvent2FAFailed`, `AuditEvent2FALocked`, `AuditEventBackupCodeUsed`. All typed as `AuditEventType` with `"auth.*.action"` dot-namespace pattern.

- [ ] **Step 11: Run tests**

Run: `go test -v -race -count=1 .`
Expected: All existing tests PASS (changes are additive, zero values safe)

- [ ] **Step 12: Commit**

```bash
git add auth.go audit.go
git commit -m "feat(auth): extend User/UserDiff with email, OAuth, and 2FA fields"
```

---

## Task 2: JWT Claims — TokenPurpose Field

**Files:**
- Modify: `auth.go`

- [ ] **Step 1: Add TokenPurpose to jwtClaims**

Update `jwtClaims` (line 499-504). **Do NOT change existing field tags** (keep `Roles` as `json:"roles"` without omitempty, keep `IsRefresh` as `json:"is_refresh"`):

```go
type jwtClaims struct {
	UserID       string     `json:"user_id"`
	Roles        []UserRole `json:"roles"`
	IsRefresh    bool       `json:"is_refresh"`
	TokenPurpose string     `json:"purpose,omitempty"`
	jwt.RegisteredClaims
}
```

Add purpose constants:

```go
const (
	tokenPurposeAccess     = "access"
	tokenPurposeRefresh    = "refresh"
	tokenPurpose2FAPending = "2fa_pending"
)
```

- [ ] **Step 2: Set TokenPurpose in generateToken**

Update `generateToken` (line 779-812) to set `TokenPurpose` based on `isRefresh`. Access tokens get `tokenPurposeAccess`, refresh tokens get `tokenPurposeRefresh`. Keep existing `IsRefresh` field assignment — both `IsRefresh` and `TokenPurpose` coexist for backward compatibility. The redundancy is intentional: `IsRefresh` is kept for old clients, `TokenPurpose` is the new standard.

- [ ] **Step 3: Add TokenPurpose check to validateAccessToken**

Find `validateAccessToken` and add after existing `IsRefresh` check:

```go
	// Reject non-access tokens (2fa_pending, etc.)
	// Allow empty purpose for backward compat with pre-existing tokens
	if claims.TokenPurpose != "" && claims.TokenPurpose != tokenPurposeAccess {
		return nil, errTwoFactorRequired
	}
```

- [ ] **Step 4: Add TokenPurpose check to validateRefreshToken**

Find `validateRefreshToken` and add after existing checks:

```go
	if claims.TokenPurpose != "" && claims.TokenPurpose != tokenPurposeRefresh {
		return nil, errUnauthorized
	}
```

- [ ] **Step 5: Add generate2FAPendingToken and validate2FAPendingToken**

Add to `service`. Pending token: signs with `accessSecret`, 5-min expiry, `TokenPurpose: tokenPurpose2FAPending`, random `jti` (JWT ID) via `RegisteredClaims.ID`. No `Roles`, `IsRefresh=false`.

Validator: parses JWT with `accessSecret`, checks `TokenPurpose == tokenPurpose2FAPending` and non-empty `ID` (jti).

- [ ] **Step 6: Add generateRandomHex helper**

Uses `crypto/rand`. Add import.

- [ ] **Step 7: Embed EmailVerified and TwoFactorEnabled in access token claims**

To avoid a DB lookup on every authenticated request, add fields to `jwtClaims`:

```go
type jwtClaims struct {
	UserID           string     `json:"user_id"`
	Roles            []UserRole `json:"roles"`
	IsRefresh        bool       `json:"is_refresh"`
	TokenPurpose     string     `json:"purpose,omitempty"`
	EmailVerified    bool       `json:"email_verified,omitempty"`
	TwoFactorEnabled bool       `json:"two_factor_enabled,omitempty"`
	jwt.RegisteredClaims
}
```

Update `generateToken` to populate these from the User struct. Update `WithAuth` middleware to extract these from claims and set them in the request context using `EmailVerifiedContextKey{}` and `TwoFactorEnabledContextKey{}`.

**Trade-off:** These values are snapshotted at token creation time. If a user verifies email or enables 2FA, the change only appears in new tokens (after next refresh). This is acceptable — same as roles, which are already embedded in access tokens.

- [ ] **Step 8: Run tests**

Run: `go test -v -race -count=1 .`
Expected: All existing tests PASS (backward compat: empty TokenPurpose accepted)

- [ ] **Step 9: Commit**

```bash
git add auth.go
git commit -m "feat(auth): add TokenPurpose and user flags to JWT claims"
```

---

## Task 3: Configuration — EmailConfig, OAuthConfig, TwoFactorConfig

**Files:**
- Create: `options_email.go`, `options_oauth.go`, `options_2fa.go`
- Modify: `options_core.go`

- [ ] **Step 1: Add sub-structs to AuthConfig**

In `options_core.go`, add three fields to `AuthConfig` after `NotRegisterRoutes bool` (line 758) and before the internal `accessSecret`/`refreshSecret` fields:

```go
	Email     EmailConfig
	OAuth     OAuthConfig
	TwoFactor TwoFactorConfig
```

- [ ] **Step 2: Create options_email.go**

Define `EmailConfig` and `SMTPConfig` structs (see spec §4). Implement With* functions following the pattern in `options_auth.go`: each returns `Option` (closure that modifies `serverOptions`). `WithEmailSender`, `WithEmailSMTP`, `WithEmailRequireVerification`, `WithEmailTokenDurations`, `WithEmailResendCooldown`, `WithEmailConfig`.

- [ ] **Step 3: Create options_oauth.go**

Define `OAuthConfig` and all 5 provider config structs (Google, GitHub, Apple with TeamID/KeyID/PrivateKey, Telegram with BotToken, Yandex). Add internal `stateSigningKey []byte` field. Implement all With* functions. `WithOAuth`, `WithOAuthGoogle`, `WithOAuthGitHub`, `WithOAuthApple`, `WithOAuthTelegram`, `WithOAuthYandex`, `WithOAuthAutoLink`, `WithOAuthBasePath`, `WithOAuthStateSigningKey`, `WithOAuthConfig`.

- [ ] **Step 4: Create options_2fa.go**

Define `TwoFactorConfig` with internal `encryptionKey []byte` field. Implement `WithTwoFactor`, `WithTwoFactorIssuer`, `WithTwoFactorEmailFallback`, `WithTwoFactorBackupCodes`, `WithTwoFactorCodeDuration`, `WithTwoFactorMaxAttempts`, `WithTwoFactorConfig`.

- [ ] **Step 5: Verify build**

Run: `go build ./...`
Expected: Compiles

- [ ] **Step 6: Commit**

```bash
git add options_email.go options_oauth.go options_2fa.go options_core.go
git commit -m "feat(auth): add EmailConfig, OAuthConfig, TwoFactorConfig with With* options"
```

---

## Task 4: Config YAML — Parsing New Sub-Structs

**Files:**
- Modify: `config.go`

- [ ] **Step 1: Add YAML config sub-structs**

After `AuthConfiguration` (line 146), add: `EmailConfiguration`, `SMTPConfiguration`, `OAuthConfiguration`, `GoogleOAuthConfiguration`, `GitHubOAuthConfiguration`, `AppleOAuthConfiguration`, `TelegramOAuthConfiguration`, `YandexOAuthConfiguration`, `TwoFactorConfiguration`. Each with YAML/JSON/env tags.

- [ ] **Step 2: Add sub-struct fields to AuthConfiguration**

Add to `AuthConfiguration` struct. **Keep all existing fields** (Enabled, JWTAccessSecret, JWTRefreshSecret, etc. including UseMemoryDatabase). Add:

```go
	Email     EmailConfiguration     `yaml:"email" json:"email"`
	OAuth     OAuthConfiguration     `yaml:"oauth" json:"oauth"`
	TwoFactor TwoFactorConfiguration `yaml:"two_factor" json:"two_factor"`
```

- [ ] **Step 3: Add config-to-options mapping**

In the auth config section (after line 402), add mapping for email (SMTP config, RequireVerification, durations, cooldown), OAuth (StateSigningKey, provider configs), and 2FA (EncryptionKey, issuer, etc.).

- [ ] **Step 4: Verify build**

Run: `go build ./...`
Expected: Compiles

- [ ] **Step 5: Commit**

```bash
git add config.go
git commit -m "feat(auth): add YAML config parsing for email, OAuth, and 2FA"
```

---

## Task 5: Email System — Interface, SMTP, Verification, Password Reset

**Files:**
- Create: `auth_email.go`, `auth_email_test.go`
- Modify: `auth.go` (RegisterRoutes, NewAuthManager validation)

- [ ] **Step 1: Write failing tests**

Create `auth_email_test.go` with `MockEmailSender` and table-driven tests:
- `TestVerifyEmailHandler` — valid token, expired token, invalid token
- `TestResendVerificationHandler` — success, cooldown 429
- `TestForgotPasswordHandler` — success (always 200), user not found (still 200)
- `TestResetPasswordHandler` — valid token + new password, expired token, invalid token
- `TestRegistrationWithEmail` — register with email sends verification
- `TestRequireVerificationBlocksTokens` — RequireVerification=true returns 201 without tokens

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run "TestVerifyEmail|TestResend|TestForgotPassword|TestResetPassword|TestRegistration|TestRequireVerification" .`
Expected: FAIL (compilation errors, functions don't exist)

- [ ] **Step 3: Implement auth_email.go**

Create with:
1. `EmailSender` interface (3 methods)
2. `EmailAuthDatabase` sub-interface (`FindByEmail`)
3. `SMTPEmailSender` using `net/smtp` stdlib
4. `ForgotPasswordRequest`, `ResetPasswordRequest` structs with Validate()
5. Token helpers: `generateEmailToken()` → random 32 bytes hex, bcrypt hash, returns (rawToken, hash)
6. Handlers: `VerifyEmailHandler`, `ResendVerificationHandler`, `ForgotPasswordHandler`, `ResetPasswordHandler`
7. Service methods called by handlers

Key details:
- Reset token format: `userID:randomHex` — handler extracts userID, loads user, bcrypt-compares
- `ForgotPasswordHandler` always returns 200 (timing-safe)
- `ResendVerificationHandler` requires Bearer auth, checks `EmailVerifyLastSentAt` + `ResendCooldown`

- [ ] **Step 4: Add email routes to RegisterRoutes**

In `auth.go` `RegisterRoutes` (line 159-173), add inside the function after existing routes:

```go
	if h.service.cfg.Email.Enabled {
		rr.HandleFunc("/verify-email", h.VerifyEmailHandler).Methods(http.MethodPost)
		rr.HandleFunc("/resend-verification", h.WithAuth(h.ResendVerificationHandler)).Methods(http.MethodPost)
		rr.HandleFunc("/forgot-password", h.ForgotPasswordHandler).Methods(http.MethodPost)
		rr.HandleFunc("/reset-password", h.ResetPasswordHandler).Methods(http.MethodPost)
	}
```

- [ ] **Step 5: Add sub-interface validation to NewAuthManager**

In `NewAuthManager` (line 104), add after existing secret validation:

```go
	if cfg.Email.Enabled {
		if _, ok := cfg.Database.(EmailAuthDatabase); !ok {
			return nil, errors.New("email auth requires AuthDatabase to implement EmailAuthDatabase")
		}
		cfg.Email.VerifyTokenDuration = lang.Check(cfg.Email.VerifyTokenDuration, 24*time.Hour)
		cfg.Email.ResetTokenDuration = lang.Check(cfg.Email.ResetTokenDuration, time.Hour)
		cfg.Email.ResendCooldown = lang.Check(cfg.Email.ResendCooldown, 60*time.Second)
		if cfg.Email.Sender == nil && cfg.Email.SMTP != nil {
			cfg.Email.Sender = NewSMTPEmailSender(*cfg.Email.SMTP)
		}
	}
```

- [ ] **Step 6: Run tests**

Run: `go test -v -race -count=1 -run "TestVerifyEmail|TestResend|TestForgotPassword|TestResetPassword|TestRegistration|TestRequireVerification" .`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add auth_email.go auth_email_test.go auth.go
git commit -m "feat(auth): add email verification and password reset with SMTP support"
```

---

## Task 6: Modify Registration and Login — Email + 2FA Integration

**Files:**
- Modify: `auth.go` (RegisterHandler, LoginHandler, service.register, service.login)
- Modify: `auth_email_test.go`

- [ ] **Step 1: Write failing tests**

Add to `auth_email_test.go`:
- `TestRegisterWithEmailSendsVerification` — registration with email field triggers verification email
- `TestRegisterRequireVerificationNoTokens` — RequireVerification=true → 201 with message, no accessToken

- [ ] **Step 2: Update RegisterHandler to use RegisterRequest**

In `RegisterHandler` (line 235): change `UserLoginRequest` to `RegisterRequest`. After `service.register`, if email config enabled and email provided, generate verification token, store via `UpdateUser`, send via `EmailSender`.

If `RequireVerification=true`, return `201` with `{message: "check your email to verify your account"}` instead of tokens.

- [ ] **Step 3: Update LoginHandler for 2FA**

In `LoginHandler` (line 266): after successful `service.login`, check if user has `TwoFactorEnabled=true` AND `TwoFactor.Enabled` in config. If so, generate 2FA pending token via `generate2FAPendingToken`, return `200` with `{twoFactorToken: "..."}` — do NOT set auth cookie or return access token.

- [ ] **Step 4: Run tests**

Run: `go test -v -race -count=1 .`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add auth.go auth_email_test.go
git commit -m "feat(auth): integrate email verification into registration and 2FA check into login"
```

---

## Task 7: OAuth — Provider Interface, State, Handlers

**Files:**
- Create: `auth_oauth.go`, `auth_oauth_test.go`
- Modify: `auth.go` (RegisterRoutes, NewAuthManager)

- [ ] **Step 1: Add dependency check**

Run: `go build ./...` — ensure everything compiles cleanly before starting OAuth.

- [ ] **Step 2: Write failing tests**

Create `auth_oauth_test.go` with `MockOAuthProvider` and tests:
- `TestOAuthRedirectHandler` — redirects to provider URL with state cookie
- `TestOAuthCallbackHandler` — exchanges code, creates user, returns tokens
- `TestOAuthCallbackAutoLink` — auto-links by verified email
- `TestOAuthCallbackAutoLinkRefusedUnverified` — refuses link when local email not verified
- `TestOAuthCallbackWith2FA` — returns redirect with twoFactorToken query param (NOT JSON)
- `TestOAuthStateHMACValidation` — rejects tampered state
- `TestOAuthLinkHandler` — links provider to authenticated user
- `TestOAuthUnlinkHandler` — unlinks provider

- [ ] **Step 3: Implement auth_oauth.go**

Create with:
1. `OAuthProvider` interface and `OAuthUserInfo` struct
2. `OAuthAuthDatabase` sub-interface (`FindByOAuthProvider`)
3. HMAC state: `generateOAuthState(signingKey []byte) (state, mac string)`, `validateOAuthState(state, mac string, signingKey []byte) bool`
4. Cookie helpers: `setOAuthStateCookie`, `getAndDeleteOAuthStateCookie` — cookie name `_servex_oauth_state`, Max-Age=600, HttpOnly, SameSite=Lax, Secure
5. `OAuthRedirectHandler`: find provider by `mux.Vars(r)["provider"]`, generate state, set cookie, `http.Redirect`
6. `OAuthCallbackHandler`: validate state HMAC, call `provider.Exchange(code)`, user lookup/create/link per spec §6, issue tokens. **When user has 2FA enabled**: redirect to frontend 2FA page with `twoFactorToken` as query parameter (NOT JSON response — this is a browser redirect flow)
7. `OAuthLinkHandler`: authenticated, link provider
8. `OAuthUnlinkHandler`: authenticated, unlink provider

**OAuth + RequireVerification:** When creating new user via OAuth with `OAuthUserInfo.Verified=true`, set `EmailVerified=true` — satisfies RequireVerification. When `Verified=false` and `RequireVerification=true`, do NOT issue tokens.

- [ ] **Step 4: Add OAuth routes to RegisterRoutes**

In `auth.go` `RegisterRoutes`, add:

```go
	if h.service.cfg.OAuth.Enabled {
		rr.HandleFunc("/oauth/{provider}", h.OAuthRedirectHandler).Methods(http.MethodGet)
		rr.HandleFunc("/oauth/{provider}/callback", h.OAuthCallbackHandler).Methods(http.MethodGet)
		rr.HandleFunc("/oauth/{provider}/link", h.WithAuth(h.OAuthLinkHandler)).Methods(http.MethodPost)
		rr.HandleFunc("/oauth/{provider}/link", h.WithAuth(h.OAuthUnlinkHandler)).Methods(http.MethodDelete)
	}
```

- [ ] **Step 5: Add OAuth validation to NewAuthManager**

```go
	if cfg.OAuth.Enabled {
		if _, ok := cfg.Database.(OAuthAuthDatabase); !ok {
			return nil, errors.New("OAuth auth requires AuthDatabase to implement OAuthAuthDatabase")
		}
		cfg.OAuth.BasePath = lang.Check(cfg.OAuth.BasePath, "/oauth")
		// Decode StateSigningKey from hex, validate >= 32 bytes
		// Build providers from convenience configs (Google, GitHub, etc.)
	}
```

- [ ] **Step 6: Run tests**

Run: `go test -v -race -count=1 -run TestOAuth .`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add auth_oauth.go auth_oauth_test.go auth.go
git commit -m "feat(auth): add OAuth flow with state HMAC, auto-link, and link/unlink handlers"
```

---

## Task 8: OAuth Providers — Google, GitHub, Apple, Telegram, Yandex

**Files:**
- Create: `auth_oauth_providers.go`, `auth_oauth_providers_test.go`

- [ ] **Step 1: Write failing tests for provider implementations**

Create `auth_oauth_providers_test.go`:
- `TestAppleGenerateClientSecret` — generates valid ES256 JWT
- `TestGoogleAuthURL` — returns correct URL with scopes and state
- `TestTelegramDataVerification` — validates bot token hash check
- `TestProviderNames` — each provider returns correct Name()

- [ ] **Step 2: Implement GoogleOAuthProvider**

```go
func (p *GoogleOAuthProvider) Name() string { return "google" }
func (p *GoogleOAuthProvider) AuthURL(state string) string { /* Google OAuth2 URL */ }
func (p *GoogleOAuthProvider) Exchange(ctx context.Context, code string) (*OAuthUserInfo, error) {
	// POST https://oauth2.googleapis.com/token
	// GET https://www.googleapis.com/oauth2/v2/userinfo
}
```

- [ ] **Step 3: Implement GitHubOAuthProvider**

POST `https://github.com/login/oauth/access_token`, GET `https://api.github.com/user` + `https://api.github.com/user/emails`.

- [ ] **Step 4: Implement AppleOAuthProvider**

Apple requires JWT-based client secret: `generateClientSecret()` creates ES256-signed JWT with `iss=TeamID`, `sub=ClientID`, `aud="https://appleid.apple.com"`, `kid` header from `KeyID`. Exchange at `https://appleid.apple.com/auth/token`.

- [ ] **Step 5: Implement TelegramOAuthProvider**

Telegram uses bot-based widget auth. Verify callback data with `sha256(data-check-string, sha256(bot_token))`.

- [ ] **Step 6: Implement YandexOAuthProvider**

POST `https://oauth.yandex.ru/token`, GET `https://login.yandex.ru/info`.

- [ ] **Step 7: Run tests**

Run: `go test -v -race -count=1 -run "TestApple|TestGoogle|TestTelegram|TestProvider" .`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add auth_oauth_providers.go auth_oauth_providers_test.go
git commit -m "feat(auth): add Google, GitHub, Apple, Telegram, Yandex OAuth providers"
```

---

## Task 9: 2FA — TOTP, Backup Codes, Attempt Tracking, Encryption

**Files:**
- Create: `auth_2fa.go`, `auth_2fa_test.go`
- Modify: `auth.go` (AuthManager struct, RegisterRoutes, NewAuthManager)
- Modify: `go.mod`

- [ ] **Step 1: Add TOTP dependency**

Run: `go get github.com/pquerna/otp`

This MUST be done first — `auth_2fa.go` imports `github.com/pquerna/otp/totp`.

- [ ] **Step 2: Write failing tests**

Create `auth_2fa_test.go`:
- `TestAESGCMEncryptDecrypt` — round-trip encrypt/decrypt
- `TestAttemptTracker` — increment, getCount, delete, expiry
- `TestAttemptTrackerEmailCooldown` — canSendEmail, markEmailSent
- `TestGenerateBackupCodes` — generates correct count, each is 8 chars
- `TestTwoFactorSetupHandler` — returns TOTP URI + backup codes
- `TestTwoFactorEnableHandler` — verify code enables 2FA
- `TestTwoFactorDisableHandler` — requires valid code
- `TestTwoFactorVerifyHandler` — TOTP code, backup code, email code
- `TestTwoFactorAttemptExhaustion` — max attempts → 401
- `TestTwoFactorPendingTokenRejectedByWithAuth` — pending token → 401 on protected route

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test -v -run TestTwoFactor .`
Expected: FAIL (compilation)

- [ ] **Step 4: Implement AES-256-GCM encryption**

In `auth_2fa.go`: `encryptTOTPSecret(plaintext string, key []byte) (string, error)` and `decryptTOTPSecret(encoded string, key []byte) (string, error)`. Format: `base64(nonce + ciphertext + GCM tag)`.

- [ ] **Step 5: Implement attempt tracker with Stop()**

```go
type attemptTracker struct {
	mu      sync.Mutex
	entries map[string]*attemptEntry
	maxAge  time.Duration
	done    chan struct{} // for clean shutdown
}

type attemptEntry struct {
	count         int
	emailCodeHash string    // bcrypt hash of email 2FA code
	lastEmailSent time.Time
	expiresAt     time.Time
}

func newAttemptTracker() *attemptTracker {
	t := &attemptTracker{
		entries: make(map[string]*attemptEntry),
		maxAge:  5 * time.Minute,
		done:    make(chan struct{}),
	}
	go t.cleanupLoop()
	return t
}

func (t *attemptTracker) Stop() {
	close(t.done)
}

func (t *attemptTracker) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.mu.Lock()
			now := time.Now()
			for jti, entry := range t.entries {
				if now.After(entry.expiresAt) {
					delete(t.entries, jti)
				}
			}
			t.mu.Unlock()
		case <-t.done:
			return
		}
	}
}

func (t *attemptTracker) increment(jti string) int { ... }
func (t *attemptTracker) getCount(jti string) int { ... }
func (t *attemptTracker) delete(jti string) { ... }
func (t *attemptTracker) canSendEmail(jti string, cooldown time.Duration) bool { ... }
func (t *attemptTracker) markEmailSent(jti string, codeHash string) { ... }
func (t *attemptTracker) getEmailCodeHash(jti string) string { ... }
```

- [ ] **Step 6: Implement backup code generation**

`generateBackupCodes(count int) (plainCodes []string, hashedCodes []string, err error)` — 8 random alphanumeric chars each, bcrypt-hashed.

- [ ] **Step 7: Implement TwoFactorSetupHandler**

Generate TOTP key via `totp.Generate()`, encrypt secret with AES-256-GCM, generate backup codes, store encrypted secret + hashed backup codes in user record via `UpdateUser`. Return TOTP provisioning URI + plain backup codes. Does NOT enable 2FA yet.

- [ ] **Step 8: Implement TwoFactorEnableHandler**

Verify TOTP code against stored (decrypted) secret. If valid, set `TwoFactorEnabled=true` via `UpdateUser`.

- [ ] **Step 9: Implement TwoFactorDisableHandler**

Require valid TOTP code (or backup code). Clear `TwoFactorEnabled`, `TwoFactorSecret`, `TwoFactorBackupCodes`.

- [ ] **Step 10: Implement TwoFactorVerifyHandler**

Validate 2FA pending token → check attempt count → try TOTP code → try backup code → try email code hash → if valid, delete tracker entry, issue tokens. If invalid, increment attempt count.

- [ ] **Step 11: Implement TwoFactorSendEmailCodeHandler**

Validate pending token → check email cooldown via `attemptTracker.canSendEmail` → generate 6-digit code → bcrypt hash → store in tracker via `markEmailSent` → send via `EmailSender.SendTwoFactorCodeEmail`. 60s cooldown hardcoded (not configurable per spec).

- [ ] **Step 12: Add attemptTracker to AuthManager**

Update `AuthManager` struct:

```go
type AuthManager struct {
	service        *service
	auditLogger    AuditLogger
	attemptTracker *attemptTracker
}
```

Initialize in `NewAuthManager` when `TwoFactor.Enabled`. Add `Stop()` call or note for cleanup.

- [ ] **Step 13: Add 2FA routes to RegisterRoutes**

```go
	if h.service.cfg.TwoFactor.Enabled {
		rr.HandleFunc("/2fa/setup", h.WithAuth(h.TwoFactorSetupHandler)).Methods(http.MethodPost)
		rr.HandleFunc("/2fa/enable", h.WithAuth(h.TwoFactorEnableHandler)).Methods(http.MethodPost)
		rr.HandleFunc("/2fa/disable", h.WithAuth(h.TwoFactorDisableHandler)).Methods(http.MethodPost)
		rr.HandleFunc("/2fa/verify", h.TwoFactorVerifyHandler).Methods(http.MethodPost)
		if h.service.cfg.TwoFactor.EmailFallback && h.service.cfg.Email.Enabled {
			rr.HandleFunc("/2fa/send-email-code", h.TwoFactorSendEmailCodeHandler).Methods(http.MethodPost)
		}
	}
```

- [ ] **Step 14: Add 2FA validation to NewAuthManager**

Decode encryption key, set defaults for BackupCodes (10), MaxVerifyAttempts (5), CodeDuration (10m), Issuer, EmailFallback (true).

- [ ] **Step 15: Run all tests**

Run: `go test -v -race -count=1 .`
Expected: All PASS

- [ ] **Step 16: Commit**

```bash
git add auth_2fa.go auth_2fa_test.go auth.go go.mod go.sum
git commit -m "feat(auth): add 2FA with TOTP, backup codes, email fallback, and attempt tracking"
```

---

## Task 10: Context Helpers

**Files:**
- Modify: `context_request.go`

- [ ] **Step 1: Add EmailVerified() and TwoFactorEnabled()**

```go
func (ctx *Context) EmailVerified() bool {
	return getValueFromContext[bool](ctx.r, EmailVerifiedContextKey{})
}

func (ctx *Context) TwoFactorEnabled() bool {
	return getValueFromContext[bool](ctx.r, TwoFactorEnabledContextKey{})
}
```

These read from context keys set by `WithAuth` middleware (wired in Task 2 Step 7).

- [ ] **Step 2: Run tests**

Run: `go test -v -race -count=1 .`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add context_request.go
git commit -m "feat(auth): add EmailVerified() and TwoFactorEnabled() context helpers"
```

---

## Task 11: Integration Tests — Cross-Feature Flows

**Files:**
- Modify: `auth_2fa_test.go`, `auth_email_test.go`, `auth_oauth_test.go`

- [ ] **Step 1: Add cross-feature tests**

In `auth_2fa_test.go`:
```go
func TestLoginWith2FA_FullFlow(t *testing.T) {
	// Register → Setup 2FA → Enable → Login → Pending token → Verify → Access token
}
func TestOAuthLoginWith2FA(t *testing.T) {
	// Create user with 2FA → OAuth callback → Redirect with pending token → Verify → Tokens
}
```

In `auth_email_test.go`:
```go
func TestRequireVerificationThenVerifyThenLogin(t *testing.T) {
	// Register with RequireVerification=true → No tokens → Verify → Login → Tokens
}
func TestOAuthWithRequireVerification(t *testing.T) {
	// OAuth Verified=true → Tokens immediately
	// OAuth Verified=false, RequireVerification=true → No tokens
}
```

In `auth_oauth_test.go`:
```go
func TestOAuthAutoLinkCollision(t *testing.T) {
	// Two providers same email → first-link wins
}
```

- [ ] **Step 2: Run full test suite**

Run: `go test -v -race -count=1 .`
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
git add auth_2fa_test.go auth_email_test.go auth_oauth_test.go
git commit -m "test(auth): add cross-feature integration tests for email, OAuth, and 2FA"
```

---

## Task 12: Final Verification

- [ ] **Step 1: Run full test suite with coverage**

Run: `make test`
Expected: All tests PASS

- [ ] **Step 2: Run build**

Run: `make build`
Expected: Binary builds

- [ ] **Step 3: Run go vet**

Run: `go vet ./...`
Expected: No issues

- [ ] **Step 4: Tidy modules**

Run: `make mod-tidy`
Expected: No changes (or minimal cleanup)

- [ ] **Step 5: Final commit if needed**

```bash
git add -A
git commit -m "chore(auth): final cleanup for auth expansion"
```
