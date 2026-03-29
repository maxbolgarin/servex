package servex

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/maxbolgarin/lang"
	"golang.org/x/crypto/bcrypt"
)

// AuthDatabase defines the interface for interacting with the user database.
type AuthDatabase interface {
	// NewUser creates a new user in the database.
	NewUser(ctx context.Context, username string, passwordHash string, roles ...UserRole) (string, error)

	// FindByID finds a user by their ID.
	FindByID(ctx context.Context, id string) (user User, exists bool, err error)
	// FindByUsername finds a user by their username.
	FindByUsername(ctx context.Context, username string) (user User, exists bool, err error)
	// FindAll retrieves all users from the database.
	FindAll(ctx context.Context) ([]User, error)

	// UpdateUser updates a user's information in the database.
	// Fields are updated only if the corresponding pointers are not nil.
	UpdateUser(ctx context.Context, id string, diff *UserDiff) error
}

// UserRole represents a role assigned to a user.
// It's defined as a string type for easy JSON marshaling/unmarshaling.
type UserRole string

// User represents a user entity in the system.
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

// OAuthLink represents a linked OAuth provider for a user.
type OAuthLink struct {
	Provider   string `json:"provider" bson:"provider" db:"provider"`
	ProviderID string `json:"provider_id" bson:"provider_id" db:"provider_id"`
	Email      string `json:"email,omitempty" bson:"email,omitempty" db:"email"`
}

type UserDiff struct {
	Username              *string     `json:"username,omitempty" bson:"username,omitempty" db:"username,omitempty"`
	Roles                 *[]UserRole `json:"roles,omitempty" bson:"roles,omitempty" db:"roles,omitempty"`
	PasswordHash          *string     `json:"password_hash,omitempty" bson:"password_hash,omitempty" db:"password_hash,omitempty"`
	RefreshTokenHash      *string     `json:"refresh_token_hash,omitempty" bson:"refresh_token_hash,omitempty" db:"refresh_token_hash,omitempty"`
	RefreshTokenExpiresAt *time.Time  `json:"refresh_token_expires_at,omitempty" bson:"refresh_token_expires_at,omitempty" db:"refresh_token_expires_at,omitempty"`

	// Email
	Email         *string `json:"email,omitempty" bson:"email,omitempty" db:"email,omitempty"`
	EmailVerified *bool   `json:"email_verified,omitempty" bson:"email_verified,omitempty" db:"email_verified,omitempty"`

	// Email verification
	EmailVerifyTokenHash      *string    `json:"email_verify_token_hash,omitempty" bson:"email_verify_token_hash,omitempty" db:"email_verify_token_hash,omitempty"`
	EmailVerifyTokenExpiresAt *time.Time `json:"email_verify_token_expires_at,omitempty" bson:"email_verify_token_expires_at,omitempty" db:"email_verify_token_expires_at,omitempty"`
	EmailVerifyLastSentAt     *time.Time `json:"email_verify_last_sent_at,omitempty" bson:"email_verify_last_sent_at,omitempty" db:"email_verify_last_sent_at,omitempty"`

	// Password reset
	PasswordResetTokenHash      *string    `json:"password_reset_token_hash,omitempty" bson:"password_reset_token_hash,omitempty" db:"password_reset_token_hash,omitempty"`
	PasswordResetTokenExpiresAt *time.Time `json:"password_reset_token_expires_at,omitempty" bson:"password_reset_token_expires_at,omitempty" db:"password_reset_token_expires_at,omitempty"`

	// OAuth
	OAuthProviders *[]OAuthLink `json:"oauth_providers,omitempty" bson:"oauth_providers,omitempty" db:"oauth_providers,omitempty"`

	// 2FA
	TwoFactorEnabled     *bool     `json:"two_factor_enabled,omitempty" bson:"two_factor_enabled,omitempty" db:"two_factor_enabled,omitempty"`
	TwoFactorSecret      *string   `json:"two_factor_secret,omitempty" bson:"two_factor_secret,omitempty" db:"two_factor_secret,omitempty"`
	TwoFactorBackupCodes *[]string `json:"two_factor_backup_codes,omitempty" bson:"two_factor_backup_codes,omitempty" db:"two_factor_backup_codes,omitempty"`
}

const (
	IDDBField                    = "id"
	IDDBBsonField                = "_id"
	UsernameDBField              = "username"
	RolesDBField                 = "roles"
	PasswordHashDBField          = "password_hash"
	RefreshTokenHashDBField      = "refresh_token_hash"
	RefreshTokenExpiresAtDBField = "refresh_token_expires_at"

	EmailDBField                      = "email"
	EmailVerifiedDBField              = "email_verified"
	EmailVerifyTokenHashDBField       = "email_verify_token_hash"
	EmailVerifyTokenExpiresAtDBField  = "email_verify_token_expires_at"
	EmailVerifyLastSentAtDBField      = "email_verify_last_sent_at"
	PasswordResetTokenHashDBField     = "password_reset_token_hash"
	PasswordResetTokenExpiresAtDBField = "password_reset_token_expires_at"
	OAuthProvidersDBField             = "oauth_providers"
	TwoFactorEnabledDBField           = "two_factor_enabled"
	TwoFactorSecretDBField            = "two_factor_secret"
	TwoFactorBackupCodesDBField       = "two_factor_backup_codes"
)

// UserLoginRequest represents the request body for user login and registration.
type UserLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// RegisterRequest represents the request body for user registration with optional email.
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

// UserUpdateRequest represents the request body for updating user information.
type UserUpdateRequest struct {
	ID       string      `json:"id"`
	Username *string     `json:"username,omitempty"`
	Roles    *[]UserRole `json:"roles,omitempty"`
	Password *string     `json:"password,omitempty"`
}

// UserLoginResponse represents the response body for successful user login or registration.
type UserLoginResponse struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Roles       []UserRole `json:"roles"`
	AccessToken string     `json:"accessToken,omitempty"`
}

// AuthManager handles authentication and authorization logic.
type AuthManager struct {
	service        *service
	auditLogger    AuditLogger
	attemptTracker *attemptTracker
}

type (
	UserContextKey             struct{}
	RoleContextKey             struct{}
	EmailVerifiedContextKey    struct{}
	TwoFactorEnabledContextKey struct{}
)

// NewAuthManager creates a new [AuthManager] with the provided configuration.
// It initializes default values for configuration fields if they are not provided.
func NewAuthManager(cfg AuthConfig, auditLogger ...AuditLogger) (*AuthManager, error) {
	if cfg.JWTAccessSecret == "" {
		return nil, errors.New("JWT access secret is required")
	}

	if cfg.JWTRefreshSecret == "" {
		return nil, errors.New("JWT refresh secret is required")
	}

	accessSecret, err := hex.DecodeString(cfg.JWTAccessSecret)
	if err != nil {
		return nil, fmt.Errorf("decode access secret: %w", err)
	}
	if len(accessSecret) < minSecretKeyLength {
		return nil, fmt.Errorf("JWT access secret must be at least %d bytes (%d hex characters)", minSecretKeyLength, minSecretKeyLength*2)
	}
	cfg.accessSecret = accessSecret

	refreshSecret, err := hex.DecodeString(cfg.JWTRefreshSecret)
	if err != nil {
		return nil, fmt.Errorf("decode refresh secret: %w", err)
	}
	if len(refreshSecret) < minSecretKeyLength {
		return nil, fmt.Errorf("JWT refresh secret must be at least %d bytes (%d hex characters)", minSecretKeyLength, minSecretKeyLength*2)
	}
	cfg.refreshSecret = refreshSecret

	cfg.RefreshTokenCookieName = lang.Check(cfg.RefreshTokenCookieName, refreshTokenCookieName)
	cfg.AuthBasePath = lang.Check(cfg.AuthBasePath, authBasePath)
	cfg.AccessTokenDuration = lang.Check(cfg.AccessTokenDuration, accessTokenDuration)
	cfg.RefreshTokenDuration = lang.Check(cfg.RefreshTokenDuration, refreshTokenDuration)
	cfg.IssuerNameInJWT = lang.Check(cfg.IssuerNameInJWT, "servex")
	cfg.MinPasswordLength = lang.Check(cfg.MinPasswordLength, defaultMinPasswordLength)

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

	if cfg.OAuth.Enabled {
		if _, ok := cfg.Database.(OAuthAuthDatabase); !ok {
			return nil, errors.New("OAuth auth requires AuthDatabase to implement OAuthAuthDatabase")
		}
		cfg.OAuth.BasePath = lang.Check(cfg.OAuth.BasePath, "/oauth")
		if cfg.OAuth.StateSigningKey != "" {
			stateKey, err := hex.DecodeString(cfg.OAuth.StateSigningKey)
			if err != nil {
				return nil, fmt.Errorf("decode OAuth state signing key: %w", err)
			}
			if len(stateKey) < 32 {
				return nil, fmt.Errorf("OAuth state signing key must be at least 32 bytes")
			}
			cfg.OAuth.stateSigningKey = stateKey
		}
		// If no explicit state signing key, generate a random one
		if len(cfg.OAuth.stateSigningKey) == 0 {
			key := make([]byte, 32)
			if _, err := crand.Read(key); err != nil {
				return nil, fmt.Errorf("generate OAuth state signing key: %w", err)
			}
			cfg.OAuth.stateSigningKey = key
		}

		// Build providers from convenience configs
		if cfg.OAuth.Google != nil {
			cfg.OAuth.Providers = append(cfg.OAuth.Providers, NewGoogleOAuthProvider(*cfg.OAuth.Google))
		}
		if cfg.OAuth.GitHub != nil {
			cfg.OAuth.Providers = append(cfg.OAuth.Providers, NewGitHubOAuthProvider(*cfg.OAuth.GitHub))
		}
		if cfg.OAuth.Apple != nil {
			cfg.OAuth.Providers = append(cfg.OAuth.Providers, NewAppleOAuthProvider(*cfg.OAuth.Apple))
		}
		if cfg.OAuth.Telegram != nil {
			cfg.OAuth.Providers = append(cfg.OAuth.Providers, NewTelegramOAuthProvider(*cfg.OAuth.Telegram))
		}
		if cfg.OAuth.Yandex != nil {
			cfg.OAuth.Providers = append(cfg.OAuth.Providers, NewYandexOAuthProvider(*cfg.OAuth.Yandex))
		}
	}

	if cfg.TwoFactor.Enabled {
		if cfg.TwoFactor.EncryptionKey == "" {
			return nil, errors.New("2FA encryption key is required")
		}
		encKey, err := hex.DecodeString(cfg.TwoFactor.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("decode 2FA encryption key: %w", err)
		}
		if len(encKey) != 32 {
			return nil, fmt.Errorf("2FA encryption key must be exactly 32 bytes (64 hex characters)")
		}
		cfg.TwoFactor.encryptionKey = encKey
		cfg.TwoFactor.BackupCodes = lang.Check(cfg.TwoFactor.BackupCodes, 10)
		cfg.TwoFactor.MaxVerifyAttempts = lang.Check(cfg.TwoFactor.MaxVerifyAttempts, 5)
		cfg.TwoFactor.CodeDuration = lang.Check(cfg.TwoFactor.CodeDuration, 10*time.Minute)
		cfg.TwoFactor.Issuer = lang.Check(cfg.TwoFactor.Issuer, "servex")
		digits := lang.Check(cfg.TwoFactor.EmailCodeDigits, 6)
		if digits < 1 || digits > 32 {
			return nil, errors.New("2FA email code digits must be between 1 and 32")
		}
		cfg.TwoFactor.EmailCodeDigits = digits
	}

	// Get audit logger (optional parameter)
	var audit AuditLogger = &NoopAuditLogger{}
	if len(auditLogger) > 0 && auditLogger[0] != nil {
		audit = auditLogger[0]
	}

	authManager := &AuthManager{
		service:     newService(cfg),
		auditLogger: audit,
	}

	if cfg.TwoFactor.Enabled {
		authManager.attemptTracker = newAttemptTracker()
	}

	return authManager, nil
}

// RegisterRoutes registers the authentication-related HTTP routes on the provided router.
// It registers the following routes:
// - /register - POST - Register a new user
// - /login - POST - Login a user
// - /refresh - POST - Refresh an access token
// - /logout - POST - Logout a user
// - /me - GET - Get the current user
func (h *AuthManager) RegisterRoutes(r *mux.Router) {
	rr := r.PathPrefix(h.service.cfg.AuthBasePath).Subrouter()
	{
		// Public routes
		rr.HandleFunc("/register", h.RegisterHandler).Methods(http.MethodPost)
		rr.HandleFunc("/login", h.LoginHandler).Methods(http.MethodPost)
		rr.HandleFunc("/refresh", h.RefreshHandler).Methods(http.MethodPost)
		rr.HandleFunc("/logout", h.LogoutHandler).Methods(http.MethodPost)
		rr.HandleFunc("/me", h.WithAuth(h.GetCurrentUserHandler)).Methods(http.MethodGet)

		// Email verification and password reset routes
		if h.service.cfg.Email.Enabled {
			rr.HandleFunc("/verify-email", h.VerifyEmailHandler).Methods(http.MethodPost)
			rr.HandleFunc("/resend-verification", h.WithAuth(h.ResendVerificationHandler)).Methods(http.MethodPost)
			rr.HandleFunc("/forgot-password", h.ForgotPasswordHandler).Methods(http.MethodPost)
			rr.HandleFunc("/reset-password", h.ResetPasswordHandler).Methods(http.MethodPost)
		}

		// OAuth routes
		if h.service.cfg.OAuth.Enabled {
			oauthBase := lang.Check(h.service.cfg.OAuth.BasePath, "/oauth")
			rr.HandleFunc(oauthBase+"/{provider}", h.OAuthRedirectHandler).Methods(http.MethodGet)
			rr.HandleFunc(oauthBase+"/{provider}/callback", h.OAuthCallbackHandler).Methods(http.MethodGet)
			rr.HandleFunc(oauthBase+"/{provider}/link", h.WithAuth(h.OAuthLinkHandler)).Methods(http.MethodPost)
			rr.HandleFunc(oauthBase+"/{provider}/link", h.WithAuth(h.OAuthUnlinkHandler)).Methods(http.MethodDelete)
		}

		// 2FA routes
		if h.service.cfg.TwoFactor.Enabled {
			rr.HandleFunc("/2fa/setup", h.WithAuth(h.TwoFactorSetupHandler)).Methods(http.MethodPost)
			rr.HandleFunc("/2fa/enable", h.WithAuth(h.TwoFactorEnableHandler)).Methods(http.MethodPost)
			rr.HandleFunc("/2fa/disable", h.WithAuth(h.TwoFactorDisableHandler)).Methods(http.MethodPost)
			rr.HandleFunc("/2fa/verify", h.TwoFactorVerifyHandler).Methods(http.MethodPost)
			if h.service.cfg.TwoFactor.EmailFallback && h.service.cfg.Email.Enabled {
				rr.HandleFunc("/2fa/send-email-code", h.TwoFactorSendEmailCodeHandler).Methods(http.MethodPost)
			}
		}

		// This roles should be set with custom roles by library user
		// rr.HandleFunc("/users", h.WithAuth(h.GetAllUsers)).Methods(http.MethodGet)
		// rr.HandleFunc("/users/role", h.WithAuth(h.UpdateUserRole)).Methods(http.MethodPut)
	}
}

// WithAuth is an HTTP middleware that enforces authentication and authorization.
// It checks for a valid JWT access token in the Authorization header.
// If roles are provided, it verifies that the authenticated user has at least one of the required roles.
// The user ID and roles are added to the request context.
func (m *AuthManager) WithAuth(next http.HandlerFunc, roles ...UserRole) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := NewContext(w, r)

		// Extract token from Authorization header
		tokenString := extractToken(r)
		if tokenString == "" {
			// Log unauthorized access attempt
			if m.auditLogger != nil {
				details := map[string]any{
					"reason": "missing_token",
				}
				m.auditLogger.LogAuthenticationEvent(AuditEventAuthUnauthorized, r, "", false, details)
			}
			ctx.Unauthorized(errUnauthorized, "missing or invalid authorization token")
			return
		}

		claims, err := m.service.validateAccessToken(tokenString)
		if err != nil {
			// Log invalid token attempt
			if m.auditLogger != nil {
				details := map[string]any{
					"reason": "invalid_token",
					"error":  err.Error(),
				}
				m.auditLogger.LogAuthenticationEvent(AuditEventAuthTokenInvalid, r, "", false, details)
			}
			ctx.Unauthorized(err, "invalid token")
			return
		}

		if !hasPermission(claims.Roles, roles) {
			// Log insufficient permissions
			if m.auditLogger != nil {
				details := map[string]any{
					"reason":         "insufficient_permissions",
					"user_roles":     claims.Roles,
					"required_roles": roles,
				}
				m.auditLogger.LogAuthenticationEvent(AuditEventAuthForbidden, r, claims.UserID, false, details)
			}
			ctx.Forbidden(errInsufficientPermissions, "insufficient permissions")
			return
		}

		reqWithContext := r.WithContext(context.WithValue(r.Context(), UserContextKey{}, claims.UserID))
		reqWithContext = reqWithContext.WithContext(context.WithValue(reqWithContext.Context(), RoleContextKey{}, claims.Roles))
		reqWithContext = reqWithContext.WithContext(context.WithValue(reqWithContext.Context(), EmailVerifiedContextKey{}, claims.EmailVerified))
		reqWithContext = reqWithContext.WithContext(context.WithValue(reqWithContext.Context(), TwoFactorEnabledContextKey{}, claims.TwoFactorEnabled))

		next(w, reqWithContext)
	}
}

// RegisterHandler handles the HTTP request for user registration.
// It reads the request body, validates it, and registers a new user.
// If email config is enabled and an email is provided, it sends a verification email.
// If RequireVerification is true, no tokens are returned until the email is verified.
func (h *AuthManager) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	var req RegisterRequest
	if err := ctx.ReadAndValidate(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	// Register user
	result, err := h.service.register(r.Context(), req)
	if err != nil {
		switch err {
		case errPasswordTooShort:
			ctx.BadRequest(err, fmt.Sprintf("password must be at least %d characters", h.service.cfg.MinPasswordLength))
		case errUsernameAlreadyExists:
			ctx.Conflict(err, err.Error())
		default:
			ctx.InternalServerError(err, "failed to register user")
		}
		return
	}

	// Handle email verification if email config is enabled and email was provided
	if h.service.cfg.Email.Enabled && req.Email != "" {
		rawToken, tokenHash, err := generateEmailToken(result.ID)
		if err != nil {
			ctx.InternalServerError(err, "failed to generate verification token")
			return
		}

		now := time.Now()
		expiresAt := now.Add(h.service.cfg.Email.VerifyTokenDuration)

		if err := h.service.db.UpdateUser(r.Context(), result.ID, &UserDiff{
			Email:                     &req.Email,
			EmailVerifyTokenHash:      lang.Ptr(tokenHash),
			EmailVerifyTokenExpiresAt: lang.Ptr(expiresAt),
			EmailVerifyLastSentAt:     lang.Ptr(now),
		}); err != nil {
			ctx.InternalServerError(err, "failed to store email verification token")
			return
		}

		if h.service.cfg.Email.Sender != nil {
			if err := h.service.cfg.Email.Sender.SendVerificationEmail(r.Context(), req.Email, rawToken); err != nil {
				ctx.InternalServerError(err, "failed to send verification email")
				return
			}
		}

		// If verification is required, return message without tokens
		if h.service.cfg.Email.RequireVerification {
			ctx.Response(http.StatusCreated, map[string]string{"message": "check your email to verify your account"})
			return
		}
	}

	h.setAuthCookie(ctx, result.RefreshToken, result.RefreshTokenExpiresAt)

	ctx.Response(http.StatusCreated, result.UserLoginResponse)
}

// LoginHandler handles the HTTP request for user login.
// It reads the request body, validates it, and logs the user in.
// It sets the auth cookie and returns the user login response.
func (h *AuthManager) LoginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	var req UserLoginRequest
	if err := ctx.ReadAndValidate(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	result, err := h.service.login(r.Context(), req)
	if err != nil {
		// Log failed login attempt
		if h.auditLogger != nil {
			details := map[string]any{
				"username": req.Username,
				"error":    err.Error(),
			}
			h.auditLogger.LogAuthenticationEvent(AuditEventAuthLoginFailure, r, req.Username, false, details)
		}

		switch err {
		case errInvalidCredentials:
			ctx.Unauthorized(err, "invalid email or password")
		case errEmailNotVerified:
			ctx.Forbidden(err, "email not verified")
		default:
			ctx.InternalServerError(err, "failed to login user")
		}
		return
	}

	// Log successful login
	if h.auditLogger != nil {
		details := map[string]any{
			"username": result.Username,
			"user_id":  result.ID,
			"roles":    result.Roles,
		}
		h.auditLogger.LogAuthenticationEvent(AuditEventAuthLoginSuccess, r, result.ID, true, details)
	}

	// Check if 2FA is required
	if h.service.cfg.TwoFactor.Enabled && result.user.TwoFactorEnabled {
		pendingToken, _, err := h.service.generate2FAPendingToken(result.user.ID)
		if err != nil {
			ctx.InternalServerError(err, "failed to generate 2FA token")
			return
		}
		ctx.Response(http.StatusOK, map[string]string{"twoFactorToken": pendingToken})
		return
	}

	h.setAuthCookie(ctx, result.RefreshToken, result.RefreshTokenExpiresAt)

	ctx.Response(http.StatusOK, result.UserLoginResponse)
}

// RefreshHandler handles the HTTP request for refreshing access tokens using a refresh token cookie.
// It reads the refresh token cookie, validates it, and refreshes the access token.
// It sets the auth cookie and returns the user login response.
func (h *AuthManager) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	refreshToken, err := ctx.Cookie(h.service.cfg.RefreshTokenCookieName)
	if err != nil {
		ctx.Unauthorized(err, "missing or invalid refresh token")
		return
	}

	result, err := h.service.refreshToken(ctx, refreshToken.Value)
	if err != nil {
		ctx.Unauthorized(err, "failed to refresh token")
		return
	}

	h.setAuthCookie(ctx, result.RefreshToken, result.RefreshTokenExpiresAt)

	ctx.Response(http.StatusOK, result.UserLoginResponse)
}

// LogoutHandler handles the HTTP request for user logout.
// It invalidates the refresh token associated with the current session.
// It sets the logout cookie and returns a no content response.
func (h *AuthManager) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	refreshToken, _ := ctx.Cookie(h.service.cfg.RefreshTokenCookieName)

	// Try to get user info before logout for audit logging
	var userID string
	if refreshToken != nil {
		if user, err := h.service.validateRefreshToken(ctx, refreshToken.Value); err == nil {
			userID = user.ID
		}
	}

	h.service.logout(ctx, lang.Deref(refreshToken).Value)

	// Log logout event
	if h.auditLogger != nil {
		details := map[string]any{
			"session_terminated": true,
		}
		h.auditLogger.LogAuthenticationEvent(AuditEventAuthLogout, r, userID, true, details)
	}

	h.setLogoutCookie(ctx)

	ctx.Response(http.StatusNoContent)
}

// GetCurrentUserHandler handles the HTTP request to retrieve the details of the currently authenticated user.
// It reads the user ID from the request context, validates it, and returns the user details.
func (h *AuthManager) GetCurrentUserHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	userID := getValueFromContext[string](r, UserContextKey{})
	if userID == "" {
		ctx.Unauthorized(errUnauthorized, "not authenticated")
		return
	}

	user, err := h.service.getUserByID(r.Context(), userID)
	if err != nil {
		ctx.InternalServerError(err, "failed to get user")
		return
	}

	ctx.Response(http.StatusOK, UserLoginResponse{
		ID:       user.ID,
		Username: user.Username,
		Roles:    user.Roles,
	})
}

// GetAllUsersHandler handles the HTTP request to retrieve all users.
// Note: This handler is intended for administrative purposes and might require specific roles.
// The corresponding route registration is commented out by default.
// It returns a list of all users.
func (h *AuthManager) GetAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	// Get all users
	users, err := h.service.getAllUsers(r.Context())
	if err != nil {
		ctx.InternalServerError(err, "failed to get users")
		return
	}

	// Convert to UserBasic to avoid sending password hashes
	resp := make([]UserLoginResponse, len(users))
	for i, user := range users {
		resp[i] = UserLoginResponse{
			ID:       user.ID,
			Username: user.Username,
			Roles:    user.Roles,
		}
	}

	ctx.Response(http.StatusOK, resp)
}

// UpdateUserRoleHandler handles the HTTP request to update a user's roles.
// Note: This handler is intended for administrative purposes and might require specific roles.
// The corresponding route registration is commented out by default.
func (h *AuthManager) UpdateUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	// Parse request body
	var req UserUpdateRequest
	if err := ctx.ReadAndValidate(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	// Update user role
	if err := h.service.updateUserRole(r.Context(), req.ID, lang.Deref(req.Roles)); err != nil {
		ctx.InternalServerError(err, "failed to update user role")
		return
	}

	ctx.Response(http.StatusOK, map[string]string{"message": "user role updated successfully"})
}

// CreateUser provides a programmatic way to create or update a user.
// If the user already exists (based on username), it updates their password and roles.
// If the user does not exist, it creates a new user with the provided details.
func (h *AuthManager) CreateUser(ctx context.Context, username, password string, roles ...UserRole) error {
	user, exists, err := h.service.db.FindByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("find user: %w", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if exists {
		err = h.service.db.UpdateUser(ctx, user.ID, &UserDiff{
			Roles:        &roles,
			PasswordHash: lang.Ptr(string(hashedPassword)),
		})
		if err != nil {
			return fmt.Errorf("update password: %w", err)
		}
		return nil
	}

	_, err = h.service.db.NewUser(ctx, username, string(hashedPassword), roles...)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	return nil
}

func (h *AuthManager) isSecureCookie(ctx *Context) bool {
	return h.service.cfg.ForceSecureCookies || ctx.r.TLS != nil
}

func (h *AuthManager) setAuthCookie(ctx *Context, token string, expiresAt time.Time) {
	ctx.SetRawCookie(&http.Cookie{
		Name:     h.service.cfg.RefreshTokenCookieName,
		Value:    token,
		Path:     authBasePath,
		HttpOnly: true,
		Secure:   h.isSecureCookie(ctx),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
	})
}

func (h *AuthManager) setLogoutCookie(ctx *Context) {
	ctx.SetRawCookie(&http.Cookie{
		Name:     h.service.cfg.RefreshTokenCookieName,
		Value:    "",
		Path:     authBasePath,
		HttpOnly: true,
		Secure:   h.isSecureCookie(ctx),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Delete cookie
		Expires:  time.Now().Add(-1 * time.Hour),
	})
}

type jwtClaims struct {
	UserID           string     `json:"user_id"`
	Roles            []UserRole `json:"roles"`
	IsRefresh        bool       `json:"is_refresh"`
	TokenPurpose     string     `json:"purpose,omitempty"`
	EmailVerified    bool       `json:"email_verified,omitempty"`
	TwoFactorEnabled bool       `json:"two_factor_enabled,omitempty"`
	jwt.RegisteredClaims
}

const (
	tokenPurposeAccess     = "access"
	tokenPurposeRefresh    = "refresh"
	tokenPurpose2FAPending = "2fa_pending"
)

type loginResult struct {
	UserLoginResponse
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
	user                  User // internal, for checking 2FA status etc.
}

// service provides auth operations
type service struct {
	db  AuthDatabase
	cfg AuthConfig
}

// newService creates a new auth service
func newService(cfg AuthConfig) *service {
	return &service{
		cfg: cfg,
		db:  cfg.Database,
	}
}

func (s *service) register(ctx context.Context, req RegisterRequest) (loginResult, error) {
	if s.cfg.MinPasswordLength > 0 && len(req.Password) < s.cfg.MinPasswordLength {
		return loginResult{}, errPasswordTooShort
	}

	_, exists, err := s.db.FindByUsername(ctx, req.Username)
	if err != nil {
		return loginResult{}, fmt.Errorf("FindByUsername: %w", err)
	}

	if exists {
		return loginResult{}, errUsernameAlreadyExists
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return loginResult{}, fmt.Errorf("hashing password: %w", err)
	}

	id, err := s.db.NewUser(ctx, req.Username, string(hashedPassword), s.cfg.RolesOnRegister...)
	if err != nil {
		return loginResult{}, fmt.Errorf("NewUser: %w", err)
	}

	accessToken, refreshToken, refreshTokenExpiresAt, err := s.generateTokens(ctx, User{
		ID:           id,
		Username:     req.Username,
		Roles:        s.cfg.RolesOnRegister,
		PasswordHash: string(hashedPassword),
	})
	if err != nil {
		return loginResult{}, fmt.Errorf("generateTokens: %w", err)
	}

	result := loginResult{
		UserLoginResponse: UserLoginResponse{
			AccessToken: accessToken,
			ID:          id,
			Username:    req.Username,
			Roles:       s.cfg.RolesOnRegister,
		},
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
	}

	return result, nil
}

func (s *service) login(ctx context.Context, req UserLoginRequest) (loginResult, error) {
	user, exists, err := s.db.FindByUsername(ctx, req.Username)
	if err != nil {
		return loginResult{}, fmt.Errorf("FindByUsername: %w", err)
	}

	if !exists {
		return loginResult{}, errInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return loginResult{}, errInvalidCredentials
	}

	// Block login if email verification is required but not completed
	if s.cfg.Email.Enabled && s.cfg.Email.RequireVerification && !user.EmailVerified {
		return loginResult{}, errEmailNotVerified
	}

	accessToken, refreshToken, refreshTokenExpiresAt, err := s.generateTokens(ctx, user)
	if err != nil {
		return loginResult{}, fmt.Errorf("generateTokens: %w", err)
	}

	out := loginResult{
		UserLoginResponse: UserLoginResponse{
			AccessToken: accessToken,
			ID:          user.ID,
			Username:    user.Username,
			Roles:       user.Roles,
		},
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
		user:                  user,
	}

	return out, nil
}

func (s *service) refreshToken(ctx context.Context, refreshToken string) (loginResult, error) {
	user, err := s.validateRefreshToken(ctx, refreshToken)
	if err != nil {
		return loginResult{}, fmt.Errorf("validateRefreshToken: %w", err)
	}

	accessToken, refreshToken, refreshTokenExpiresAt, err := s.generateTokens(ctx, user)
	if err != nil {
		return loginResult{}, fmt.Errorf("generateTokens: %w", err)
	}

	out := loginResult{
		UserLoginResponse: UserLoginResponse{
			AccessToken: accessToken,
			ID:          user.ID,
			Username:    user.Username,
			Roles:       user.Roles,
		},
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
	}

	return out, nil
}

func (s *service) logout(ctx context.Context, refreshToken string) {
	user, _ := s.validateRefreshToken(ctx, refreshToken)
	if user.ID == "" {
		return
	}
	_ = s.db.UpdateUser(ctx, user.ID, &UserDiff{
		RefreshTokenHash:      lang.Ptr(""),
		RefreshTokenExpiresAt: lang.Ptr(time.Time{}),
	})
}

func (s *service) getUserByID(ctx context.Context, id string) (User, error) {
	user, _, err := s.db.FindByID(ctx, id)
	if err != nil {
		return User{}, fmt.Errorf("FindByID: %w", err)
	}
	return user, nil
}

func (s *service) getAllUsers(ctx context.Context) ([]User, error) {
	users, err := s.db.FindAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("FindAll: %w", err)
	}
	return users, nil
}

func (s *service) updateUserRole(ctx context.Context, id string, roles []UserRole) error {
	return s.db.UpdateUser(ctx, id, &UserDiff{
		Roles: &roles,
	})
}

func (s *service) validateAccessToken(tokenString string) (claims *jwtClaims, err error) {
	claims, err = s.parseToken(tokenString, s.cfg.accessSecret)
	if err != nil {
		return nil, fmt.Errorf("parseToken: %w", err)
	}

	if claims.IsRefresh {
		return nil, fmt.Errorf("unexpected refresh token")
	}

	if claims.TokenPurpose != "" && claims.TokenPurpose != tokenPurposeAccess {
		return nil, errTwoFactorRequired
	}

	if claims.Issuer != s.cfg.IssuerNameInJWT {
		return nil, fmt.Errorf("invalid issuer")
	}

	if claims.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("expired token")
	}

	return claims, nil
}

func (s *service) validateRefreshToken(ctx context.Context, tokenString string) (user User, err error) {
	claims, err := s.parseToken(tokenString, s.cfg.refreshSecret)
	if err != nil {
		return User{}, fmt.Errorf("parseToken: %w", err)
	}

	user, exists, err := s.db.FindByID(ctx, claims.UserID)
	if err != nil {
		return User{}, fmt.Errorf("FindByID: %w", err)
	}

	if !exists {
		return User{}, fmt.Errorf("user not found")
	}

	if !claims.IsRefresh {
		return user, fmt.Errorf("unexpected access token")
	}

	if claims.TokenPurpose != "" && claims.TokenPurpose != tokenPurposeRefresh {
		return user, fmt.Errorf("unexpected token purpose")
	}

	if claims.ExpiresAt.Before(time.Now()) {
		return user, fmt.Errorf("expired token")
	}

	tokenString = tokenString[:72]
	if err := bcrypt.CompareHashAndPassword([]byte(user.RefreshTokenHash), []byte(tokenString)); err != nil {
		return user, fmt.Errorf("refresh token mismatch")
	}

	if user.RefreshTokenExpiresAt.Before(time.Now()) {
		return user, fmt.Errorf("refresh token expired")
	}

	return user, nil
}

func (s *service) parseToken(tokenString string, key []byte) (*jwtClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwtClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token format")
	}

	claims, ok := token.Claims.(*jwtClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid claims")
	}

	return claims, nil
}

func (s *service) generateTokens(ctx context.Context, user User) (string, string, time.Time, error) {
	accessToken, _, err := s.generateAccessToken(user)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("generating access token: %w", err)
	}

	refreshToken, refreshTokenExpiresAt, err := s.generateAndSaveRefreshToken(ctx, user)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("generating refresh token: %w", err)
	}

	return accessToken, refreshToken, refreshTokenExpiresAt, nil
}

func (s *service) generateAccessToken(user User) (string, time.Time, error) {
	return s.generateToken(user, false)
}

func (s *service) generateAndSaveRefreshToken(ctx context.Context, user User) (string, time.Time, error) {
	token, expiresAt, err := s.generateToken(user, true)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("generating refresh token: %w", err)
	}

	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(token[:72]), bcrypt.DefaultCost)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("hashing refresh token: %w", err)
	}

	if err := s.db.UpdateUser(ctx, user.ID, &UserDiff{
		RefreshTokenHash:      lang.Ptr(string(refreshTokenHash)),
		RefreshTokenExpiresAt: lang.Ptr(expiresAt),
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("updating refresh token: %w", err)
	}

	return token, expiresAt, nil
}

func (s *service) generateToken(user User, isRefresh bool) (string, time.Time, error) {
	expiresAt := time.Now().Add(s.cfg.AccessTokenDuration)
	secret := s.cfg.accessSecret
	purpose := tokenPurposeAccess
	if isRefresh {
		expiresAt = time.Now().Add(s.cfg.RefreshTokenDuration)
		secret = s.cfg.refreshSecret
		purpose = tokenPurposeRefresh
	}

	claims := jwtClaims{
		UserID:       user.ID,
		IsRefresh:    isRefresh,
		TokenPurpose: purpose,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    s.cfg.IssuerNameInJWT,
		},
	}

	// Make refresh lighter — only include roles and user flags in access tokens
	if !isRefresh {
		claims.Roles = user.Roles
		claims.EmailVerified = user.EmailVerified
		claims.TwoFactorEnabled = user.TwoFactorEnabled
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get complete token string
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signing token: %w", err)
	}

	return tokenString, expiresAt, nil
}

func (s *service) generate2FAPendingToken(userID string) (string, time.Time, error) {
	expiresAt := time.Now().Add(5 * time.Minute)
	claims := jwtClaims{
		UserID:       userID,
		TokenPurpose: tokenPurpose2FAPending,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        generateRandomHex(16),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    s.cfg.IssuerNameInJWT,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.cfg.accessSecret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signing 2FA pending token: %w", err)
	}
	return tokenString, expiresAt, nil
}

func (s *service) validate2FAPendingToken(tokenString string) (*jwtClaims, error) {
	claims, err := s.parseToken(tokenString, s.cfg.accessSecret)
	if err != nil {
		return nil, fmt.Errorf("parsing 2FA pending token: %w", err)
	}
	if claims.TokenPurpose != tokenPurpose2FAPending {
		return nil, errUnauthorized
	}
	if claims.ID == "" {
		return nil, errUnauthorized
	}
	if claims.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("expired 2FA pending token")
	}
	return claims, nil
}

func generateRandomHex(n int) string {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

var (
	errInvalidCredentials      = errors.New("invalid username or password")
	errUnauthorized            = errors.New("unauthorized")
	errInsufficientPermissions = errors.New("insufficient permissions")
	errUsernameAlreadyExists   = errors.New("username already exists")
	errPasswordTooShort        = errors.New("password too short")

	errEmailNotVerified         = errors.New("email not verified")
	errInvalidVerifyToken       = errors.New("invalid or expired verification token")
	errVerifyCooldown           = errors.New("verification email sent recently")
	errInvalidResetToken        = errors.New("invalid or expired reset token")
	errOAuthProviderNotFound    = errors.New("OAuth provider not found")
	errOAuthStateMismatch       = errors.New("OAuth state mismatch")
	errOAuthEmailNotVerified    = errors.New("email already registered, verify your email first or log in to link this provider")
	errOAuthAlreadyLinked       = errors.New("OAuth provider already linked")
	errTwoFactorRequired        = errors.New("2FA verification required")
	errTwoFactorAlreadyEnabled  = errors.New("2FA already enabled")
	errTwoFactorNotEnabled      = errors.New("2FA not enabled")
	errInvalidTwoFactorCode     = errors.New("invalid 2FA code")
	errTwoFactorTooManyAttempts = errors.New("too many 2FA attempts, re-authenticate")
)

// Validate checks if the UserLoginRequest is valid.
func (req UserLoginRequest) Validate() error {
	if req.Username == "" {
		return errors.New("username is required")
	}
	if req.Password == "" {
		return errors.New("password is required")
	}
	return nil
}

// Validate checks if the UserUpdateRequest is valid.
func (req UserUpdateRequest) Validate() error {
	if req.ID == "" {
		return errors.New("id is required")
	}
	if req.Roles == nil && req.Username == nil && req.Password == nil {
		return errors.New("at least one field must be provided")
	}
	return nil
}

// extractToken extracts the JWT token from the Authorization header
func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if bearerToken == "" {
		return ""
	}

	// Format: "Bearer {token}"
	parts := strings.Split(bearerToken, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

// hasPermission checks if the given user roles contain at least one of the required roles.
// If requiredRoles is empty, it grants permission (returns true).
func hasPermission(userRoles []UserRole, requiredRoles []UserRole) bool {
	// If no specific roles are required, access is granted.
	if len(requiredRoles) == 0 {
		return true
	}
	// Check if the user has at least one of the required roles.
	for _, requiredRole := range requiredRoles {
		if slices.Contains(userRoles, requiredRole) {
			return true // Found a matching role
		}
	}
	// No matching required role found in the user's roles.
	return false
}

const (
	refreshTokenCookieName = "_servexrt"
	authBasePath           = "/api/v1/auth"

	accessTokenDuration  = 5 * time.Minute
	refreshTokenDuration = 7 * 24 * time.Hour

	defaultMinPasswordLength = 8
	minSecretKeyLength       = 32
)

// MockAuthDatabase provides a mock implementation of the AuthDatabase interface for testing.
type MemoryAuthDatabase struct {
	mu            sync.RWMutex
	users         map[string]User // Map username to User
	usersByID     map[string]User // Map ID to User
	usersByEmail  map[string]User // Map email to User
	userIDCounter int
}

func NewMemoryAuthDatabase() *MemoryAuthDatabase {
	return &MemoryAuthDatabase{
		users:        make(map[string]User),
		usersByID:    make(map[string]User),
		usersByEmail: make(map[string]User),
	}
}

func (db *MemoryAuthDatabase) NewUser(ctx context.Context, username string, passwordHash string, roles ...UserRole) (string, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.users[username]; exists {
		return "", fmt.Errorf("username %q already exists", username)
	}

	db.userIDCounter++
	id := fmt.Sprintf("user-%d", db.userIDCounter)
	user := User{
		ID:           id,
		Username:     username,
		PasswordHash: passwordHash,
		Roles:        roles,
	}
	db.users[username] = user
	db.usersByID[id] = user
	return id, nil
}

func (db *MemoryAuthDatabase) FindByID(ctx context.Context, id string) (User, bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	user, exists := db.usersByID[id]
	return user, exists, nil
}

func (db *MemoryAuthDatabase) FindByUsername(ctx context.Context, username string) (User, bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	user, exists := db.users[username]
	return user, exists, nil
}

func (db *MemoryAuthDatabase) FindAll(ctx context.Context) ([]User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	users := make([]User, 0, len(db.usersByID))
	for _, user := range db.usersByID {
		users = append(users, user)
	}
	return users, nil
}

func (db *MemoryAuthDatabase) UpdateUser(ctx context.Context, id string, diff *UserDiff) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	user, exists := db.usersByID[id]
	if !exists {
		return fmt.Errorf("user with id %s not found", id)
	}

	// Remove old username mapping if username is changing
	if diff.Username != nil && *diff.Username != user.Username {
		if _, exists := db.users[*diff.Username]; exists {
			return fmt.Errorf("new username %q already exists", *diff.Username)
		}
		delete(db.users, user.Username)
		user.Username = *diff.Username
	}

	if diff.Roles != nil {
		user.Roles = *diff.Roles
	}
	if diff.PasswordHash != nil {
		user.PasswordHash = *diff.PasswordHash
	}
	if diff.RefreshTokenHash != nil {
		user.RefreshTokenHash = *diff.RefreshTokenHash
	}
	if diff.RefreshTokenExpiresAt != nil {
		user.RefreshTokenExpiresAt = *diff.RefreshTokenExpiresAt
	}

	// Email
	if diff.Email != nil && *diff.Email != user.Email {
		// Remove old email index entry
		if user.Email != "" {
			delete(db.usersByEmail, user.Email)
		}
		user.Email = *diff.Email
		// Add new email index entry
		if user.Email != "" {
			db.usersByEmail[user.Email] = user
		}
	}
	if diff.EmailVerified != nil {
		user.EmailVerified = *diff.EmailVerified
	}

	// Email verification
	if diff.EmailVerifyTokenHash != nil {
		user.EmailVerifyTokenHash = *diff.EmailVerifyTokenHash
	}
	if diff.EmailVerifyTokenExpiresAt != nil {
		user.EmailVerifyTokenExpiresAt = *diff.EmailVerifyTokenExpiresAt
	}
	if diff.EmailVerifyLastSentAt != nil {
		user.EmailVerifyLastSentAt = *diff.EmailVerifyLastSentAt
	}

	// Password reset
	if diff.PasswordResetTokenHash != nil {
		user.PasswordResetTokenHash = *diff.PasswordResetTokenHash
	}
	if diff.PasswordResetTokenExpiresAt != nil {
		user.PasswordResetTokenExpiresAt = *diff.PasswordResetTokenExpiresAt
	}

	// OAuth
	if diff.OAuthProviders != nil {
		user.OAuthProviders = *diff.OAuthProviders
	}

	// 2FA
	if diff.TwoFactorEnabled != nil {
		user.TwoFactorEnabled = *diff.TwoFactorEnabled
	}
	if diff.TwoFactorSecret != nil {
		user.TwoFactorSecret = *diff.TwoFactorSecret
	}
	if diff.TwoFactorBackupCodes != nil {
		user.TwoFactorBackupCodes = *diff.TwoFactorBackupCodes
	}

	// Update maps
	db.users[user.Username] = user
	db.usersByID[id] = user
	if user.Email != "" {
		db.usersByEmail[user.Email] = user
	}

	return nil
}

// FindByEmail finds a user by their email address.
func (db *MemoryAuthDatabase) FindByEmail(ctx context.Context, email string) (User, bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	user, exists := db.usersByEmail[email]
	return user, exists, nil
}

// FindByOAuthProvider finds a user by their OAuth provider and provider ID.
func (db *MemoryAuthDatabase) FindByOAuthProvider(ctx context.Context, provider, providerID string) (User, bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	for _, user := range db.usersByID {
		for _, link := range user.OAuthProviders {
			if link.Provider == provider && link.ProviderID == providerID {
				return user, true, nil
			}
		}
	}
	return User{}, false, nil
}
