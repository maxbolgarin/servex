package servex

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/maxbolgarin/lang"
	"golang.org/x/crypto/bcrypt"
)

// EmailAuthDatabase is a sub-interface of AuthDatabase required when email verification
// or password reset features are enabled. It provides email-based user lookup
// in addition to the standard AuthDatabase methods.
type EmailAuthDatabase interface {
	FindByEmail(ctx context.Context, email string) (User, bool, error)
}

// SMTPEmailSender implements VerificationEmailSender, PasswordResetEmailSender,
// and TwoFactorEmailSender using net/smtp. A single SMTPEmailSender instance can be
// passed to all three flow configurations for convenience.
type SMTPEmailSender struct {
	cfg              SMTPConfig
	verificationMode EmailVerificationMode
}

// NewSMTPEmailSender creates a new SMTPEmailSender with the provided SMTP configuration.
// The verificationMode controls how verification emails are formatted:
//   - EmailVerificationCodeMode: the email body shows the code directly
//   - EmailVerificationTokenMode: the email body includes a clickable link with the token
func NewSMTPEmailSender(cfg SMTPConfig, verificationMode EmailVerificationMode) *SMTPEmailSender {
	return &SMTPEmailSender{cfg: cfg, verificationMode: verificationMode}
}

// SendVerificationEmail sends an email verification code or token to the user.
// In code mode, the email body contains the code directly.
// In token mode, the email body contains a verification link with the token as a query parameter.
func (s *SMTPEmailSender) SendVerificationEmail(ctx context.Context, to string, codeOrToken string) error {
	subject := lang.Check(s.cfg.VerificationSubject, "Verify your email")
	var body string
	if s.verificationMode == EmailVerificationTokenMode {
		body = fmt.Sprintf("Please verify your email by clicking the following link:\n\n%s?token=%s", s.cfg.VerificationURL, url.QueryEscape(codeOrToken))
	} else {
		body = fmt.Sprintf("Your email verification code is: %s", codeOrToken)
	}
	return s.send(to, subject, body)
}

// SendPasswordResetEmail sends a password reset link to the user.
// The token is appended as a query parameter to the configured PasswordResetURL.
func (s *SMTPEmailSender) SendPasswordResetEmail(ctx context.Context, to string, token string) error {
	subject := lang.Check(s.cfg.PasswordResetSubject, "Reset your password")
	body := fmt.Sprintf("To reset your password, click the following link:\n\n%s?token=%s", s.cfg.PasswordResetURL, url.QueryEscape(token))
	return s.send(to, subject, body)
}

// SendTwoFactorCodeEmail sends a 2FA verification code to the user.
func (s *SMTPEmailSender) SendTwoFactorCodeEmail(ctx context.Context, to string, code string) error {
	subject := lang.Check(s.cfg.TwoFactorCodeSubject, "Your verification code")
	body := fmt.Sprintf("Your verification code is: %s", code)
	return s.send(to, subject, body)
}

func (s *SMTPEmailSender) send(to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\n%s",
		s.cfg.From, to, subject, body)

	return smtp.SendMail(addr, auth, s.cfg.From, []string{to}, []byte(msg))
}

// ForgotPasswordRequest represents the request body for initiating a password reset.
type ForgotPasswordRequest struct {
	Identifier string `json:"identifier"` // email address or username
}

// Validate checks if the ForgotPasswordRequest is valid.
func (req ForgotPasswordRequest) Validate() error {
	if req.Identifier == "" {
		return errors.New("identifier is required")
	}
	if strings.Contains(req.Identifier, "@") {
		if _, err := mail.ParseAddress(req.Identifier); err != nil {
			return errors.New("invalid email address format")
		}
		if strings.ContainsAny(req.Identifier, "\r\n") {
			return errors.New("invalid email address format")
		}
	}
	return nil
}

// ResetPasswordRequest represents the request body for completing a password reset.
type ResetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// Validate checks if the ResetPasswordRequest is valid.
func (req ResetPasswordRequest) Validate() error {
	if req.Token == "" {
		return errors.New("token is required")
	}
	if req.Password == "" {
		return errors.New("password is required")
	}
	return nil
}

// verifyEmailRequest represents the request body for email verification.
// In code mode, both Code and Email fields are required.
// In token mode, only the Token field is required.
type verifyEmailRequest struct {
	// Token is the verification token (token mode only). Format: "userID:randomHex".
	Token string `json:"token,omitempty"`
	// Code is the verification code (code mode only). E.g. "123456".
	Code string `json:"code,omitempty"`
	// Email is the user's email address (code mode only). Used to look up the user.
	Email string `json:"email,omitempty"`
}

// validateForMode checks if the verifyEmailRequest has the required fields
// based on the configured verification mode.
func (req verifyEmailRequest) validateForMode(mode EmailVerificationMode) error {
	if mode == EmailVerificationTokenMode {
		if req.Token == "" {
			return errors.New("token is required")
		}
		return nil
	}
	// Code mode
	if req.Code == "" {
		return errors.New("code is required")
	}
	if req.Email == "" {
		return errors.New("email is required")
	}
	return nil
}

// generateEmailToken generates a random token for email verification (token mode) or password reset.
// It returns the raw token (userID:randomHex format), the bcrypt hash of the random portion,
// and any error encountered.
func generateEmailToken(userID string) (rawToken string, hash string, err error) {
	randomPart, err := generateRandomHex(32)
	if err != nil {
		return "", "", fmt.Errorf("generating random token: %w", err)
	}
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(randomPart), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("hashing email token: %w", err)
	}
	return userID + ":" + randomPart, string(hashBytes), nil
}

// generateVerificationCode generates a verification code using the configured CodeGenerator,
// or falls back to the built-in numeric generator with the configured number of digits.
// Returns the plaintext code and its bcrypt hash.
func generateVerificationCode(cfg EmailVerificationConfig) (code string, hash string, err error) {
	var rawCode string
	if cfg.CodeGenerator != nil {
		rawCode, err = cfg.CodeGenerator.Generate()
	} else {
		digits := lang.Check(cfg.CodeDigits, 6)
		rawCode, err = generateNumericEmailCode(digits)
	}
	if err != nil {
		return "", "", fmt.Errorf("generating verification code: %w", err)
	}

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(rawCode), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("hashing verification code: %w", err)
	}
	return rawCode, string(hashBytes), nil
}

// VerifyEmailHandler handles the HTTP request for email verification.
// In token mode: validates the token, marks the email as verified, and clears the token fields.
// In code mode: validates the code and email, looks up the user by email, and marks as verified.
func (h *AuthManager) VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	var req verifyEmailRequest
	if err := ctx.ReadJSON(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	mode := h.service.cfg.EmailVerification.Mode
	if err := req.validateForMode(mode); err != nil {
		ctx.BadRequest(err, err.Error())
		return
	}

	if mode == EmailVerificationTokenMode {
		h.verifyEmailByToken(ctx, r, req.Token)
	} else {
		h.verifyEmailByCode(ctx, r, req.Code, req.Email)
	}
}

// verifyEmailByToken handles email verification using a long token (token mode).
func (h *AuthManager) verifyEmailByToken(ctx *Context, r *http.Request, token string) {
	parts := strings.SplitN(token, ":", 2)
	if len(parts) != 2 {
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventEmailVerifyFailed, r, "", false, map[string]any{
				"reason": "invalid_token_format",
			})
		}
		ctx.BadRequest(errInvalidVerifyToken, errInvalidVerifyToken.Error())
		return
	}

	userID := parts[0]
	tokenPart := parts[1]

	user, exists, err := h.service.db.FindByID(r.Context(), userID)
	if err != nil {
		ctx.InternalServerError(err, "failed to find user")
		return
	}
	if !exists {
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventEmailVerifyFailed, r, userID, false, map[string]any{
				"reason": "user_not_found",
			})
		}
		ctx.BadRequest(errInvalidVerifyToken, errInvalidVerifyToken.Error())
		return
	}

	// Check token hash
	if err := bcrypt.CompareHashAndPassword([]byte(user.EmailVerifyTokenHash), []byte(tokenPart)); err != nil {
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventEmailVerifyFailed, r, userID, false, map[string]any{
				"reason": "token_mismatch",
			})
		}
		ctx.BadRequest(errInvalidVerifyToken, errInvalidVerifyToken.Error())
		return
	}

	// Check expiry
	if time.Now().After(user.EmailVerifyTokenExpiresAt) {
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventEmailVerifyFailed, r, userID, false, map[string]any{
				"reason": "token_expired",
			})
		}
		ctx.BadRequest(errInvalidVerifyToken, errInvalidVerifyToken.Error())
		return
	}

	h.markEmailVerified(ctx, r, userID, user.Email)
}

// verifyEmailByCode handles email verification using a short code (code mode).
func (h *AuthManager) verifyEmailByCode(ctx *Context, r *http.Request, code, email string) {
	emailDB, ok := h.service.db.(EmailAuthDatabase)
	if !ok {
		ctx.InternalServerError(errors.New("database does not support email lookup"), "internal error")
		return
	}

	user, found, err := emailDB.FindByEmail(r.Context(), email)
	if err != nil {
		ctx.InternalServerError(err, "failed to find user")
		return
	}
	if !found {
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventEmailVerifyFailed, r, "", false, map[string]any{
				"reason": "user_not_found",
				"email":  email,
			})
		}
		ctx.BadRequest(errInvalidVerifyToken, errInvalidVerifyToken.Error())
		return
	}

	// Check code hash (stored in EmailVerifyTokenHash)
	if err := bcrypt.CompareHashAndPassword([]byte(user.EmailVerifyTokenHash), []byte(code)); err != nil {
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventEmailVerifyFailed, r, user.ID, false, map[string]any{
				"reason": "code_mismatch",
			})
		}
		ctx.BadRequest(errInvalidVerifyToken, errInvalidVerifyToken.Error())
		return
	}

	// Check expiry
	if time.Now().After(user.EmailVerifyTokenExpiresAt) {
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventEmailVerifyFailed, r, user.ID, false, map[string]any{
				"reason": "code_expired",
			})
		}
		ctx.BadRequest(errInvalidVerifyToken, errInvalidVerifyToken.Error())
		return
	}

	h.markEmailVerified(ctx, r, user.ID, user.Email)
}

// markEmailVerified marks the user's email as verified, clears the verification token/code fields,
// generates access and refresh tokens, and returns a login response so the user is auto-logged-in.
func (h *AuthManager) markEmailVerified(ctx *Context, r *http.Request, userID, email string) {
	if err := h.service.db.UpdateUser(r.Context(), userID, &UserDiff{
		EmailVerified:             lang.Ptr(true),
		EmailVerifyTokenHash:      lang.Ptr(""),
		EmailVerifyTokenExpiresAt: lang.Ptr(time.Time{}),
	}); err != nil {
		ctx.InternalServerError(err, "failed to update user")
		return
	}

	if h.auditLogger != nil {
		h.auditLogger.LogAuthenticationEvent(AuditEventEmailVerified, r, userID, true, map[string]any{
			"email": email,
		})
	}

	// Auto-login: generate tokens so the user doesn't have to log in manually after verification.
	user, exists, err := h.service.db.FindByID(r.Context(), userID)
	if err != nil || !exists {
		ctx.InternalServerError(err, "failed to find user after verification")
		return
	}

	accessToken, refreshToken, refreshTokenExpiresAt, err := h.service.generateTokens(r.Context(), user)
	if err != nil {
		ctx.InternalServerError(err, "failed to generate tokens after verification")
		return
	}

	h.setAuthCookie(ctx, refreshToken, refreshTokenExpiresAt)

	ctx.Response(http.StatusOK, UserLoginResponse{
		AccessToken: accessToken,
		ID:          user.ID,
		Username:    user.Username,
		Roles:       user.Roles,
	})
}

// ResendVerificationHandler handles the HTTP request for resending a verification email.
// It requires authentication and respects the configured resend cooldown.
// In code mode, it generates a new code. In token mode, it generates a new token.
func (h *AuthManager) ResendVerificationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	userID := getValueFromContext[string](r, UserContextKey{})
	if userID == "" {
		ctx.Unauthorized(errUnauthorized, "not authenticated")
		return
	}

	user, exists, err := h.service.db.FindByID(r.Context(), userID)
	if err != nil {
		ctx.InternalServerError(err, "failed to find user")
		return
	}
	if !exists {
		ctx.Unauthorized(errUnauthorized, "user not found")
		return
	}

	if user.EmailVerified {
		ctx.BadRequest(errors.New("email already verified"), "email already verified")
		return
	}

	if user.Email == "" {
		ctx.BadRequest(errors.New("no email address"), "no email address on account")
		return
	}

	// Check cooldown
	if !user.EmailVerifyLastSentAt.IsZero() && time.Since(user.EmailVerifyLastSentAt) < h.service.cfg.EmailVerification.ResendCooldown {
		ctx.TooManyRequests(errVerifyCooldown, errVerifyCooldown.Error())
		return
	}

	cfg := h.service.cfg.EmailVerification
	now := time.Now()

	var sendValue string // code or token to send via email
	var hashValue string // bcrypt hash to store

	if cfg.Mode == EmailVerificationTokenMode {
		rawToken, tokenHash, err := generateEmailToken(userID)
		if err != nil {
			ctx.InternalServerError(err, "failed to generate verification token")
			return
		}
		sendValue = rawToken
		hashValue = tokenHash
	} else {
		code, codeHash, err := generateVerificationCode(cfg)
		if err != nil {
			ctx.InternalServerError(err, "failed to generate verification code")
			return
		}
		sendValue = code
		hashValue = codeHash
	}

	var expiresAt time.Time
	if cfg.Mode == EmailVerificationTokenMode {
		expiresAt = now.Add(cfg.TokenDuration)
	} else {
		expiresAt = now.Add(cfg.CodeDuration)
	}

	if err := h.service.db.UpdateUser(r.Context(), userID, &UserDiff{
		EmailVerifyTokenHash:      lang.Ptr(hashValue),
		EmailVerifyTokenExpiresAt: lang.Ptr(expiresAt),
		EmailVerifyLastSentAt:     lang.Ptr(now),
	}); err != nil {
		ctx.InternalServerError(err, "failed to update verification token")
		return
	}

	// Send verification email
	if cfg.Sender != nil {
		if err := cfg.Sender.SendVerificationEmail(r.Context(), user.Email, sendValue); err != nil {
			ctx.InternalServerError(err, "failed to send verification email")
			return
		}
	}

	ctx.Response(http.StatusOK, map[string]string{"message": "verification email sent"})
}

// ForgotPasswordHandler handles the HTTP request for initiating a password reset.
// It always returns 200 regardless of whether the user exists, to prevent user enumeration.
func (h *AuthManager) ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	var req ForgotPasswordRequest
	if err := ctx.ReadAndValidate(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	const successMessage = "if the account exists, a reset link has been sent"

	// Find user by email or username
	var user User
	var found bool
	var findErr error

	if strings.Contains(req.Identifier, "@") {
		emailDB, ok := h.service.db.(EmailAuthDatabase)
		if !ok {
			// Should not happen if validated at startup, but handle gracefully
			ctx.Response(http.StatusOK, map[string]string{"message": successMessage})
			return
		}
		user, found, findErr = emailDB.FindByEmail(r.Context(), req.Identifier)
	} else {
		user, found, findErr = h.service.db.FindByUsername(r.Context(), req.Identifier)
	}

	if findErr != nil {
		// Log error but return success to prevent enumeration
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventPasswordResetFailed, r, "", false, map[string]any{
				"reason": "db_error",
				"error":  findErr.Error(),
			})
		}
		ctx.Response(http.StatusOK, map[string]string{"message": successMessage})
		return
	}

	if !found || user.Email == "" {
		// No user or no email — still return success
		ctx.Response(http.StatusOK, map[string]string{"message": successMessage})
		return
	}

	// Enforce resend cooldown using existing token expiry to derive last sent time
	if h.service.cfg.PasswordReset.ResendCooldown > 0 && !user.PasswordResetTokenExpiresAt.IsZero() {
		lastSentAt := user.PasswordResetTokenExpiresAt.Add(-h.service.cfg.PasswordReset.TokenDuration)
		if time.Since(lastSentAt) < h.service.cfg.PasswordReset.ResendCooldown {
			// Still within cooldown — return success to prevent enumeration
			ctx.Response(http.StatusOK, map[string]string{"message": successMessage})
			return
		}
	}

	// Generate reset token
	rawToken, tokenHash, err := generateEmailToken(user.ID)
	if err != nil {
		// Log error but return success
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventPasswordResetFailed, r, user.ID, false, map[string]any{
				"reason": "token_generation_error",
			})
		}
		ctx.Response(http.StatusOK, map[string]string{"message": successMessage})
		return
	}

	expiresAt := time.Now().Add(h.service.cfg.PasswordReset.TokenDuration)

	if err := h.service.db.UpdateUser(r.Context(), user.ID, &UserDiff{
		PasswordResetTokenHash:      lang.Ptr(tokenHash),
		PasswordResetTokenExpiresAt: lang.Ptr(expiresAt),
	}); err != nil {
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventPasswordResetFailed, r, user.ID, false, map[string]any{
				"reason": "db_update_error",
			})
		}
		ctx.Response(http.StatusOK, map[string]string{"message": successMessage})
		return
	}

	// Send reset email
	if h.service.cfg.PasswordReset.Sender != nil {
		if err := h.service.cfg.PasswordReset.Sender.SendPasswordResetEmail(r.Context(), user.Email, rawToken); err != nil {
			if h.auditLogger != nil {
				h.auditLogger.LogAuthenticationEvent(AuditEventPasswordResetFailed, r, user.ID, false, map[string]any{
					"reason": "email_send_error",
				})
			}
		}
	}

	if h.auditLogger != nil {
		h.auditLogger.LogAuthenticationEvent(AuditEventPasswordResetReq, r, user.ID, true, map[string]any{
			"email": user.Email,
		})
	}

	ctx.Response(http.StatusOK, map[string]string{"message": successMessage})
}

// ResetPasswordHandler handles the HTTP request for completing a password reset.
// It validates the reset token, updates the password, and forces re-login by clearing the refresh token.
func (h *AuthManager) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	var req ResetPasswordRequest
	if err := ctx.ReadAndValidate(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	if h.service.cfg.MinPasswordLength > 0 && len(req.Password) < h.service.cfg.MinPasswordLength {
		ctx.BadRequest(errPasswordTooShort, fmt.Sprintf("password must be at least %d characters", h.service.cfg.MinPasswordLength))
		return
	}
	if len(req.Password) > 128 {
		ctx.BadRequest(nil, "password must be 128 characters or fewer")
		return
	}

	parts := strings.SplitN(req.Token, ":", 2)
	if len(parts) != 2 {
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventPasswordResetFailed, r, "", false, map[string]any{
				"reason": "invalid_token_format",
			})
		}
		ctx.BadRequest(errInvalidResetToken, errInvalidResetToken.Error())
		return
	}

	userID := parts[0]
	tokenPart := parts[1]

	user, exists, err := h.service.db.FindByID(r.Context(), userID)
	if err != nil {
		ctx.InternalServerError(err, "failed to find user")
		return
	}
	if !exists {
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventPasswordResetFailed, r, userID, false, map[string]any{
				"reason": "user_not_found",
			})
		}
		ctx.BadRequest(errInvalidResetToken, errInvalidResetToken.Error())
		return
	}

	// Check token hash
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordResetTokenHash), []byte(tokenPart)); err != nil {
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventPasswordResetFailed, r, userID, false, map[string]any{
				"reason": "token_mismatch",
			})
		}
		ctx.BadRequest(errInvalidResetToken, errInvalidResetToken.Error())
		return
	}

	// Check expiry
	if time.Now().After(user.PasswordResetTokenExpiresAt) {
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventPasswordResetFailed, r, userID, false, map[string]any{
				"reason": "token_expired",
			})
		}
		ctx.BadRequest(errInvalidResetToken, errInvalidResetToken.Error())
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.InternalServerError(err, "failed to hash password")
		return
	}

	// Update password, clear reset token, clear refresh token (force re-login)
	if err := h.service.db.UpdateUser(r.Context(), userID, &UserDiff{
		PasswordHash:                lang.Ptr(string(hashedPassword)),
		PasswordResetTokenHash:      lang.Ptr(""),
		PasswordResetTokenExpiresAt: lang.Ptr(time.Time{}),
		RefreshTokenHash:            lang.Ptr(""),
		RefreshTokenExpiresAt:       lang.Ptr(time.Time{}),
	}); err != nil {
		ctx.InternalServerError(err, "failed to update password")
		return
	}

	if h.auditLogger != nil {
		h.auditLogger.LogAuthenticationEvent(AuditEventPasswordResetDone, r, userID, true, map[string]any{
			"email": user.Email,
		})
	}

	ctx.Response(http.StatusOK, map[string]string{"message": "password reset successfully"})
}
