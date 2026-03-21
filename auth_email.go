package servex

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/maxbolgarin/lang"
	"golang.org/x/crypto/bcrypt"
)

// EmailAuthDatabase is a sub-interface of AuthDatabase required when EmailConfig.Enabled is true.
// It provides email-based user lookup in addition to the standard AuthDatabase methods.
type EmailAuthDatabase interface {
	FindByEmail(ctx context.Context, email string) (User, bool, error)
}

// SMTPEmailSender implements EmailSender using net/smtp.
type SMTPEmailSender struct {
	cfg SMTPConfig
}

// NewSMTPEmailSender creates a new SMTPEmailSender with the provided SMTP configuration.
func NewSMTPEmailSender(cfg SMTPConfig) *SMTPEmailSender {
	return &SMTPEmailSender{cfg: cfg}
}

// SendVerificationEmail sends an email verification link to the user.
func (s *SMTPEmailSender) SendVerificationEmail(ctx context.Context, to string, token string) error {
	subject := lang.Check(s.cfg.VerificationSubject, "Verify your email")
	body := fmt.Sprintf("Please verify your email by clicking the following link:\n\n%s?token=%s", s.cfg.VerificationURL, url.QueryEscape(token))
	return s.send(to, subject, body)
}

// SendPasswordResetEmail sends a password reset link to the user.
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
type verifyEmailRequest struct {
	Token string `json:"token"`
}

// Validate checks if the verifyEmailRequest is valid.
func (req verifyEmailRequest) Validate() error {
	if req.Token == "" {
		return errors.New("token is required")
	}
	return nil
}

// generateEmailToken generates a random token for email verification or password reset.
// It returns the raw token (userID:randomHex format), the bcrypt hash of the random portion,
// and any error encountered.
func generateEmailToken(userID string) (rawToken string, hash string, err error) {
	randomPart := generateRandomHex(32)
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(randomPart), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("hashing email token: %w", err)
	}
	return userID + ":" + randomPart, string(hashBytes), nil
}

// VerifyEmailHandler handles the HTTP request for email verification.
// It validates the token, marks the email as verified, and clears the verification token fields.
func (h *AuthManager) VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	var req verifyEmailRequest
	if err := ctx.ReadAndValidate(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	parts := strings.SplitN(req.Token, ":", 2)
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

	// Mark email as verified and clear token fields
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
			"email": user.Email,
		})
	}

	ctx.Response(http.StatusOK, map[string]string{"message": "email verified successfully"})
}

// ResendVerificationHandler handles the HTTP request for resending a verification email.
// It requires authentication and respects the configured resend cooldown.
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
	if !user.EmailVerifyLastSentAt.IsZero() && time.Since(user.EmailVerifyLastSentAt) < h.service.cfg.Email.ResendCooldown {
		ctx.TooManyRequests(errVerifyCooldown, errVerifyCooldown.Error())
		return
	}

	// Generate new token
	rawToken, tokenHash, err := generateEmailToken(userID)
	if err != nil {
		ctx.InternalServerError(err, "failed to generate verification token")
		return
	}

	now := time.Now()
	expiresAt := now.Add(h.service.cfg.Email.VerifyTokenDuration)

	if err := h.service.db.UpdateUser(r.Context(), userID, &UserDiff{
		EmailVerifyTokenHash:      lang.Ptr(tokenHash),
		EmailVerifyTokenExpiresAt: lang.Ptr(expiresAt),
		EmailVerifyLastSentAt:     lang.Ptr(now),
	}); err != nil {
		ctx.InternalServerError(err, "failed to update verification token")
		return
	}

	// Send verification email
	if h.service.cfg.Email.Sender != nil {
		if err := h.service.cfg.Email.Sender.SendVerificationEmail(r.Context(), user.Email, rawToken); err != nil {
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

	expiresAt := time.Now().Add(h.service.cfg.Email.ResetTokenDuration)

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
	if h.service.cfg.Email.Sender != nil {
		if err := h.service.cfg.Email.Sender.SendPasswordResetEmail(r.Context(), user.Email, rawToken); err != nil {
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
