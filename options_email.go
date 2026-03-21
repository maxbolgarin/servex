package servex

import (
	"context"
	"time"
)

// EmailSender sends emails for verification, password reset, and 2FA.
// Implement this interface to provide custom email delivery.
//
// If nil and SMTP is configured in EmailConfig, a built-in SMTP sender is used.
type EmailSender interface {
	// SendVerificationEmail sends an email verification link to the user.
	SendVerificationEmail(ctx context.Context, to string, token string) error

	// SendPasswordResetEmail sends a password reset link to the user.
	SendPasswordResetEmail(ctx context.Context, to string, token string) error

	// SendTwoFactorCodeEmail sends a 2FA verification code to the user.
	SendTwoFactorCodeEmail(ctx context.Context, to string, code string) error
}

// EmailConfig configures email verification and password reset.
type EmailConfig struct {
	// Enabled activates email verification and password reset features.
	Enabled bool

	// Sender is a custom email sending implementation.
	// If nil and SMTP is configured, a built-in SMTP sender is used.
	Sender EmailSender

	// SMTP configures the built-in SMTP email sender.
	// Ignored if a custom Sender is provided.
	SMTP *SMTPConfig

	// RequireVerification blocks login until email is verified.
	// Default: false (allow login with unverified email).
	RequireVerification bool

	// VerifyTokenDuration is how long email verification tokens are valid.
	// Default: 24h.
	VerifyTokenDuration time.Duration

	// ResetTokenDuration is how long password reset tokens are valid.
	// Default: 1h.
	ResetTokenDuration time.Duration

	// ResendCooldown is the minimum interval between verification email resends.
	// Default: 60s.
	ResendCooldown time.Duration
}

// SMTPConfig configures the built-in SMTP email sender.
type SMTPConfig struct {
	// Host is the SMTP server hostname.
	Host string

	// Port is the SMTP server port (e.g. 587 for STARTTLS).
	Port int

	// Username is the SMTP authentication username.
	Username string

	// Password is the SMTP authentication password.
	Password string

	// From is the sender email address (e.g. "noreply@example.com").
	From string

	// VerificationSubject is the subject line for verification emails.
	// Default: "Verify your email".
	VerificationSubject string

	// PasswordResetSubject is the subject line for password reset emails.
	// Default: "Reset your password".
	PasswordResetSubject string

	// TwoFactorCodeSubject is the subject line for 2FA code emails.
	// Default: "Your verification code".
	TwoFactorCodeSubject string

	// VerificationURL is the base URL for email verification links.
	// The verification token is appended as a query parameter.
	// Example: "https://myapp.com/verify-email".
	VerificationURL string

	// PasswordResetURL is the base URL for password reset links.
	// The reset token is appended as a query parameter.
	// Example: "https://myapp.com/reset-password".
	PasswordResetURL string
}

// WithEmailSender enables email features with a custom EmailSender implementation.
//
// Example:
//
//	server := servex.New(servex.WithEmailSender(myCustomSender))
//
// The sender must implement the EmailSender interface, handling verification,
// password reset, and 2FA code delivery.
func WithEmailSender(sender EmailSender) Option {
	return func(op *Options) {
		op.Auth.Email.Enabled = true
		op.Auth.Email.Sender = sender
	}
}

// WithEmailSMTP enables email features with SMTP configuration.
// A built-in SMTP sender will be created from the provided configuration.
//
// Example:
//
//	server := servex.New(servex.WithEmailSMTP(servex.SMTPConfig{
//		Host:            "smtp.example.com",
//		Port:            587,
//		Username:        "noreply@example.com",
//		Password:        os.Getenv("SMTP_PASSWORD"),
//		From:            "noreply@example.com",
//		VerificationURL: "https://myapp.com/verify-email",
//		PasswordResetURL: "https://myapp.com/reset-password",
//	}))
func WithEmailSMTP(cfg SMTPConfig) Option {
	return func(op *Options) {
		op.Auth.Email.Enabled = true
		op.Auth.Email.SMTP = &cfg
	}
}

// WithEmailRequireVerification sets whether email verification is required before login.
// When true, users must verify their email address before they can log in.
//
// Example:
//
//	server := servex.New(
//		servex.WithEmailSMTP(smtpCfg),
//		servex.WithEmailRequireVerification(true),
//	)
func WithEmailRequireVerification(require bool) Option {
	return func(op *Options) {
		op.Auth.Email.RequireVerification = require
	}
}

// WithEmailTokenDurations sets the duration for email verification and password reset tokens.
//
// Example:
//
//	server := servex.New(servex.WithEmailTokenDurations(
//		48*time.Hour,   // Verification token: 48 hours
//		30*time.Minute, // Password reset token: 30 minutes
//	))
//
// Defaults: verification 24h, password reset 1h.
func WithEmailTokenDurations(verify, reset time.Duration) Option {
	return func(op *Options) {
		op.Auth.Email.VerifyTokenDuration = verify
		op.Auth.Email.ResetTokenDuration = reset
	}
}

// WithEmailResendCooldown sets the minimum interval between verification email resends.
// This prevents abuse by limiting how frequently a user can request new verification emails.
//
// Example:
//
//	server := servex.New(servex.WithEmailResendCooldown(2 * time.Minute))
//
// Default: 60s.
func WithEmailResendCooldown(d time.Duration) Option {
	return func(op *Options) {
		op.Auth.Email.ResendCooldown = d
	}
}

// WithEmailConfig sets the complete email configuration.
// Use this when you need to configure multiple email settings at once
// or when loading configuration from files or environment variables.
//
// Example:
//
//	emailCfg := servex.EmailConfig{
//		Enabled:             true,
//		RequireVerification: true,
//		VerifyTokenDuration: 48 * time.Hour,
//		ResetTokenDuration:  30 * time.Minute,
//		ResendCooldown:      2 * time.Minute,
//		SMTP: &servex.SMTPConfig{
//			Host: "smtp.example.com",
//			Port: 587,
//		},
//	}
//	server := servex.New(servex.WithEmailConfig(emailCfg))
func WithEmailConfig(cfg EmailConfig) Option {
	return func(op *Options) {
		op.Auth.Email = cfg
	}
}
