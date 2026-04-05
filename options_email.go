package servex

import (
	"context"
	"time"
)

// VerificationEmailSender sends email verification codes or tokens.
// Implement this interface to provide custom email delivery for the verification flow.
// In code mode the codeOrToken parameter contains a short numeric code (e.g. "123456").
// In token mode it contains a long token string suitable for embedding in a link.
type VerificationEmailSender interface {
	SendVerificationEmail(ctx context.Context, to string, codeOrToken string) error
}

// PasswordResetEmailSender sends password reset tokens via email.
// Implement this interface to provide custom email delivery for the password reset flow.
// The token parameter contains a long token string for embedding in a reset link.
type PasswordResetEmailSender interface {
	SendPasswordResetEmail(ctx context.Context, to string, token string) error
}

// TwoFactorEmailSender sends 2FA verification codes via email.
// Implement this interface to provide custom email delivery for the 2FA flow.
// The code parameter contains a short verification code (e.g. "123456").
type TwoFactorEmailSender interface {
	SendTwoFactorCodeEmail(ctx context.Context, to string, code string) error
}

// EmailVerificationMode determines how email verification works.
type EmailVerificationMode int

const (
	// EmailVerificationCodeMode sends a short numeric code (default 6 digits) that the user
	// submits via the API. This is the default mode. The code is bcrypt-hashed and stored
	// with an expiry. Users submit the code along with their email address to verify.
	EmailVerificationCodeMode EmailVerificationMode = iota

	// EmailVerificationTokenMode sends a long token suitable for building a verification link.
	// The token format is "userID:randomHex" and contains the user identity, so the verify
	// endpoint does not require authentication or an email address in the request body.
	EmailVerificationTokenMode
)

// EmailVerificationConfig configures email verification.
// This is independent of password reset and 2FA email delivery.
type EmailVerificationConfig struct {
	// Enabled activates email verification features.
	// When enabled, users can verify their email address after registration.
	Enabled bool

	// Sender is a custom email sender for delivering verification codes or tokens.
	// If nil and SMTP is configured, a built-in SMTP sender is used.
	Sender VerificationEmailSender

	// SMTP configures the built-in SMTP sender for verification emails.
	// Ignored if a custom Sender is provided.
	SMTP *SMTPConfig

	// RequireVerification blocks login until email is verified.
	// When true, users must verify their email address before they can log in.
	// Default: false (allow login with unverified email).
	RequireVerification bool

	// Mode determines how email verification works.
	// EmailVerificationCodeMode (default): sends a short numeric code.
	// EmailVerificationTokenMode: sends a long token for building a verification link.
	Mode EmailVerificationMode

	// CodeGenerator, if set, is used to generate verification codes in code mode.
	// When nil, a built-in numeric generator with CodeDigits digits is used.
	// Uses the shared CodeGenerator interface, which is also used by 2FA.
	CodeGenerator CodeGenerator

	// CodeDigits is the length of verification codes (decimal digits) in code mode.
	// Ignored when CodeGenerator is non-nil. Default: 6. Range: 1–32.
	CodeDigits int

	// CodeDuration is how long verification codes remain valid in code mode.
	// Default: 10m.
	CodeDuration time.Duration

	// TokenDuration is how long verification tokens remain valid in token mode.
	// Default: 24h.
	TokenDuration time.Duration

	// ResendCooldown is the minimum interval between verification email resends.
	// This prevents abuse by limiting how frequently a user can request new codes or tokens.
	// Default: 60s.
	ResendCooldown time.Duration
}

// PasswordResetConfig configures password reset via email.
// This is independent of email verification and 2FA email delivery.
type PasswordResetConfig struct {
	// Enabled activates password reset features.
	// When enabled, users can request a password reset token via email.
	Enabled bool

	// Sender is a custom email sender for delivering password reset tokens.
	// If nil and SMTP is configured, a built-in SMTP sender is used.
	Sender PasswordResetEmailSender

	// SMTP configures the built-in SMTP sender for password reset emails.
	// Ignored if a custom Sender is provided.
	SMTP *SMTPConfig

	// TokenDuration is how long password reset tokens are valid.
	// Default: 1h.
	TokenDuration time.Duration

	// ResendCooldown is the minimum interval between password reset email resends per user.
	// This prevents email flooding abuse.
	// Default: 60s.
	ResendCooldown time.Duration
}

// SMTPConfig configures the built-in SMTP email sender.
// The same SMTPConfig can be passed to WithEmailSMTP (convenience function)
// which sets up senders for all three flows (verification, password reset, 2FA),
// or to individual flow options (WithTwoFactorEmailSMTP, etc.) for per-flow configuration.
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

	// VerificationURL is the base URL for email verification links (token mode only).
	// The verification token is appended as a query parameter.
	// Example: "https://myapp.com/verify-email".
	VerificationURL string

	// PasswordResetURL is the base URL for password reset links.
	// The reset token is appended as a query parameter.
	// Example: "https://myapp.com/reset-password".
	PasswordResetURL string
}

// WithVerificationEmailSender enables email verification with a custom VerificationEmailSender.
//
// Example:
//
//	server := servex.New(servex.WithVerificationEmailSender(myVerifSender))
func WithVerificationEmailSender(sender VerificationEmailSender) Option {
	return func(op *Options) {
		op.Auth.EmailVerification.Enabled = true
		op.Auth.EmailVerification.Sender = sender
	}
}

// WithPasswordResetEmailSender enables password reset with a custom PasswordResetEmailSender.
//
// Example:
//
//	server := servex.New(servex.WithPasswordResetEmailSender(myResetSender))
func WithPasswordResetEmailSender(sender PasswordResetEmailSender) Option {
	return func(op *Options) {
		op.Auth.PasswordReset.Enabled = true
		op.Auth.PasswordReset.Sender = sender
	}
}

// WithEmailSMTP enables email verification, password reset, and 2FA email delivery
// using the same SMTP configuration. A built-in SMTPEmailSender is created and used
// for all three flows. This is a convenience function — use per-flow options
// (WithTwoFactorEmailSMTP, etc.) when different SMTP configurations are needed.
//
// Example:
//
//	server := servex.New(servex.WithEmailSMTP(servex.SMTPConfig{
//		Host:             "smtp.example.com",
//		Port:             587,
//		Username:         "noreply@example.com",
//		Password:         os.Getenv("SMTP_PASSWORD"),
//		From:             "noreply@example.com",
//		VerificationURL:  "https://myapp.com/verify-email",
//		PasswordResetURL: "https://myapp.com/reset-password",
//	}))
func WithEmailSMTP(cfg SMTPConfig) Option {
	return func(op *Options) {
		op.Auth.EmailVerification.Enabled = true
		op.Auth.EmailVerification.SMTP = &cfg
		op.Auth.PasswordReset.Enabled = true
		op.Auth.PasswordReset.SMTP = &cfg
		op.Auth.TwoFactor.SMTP = &cfg
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
		op.Auth.EmailVerification.RequireVerification = require
	}
}

// WithEmailVerificationMode sets the verification mode: EmailVerificationCodeMode (default)
// or EmailVerificationTokenMode. Code mode sends a short numeric code. Token mode sends
// a long token for building a verification link.
//
// Example:
//
//	// Use token mode for link-based verification
//	server := servex.New(servex.WithEmailVerificationMode(servex.EmailVerificationTokenMode))
func WithEmailVerificationMode(mode EmailVerificationMode) Option {
	return func(op *Options) {
		op.Auth.EmailVerification.Mode = mode
	}
}

// WithEmailVerificationCodeDigits sets the number of digits in verification codes (code mode).
// Ignored if a custom CodeGenerator is set. Default: 6. Valid range: 1–32.
func WithEmailVerificationCodeDigits(n int) Option {
	return func(op *Options) {
		op.Auth.EmailVerification.CodeDigits = n
	}
}

// WithEmailVerificationCodeGenerator sets a custom code generator for email verification.
// When non-nil, CodeDigits is ignored. Uses the shared CodeGenerator interface.
//
// Example:
//
//	server := servex.New(servex.WithEmailVerificationCodeGenerator(
//		servex.NewNumericCodeGenerator(8), // 8-digit codes
//	))
func WithEmailVerificationCodeGenerator(g CodeGenerator) Option {
	return func(op *Options) {
		op.Auth.EmailVerification.CodeGenerator = g
	}
}

// WithEmailVerificationCodeDuration sets how long verification codes remain valid (code mode).
//
// Example:
//
//	server := servex.New(servex.WithEmailVerificationCodeDuration(5 * time.Minute))
//
// Default: 10m.
func WithEmailVerificationCodeDuration(d time.Duration) Option {
	return func(op *Options) {
		op.Auth.EmailVerification.CodeDuration = d
	}
}

// WithEmailVerificationTokenDuration sets how long verification tokens remain valid (token mode).
//
// Example:
//
//	server := servex.New(servex.WithEmailVerificationTokenDuration(48 * time.Hour))
//
// Default: 24h.
func WithEmailVerificationTokenDuration(d time.Duration) Option {
	return func(op *Options) {
		op.Auth.EmailVerification.TokenDuration = d
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
		op.Auth.EmailVerification.ResendCooldown = d
	}
}

// WithPasswordResetTokenDuration sets how long password reset tokens are valid.
//
// Example:
//
//	server := servex.New(servex.WithPasswordResetTokenDuration(30 * time.Minute))
//
// Default: 1h.
func WithPasswordResetTokenDuration(d time.Duration) Option {
	return func(op *Options) {
		op.Auth.PasswordReset.TokenDuration = d
	}
}

// WithPasswordResetResendCooldown sets the minimum interval between password reset email resends.
// This prevents email flooding abuse by limiting how frequently a user can request reset tokens.
// Default: 60s.
func WithPasswordResetResendCooldown(d time.Duration) Option {
	return func(op *Options) {
		op.Auth.PasswordReset.ResendCooldown = d
	}
}

// WithEmailVerificationConfig sets the complete email verification configuration.
// Use this when you need to configure multiple verification settings at once
// or when loading configuration from files or environment variables.
//
// Example:
//
//	cfg := servex.EmailVerificationConfig{
//		Enabled:             true,
//		RequireVerification: true,
//		Mode:                servex.EmailVerificationCodeMode,
//		CodeDigits:          6,
//		CodeDuration:        10 * time.Minute,
//		ResendCooldown:      time.Minute,
//	}
//	server := servex.New(servex.WithEmailVerificationConfig(cfg))
func WithEmailVerificationConfig(cfg EmailVerificationConfig) Option {
	return func(op *Options) {
		op.Auth.EmailVerification = cfg
	}
}

// WithPasswordResetConfig sets the complete password reset configuration.
// Use this when you need to configure multiple password reset settings at once
// or when loading configuration from files or environment variables.
//
// Example:
//
//	cfg := servex.PasswordResetConfig{
//		Enabled:       true,
//		TokenDuration: 30 * time.Minute,
//	}
//	server := servex.New(servex.WithPasswordResetConfig(cfg))
func WithPasswordResetConfig(cfg PasswordResetConfig) Option {
	return func(op *Options) {
		op.Auth.PasswordReset = cfg
	}
}
