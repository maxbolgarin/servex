package servex

import "time"

// CodeGenerator produces one-time verification codes.
// It is used by both email verification (code mode) and 2FA email fallback.
// Each flow configures its own CodeGenerator instance independently.
// Return values should be suitable for the user to type (typically decimal digits).
type CodeGenerator interface {
	Generate() (string, error)
}

type numericCodeGenerator struct {
	digits int
}

// NewNumericCodeGenerator returns a CodeGenerator that emits a uniform random
// decimal string of exactly n digits (leading zeros preserved). If n <= 0, 6 is used.
// Values above 32 are clamped to 32.
//
// This generator is used by default for both email verification codes and 2FA email codes.
func NewNumericCodeGenerator(n int) CodeGenerator {
	if n <= 0 {
		n = 6
	}
	if n > 32 {
		n = 32
	}
	return &numericCodeGenerator{digits: n}
}

func (g *numericCodeGenerator) Generate() (string, error) {
	return generateNumericEmailCode(g.digits)
}

// TwoFactorConfig configures TOTP and email code 2FA.
type TwoFactorConfig struct {
	// Enabled activates two-factor authentication features.
	Enabled bool

	// Issuer is the issuer name displayed in TOTP authenticator apps (e.g. Google Authenticator).
	// This helps users identify which service the TOTP code belongs to.
	Issuer string

	// EmailFallback enables email-based 2FA codes as an alternative to TOTP.
	// When true, users can receive a verification code via email instead of using their
	// authenticator app. Requires EmailSender to be configured.
	// Default: true when 2FA is enabled via WithTwoFactor() or YAML configuration.
	// WithTwoFactorConfig() uses the struct value as-is.
	EmailFallback bool

	// emailFallbackSet records that EmailFallback was set explicitly via
	// WithTwoFactorEmailFallback, so WithTwoFactor does not override it
	// with the default regardless of option order.
	emailFallbackSet bool

	// EmailSender delivers 2FA verification codes via email.
	// This is independent of the email verification and password reset senders,
	// allowing each flow to use a different email delivery implementation.
	// If nil and SMTP is configured, a built-in SMTP sender is used.
	EmailSender TwoFactorEmailSender

	// SMTP configures the built-in SMTP sender for 2FA emails.
	// Ignored if a custom EmailSender is provided.
	SMTP *SMTPConfig

	// CodeDuration is how long email-based 2FA codes remain valid.
	// Default: 10m.
	CodeDuration time.Duration

	// EmailCodeDigits is the length of email-based 2FA codes (decimal digits).
	// Ignored when EmailCodeGenerator is non-nil. Default: 6. Range: 1–32.
	EmailCodeDigits int

	// EmailCodeGenerator, if set, is used to generate email 2FA codes instead of
	// the built-in numeric generator (EmailCodeDigits).
	// Uses the shared CodeGenerator interface.
	EmailCodeGenerator CodeGenerator

	// BackupCodes is the number of one-time backup codes generated when 2FA is enabled.
	// Backup codes allow account recovery if the user loses their authenticator device.
	// Default: 10.
	BackupCodes int

	// EncryptionKey is a hex-encoded 32-byte key for AES-256-GCM encryption of TOTP secrets.
	// TOTP secrets are encrypted at rest using this key.
	EncryptionKey string

	// MaxVerifyAttempts is the maximum number of failed 2FA verification attempts before lockout.
	// Default: 5.
	MaxVerifyAttempts int

	// encryptionKey is the decoded encryption key (internal use).
	encryptionKey []byte
}

// WithTwoFactor enables two-factor authentication with the given encryption key.
// The key must be a hex-encoded 32-byte string for AES-256-GCM encryption of TOTP secrets.
//
// Example:
//
//	server := servex.New(servex.WithTwoFactor(os.Getenv("TOTP_ENCRYPTION_KEY")))
func WithTwoFactor(encryptionKey string) Option {
	return func(op *Options) {
		op.Auth.TwoFactor.Enabled = true
		op.Auth.TwoFactor.EncryptionKey = encryptionKey
		if !op.Auth.TwoFactor.emailFallbackSet {
			op.Auth.TwoFactor.EmailFallback = true
		}
	}
}

// WithTwoFactorIssuer sets the issuer name displayed in TOTP authenticator apps.
//
// Example:
//
//	server := servex.New(
//		servex.WithTwoFactor(encKey),
//		servex.WithTwoFactorIssuer("My Application"),
//	)
func WithTwoFactorIssuer(name string) Option {
	return func(op *Options) {
		op.Auth.TwoFactor.Issuer = name
	}
}

// WithTwoFactorEmailFallback sets whether email-based 2FA codes are available as a fallback.
// Requires a TwoFactorEmailSender to be configured via WithTwoFactorEmailSender or WithTwoFactorEmailSMTP.
//
// Example:
//
//	// Disable email fallback (TOTP only)
//	server := servex.New(servex.WithTwoFactorEmailFallback(false))
//
// Default: true.
func WithTwoFactorEmailFallback(enabled bool) Option {
	return func(op *Options) {
		op.Auth.TwoFactor.EmailFallback = enabled
		op.Auth.TwoFactor.emailFallbackSet = true
	}
}

// WithTwoFactorEmailSender sets a custom email sender for delivering 2FA verification codes.
// This sender is independent of the email verification and password reset senders.
//
// Example:
//
//	server := servex.New(
//		servex.WithTwoFactor(encKey),
//		servex.WithTwoFactorEmailSender(myCustom2FASender),
//	)
func WithTwoFactorEmailSender(sender TwoFactorEmailSender) Option {
	return func(op *Options) {
		op.Auth.TwoFactor.EmailSender = sender
	}
}

// WithTwoFactorEmailSMTP configures a built-in SMTP sender for delivering 2FA verification codes.
// The TwoFactorCodeSubject field of SMTPConfig is used as the email subject line.
//
// Example:
//
//	server := servex.New(
//		servex.WithTwoFactor(encKey),
//		servex.WithTwoFactorEmailSMTP(servex.SMTPConfig{
//			Host: "smtp.example.com", Port: 587,
//			Username: "noreply@example.com",
//			Password: os.Getenv("SMTP_PASSWORD"),
//			From:     "noreply@example.com",
//		}),
//	)
func WithTwoFactorEmailSMTP(cfg SMTPConfig) Option {
	return func(op *Options) {
		op.Auth.TwoFactor.SMTP = &cfg
	}
}

// WithTwoFactorBackupCodes sets the number of one-time backup codes generated when 2FA is enabled.
// Backup codes allow account recovery if the user loses their authenticator device.
//
// Example:
//
//	server := servex.New(servex.WithTwoFactorBackupCodes(12))
//
// Default: 10.
func WithTwoFactorBackupCodes(count int) Option {
	return func(op *Options) {
		op.Auth.TwoFactor.BackupCodes = count
	}
}

// WithTwoFactorCodeDuration sets how long email-based 2FA codes remain valid.
//
// Example:
//
//	server := servex.New(servex.WithTwoFactorCodeDuration(5 * time.Minute))
//
// Default: 10m.
func WithTwoFactorCodeDuration(d time.Duration) Option {
	return func(op *Options) {
		op.Auth.TwoFactor.CodeDuration = d
	}
}

// WithTwoFactorEmailCodeDigits sets the number of decimal digits in email-based 2FA codes.
// Ignored if WithTwoFactorEmailCodeGenerator is used. Default: 6. Valid range: 1–32.
func WithTwoFactorEmailCodeDigits(n int) Option {
	return func(op *Options) {
		op.Auth.TwoFactor.EmailCodeDigits = n
	}
}

// WithTwoFactorEmailCodeGenerator sets a custom generator for email-based 2FA codes.
// When non-nil, EmailCodeDigits is ignored for code generation.
// Uses the shared CodeGenerator interface, which is also used by email verification.
func WithTwoFactorEmailCodeGenerator(g CodeGenerator) Option {
	return func(op *Options) {
		op.Auth.TwoFactor.EmailCodeGenerator = g
	}
}

// WithTwoFactorMaxAttempts sets the maximum number of failed 2FA verification attempts
// before the user is locked out.
//
// Example:
//
//	server := servex.New(servex.WithTwoFactorMaxAttempts(3))
//
// Default: 5.
func WithTwoFactorMaxAttempts(n int) Option {
	return func(op *Options) {
		op.Auth.TwoFactor.MaxVerifyAttempts = n
	}
}

// WithTwoFactorConfig sets the complete two-factor authentication configuration.
// Use this when you need to configure multiple 2FA settings at once
// or when loading configuration from files or environment variables.
//
// The struct is used as-is: unlike WithTwoFactor(), no EmailFallback default
// is applied, so set EmailFallback explicitly when email codes are wanted.
//
// Example:
//
//	tfaCfg := servex.TwoFactorConfig{
//		Enabled:           true,
//		Issuer:            "My Application",
//		EmailFallback:     true,
//		CodeDuration:      5 * time.Minute,
//		BackupCodes:       12,
//		EncryptionKey:     os.Getenv("TOTP_ENCRYPTION_KEY"),
//		MaxVerifyAttempts: 3,
//	}
//	server := servex.New(servex.WithTwoFactorConfig(tfaCfg))
func WithTwoFactorConfig(cfg TwoFactorConfig) Option {
	return func(op *Options) {
		op.Auth.TwoFactor = cfg
	}
}
