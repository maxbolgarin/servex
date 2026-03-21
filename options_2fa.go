package servex

import "time"

// TwoFactorConfig configures TOTP and email code 2FA.
type TwoFactorConfig struct {
	// Enabled activates two-factor authentication features.
	Enabled bool

	// Issuer is the issuer name displayed in TOTP authenticator apps (e.g. Google Authenticator).
	// This helps users identify which service the TOTP code belongs to.
	Issuer string

	// EmailFallback enables email-based 2FA codes as an alternative to TOTP.
	// Requires email features to be configured. Default: true.
	EmailFallback bool

	// CodeDuration is how long email-based 2FA codes remain valid.
	// Default: 10m.
	CodeDuration time.Duration

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
// Requires email features to be configured via WithEmailSender or WithEmailSMTP.
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
