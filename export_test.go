package servex

import (
	"errors"
	"time"
)

// ExportGenerateEmailToken exposes generateEmailToken for testing.
var ExportGenerateEmailToken = generateEmailToken

// ErrMockEmail is a sentinel error for testing email sending failures.
var ErrMockEmail = errors.New("simulated email error")

// ExportAppleGenerateClientSecret exposes AppleOAuthProvider.generateClientSecret for testing.
func ExportAppleGenerateClientSecret(p *AppleOAuthProvider) (string, error) {
	return p.generateClientSecret()
}

// ExportEncryptTOTPSecret exposes encryptTOTPSecret for testing.
var ExportEncryptTOTPSecret = encryptTOTPSecret

// ExportDecryptTOTPSecret exposes decryptTOTPSecret for testing.
var ExportDecryptTOTPSecret = decryptTOTPSecret

// ExportGenerateBackupCodes exposes generateBackupCodes for testing.
var ExportGenerateBackupCodes = generateBackupCodes

// ExportNewAttemptTracker exposes newAttemptTracker for testing.
func ExportNewAttemptTracker() *attemptTracker {
	return newAttemptTracker()
}

// Increment exposes attemptTracker.increment for testing.
func (t *attemptTracker) Increment(jti string) int {
	return t.increment(jti)
}

// GetCount exposes attemptTracker.getCount for testing.
func (t *attemptTracker) GetCount(jti string) int {
	return t.getCount(jti)
}

// Delete exposes attemptTracker.delete for testing.
func (t *attemptTracker) Delete(jti string) {
	t.delete(jti)
}

// CanSendEmail exposes attemptTracker.canSendEmail for testing.
func (t *attemptTracker) CanSendEmail(jti string, cooldown time.Duration) bool {
	return t.canSendEmail(jti, cooldown)
}

// MarkEmailSent exposes attemptTracker.markEmailSent for testing.
func (t *attemptTracker) MarkEmailSent(jti string, codeHash string) {
	t.markEmailSent(jti, codeHash)
}

// GetEmailCodeHash exposes attemptTracker.getEmailCodeHash for testing.
func (t *attemptTracker) GetEmailCodeHash(jti string) string {
	return t.getEmailCodeHash(jti)
}

// StopAttemptTracker stops the attempt tracker, safe to call when tracker is nil.
func (m *AuthManager) StopAttemptTracker() {
	if m.attemptTracker != nil {
		m.attemptTracker.Stop()
	}
}
