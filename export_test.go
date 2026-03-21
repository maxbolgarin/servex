package servex

import "errors"

// ExportGenerateEmailToken exposes generateEmailToken for testing.
var ExportGenerateEmailToken = generateEmailToken

// ErrMockEmail is a sentinel error for testing email sending failures.
var ErrMockEmail = errors.New("simulated email error")

// ExportAppleGenerateClientSecret exposes AppleOAuthProvider.generateClientSecret for testing.
func ExportAppleGenerateClientSecret(p *AppleOAuthProvider) (string, error) {
	return p.generateClientSecret()
}
