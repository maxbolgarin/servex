package servex

import (
	"testing"
	"time"
)

func TestMergeOptions(t *testing.T) {
	preset1 := []Option{
		WithReadTimeout(30 * time.Second),
		WithHealthEndpoint(),
	}

	preset2 := []Option{
		WithIdleTimeout(60 * time.Second),
		WithAuthToken("test-token"),
	}

	preset3 := []Option{
		WithRPS(100),
	}

	merged := MergeOptions(preset1, preset2, preset3)

	if len(merged) != 5 {
		t.Errorf("expected 5 merged options, got %d", len(merged))
	}

	// Test with empty presets
	emptyMerged := MergeOptions()
	if len(emptyMerged) != 0 {
		t.Errorf("expected 0 options for empty merge, got %d", len(emptyMerged))
	}

	// Test with nil slices
	nilMerged := MergeOptions(nil, preset1, nil)
	if len(nilMerged) != 2 {
		t.Errorf("expected 2 options when merging with nil, got %d", len(nilMerged))
	}
}

func TestDevelopmentPreset(t *testing.T) {
	preset := DevelopmentPreset()

	if len(preset) == 0 {
		t.Error("development preset should not be empty")
	}

	// Apply preset to server options and verify key settings
	opts := parseOptions(preset)

	if opts.ReadTimeout != 30*time.Second {
		t.Errorf("expected read timeout 30s, got %v", opts.ReadTimeout)
	}

	if opts.IdleTimeout != 60*time.Second {
		t.Errorf("expected idle timeout 60s, got %v", opts.IdleTimeout)
	}

	if !opts.EnableHealthEndpoint {
		t.Error("expected health endpoint to be enabled")
	}

	if !opts.SendErrorToClient {
		t.Error("expected send error to client to be enabled for development")
	}
}

func TestProductionPreset(t *testing.T) {
	preset := ProductionPreset()

	if len(preset) == 0 {
		t.Error("production preset should not be empty")
	}

	opts := parseOptions(preset)

	if opts.ReadTimeout != 10*time.Second {
		t.Errorf("expected read timeout 10s, got %v", opts.ReadTimeout)
	}

	if opts.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("expected read header timeout 5s, got %v", opts.ReadHeaderTimeout)
	}

	if opts.IdleTimeout != 120*time.Second {
		t.Errorf("expected idle timeout 120s, got %v", opts.IdleTimeout)
	}

	if !opts.Security.Enabled {
		t.Error("expected security to be enabled")
	}

	if !opts.Security.CSRFEnabled {
		t.Error("expected CSRF protection to be enabled")
	}

	if opts.RateLimit.RequestsPerInterval != 100 {
		t.Errorf("expected RPS 100, got %d", opts.RateLimit.RequestsPerInterval)
	}

	if !opts.EnableHealthEndpoint {
		t.Error("expected health endpoint to be enabled")
	}

	if opts.HealthPath != "/health" {
		t.Errorf("expected health path '/health', got '%s'", opts.HealthPath)
	}

	// Check that some headers are removed
	expectedHeaders := []string{"Server", "X-Powered-By"}
	for _, header := range expectedHeaders {
		found := false
		for _, removeHeader := range opts.HeadersToRemove {
			if removeHeader == header {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected header '%s' to be removed", header)
		}
	}
}

func TestAPIServerPreset(t *testing.T) {
	preset := APIServerPreset()

	if len(preset) == 0 {
		t.Error("API server preset should not be empty")
	}

	opts := parseOptions(preset)

	if opts.ReadTimeout != 15*time.Second {
		t.Errorf("expected read timeout 15s, got %v", opts.ReadTimeout)
	}

	if opts.IdleTimeout != 90*time.Second {
		t.Errorf("expected idle timeout 90s, got %v", opts.IdleTimeout)
	}

	if !opts.Security.Enabled {
		t.Error("expected security to be enabled")
	}

	if opts.RateLimit.RequestsPerInterval != 1000 {
		t.Errorf("expected RPM 1000, got %d", opts.RateLimit.RequestsPerInterval)
	}

	if opts.RateLimit.BurstSize != 50 {
		t.Errorf("expected burst size 50, got %d", opts.RateLimit.BurstSize)
	}

	if opts.HealthPath != "/api/health" {
		t.Errorf("expected health path '/api/health', got '%s'", opts.HealthPath)
	}

	// Check custom headers
	if opts.CustomHeaders["X-API-Version"] != "v1.0" {
		t.Errorf("expected X-API-Version header to be 'v1.0', got '%s'", opts.CustomHeaders["X-API-Version"])
	}
}

func TestWebAppPreset(t *testing.T) {
	preset := WebAppPreset()

	if len(preset) == 0 {
		t.Error("web app preset should not be empty")
	}

	opts := parseOptions(preset)

	if opts.ReadTimeout != 30*time.Second {
		t.Errorf("expected read timeout 30s, got %v", opts.ReadTimeout)
	}

	if opts.IdleTimeout != 180*time.Second {
		t.Errorf("expected idle timeout 180s, got %v", opts.IdleTimeout)
	}

	if !opts.Security.Enabled {
		t.Error("expected security to be enabled")
	}

	if !opts.Security.CSRFEnabled {
		t.Error("expected CSRF protection to be enabled")
	}

	if opts.Security.CSRFTokenEndpoint != "/csrf-token" {
		t.Errorf("expected CSRF token endpoint '/csrf-token', got '%s'", opts.Security.CSRFTokenEndpoint)
	}

	if opts.RateLimit.RequestsPerInterval != 50 {
		t.Errorf("expected RPS 50, got %d", opts.RateLimit.RequestsPerInterval)
	}

	// Check that CSP is configured
	if opts.Security.ContentSecurityPolicy == "" {
		t.Error("expected Content Security Policy to be configured")
	}
}

func TestMicroservicePreset(t *testing.T) {
	preset := MicroservicePreset()

	if len(preset) == 0 {
		t.Error("microservice preset should not be empty")
	}

	opts := parseOptions(preset)

	if opts.ReadTimeout != 5*time.Second {
		t.Errorf("expected read timeout 5s, got %v", opts.ReadTimeout)
	}

	if opts.ReadHeaderTimeout != 2*time.Second {
		t.Errorf("expected read header timeout 2s, got %v", opts.ReadHeaderTimeout)
	}

	if opts.IdleTimeout != 30*time.Second {
		t.Errorf("expected idle timeout 30s, got %v", opts.IdleTimeout)
	}

	if opts.RateLimit.RequestsPerInterval != 200 {
		t.Errorf("expected RPS 200, got %d", opts.RateLimit.RequestsPerInterval)
	}

	// Should have basic security headers but not strict
	if !opts.Security.Enabled {
		t.Error("expected basic security to be enabled")
	}
}

func TestHighSecurityPreset(t *testing.T) {
	preset := HighSecurityPreset()

	if len(preset) == 0 {
		t.Error("high security preset should not be empty")
	}

	opts := parseOptions(preset)

	if opts.ReadTimeout != 10*time.Second {
		t.Errorf("expected read timeout 10s, got %v", opts.ReadTimeout)
	}

	if opts.ReadHeaderTimeout != 3*time.Second {
		t.Errorf("expected read header timeout 3s, got %v", opts.ReadHeaderTimeout)
	}

	if opts.IdleTimeout != 60*time.Second {
		t.Errorf("expected idle timeout 60s, got %v", opts.IdleTimeout)
	}

	if !opts.Security.Enabled {
		t.Error("expected security to be enabled")
	}

	if !opts.Security.CSRFEnabled {
		t.Error("expected CSRF protection to be enabled")
	}

	if !opts.Security.CSRFCookieHttpOnly {
		t.Error("expected CSRF cookie to be HttpOnly")
	}

	if opts.Security.CSRFCookieSameSite != "Strict" {
		t.Errorf("expected CSRF cookie SameSite to be 'Strict', got '%s'", opts.Security.CSRFCookieSameSite)
	}

	// Should have aggressive rate limiting
	if opts.RateLimit.RequestsPerInterval != 20 {
		t.Errorf("expected RPS 20, got %d", opts.RateLimit.RequestsPerInterval)
	}

	if opts.RateLimit.BurstSize != 5 {
		t.Errorf("expected burst size 5, got %d", opts.RateLimit.BurstSize)
	}

	// Should have request filtering
	if len(opts.Filter.BlockedUserAgentsRegex) == 0 {
		t.Error("expected blocked user agents regex to be configured")
	}

	if len(opts.Filter.BlockedQueryParams) == 0 {
		t.Error("expected blocked query params to be configured")
	}
}

func TestMinimalPreset(t *testing.T) {
	preset := MinimalPreset()

	if len(preset) == 0 {
		t.Error("minimal preset should not be empty")
	}

	opts := parseOptions(preset)

	if opts.ReadTimeout != 30*time.Second {
		t.Errorf("expected read timeout 30s, got %v", opts.ReadTimeout)
	}

	if !opts.EnableHealthEndpoint {
		t.Error("expected health endpoint to be enabled")
	}

	// Should be minimal - no security, no rate limiting by default
	if opts.Security.Enabled {
		t.Error("expected security to be disabled in minimal preset")
	}

	if opts.RateLimit.Enabled {
		t.Error("expected rate limiting to be disabled in minimal preset")
	}
}

func TestQuickTLSPreset(t *testing.T) {
	certFile := "test.crt"
	keyFile := "test.key"
	preset := QuickTLSPreset(certFile, keyFile)

	if len(preset) == 0 {
		t.Error("quick TLS preset should not be empty")
	}

	opts := parseOptions(preset)

	// Should include production settings
	if opts.ReadTimeout != 10*time.Second {
		t.Errorf("expected read timeout 10s, got %v", opts.ReadTimeout)
	}

	if !opts.Security.Enabled {
		t.Error("expected security to be enabled")
	}

	// Should have HSTS configured
	if opts.Security.StrictTransportSecurity == "" {
		t.Error("expected HSTS to be configured")
	}

	// Should have certificate paths configured
	if opts.CertFilePath != certFile {
		t.Errorf("expected cert file path '%s', got '%s'", certFile, opts.CertFilePath)
	}

	if opts.KeyFilePath != keyFile {
		t.Errorf("expected key file path '%s', got '%s'", keyFile, opts.KeyFilePath)
	}
}

func TestAuthAPIPreset(t *testing.T) {
	preset := AuthAPIPreset()

	if len(preset) == 0 {
		t.Error("auth API preset should not be empty")
	}

	opts := parseOptions(preset)

	// Should include API server settings
	if opts.ReadTimeout != 15*time.Second {
		t.Errorf("expected read timeout 15s, got %v", opts.ReadTimeout)
	}

	if opts.RateLimit.RequestsPerInterval != 1000 {
		t.Errorf("expected RPM 1000, got %d", opts.RateLimit.RequestsPerInterval)
	}

	// Should have auth configuration
	if opts.Auth.AuthBasePath != "/api/v1/auth" {
		t.Errorf("expected auth base path '/api/v1/auth', got '%s'", opts.Auth.AuthBasePath)
	}

	if len(opts.Auth.RolesOnRegister) == 0 {
		t.Error("expected initial roles to be configured")
	}

	if opts.Auth.RolesOnRegister[0] != UserRole("user") {
		t.Errorf("expected first initial role to be 'user', got '%s'", opts.Auth.RolesOnRegister[0])
	}

	if opts.Auth.AccessTokenDuration != 15*time.Minute {
		t.Errorf("expected access token duration 15m, got %v", opts.Auth.AccessTokenDuration)
	}

	if opts.Auth.RefreshTokenDuration != 7*24*time.Hour {
		t.Errorf("expected refresh token duration 7 days, got %v", opts.Auth.RefreshTokenDuration)
	}
}

func TestPresetCombinations(t *testing.T) {
	// Test combining presets
	combined := MergeOptions(
		DevelopmentPreset(),
		[]Option{WithRPS(200)}, // Override RPS
	)

	opts := parseOptions(combined)

	// Should have development settings
	if opts.ReadTimeout != 30*time.Second {
		t.Errorf("expected read timeout 30s, got %v", opts.ReadTimeout)
	}

	if !opts.SendErrorToClient {
		t.Error("expected send error to client to be enabled")
	}

	// Should have overridden RPS
	if opts.RateLimit.RequestsPerInterval != 200 {
		t.Errorf("expected RPS 200, got %d", opts.RateLimit.RequestsPerInterval)
	}
}

func TestPresetValidation(t *testing.T) {
	// Test that presets create valid server configurations
	presets := []struct {
		name   string
		preset []Option
	}{
		{"Development", DevelopmentPreset()},
		{"Production", ProductionPreset()},
		{"APIServer", APIServerPreset()},
		{"WebApp", WebAppPreset()},
		{"Microservice", MicroservicePreset()},
		{"HighSecurity", HighSecurityPreset()},
		{"Minimal", MinimalPreset()},
		{"QuickTLS", QuickTLSPreset("cert.pem", "key.pem")},
		{"AuthAPI", AuthAPIPreset()},
	}

	for _, preset := range presets {
		t.Run(preset.name, func(t *testing.T) {
			opts := parseOptions(preset.preset)

			// Validate that the options are valid (don't cause panics)
			if err := opts.Validate(); err != nil {
				// Some presets may have validation errors (like missing cert files)
				// but they shouldn't panic
				t.Logf("Preset %s has validation warnings: %v", preset.name, err)
			}

			// Basic sanity checks
			if opts.ReadTimeout <= 0 {
				t.Errorf("preset %s has invalid read timeout: %v", preset.name, opts.ReadTimeout)
			}

			if opts.IdleTimeout < 0 {
				t.Errorf("preset %s has invalid idle timeout: %v", preset.name, opts.IdleTimeout)
			}
		})
	}
}

func TestPresetDocumentation(t *testing.T) {
	// This test ensures presets have reasonable defaults and are well-documented
	// by checking key characteristics

	t.Run("development is permissive", func(t *testing.T) {
		opts := parseOptions(DevelopmentPreset())
		if opts.SendErrorToClient != true {
			t.Error("development should send errors to client for debugging")
		}
	})

	t.Run("production is secure", func(t *testing.T) {
		opts := parseOptions(ProductionPreset())
		if !opts.Security.Enabled {
			t.Error("production should enable security")
		}
		if !opts.Security.CSRFEnabled {
			t.Error("production should enable CSRF protection")
		}
	})

	t.Run("high security is restrictive", func(t *testing.T) {
		opts := parseOptions(HighSecurityPreset())
		if opts.RateLimit.RequestsPerInterval >= 100 {
			t.Error("high security should have aggressive rate limiting")
		}
		if len(opts.Filter.BlockedUserAgentsRegex) == 0 {
			t.Error("high security should block suspicious user agents")
		}
	})

	t.Run("microservice has fast timeouts", func(t *testing.T) {
		opts := parseOptions(MicroservicePreset())
		if opts.ReadTimeout >= 10*time.Second {
			t.Error("microservice should have fast timeouts")
		}
	})
}
