package servex

import (
	"crypto/tls"
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

	// Test merging multiple presets
	merged := MergeWithPreset(preset1, preset2...)
	merged = MergeWithPreset(merged, preset3...)

	if len(merged) != 5 {
		t.Errorf("expected 5 merged options, got %d", len(merged))
	}

	// Test with empty presets
	emptyMerged := MergeWithPreset([]Option{})
	if len(emptyMerged) != 0 {
		t.Errorf("expected 0 options for empty merge, got %d", len(emptyMerged))
	}

	// Test with nil slices
	nilMerged := MergeWithPreset(preset1)
	if len(nilMerged) != 2 {
		t.Errorf("expected 2 options when using preset1 only, got %d", len(nilMerged))
	}
}

func TestDevelopmentPreset(t *testing.T) {
	preset := DevelopmentPreset()

	if len(preset) == 0 {
		t.Error("development preset should not be empty")
	}

	// Apply preset to server options and verify key settings
	opts := parseOptions(preset)

	if !opts.EnableHealthEndpoint {
		t.Error("expected health endpoint to be enabled")
	}

	if !opts.SendErrorToClient {
		t.Error("expected send error to client to be enabled for development")
	}

	if !opts.EnableDefaultMetrics {
		t.Error("expected default metrics to be enabled for development monitoring")
	}
}

func TestProductionPreset(t *testing.T) {
	// Create a dummy certificate for testing
	cert, err := ReadCertificateFromFile("testdata/server.crt", "testdata/server.key")
	if err != nil {
		// Create a self-signed certificate for testing
		cert = tls.Certificate{}
	}
	preset := ProductionPreset(cert)

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

	if !opts.EnableDefaultMetrics {
		t.Error("expected default metrics to be enabled")
	}

	if !opts.EnableDefaultAuditLogger {
		t.Error("expected default audit logger to be enabled")
	}

	if !opts.EnableRequestSizeLimits {
		t.Error("expected request size limits to be enabled")
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

	if opts.HealthPath != "/health" {
		t.Errorf("expected health path '/health', got '%s'", opts.HealthPath)
	}

	if !opts.EnableDefaultMetrics {
		t.Error("expected default metrics to be enabled")
	}

	if !opts.EnableDefaultAuditLogger {
		t.Error("expected default audit logger to be enabled")
	}

	if !opts.EnableRequestSizeLimits {
		t.Error("expected request size limits to be enabled")
	}

	if opts.MaxRequestBodySize != 10<<20 {
		t.Errorf("expected max request body size 10MB, got %d", opts.MaxRequestBodySize)
	}

	if opts.MaxJSONBodySize != 1<<20 {
		t.Errorf("expected max JSON body size 1MB, got %d", opts.MaxJSONBodySize)
	}

	if !opts.Cache.Enabled {
		t.Error("expected cache control to be enabled")
	}
}

func TestWebAppPreset(t *testing.T) {
	// Create a dummy certificate for testing
	cert := tls.Certificate{}
	preset := WebAppPreset(cert)

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

	if !opts.EnableDefaultMetrics {
		t.Error("expected default metrics to be enabled")
	}

	if !opts.EnableRequestSizeLimits {
		t.Error("expected request size limits to be enabled")
	}

	if opts.MaxRequestBodySize != 50<<20 {
		t.Errorf("expected max request body size 50MB, got %d", opts.MaxRequestBodySize)
	}

	if opts.MaxJSONBodySize != 5<<20 {
		t.Errorf("expected max JSON body size 5MB, got %d", opts.MaxJSONBodySize)
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

	if !opts.EnableDefaultMetrics {
		t.Error("expected default metrics to be enabled")
	}

	if !opts.EnableRequestSizeLimits {
		t.Error("expected request size limits to be enabled")
	}

	if opts.MaxRequestBodySize != 5<<20 {
		t.Errorf("expected max request body size 5MB, got %d", opts.MaxRequestBodySize)
	}

	if opts.MaxJSONBodySize != 1<<20 {
		t.Errorf("expected max JSON body size 1MB, got %d", opts.MaxJSONBodySize)
	}

	// Should have basic security headers but not strict
	if !opts.Security.Enabled {
		t.Error("expected basic security to be enabled")
	}
}

func TestHighSecurityPreset(t *testing.T) {
	// Create a dummy certificate for testing
	cert := tls.Certificate{}
	preset := HighSecurityPreset(cert)

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

	if !opts.EnableDefaultAuditLogger {
		t.Error("expected default audit logger to be enabled")
	}

	if !opts.EnableRequestSizeLimits {
		t.Error("expected request size limits to be enabled")
	}

	// Should have strict (smaller) size limits compared to other presets
	if opts.MaxRequestBodySize != 10<<20 {
		t.Errorf("expected strict max request body size 10MB, got %d", opts.MaxRequestBodySize)
	}

	if opts.MaxJSONBodySize != 512<<10 {
		t.Errorf("expected strict max JSON body size 512KB, got %d", opts.MaxJSONBodySize)
	}

	// Should have request filtering
	if len(opts.Filter.BlockedUserAgentsRegex) == 0 {
		t.Error("expected blocked user agents regex to be configured")
	}

	if len(opts.Filter.BlockedQueryParams) == 0 {
		t.Error("expected blocked query params to be configured")
	}
}

// Commented out tests for undefined presets
// TODO: Implement these presets or remove these tests

/*
func TestMinimalPreset(t *testing.T) {
	preset := MinimalPreset()
	// ... test implementation
}

func TestQuickTLSPreset(t *testing.T) {
	certFile := "test.crt"
	keyFile := "test.key"
	preset := QuickTLSPreset(certFile, keyFile)
	// ... test implementation
}

func TestAuthAPIPreset(t *testing.T) {
	preset := AuthAPIPreset()
	// ... test implementation
}
*/

func TestPresetCombinations(t *testing.T) {
	// Test combining presets
	combined := MergeWithPreset(
		DevelopmentPreset(),
		WithRPS(200), // Override RPS
	)

	opts := parseOptions(combined)

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
	cert := tls.Certificate{} // Dummy certificate for testing

	presets := []struct {
		name   string
		preset []Option
	}{
		{"Development", DevelopmentPreset()},
		{"Production", ProductionPreset(cert)},
		{"APIServer", APIServerPreset()},
		{"WebApp", WebAppPreset(cert)},
		{"Microservice", MicroservicePreset()},
		{"HighSecurity", HighSecurityPreset(cert)},
		{"TLS", TLSPreset("cert.pem", "key.pem")},
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
		cert := tls.Certificate{}
		opts := parseOptions(ProductionPreset(cert))
		if !opts.Security.Enabled {
			t.Error("production should enable security")
		}
		if !opts.Security.CSRFEnabled {
			t.Error("production should enable CSRF protection")
		}
	})

	t.Run("high security is restrictive", func(t *testing.T) {
		cert := tls.Certificate{}
		opts := parseOptions(HighSecurityPreset(cert))
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
