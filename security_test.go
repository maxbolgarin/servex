package servex_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/maxbolgarin/servex"
)

// TestSecurityHeadersMiddleware tests the security headers middleware functionality.
func TestSecurityHeadersMiddleware(t *testing.T) {
	config := servex.SecurityConfig{
		Enabled:                       true,
		ContentSecurityPolicy:         "default-src 'self'",
		XContentTypeOptions:           "nosniff",
		XFrameOptions:                 "DENY",
		XXSSProtection:                "1; mode=block",
		StrictTransportSecurity:       "max-age=31536000",
		ReferrerPolicy:                "strict-origin-when-cross-origin",
		PermissionsPolicy:             "camera=(), microphone=()",
		XPermittedCrossDomainPolicies: "none",
		CrossOriginEmbedderPolicy:     "require-corp",
		CrossOriginOpenerPolicy:       "same-origin",
		CrossOriginResourcePolicy:     "same-site",
	}

	router := mux.NewRouter()
	servex.RegisterSecurityHeadersMiddleware(router, config)

	// Add a test handler
	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Create a test request
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	// Execute the request
	router.ServeHTTP(rr, req)

	// Verify response
	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	// Verify all security headers are present
	expectedHeaders := map[string]string{
		"Content-Security-Policy":           "default-src 'self'",
		"X-Content-Type-Options":            "nosniff",
		"X-Frame-Options":                   "DENY",
		"X-XSS-Protection":                  "1; mode=block",
		"Strict-Transport-Security":         "max-age=31536000",
		"Referrer-Policy":                   "strict-origin-when-cross-origin",
		"Permissions-Policy":                "camera=(), microphone=()",
		"X-Permitted-Cross-Domain-Policies": "none",
		"Cross-Origin-Embedder-Policy":      "require-corp",
		"Cross-Origin-Opener-Policy":        "same-origin",
		"Cross-Origin-Resource-Policy":      "same-site",
	}

	for headerName, expectedValue := range expectedHeaders {
		actualValue := rr.Header().Get(headerName)
		if actualValue != expectedValue {
			t.Errorf("expected header %s to be %q, got %q", headerName, expectedValue, actualValue)
		}
	}
}

// TestSecurityHeadersDisabled tests that no headers are applied when security is disabled.
func TestSecurityHeadersDisabled(t *testing.T) {
	config := servex.SecurityConfig{
		Enabled:               false, // Disabled
		ContentSecurityPolicy: "default-src 'self'",
		XContentTypeOptions:   "nosniff",
	}

	router := mux.NewRouter()
	servex.RegisterSecurityHeadersMiddleware(router, config)

	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Verify no security headers are present
	securityHeaders := []string{
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Strict-Transport-Security",
		"Referrer-Policy",
	}

	for _, headerName := range securityHeaders {
		if value := rr.Header().Get(headerName); value != "" {
			t.Errorf("expected header %s to be empty when security is disabled, got %q", headerName, value)
		}
	}
}

// TestSecurityHeadersPathExclusion tests that excluded paths don't receive security headers.
func TestSecurityHeadersPathExclusion(t *testing.T) {
	config := servex.SecurityConfig{
		Enabled:             true,
		XContentTypeOptions: "nosniff",
		XFrameOptions:       "DENY",
		ExcludePaths:        []string{"/api/*", "/health"},
	}

	router := mux.NewRouter()
	servex.RegisterSecurityHeadersMiddleware(router, config)

	// Add test handlers
	router.HandleFunc("/app/page", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	router.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		path              string
		shouldHaveHeaders bool
		description       string
	}{
		{"/app/page", true, "regular path should have headers"},
		{"/api/data", false, "excluded API path should not have headers"},
		{"/health", false, "excluded health path should not have headers"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			hasHeaders := rr.Header().Get("X-Content-Type-Options") != ""
			if hasHeaders != tt.shouldHaveHeaders {
				t.Errorf("path %s: expected headers present = %v, got %v", tt.path, tt.shouldHaveHeaders, hasHeaders)
			}
		})
	}
}

// TestSecurityHeadersPathInclusion tests that only included paths receive security headers.
func TestSecurityHeadersPathInclusion(t *testing.T) {
	config := servex.SecurityConfig{
		Enabled:             true,
		XContentTypeOptions: "nosniff",
		XFrameOptions:       "DENY",
		IncludePaths:        []string{"/app/*", "/secure/*"},
	}

	router := mux.NewRouter()
	servex.RegisterSecurityHeadersMiddleware(router, config)

	// Add test handlers
	router.HandleFunc("/app/page", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	router.HandleFunc("/secure/data", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	router.HandleFunc("/public/info", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		path              string
		shouldHaveHeaders bool
		description       string
	}{
		{"/app/page", true, "included app path should have headers"},
		{"/secure/data", true, "included secure path should have headers"},
		{"/public/info", false, "non-included public path should not have headers"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			hasHeaders := rr.Header().Get("X-Content-Type-Options") != ""
			if hasHeaders != tt.shouldHaveHeaders {
				t.Errorf("path %s: expected headers present = %v, got %v", tt.path, tt.shouldHaveHeaders, hasHeaders)
			}
		})
	}
}

// TestSecurityHeadersIncludeAndExcludePaths tests the interaction between include and exclude paths.
func TestSecurityHeadersIncludeAndExcludePaths(t *testing.T) {
	config := servex.SecurityConfig{
		Enabled:             true,
		XContentTypeOptions: "nosniff",
		IncludePaths:        []string{"/app/*"},
		ExcludePaths:        []string{"/app/public/*"},
	}

	router := mux.NewRouter()
	servex.RegisterSecurityHeadersMiddleware(router, config)

	// Add test handlers
	router.HandleFunc("/app/private", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	router.HandleFunc("/app/public/data", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	router.HandleFunc("/other/page", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		path              string
		shouldHaveHeaders bool
		description       string
	}{
		{"/app/private", true, "included but not excluded path should have headers"},
		{"/app/public/data", false, "included but explicitly excluded path should not have headers"},
		{"/other/page", false, "not included path should not have headers"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			hasHeaders := rr.Header().Get("X-Content-Type-Options") != ""
			if hasHeaders != tt.shouldHaveHeaders {
				t.Errorf("path %s: expected headers present = %v, got %v", tt.path, tt.shouldHaveHeaders, hasHeaders)
			}
		})
	}
}

// TestSecurityHeadersWildcardPatterns tests wildcard pattern matching in paths.
func TestSecurityHeadersWildcardPatterns(t *testing.T) {
	config := servex.SecurityConfig{
		Enabled:             true,
		XContentTypeOptions: "nosniff",
		ExcludePaths:        []string{"/api/v*/public", "/static/*.css"},
	}

	router := mux.NewRouter()
	servex.RegisterSecurityHeadersMiddleware(router, config)

	// Add test handlers for different path patterns
	paths := []string{
		"/api/v1/public",
		"/api/v2/public",
		"/api/v1/private",
		"/static/style.css",
		"/static/app.js",
		"/app/page",
	}

	for _, path := range paths {
		// Create a closure to capture the path variable
		currentPath := path
		router.HandleFunc(currentPath, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}

	tests := []struct {
		path              string
		shouldHaveHeaders bool
		description       string
	}{
		{"/api/v1/public", false, "should match /api/v*/public pattern"},
		{"/api/v2/public", false, "should match /api/v*/public pattern"},
		{"/api/v1/private", true, "should not match exclude pattern"},
		{"/static/style.css", false, "should match /static/*.css pattern"},
		{"/static/app.js", true, "should not match *.css pattern"},
		{"/app/page", true, "should not match any exclude pattern"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			hasHeaders := rr.Header().Get("X-Content-Type-Options") != ""
			if hasHeaders != tt.shouldHaveHeaders {
				t.Errorf("path %s: expected headers present = %v, got %v", tt.path, tt.shouldHaveHeaders, hasHeaders)
			}
		})
	}
}

// TestCustomHeadersMiddleware tests that custom headers are properly applied.
func TestCustomHeadersMiddleware(t *testing.T) {
	customHeaders := map[string]string{
		"X-API-Version":   "v1.0",
		"X-Service-Name":  "test-service",
		"X-Custom-Header": "custom-value",
		"Cache-Control":   "no-cache", // Should be able to override standard headers
	}

	router := mux.NewRouter()
	servex.RegisterCustomHeadersMiddleware(router, customHeaders)

	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Verify all custom headers are present
	for headerName, expectedValue := range customHeaders {
		actualValue := rr.Header().Get(headerName)
		if actualValue != expectedValue {
			t.Errorf("expected custom header %s to be %q, got %q", headerName, expectedValue, actualValue)
		}
	}
}

// TestHeaderRemovalMiddleware tests that specified headers are removed.
func TestHeaderRemovalMiddleware(t *testing.T) {
	headersToRemove := []string{"Server", "X-Powered-By", "X-AspNet-Version"}

	router := mux.NewRouter()
	servex.RegisterHeaderRemovalMiddleware(router, headersToRemove)

	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		// Simulate headers that might be added by other middleware or the Go standard library
		w.Header().Set("Server", "Go HTTP Server")
		w.Header().Set("X-Powered-By", "Go/1.21")
		w.Header().Set("X-AspNet-Version", "4.0.30319")
		w.Header().Set("X-Keep-This", "should-remain")

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Verify specified headers are removed
	for _, headerName := range headersToRemove {
		if value := rr.Header().Get(headerName); value != "" {
			t.Errorf("expected header %s to be removed, but got value %q", headerName, value)
		}
	}

	// Verify other headers remain
	if value := rr.Header().Get("X-Keep-This"); value != "should-remain" {
		t.Errorf("expected header X-Keep-This to remain with value 'should-remain', got %q", value)
	}
}

// TestSecurityHeadersPartialConfig tests that only configured headers are applied.
func TestSecurityHeadersPartialConfig(t *testing.T) {
	config := servex.SecurityConfig{
		Enabled:             true,
		XContentTypeOptions: "nosniff",
		XFrameOptions:       "DENY",
		// Other headers intentionally not set
	}

	router := mux.NewRouter()
	servex.RegisterSecurityHeadersMiddleware(router, config)

	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Verify configured headers are present
	if value := rr.Header().Get("X-Content-Type-Options"); value != "nosniff" {
		t.Errorf("expected X-Content-Type-Options to be 'nosniff', got %q", value)
	}
	if value := rr.Header().Get("X-Frame-Options"); value != "DENY" {
		t.Errorf("expected X-Frame-Options to be 'DENY', got %q", value)
	}

	// Verify unconfigured headers are not present
	unconfiguredHeaders := []string{
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"X-XSS-Protection",
		"Referrer-Policy",
	}

	for _, headerName := range unconfiguredHeaders {
		if value := rr.Header().Get(headerName); value != "" {
			t.Errorf("expected unconfigured header %s to be empty, got %q", headerName, value)
		}
	}
}

// TestSecurityAndCustomHeadersIntegration tests the interaction between security headers and custom headers.
func TestSecurityAndCustomHeadersIntegration(t *testing.T) {
	securityConfig := servex.SecurityConfig{
		Enabled:             true,
		XContentTypeOptions: "nosniff",
		XFrameOptions:       "DENY",
	}

	customHeaders := map[string]string{
		"X-API-Version":   "v1.0",
		"X-Frame-Options": "SAMEORIGIN", // Should override security header
		"X-Custom-Header": "custom-value",
	}

	headersToRemove := []string{"Server"}

	router := mux.NewRouter()

	// Register middleware in order: security first, then custom headers, then removal
	servex.RegisterSecurityHeadersMiddleware(router, securityConfig)
	servex.RegisterCustomHeadersMiddleware(router, customHeaders)
	servex.RegisterHeaderRemovalMiddleware(router, headersToRemove)

	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Go HTTP Server") // Should be removed
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Verify security headers
	if value := rr.Header().Get("X-Content-Type-Options"); value != "nosniff" {
		t.Errorf("expected X-Content-Type-Options to be 'nosniff', got %q", value)
	}

	// Verify custom header overrode security header
	if value := rr.Header().Get("X-Frame-Options"); value != "SAMEORIGIN" {
		t.Errorf("expected X-Frame-Options to be overridden to 'SAMEORIGIN', got %q", value)
	}

	// Verify custom headers
	if value := rr.Header().Get("X-API-Version"); value != "v1.0" {
		t.Errorf("expected X-API-Version to be 'v1.0', got %q", value)
	}
	if value := rr.Header().Get("X-Custom-Header"); value != "custom-value" {
		t.Errorf("expected X-Custom-Header to be 'custom-value', got %q", value)
	}

	// Verify header was removed
	if value := rr.Header().Get("Server"); value != "" {
		t.Errorf("expected Server header to be removed, got %q", value)
	}
}
