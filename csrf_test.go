package servex

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func TestCSRFProtection(t *testing.T) {
	t.Run("CSRF middleware disabled by default", func(t *testing.T) {
		router := mux.NewRouter()
		RegisterSecurityHeadersMiddleware(router, SecurityConfig{Enabled: true})

		// Create a POST request without CSRF token
		req := httptest.NewRequest("POST", "/test", strings.NewReader("data=test"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should not be blocked since CSRF is disabled
		if w.Code == http.StatusForbidden {
			t.Error("Request should not be blocked when CSRF is disabled")
		}
	})

	t.Run("CSRF protection blocks requests without token", func(t *testing.T) {
		router := mux.NewRouter()
		config := SecurityConfig{
			Enabled:     true,
			CSRFEnabled: true,
		}
		RegisterSecurityHeadersMiddleware(router, config)

		// Add a test handler
		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}).Methods("POST")

		// Create a POST request without CSRF token
		req := httptest.NewRequest("POST", "/test", strings.NewReader("data=test"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should be blocked
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status 403, got %d", w.Code)
		}

		if !strings.Contains(w.Body.String(), "CSRF token validation failed") {
			t.Error("Expected CSRF error message")
		}
	})

	t.Run("Safe methods bypass CSRF protection", func(t *testing.T) {
		router := mux.NewRouter()
		config := SecurityConfig{
			Enabled:     true,
			CSRFEnabled: true,
		}
		RegisterSecurityHeadersMiddleware(router, config)

		// Add a test handler
		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}).Methods("GET", "POST")

		// Test safe methods
		safeMethods := []string{"GET", "HEAD", "OPTIONS", "TRACE"}
		for _, method := range safeMethods {
			req := httptest.NewRequest(method, "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code == http.StatusForbidden {
				t.Errorf("Safe method %s should not be blocked by CSRF", method)
			}
		}
	})

	t.Run("CSRF token endpoint returns valid token", func(t *testing.T) {
		router := mux.NewRouter()
		config := SecurityConfig{
			Enabled:           true,
			CSRFEnabled:       true,
			CSRFTokenEndpoint: "/csrf-token",
		}
		RegisterSecurityHeadersMiddleware(router, config)

		// Request CSRF token
		req := httptest.NewRequest("GET", "/csrf-token", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Check response content type
		if w.Header().Get("Content-Type") != "application/json" {
			t.Error("Expected JSON content type")
		}

		// Check that a cookie was set
		cookies := w.Result().Cookies()
		var csrfCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "csrf_token" {
				csrfCookie = cookie
				break
			}
		}

		if csrfCookie == nil {
			t.Error("Expected CSRF cookie to be set")
		}

		if csrfCookie.Value == "" {
			t.Error("CSRF cookie should have a value")
		}

		// Check JSON response
		body := w.Body.String()
		if !strings.Contains(body, "csrf_token") {
			t.Error("Response should contain csrf_token field")
		}
	})

	t.Run("Valid CSRF token allows request", func(t *testing.T) {
		router := mux.NewRouter()
		config := SecurityConfig{
			Enabled:           true,
			CSRFEnabled:       true,
			CSRFTokenEndpoint: "/csrf-token",
		}
		RegisterSecurityHeadersMiddleware(router, config)

		// Add a test handler
		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}).Methods("POST")

		// First, get a CSRF token
		tokenReq := httptest.NewRequest("GET", "/csrf-token", nil)
		tokenW := httptest.NewRecorder()
		router.ServeHTTP(tokenW, tokenReq)

		// Extract token from cookie
		cookies := tokenW.Result().Cookies()
		var token string
		for _, cookie := range cookies {
			if cookie.Name == "csrf_token" {
				token = cookie.Value
				break
			}
		}

		if token == "" {
			t.Fatal("Could not get CSRF token")
		}

		// Now make a POST request with the token in header
		req := httptest.NewRequest("POST", "/test", strings.NewReader("data=test"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-CSRF-Token", token)
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		if w.Body.String() != "success" {
			t.Error("Expected success response")
		}
	})

	t.Run("CSRF token in form field", func(t *testing.T) {
		router := mux.NewRouter()
		config := SecurityConfig{
			Enabled:           true,
			CSRFEnabled:       true,
			CSRFTokenEndpoint: "/csrf-token",
		}
		RegisterSecurityHeadersMiddleware(router, config)

		// Add a test handler
		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}).Methods("POST")

		// Get CSRF token
		tokenReq := httptest.NewRequest("GET", "/csrf-token", nil)
		tokenW := httptest.NewRecorder()
		router.ServeHTTP(tokenW, tokenReq)

		cookies := tokenW.Result().Cookies()
		var token string
		for _, cookie := range cookies {
			if cookie.Name == "csrf_token" {
				token = cookie.Value
				break
			}
		}

		// Make POST request with token in form field
		formData := url.Values{}
		formData.Set("X-CSRF-Token", token)
		formData.Set("data", "test")

		req := httptest.NewRequest("POST", "/test", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Custom CSRF configuration", func(t *testing.T) {
		router := mux.NewRouter()
		config := SecurityConfig{
			Enabled:           true,
			CSRFEnabled:       true,
			CSRFTokenName:     "X-Custom-Token",
			CSRFCookieName:    "custom_csrf",
			CSRFErrorMessage:  "Custom error message",
			CSRFTokenEndpoint: "/custom-token",
		}
		RegisterSecurityHeadersMiddleware(router, config)

		// Add a test handler
		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}).Methods("POST")

		// Test custom endpoint
		tokenReq := httptest.NewRequest("GET", "/custom-token", nil)
		tokenW := httptest.NewRecorder()
		router.ServeHTTP(tokenW, tokenReq)

		if tokenW.Code != http.StatusOK {
			t.Error("Custom token endpoint should work")
		}

		// Check custom cookie name
		cookies := tokenW.Result().Cookies()
		var found bool
		for _, cookie := range cookies {
			if cookie.Name == "custom_csrf" {
				found = true
				break
			}
		}

		if !found {
			t.Error("Expected custom CSRF cookie name")
		}

		// Test custom error message
		req := httptest.NewRequest("POST", "/test", strings.NewReader("data=test"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if !strings.Contains(w.Body.String(), "Custom error message") {
			t.Error("Expected custom error message")
		}
	})

	t.Run("CSRF excluded paths", func(t *testing.T) {
		router := mux.NewRouter()
		config := SecurityConfig{
			Enabled:      true,
			CSRFEnabled:  true,
			ExcludePaths: []string{"/excluded"},
		}
		RegisterSecurityHeadersMiddleware(router, config)

		// Add test handlers
		router.HandleFunc("/excluded", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("excluded"))
		}).Methods("POST")

		router.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("protected"))
		}).Methods("POST")

		// Test excluded path
		excludedReq := httptest.NewRequest("POST", "/excluded", strings.NewReader("data=test"))
		excludedReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w1 := httptest.NewRecorder()
		router.ServeHTTP(w1, excludedReq)

		if w1.Code != http.StatusOK {
			t.Error("Excluded path should not be CSRF protected")
		}

		// Test protected path
		protectedReq := httptest.NewRequest("POST", "/protected", strings.NewReader("data=test"))
		protectedReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w2 := httptest.NewRecorder()
		router.ServeHTTP(w2, protectedReq)

		if w2.Code != http.StatusForbidden {
			t.Error("Protected path should be CSRF protected")
		}
	})
}

func TestCSRFCookieConfiguration(t *testing.T) {
	t.Run("CSRF cookie attributes", func(t *testing.T) {
		router := mux.NewRouter()
		config := SecurityConfig{
			Enabled:            true,
			CSRFEnabled:        true,
			CSRFTokenEndpoint:  "/csrf-token",
			CSRFCookieHttpOnly: true,
			CSRFCookieSecure:   true,
			CSRFCookieSameSite: "Strict",
			CSRFCookiePath:     "/app",
			CSRFCookieMaxAge:   1800,
		}
		RegisterSecurityHeadersMiddleware(router, config)

		// Request CSRF token
		req := httptest.NewRequest("GET", "/csrf-token", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Check cookie attributes
		cookies := w.Result().Cookies()
		var csrfCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "csrf_token" {
				csrfCookie = cookie
				break
			}
		}

		if csrfCookie == nil {
			t.Fatal("CSRF cookie not found")
		}

		if !csrfCookie.HttpOnly {
			t.Error("Cookie should be HttpOnly")
		}

		if !csrfCookie.Secure {
			t.Error("Cookie should be Secure")
		}

		if csrfCookie.SameSite != http.SameSiteStrictMode {
			t.Error("Cookie should have Strict SameSite")
		}

		if csrfCookie.Path != "/app" {
			t.Error("Cookie should have custom path")
		}

		if csrfCookie.MaxAge != 1800 {
			t.Error("Cookie should have custom MaxAge")
		}
	})
}

func TestCSRFTokenGeneration(t *testing.T) {
	t.Run("Generated tokens are unique", func(t *testing.T) {
		token1 := generateCSRFToken()
		token2 := generateCSRFToken()

		if token1 == token2 {
			t.Error("Generated tokens should be unique")
		}

		if len(token1) == 0 || len(token2) == 0 {
			t.Error("Generated tokens should not be empty")
		}
	})

	t.Run("Tokens have sufficient length", func(t *testing.T) {
		token := generateCSRFToken()

		// Base64 encoded 32 bytes should be longer than 40 characters
		if len(token) < 40 {
			t.Errorf("Token too short: %d characters", len(token))
		}
	})
}

func TestParseSameSite(t *testing.T) {
	tests := []struct {
		input    string
		expected http.SameSite
	}{
		{"strict", http.SameSiteStrictMode},
		{"Strict", http.SameSiteStrictMode},
		{"STRICT", http.SameSiteStrictMode},
		{"lax", http.SameSiteLaxMode},
		{"Lax", http.SameSiteLaxMode},
		{"LAX", http.SameSiteLaxMode},
		{"none", http.SameSiteNoneMode},
		{"None", http.SameSiteNoneMode},
		{"NONE", http.SameSiteNoneMode},
		{"invalid", http.SameSiteLaxMode}, // Default
		{"", http.SameSiteLaxMode},        // Default
	}

	for _, test := range tests {
		result := parseSameSite(test.input)
		if result != test.expected {
			t.Errorf("parseSameSite(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestCSRFIntegrationWithOptions(t *testing.T) {
	t.Run("CSRF configuration through options", func(t *testing.T) {
		server, err := NewServer(
			WithCSRFProtection(),
			WithCSRFTokenName("X-My-Token"),
			WithCSRFCookieName("my_token"),
			WithCSRFTokenEndpoint("/my-csrf"),
		)

		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		// Verify configuration was applied
		if !server.opts.Security.CSRFEnabled {
			t.Error("CSRF should be enabled")
		}

		if server.opts.Security.CSRFTokenName != "X-My-Token" {
			t.Error("Custom token name not set")
		}

		if server.opts.Security.CSRFCookieName != "my_token" {
			t.Error("Custom cookie name not set")
		}

		if server.opts.Security.CSRFTokenEndpoint != "/my-csrf" {
			t.Error("Custom endpoint not set")
		}
	})
}
