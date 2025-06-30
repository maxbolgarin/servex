package servex

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// TestRouter is a simple implementation of MiddlewareRouter for testing
type TestRouter struct {
	middleware func(http.Handler) http.Handler
}

func (r *TestRouter) Use(middleware ...mux.MiddlewareFunc) {
	if len(middleware) > 0 {
		r.middleware = middleware[0]
	}
}

// ServeHTTP applies middleware if it exists, otherwise calls the handler directly
func (r *TestRouter) ServeHTTP(handler http.Handler, w http.ResponseWriter, req *http.Request) {
	if r.middleware != nil {
		r.middleware(handler).ServeHTTP(w, req)
	} else {
		handler.ServeHTTP(w, req)
	}
}

// createTestHandler returns a simple handler for testing
func createTestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})
}

// staticKeyFunc returns a key function that always returns the same key
func staticKeyFunc(key string) func(r *http.Request) string {
	return func(r *http.Request) string {
		return key
	}
}

func TestRateLimitMiddleware_Basic(t *testing.T) {
	// Create a new router
	router := &TestRouter{}

	// Configure rate limiting with a static key function to ensure all requests use the same key
	cfg := RateLimitConfig{
		Enabled:             true,
		RequestsPerInterval: 3,
		Interval:            time.Second,
		StatusCode:          http.StatusTooManyRequests,
		Message:             "rate limit exceeded",
		KeyFunc:             staticKeyFunc("test-client"),
	}

	// Register middleware
	RegisterRateLimitMiddleware(router, cfg)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply middleware safely
		router.ServeHTTP(createTestHandler(), w, r)
	}))
	defer server.Close()

	// Make sure all requests happen quickly, before tokens can refill
	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	// Make requests under the limit
	for i := 0; i < cfg.RequestsPerInterval; i++ {
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK, got %v", resp.StatusCode)
		}
	}

	// Make a request that should exceed the limit
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status TooManyRequests, got %v", resp.StatusCode)
	}
}

func TestRateLimitMiddleware_Disabled(t *testing.T) {
	// Create a new router
	router := &TestRouter{}

	// Configure rate limiting with 0 requests per interval (disabled)
	cfg := RateLimitConfig{
		RequestsPerInterval: 0,
	}

	// Register middleware
	cleanup := RegisterRateLimitMiddleware(router, cfg)

	// The middleware should not be set and cleanup should be nil
	if router.middleware != nil {
		t.Errorf("Rate limiting should be disabled, but middleware was registered")
	}

	if cleanup != nil {
		t.Errorf("Expected cleanup function to be nil for disabled rate limiting")
	}
}

func TestRateLimitMiddleware_ExcludePaths(t *testing.T) {
	// Create a new router
	router := &TestRouter{}

	// Configure rate limiting with excluded paths and a static key function
	cfg := RateLimitConfig{
		Enabled:             true,
		RequestsPerInterval: 2,
		Interval:            time.Second,
		StatusCode:          http.StatusTooManyRequests,
		Message:             "rate limit exceeded",
		ExcludePaths:        []string{"/excluded"},
		KeyFunc:             staticKeyFunc("test-client"),
	}

	// Register middleware
	RegisterRateLimitMiddleware(router, cfg)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply middleware safely
		router.ServeHTTP(createTestHandler(), w, r)
	}))
	defer server.Close()

	// Make requests to a rate-limited path
	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	for i := 0; i < cfg.RequestsPerInterval; i++ {
		req, _ := http.NewRequest("GET", server.URL+"/normal", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK, got %v", resp.StatusCode)
		}
	}

	// Another request to the rate-limited path should be blocked
	req, _ := http.NewRequest("GET", server.URL+"/normal", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status TooManyRequests, got %v", resp.StatusCode)
	}

	// Requests to excluded path should not be rate limited
	for i := 0; i < cfg.RequestsPerInterval*2; i++ {
		req, _ := http.NewRequest("GET", server.URL+"/excluded", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK for excluded path, got %v", resp.StatusCode)
		}
	}
}

func TestRateLimitMiddleware_IncludePaths(t *testing.T) {
	// Create a new router
	router := &TestRouter{}

	// Configure rate limiting with included paths and a static key function
	cfg := RateLimitConfig{
		Enabled:             true,
		RequestsPerInterval: 2,
		Interval:            time.Second,
		StatusCode:          http.StatusTooManyRequests,
		Message:             "rate limit exceeded",
		IncludePaths:        []string{"/included"},
		KeyFunc:             staticKeyFunc("test-client"),
	}

	// Register middleware
	RegisterRateLimitMiddleware(router, cfg)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply middleware safely
		router.ServeHTTP(createTestHandler(), w, r)
	}))
	defer server.Close()

	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	// Requests to non-included path should not be rate limited
	for i := 0; i < cfg.RequestsPerInterval*2; i++ {
		req, _ := http.NewRequest("GET", server.URL+"/not-included", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK for non-included path, got %v", resp.StatusCode)
		}
	}

	// Make requests to an included path (should be rate limited)
	for i := 0; i < cfg.RequestsPerInterval; i++ {
		req, _ := http.NewRequest("GET", server.URL+"/included", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK, got %v", resp.StatusCode)
		}
	}

	// Another request to the included path should be blocked
	req, _ := http.NewRequest("GET", server.URL+"/included", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status TooManyRequests, got %v", resp.StatusCode)
	}
}

func TestRateLimitMiddleware_KeyFunction(t *testing.T) {
	// Create a new router
	router := &TestRouter{}

	// Custom key function that uses the X-User-ID header
	customKeyFunc := func(r *http.Request) string {
		return r.Header.Get("X-User-ID")
	}

	// Configure rate limiting with a custom key function
	cfg := RateLimitConfig{
		Enabled:             true,
		RequestsPerInterval: 2,
		Interval:            time.Second,
		StatusCode:          http.StatusTooManyRequests,
		Message:             "rate limit exceeded",
		KeyFunc:             customKeyFunc,
	}

	// Register middleware
	RegisterRateLimitMiddleware(router, cfg)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply middleware safely
		router.ServeHTTP(createTestHandler(), w, r)
	}))
	defer server.Close()

	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	// Make requests with different user IDs
	for userId := 1; userId <= 3; userId++ {
		userKey := fmt.Sprintf("user-%d", userId)

		// Each user should be able to make requests up to the limit
		for i := 0; i < cfg.RequestsPerInterval; i++ {
			req, _ := http.NewRequest("GET", server.URL, nil)
			req.Header.Set("X-User-ID", userKey)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status OK for user %d request %d, got %v", userId, i, resp.StatusCode)
			}
		}

		// Another request from the same user should be blocked
		req, _ := http.NewRequest("GET", server.URL, nil)
		req.Header.Set("X-User-ID", userKey)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("Expected status TooManyRequests for user %d extra request, got %v", userId, resp.StatusCode)
		}
	}
}

func TestRateLimitMiddleware_BurstSize(t *testing.T) {
	// Create a new router
	router := &TestRouter{}

	// Configure rate limiting with a burst size larger than requests per interval and a static key
	cfg := RateLimitConfig{
		Enabled:             true,
		RequestsPerInterval: 2,
		BurstSize:           4, // Allow bursts of up to 4 requests
		Interval:            time.Second,
		StatusCode:          http.StatusTooManyRequests,
		Message:             "rate limit exceeded",
		KeyFunc:             staticKeyFunc("test-client"),
	}

	// Register middleware
	RegisterRateLimitMiddleware(router, cfg)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply middleware safely
		router.ServeHTTP(createTestHandler(), w, r)
	}))
	defer server.Close()

	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	// Should be able to make burst size number of requests immediately
	for i := 0; i < cfg.BurstSize; i++ {
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK for burst request %d, got %v", i, resp.StatusCode)
		}
	}

	// The next request should exceed the limit
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status TooManyRequests after burst, got %v", resp.StatusCode)
	}

	// Wait for tokens to refill (at the rate of RequestsPerInterval per Interval)
	time.Sleep(cfg.Interval)

	// Should be able to make RequestsPerInterval more requests
	for i := 0; i < cfg.RequestsPerInterval; i++ {
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK after waiting, got %v", resp.StatusCode)
		}
	}
}

func TestRateLimitMiddleware_CleanupInterval(t *testing.T) {
	// This test is more theoretical as it's hard to test the cleanup directly
	// Create a new router
	router := &TestRouter{}

	// Configure rate limiting
	cfg := RateLimitConfig{
		Enabled:             true,
		RequestsPerInterval: 2,
		Interval:            time.Second,
		KeyFunc:             staticKeyFunc("test-client"),
	}

	// Register middleware
	RegisterRateLimitMiddleware(router, cfg)

	// The cleanup should happen automatically in the middleware
	// We can't directly test it without exposing internals, but we can verify
	// the middleware doesn't panic when handling requests

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply middleware safely
		router.ServeHTTP(createTestHandler(), w, r)
	}))
	defer server.Close()

	// Make a few requests with different IPs to populate the visitors map
	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	var wg sync.WaitGroup
	// Create multiple "visitors" by using different keys
	for i := 1; i <= 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			req, _ := http.NewRequest("GET", server.URL, nil)
			req.Header.Set("X-Forwarded-For", fmt.Sprintf("192.168.1.%d", id))
			resp, err := client.Do(req)
			if err != nil {
				t.Logf("Failed to make request: %v", err)
				return
			}
			resp.Body.Close()
		}(i)
	}
	wg.Wait()

	// If we got here without panics, assume the cleanup logic works
}

func TestRateLimitMiddleware_DefaultValues(t *testing.T) {
	// Create a new router
	router := &TestRouter{}

	// Configure rate limiting with minimal configuration and a static key
	cfg := RateLimitConfig{
		Enabled:             true,
		RequestsPerInterval: 3,
		KeyFunc:             staticKeyFunc("test-client"),
	}

	// Register middleware
	RegisterRateLimitMiddleware(router, cfg)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply middleware safely
		router.ServeHTTP(createTestHandler(), w, r)
	}))
	defer server.Close()

	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	// Make requests under the limit
	for i := 0; i < cfg.RequestsPerInterval; i++ {
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK, got %v", resp.StatusCode)
		}
	}

	// Make a request that should exceed the limit
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Default status code should be 429
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status TooManyRequests, got %v", resp.StatusCode)
	}
}

// TestRateLimitMiddleware_RequestBodyPreservation tests that the rate limiter preserves the request body
// for subsequent handlers when extracting username for rate limiting.
func TestRateLimitMiddleware_RequestBodyPreservation(t *testing.T) {
	cfg := RateLimitConfig{
		Enabled:             true,
		RequestsPerInterval: 10,
		Interval:            time.Minute,
		BurstSize:           1,
	}

	router := &TestRouter{}
	RegisterRateLimitMiddleware(router, cfg)

	// Create a test handler that reads the request body
	var receivedBody string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body in handler: %v", err)
		}
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	})

	// Create test request with JSON body containing username
	requestBody := `{"username":"testuser","password":"testpass"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute request safely
	router.ServeHTTP(handler, w, req)

	// Verify the request body was preserved for the handler
	if receivedBody != requestBody {
		t.Errorf("expected body %q, got %q", requestBody, receivedBody)
	}

	// Verify the response is OK (not rate limited)
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

// TestIPKeyExtraction tests the IP key extraction functions directly.
func TestIPKeyExtraction(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		headers        map[string]string
		expectedKey    string
	}{
		{
			name:           "No trusted proxies - ignores X-Forwarded-For",
			trustedProxies: []string{},
			remoteAddr:     "192.168.1.100:12345",
			headers:        map[string]string{"X-Forwarded-For": "10.0.0.1"},
			expectedKey:    "192.168.1.100",
		},
		{
			name:           "No trusted proxies - ignores X-Real-IP",
			trustedProxies: []string{},
			remoteAddr:     "192.168.1.100:12345",
			headers:        map[string]string{"X-Real-IP": "10.0.0.1"},
			expectedKey:    "192.168.1.100",
		},
		{
			name:           "Untrusted proxy - ignores headers",
			trustedProxies: []string{"10.0.0.0/24"},
			remoteAddr:     "192.168.1.100:12345",
			headers:        map[string]string{"X-Forwarded-For": "10.0.0.1"},
			expectedKey:    "192.168.1.100",
		},
		{
			name:           "Trusted proxy - uses X-Forwarded-For",
			trustedProxies: []string{"10.0.0.0/24"},
			remoteAddr:     "10.0.0.5:12345",
			headers:        map[string]string{"X-Forwarded-For": "203.0.113.1"},
			expectedKey:    "203.0.113.1",
		},
		{
			name:           "Trusted proxy - uses X-Real-IP",
			trustedProxies: []string{"10.0.0.5"},
			remoteAddr:     "10.0.0.5:12345",
			headers:        map[string]string{"X-Real-IP": "203.0.113.2"},
			expectedKey:    "203.0.113.2",
		},
		{
			name:           "Trusted proxy - multiple IPs in X-Forwarded-For",
			trustedProxies: []string{"10.0.0.0/24"},
			remoteAddr:     "10.0.0.5:12345",
			headers:        map[string]string{"X-Forwarded-For": "203.0.113.1, 10.0.0.10, 10.0.0.5"},
			expectedKey:    "203.0.113.1",
		},
		{
			name:           "Trusted proxy - invalid IP in header falls back to RemoteAddr",
			trustedProxies: []string{"10.0.0.0/24"},
			remoteAddr:     "10.0.0.5:12345",
			headers:        map[string]string{"X-Forwarded-For": "invalid-ip"},
			expectedKey:    "10.0.0.5",
		},
		{
			name:           "IPv6 trusted proxy",
			trustedProxies: []string{"2001:db8::/32"},
			remoteAddr:     "[2001:db8::1]:12345",
			headers:        map[string]string{"X-Real-IP": "203.0.113.1"},
			expectedKey:    "203.0.113.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the IP key function with trusted proxies
			keyFunc := getIPKeyFuncWithProxies(tt.trustedProxies)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			actualKey := keyFunc(req)

			if actualKey != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, actualKey)
			}
		})
	}
}

// TestTrustedProxyEdgeCases tests edge cases for trusted proxy validation.
func TestTrustedProxyEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		headers        map[string]string
		expectedKey    string
	}{
		{
			name:           "Single IP without CIDR becomes /32",
			trustedProxies: []string{"10.0.0.5"},
			remoteAddr:     "10.0.0.5:12345",
			headers:        map[string]string{"X-Real-IP": "203.0.113.1"},
			expectedKey:    "203.0.113.1",
		},
		{
			name:           "IPv6 single IP becomes /128",
			trustedProxies: []string{"2001:db8::1"},
			remoteAddr:     "[2001:db8::1]:12345",
			headers:        map[string]string{"X-Real-IP": "203.0.113.1"},
			expectedKey:    "203.0.113.1",
		},
		{
			name:           "Invalid proxy config ignored",
			trustedProxies: []string{"invalid-ip", "10.0.0.0/24"},
			remoteAddr:     "10.0.0.5:12345",
			headers:        map[string]string{"X-Real-IP": "203.0.113.1"},
			expectedKey:    "203.0.113.1",
		},
		{
			name:           "RemoteAddr without port",
			trustedProxies: []string{"10.0.0.0/24"},
			remoteAddr:     "10.0.0.5",
			headers:        map[string]string{"X-Real-IP": "203.0.113.1"},
			expectedKey:    "203.0.113.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the IP key function with trusted proxies
			keyFunc := getIPKeyFuncWithProxies(tt.trustedProxies)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			actualKey := keyFunc(req)

			if actualKey != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, actualKey)
			}
		})
	}
}

// TestUsernameRateLimiting tests username-based rate limiting functionality.
func TestUsernameRateLimiting(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		path           string
		requestBody    string
		trustedProxies []string
		remoteAddr     string
		headers        map[string]string
		expectedKey    string
		description    string
	}{
		{
			name:        "Login endpoint with username extracts username",
			method:      http.MethodPost,
			path:        "/login",
			requestBody: `{"username":"testuser","password":"testpass"}`,
			expectedKey: "testuser",
			description: "Should extract username from login request body",
		},
		{
			name:        "Register endpoint with username extracts username",
			method:      http.MethodPost,
			path:        "/register",
			requestBody: `{"username":"newuser","password":"newpass","email":"test@example.com"}`,
			expectedKey: "newuser",
			description: "Should extract username from register request body",
		},
		{
			name:        "Login with empty username falls back to IP",
			method:      http.MethodPost,
			path:        "/login",
			requestBody: `{"username":"","password":"testpass"}`,
			remoteAddr:  "192.168.1.100:12345",
			expectedKey: "192.168.1.100",
			description: "Should fall back to IP when username is empty",
		},
		{
			name:        "Login with missing username falls back to IP",
			method:      http.MethodPost,
			path:        "/login",
			requestBody: `{"password":"testpass"}`,
			remoteAddr:  "192.168.1.100:12345",
			expectedKey: "192.168.1.100",
			description: "Should fall back to IP when username field is missing",
		},
		{
			name:        "Login with invalid JSON falls back to IP",
			method:      http.MethodPost,
			path:        "/login",
			requestBody: `{invalid-json}`,
			remoteAddr:  "192.168.1.100:12345",
			expectedKey: "192.168.1.100",
			description: "Should fall back to IP when JSON is invalid",
		},
		{
			name:        "Login with empty body falls back to IP",
			method:      http.MethodPost,
			path:        "/login",
			requestBody: "",
			remoteAddr:  "192.168.1.100:12345",
			expectedKey: "192.168.1.100",
			description: "Should fall back to IP when body is empty",
		},
		{
			name:        "Non-auth endpoint uses IP",
			method:      http.MethodPost,
			path:        "/api/data",
			requestBody: `{"username":"testuser","data":"some data"}`,
			remoteAddr:  "192.168.1.100:12345",
			expectedKey: "192.168.1.100",
			description: "Should use IP for non-auth endpoints even with username in body",
		},
		{
			name:        "GET request to login uses IP",
			method:      http.MethodGet,
			path:        "/login",
			requestBody: `{"username":"testuser","password":"testpass"}`,
			remoteAddr:  "192.168.1.100:12345",
			expectedKey: "192.168.1.100",
			description: "Should use IP for non-POST requests to auth endpoints",
		},
		{
			name:           "Login with trusted proxy and username",
			method:         http.MethodPost,
			path:           "/login",
			requestBody:    `{"username":"proxyuser","password":"testpass"}`,
			trustedProxies: []string{"10.0.0.0/24"},
			remoteAddr:     "10.0.0.5:12345",
			headers:        map[string]string{"X-Real-IP": "203.0.113.1"},
			expectedKey:    "proxyuser",
			description:    "Should extract username even when request comes through trusted proxy",
		},
		{
			name:           "Non-auth endpoint with trusted proxy uses real IP",
			method:         http.MethodPost,
			path:           "/api/data",
			requestBody:    `{"data":"some data"}`,
			trustedProxies: []string{"10.0.0.0/24"},
			remoteAddr:     "10.0.0.5:12345",
			headers:        map[string]string{"X-Real-IP": "203.0.113.1"},
			expectedKey:    "203.0.113.1",
			description:    "Should use real IP from trusted proxy for non-auth endpoints",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the username key function with trusted proxies
			keyFunc := getUsernameKeyFuncWithProxies(tt.trustedProxies)

			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")

			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			} else {
				req.RemoteAddr = "127.0.0.1:12345" // default
			}

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			actualKey := keyFunc(req)

			if actualKey != tt.expectedKey {
				t.Errorf("%s: expected key %q, got %q", tt.description, tt.expectedKey, actualKey)
			}
		})
	}
}

// TestUsernameRateLimitingBodyPreservation tests that username extraction preserves the request body.
func TestUsernameRateLimitingBodyPreservation(t *testing.T) {
	requestBody := `{"username":"testuser","password":"secretpass","extra":"data"}`

	// Create the username key function
	keyFunc := getUsernameKeyFuncWithProxies(nil)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"

	// Extract the key (this should preserve the body)
	actualKey := keyFunc(req)

	// Verify the key is the username
	if actualKey != "testuser" {
		t.Errorf("expected key to be 'testuser', got %q", actualKey)
	}

	// Verify the body is still readable
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read preserved body: %v", err)
	}

	if string(body) != requestBody {
		t.Errorf("expected preserved body %q, got %q", requestBody, string(body))
	}
}

// TestUsernameRateLimitingIntegration tests username rate limiting through the full middleware.
func TestUsernameRateLimitingIntegration(t *testing.T) {
	cfg := RateLimitConfig{
		Enabled:             true,
		RequestsPerInterval: 2, // Allow only 2 requests
		Interval:            time.Minute,
		BurstSize:           2,
	}

	router := &TestRouter{}
	RegisterRateLimitMiddleware(router, cfg)

	var requestBodies []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read and store the body to verify it's preserved
		body, _ := io.ReadAll(r.Body)
		requestBodies = append(requestBodies, string(body))
		w.WriteHeader(http.StatusOK)
	})

	// Test 1: First login for user1 - should succeed
	req1 := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"user1","password":"pass1"}`))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(handler, w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("first request for user1 should succeed, got status %d", w1.Code)
	}

	// Test 2: Second login for user1 - should succeed (within burst)
	req2 := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"user1","password":"pass1"}`))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(handler, w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("second request for user1 should succeed, got status %d", w2.Code)
	}

	// Test 3: Third login for user1 - should be rate limited
	req3 := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"user1","password":"pass1"}`))
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	router.ServeHTTP(handler, w3, req3)

	if w3.Code != http.StatusTooManyRequests {
		t.Errorf("third request for user1 should be rate limited, got status %d", w3.Code)
	}

	// Test 4: First login for user2 - should succeed (different user)
	req4 := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"user2","password":"pass2"}`))
	req4.Header.Set("Content-Type", "application/json")
	w4 := httptest.NewRecorder()
	router.ServeHTTP(handler, w4, req4)

	if w4.Code != http.StatusOK {
		t.Errorf("first request for user2 should succeed, got status %d", w4.Code)
	}

	// Verify that request bodies were preserved for successful requests
	expectedBodies := []string{
		`{"username":"user1","password":"pass1"}`,
		`{"username":"user1","password":"pass1"}`,
		`{"username":"user2","password":"pass2"}`,
	}

	if len(requestBodies) != len(expectedBodies) {
		t.Errorf("expected %d preserved bodies, got %d", len(expectedBodies), len(requestBodies))
	}

	for i, expected := range expectedBodies {
		if i < len(requestBodies) && requestBodies[i] != expected {
			t.Errorf("request %d: expected body %q, got %q", i+1, expected, requestBodies[i])
		}
	}
}

// TestUsernameRateLimitingFallbackToIP tests that invalid username requests fall back to IP-based limiting.
func TestUsernameRateLimitingFallbackToIP(t *testing.T) {
	cfg := RateLimitConfig{
		Enabled:             true,
		RequestsPerInterval: 2, // Allow only 2 requests
		Interval:            time.Minute,
		BurstSize:           2,
	}

	router := &TestRouter{}
	RegisterRateLimitMiddleware(router, cfg)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// All requests from same IP with invalid JSON should be rate limited together
	baseReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{invalid-json}`))
		req.RemoteAddr = "192.168.1.100:12345"
		return req
	}

	// First request - should succeed
	w1 := httptest.NewRecorder()
	router.ServeHTTP(handler, w1, baseReq())
	if w1.Code != http.StatusOK {
		t.Errorf("first request should succeed, got status %d", w1.Code)
	}

	// Second request - should succeed
	w2 := httptest.NewRecorder()
	router.ServeHTTP(handler, w2, baseReq())
	if w2.Code != http.StatusOK {
		t.Errorf("second request should succeed, got status %d", w2.Code)
	}

	// Third request - should be rate limited (IP-based)
	w3 := httptest.NewRecorder()
	router.ServeHTTP(handler, w3, baseReq())
	if w3.Code != http.StatusTooManyRequests {
		t.Errorf("third request should be rate limited, got status %d", w3.Code)
	}
}
