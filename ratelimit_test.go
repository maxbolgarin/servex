package servex_test

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
	"github.com/maxbolgarin/servex"
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
	cfg := servex.RateLimitConfig{
		RequestsPerInterval: 3,
		Interval:            time.Second,
		StatusCode:          http.StatusTooManyRequests,
		Message:             "rate limit exceeded",
		KeyFunc:             staticKeyFunc("test-client"),
	}

	// Register middleware
	servex.RegisterRateLimitMiddleware(router, cfg)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply middleware
		handler := router.middleware(createTestHandler())
		handler.ServeHTTP(w, r)
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
	cfg := servex.RateLimitConfig{
		RequestsPerInterval: 0,
	}

	// Register middleware
	servex.RegisterRateLimitMiddleware(router, cfg)

	// The middleware should not be set
	if router.middleware != nil {
		t.Errorf("Rate limiting should be disabled, but middleware was registered")
	}
}

func TestRateLimitMiddleware_ExcludePaths(t *testing.T) {
	// Create a new router
	router := &TestRouter{}

	// Configure rate limiting with excluded paths and a static key function
	cfg := servex.RateLimitConfig{
		RequestsPerInterval: 2,
		Interval:            time.Second,
		StatusCode:          http.StatusTooManyRequests,
		Message:             "rate limit exceeded",
		ExcludePaths:        []string{"/excluded"},
		KeyFunc:             staticKeyFunc("test-client"),
	}

	// Register middleware
	servex.RegisterRateLimitMiddleware(router, cfg)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply middleware
		handler := router.middleware(createTestHandler())
		handler.ServeHTTP(w, r)
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
	cfg := servex.RateLimitConfig{
		RequestsPerInterval: 2,
		Interval:            time.Second,
		StatusCode:          http.StatusTooManyRequests,
		Message:             "rate limit exceeded",
		IncludePaths:        []string{"/included"},
		KeyFunc:             staticKeyFunc("test-client"),
	}

	// Register middleware
	servex.RegisterRateLimitMiddleware(router, cfg)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply middleware
		handler := router.middleware(createTestHandler())
		handler.ServeHTTP(w, r)
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
	cfg := servex.RateLimitConfig{
		RequestsPerInterval: 2,
		Interval:            time.Second,
		StatusCode:          http.StatusTooManyRequests,
		Message:             "rate limit exceeded",
		KeyFunc:             customKeyFunc,
	}

	// Register middleware
	servex.RegisterRateLimitMiddleware(router, cfg)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply middleware
		handler := router.middleware(createTestHandler())
		handler.ServeHTTP(w, r)
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
	cfg := servex.RateLimitConfig{
		RequestsPerInterval: 2,
		BurstSize:           4, // Allow bursts of up to 4 requests
		Interval:            time.Second,
		StatusCode:          http.StatusTooManyRequests,
		Message:             "rate limit exceeded",
		KeyFunc:             staticKeyFunc("test-client"),
	}

	// Register middleware
	servex.RegisterRateLimitMiddleware(router, cfg)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply middleware
		handler := router.middleware(createTestHandler())
		handler.ServeHTTP(w, r)
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
	cfg := servex.RateLimitConfig{
		RequestsPerInterval: 2,
		Interval:            time.Second,
		KeyFunc:             staticKeyFunc("test-client"),
	}

	// Register middleware
	servex.RegisterRateLimitMiddleware(router, cfg)

	// The cleanup should happen automatically in the middleware
	// We can't directly test it without exposing internals, but we can verify
	// the middleware doesn't panic when handling requests

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply middleware
		handler := router.middleware(createTestHandler())
		handler.ServeHTTP(w, r)
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
	cfg := servex.RateLimitConfig{
		RequestsPerInterval: 3,
		KeyFunc:             staticKeyFunc("test-client"),
	}

	// Register middleware
	servex.RegisterRateLimitMiddleware(router, cfg)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply middleware
		handler := router.middleware(createTestHandler())
		handler.ServeHTTP(w, r)
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
	cfg := servex.RateLimitConfig{
		RequestsPerInterval: 10,
		Interval:            time.Minute,
		BurstSize:           1,
	}

	router := &TestRouter{}
	servex.RegisterRateLimitMiddleware(router, cfg)

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

	// Apply middleware
	middlewareHandler := router.middleware(handler)

	// Create test request with JSON body containing username
	requestBody := `{"username":"testuser","password":"testpass"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute request
	middlewareHandler.ServeHTTP(w, req)

	// Verify the request body was preserved for the handler
	if receivedBody != requestBody {
		t.Errorf("expected body %q, got %q", requestBody, receivedBody)
	}

	// Verify the response is OK (not rate limited)
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}
