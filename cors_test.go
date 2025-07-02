package servex

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestCORSMiddleware(t *testing.T) {
	t.Run("CORS middleware disabled by default", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{} // CORS not enabled

		RegisterCORSMiddleware(router, opts)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		})

		req := httptest.NewRequest(GET, "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should not have CORS headers when disabled
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("Should not have CORS headers when disabled")
		}

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Basic CORS headers for simple request", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			CORS: CORSConfig{
				Enabled: true,
			},
		}

		RegisterCORSMiddleware(router, opts)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		})

		req := httptest.NewRequest(GET, "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should have basic CORS headers
		if w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("Expected Access-Control-Allow-Origin to be '*', got '%s'",
				w.Header().Get("Access-Control-Allow-Origin"))
		}

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("CORS with specific allowed origins", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			CORS: CORSConfig{
				Enabled:      true,
				AllowOrigins: []string{"http://example.com", "https://app.example.com"},
			},
		}

		RegisterCORSMiddleware(router, opts)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Test allowed origin
		req := httptest.NewRequest(GET, "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
			t.Errorf("Expected Access-Control-Allow-Origin to be 'http://example.com', got '%s'",
				w.Header().Get("Access-Control-Allow-Origin"))
		}

		// Test disallowed origin
		req2 := httptest.NewRequest(GET, "/test", nil)
		req2.Header.Set("Origin", "http://malicious.com")
		w2 := httptest.NewRecorder()

		router.ServeHTTP(w2, req2)

		if w2.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("Should not set CORS headers for disallowed origin")
		}
	})

	t.Run("CORS preflight request handling", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			CORS: CORSConfig{
				Enabled:      true,
				AllowOrigins: []string{"http://example.com"},
				AllowMethods: []string{GET, POST, PUT},
				AllowHeaders: []string{"Content-Type", "Authorization"},
			},
		}

		RegisterCORSMiddleware(router, opts)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}).Methods(POST)

		// Send preflight request
		req := httptest.NewRequest(OPTIONS, "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("Access-Control-Request-Method", POST)
		req.Header.Set("Access-Control-Request-Headers", "Content-Type")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should respond to preflight
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200 for preflight, got %d", w.Code)
		}

		if w.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
			t.Error("Preflight should include Allow-Origin header")
		}

		if w.Header().Get("Access-Control-Allow-Methods") != "GET, POST, PUT" {
			t.Errorf("Expected Allow-Methods 'GET, POST, PUT', got '%s'",
				w.Header().Get("Access-Control-Allow-Methods"))
		}

		if w.Header().Get("Access-Control-Allow-Headers") != "Content-Type, Authorization" {
			t.Errorf("Expected Allow-Headers 'Content-Type, Authorization', got '%s'",
				w.Header().Get("Access-Control-Allow-Headers"))
		}
	})

	t.Run("CORS preflight with invalid method", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			CORS: CORSConfig{
				Enabled:      true,
				AllowOrigins: []string{"http://example.com"},
				AllowMethods: []string{GET, POST},
			},
		}

		RegisterCORSMiddleware(router, opts)

		// Send preflight with disallowed method
		req := httptest.NewRequest(OPTIONS, "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("Access-Control-Request-Method", DELETE)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should reject preflight
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405 for invalid method, got %d", w.Code)
		}
	})

	t.Run("CORS preflight with invalid headers", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			CORS: CORSConfig{
				Enabled:      true,
				AllowOrigins: []string{"http://example.com"},
				AllowMethods: []string{GET, POST},
				AllowHeaders: []string{"Content-Type"},
			},
		}

		RegisterCORSMiddleware(router, opts)

		// Send preflight with disallowed header
		req := httptest.NewRequest(OPTIONS, "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("Access-Control-Request-Method", POST)
		req.Header.Set("Access-Control-Request-Headers", "X-Custom-Header")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should reject preflight
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status 403 for invalid headers, got %d", w.Code)
		}
	})

	t.Run("CORS with credentials", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			CORS: CORSConfig{
				Enabled:          true,
				AllowOrigins:     []string{"http://example.com"},
				AllowCredentials: true,
			},
		}

		RegisterCORSMiddleware(router, opts)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(GET, "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
			t.Error("Should set Allow-Credentials to true")
		}
	})

	t.Run("CORS with exposed headers", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			CORS: CORSConfig{
				Enabled:       true,
				AllowOrigins:  []string{"*"},
				ExposeHeaders: []string{"X-Total-Count", "X-Page-Count"},
			},
		}

		RegisterCORSMiddleware(router, opts)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Total-Count", "100")
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(GET, "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Expose-Headers") != "X-Total-Count, X-Page-Count" {
			t.Errorf("Expected Expose-Headers 'X-Total-Count, X-Page-Count', got '%s'",
				w.Header().Get("Access-Control-Expose-Headers"))
		}
	})

	t.Run("CORS with max age", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			CORS: CORSConfig{
				Enabled:      true,
				AllowOrigins: []string{"*"},
				MaxAge:       3600,
			},
		}

		RegisterCORSMiddleware(router, opts)

		// Send preflight request
		req := httptest.NewRequest(OPTIONS, "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("Access-Control-Request-Method", POST)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Max-Age") != "3600" {
			t.Errorf("Expected Max-Age '3600', got '%s'",
				w.Header().Get("Access-Control-Max-Age"))
		}
	})

	t.Run("CORS path filtering", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			CORS: CORSConfig{
				Enabled:      true,
				AllowOrigins: []string{"*"},
				IncludePaths: []string{"/api/*"},
			},
		}

		RegisterCORSMiddleware(router, opts)

		router.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		router.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Test API path (should have CORS)
		req1 := httptest.NewRequest(GET, "/api/users", nil)
		req1.Header.Set("Origin", "http://example.com")
		w1 := httptest.NewRecorder()

		router.ServeHTTP(w1, req1)

		if w1.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Error("API path should have CORS headers")
		}

		// Test public path (should not have CORS)
		req2 := httptest.NewRequest(GET, "/public", nil)
		req2.Header.Set("Origin", "http://example.com")
		w2 := httptest.NewRecorder()

		router.ServeHTTP(w2, req2)

		if w2.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("Public path should not have CORS headers")
		}
	})

	t.Run("CORS without origin header", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			CORS: CORSConfig{
				Enabled: true,
			},
		}

		RegisterCORSMiddleware(router, opts)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Request without Origin header
		req := httptest.NewRequest(GET, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should not set CORS headers without Origin
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("Should not set CORS headers without Origin header")
		}

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("CORS wildcard origin with credentials should fail", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			CORS: CORSConfig{
				Enabled:          true,
				AllowOrigins:     []string{"*"},
				AllowCredentials: true,
			},
		}

		RegisterCORSMiddleware(router, opts)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(GET, "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// When credentials are allowed, wildcard should be replaced with actual origin
		if w.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
			t.Errorf("Expected specific origin when credentials enabled, got '%s'",
				w.Header().Get("Access-Control-Allow-Origin"))
		}

		if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
			t.Error("Should set Allow-Credentials to true")
		}
	})
}

func TestCORSOriginMatching(t *testing.T) {
	testCases := []struct {
		name         string
		allowOrigins []string
		origin       string
		expected     bool
	}{
		{"wildcard allows all", []string{"*"}, "http://example.com", true},
		{"exact match", []string{"http://example.com"}, "http://example.com", true},
		{"no match", []string{"http://example.com"}, "http://other.com", false},
		{"multiple origins match", []string{"http://example.com", "https://app.com"}, "https://app.com", true},
		{"multiple origins no match", []string{"http://example.com", "https://app.com"}, "http://malicious.com", false},
		{"case sensitive", []string{"http://Example.com"}, "http://example.com", false},
		{"empty origin", []string{"http://example.com"}, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := originAllowedCORS(tc.origin, tc.allowOrigins)
			if result != tc.expected {
				t.Errorf("originAllowedCORS(%s, %v) = %v, expected %v",
					tc.origin, tc.allowOrigins, result, tc.expected)
			}
		})
	}
}

func TestCORSMethodValidation(t *testing.T) {
	testCases := []struct {
		name         string
		allowMethods []string
		method       string
		expected     bool
	}{
		{"allowed method", []string{GET, POST, PUT}, POST, true},
		{"disallowed method", []string{GET, POST}, DELETE, false},
		{"case insensitive", []string{"get", "post"}, GET, true},
		{"empty methods allows all", []string{}, PATCH, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := methodAllowedCORS(tc.method, tc.allowMethods)
			if result != tc.expected {
				t.Errorf("methodAllowedCORS(%s, %v) = %v, expected %v",
					tc.method, tc.allowMethods, result, tc.expected)
			}
		})
	}
}

func TestCORSHeaderValidation(t *testing.T) {
	testCases := []struct {
		name         string
		allowHeaders []string
		headers      []string
		expected     bool
	}{
		{"allowed headers", []string{"Content-Type", "Authorization"}, []string{"Content-Type"}, true},
		{"multiple allowed headers", []string{"Content-Type", "Authorization"}, []string{"Content-Type", "Authorization"}, true},
		{"disallowed header", []string{"Content-Type"}, []string{"X-Custom"}, false},
		{"mixed allowed/disallowed", []string{"Content-Type"}, []string{"Content-Type", "X-Custom"}, false},
		{"case insensitive", []string{"content-type"}, []string{"Content-Type"}, true},
		{"empty headers allows all", []string{}, []string{"X-Anything"}, true},
		{"no headers requested", []string{"Content-Type"}, []string{}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := headersAllowedCORS(tc.headers, tc.allowHeaders)
			if result != tc.expected {
				t.Errorf("headersAllowedCORS(%v, %v) = %v, expected %v",
					tc.headers, tc.allowHeaders, result, tc.expected)
			}
		})
	}
}

func TestCORSConfigurationThroughOptions(t *testing.T) {
	t.Run("WithCORS enables CORS with defaults", func(t *testing.T) {
		server, err := NewServer(WithCORS())
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		if !server.opts.CORS.Enabled {
			t.Error("CORS should be enabled")
		}
	})

	t.Run("WithCORSAllowOrigins sets origins", func(t *testing.T) {
		server, err := NewServer(WithCORSAllowOrigins("http://example.com", "https://app.com"))
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		expected := []string{"http://example.com", "https://app.com"}
		if len(server.opts.CORS.AllowOrigins) != len(expected) {
			t.Errorf("Expected %d origins, got %d", len(expected), len(server.opts.CORS.AllowOrigins))
		}

		for i, origin := range expected {
			if server.opts.CORS.AllowOrigins[i] != origin {
				t.Errorf("Expected origin %s, got %s", origin, server.opts.CORS.AllowOrigins[i])
			}
		}
	})

	t.Run("WithCORSAllowMethods sets methods", func(t *testing.T) {
		server, err := NewServer(WithCORSAllowMethods(GET, POST, PUT))
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		expected := []string{GET, POST, PUT}
		if len(server.opts.CORS.AllowMethods) != len(expected) {
			t.Errorf("Expected %d methods, got %d", len(expected), len(server.opts.CORS.AllowMethods))
		}
	})

	t.Run("WithCORSAllowHeaders sets headers", func(t *testing.T) {
		server, err := NewServer(WithCORSAllowHeaders("Content-Type", "Authorization"))
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		expected := []string{"Content-Type", "Authorization"}
		if len(server.opts.CORS.AllowHeaders) != len(expected) {
			t.Errorf("Expected %d headers, got %d", len(expected), len(server.opts.CORS.AllowHeaders))
		}
	})

	t.Run("WithCORSExposeHeaders sets expose headers", func(t *testing.T) {
		server, err := NewServer(WithCORSExposeHeaders("X-Total-Count", "X-Page"))
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		expected := []string{"X-Total-Count", "X-Page"}
		if len(server.opts.CORS.ExposeHeaders) != len(expected) {
			t.Errorf("Expected %d expose headers, got %d", len(expected), len(server.opts.CORS.ExposeHeaders))
		}
	})

	t.Run("WithCORSAllowCredentials enables credentials", func(t *testing.T) {
		server, err := NewServer(WithCORSAllowCredentials())
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		if !server.opts.CORS.AllowCredentials {
			t.Error("CORS credentials should be enabled")
		}
	})

	t.Run("WithCORSMaxAge sets max age", func(t *testing.T) {
		server, err := NewServer(WithCORSMaxAge(7200))
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		if server.opts.CORS.MaxAge != 7200 {
			t.Errorf("Expected max age 7200, got %d", server.opts.CORS.MaxAge)
		}
	})

	t.Run("WithCORSPaths sets paths", func(t *testing.T) {
		server, err := NewServer(WithCORSIncludePaths("/api/*", "/public/*"))
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		expected := []string{"/api/*", "/public/*"}
		if len(server.opts.CORS.IncludePaths) != len(expected) {
			t.Errorf("Expected %d paths, got %d", len(expected), len(server.opts.CORS.IncludePaths))
		}
	})

	t.Run("WithCORSConfig sets full configuration", func(t *testing.T) {
		config := CORSConfig{
			Enabled:          true,
			AllowOrigins:     []string{"http://example.com"},
			AllowMethods:     []string{GET, POST},
			AllowHeaders:     []string{"Content-Type"},
			ExposeHeaders:    []string{"X-Total"},
			AllowCredentials: true,
			MaxAge:           3600,
			IncludePaths:     []string{"/api/*"},
		}

		server, err := NewServer(WithCORSConfig(config))
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		if !server.opts.CORS.Enabled {
			t.Error("CORS should be enabled")
		}

		if server.opts.CORS.AllowOrigins[0] != "http://example.com" {
			t.Error("CORS origins not set correctly")
		}

		if !server.opts.CORS.AllowCredentials {
			t.Error("CORS credentials should be enabled")
		}

		if server.opts.CORS.MaxAge != 3600 {
			t.Error("CORS max age not set correctly")
		}
	})
}
