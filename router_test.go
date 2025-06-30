package servex

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// Test WithBasePath method
func TestServer_WithBasePath(t *testing.T) {
	tests := []struct {
		name     string
		basePath string
		expected string
	}{
		{
			name:     "valid base path",
			basePath: "/api/v1",
			expected: "/api/v1",
		},
		{
			name:     "empty base path",
			basePath: "",
			expected: "",
		},
		{
			name:     "root base path",
			basePath: "/",
			expected: "/",
		},
		{
			name:     "nested base path",
			basePath: "/api/v2/users",
			expected: "/api/v2/users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := New()
			if err != nil {
				t.Fatalf("unexpected error creating server: %v", err)
			}

			result := server.WithBasePath(tt.basePath)
			if result != server {
				t.Error("WithBasePath should return the server instance for method chaining")
			}

			if server.basePath != tt.expected {
				t.Errorf("expected basePath to be %q, got %q", tt.expected, server.basePath)
			}
		})
	}
}

// Test Router method and R shortcut
func TestServer_Router(t *testing.T) {
	server, err := New()
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	t.Run("Router without path", func(t *testing.T) {
		router := server.Router()
		if router == nil {
			t.Error("Router() should return a non-nil router")
		}
		if router != server.router {
			t.Error("Router() should return the main router when no path is provided")
		}
	})

	t.Run("Router with path", func(t *testing.T) {
		subrouter := server.Router("/api")
		if subrouter == nil {
			t.Error("Router(\"/api\") should return a non-nil subrouter")
		}
		if subrouter == server.router {
			t.Error("Router(\"/api\") should return a subrouter, not the main router")
		}
	})

	t.Run("R shortcut", func(t *testing.T) {
		router1 := server.Router()
		router2 := server.R()
		if router1 != router2 {
			t.Error("R() should return the same router as Router()")
		}

		subrouter1 := server.Router("/api")
		subrouter2 := server.R("/api")
		// Note: These won't be the same instance since they create new subrouters each time
		// but they should both be non-nil
		if subrouter1 == nil || subrouter2 == nil {
			t.Error("Both Router(\"/api\") and R(\"/api\") should return non-nil subrouters")
		}
	})
}

// Test AddMiddleware method
func TestServer_AddMiddleware(t *testing.T) {
	server, err := New()
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	t.Run("add single middleware", func(t *testing.T) {
		var middlewareCalled bool
		middleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				middlewareCalled = true
				next.ServeHTTP(w, r)
			})
		}

		server.AddMiddlewares(middleware)
		server.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()
		server.router.ServeHTTP(rr, req)

		if !middlewareCalled {
			t.Error("middleware should have been called")
		}
		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})

	t.Run("add multiple middleware", func(t *testing.T) {
		server2, err := New()
		if err != nil {
			t.Fatalf("unexpected error creating server: %v", err)
		}

		var order []string
		middleware1 := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, "middleware1")
				next.ServeHTTP(w, r)
			})
		}
		middleware2 := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, "middleware2")
				next.ServeHTTP(w, r)
			})
		}

		server2.Use(middleware1, middleware2)
		server2.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "handler")
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()
		server2.router.ServeHTTP(rr, req)

		expectedOrder := []string{"middleware1", "middleware2", "handler"}
		if len(order) != len(expectedOrder) {
			t.Errorf("expected order length %d, got %d", len(expectedOrder), len(order))
		}
		for i, expected := range expectedOrder {
			if i >= len(order) || order[i] != expected {
				t.Errorf("expected order[%d] to be %q, got %q", i, expected, order[i])
			}
		}
	})

	t.Run("add nil middleware", func(t *testing.T) {
		server3, err := New()
		if err != nil {
			t.Fatalf("unexpected error creating server: %v", err)
		}

		// Should not panic
		server3.AddMiddlewares(nil)
		server3.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()
		server3.router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})
}

// Test Handle method and H shortcut
func TestServer_Handle(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		methods      []string
		reqPath      string
		reqMethod    string
		expectStatus int
	}{
		{
			name:         "handle without methods",
			path:         "/test",
			methods:      nil,
			reqPath:      "/test",
			reqMethod:    "GET",
			expectStatus: http.StatusOK,
		},
		{
			name:         "handle with GET method",
			path:         "/test",
			methods:      []string{"GET"},
			reqPath:      "/test",
			reqMethod:    "GET",
			expectStatus: http.StatusOK,
		},
		{
			name:         "handle with POST method",
			path:         "/test",
			methods:      []string{"POST"},
			reqPath:      "/test",
			reqMethod:    "POST",
			expectStatus: http.StatusOK,
		},
		{
			name:         "handle with multiple methods",
			path:         "/test",
			methods:      []string{"GET", "POST"},
			reqPath:      "/test",
			reqMethod:    "GET",
			expectStatus: http.StatusOK,
		},
		{
			name:         "method not allowed",
			path:         "/test",
			methods:      []string{"POST"},
			reqPath:      "/test",
			reqMethod:    "GET",
			expectStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := New()
			if err != nil {
				t.Fatalf("unexpected error creating server: %v", err)
			}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})

			route := server.Handle(tt.path, handler, tt.methods...)
			if route == nil {
				t.Error("Handle should return a non-nil route")
			}

			req := httptest.NewRequest(tt.reqMethod, tt.reqPath, nil)
			rr := httptest.NewRecorder()
			server.router.ServeHTTP(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d", tt.expectStatus, rr.Code)
			}
		})
	}

	t.Run("H shortcut", func(t *testing.T) {
		server, err := New()
		if err != nil {
			t.Fatalf("unexpected error creating server: %v", err)
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		route := server.H("/test", handler, "GET")
		if route == nil {
			t.Error("H should return a non-nil route")
		}

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()
		server.router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})
}

// Test HandleFunc method and HF shortcut
func TestServer_HandleFunc(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		methods      []string
		reqPath      string
		reqMethod    string
		expectStatus int
	}{
		{
			name:         "handlefunc without methods",
			path:         "/test",
			methods:      nil,
			reqPath:      "/test",
			reqMethod:    "GET",
			expectStatus: http.StatusOK,
		},
		{
			name:         "handlefunc with GET method",
			path:         "/test",
			methods:      []string{"GET"},
			reqPath:      "/test",
			reqMethod:    "GET",
			expectStatus: http.StatusOK,
		},
		{
			name:         "handlefunc with POST method",
			path:         "/test",
			methods:      []string{"POST"},
			reqPath:      "/test",
			reqMethod:    "POST",
			expectStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := New()
			if err != nil {
				t.Fatalf("unexpected error creating server: %v", err)
			}

			handlerFunc := func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}

			route := server.HandleFunc(tt.path, handlerFunc, tt.methods...)
			if route == nil {
				t.Error("HandleFunc should return a non-nil route")
			}

			req := httptest.NewRequest(tt.reqMethod, tt.reqPath, nil)
			rr := httptest.NewRecorder()
			server.router.ServeHTTP(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d", tt.expectStatus, rr.Code)
			}
		})
	}

	t.Run("HF shortcut", func(t *testing.T) {
		server, err := New()
		if err != nil {
			t.Fatalf("unexpected error creating server: %v", err)
		}

		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}

		route := server.HF("/test", handlerFunc, "GET")
		if route == nil {
			t.Error("HF should return a non-nil route")
		}

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()
		server.router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})
}

// Test base path functionality with routes
func TestServer_BasePathIntegration(t *testing.T) {
	server, err := New()
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	server.WithBasePath("/api/v1")
	server.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("users"))
	})

	tests := []struct {
		name         string
		path         string
		expectStatus int
		expectBody   string
	}{
		{
			name:         "request to base path + route",
			path:         "/api/v1/users",
			expectStatus: http.StatusOK,
			expectBody:   "users",
		},
		{
			name:         "request to route without base path",
			path:         "/users",
			expectStatus: http.StatusNotFound,
			expectBody:   "404 page not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()
			server.router.ServeHTTP(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d", tt.expectStatus, rr.Code)
			}

			body := strings.TrimSpace(rr.Body.String())
			if body != tt.expectBody {
				t.Errorf("expected body %q, got %q", tt.expectBody, body)
			}
		})
	}
}

// Test HTTP method-specific handlers
func TestServer_HTTPMethodHandlers(t *testing.T) {
	tests := []struct {
		name         string
		setupRoute   func(*Server, string, http.HandlerFunc) *mux.Route
		method       string
		path         string
		expectStatus int
	}{
		// GET handlers
		{
			name:         "Get method",
			setupRoute:   (*Server).Get,
			method:       "GET",
			path:         "/get",
			expectStatus: http.StatusOK,
		},
		{
			name:         "GET method (alias)",
			setupRoute:   (*Server).GET,
			method:       "GET",
			path:         "/get-alias",
			expectStatus: http.StatusOK,
		},
		// POST handlers
		{
			name:         "Post method",
			setupRoute:   (*Server).Post,
			method:       "POST",
			path:         "/post",
			expectStatus: http.StatusOK,
		},
		{
			name:         "POST method (alias)",
			setupRoute:   (*Server).POST,
			method:       "POST",
			path:         "/post-alias",
			expectStatus: http.StatusOK,
		},
		// PUT handlers
		{
			name:         "Put method",
			setupRoute:   (*Server).Put,
			method:       "PUT",
			path:         "/put",
			expectStatus: http.StatusOK,
		},
		{
			name:         "PUT method (alias)",
			setupRoute:   (*Server).PUT,
			method:       "PUT",
			path:         "/put-alias",
			expectStatus: http.StatusOK,
		},
		// PATCH handlers
		{
			name:         "Patch method",
			setupRoute:   (*Server).Patch,
			method:       "PATCH",
			path:         "/patch",
			expectStatus: http.StatusOK,
		},
		{
			name:         "PATCH method (alias)",
			setupRoute:   (*Server).PATCH,
			method:       "PATCH",
			path:         "/patch-alias",
			expectStatus: http.StatusOK,
		},
		// DELETE handlers
		{
			name:         "Delete method",
			setupRoute:   (*Server).Delete,
			method:       "DELETE",
			path:         "/delete",
			expectStatus: http.StatusOK,
		},
		{
			name:         "DELETE method (alias)",
			setupRoute:   (*Server).DELETE,
			method:       "DELETE",
			path:         "/delete-alias",
			expectStatus: http.StatusOK,
		},
		// OPTIONS handlers
		{
			name:         "Options method",
			setupRoute:   (*Server).Options,
			method:       "OPTIONS",
			path:         "/options",
			expectStatus: http.StatusOK,
		},
		{
			name:         "OPTIONS method (alias)",
			setupRoute:   (*Server).OPTIONS,
			method:       "OPTIONS",
			path:         "/options-alias",
			expectStatus: http.StatusOK,
		},
		// HEAD handlers
		{
			name:         "Head method",
			setupRoute:   (*Server).Head,
			method:       "HEAD",
			path:         "/head",
			expectStatus: http.StatusOK,
		},
		{
			name:         "HEAD method (alias)",
			setupRoute:   (*Server).HEAD,
			method:       "HEAD",
			path:         "/head-alias",
			expectStatus: http.StatusOK,
		},
		// TRACE handlers
		{
			name:         "Trace method",
			setupRoute:   (*Server).Trace,
			method:       "TRACE",
			path:         "/trace",
			expectStatus: http.StatusOK,
		},
		{
			name:         "TRACE method (alias)",
			setupRoute:   (*Server).TRACE,
			method:       "TRACE",
			path:         "/trace-alias",
			expectStatus: http.StatusOK,
		},
		// CONNECT handlers
		{
			name:         "Connect method",
			setupRoute:   (*Server).Connect,
			method:       "CONNECT",
			path:         "/connect",
			expectStatus: http.StatusOK,
		},
		{
			name:         "CONNECT method (alias)",
			setupRoute:   (*Server).CONNECT,
			method:       "CONNECT",
			path:         "/connect-alias",
			expectStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := New()
			if err != nil {
				t.Fatalf("unexpected error creating server: %v", err)
			}

			handler := func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("method " + r.Method))
			}

			route := tt.setupRoute(server, tt.path, handler)
			if route == nil {
				t.Error("route should not be nil")
			}

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rr := httptest.NewRecorder()
			server.router.ServeHTTP(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d", tt.expectStatus, rr.Code)
			}

			expectedBody := "method " + tt.method
			body := strings.TrimSpace(rr.Body.String())
			if body != expectedBody {
				t.Errorf("expected body %q, got %q", expectedBody, body)
			}
		})
	}
}

// Test wrong method for specific handlers
func TestServer_HTTPMethodHandlers_WrongMethod(t *testing.T) {
	server, err := New()
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	// Set up GET handler
	server.Get("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Try to access with POST
	req := httptest.NewRequest("POST", "/test", nil)
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

// Helper function to create a real AuthManager for testing
func createTestAuthManager(t *testing.T) *AuthManager {
	// Create memory database
	db := NewMemoryAuthDatabase()

	// Create auth config
	authCfg := AuthConfig{
		Database:               db,
		JWTAccessSecret:        "3031323334353637383940414243444546474849505152535455565758596061", // hex-encoded 32 bytes
		JWTRefreshSecret:       "6162636465666768697071727374757677787980818283848586878889909192", // hex-encoded 32 bytes
		AccessTokenDuration:    5 * time.Minute,
		RefreshTokenDuration:   24 * time.Hour,
		IssuerNameInJWT:        "test-issuer",
		AuthBasePath:           "/api/v1/auth",
		RefreshTokenCookieName: "_servexrt",
	}

	// Create auth manager
	authManager, err := NewAuthManager(authCfg)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	return authManager
}

// Test WithAuth method
func TestServer_WithAuth(t *testing.T) {
	t.Run("auth enabled", func(t *testing.T) {
		logger := &MockLogger{}
		server, err := New(WithLogger(logger))
		if err != nil {
			t.Fatalf("unexpected error creating server: %v", err)
		}

		// Enable auth and set real auth manager
		server.opts.Auth.Enabled = true
		server.auth = createTestAuthManager(t)

		originalHandler := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("authorized"))
		}

		// Test that WithAuth returns a valid handler function
		wrappedHandler := server.WithAuth(originalHandler, UserRole("admin"))
		if wrappedHandler == nil {
			t.Error("WithAuth should return a non-nil handler")
		}

		// Test that it rejects requests without auth (this verifies auth integration)
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()
		wrappedHandler(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d for unauthenticated request, got %d", http.StatusUnauthorized, rr.Code)
		}
	})

	t.Run("auth disabled", func(t *testing.T) {
		logger := &MockLogger{}
		server, err := New(WithLogger(logger))
		if err != nil {
			t.Fatalf("unexpected error creating server: %v", err)
		}

		// Auth is disabled by default
		originalHandler := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("no auth"))
		}

		wrappedHandler := server.WithAuth(originalHandler, UserRole("admin"))

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()
		wrappedHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}

		body := strings.TrimSpace(rr.Body.String())
		if body != "no auth" {
			t.Errorf("expected body %q, got %q", "no auth", body)
		}

		// Check that error was logged
		if len(logger.Messages) == 0 {
			t.Error("expected error message to be logged when auth is disabled")
		} else if !strings.Contains(logger.Messages[0], "auth is not enabled") {
			t.Errorf("expected error message about auth not enabled, got: %s", logger.Messages[0])
		}
	})
}

// Test HandleWithAuth and HA shortcut
func TestServer_HandleWithAuth(t *testing.T) {
	logger := &MockLogger{}
	server, err := New(WithLogger(logger))
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	// Enable auth and set real auth manager
	server.opts.Auth.Enabled = true
	server.auth = createTestAuthManager(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("auth handler"))
	})

	t.Run("HandleWithAuth", func(t *testing.T) {
		route := server.HandleWithAuth("/auth-test", handler, UserRole("admin"))
		if route == nil {
			t.Error("HandleWithAuth should return a non-nil route")
		}

		// Test that route requires auth (should reject without auth header)
		req := httptest.NewRequest("GET", "/auth-test", nil)
		rr := httptest.NewRecorder()
		server.router.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d for unauthenticated request, got %d", http.StatusUnauthorized, rr.Code)
		}
	})

	t.Run("HA shortcut", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ha handler"))
		}

		route := server.HA("/ha-test", handlerFunc, UserRole("admin"))
		if route == nil {
			t.Error("HA should return a non-nil route")
		}

		// Test that route requires auth (should reject without auth header)
		req := httptest.NewRequest("GET", "/ha-test", nil)
		rr := httptest.NewRecorder()
		server.router.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d for unauthenticated request, got %d", http.StatusUnauthorized, rr.Code)
		}
	})
}

// Test HandleFuncWithAuth and HFA shortcut
func TestServer_HandleFuncWithAuth(t *testing.T) {
	logger := &MockLogger{}
	server, err := New(WithLogger(logger))
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	// Enable auth and set real auth manager
	server.opts.Auth.Enabled = true
	server.auth = createTestAuthManager(t)

	t.Run("HandleFuncWithAuth", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("auth func handler"))
		}

		route := server.HandleFuncWithAuth("/auth-func-test", handlerFunc, UserRole("admin"))
		if route == nil {
			t.Error("HandleFuncWithAuth should return a non-nil route")
		}

		// Test that route requires auth (should reject without auth header)
		req := httptest.NewRequest("GET", "/auth-func-test", nil)
		rr := httptest.NewRecorder()
		server.router.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d for unauthenticated request, got %d", http.StatusUnauthorized, rr.Code)
		}
	})

	t.Run("HFA shortcut", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("hfa handler"))
		}

		route := server.HFA("/hfa-test", handlerFunc, UserRole("admin"))
		if route == nil {
			t.Error("HFA should return a non-nil route")
		}

		// Test that route requires auth (should reject without auth header)
		req := httptest.NewRequest("GET", "/hfa-test", nil)
		rr := httptest.NewRecorder()
		server.router.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d for unauthenticated request, got %d", http.StatusUnauthorized, rr.Code)
		}
	})
}

// Test HTTP method-specific handlers with auth
func TestServer_HTTPMethodHandlersWithAuth(t *testing.T) {
	tests := []struct {
		name       string
		setupRoute func(*Server, string, http.HandlerFunc, ...UserRole) *mux.Route
		method     string
		path       string
	}{
		{
			name:       "GetWithAuth",
			setupRoute: (*Server).GetWithAuth,
			method:     "GET",
			path:       "/get-auth",
		},
		{
			name:       "PostWithAuth",
			setupRoute: (*Server).PostWithAuth,
			method:     "POST",
			path:       "/post-auth",
		},
		{
			name:       "PutWithAuth",
			setupRoute: (*Server).PutWithAuth,
			method:     "PUT",
			path:       "/put-auth",
		},
		{
			name:       "PatchWithAuth",
			setupRoute: (*Server).PatchWithAuth,
			method:     "PATCH",
			path:       "/patch-auth",
		},
		{
			name:       "DeleteWithAuth",
			setupRoute: (*Server).DeleteWithAuth,
			method:     "DELETE",
			path:       "/delete-auth",
		},
		{
			name:       "OptionsWithAuth",
			setupRoute: (*Server).OptionsWithAuth,
			method:     "OPTIONS",
			path:       "/options-auth",
		},
		{
			name:       "HeadWithAuth",
			setupRoute: (*Server).HeadWithAuth,
			method:     "HEAD",
			path:       "/head-auth",
		},
		{
			name:       "TraceWithAuth",
			setupRoute: (*Server).TraceWithAuth,
			method:     "TRACE",
			path:       "/trace-auth",
		},
		{
			name:       "ConnectWithAuth",
			setupRoute: (*Server).ConnectWithAuth,
			method:     "CONNECT",
			path:       "/connect-auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &MockLogger{}
			server, err := New(WithLogger(logger))
			if err != nil {
				t.Fatalf("unexpected error creating server: %v", err)
			}

			// Enable auth and set real auth manager
			server.opts.Auth.Enabled = true
			server.auth = createTestAuthManager(t)

			handler := func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("auth " + r.Method))
			}

			route := tt.setupRoute(server, tt.path, handler, UserRole("admin"))
			if route == nil {
				t.Error("route should not be nil")
			}

			// Test that route requires auth (should reject without auth header)
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rr := httptest.NewRecorder()
			server.router.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Errorf("expected status %d for unauthenticated request, got %d", http.StatusUnauthorized, rr.Code)
			}
		})
	}
}

// Test route return values for method chaining
func TestServer_RouteChaining(t *testing.T) {
	server, err := New()
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	// Test that routes can be chained with additional settings
	route := server.Get("/chain-test", handler).Host("example.com")
	if route == nil {
		t.Error("route should not be nil")
	}

	// Test request to wrong host should fail
	req := httptest.NewRequest("GET", "/chain-test", nil)
	req.Host = "wronghost.com"
	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Error("request to wrong host should not succeed")
	}

	// Test request to correct host should succeed
	req2 := httptest.NewRequest("GET", "/chain-test", nil)
	req2.Host = "example.com"
	rr2 := httptest.NewRecorder()
	server.router.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Errorf("request to correct host should succeed, got status %d", rr2.Code)
	}
}
