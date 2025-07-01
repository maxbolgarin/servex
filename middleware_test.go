package servex

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// TestLoggingResponseWriter tests the loggingResponseWriter wrapper
func TestLoggingResponseWriter(t *testing.T) {
	t.Run("captures status code", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		lrw := &loggingResponseWriter{ResponseWriter: recorder, statusCode: http.StatusOK}

		lrw.WriteHeader(http.StatusNotFound)

		if lrw.statusCode != http.StatusNotFound {
			t.Errorf("expected status code %d, got %d", http.StatusNotFound, lrw.statusCode)
		}

		if !lrw.wroteHeader {
			t.Error("wroteHeader should be true after calling WriteHeader")
		}
	})

	t.Run("prevents multiple WriteHeader calls", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		lrw := &loggingResponseWriter{ResponseWriter: recorder, statusCode: http.StatusOK}

		lrw.WriteHeader(http.StatusNotFound)
		lrw.WriteHeader(http.StatusInternalServerError) // This should be ignored

		if lrw.statusCode != http.StatusNotFound {
			t.Errorf("expected status code %d, got %d", http.StatusNotFound, lrw.statusCode)
		}
	})

	t.Run("Write calls WriteHeader if not already called", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		lrw := &loggingResponseWriter{ResponseWriter: recorder, statusCode: http.StatusOK}

		_, err := lrw.Write([]byte("test"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !lrw.wroteHeader {
			t.Error("wroteHeader should be true after calling Write")
		}

		if lrw.statusCode != http.StatusOK {
			t.Errorf("expected status code %d, got %d", http.StatusOK, lrw.statusCode)
		}
	})
}

// TestRegisterLoggingMiddleware tests the logging middleware registration and functionality
func TestRegisterLoggingMiddleware(t *testing.T) {
	t.Run("logs requests with custom logger", func(t *testing.T) {
		mockLogger := &MockRequestLogger{}
		router := mux.NewRouter()

		RegisterLoggingMiddleware(router, mockLogger, nil)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test response"))
		})

		req := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if len(mockLogger.LoggedBundles) != 1 {
			t.Errorf("expected 1 logged request, got %d", len(mockLogger.LoggedBundles))
		}

		bundle := mockLogger.LoggedBundles[0]
		if bundle.Request.Method != "GET" {
			t.Errorf("expected method GET, got %s", bundle.Request.Method)
		}
		if bundle.Request.URL.Path != "/test" {
			t.Errorf("expected path /test, got %s", bundle.Request.URL.Path)
		}
	})

	t.Run("skips logging when NoLog is set", func(t *testing.T) {
		mockLogger := &MockRequestLogger{}
		router := mux.NewRouter()

		RegisterLoggingMiddleware(router, mockLogger, nil)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			C(w, r).NoLog()
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if len(mockLogger.LoggedBundles) != 0 {
			t.Errorf("expected 0 logged requests, got %d", len(mockLogger.LoggedBundles))
		}
	})

	t.Run("uses default logger when nil provided", func(t *testing.T) {
		router := mux.NewRouter()

		// Should not panic with nil logger
		RegisterLoggingMiddleware(router, nil, nil)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		// Should not panic
		router.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", recorder.Code)
		}
	})
}

// TestRegisterRecoverMiddleware tests the panic recovery middleware
func TestRegisterRecoverMiddleware(t *testing.T) {
	t.Run("recovers from panic", func(t *testing.T) {
		mockLogger := &MockLogger{}
		router := mux.NewRouter()

		RegisterRecoverMiddleware(router, mockLogger)

		router.HandleFunc("/panic", func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		})

		req := httptest.NewRequest("GET", "/panic", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusInternalServerError {
			t.Errorf("expected status 500, got %d", recorder.Code)
		}

		if len(mockLogger.Messages) == 0 {
			t.Error("expected panic to be logged")
		}

		// Check that the error field contains "panic recovered"
		// The logger.Error call uses: logger.Error(string(debug.Stack()), "error", err)
		// where err is fmt.Errorf("panic recovered: %v", panicErr)
		found := false
		for i := 0; i < len(mockLogger.Fields); i++ {
			fields := mockLogger.Fields[i]
			for j := 0; j < len(fields)-1; j += 2 {
				if key, ok := fields[j].(string); ok && key == "error" {
					if errValue, ok := fields[j+1].(error); ok {
						if strings.Contains(errValue.Error(), "panic recovered") {
							found = true
							break
						}
					}
				}
			}
			if found {
				break
			}
		}

		if !found {
			t.Errorf("expected log fields to contain error with 'panic recovered', got fields: %+v", mockLogger.Fields)
		}
	})

	t.Run("uses default logger when nil provided", func(t *testing.T) {
		router := mux.NewRouter()

		// Should not panic with nil logger
		RegisterRecoverMiddleware(router, nil)

		router.HandleFunc("/panic", func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		})

		req := httptest.NewRequest("GET", "/panic", nil)
		recorder := httptest.NewRecorder()

		// Should not panic
		router.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusInternalServerError {
			t.Errorf("expected status 500, got %d", recorder.Code)
		}
	})

	t.Run("does not interfere with normal requests", func(t *testing.T) {
		router := mux.NewRouter()

		RegisterRecoverMiddleware(router, nil)

		router.HandleFunc("/normal", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		})

		req := httptest.NewRequest("GET", "/normal", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", recorder.Code)
		}

		body := recorder.Body.String()
		if body != "success" {
			t.Errorf("expected body 'success', got %s", body)
		}
	})
}

// TestRegisterSimpleAuthMiddleware tests the simple authentication middleware
func TestRegisterSimpleAuthMiddleware(t *testing.T) {
	t.Run("allows valid token", func(t *testing.T) {
		router := mux.NewRouter()

		RegisterSimpleAuthMiddleware(router, "valid-token")

		router.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("protected content"))
		})

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "valid-token")
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", recorder.Code)
		}
	})

	t.Run("allows valid bearer token", func(t *testing.T) {
		router := mux.NewRouter()

		RegisterSimpleAuthMiddleware(router, "valid-token")

		router.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", recorder.Code)
		}
	})

	t.Run("rejects invalid token", func(t *testing.T) {
		router := mux.NewRouter()

		RegisterSimpleAuthMiddleware(router, "valid-token")

		router.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "invalid-token")
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", recorder.Code)
		}
	})

	t.Run("rejects missing authorization header", func(t *testing.T) {
		router := mux.NewRouter()

		RegisterSimpleAuthMiddleware(router, "valid-token")

		router.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/protected", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", recorder.Code)
		}
	})

	t.Run("does not register middleware when token is empty", func(t *testing.T) {
		router := mux.NewRouter()

		RegisterSimpleAuthMiddleware(router, "")

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		// Should work without authorization since middleware is not registered
		if recorder.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", recorder.Code)
		}
	})
}

// TestRegisterRequestSizeLimitMiddleware tests the request size limiting middleware
func TestRegisterRequestSizeLimitMiddleware(t *testing.T) {
	t.Run("enforces content-length limits", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			EnableRequestSizeLimits: true,
			MaxRequestBodySize:      100, // 100 bytes
		}

		RegisterRequestSizeLimitMiddleware(router, opts)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Create request with large content-length
		req := httptest.NewRequest("POST", "/test", strings.NewReader("test body"))
		req.ContentLength = 200 // Exceeds limit
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("expected status 413, got %d", recorder.Code)
		}
	})

	t.Run("allows requests within limits", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			EnableRequestSizeLimits: true,
			MaxRequestBodySize:      1000,
		}

		RegisterRequestSizeLimitMiddleware(router, opts)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("POST", "/test", strings.NewReader("small body"))
		req.ContentLength = 10
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", recorder.Code)
		}
	})

	t.Run("handles chunked encoding", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			EnableRequestSizeLimits: true,
			MaxRequestBodySize:      100,
		}

		RegisterRequestSizeLimitMiddleware(router, opts)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("POST", "/test", strings.NewReader("test body"))
		req.ContentLength = -1 // Indicates chunked encoding
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		// Should pass through for chunked encoding
		if recorder.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", recorder.Code)
		}
	})

	t.Run("enforces JSON body limits", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			EnableRequestSizeLimits: true,
			MaxJSONBodySize:         50,
		}

		RegisterRequestSizeLimitMiddleware(router, opts)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("POST", "/test", strings.NewReader("test body"))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = 100 // Exceeds JSON limit
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("expected status 413, got %d", recorder.Code)
		}
	})

	t.Run("does not register when disabled", func(t *testing.T) {
		router := mux.NewRouter()
		opts := Options{
			EnableRequestSizeLimits: false,
		}

		RegisterRequestSizeLimitMiddleware(router, opts)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Large request should pass through when middleware is disabled
		req := httptest.NewRequest("POST", "/test", strings.NewReader("large body"))
		req.ContentLength = 10000
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Errorf("expected status 200 when middleware disabled, got %d", recorder.Code)
		}
	})
}

// TestRegisterCustomHeadersMiddleware tests the custom headers middleware
func TestRegisterCustomHeadersMiddleware(t *testing.T) {
	t.Run("adds custom headers", func(t *testing.T) {
		router := mux.NewRouter()
		customHeaders := map[string]string{
			"X-Custom-Header": "custom-value",
			"X-API-Version":   "v1.0",
		}

		RegisterCustomHeadersMiddleware(router, customHeaders)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if recorder.Header().Get("X-Custom-Header") != "custom-value" {
			t.Errorf("expected X-Custom-Header to be 'custom-value', got '%s'",
				recorder.Header().Get("X-Custom-Header"))
		}

		if recorder.Header().Get("X-API-Version") != "v1.0" {
			t.Errorf("expected X-API-Version to be 'v1.0', got '%s'",
				recorder.Header().Get("X-API-Version"))
		}
	})

	t.Run("does not interfere when empty", func(t *testing.T) {
		router := mux.NewRouter()

		RegisterCustomHeadersMiddleware(router, map[string]string{})

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", recorder.Code)
		}
	})
}

// TestRegisterHeaderRemovalMiddleware tests the header removal middleware
func TestRegisterHeaderRemovalMiddleware(t *testing.T) {
	t.Run("removes specified headers", func(t *testing.T) {
		router := mux.NewRouter()
		headersToRemove := []string{"Server", "X-Powered-By"}

		RegisterHeaderRemovalMiddleware(router, headersToRemove)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			// Set headers that should be removed
			w.Header().Set("Server", "nginx")
			w.Header().Set("X-Powered-By", "PHP")
			w.Header().Set("X-Keep-This", "should-remain")
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if recorder.Header().Get("Server") != "" {
			t.Error("Server header should have been removed")
		}

		if recorder.Header().Get("X-Powered-By") != "" {
			t.Error("X-Powered-By header should have been removed")
		}

		if recorder.Header().Get("X-Keep-This") != "should-remain" {
			t.Error("X-Keep-This header should have been preserved")
		}
	})

	t.Run("does not interfere when empty", func(t *testing.T) {
		router := mux.NewRouter()

		RegisterHeaderRemovalMiddleware(router, []string{})

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "nginx")
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		// Header should remain when no removal list provided
		if recorder.Header().Get("Server") != "nginx" {
			t.Error("Server header should have been preserved")
		}
	})
}

// MockRequestLogger for testing
type MockRequestLogger struct {
	LoggedBundles []RequestLogBundle
}

func (m *MockRequestLogger) Log(bundle RequestLogBundle) {
	m.LoggedBundles = append(m.LoggedBundles, bundle)
}
