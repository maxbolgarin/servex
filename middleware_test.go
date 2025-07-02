package servex

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"compress/gzip"

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

		req := httptest.NewRequest(GET, "/test", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		if len(mockLogger.LoggedBundles) != 1 {
			t.Errorf("expected 1 logged request, got %d", len(mockLogger.LoggedBundles))
		}

		bundle := mockLogger.LoggedBundles[0]
		if bundle.Request.Method != GET {
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

		req := httptest.NewRequest(GET, "/test", nil)
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

		req := httptest.NewRequest(GET, "/test", nil)
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

		req := httptest.NewRequest(GET, "/panic", nil)
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

		req := httptest.NewRequest(GET, "/panic", nil)
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

		req := httptest.NewRequest(GET, "/normal", nil)
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

		req := httptest.NewRequest(GET, "/protected", nil)
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

		req := httptest.NewRequest(GET, "/protected", nil)
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

		req := httptest.NewRequest(GET, "/protected", nil)
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

		req := httptest.NewRequest(GET, "/protected", nil)
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

		req := httptest.NewRequest(GET, "/test", nil)
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
		req := httptest.NewRequest(POST, "/test", strings.NewReader("test body"))
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

		req := httptest.NewRequest(POST, "/test", strings.NewReader("small body"))
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

		req := httptest.NewRequest(POST, "/test", strings.NewReader("test body"))
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

		req := httptest.NewRequest(POST, "/test", strings.NewReader("test body"))
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
		req := httptest.NewRequest(POST, "/test", strings.NewReader("large body"))
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

		req := httptest.NewRequest(GET, "/test", nil)
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

		req := httptest.NewRequest(GET, "/test", nil)
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

		req := httptest.NewRequest(GET, "/test", nil)
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

		req := httptest.NewRequest(GET, "/test", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, req)

		// Header should remain when no removal list provided
		if recorder.Header().Get("Server") != "nginx" {
			t.Error("Server header should have been preserved")
		}
	})
}

// TestRegisterCompressionMiddleware tests the compression middleware registration and functionality
func TestRegisterCompressionMiddleware(t *testing.T) {
	// Test 1: Disabled compression middleware
	t.Run("disabled compression", func(t *testing.T) {
		router := mux.NewRouter()
		cfg := CompressionConfig{Enabled: false}

		// Register middleware (should not register anything)
		RegisterCompressionMiddleware(router, cfg)

		// Add a test handler
		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(strings.Repeat("Hello World! ", 100))) // Large content
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Accept-Encoding", "gzip")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should not be compressed
		if w.Header().Get("Content-Encoding") != "" {
			t.Errorf("Expected no compression, but got Content-Encoding: %s", w.Header().Get("Content-Encoding"))
		}
	})

	// Test 2: Basic gzip compression
	t.Run("gzip compression", func(t *testing.T) {
		router := mux.NewRouter()
		cfg := CompressionConfig{
			Enabled: true,
			Level:   6,
			MinSize: 100,
			Types:   []string{"text/plain"},
		}

		RegisterCompressionMiddleware(router, cfg)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(strings.Repeat("Hello World! ", 100))) // Large content
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Accept-Encoding", "gzip")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should be compressed
		if w.Header().Get("Content-Encoding") != "gzip" {
			t.Errorf("Expected gzip compression, but got Content-Encoding: %s", w.Header().Get("Content-Encoding"))
		}

		if w.Header().Get("Vary") != "Accept-Encoding" {
			t.Errorf("Expected Vary: Accept-Encoding, but got: %s", w.Header().Get("Vary"))
		}

		// Verify content is actually compressed by decompressing it
		reader, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
		if err != nil {
			t.Fatalf("Failed to create gzip reader: %v", err)
		}
		defer reader.Close()

		decompressed, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("Failed to decompress response: %v", err)
		}

		expectedContent := strings.Repeat("Hello World! ", 100)
		if string(decompressed) != expectedContent {
			t.Errorf("Decompressed content doesn't match expected")
		}
	})

	// Test 3: Deflate compression
	t.Run("deflate compression", func(t *testing.T) {
		router := mux.NewRouter()
		cfg := CompressionConfig{
			Enabled: true,
			Level:   6,
			MinSize: 100,
			Types:   []string{"text/plain"},
		}

		RegisterCompressionMiddleware(router, cfg)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(strings.Repeat("Hello World! ", 100))) // Large content
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Accept-Encoding", "deflate") // Only deflate

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should be compressed with deflate
		if w.Header().Get("Content-Encoding") != "deflate" {
			t.Errorf("Expected deflate compression, but got Content-Encoding: %s", w.Header().Get("Content-Encoding"))
		}
	})

	// Test 4: No Accept-Encoding header
	t.Run("no accept-encoding header", func(t *testing.T) {
		router := mux.NewRouter()
		cfg := CompressionConfig{
			Enabled: true,
			Level:   6,
			MinSize: 100,
			Types:   []string{"text/plain"},
		}

		RegisterCompressionMiddleware(router, cfg)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(strings.Repeat("Hello World! ", 100))) // Large content
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		// No Accept-Encoding header

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should not be compressed
		if w.Header().Get("Content-Encoding") != "" {
			t.Errorf("Expected no compression, but got Content-Encoding: %s", w.Header().Get("Content-Encoding"))
		}
	})

	// Test 5: Client doesn't accept compression
	t.Run("client doesn't accept compression", func(t *testing.T) {
		router := mux.NewRouter()
		cfg := CompressionConfig{
			Enabled: true,
			Level:   6,
			MinSize: 100,
			Types:   []string{"text/plain"},
		}

		RegisterCompressionMiddleware(router, cfg)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(strings.Repeat("Hello World! ", 100))) // Large content
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Accept-Encoding", "br") // Only Brotli (not supported)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should not be compressed
		if w.Header().Get("Content-Encoding") != "" {
			t.Errorf("Expected no compression, but got Content-Encoding: %s", w.Header().Get("Content-Encoding"))
		}
	})
}

// TestCompressionResponseWriter tests the compression response writer directly
func TestCompressionResponseWriter(t *testing.T) {
	// Test 1: Small content should not be compressed
	t.Run("small content not compressed", func(t *testing.T) {
		w := httptest.NewRecorder()
		compressibleTypes := map[string]bool{"text/plain": true}

		crw := &compressionResponseWriter{
			ResponseWriter:    w,
			encoding:          "gzip",
			level:             6,
			minSize:           100,
			compressibleTypes: compressibleTypes,
			buf:               make([]byte, 0),
		}

		// Write small content
		crw.Header().Set("Content-Type", "text/plain")
		crw.WriteHeader(http.StatusOK)
		crw.Write([]byte("Small content")) // Less than minSize
		crw.Close()

		// Should not be compressed
		if w.Header().Get("Content-Encoding") != "" {
			t.Errorf("Expected no compression for small content, but got Content-Encoding: %s", w.Header().Get("Content-Encoding"))
		}

		if w.Body.String() != "Small content" {
			t.Errorf("Expected uncompressed content, but got: %s", w.Body.String())
		}
	})

	// Test 2: Large content should be compressed
	t.Run("large content compressed", func(t *testing.T) {
		w := httptest.NewRecorder()
		compressibleTypes := map[string]bool{"text/plain": true}

		crw := &compressionResponseWriter{
			ResponseWriter:    w,
			encoding:          "gzip",
			level:             6,
			minSize:           50,
			compressibleTypes: compressibleTypes,
			buf:               make([]byte, 0),
		}

		// Write large content
		crw.Header().Set("Content-Type", "text/plain")
		crw.WriteHeader(http.StatusOK)
		largeContent := strings.Repeat("Large content for compression! ", 10)
		crw.Write([]byte(largeContent))
		crw.Close()

		// Should be compressed
		if w.Header().Get("Content-Encoding") != "gzip" {
			t.Errorf("Expected gzip compression, but got Content-Encoding: %s", w.Header().Get("Content-Encoding"))
		}

		if w.Header().Get("Vary") != "Accept-Encoding" {
			t.Errorf("Expected Vary: Accept-Encoding, but got: %s", w.Header().Get("Vary"))
		}

		// Verify compressed content
		reader, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
		if err != nil {
			t.Fatalf("Failed to create gzip reader: %v", err)
		}
		defer reader.Close()

		decompressed, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("Failed to decompress response: %v", err)
		}

		if string(decompressed) != largeContent {
			t.Errorf("Decompressed content doesn't match expected")
		}
	})

	// Test 3: Non-compressible content type
	t.Run("non-compressible content type", func(t *testing.T) {
		w := httptest.NewRecorder()
		compressibleTypes := map[string]bool{"text/plain": true}

		crw := &compressionResponseWriter{
			ResponseWriter:    w,
			encoding:          "gzip",
			level:             6,
			minSize:           50,
			compressibleTypes: compressibleTypes,
			buf:               make([]byte, 0),
		}

		// Write content with non-compressible type
		crw.Header().Set("Content-Type", "image/png")
		crw.WriteHeader(http.StatusOK)
		largeContent := strings.Repeat("Large binary content! ", 10)
		crw.Write([]byte(largeContent))
		crw.Close()

		// Should not be compressed
		if w.Header().Get("Content-Encoding") != "" {
			t.Errorf("Expected no compression for non-compressible type, but got Content-Encoding: %s", w.Header().Get("Content-Encoding"))
		}

		if w.Body.String() != largeContent {
			t.Errorf("Expected uncompressed content, but got different content")
		}
	})

	// Test 4: Already compressed content
	t.Run("already compressed content", func(t *testing.T) {
		w := httptest.NewRecorder()
		compressibleTypes := map[string]bool{"text/plain": true}

		crw := &compressionResponseWriter{
			ResponseWriter:    w,
			encoding:          "gzip",
			level:             6,
			minSize:           50,
			compressibleTypes: compressibleTypes,
			buf:               make([]byte, 0),
		}

		// Set Content-Encoding before writing
		crw.Header().Set("Content-Type", "text/plain")
		crw.Header().Set("Content-Encoding", "br") // Already compressed with Brotli
		crw.WriteHeader(http.StatusOK)
		largeContent := strings.Repeat("Large content! ", 10)
		crw.Write([]byte(largeContent))
		crw.Close()

		// Should not be re-compressed
		if w.Header().Get("Content-Encoding") != "br" {
			t.Errorf("Expected original Content-Encoding to be preserved, but got: %s", w.Header().Get("Content-Encoding"))
		}

		if w.Body.String() != largeContent {
			t.Errorf("Expected content to be unchanged, but got different content")
		}
	})

	// Test 5: Content-Length header optimization
	t.Run("content-length header optimization", func(t *testing.T) {
		w := httptest.NewRecorder()
		compressibleTypes := map[string]bool{"text/plain": true}

		crw := &compressionResponseWriter{
			ResponseWriter:    w,
			encoding:          "gzip",
			level:             6,
			minSize:           50,
			compressibleTypes: compressibleTypes,
			buf:               make([]byte, 0),
		}

		// Set Content-Length that indicates large content
		largeContent := strings.Repeat("Large content! ", 10)
		crw.Header().Set("Content-Type", "text/plain")
		crw.Header().Set("Content-Length", strconv.Itoa(len(largeContent)))
		crw.WriteHeader(http.StatusOK)
		crw.Write([]byte(largeContent))
		crw.Close()

		// Should be compressed and Content-Length should be removed
		if w.Header().Get("Content-Encoding") != "gzip" {
			t.Errorf("Expected gzip compression, but got Content-Encoding: %s", w.Header().Get("Content-Encoding"))
		}

		if w.Header().Get("Content-Length") != "" {
			t.Errorf("Expected Content-Length to be removed, but got: %s", w.Header().Get("Content-Length"))
		}
	})

	// Test 6: Small Content-Length header
	t.Run("small content-length header", func(t *testing.T) {
		w := httptest.NewRecorder()
		compressibleTypes := map[string]bool{"text/plain": true}

		crw := &compressionResponseWriter{
			ResponseWriter:    w,
			encoding:          "gzip",
			level:             6,
			minSize:           100,
			compressibleTypes: compressibleTypes,
			buf:               make([]byte, 0),
		}

		// Set Content-Length that indicates small content
		smallContent := "Small"
		crw.Header().Set("Content-Type", "text/plain")
		crw.Header().Set("Content-Length", strconv.Itoa(len(smallContent)))
		crw.WriteHeader(http.StatusOK)
		crw.Write([]byte(smallContent))
		crw.Close()

		// Should not be compressed due to small Content-Length
		if w.Header().Get("Content-Encoding") != "" {
			t.Errorf("Expected no compression for small Content-Length, but got Content-Encoding: %s", w.Header().Get("Content-Encoding"))
		}

		if w.Body.String() != smallContent {
			t.Errorf("Expected uncompressed content, but got: %s", w.Body.String())
		}
	})
}

// TestShouldApplyCompression tests the path matching logic for compression
func TestShouldApplyCompression(t *testing.T) {
	// Test 1: No path restrictions
	t.Run("no path restrictions", func(t *testing.T) {
		cfg := CompressionConfig{}
		req := httptest.NewRequest(http.MethodGet, "/any/path", nil)

		if !shouldApplyCompression(req, cfg) {
			t.Error("Expected compression to be applied with no path restrictions")
		}
	})

	// Test 2: Include paths - matching
	t.Run("include paths matching", func(t *testing.T) {
		cfg := CompressionConfig{
			IncludePaths: []string{"/api/*", "/static/*"},
		}

		req1 := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req2 := httptest.NewRequest(http.MethodGet, "/static/style.css", nil)

		if !shouldApplyCompression(req1, cfg) {
			t.Error("Expected compression to be applied for matching include path /api/*")
		}

		if !shouldApplyCompression(req2, cfg) {
			t.Error("Expected compression to be applied for matching include path /static/*")
		}
	})

	// Test 3: Include paths - not matching
	t.Run("include paths not matching", func(t *testing.T) {
		cfg := CompressionConfig{
			IncludePaths: []string{"/api/*", "/static/*"},
		}

		req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)

		if shouldApplyCompression(req, cfg) {
			t.Error("Expected compression not to be applied for non-matching include path")
		}
	})

	// Test 4: Exclude paths - matching
	t.Run("exclude paths matching", func(t *testing.T) {
		cfg := CompressionConfig{
			ExcludePaths: []string{"/api/binary/*", "/downloads/*"},
		}

		req1 := httptest.NewRequest(http.MethodGet, "/api/binary/file.zip", nil)
		req2 := httptest.NewRequest(http.MethodGet, "/downloads/file.pdf", nil)

		if shouldApplyCompression(req1, cfg) {
			t.Error("Expected compression not to be applied for matching exclude path /api/binary/*")
		}

		if shouldApplyCompression(req2, cfg) {
			t.Error("Expected compression not to be applied for matching exclude path /downloads/*")
		}
	})

	// Test 5: Exclude paths - not matching
	t.Run("exclude paths not matching", func(t *testing.T) {
		cfg := CompressionConfig{
			ExcludePaths: []string{"/api/binary/*", "/downloads/*"},
		}

		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

		if !shouldApplyCompression(req, cfg) {
			t.Error("Expected compression to be applied for non-matching exclude path")
		}
	})

	// Test 6: Include and exclude paths - include wins
	t.Run("include and exclude paths - include wins", func(t *testing.T) {
		cfg := CompressionConfig{
			IncludePaths: []string{"/api/*"},
			ExcludePaths: []string{"/api/binary/*"},
		}

		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

		if !shouldApplyCompression(req, cfg) {
			t.Error("Expected compression to be applied when path matches include but not exclude")
		}
	})

	// Test 7: Include and exclude paths - exclude wins
	t.Run("include and exclude paths - exclude wins", func(t *testing.T) {
		cfg := CompressionConfig{
			IncludePaths: []string{"/api/*"},
			ExcludePaths: []string{"/api/binary/*"},
		}

		req := httptest.NewRequest(http.MethodGet, "/api/binary/file.zip", nil)

		if shouldApplyCompression(req, cfg) {
			t.Error("Expected compression not to be applied when path matches both include and exclude")
		}
	})
}

// TestCompressionMiddlewareDefaults tests default configuration values
func TestCompressionMiddlewareDefaults(t *testing.T) {
	// Test 1: Default compression level
	t.Run("default compression level", func(t *testing.T) {
		router := mux.NewRouter()
		cfg := CompressionConfig{
			Enabled: true,
			Level:   0, // Invalid level, should default to 6
			MinSize: 50,
			Types:   []string{"text/plain"},
		}

		RegisterCompressionMiddleware(router, cfg)

		// We can't directly test the level, but we can verify compression works
		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(strings.Repeat("Test content! ", 10)))
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Accept-Encoding", "gzip")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Header().Get("Content-Encoding") != "gzip" {
			t.Error("Expected compression to work with default level")
		}
	})

	// Test 2: Default minimum size
	t.Run("default minimum size", func(t *testing.T) {
		router := mux.NewRouter()
		cfg := CompressionConfig{
			Enabled: true,
			Level:   6,
			MinSize: -1, // Invalid size, should default to 1024
			Types:   []string{"text/plain"},
		}

		RegisterCompressionMiddleware(router, cfg)

		router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("Small content")) // Less than 1024 bytes
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Accept-Encoding", "gzip")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should not be compressed due to default minSize of 1024
		if w.Header().Get("Content-Encoding") != "" {
			t.Error("Expected no compression for small content with default minSize")
		}
	})

	// Test 3: Default MIME types
	t.Run("default mime types", func(t *testing.T) {
		router := mux.NewRouter()
		cfg := CompressionConfig{
			Enabled: true,
			Level:   6,
			MinSize: 50,
			Types:   nil, // Should use defaults
		}

		RegisterCompressionMiddleware(router, cfg)

		// Test various default types
		testCases := []struct {
			contentType    string
			shouldCompress bool
		}{
			{"text/html", true},
			{"text/css", true},
			{"text/plain", true},
			{"application/json", true},
			{"application/javascript", true},
			{"image/svg+xml", true},
			{"image/png", false}, // Not in defaults
			{"video/mp4", false}, // Not in defaults
		}

		for _, tc := range testCases {
			t.Run(tc.contentType, func(t *testing.T) {
				router.HandleFunc("/test-"+strings.ReplaceAll(tc.contentType, "/", "-"), func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", tc.contentType)
					w.Write([]byte(strings.Repeat("Test content! ", 10)))
				})

				req := httptest.NewRequest(http.MethodGet, "/test-"+strings.ReplaceAll(tc.contentType, "/", "-"), nil)
				req.Header.Set("Accept-Encoding", "gzip")

				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				hasCompression := w.Header().Get("Content-Encoding") == "gzip"
				if hasCompression != tc.shouldCompress {
					t.Errorf("Content-Type %s: expected compression=%t, got compression=%t",
						tc.contentType, tc.shouldCompress, hasCompression)
				}
			})
		}
	})
}

// TestCompressionEdgeCases tests edge cases and error conditions
func TestCompressionEdgeCases(t *testing.T) {
	// Test 1: WriteHeader called multiple times
	t.Run("write header multiple times", func(t *testing.T) {
		w := httptest.NewRecorder()
		compressibleTypes := map[string]bool{"text/plain": true}

		crw := &compressionResponseWriter{
			ResponseWriter:    w,
			encoding:          "gzip",
			level:             6,
			minSize:           50,
			compressibleTypes: compressibleTypes,
			buf:               make([]byte, 0),
		}

		crw.Header().Set("Content-Type", "text/plain")
		crw.WriteHeader(http.StatusOK)
		crw.WriteHeader(http.StatusInternalServerError) // Should be ignored

		largeContent := strings.Repeat("Content! ", 20)
		crw.Write([]byte(largeContent))
		crw.Close()

		// Should still work properly
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		if w.Header().Get("Content-Encoding") != "gzip" {
			t.Error("Expected compression to still work")
		}
	})

	// Test 2: Write called before WriteHeader
	t.Run("write before write header", func(t *testing.T) {
		w := httptest.NewRecorder()
		compressibleTypes := map[string]bool{"text/plain": true}

		crw := &compressionResponseWriter{
			ResponseWriter:    w,
			encoding:          "gzip",
			level:             6,
			minSize:           50,
			compressibleTypes: compressibleTypes,
			buf:               make([]byte, 0),
		}

		crw.Header().Set("Content-Type", "text/plain")
		// Call Write before WriteHeader
		largeContent := strings.Repeat("Content! ", 20)
		crw.Write([]byte(largeContent))
		crw.Close()

		// Should automatically call WriteHeader(200)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		if w.Header().Get("Content-Encoding") != "gzip" {
			t.Error("Expected compression to work when Write is called before WriteHeader")
		}
	})

	// Test 3: Content-Type with charset
	t.Run("content type with charset", func(t *testing.T) {
		w := httptest.NewRecorder()
		compressibleTypes := map[string]bool{"text/html": true}

		crw := &compressionResponseWriter{
			ResponseWriter:    w,
			encoding:          "gzip",
			level:             6,
			minSize:           50,
			compressibleTypes: compressibleTypes,
			buf:               make([]byte, 0),
		}

		// Content-Type with charset parameter
		crw.Header().Set("Content-Type", "text/html; charset=utf-8")
		crw.WriteHeader(http.StatusOK)

		largeContent := strings.Repeat("HTML content! ", 20)
		crw.Write([]byte(largeContent))
		crw.Close()

		// Should be compressed (charset should be ignored)
		if w.Header().Get("Content-Encoding") != "gzip" {
			t.Error("Expected compression to work with Content-Type containing charset")
		}
	})

	// Test 4: Empty content
	t.Run("empty content", func(t *testing.T) {
		w := httptest.NewRecorder()
		compressibleTypes := map[string]bool{"text/plain": true}

		crw := &compressionResponseWriter{
			ResponseWriter:    w,
			encoding:          "gzip",
			level:             6,
			minSize:           50,
			compressibleTypes: compressibleTypes,
			buf:               make([]byte, 0),
		}

		crw.Header().Set("Content-Type", "text/plain")
		crw.WriteHeader(http.StatusOK)
		// No content written
		crw.Close()

		// Should not be compressed (no content)
		if w.Header().Get("Content-Encoding") != "" {
			t.Error("Expected no compression for empty content")
		}

		if w.Body.Len() != 0 {
			t.Error("Expected empty body")
		}
	})

	// Test 5: Compression level boundary values
	t.Run("compression level boundaries", func(t *testing.T) {
		testCases := []struct {
			level    int
			expected int
		}{
			{-1, 6}, // Invalid, should default to 6
			{0, 6},  // Invalid, should default to 6
			{1, 1},  // Valid minimum
			{5, 5},  // Valid middle
			{9, 9},  // Valid maximum
			{10, 6}, // Invalid, should default to 6
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("level_%d", tc.level), func(t *testing.T) {
				router := mux.NewRouter()
				cfg := CompressionConfig{
					Enabled: true,
					Level:   tc.level,
					MinSize: 50,
					Types:   []string{"text/plain"},
				}

				RegisterCompressionMiddleware(router, cfg)

				router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/plain")
					w.Write([]byte(strings.Repeat("Test! ", 20)))
				})

				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				req.Header.Set("Accept-Encoding", "gzip")

				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				// Should always compress regardless of level (we can't test the actual level used)
				if w.Header().Get("Content-Encoding") != "gzip" {
					t.Errorf("Expected compression to work with level %d", tc.level)
				}
			})
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
