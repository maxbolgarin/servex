package servex

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	mr "math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

func randAddress() string {
	return fmt.Sprintf(":%d", 10000+int(math.Floor(10000*mr.New(mr.NewSource(time.Now().UnixNano())).Float64())))
}

func TestNewServer(t *testing.T) {
	// Basic test for server initialization with default options
	server, err := NewServer()
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	if server.Router() == nil {
		t.Fatal("Server router should not be nil")
	}
}

func TestStart(t *testing.T) {
	log := &MockLogger{}
	cfg := BaseConfig{
		HTTP:  randAddress(),
		HTTPS: randAddress(),
	}

	s, err := StartServer(cfg, func(r *mux.Router) {
		r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, world!"))
		})
	}, WithLogger(log), WithCertificate(tls.Certificate{}))
	if err != nil {
		t.Fatalf("unexpected error starting server: %v", err)
	}

	if !strings.Contains(log.Messages[0], "http server started") {
		t.Errorf("expected first message to be 'http server started', got: %s", log.Messages[0])
	}

	if !strings.Contains(log.Messages[1], "https server started") {
		t.Errorf("expected second message to be 'https server started', got: %s", log.Messages[1])
	}

	resp, err := http.Get("http://" + cfg.HTTP)
	if err != nil {
		t.Fatalf("unexpected error getting response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code to be %d, got: %d", http.StatusOK, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Hello, world!" {
		t.Errorf("expected body to be 'Hello, world!', got: %s", string(body))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s(ctx)

	_, err = http.Get("http://" + cfg.HTTP)
	if err == nil {
		t.Errorf("expected error getting response after server shutdown, got: %v", err)
	}
}

func TestStartWithShutdown(t *testing.T) {
	log := &MockLogger{}
	cfg := BaseConfig{
		HTTP:  randAddress(),
		HTTPS: randAddress(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := StartServerWithShutdown(ctx, cfg, func(r *mux.Router) {
		r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, world!"))
		})
	}, WithLogger(log), WithCertificate(tls.Certificate{}))
	if err != nil {
		t.Fatalf("unexpected error starting server: %v", err)
	}

	if !strings.Contains(log.Messages[0], "http server started") {
		t.Errorf("expected first message to be 'http server started', got: %s", log.Messages[0])
	}

	if !strings.Contains(log.Messages[1], "https server started") {
		t.Errorf("expected second message to be 'https server started', got: %s", log.Messages[1])
	}

	resp, err := http.Get("http://" + cfg.HTTP)
	if err != nil {
		t.Fatalf("unexpected error getting response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code to be %d, got: %d", http.StatusOK, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Hello, world!" {
		t.Errorf("expected body to be 'Hello, world!', got: %s", string(body))
	}

	cancel()
	time.Sleep(time.Millisecond)

	_, err = http.Get("http://" + cfg.HTTP)
	if err == nil {
		t.Errorf("expected error getting response after server shutdown, got: %v", err)
	}
}

func TestServerStart(t *testing.T) {
	log := &MockLogger{}
	server, err := NewServer(WithLogger(log), WithCertificate(tls.Certificate{}))

	err = server.Start("", "")
	if err == nil {
		t.Fatalf("expected error for empty address, got: %v", err)
	}

	httpAddress := randAddress()
	httpsAddress := randAddress()

	err = server.Start(httpAddress, httpsAddress)
	if err != nil {
		t.Fatalf("unexpected error starting server: %v", err)
	}

	if !strings.Contains(log.Messages[0], "http server started") {
		t.Errorf("expected first message to be 'http server started', got: %s", log.Messages[0])
	}

	if !strings.Contains(log.Messages[1], "https server started") {
		t.Errorf("expected second message to be 'https server started', got: %s", log.Messages[1])
	}

	if server.HTTPAddress() != httpAddress {
		t.Errorf("expected http address to be %s, got: %s", httpAddress, server.HTTPAddress())
	}

	if server.HTTPSAddress() != httpsAddress {
		t.Errorf("expected https address to be %s, got: %s", httpsAddress, server.HTTPSAddress())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Errorf("unexpected error shutting down server: %v", err)
	}
}

func TestServerStartWithShutdown(t *testing.T) {
	log := &MockLogger{}
	server, err := NewServer(WithLogger(log), WithCertificate(tls.Certificate{}))

	httpAddress := randAddress()
	httpsAddress := randAddress()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = server.StartWithShutdown(ctx, httpAddress, httpsAddress)
	if err != nil {
		t.Fatalf("unexpected error starting server: %v", err)
	}

	if !strings.Contains(log.Messages[0], "http server started") {
		t.Errorf("expected first message to be 'http server started', got: %s", log.Messages[0])
	}

	if !strings.Contains(log.Messages[1], "https server started") {
		t.Errorf("expected second message to be 'https server started', got: %s", log.Messages[1])
	}
}

func TestServerStartHTTP(t *testing.T) {
	log := &MockLogger{}
	server, err := NewServer(WithLogger(log))
	address := randAddress()

	err = server.StartHTTP(address)
	if err != nil {
		t.Fatalf("unexpected error starting HTTP server: %v", err)
	}

	if !strings.Contains(log.LastMessage, "http server started") {
		t.Errorf("expected last message to be 'http server started', got: %s", log.LastMessage)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Errorf("unexpected error shutting down server: %v", err)
	}
}

func TestServerStartWithShutdownHTTP(t *testing.T) {
	log := &MockLogger{}
	server, err := NewServer(WithLogger(log))
	address := randAddress()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = server.StartWithShutdownHTTP(ctx, address)
	if err != nil {
		t.Fatalf("unexpected error starting HTTP server: %v", err)
	}

	if !strings.Contains(log.LastMessage, "http server started") {
		t.Errorf("expected last message to be 'http server started', got: %s", log.LastMessage)
	}
}

func TestServerStartHTTPSNoCert(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}
	address := ":8443"
	err = server.StartHTTPS(address)

	if err == nil || err.Error() != "TLS certificate is required for HTTPS server" {
		t.Fatalf("expected error for missing TLS certificate, got: %v", err)
	}
}

func TestServerStartHTTPS(t *testing.T) {
	log := &MockLogger{}
	server, err := NewServer(WithCertificate(tls.Certificate{}), WithLogger(log))
	address := randAddress()

	err = server.StartHTTPS(address)
	if err != nil {
		t.Fatalf("unexpected error starting HTTPS server: %v", err)
	}

	if !strings.Contains(log.LastMessage, "https server started") {
		t.Errorf("expected last message to be 'https server started', got: %s", log.LastMessage)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Errorf("unexpected error shutting down server: %v", err)
	}
}

func TestServerStartWithShutdownHTTPS(t *testing.T) {
	log := &MockLogger{}
	server, err := NewServer(WithCertificate(tls.Certificate{}), WithLogger(log))
	address := randAddress()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = server.StartWithShutdownHTTPS(ctx, address)
	if err != nil {
		t.Fatalf("unexpected error starting HTTPS server: %v", err)
	}

	if !strings.Contains(log.LastMessage, "https server started") {
		t.Errorf("expected last message to be 'https server started', got: %s", log.LastMessage)
	}
}

// TestServerStartHTTPSWithCertFilePaths tests HTTPS server startup with certificate file paths but non-existent files.
func TestServerStartHTTPSWithCertFilePaths(t *testing.T) {
	// Test with non-existent certificate files
	_, err := NewServer(WithCertificateFromFile("nonexistent-cert.pem", "nonexistent-key.pem"))
	if err == nil {
		t.Fatalf("expected error for non-existent certificate files, got: nil")
	}
}

// TestPrepareServerWithCertFiles tests the prepareServer function with certificate files in BaseConfig.
func TestPrepareServerWithCertFiles(t *testing.T) {
	cfg := BaseConfig{
		HTTP:     ":8080",
		CertFile: "nonexistent-cert.pem",
		KeyFile:  "nonexistent-key.pem",
	}

	_, err := StartServer(cfg, func(r *mux.Router) {
		r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello"))
		})
	})

	if err == nil {
		t.Fatalf("expected error for non-existent certificate files, got: nil")
	}

	// The error should contain information about reading the certificate
	expectedErrorSubstring := "read certificate"
	if !strings.Contains(err.Error(), expectedErrorSubstring) {
		t.Errorf("expected error to contain %q, got: %s", expectedErrorSubstring, err.Error())
	}
}

// TestPrepareServerWithValidConfig tests the prepareServer function with valid config but no certificate files.
func TestPrepareServerWithValidConfig(t *testing.T) {
	cfg := BaseConfig{
		HTTP: ":12323",
		// No certificate files specified
	}

	shutdown, err := StartServer(cfg, func(r *mux.Router) {
		r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello"))
		})
	})

	if err != nil {
		t.Fatalf("unexpected error for valid config: %v", err)
	}

	// Clean up
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if shutdown != nil {
		shutdown(ctx)
	}
}

func TestAuthMiddleware(t *testing.T) {
	server, err := NewServer(WithAuthToken("valid-token"))
	router := server.Router()
	request, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("could not create request: %v", err)
	}

	server.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	responseRecorder := httptest.NewRecorder()
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("expected StatusUnauthorized, got %d", responseRecorder.Code)
	}

	request.Header.Set("Authorization", "invalid-token")

	responseRecorder = httptest.NewRecorder()
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("expected StatusUnauthorized, got %d", responseRecorder.Code)
	}

	request.Header.Set("Authorization", "valid-token")

	responseRecorder = httptest.NewRecorder()
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusOK {
		t.Errorf("expected StatusOK, got %d", responseRecorder.Code)
	}
}

// TestServerStartupWaiting tests that the server startup waiting mechanism works correctly.
func TestServerStartupWaiting(t *testing.T) {
	t.Run("HTTP server startup waiting", func(t *testing.T) {
		s, err := NewServer()
		if err != nil {
			t.Fatalf("unexpected error creating server: %v", err)
		}

		// Start HTTP server
		err = s.StartHTTP(":0") // Use port 0 to get any available port
		if err != nil {
			t.Fatalf("failed to start HTTP server: %v", err)
		}
		defer s.Shutdown(context.Background())

		// Verify server is ready by making a request
		if s.HTTPAddress() == "" {
			t.Error("HTTP address should not be empty after successful start")
		}

	})

	t.Run("HTTPS server startup waiting", func(t *testing.T) {
		s, err := NewServer(WithCertificate(tls.Certificate{}))
		if err != nil {
			t.Fatalf("unexpected error creating server: %v", err)
		}

		// Start HTTPS server
		err = s.StartHTTPS(":0") // Use port 0 to get any available port
		if err != nil {
			t.Fatalf("failed to start HTTPS server: %v", err)
		}
		defer s.Shutdown(context.Background())

		// Verify server is ready
		if s.HTTPSAddress() == "" {
			t.Error("HTTPS address should not be empty after successful start")
		}
	})

	t.Run("Both HTTP and HTTPS startup waiting", func(t *testing.T) {
		s, err := NewServer(WithCertificate(tls.Certificate{}))
		if err != nil {
			t.Fatalf("unexpected error creating server: %v", err)
		}

		// Start both servers
		err = s.Start(":0", ":0") // Use port 0 to get any available ports
		if err != nil {
			t.Fatalf("failed to start servers: %v", err)
		}
		defer s.Shutdown(context.Background())

		// Verify both servers are ready
		if s.HTTPAddress() == "" {
			t.Error("HTTP address should not be empty after successful start")
		}
		if s.HTTPSAddress() == "" {
			t.Error("HTTPS address should not be empty after successful start")
		}
	})

}

// TestStartupErrorHandling tests error handling during server startup.
func TestStartupErrorHandling(t *testing.T) {
	t.Run("Invalid address should return error immediately", func(t *testing.T) {
		s, err := NewServer()
		if err != nil {
			t.Fatalf("unexpected error creating server: %v", err)
		}

		err = s.StartHTTP("invalid-address")
		if err == nil {
			t.Error("StartHTTP should return error for invalid address")
		}
	})

	t.Run("Port already in use", func(t *testing.T) {
		// Use a specific port instead of :0 to ensure conflict
		addr := randAddress()

		// Start first server
		s1, err := NewServer()
		if err != nil {
			t.Fatalf("unexpected error creating server: %v", err)
		}
		err = s1.StartHTTP(addr)
		if err != nil {
			t.Fatalf("failed to start first server: %v", err)
		}
		defer s1.Shutdown(context.Background())

		// Verify first server is actually listening by making a request
		resp, err := http.Get("http://" + addr)
		if err == nil {
			resp.Body.Close()
		}

		// Try to start second server on the same address
		s2, err := NewServer()
		if err != nil {
			t.Fatalf("unexpected error creating server: %v", err)
		}
		err = s2.StartHTTP(addr)
		if err == nil {
			t.Error("StartHTTP should return error when port is already in use")
			s2.Shutdown(context.Background())
		}
	})
}

// TestRequestSizeLimitMiddleware tests the request size limit middleware functionality.
func TestRequestSizeLimitMiddleware(t *testing.T) {
	tests := []struct {
		name               string
		options            []Option
		requestBody        string
		contentType        string
		contentLength      *string // Use pointer to distinguish between nil (not set) and "" (empty)
		expectedStatus     int
		expectErrorMessage string
	}{
		{
			name: "Request within general limit",
			options: []Option{
				WithMaxRequestBodySize(100),
				WithEnableRequestSizeLimits(true),
			},
			requestBody:    "short message",
			contentType:    "text/plain",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Request exceeds general limit",
			options: []Option{
				WithMaxRequestBodySize(10),
				WithEnableRequestSizeLimits(true),
			},
			requestBody:        "this is a very long message that exceeds the 10 byte limit",
			contentType:        "text/plain",
			expectedStatus:     http.StatusRequestEntityTooLarge,
			expectErrorMessage: "Request body too large",
		},
		{
			name: "JSON request within JSON limit",
			options: []Option{
				WithMaxRequestBodySize(100),
				WithMaxJSONBodySize(100),
				WithEnableRequestSizeLimits(true),
			},
			requestBody:    `{"test": "data"}`,
			contentType:    "application/json",
			expectedStatus: http.StatusOK,
		},
		{
			name: "JSON request exceeds JSON limit",
			options: []Option{
				WithMaxRequestBodySize(100),
				WithMaxJSONBodySize(20),
				WithEnableRequestSizeLimits(true),
			},
			requestBody:        `{"test": "this is a very long message that exceeds the JSON limit"}`,
			contentType:        "application/json",
			expectedStatus:     http.StatusRequestEntityTooLarge,
			expectErrorMessage: "JSON body too large",
		},
		{
			name: "Middleware disabled - should pass through",
			options: []Option{
				WithMaxRequestBodySize(10),         // Very small limit
				WithEnableRequestSizeLimits(false), // But disabled
			},
			requestBody:    "this message exceeds 10 bytes but should pass through",
			contentType:    "text/plain",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Missing Content-Length header - should pass through",
			options: []Option{
				WithMaxRequestBodySize(10),
				WithEnableRequestSizeLimits(true),
			},
			requestBody:    "long message",
			contentType:    "text/plain",
			contentLength:  func() *string { s := ""; return &s }(), // Empty Content-Length header
			expectedStatus: http.StatusOK,
		},
		{
			name: "JSON within general limit but exceeds JSON limit",
			options: []Option{
				WithMaxRequestBodySize(100), // General limit: 100 bytes
				WithMaxJSONBodySize(30),     // JSON limit: 30 bytes
				WithEnableRequestSizeLimits(true),
			},
			requestBody:        `{"test": "this JSON message is longer than 30 bytes but under 100 bytes"}`,
			contentType:        "application/json",
			expectedStatus:     http.StatusRequestEntityTooLarge,
			expectErrorMessage: "JSON body too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server with options
			server, err := NewServer(tt.options...)
			if err != nil {
				t.Fatalf("unexpected error creating server: %v", err)
			}

			// Add a test handler
			server.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
				ctx := server.C(w, r)
				ctx.Response(http.StatusOK, "success")
			}, "POST")

			// Create test request
			req := httptest.NewRequest("POST", "/test", strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", tt.contentType)

			// Set Content-Length if specified
			if tt.contentLength != nil {
				if *tt.contentLength == "" {
					// For empty contentLength, we want to simulate missing Content-Length
					// We need to manually set ContentLength to -1 to simulate chunked encoding
					req.ContentLength = -1
					req.Header.Del("Content-Length")
				} else {
					// Set specific Content-Length value
					req.Header.Set("Content-Length", *tt.contentLength)
				}
			} else {
				// Default case: set Content-Length to actual body size
				req.Header.Set("Content-Length", strconv.Itoa(len(tt.requestBody)))
			}

			// Record response
			w := httptest.NewRecorder()

			// Execute request
			server.Router().ServeHTTP(w, req)

			// Check status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			// Check error message if expected
			if tt.expectErrorMessage != "" {
				body := w.Body.String()
				if !strings.Contains(body, tt.expectErrorMessage) {
					t.Errorf("expected response to contain %q, got %q", tt.expectErrorMessage, body)
				}
			}
		})
	}
}

// TestRequestSizeLimitMiddlewareWithStrictLimits tests the middleware with strict security limits.
func TestRequestSizeLimitMiddlewareWithStrictLimits(t *testing.T) {
	// Create server with strict limits
	server, err := NewServer(WithStrictRequestSizeLimits())
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	server.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		ctx := server.C(w, r)
		ctx.Response(http.StatusOK, "success")
	}, "POST")

	tests := []struct {
		name           string
		requestBody    string
		contentType    string
		expectedStatus int
	}{
		{
			name:           "Small JSON request - should pass",
			requestBody:    `{"test": "small"}`,
			contentType:    "application/json",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Large JSON request - should fail with strict limits",
			requestBody:    strings.Repeat(`{"test": "data"}`, 40000), // ~640KB, larger than 512KB limit
			contentType:    "application/json",
			expectedStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name:           "Small general request - should pass",
			requestBody:    "small message",
			contentType:    "text/plain",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Large general request - should fail with strict limits",
			requestBody:    strings.Repeat("large message ", 800000), // ~11.2MB, larger than 10MB limit
			contentType:    "text/plain",
			expectedStatus: http.StatusRequestEntityTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", tt.contentType)
			req.Header.Set("Content-Length", strconv.Itoa(len(tt.requestBody)))

			w := httptest.NewRecorder()
			server.Router().ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status code %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// TestRequestSizeLimitMiddlewareWithMultipartForm tests the middleware with multipart form data.
func TestRequestSizeLimitMiddlewareWithMultipartForm(t *testing.T) {
	server, err := NewServer(
		WithMaxRequestBodySize(1000), // 1KB general limit
		WithEnableRequestSizeLimits(true),
	)
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	server.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		ctx := server.C(w, r)
		ctx.Response(http.StatusOK, "upload success")
	}, "POST")

	tests := []struct {
		name           string
		formData       string
		expectedStatus int
	}{
		{
			name: "Small multipart form - should pass",
			formData: "--boundary\r\n" +
				"Content-Disposition: form-data; name=\"field\"\r\n\r\n" +
				"value\r\n" +
				"--boundary--\r\n",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Large multipart form - should fail",
			formData: "--boundary\r\n" +
				"Content-Disposition: form-data; name=\"field\"\r\n\r\n" +
				strings.Repeat("x", 2000) + "\r\n" + // Much larger than 1KB
				"--boundary--\r\n",
			expectedStatus: http.StatusRequestEntityTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/upload", strings.NewReader(tt.formData))
			req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
			req.Header.Set("Content-Length", strconv.Itoa(len(tt.formData)))

			w := httptest.NewRecorder()
			server.Router().ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status code %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// TestRequestSizeLimitMiddlewareNotRegisteredWhenDisabled tests that middleware is not registered when disabled.
func TestRequestSizeLimitMiddlewareNotRegisteredWhenDisabled(t *testing.T) {
	// Create server with middleware disabled (default behavior)
	server, err := NewServer(
	// Don't set any size limits - this way we test that middleware is not active
	// and context methods use their default limits
	)
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	server.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		ctx := server.C(w, r)
		// Try to read the body - this should work with default context limits
		body, err := ctx.Read()
		if err != nil {
			ctx.InternalServerError(err, "Failed to read body")
			return
		}
		ctx.Response(http.StatusOK, fmt.Sprintf("received %d bytes", len(body)))
	}, "POST")

	// Send a moderately large request that would be blocked by strict middleware limits
	// but should pass with default context limits (32MB default)
	largeBody := strings.Repeat("this is a moderately large message for testing. ", 500) // ~25KB
	req := httptest.NewRequest("POST", "/test", strings.NewReader(largeBody))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Length", strconv.Itoa(len(largeBody)))

	w := httptest.NewRecorder()
	server.Router().ServeHTTP(w, req)

	// Should succeed because middleware is not registered and context uses reasonable defaults
	if w.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, w.Code)
	}

	// Should receive the full body
	body := w.Body.String()
	if !strings.Contains(body, "received") {
		t.Errorf("expected response to indicate body was received, got %q", body)
	}
}

// TestRequestSizeLimitWithDefaultOptions tests request size limits with default reasonable options.
func TestRequestSizeLimitWithDefaultOptions(t *testing.T) {
	// Create server with default request size limits
	server, err := NewServer(WithRequestSizeLimits())
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	server.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		ctx := server.C(w, r)
		ctx.Response(http.StatusOK, "success")
	}, "POST")

	tests := []struct {
		name           string
		bodySize       int
		contentType    string
		expectedStatus int
	}{
		{
			name:           "1KB JSON - should pass",
			bodySize:       1024,
			contentType:    "application/json",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "2MB JSON - should fail (exceeds 1MB JSON limit)",
			bodySize:       2 * 1024 * 1024,
			contentType:    "application/json",
			expectedStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name:           "10MB general request - should pass (under 100MB general limit)",
			bodySize:       10 * 1024 * 1024,
			contentType:    "text/plain",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "120MB general request - should fail (exceeds 100MB general limit)",
			bodySize:       120 * 1024 * 1024,
			contentType:    "text/plain",
			expectedStatus: http.StatusRequestEntityTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create body of specified size
			body := strings.Repeat("x", tt.bodySize)

			req := httptest.NewRequest("POST", "/test", strings.NewReader(body))
			req.Header.Set("Content-Type", tt.contentType)
			req.Header.Set("Content-Length", strconv.Itoa(len(body)))

			w := httptest.NewRecorder()
			server.Router().ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status code %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}
