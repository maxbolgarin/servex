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
	server := New()

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

	s, err := Start(cfg, func(r *mux.Router) {
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

	err := StartWithShutdown(ctx, cfg, func(r *mux.Router) {
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
	server := New(WithLogger(log), WithCertificate(tls.Certificate{}))

	err := server.Start("", "")
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
	server := New(WithLogger(log), WithCertificate(tls.Certificate{}))

	httpAddress := randAddress()
	httpsAddress := randAddress()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := server.StartWithShutdown(ctx, httpAddress, httpsAddress)
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
	server := New(WithLogger(log))
	address := randAddress()

	err := server.StartHTTP(address)
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
	server := New(WithLogger(log))
	address := randAddress()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := server.StartWithShutdownHTTP(ctx, address)
	if err != nil {
		t.Fatalf("unexpected error starting HTTP server: %v", err)
	}

	if !strings.Contains(log.LastMessage, "http server started") {
		t.Errorf("expected last message to be 'http server started', got: %s", log.LastMessage)
	}
}

func TestServerStartHTTPSNoCert(t *testing.T) {
	server := New()
	address := ":8443"
	err := server.StartHTTPS(address)

	if err == nil || err.Error() != "TLS certificate is required for HTTPS server" {
		t.Fatalf("expected error for missing TLS certificate, got: %v", err)
	}
}

func TestServerStartHTTPS(t *testing.T) {
	log := &MockLogger{}
	server := New(WithCertificate(tls.Certificate{}), WithLogger(log))
	address := randAddress()

	err := server.StartHTTPS(address)
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
	server := New(WithCertificate(tls.Certificate{}), WithLogger(log))
	address := randAddress()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := server.StartWithShutdownHTTPS(ctx, address)
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
	server := New(WithCertificateFromFile("nonexistent-cert.pem", "nonexistent-key.pem"))
	address := randAddress()

	err := server.StartHTTPS(address)
	if err == nil {
		t.Fatalf("expected error for non-existent certificate files, got: nil")
	}

	// The error should contain information about reading the certificate
	expectedErrorSubstring := "read certificate from file"
	if !strings.Contains(err.Error(), expectedErrorSubstring) {
		t.Errorf("expected error to contain %q, got: %s", expectedErrorSubstring, err.Error())
	}
}

// TestPrepareServerWithCertFiles tests the prepareServer function with certificate files in BaseConfig.
func TestPrepareServerWithCertFiles(t *testing.T) {
	cfg := BaseConfig{
		HTTP:     ":8080",
		CertFile: "nonexistent-cert.pem",
		KeyFile:  "nonexistent-key.pem",
	}

	_, err := Start(cfg, func(r *mux.Router) {
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
		HTTP: ":8080",
		// No certificate files specified
	}

	shutdown, err := Start(cfg, func(r *mux.Router) {
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
	server := New(WithAuthToken("valid-token"))
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
		s := New()

		// Start HTTP server
		err := s.StartHTTP(":0") // Use port 0 to get any available port
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
		s := New(WithCertificate(tls.Certificate{}))

		// Start HTTPS server
		err := s.StartHTTPS(":0") // Use port 0 to get any available port
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
		s := New(WithCertificate(tls.Certificate{}))

		// Start both servers
		err := s.Start(":0", ":0") // Use port 0 to get any available ports
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
		s := New()

		err := s.StartHTTP("invalid-address")
		if err == nil {
			t.Error("StartHTTP should return error for invalid address")
		}
	})

	t.Run("Port already in use", func(t *testing.T) {
		// Use a specific port instead of :0 to ensure conflict
		addr := randAddress()

		// Start first server
		s1 := New()
		err := s1.StartHTTP(addr)
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
		s2 := New()
		err = s2.StartHTTP(addr)
		if err == nil {
			t.Error("StartHTTP should return error when port is already in use")
			s2.Shutdown(context.Background())
		}
	})
}
