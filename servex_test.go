package servex_test

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
	"github.com/maxbolgarin/servex"
)

func randAddress() string {
	return fmt.Sprintf(":%d", 10000+int(math.Floor(10000*mr.New(mr.NewSource(time.Now().UnixNano())).Float64())))
}

func TestNewServer(t *testing.T) {
	// Basic test for server initialization with default options
	server := servex.New()

	if server.Router() == nil {
		t.Fatal("Server router should not be nil")
	}
}

func TestStart(t *testing.T) {
	log := &MockLogger{}
	cfg := servex.BaseConfig{
		HTTP:  randAddress(),
		HTTPS: randAddress(),
	}

	s, err := servex.Start(cfg, func(r *mux.Router) {
		r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, world!"))
		})
	}, servex.WithLogger(log), servex.WithCertificate(tls.Certificate{}))
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
	cfg := servex.BaseConfig{
		HTTP:  randAddress(),
		HTTPS: randAddress(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := servex.StartWithShutdown(ctx, cfg, func(r *mux.Router) {
		r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, world!"))
		})
	}, servex.WithLogger(log), servex.WithCertificate(tls.Certificate{}))
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
	server := servex.New(servex.WithLogger(log), servex.WithCertificate(tls.Certificate{}))

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
	server := servex.New(servex.WithLogger(log), servex.WithCertificate(tls.Certificate{}))

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
	server := servex.New(servex.WithLogger(log))
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
	server := servex.New(servex.WithLogger(log))
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
	server := servex.New()
	address := ":8443"
	err := server.StartHTTPS(address)

	if err == nil || err.Error() != "TLS certificate is required for HTTPS server" {
		t.Fatalf("expected error for missing TLS certificate, got: %v", err)
	}
}

func TestServerStartHTTPS(t *testing.T) {
	log := &MockLogger{}
	server := servex.New(servex.WithCertificate(tls.Certificate{}), servex.WithLogger(log))
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
	server := servex.New(servex.WithCertificate(tls.Certificate{}), servex.WithLogger(log))
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
	server := servex.New(servex.WithCertificateFromFile("nonexistent-cert.pem", "nonexistent-key.pem"))
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
	cfg := servex.BaseConfig{
		HTTP:     ":8080",
		CertFile: "nonexistent-cert.pem",
		KeyFile:  "nonexistent-key.pem",
	}

	_, err := servex.Start(cfg, func(r *mux.Router) {
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
	cfg := servex.BaseConfig{
		HTTP: ":8080",
		// No certificate files specified
	}

	shutdown, err := servex.Start(cfg, func(r *mux.Router) {
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
	server := servex.New(servex.WithAuthToken("valid-token"))
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
