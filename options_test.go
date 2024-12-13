package servex_test

import (
	"crypto/tls"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/maxbolgarin/servex"
)

// TestWithCertificate tests whether the WithCertificate option sets the TLS certificate correctly.
func TestWithCertificate(t *testing.T) {
	cert := tls.Certificate{}
	option := servex.WithCertificate(cert)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Certificate, &cert) {
		t.Errorf("expected certificate to be %v, got %v", cert, options.Certificate)
	}
}

// TestWithReadTimeout verifies the WithReadTimeout sets the ReadTimeout properly.
func TestWithReadTimeout(t *testing.T) {
	timeout := 30 * time.Second
	option := servex.WithReadTimeout(timeout)
	options := servex.Options{}
	option(&options)

	// It should set to the provided timeout or default if timeout <= 0
	if options.ReadTimeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, options.ReadTimeout)
	}
}

// TestWithReadHeaderTimeout verifies the WithReadHeaderTimeout sets the ReadHeaderTimeout.
func TestWithReadHeaderTimeout(t *testing.T) {
	timeout := 15 * time.Second
	option := servex.WithReadHeaderTimeout(timeout)
	options := servex.Options{}
	option(&options)

	// It should set to the provided timeout
	if options.ReadHeaderTimeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, options.ReadHeaderTimeout)
	}
}

// TestWithIdleTimeout verifies the WithIdleTimeout sets the IdleTimeout properly.
func TestWithIdleTimeout(t *testing.T) {
	timeout := 90 * time.Second
	option := servex.WithIdleTimeout(timeout)
	options := servex.Options{}
	option(&options)

	if options.IdleTimeout != timeout {
		t.Errorf("expected idle timeout %v, got %v", timeout, options.IdleTimeout)
	}
}

// TestWithAuthToken verifies the WithAuthToken sets the token correctly.
func TestWithAuthToken(t *testing.T) {
	token := "securetoken"
	option := servex.WithAuthToken(token)
	options := servex.Options{}
	option(&options)

	if options.AuthToken != token {
		t.Errorf("expected token %q, got %q", token, options.AuthToken)
	}
}

// TestWithMetrics verifies that the WithMetrics option sets the Metrics interface.
func TestWithMetrics(t *testing.T) {
	metrics := &mockMetrics{}
	option := servex.WithMetrics(metrics)
	options := servex.Options{}
	option(&options)

	if options.Metrics != metrics {
		t.Errorf("expected metrics %v, got %v", metrics, options.Metrics)
	}
}

// TestWithLogger verifies that the WithLogger option sets the Logger.
func TestWithLogger(t *testing.T) {
	logger := &mockLogger{}
	option := servex.WithLogger(logger)
	options := servex.Options{}
	option(&options)

	if options.Logger != logger {
		t.Errorf("expected logger %v, got %v", logger, options.Logger)
	}
}

// TestWithRequestLogger verifies that the WithRequestLogger option sets the RequestLogger.
func TestWithRequestLogger(t *testing.T) {
	reqLogger := &mockRequestLogger{}
	option := servex.WithRequestLogger(reqLogger)
	options := servex.Options{}
	option(&options)

	if options.RequestLogger != reqLogger {
		t.Errorf("expected request logger %v, got %v", reqLogger, options.RequestLogger)
	}
}

func TestBaseConfigValidate(t *testing.T) {
	tests := []struct {
		config   servex.BaseConfig
		hasError bool
	}{
		{servex.BaseConfig{HTTP: "", HTTPS: ""}, true},
		{servex.BaseConfig{HTTP: ":8080", HTTPS: ""}, false},
		{servex.BaseConfig{HTTP: "", HTTPS: ":8443", CertFile: "cert.pem", KeyFile: "key.pem"}, false},
		{servex.BaseConfig{HTTP: "invalid", HTTPS: ""}, true},
		{servex.BaseConfig{HTTP: "", HTTPS: "invalid"}, true},
		{servex.BaseConfig{HTTP: "", HTTPS: ":8443"}, false},
	}

	for _, tt := range tests {
		err := tt.config.Validate()
		if (err != nil) != tt.hasError {
			t.Errorf("Validate() with config %v expected error: %v, got: %v", tt.config, tt.hasError, err)
		}
	}
}

type mockMetrics struct{}

func (m *mockMetrics) HandleRequest(r *http.Request) {}

type mockLogger struct{}

func (m *mockLogger) Error(msg string, args ...interface{}) {}

func (m *mockLogger) Info(msg string, args ...interface{}) {}

func (m *mockLogger) Debug(msg string, args ...interface{}) {}

type mockRequestLogger struct{}

func (m *mockRequestLogger) Log(servex.RequestLogBundle) {}
