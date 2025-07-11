package servex_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/maxbolgarin/servex/v2"
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

// TestWithCertificatePtr tests whether the WithCertificatePtr option sets the TLS certificate pointer correctly.
func TestWithCertificatePtr(t *testing.T) {
	cert := &tls.Certificate{}
	option := servex.WithCertificatePtr(cert)
	options := servex.Options{}
	option(&options)

	if options.Certificate != cert {
		t.Errorf("expected certificate pointer to be %p, got %p", cert, options.Certificate)
	}
}

// TestWithCertificateFromFile tests whether the WithCertificateFromFile option sets the certificate file paths correctly.
func TestWithCertificateFromFile(t *testing.T) {
	certFilePath := "cert.pem"
	keyFilePath := "key.pem"
	option := servex.WithCertificateFromFile(certFilePath, keyFilePath)
	options := servex.Options{}
	option(&options)

	if options.CertFilePath != certFilePath {
		t.Errorf("expected cert file path to be %q, got %q", certFilePath, options.CertFilePath)
	}
	if options.KeyFilePath != keyFilePath {
		t.Errorf("expected key file path to be %q, got %q", keyFilePath, options.KeyFilePath)
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

// TestWithNoRequestLog verifies that WithNoRequestLog disables request logging.
func TestWithNoRequestLog(t *testing.T) {
	option := servex.WithNoRequestLog()
	options := servex.Options{}
	option(&options)

	if !options.DisableRequestLogging {
		t.Errorf("expected DisableRequestLogging to be true, got false")
	}

	// Verify that RequestLogger is set to noopRequestLogger by checking its behavior
	if options.RequestLogger == nil {
		t.Errorf("expected RequestLogger to be set to noopRequestLogger, got nil")
	}

	// Test that the logger doesn't actually log anything (noop behavior)
	bundle := servex.RequestLogBundle{}
	options.RequestLogger.Log(bundle) // Should do nothing
}

// TestWithDisableRequestLogging verifies that WithDisableRequestLogging disables request logging.
func TestWithDisableRequestLogging(t *testing.T) {
	option := servex.WithDisableRequestLogging()
	options := servex.Options{}
	option(&options)

	if !options.DisableRequestLogging {
		t.Errorf("expected DisableRequestLogging to be true, got false")
	}

	// Verify that RequestLogger is set to noopRequestLogger by checking its behavior
	if options.RequestLogger == nil {
		t.Errorf("expected RequestLogger to be set to noopRequestLogger, got nil")
	}

	// Test that the logger doesn't actually log anything (noop behavior)
	bundle := servex.RequestLogBundle{}
	options.RequestLogger.Log(bundle) // Should do nothing
}

// TestWithLogFields verifies that WithLogFields sets the LogFields correctly.
func TestWithLogFields(t *testing.T) {
	fields := []string{servex.MethodLogField, servex.StatusLogField, servex.DurationLogField}
	option := servex.WithLogFields(fields...)
	options := servex.Options{}
	option(&options)

	if len(options.LogFields) != len(fields) {
		t.Errorf("expected %d log fields, got %d", len(fields), len(options.LogFields))
	}

	for i, expectedField := range fields {
		if i >= len(options.LogFields) || options.LogFields[i] != expectedField {
			t.Errorf("expected log field %q at index %d, got %q", expectedField, i, options.LogFields[i])
		}
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

func (m *mockMetrics) HandleResponse(r *http.Request, w http.ResponseWriter, statusCode int, duration time.Duration) {
}

type mockLogger struct{}

func (m *mockLogger) Error(msg string, args ...any) {}

func (m *mockLogger) Info(msg string, args ...any) {}

func (m *mockLogger) Debug(msg string, args ...any) {}

type mockRequestLogger struct{}

func (m *mockRequestLogger) Log(servex.RequestLogBundle) {}

// TestWithAuth verifies that WithAuth sets the database and enables auth.
func TestWithAuth(t *testing.T) {
	db := &mockAuthDatabase{}
	option := servex.WithAuth(db)
	options := servex.Options{}
	option(&options)

	// Check if the database is set correctly
	if !reflect.DeepEqual(options.Auth.Database, db) {
		t.Errorf("expected auth database %v, got %v", db, options.Auth.Database)
	}
	// Note: We don't directly test the internal 'enabled' flag.
	// Setting the database implies auth is enabled via WithAuth.
}

// TestWithAuthMemoryDatabase verifies that WithAuthMemoryDatabase sets an in-memory database and enables auth.
func TestWithAuthMemoryDatabase(t *testing.T) {
	option := servex.WithAuthMemoryDatabase()
	options := servex.Options{}
	option(&options)

	if options.Auth.Database == nil {
		t.Error("expected auth database to be set, got nil")
	}
	// Note: We don't directly test the internal 'enabled' flag.
	// Setting the memory database implies auth is enabled via WithAuthMemoryDatabase.
	// Also, we don't check the specific type, just that it's not nil.
}

// TestWithAuthConfig verifies that WithAuthConfig sets the entire AuthConfig and enables auth.
func TestWithAuthConfig(t *testing.T) {
	db := &mockAuthDatabase{}
	authCfg := servex.AuthConfig{
		Database:               db,
		JWTAccessSecret:        "access",
		JWTRefreshSecret:       "refresh",
		AccessTokenDuration:    10 * time.Minute,
		RefreshTokenDuration:   10 * 24 * time.Hour,
		IssuerNameInJWT:        "myissuer",
		RefreshTokenCookieName: "_myrt",
		AuthBasePath:           "/auth/v2",
		RolesOnRegister:        []servex.UserRole{"user"},
		NotRegisterRoutes:      true,
	}

	option := servex.WithAuthConfig(authCfg)
	options := servex.Options{}
	option(&options)

	// Compare relevant fields, database compared via reflect.DeepEqual
	if !reflect.DeepEqual(options.Auth.Database, db) {
		t.Errorf("auth config mismatch: database expected %v, got %v", db, options.Auth.Database)
	}
	if options.Auth.JWTAccessSecret != authCfg.JWTAccessSecret {
		t.Errorf("auth config mismatch: JWTAccessSecret expected %q, got %q", authCfg.JWTAccessSecret, options.Auth.JWTAccessSecret)
	}
	if options.Auth.JWTRefreshSecret != authCfg.JWTRefreshSecret {
		t.Errorf("auth config mismatch: JWTRefreshSecret expected %q, got %q", authCfg.JWTRefreshSecret, options.Auth.JWTRefreshSecret)
	}
	if options.Auth.AccessTokenDuration != authCfg.AccessTokenDuration {
		t.Errorf("auth config mismatch: AccessTokenDuration expected %v, got %v", authCfg.AccessTokenDuration, options.Auth.AccessTokenDuration)
	}
	if options.Auth.RefreshTokenDuration != authCfg.RefreshTokenDuration {
		t.Errorf("auth config mismatch: RefreshTokenDuration expected %v, got %v", authCfg.RefreshTokenDuration, options.Auth.RefreshTokenDuration)
	}
	if options.Auth.IssuerNameInJWT != authCfg.IssuerNameInJWT {
		t.Errorf("auth config mismatch: IssuerNameInJWT expected %q, got %q", authCfg.IssuerNameInJWT, options.Auth.IssuerNameInJWT)
	}
	if options.Auth.RefreshTokenCookieName != authCfg.RefreshTokenCookieName {
		t.Errorf("auth config mismatch: RefreshTokenCookieName expected %q, got %q", authCfg.RefreshTokenCookieName, options.Auth.RefreshTokenCookieName)
	}
	if options.Auth.AuthBasePath != authCfg.AuthBasePath {
		t.Errorf("auth config mismatch: AuthBasePath expected %q, got %q", authCfg.AuthBasePath, options.Auth.AuthBasePath)
	}
	if !reflect.DeepEqual(options.Auth.RolesOnRegister, authCfg.RolesOnRegister) {
		t.Errorf("auth config mismatch: InitialRoles expected %v, got %v", authCfg.RolesOnRegister, options.Auth.RolesOnRegister)
	}
	if options.Auth.NotRegisterRoutes != authCfg.NotRegisterRoutes {
		t.Errorf("auth config mismatch: NotRegisterRoutes expected %v, got %v", authCfg.NotRegisterRoutes, options.Auth.NotRegisterRoutes)
	}
	// Note: We don't directly test the internal 'enabled' flag.
	// Setting the AuthConfig implies auth is enabled via WithAuthConfig.
}

// TestWithAuthKey verifies that WithAuthKey sets JWT access and refresh secrets.
func TestWithAuthKey(t *testing.T) {
	accessKey := "accesssecret"
	refreshKey := "refreshsecret"
	option := servex.WithAuthKey(accessKey, refreshKey)
	options := servex.Options{}
	option(&options)

	if options.Auth.JWTAccessSecret != accessKey {
		t.Errorf("expected access key %q, got %q", accessKey, options.Auth.JWTAccessSecret)
	}
	if options.Auth.JWTRefreshSecret != refreshKey {
		t.Errorf("expected refresh key %q, got %q", refreshKey, options.Auth.JWTRefreshSecret)
	}
}

// TestWithAuthIssuer verifies that WithAuthIssuer sets the JWT issuer name.
func TestWithAuthIssuer(t *testing.T) {
	issuer := "testissuer"
	option := servex.WithAuthIssuer(issuer)
	options := servex.Options{}
	option(&options)

	if options.Auth.IssuerNameInJWT != issuer {
		t.Errorf("expected issuer %q, got %q", issuer, options.Auth.IssuerNameInJWT)
	}
}

// TestWithAuthBasePath verifies that WithAuthBasePath sets the authentication base path.
func TestWithAuthBasePath(t *testing.T) {
	path := "/api/auth"
	option := servex.WithAuthBasePath(path)
	options := servex.Options{}
	option(&options)

	if options.Auth.AuthBasePath != path {
		t.Errorf("expected auth base path %q, got %q", path, options.Auth.AuthBasePath)
	}
}

// TestWithAuthInitialRoles verifies that WithAuthInitialRoles sets the initial user roles.
func TestWithAuthInitialRoles(t *testing.T) {
	roles := []servex.UserRole{"admin", "user"}
	option := servex.WithAuthInitialRoles(roles...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Auth.RolesOnRegister, roles) {
		t.Errorf("expected initial roles %v, got %v", roles, options.Auth.RolesOnRegister)
	}
}

// TestWithAuthRefreshTokenCookieName verifies that WithAuthRefreshTokenCookieName sets the cookie name.
func TestWithAuthRefreshTokenCookieName(t *testing.T) {
	name := "my_refresh_token"
	option := servex.WithAuthRefreshTokenCookieName(name)
	options := servex.Options{}
	option(&options)

	if options.Auth.RefreshTokenCookieName != name {
		t.Errorf("expected refresh token cookie name %q, got %q", name, options.Auth.RefreshTokenCookieName)
	}
}

// TestWithAuthTokensDuration verifies that WithAuthTokensDuration sets the token durations.
func TestWithAuthTokensDuration(t *testing.T) {
	accessDuration := 15 * time.Minute
	refreshDuration := 14 * 24 * time.Hour
	option := servex.WithAuthTokensDuration(accessDuration, refreshDuration)
	options := servex.Options{}
	option(&options)

	if options.Auth.AccessTokenDuration != accessDuration {
		t.Errorf("expected access token duration %v, got %v", accessDuration, options.Auth.AccessTokenDuration)
	}
	if options.Auth.RefreshTokenDuration != refreshDuration {
		t.Errorf("expected refresh token duration %v, got %v", refreshDuration, options.Auth.RefreshTokenDuration)
	}
}

// TestWithAuthNotRegisterRoutes verifies that WithAuthNotRegisterRoutes sets the flag.
func TestWithAuthNotRegisterRoutes(t *testing.T) {
	option := servex.WithAuthNotRegisterRoutes(true)
	options := servex.Options{}
	option(&options)

	if !options.Auth.NotRegisterRoutes {
		t.Errorf("expected NotRegisterRoutes to be true, got false")
	}

	option = servex.WithAuthNotRegisterRoutes(false)
	options = servex.Options{} // Reset options
	option(&options)

	if options.Auth.NotRegisterRoutes {
		t.Errorf("expected NotRegisterRoutes to be false, got true")
	}
}

// mockAuthDatabase provides a mock implementation of the AuthDatabase interface.
type mockAuthDatabase struct{}

// NewUser mocks creating a new user.
func (m *mockAuthDatabase) NewUser(ctx context.Context, username string, passwordHash string, roles ...servex.UserRole) (string, error) {
	return "mockUserID", nil
}

// FindByID mocks finding a user by ID.
func (m *mockAuthDatabase) FindByID(ctx context.Context, id string) (servex.User, bool, error) {
	return servex.User{ID: id}, true, nil // Return a dummy user
}

// FindByUsername mocks finding a user by username.
func (m *mockAuthDatabase) FindByUsername(ctx context.Context, username string) (servex.User, bool, error) {
	return servex.User{Username: username}, true, nil // Return a dummy user
}

// FindAll mocks retrieving all users.
func (m *mockAuthDatabase) FindAll(ctx context.Context) ([]servex.User, error) {
	return []servex.User{}, nil // Return an empty slice
}

// UpdateUser mocks updating a user.
func (m *mockAuthDatabase) UpdateUser(ctx context.Context, id string, diff *servex.UserDiff) error {
	return nil
}

// TestWithRateLimitConfig verifies that WithRateLimitConfig sets the entire RateLimitConfig.
func TestWithRateLimitConfig(t *testing.T) {
	customKeyFunc := func(r *http.Request) string { return "testkey" }
	rateLimit := servex.RateLimitConfig{
		RequestsPerInterval: 100,
		Interval:            time.Minute,
		BurstSize:           150,
		StatusCode:          http.StatusTooManyRequests,
		Message:             "custom rate limit message",
		KeyFunc:             customKeyFunc,
		ExcludePaths:        []string{"/health", "/metrics"},
		IncludePaths:        []string{"/api"},
	}

	option := servex.WithRateLimitConfig(rateLimit)
	options := servex.Options{}
	option(&options)

	// Compare all fields
	if options.RateLimit.RequestsPerInterval != rateLimit.RequestsPerInterval {
		t.Errorf("expected requests per interval %d, got %d", rateLimit.RequestsPerInterval, options.RateLimit.RequestsPerInterval)
	}
	if options.RateLimit.Interval != rateLimit.Interval {
		t.Errorf("expected interval %v, got %v", rateLimit.Interval, options.RateLimit.Interval)
	}
	if options.RateLimit.BurstSize != rateLimit.BurstSize {
		t.Errorf("expected burst size %d, got %d", rateLimit.BurstSize, options.RateLimit.BurstSize)
	}
	if options.RateLimit.StatusCode != rateLimit.StatusCode {
		t.Errorf("expected status code %d, got %d", rateLimit.StatusCode, options.RateLimit.StatusCode)
	}
	if options.RateLimit.Message != rateLimit.Message {
		t.Errorf("expected message %q, got %q", rateLimit.Message, options.RateLimit.Message)
	}
	// Can't directly compare function references, but we ensure KeyFunc is set
	if options.RateLimit.KeyFunc == nil {
		t.Errorf("expected KeyFunc to be set, got nil")
	}
	if !reflect.DeepEqual(options.RateLimit.ExcludePaths, rateLimit.ExcludePaths) {
		t.Errorf("expected exclude paths %v, got %v", rateLimit.ExcludePaths, options.RateLimit.ExcludePaths)
	}
	if !reflect.DeepEqual(options.RateLimit.IncludePaths, rateLimit.IncludePaths) {
		t.Errorf("expected include paths %v, got %v", rateLimit.IncludePaths, options.RateLimit.IncludePaths)
	}
}

// TestWithRPM verifies that WithRPM sets the requests per minute limit.
func TestWithRPM(t *testing.T) {
	rpm := 120
	option := servex.WithRPM(rpm)
	options := servex.Options{}
	option(&options)

	if options.RateLimit.RequestsPerInterval != rpm {
		t.Errorf("expected requests per interval %d, got %d", rpm, options.RateLimit.RequestsPerInterval)
	}
	if options.RateLimit.Interval != time.Minute {
		t.Errorf("expected interval to be 1 minute, got %v", options.RateLimit.Interval)
	}
}

// TestWithRPS verifies that WithRPS sets the requests per second limit.
func TestWithRPS(t *testing.T) {
	rps := 30
	option := servex.WithRPS(rps)
	options := servex.Options{}
	option(&options)

	if options.RateLimit.RequestsPerInterval != rps {
		t.Errorf("expected requests per interval %d, got %d", rps, options.RateLimit.RequestsPerInterval)
	}
	if options.RateLimit.Interval != time.Second {
		t.Errorf("expected interval to be 1 second, got %v", options.RateLimit.Interval)
	}
}

// TestWithRequestsPerInterval verifies that WithRequestsPerInterval sets the rate limit configuration.
func TestWithRequestsPerInterval(t *testing.T) {
	requests := 500
	interval := 5 * time.Minute
	option := servex.WithRequestsPerInterval(requests, interval)
	options := servex.Options{}
	option(&options)

	if options.RateLimit.RequestsPerInterval != requests {
		t.Errorf("expected requests per interval %d, got %d", requests, options.RateLimit.RequestsPerInterval)
	}
	if options.RateLimit.Interval != interval {
		t.Errorf("expected interval %v, got %v", interval, options.RateLimit.Interval)
	}
}

// TestWithBurstSize verifies that WithBurstSize sets the burst size in rate limit configuration.
func TestWithBurstSize(t *testing.T) {
	burstSize := 200
	option := servex.WithBurstSize(burstSize)
	options := servex.Options{}
	option(&options)

	if options.RateLimit.BurstSize != burstSize {
		t.Errorf("expected burst size %d, got %d", burstSize, options.RateLimit.BurstSize)
	}
}

// TestWithRateLimitStatusCode verifies that WithRateLimitStatusCode sets the status code in rate limit configuration.
func TestWithRateLimitStatusCode(t *testing.T) {
	statusCode := http.StatusServiceUnavailable // Using 503 instead of default 429
	option := servex.WithRateLimitStatusCode(statusCode)
	options := servex.Options{}
	option(&options)

	if options.RateLimit.StatusCode != statusCode {
		t.Errorf("expected status code %d, got %d", statusCode, options.RateLimit.StatusCode)
	}
}

// TestWithRateLimitMessage verifies that WithRateLimitMessage sets the message in rate limit configuration.
func TestWithRateLimitMessage(t *testing.T) {
	message := "Too many requests, try again later"
	option := servex.WithRateLimitMessage(message)
	options := servex.Options{}
	option(&options)

	if options.RateLimit.Message != message {
		t.Errorf("expected message %q, got %q", message, options.RateLimit.Message)
	}
}

// TestWithRateLimitKeyFunc verifies that WithRateLimitKeyFunc sets the key function in rate limit configuration.
func TestWithRateLimitKeyFunc(t *testing.T) {
	keyFunc := func(r *http.Request) string {
		return r.RemoteAddr
	}
	option := servex.WithRateLimitKeyFunc(keyFunc)
	options := servex.Options{}
	option(&options)

	// Cannot directly compare functions, so just check it's not nil
	if options.RateLimit.KeyFunc == nil {
		t.Errorf("expected KeyFunc to be set, got nil")
	}
}

// TestWithRateLimitExcludePaths verifies that WithRateLimitExcludePaths sets the excluded paths in rate limit configuration.
func TestWithRateLimitExcludePaths(t *testing.T) {
	paths := []string{"/health", "/metrics", "/docs"}
	option := servex.WithRateLimitExcludePaths(paths...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.RateLimit.ExcludePaths, paths) {
		t.Errorf("expected exclude paths %v, got %v", paths, options.RateLimit.ExcludePaths)
	}
}

// TestWithRateLimitIncludePaths verifies that WithRateLimitIncludePaths sets the included paths in rate limit configuration.
func TestWithRateLimitIncludePaths(t *testing.T) {
	paths := []string{"/api/v1", "/api/v2/users"}
	option := servex.WithRateLimitIncludePaths(paths...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.RateLimit.IncludePaths, paths) {
		t.Errorf("expected include paths %v, got %v", paths, options.RateLimit.IncludePaths)
	}
}

// TestWithRateLimitTrustedProxies verifies that WithRateLimitTrustedProxies sets the trusted proxies correctly.
func TestWithRateLimitTrustedProxies(t *testing.T) {
	trustedProxies := []string{"10.0.0.0/24", "192.168.1.1", "2001:db8::/32"}
	option := servex.WithRateLimitTrustedProxies(trustedProxies...)
	options := servex.Options{}
	option(&options)

	if len(options.RateLimit.TrustedProxies) != len(trustedProxies) {
		t.Errorf("expected %d trusted proxies, got %d", len(trustedProxies), len(options.RateLimit.TrustedProxies))
	}

	for i, expected := range trustedProxies {
		if options.RateLimit.TrustedProxies[i] != expected {
			t.Errorf("expected trusted proxy %q at index %d, got %q", expected, i, options.RateLimit.TrustedProxies[i])
		}
	}
}

// TestReadCertificate tests the ReadCertificate utility function with invalid data.
func TestReadCertificate(t *testing.T) {
	// Test with invalid certificate data
	invalidCert := []byte("invalid cert data")
	invalidKey := []byte("invalid key data")

	_, err := servex.ReadCertificate(invalidCert, invalidKey)
	if err == nil {
		t.Errorf("expected error for invalid certificate data, got nil")
	}

	// Test with empty data
	_, err = servex.ReadCertificate([]byte{}, []byte{})
	if err == nil {
		t.Errorf("expected error for empty certificate data, got nil")
	}
}

// TestReadCertificateFromFile tests the ReadCertificateFromFile utility function with non-existent files.
func TestReadCertificateFromFile(t *testing.T) {
	certFilePath := "cert.pem"
	keyFilePath := "key.pem"

	cert, err := servex.ReadCertificateFromFile(certFilePath, keyFilePath)
	if err == nil {
		t.Errorf("expected error reading non-existent certificate files, got none")
	}
	// When there's an error, cert should be zero-value
	if len(cert.Certificate) != 0 {
		t.Errorf("expected zero-value certificate when error occurs, got %v", cert)
	}
}

// Filter option tests

func TestWithFilterConfig(t *testing.T) {
	filterConfig := servex.FilterConfig{
		AllowedIPs:     []string{"192.168.1.0/24"},
		BlockedIPs:     []string{"10.0.0.1"},
		StatusCode:     403,
		Message:        "Blocked",
		ExcludePaths:   []string{"/health"},
		IncludePaths:   []string{"/api"},
		TrustedProxies: []string{"172.16.0.0/12"},
	}
	option := servex.WithFilterConfig(filterConfig)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter, filterConfig) {
		t.Errorf("expected filter config to be %v, got %v", filterConfig, options.Filter)
	}
}

func TestWithAllowedIPs(t *testing.T) {
	ips := []string{"192.168.1.0/24", "10.0.0.1", "::1"}
	option := servex.WithAllowedIPs(ips...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.AllowedIPs, ips) {
		t.Errorf("expected allowed IPs to be %v, got %v", ips, options.Filter.AllowedIPs)
	}
}

func TestWithBlockedIPs(t *testing.T) {
	ips := []string{"203.0.113.0/24", "198.51.100.1"}
	option := servex.WithBlockedIPs(ips...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.BlockedIPs, ips) {
		t.Errorf("expected blocked IPs to be %v, got %v", ips, options.Filter.BlockedIPs)
	}
}

func TestWithAllowedUserAgents(t *testing.T) {
	userAgents := []string{"Mozilla/5.0", "Chrome/90.0", "Safari/14.0"}
	option := servex.WithAllowedUserAgents(userAgents...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.AllowedUserAgents, userAgents) {
		t.Errorf("expected allowed user agents to be %v, got %v", userAgents, options.Filter.AllowedUserAgents)
	}
}

func TestWithAllowedUserAgentsRegex(t *testing.T) {
	patterns := []string{"Mozilla.*", ".*Chrome.*", "Safari/[0-9]+"}
	option := servex.WithAllowedUserAgentsRegex(patterns...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.AllowedUserAgentsRegex, patterns) {
		t.Errorf("expected allowed user agent regex patterns to be %v, got %v", patterns, options.Filter.AllowedUserAgentsRegex)
	}
}

func TestWithBlockedUserAgents(t *testing.T) {
	userAgents := []string{"BadBot/1.0", "Scraper/2.0", "EvilCrawler"}
	option := servex.WithBlockedUserAgents(userAgents...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.BlockedUserAgents, userAgents) {
		t.Errorf("expected blocked user agents to be %v, got %v", userAgents, options.Filter.BlockedUserAgents)
	}
}

func TestWithBlockedUserAgentsRegex(t *testing.T) {
	patterns := []string{".*[Bb]ot.*", ".*[Ss]craper.*", ".*[Cc]rawler.*"}
	option := servex.WithBlockedUserAgentsRegex(patterns...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.BlockedUserAgentsRegex, patterns) {
		t.Errorf("expected blocked user agent regex patterns to be %v, got %v", patterns, options.Filter.BlockedUserAgentsRegex)
	}
}

func TestWithAllowedHeaders(t *testing.T) {
	headers := map[string][]string{
		"Authorization": {"Bearer token123", "Basic auth456"},
		"X-API-Key":     {"key1", "key2"},
	}
	option := servex.WithAllowedHeaders(headers)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.AllowedHeaders, headers) {
		t.Errorf("expected allowed headers to be %v, got %v", headers, options.Filter.AllowedHeaders)
	}
}

func TestWithAllowedHeadersRegex(t *testing.T) {
	headers := map[string][]string{
		"Authorization": {"Bearer .*", "Basic [A-Za-z0-9]+"},
		"X-API-Key":     {"^key-[0-9a-f]{32}$"},
	}
	option := servex.WithAllowedHeadersRegex(headers)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.AllowedHeadersRegex, headers) {
		t.Errorf("expected allowed header regex patterns to be %v, got %v", headers, options.Filter.AllowedHeadersRegex)
	}
}

func TestWithBlockedHeaders(t *testing.T) {
	headers := map[string][]string{
		"X-Debug":   {"true", "1", "on"},
		"X-Private": {"internal"},
	}
	option := servex.WithBlockedHeaders(headers)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.BlockedHeaders, headers) {
		t.Errorf("expected blocked headers to be %v, got %v", headers, options.Filter.BlockedHeaders)
	}
}

func TestWithBlockedHeadersRegex(t *testing.T) {
	headers := map[string][]string{
		"X-Admin":         {".*"},
		"X-Forwarded-For": {".*script.*", ".*<.*>.*"},
	}
	option := servex.WithBlockedHeadersRegex(headers)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.BlockedHeadersRegex, headers) {
		t.Errorf("expected blocked header regex patterns to be %v, got %v", headers, options.Filter.BlockedHeadersRegex)
	}
}

func TestWithAllowedQueryParams(t *testing.T) {
	params := map[string][]string{
		"api_key": {"secret123", "secret456"},
		"version": {"v1", "v2"},
	}
	option := servex.WithAllowedQueryParams(params)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.AllowedQueryParams, params) {
		t.Errorf("expected allowed query params to be %v, got %v", params, options.Filter.AllowedQueryParams)
	}
}

func TestWithAllowedQueryParamsRegex(t *testing.T) {
	params := map[string][]string{
		"api_key": {"secret[0-9]+", "key-[a-f0-9]{32}"},
		"version": {"v[0-9]+", "beta.*"},
	}
	option := servex.WithAllowedQueryParamsRegex(params)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.AllowedQueryParamsRegex, params) {
		t.Errorf("expected allowed query param regex patterns to be %v, got %v", params, options.Filter.AllowedQueryParamsRegex)
	}
}

func TestWithBlockedQueryParams(t *testing.T) {
	params := map[string][]string{
		"debug":  {"true", "1", "on"},
		"unsafe": {"yes", "enable"},
	}
	option := servex.WithBlockedQueryParams(params)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.BlockedQueryParams, params) {
		t.Errorf("expected blocked query params to be %v, got %v", params, options.Filter.BlockedQueryParams)
	}
}

func TestWithBlockedQueryParamsRegex(t *testing.T) {
	params := map[string][]string{
		"admin":    {".*"},
		"redirect": {"https?://[^/]*[^.].*"},
	}
	option := servex.WithBlockedQueryParamsRegex(params)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.BlockedQueryParamsRegex, params) {
		t.Errorf("expected blocked query param regex patterns to be %v, got %v", params, options.Filter.BlockedQueryParamsRegex)
	}
}

func TestWithFilterExcludePaths(t *testing.T) {
	paths := []string{"/health", "/metrics", "/favicon.ico"}
	option := servex.WithFilterExcludePaths(paths...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.ExcludePaths, paths) {
		t.Errorf("expected filter exclude paths to be %v, got %v", paths, options.Filter.ExcludePaths)
	}
}

func TestWithFilterIncludePaths(t *testing.T) {
	paths := []string{"/api/v1", "/secure", "/admin"}
	option := servex.WithFilterIncludePaths(paths...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.IncludePaths, paths) {
		t.Errorf("expected filter include paths to be %v, got %v", paths, options.Filter.IncludePaths)
	}
}

func TestWithFilterStatusCode(t *testing.T) {
	statusCode := 418 // I'm a teapot
	option := servex.WithFilterStatusCode(statusCode)
	options := servex.Options{}
	option(&options)

	if options.Filter.StatusCode != statusCode {
		t.Errorf("expected filter status code to be %d, got %d", statusCode, options.Filter.StatusCode)
	}
}

func TestWithFilterMessage(t *testing.T) {
	message := "Custom security filter message"
	option := servex.WithFilterMessage(message)
	options := servex.Options{}
	option(&options)

	if options.Filter.Message != message {
		t.Errorf("expected filter message to be %q, got %q", message, options.Filter.Message)
	}
}

func TestWithFilterTrustedProxies(t *testing.T) {
	proxies := []string{"172.16.0.0/12", "10.0.0.0/8", "192.168.1.1"}
	option := servex.WithFilterTrustedProxies(proxies...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Filter.TrustedProxies, proxies) {
		t.Errorf("expected filter trusted proxies to be %v, got %v", proxies, options.Filter.TrustedProxies)
	}
}

// Test combinations of filter options
func TestMultipleFilterOptions(t *testing.T) {
	opts := servex.Options{}
	servex.WithAllowedIPs("192.168.1.0/24")(&opts)
	servex.WithBlockedUserAgents("badbot")(&opts)
	servex.WithFilterStatusCode(403)(&opts)

	if len(opts.Filter.AllowedIPs) != 1 || opts.Filter.AllowedIPs[0] != "192.168.1.0/24" {
		t.Errorf("Expected AllowedIPs to be ['192.168.1.0/24'], got %v", opts.Filter.AllowedIPs)
	}
	if len(opts.Filter.BlockedUserAgents) != 1 || opts.Filter.BlockedUserAgents[0] != "badbot" {
		t.Errorf("Expected BlockedUserAgents to be ['badbot'], got %v", opts.Filter.BlockedUserAgents)
	}
	if opts.Filter.StatusCode != 403 {
		t.Errorf("Expected StatusCode to be 403, got %d", opts.Filter.StatusCode)
	}
}

// TestWithHealthEndpoint tests the WithHealthEndpoint option.
func TestWithHealthEndpoint(t *testing.T) {
	opts := servex.Options{}
	servex.WithHealthEndpoint()(&opts)

	if !opts.EnableHealthEndpoint {
		t.Errorf("Expected EnableHealthEndpoint to be true, got %v", opts.EnableHealthEndpoint)
	}
	if opts.HealthPath != "/health" {
		t.Errorf("Expected HealthPath to be '/health', got %s", opts.HealthPath)
	}
}

// TestWithHealthPath tests the WithHealthPath option.
func TestWithHealthPath(t *testing.T) {
	customPath := "/api/health"
	opts := servex.Options{}
	servex.WithHealthPath(customPath)(&opts)

	if !opts.EnableHealthEndpoint {
		t.Errorf("Expected EnableHealthEndpoint to be true, got %v", opts.EnableHealthEndpoint)
	}
	if opts.HealthPath != customPath {
		t.Errorf("Expected HealthPath to be '%s', got %s", customPath, opts.HealthPath)
	}
}

// Cache Control Tests

// TestWithCacheConfig verifies that WithCacheConfig sets the cache configuration correctly.
func TestWithCacheConfig(t *testing.T) {
	config := servex.CacheConfig{
		Enabled:      true,
		CacheControl: "public, max-age=3600",
		ETag:         `"v1.2.3"`,
		LastModified: "Wed, 21 Oct 2015 07:28:00 GMT",
		Vary:         "Accept-Encoding",
		ExcludePaths: []string{"/api/*"},
		IncludePaths: []string{"/static/*"},
	}

	option := servex.WithCacheConfig(config)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Cache, config) {
		t.Errorf("expected cache config to be %+v, got %+v", config, options.Cache)
	}
}

// TestWithCacheControl verifies that WithCacheControl enables caching and sets the Cache-Control header.
func TestWithCacheControl(t *testing.T) {
	cacheControl := "public, max-age=3600"
	option := servex.WithCacheControl(cacheControl)
	options := servex.Options{}
	option(&options)

	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.CacheControl != cacheControl {
		t.Errorf("expected cache control to be %q, got %q", cacheControl, options.Cache.CacheControl)
	}
}

// TestWithCacheHeaders verifies that WithCacheHeaders sets default cache headers.
func TestWithCacheHeaders(t *testing.T) {
	option := servex.WithCacheHeaders()
	options := servex.Options{}
	option(&options)

	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.CacheControl != "public, max-age=3600" {
		t.Errorf("expected default cache control, got %q", options.Cache.CacheControl)
	}
	if options.Cache.Vary != "Accept-Encoding" {
		t.Errorf("expected default vary header, got %q", options.Cache.Vary)
	}
}

// TestWithCacheExpires verifies that WithCacheExpires sets the Expires header.
func TestWithCacheExpires(t *testing.T) {
	expires := "Wed, 21 Oct 2025 07:28:00 GMT"
	option := servex.WithCacheExpires(expires)
	options := servex.Options{}
	option(&options)

	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.Expires != expires {
		t.Errorf("expected expires to be %q, got %q", expires, options.Cache.Expires)
	}
}

// TestWithCacheExpiresTime verifies that WithCacheExpiresTime formats time correctly.
func TestWithCacheExpiresTime(t *testing.T) {
	testTime := time.Date(2025, 10, 21, 7, 28, 0, 0, time.UTC)
	expected := testTime.Format(http.TimeFormat)

	option := servex.WithCacheExpiresTime(testTime)
	options := servex.Options{}
	option(&options)

	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.Expires != expected {
		t.Errorf("expected expires to be %q, got %q", expected, options.Cache.Expires)
	}
}

// TestWithCacheETag verifies that WithCacheETag sets the ETag header.
func TestWithCacheETag(t *testing.T) {
	etag := `"v1.2.3"`
	option := servex.WithCacheETag(etag)
	options := servex.Options{}
	option(&options)

	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.ETag != etag {
		t.Errorf("expected etag to be %q, got %q", etag, options.Cache.ETag)
	}
}

// TestWithCacheETagFunc verifies that WithCacheETagFunc sets the dynamic ETag function.
func TestWithCacheETagFunc(t *testing.T) {
	etagFunc := func(r *http.Request) string {
		return `"dynamic-etag"`
	}

	option := servex.WithCacheETagFunc(etagFunc)
	options := servex.Options{}
	option(&options)

	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.ETagFunc == nil {
		t.Errorf("expected etag function to be set, got nil")
	}

	// Test the function works
	req, _ := http.NewRequest(servex.GET, "/test", nil)
	result := options.Cache.ETagFunc(req)
	if result != `"dynamic-etag"` {
		t.Errorf("expected etag function to return %q, got %q", `"dynamic-etag"`, result)
	}
}

// TestWithCacheLastModified verifies that WithCacheLastModified sets the Last-Modified header.
func TestWithCacheLastModified(t *testing.T) {
	lastModified := "Wed, 21 Oct 2015 07:28:00 GMT"
	option := servex.WithCacheLastModified(lastModified)
	options := servex.Options{}
	option(&options)

	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.LastModified != lastModified {
		t.Errorf("expected last modified to be %q, got %q", lastModified, options.Cache.LastModified)
	}
}

// TestWithCacheLastModifiedTime verifies that WithCacheLastModifiedTime formats time correctly.
func TestWithCacheLastModifiedTime(t *testing.T) {
	testTime := time.Date(2015, 10, 21, 7, 28, 0, 0, time.UTC)
	expected := "Wed, 21 Oct 2015 07:28:00 GMT"

	option := servex.WithCacheLastModifiedTime(testTime)
	options := servex.Options{}
	option(&options)

	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.LastModified != expected {
		t.Errorf("expected last modified to be %q, got %q", expected, options.Cache.LastModified)
	}
}

// TestWithCacheLastModifiedFunc verifies that WithCacheLastModifiedFunc sets the dynamic LastModified function.
func TestWithCacheLastModifiedFunc(t *testing.T) {
	testTime := time.Date(2015, 10, 21, 7, 28, 0, 0, time.UTC)
	lastModFunc := func(r *http.Request) time.Time {
		return testTime
	}

	option := servex.WithCacheLastModifiedFunc(lastModFunc)
	options := servex.Options{}
	option(&options)

	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.LastModifiedFunc == nil {
		t.Errorf("expected last modified function to be set, got nil")
	}

	// Test the function works
	req, _ := http.NewRequest(servex.GET, "/test", nil)
	result := options.Cache.LastModifiedFunc(req)
	if !result.Equal(testTime) {
		t.Errorf("expected last modified function to return %v, got %v", testTime, result)
	}
}

// TestWithCacheVary verifies that WithCacheVary sets the Vary header.
func TestWithCacheVary(t *testing.T) {
	vary := "Accept-Encoding, User-Agent"
	option := servex.WithCacheVary(vary)
	options := servex.Options{}
	option(&options)

	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.Vary != vary {
		t.Errorf("expected vary to be %q, got %q", vary, options.Cache.Vary)
	}
}

// TestWithCacheExcludePaths verifies that WithCacheExcludePaths sets exclude paths.
func TestWithCacheExcludePaths(t *testing.T) {
	paths := []string{"/api/*", "/admin/*"}
	option := servex.WithCacheExcludePaths(paths...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Cache.ExcludePaths, paths) {
		t.Errorf("expected exclude paths to be %v, got %v", paths, options.Cache.ExcludePaths)
	}
}

// TestWithCacheIncludePaths verifies that WithCacheIncludePaths sets include paths.
func TestWithCacheIncludePaths(t *testing.T) {
	paths := []string{"/static/*", "/assets/*"}
	option := servex.WithCacheIncludePaths(paths...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Cache.IncludePaths, paths) {
		t.Errorf("expected include paths to be %v, got %v", paths, options.Cache.IncludePaths)
	}
}

// TestWithCacheNoCache verifies that WithCacheNoCache sets no-cache headers.
func TestWithCacheNoCache(t *testing.T) {
	option := servex.WithCacheNoCache()
	options := servex.Options{}
	option(&options)

	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.CacheControl != "no-cache, must-revalidate" {
		t.Errorf("expected no-cache control, got %q", options.Cache.CacheControl)
	}
}

// TestWithCacheNoStore verifies that WithCacheNoStore sets no-store headers.
func TestWithCacheNoStore(t *testing.T) {
	option := servex.WithCacheNoStore()
	options := servex.Options{}
	option(&options)

	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.CacheControl != "no-store, no-cache, must-revalidate" {
		t.Errorf("expected no-store control, got %q", options.Cache.CacheControl)
	}
}

// TestWithCachePublic verifies that WithCachePublic sets public cache headers.
func TestWithCachePublic(t *testing.T) {
	maxAge := 3600
	option := servex.WithCachePublic(maxAge)
	options := servex.Options{}
	option(&options)

	expected := "public, max-age=3600"
	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.CacheControl != expected {
		t.Errorf("expected cache control to be %q, got %q", expected, options.Cache.CacheControl)
	}
}

// TestWithCachePrivate verifies that WithCachePrivate sets private cache headers.
func TestWithCachePrivate(t *testing.T) {
	maxAge := 900
	option := servex.WithCachePrivate(maxAge)
	options := servex.Options{}
	option(&options)

	expected := "private, max-age=900"
	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.CacheControl != expected {
		t.Errorf("expected cache control to be %q, got %q", expected, options.Cache.CacheControl)
	}
}

// TestWithCacheStaticAssets verifies that WithCacheStaticAssets sets optimal static asset headers.
func TestWithCacheStaticAssets(t *testing.T) {
	tests := []struct {
		name           string
		maxAge         int
		expectedMaxAge int
	}{
		{"default max-age", 0, 31536000},
		{"custom max-age", 15552000, 15552000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option := servex.WithCacheStaticAssets(tt.maxAge)
			options := servex.Options{}
			option(&options)

			expected := "public, max-age=" + strconv.Itoa(tt.expectedMaxAge) + ", immutable"
			if !options.Cache.Enabled {
				t.Errorf("expected cache to be enabled, got disabled")
			}
			if options.Cache.CacheControl != expected {
				t.Errorf("expected cache control to be %q, got %q", expected, options.Cache.CacheControl)
			}
			if options.Cache.Vary != "Accept-Encoding" {
				t.Errorf("expected default vary header, got %q", options.Cache.Vary)
			}
		})
	}
}

// TestWithCacheAPI verifies that WithCacheAPI sets optimal API cache headers.
func TestWithCacheAPI(t *testing.T) {
	tests := []struct {
		name           string
		maxAge         int
		expectedMaxAge int
	}{
		{"default max-age", 0, 300},
		{"custom max-age", 600, 600},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option := servex.WithCacheAPI(tt.maxAge)
			options := servex.Options{}
			option(&options)

			expected := "public, max-age=" + strconv.Itoa(tt.expectedMaxAge) + ", must-revalidate"
			if !options.Cache.Enabled {
				t.Errorf("expected cache to be enabled, got disabled")
			}
			if options.Cache.CacheControl != expected {
				t.Errorf("expected cache control to be %q, got %q", expected, options.Cache.CacheControl)
			}
			if options.Cache.Vary != "Accept-Encoding" {
				t.Errorf("expected default vary header, got %q", options.Cache.Vary)
			}
		})
	}
}

// TestMultipleCacheOptions verifies that multiple cache options work together correctly.
func TestMultipleCacheOptions(t *testing.T) {
	testTime := time.Date(2015, 10, 21, 7, 28, 0, 0, time.UTC)
	options := servex.Options{}

	// Apply multiple options
	servex.WithCachePublic(3600)(&options)
	servex.WithCacheETag(`"v1.2.3"`)(&options)
	servex.WithCacheLastModifiedTime(testTime)(&options)
	servex.WithCacheVary("Accept-Encoding, User-Agent")(&options)
	servex.WithCacheIncludePaths("/static/*")(&options)
	servex.WithCacheExcludePaths("/api/*")(&options)

	// Verify all options are set correctly
	if !options.Cache.Enabled {
		t.Errorf("expected cache to be enabled, got disabled")
	}
	if options.Cache.CacheControl != "public, max-age=3600" {
		t.Errorf("expected cache control to be 'public, max-age=3600', got %q", options.Cache.CacheControl)
	}
	if options.Cache.ETag != `"v1.2.3"` {
		t.Errorf("expected etag to be '\"v1.2.3\"', got %q", options.Cache.ETag)
	}
	if options.Cache.LastModified != "Wed, 21 Oct 2015 07:28:00 GMT" {
		t.Errorf("expected last modified to be correctly formatted, got %q", options.Cache.LastModified)
	}
	if options.Cache.Vary != "Accept-Encoding, User-Agent" {
		t.Errorf("expected vary header, got %q", options.Cache.Vary)
	}
	if len(options.Cache.IncludePaths) != 1 || options.Cache.IncludePaths[0] != "/static/*" {
		t.Errorf("expected include paths to be ['/static/*'], got %v", options.Cache.IncludePaths)
	}
	if len(options.Cache.ExcludePaths) != 1 || options.Cache.ExcludePaths[0] != "/api/*" {
		t.Errorf("expected exclude paths to be ['/api/*'], got %v", options.Cache.ExcludePaths)
	}
}

// TestWithSecurityConfig tests whether the WithSecurityConfig option sets the security configuration correctly.
func TestWithSecurityConfig(t *testing.T) {
	securityConfig := servex.SecurityConfig{
		Enabled:                 true,
		ContentSecurityPolicy:   "default-src 'self'",
		XContentTypeOptions:     "nosniff",
		XFrameOptions:           "DENY",
		XXSSProtection:          "1; mode=block",
		StrictTransportSecurity: "max-age=31536000",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		PermissionsPolicy:       "camera=(), microphone=()",
		ExcludePaths:            []string{"/api/*"},
		IncludePaths:            []string{"/secure/*"},
	}

	option := servex.WithSecurityConfig(securityConfig)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Security, securityConfig) {
		t.Errorf("expected security config to be %+v, got %+v", securityConfig, options.Security)
	}
}

// TestWithSecurityHeaders tests whether the WithSecurityHeaders option enables basic security headers.
func TestWithSecurityHeaders(t *testing.T) {
	option := servex.WithSecurityHeaders()
	options := servex.Options{}
	option(&options)

	if !options.Security.Enabled {
		t.Errorf("expected security to be enabled, got false")
	}
	if options.Security.XContentTypeOptions != "nosniff" {
		t.Errorf("expected X-Content-Type-Options to be 'nosniff', got %q", options.Security.XContentTypeOptions)
	}
	if options.Security.XFrameOptions != "DENY" {
		t.Errorf("expected X-Frame-Options to be 'DENY', got %q", options.Security.XFrameOptions)
	}
	if options.Security.XXSSProtection != "1; mode=block" {
		t.Errorf("expected X-XSS-Protection to be '1; mode=block', got %q", options.Security.XXSSProtection)
	}
	if options.Security.ReferrerPolicy != "strict-origin-when-cross-origin" {
		t.Errorf("expected Referrer-Policy to be 'strict-origin-when-cross-origin', got %q", options.Security.ReferrerPolicy)
	}
}

// TestWithStrictSecurityHeaders tests whether the WithStrictSecurityHeaders option enables all strict security headers.
func TestWithStrictSecurityHeaders(t *testing.T) {
	option := servex.WithStrictSecurityHeaders()
	options := servex.Options{}
	option(&options)

	expectedHeaders := map[string]string{
		"ContentSecurityPolicy":         "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
		"XContentTypeOptions":           "nosniff",
		"XFrameOptions":                 "DENY",
		"XXSSProtection":                "1; mode=block",
		"StrictTransportSecurity":       "max-age=31536000; includeSubDomains; preload",
		"ReferrerPolicy":                "strict-origin-when-cross-origin",
		"PermissionsPolicy":             "camera=(), microphone=(), geolocation=()",
		"XPermittedCrossDomainPolicies": "none",
		"CrossOriginEmbedderPolicy":     "require-corp",
		"CrossOriginOpenerPolicy":       "same-origin",
		"CrossOriginResourcePolicy":     "same-site",
	}

	if !options.Security.Enabled {
		t.Errorf("expected security to be enabled, got false")
	}

	// Check each expected header
	securityValue := reflect.ValueOf(options.Security)
	for field, expectedValue := range expectedHeaders {
		fieldValue := securityValue.FieldByName(field)
		if !fieldValue.IsValid() {
			t.Errorf("field %s not found in SecurityConfig", field)
			continue
		}
		actualValue := fieldValue.String()
		if actualValue != expectedValue {
			t.Errorf("expected %s to be %q, got %q", field, expectedValue, actualValue)
		}
	}
}

// TestWithContentSecurityPolicy tests whether the WithContentSecurityPolicy option sets CSP correctly.
func TestWithContentSecurityPolicy(t *testing.T) {
	policy := "default-src 'self'; script-src 'self' 'unsafe-inline'"
	option := servex.WithContentSecurityPolicy(policy)
	options := servex.Options{}
	option(&options)

	if !options.Security.Enabled {
		t.Errorf("expected security to be enabled, got false")
	}
	if options.Security.ContentSecurityPolicy != policy {
		t.Errorf("expected Content-Security-Policy to be %q, got %q", policy, options.Security.ContentSecurityPolicy)
	}
}

// TestWithHSTSHeader tests whether the WithHSTSHeader option sets HSTS correctly with different configurations.
func TestWithHSTSHeader(t *testing.T) {
	tests := []struct {
		maxAge            int
		includeSubdomains bool
		preload           bool
		expected          string
	}{
		{31536000, false, false, "max-age=31536000"},
		{31536000, true, false, "max-age=31536000; includeSubDomains"},
		{31536000, false, true, "max-age=31536000; preload"},
		{31536000, true, true, "max-age=31536000; includeSubDomains; preload"},
		{0, false, false, "max-age=0"},
	}

	for _, tt := range tests {
		option := servex.WithHSTSHeader(tt.maxAge, tt.includeSubdomains, tt.preload)
		options := servex.Options{}
		option(&options)

		if !options.Security.Enabled {
			t.Errorf("expected security to be enabled, got false")
		}
		if options.Security.StrictTransportSecurity != tt.expected {
			t.Errorf("expected HSTS header to be %q, got %q", tt.expected, options.Security.StrictTransportSecurity)
		}
	}
}

// TestWithSecurityExcludePaths tests whether the WithSecurityExcludePaths option sets exclude paths correctly.
func TestWithSecurityExcludePaths(t *testing.T) {
	paths := []string{"/api/*", "/health", "/metrics"}
	option := servex.WithSecurityExcludePaths(paths...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Security.ExcludePaths, paths) {
		t.Errorf("expected exclude paths to be %v, got %v", paths, options.Security.ExcludePaths)
	}
}

// TestWithSecurityIncludePaths tests whether the WithSecurityIncludePaths option sets include paths correctly.
func TestWithSecurityIncludePaths(t *testing.T) {
	paths := []string{"/app/*", "/secure/*", "/admin/*"}
	option := servex.WithSecurityIncludePaths(paths...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.Security.IncludePaths, paths) {
		t.Errorf("expected include paths to be %v, got %v", paths, options.Security.IncludePaths)
	}
}

// TestWithCustomHeaders tests whether the WithCustomHeaders option sets custom headers correctly.
func TestWithCustomHeaders(t *testing.T) {
	headers := map[string]string{
		"X-API-Version":  "v1.0",
		"X-Service-Name": "test-service",
		"X-Environment":  "testing",
	}

	option := servex.WithCustomHeaders(headers)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.CustomHeaders, headers) {
		t.Errorf("expected custom headers to be %v, got %v", headers, options.CustomHeaders)
	}
}

// TestWithCustomHeadersMultiple tests whether multiple calls to WithCustomHeaders merge headers correctly.
func TestWithCustomHeadersMultiple(t *testing.T) {
	headers1 := map[string]string{
		"X-API-Version": "v1.0",
		"X-Service":     "test",
	}
	headers2 := map[string]string{
		"X-Environment": "testing",
		"X-API-Version": "v2.0", // This should override
	}

	option1 := servex.WithCustomHeaders(headers1)
	option2 := servex.WithCustomHeaders(headers2)
	options := servex.Options{}
	option1(&options)
	option2(&options)

	expected := map[string]string{
		"X-API-Version": "v2.0", // Overridden value
		"X-Service":     "test",
		"X-Environment": "testing",
	}

	if !reflect.DeepEqual(options.CustomHeaders, expected) {
		t.Errorf("expected custom headers to be %v, got %v", expected, options.CustomHeaders)
	}
}

// TestWithRemoveHeaders tests whether the WithRemoveHeaders option sets headers to remove correctly.
func TestWithRemoveHeaders(t *testing.T) {
	headers := []string{"Server", "X-Powered-By", "X-AspNet-Version"}
	option := servex.WithRemoveHeaders(headers...)
	options := servex.Options{}
	option(&options)

	if !reflect.DeepEqual(options.HeadersToRemove, headers) {
		t.Errorf("expected headers to remove to be %v, got %v", headers, options.HeadersToRemove)
	}
}

// TestWithRemoveHeadersMultiple tests whether multiple calls to WithRemoveHeaders append headers correctly.
func TestWithRemoveHeadersMultiple(t *testing.T) {
	headers1 := []string{"Server", "X-Powered-By"}
	headers2 := []string{"X-AspNet-Version", "X-Generator"}

	option1 := servex.WithRemoveHeaders(headers1...)
	option2 := servex.WithRemoveHeaders(headers2...)
	options := servex.Options{}
	option1(&options)
	option2(&options)

	expected := []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"}
	if !reflect.DeepEqual(options.HeadersToRemove, expected) {
		t.Errorf("expected headers to remove to be %v, got %v", expected, options.HeadersToRemove)
	}
}

// TestSecurityPathsMultiple tests whether multiple calls to security path options append paths correctly.
func TestSecurityPathsMultiple(t *testing.T) {
	excludePaths1 := []string{"/api/*", "/health"}
	excludePaths2 := []string{"/metrics", "/debug/*"}
	includePaths1 := []string{"/app/*", "/secure/*"}
	includePaths2 := []string{"/admin/*"}

	option1 := servex.WithSecurityExcludePaths(excludePaths1...)
	option2 := servex.WithSecurityExcludePaths(excludePaths2...)
	option3 := servex.WithSecurityIncludePaths(includePaths1...)
	option4 := servex.WithSecurityIncludePaths(includePaths2...)

	options := servex.Options{}
	option1(&options)
	option2(&options)
	option3(&options)
	option4(&options)

	expectedExclude := []string{"/api/*", "/health", "/metrics", "/debug/*"}
	expectedInclude := []string{"/app/*", "/secure/*", "/admin/*"}

	if !reflect.DeepEqual(options.Security.ExcludePaths, expectedExclude) {
		t.Errorf("expected exclude paths to be %v, got %v", expectedExclude, options.Security.ExcludePaths)
	}
	if !reflect.DeepEqual(options.Security.IncludePaths, expectedInclude) {
		t.Errorf("expected include paths to be %v, got %v", expectedInclude, options.Security.IncludePaths)
	}
}

// TestMultipleSecurityOptions tests whether multiple security options work together correctly.
func TestMultipleSecurityOptions(t *testing.T) {
	options := servex.Options{}

	// Apply multiple security options
	servex.WithSecurityHeaders()(&options)
	servex.WithContentSecurityPolicy("default-src 'self'")(&options)
	servex.WithHSTSHeader(31536000, true, true)(&options)
	servex.WithSecurityExcludePaths("/api/*", "/health")(&options)
	servex.WithCustomHeaders(map[string]string{
		"X-API-Version": "v1.0",
	})(&options)
	servex.WithRemoveHeaders("Server", "X-Powered-By")(&options)

	// Verify security is enabled
	if !options.Security.Enabled {
		t.Errorf("expected security to be enabled, got false")
	}

	// Verify CSP was set (should override the basic one)
	if options.Security.ContentSecurityPolicy != "default-src 'self'" {
		t.Errorf("expected CSP to be 'default-src 'self'', got %q", options.Security.ContentSecurityPolicy)
	}

	// Verify HSTS was set
	expectedHSTS := "max-age=31536000; includeSubDomains; preload"
	if options.Security.StrictTransportSecurity != expectedHSTS {
		t.Errorf("expected HSTS to be %q, got %q", expectedHSTS, options.Security.StrictTransportSecurity)
	}

	// Verify basic security headers are still there
	if options.Security.XContentTypeOptions != "nosniff" {
		t.Errorf("expected X-Content-Type-Options to be 'nosniff', got %q", options.Security.XContentTypeOptions)
	}

	// Verify paths
	expectedExclude := []string{"/api/*", "/health"}
	if !reflect.DeepEqual(options.Security.ExcludePaths, expectedExclude) {
		t.Errorf("expected exclude paths to be %v, got %v", expectedExclude, options.Security.ExcludePaths)
	}

	// Verify custom headers
	expectedHeaders := map[string]string{"X-API-Version": "v1.0"}
	if !reflect.DeepEqual(options.CustomHeaders, expectedHeaders) {
		t.Errorf("expected custom headers to be %v, got %v", expectedHeaders, options.CustomHeaders)
	}

	// Verify headers to remove
	expectedRemove := []string{"Server", "X-Powered-By"}
	if !reflect.DeepEqual(options.HeadersToRemove, expectedRemove) {
		t.Errorf("expected headers to remove to be %v, got %v", expectedRemove, options.HeadersToRemove)
	}
}

// TestSecurityConfigOverride tests whether individual security options override SecurityConfig.
func TestSecurityConfigOverride(t *testing.T) {
	// Start with a full security config
	securityConfig := servex.SecurityConfig{
		Enabled:                 true,
		ContentSecurityPolicy:   "default-src 'none'",
		XContentTypeOptions:     "nosniff",
		XFrameOptions:           "SAMEORIGIN",
		StrictTransportSecurity: "max-age=86400",
	}

	options := servex.Options{}
	servex.WithSecurityConfig(securityConfig)(&options)

	// Override specific values
	servex.WithContentSecurityPolicy("default-src 'self'")(&options)
	servex.WithHSTSHeader(31536000, true, false)(&options)

	// Verify overrides took effect
	if options.Security.ContentSecurityPolicy != "default-src 'self'" {
		t.Errorf("expected CSP to be overridden to 'default-src 'self'', got %q", options.Security.ContentSecurityPolicy)
	}

	expectedHSTS := "max-age=31536000; includeSubDomains"
	if options.Security.StrictTransportSecurity != expectedHSTS {
		t.Errorf("expected HSTS to be overridden to %q, got %q", expectedHSTS, options.Security.StrictTransportSecurity)
	}

	// Verify non-overridden values remain
	if options.Security.XContentTypeOptions != "nosniff" {
		t.Errorf("expected X-Content-Type-Options to remain 'nosniff', got %q", options.Security.XContentTypeOptions)
	}
	if options.Security.XFrameOptions != "SAMEORIGIN" {
		t.Errorf("expected X-Frame-Options to remain 'SAMEORIGIN', got %q", options.Security.XFrameOptions)
	}
}

// TestWithMaxRequestBodySize tests whether the WithMaxRequestBodySize option sets the maximum request body size correctly.
func TestWithMaxRequestBodySize(t *testing.T) {
	tests := []struct {
		name           string
		size           int64
		expectedSize   int64
		expectedEnable bool
	}{
		{"1MB size", 1 << 20, 1 << 20, true},
		{"10MB size", 10 << 20, 10 << 20, true},
		{"100MB size", 100 << 20, 100 << 20, true},
		{"zero size", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option := servex.WithMaxRequestBodySize(tt.size)
			options := servex.Options{}
			option(&options)

			if options.MaxRequestBodySize != tt.expectedSize {
				t.Errorf("expected MaxRequestBodySize to be %d, got %d", tt.expectedSize, options.MaxRequestBodySize)
			}
			if options.EnableRequestSizeLimits != tt.expectedEnable {
				t.Errorf("expected EnableRequestSizeLimits to be %t, got %t", tt.expectedEnable, options.EnableRequestSizeLimits)
			}
		})
	}
}

// TestWithMaxJSONBodySize tests whether the WithMaxJSONBodySize option sets the maximum JSON body size correctly.
func TestWithMaxJSONBodySize(t *testing.T) {
	tests := []struct {
		name           string
		size           int64
		expectedSize   int64
		expectedEnable bool
	}{
		{"512KB size", 512 << 10, 512 << 10, true},
		{"1MB size", 1 << 20, 1 << 20, true},
		{"5MB size", 5 << 20, 5 << 20, true},
		{"zero size", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option := servex.WithMaxJSONBodySize(tt.size)
			options := servex.Options{}
			option(&options)

			if options.MaxJSONBodySize != tt.expectedSize {
				t.Errorf("expected MaxJSONBodySize to be %d, got %d", tt.expectedSize, options.MaxJSONBodySize)
			}
			if options.EnableRequestSizeLimits != tt.expectedEnable {
				t.Errorf("expected EnableRequestSizeLimits to be %t, got %t", tt.expectedEnable, options.EnableRequestSizeLimits)
			}
		})
	}
}

// TestWithMaxFileUploadSize tests whether the WithMaxFileUploadSize option sets the maximum file upload size correctly.
func TestWithMaxFileUploadSize(t *testing.T) {
	tests := []struct {
		name           string
		size           int64
		expectedSize   int64
		expectedEnable bool
	}{
		{"10MB size", 10 << 20, 10 << 20, true},
		{"100MB size", 100 << 20, 100 << 20, true},
		{"1GB size", 1 << 30, 1 << 30, true},
		{"zero size", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option := servex.WithMaxFileUploadSize(tt.size)
			options := servex.Options{}
			option(&options)

			if options.MaxFileUploadSize != tt.expectedSize {
				t.Errorf("expected MaxFileUploadSize to be %d, got %d", tt.expectedSize, options.MaxFileUploadSize)
			}
			if options.EnableRequestSizeLimits != tt.expectedEnable {
				t.Errorf("expected EnableRequestSizeLimits to be %t, got %t", tt.expectedEnable, options.EnableRequestSizeLimits)
			}
		})
	}
}

// TestWithMaxMultipartMemory tests whether the WithMaxMultipartMemory option sets the multipart memory limit correctly.
func TestWithMaxMultipartMemory(t *testing.T) {
	tests := []struct {
		name         string
		size         int64
		expectedSize int64
	}{
		{"5MB memory", 5 << 20, 5 << 20},
		{"10MB memory", 10 << 20, 10 << 20},
		{"32MB memory", 32 << 20, 32 << 20},
		{"zero size", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option := servex.WithMaxMultipartMemory(tt.size)
			options := servex.Options{}
			option(&options)

			if options.MaxMultipartMemory != tt.expectedSize {
				t.Errorf("expected MaxMultipartMemory to be %d, got %d", tt.expectedSize, options.MaxMultipartMemory)
			}
		})
	}
}

// TestWithEnableRequestSizeLimits tests whether the WithEnableRequestSizeLimits option enables/disables size limits correctly.
func TestWithEnableRequestSizeLimits(t *testing.T) {
	tests := []struct {
		name     string
		enable   bool
		expected bool
	}{
		{"enable limits", true, true},
		{"disable limits", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option := servex.WithEnableRequestSizeLimits(tt.enable)
			options := servex.Options{}
			option(&options)

			if options.EnableRequestSizeLimits != tt.expected {
				t.Errorf("expected EnableRequestSizeLimits to be %t, got %t", tt.expected, options.EnableRequestSizeLimits)
			}
		})
	}
}

// TestWithRequestSizeLimits tests whether the WithRequestSizeLimits option sets reasonable defaults.
func TestWithRequestSizeLimits(t *testing.T) {
	option := servex.WithRequestSizeLimits()
	options := servex.Options{}
	option(&options)

	if options.MaxRequestBodySize != 100<<20 {
		t.Errorf("expected MaxRequestBodySize to be %d, got %d", 100<<20, options.MaxRequestBodySize)
	}
	if options.MaxJSONBodySize != 1<<20 {
		t.Errorf("expected MaxJSONBodySize to be %d, got %d", 1<<20, options.MaxJSONBodySize)
	}
	if options.MaxFileUploadSize != 100<<20 {
		t.Errorf("expected MaxFileUploadSize to be %d, got %d", 100<<20, options.MaxFileUploadSize)
	}
	if options.MaxMultipartMemory != 10<<20 {
		t.Errorf("expected MaxMultipartMemory to be %d, got %d", 10<<20, options.MaxMultipartMemory)
	}
	if !options.EnableRequestSizeLimits {
		t.Errorf("expected EnableRequestSizeLimits to be true, got false")
	}
}

// TestWithStrictRequestSizeLimits tests whether the WithStrictRequestSizeLimits option sets strict security limits.
func TestWithStrictRequestSizeLimits(t *testing.T) {
	option := servex.WithStrictRequestSizeLimits()
	options := servex.Options{}
	option(&options)

	if options.MaxRequestBodySize != 10<<20 {
		t.Errorf("expected MaxRequestBodySize to be %d, got %d", 10<<20, options.MaxRequestBodySize)
	}
	if options.MaxJSONBodySize != 512<<10 {
		t.Errorf("expected MaxJSONBodySize to be %d, got %d", 512<<10, options.MaxJSONBodySize)
	}
	if options.MaxFileUploadSize != 10<<20 {
		t.Errorf("expected MaxFileUploadSize to be %d, got %d", 10<<20, options.MaxFileUploadSize)
	}
	if options.MaxMultipartMemory != 5<<20 {
		t.Errorf("expected MaxMultipartMemory to be %d, got %d", 5<<20, options.MaxMultipartMemory)
	}
	if !options.EnableRequestSizeLimits {
		t.Errorf("expected EnableRequestSizeLimits to be true, got false")
	}
}

// TestMultipleRequestSizeOptions tests that multiple request size options work together correctly.
func TestMultipleRequestSizeOptions(t *testing.T) {
	options := servex.Options{}

	// Apply multiple options
	servex.WithMaxRequestBodySize(50 << 20)(&options)
	servex.WithMaxJSONBodySize(2 << 20)(&options)
	servex.WithMaxFileUploadSize(200 << 20)(&options)
	servex.WithMaxMultipartMemory(20 << 20)(&options)
	servex.WithEnableRequestSizeLimits(true)(&options)

	// Verify all options are set correctly
	if options.MaxRequestBodySize != 50<<20 {
		t.Errorf("expected MaxRequestBodySize to be %d, got %d", 50<<20, options.MaxRequestBodySize)
	}
	if options.MaxJSONBodySize != 2<<20 {
		t.Errorf("expected MaxJSONBodySize to be %d, got %d", 2<<20, options.MaxJSONBodySize)
	}
	if options.MaxFileUploadSize != 200<<20 {
		t.Errorf("expected MaxFileUploadSize to be %d, got %d", 200<<20, options.MaxFileUploadSize)
	}
	if options.MaxMultipartMemory != 20<<20 {
		t.Errorf("expected MaxMultipartMemory to be %d, got %d", 20<<20, options.MaxMultipartMemory)
	}
	if !options.EnableRequestSizeLimits {
		t.Errorf("expected EnableRequestSizeLimits to be true, got false")
	}
}
