package servex_test

import (
	"context"
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
