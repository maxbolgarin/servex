package servex_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/maxbolgarin/lang"
	"github.com/maxbolgarin/servex/v2"
	"golang.org/x/crypto/bcrypt"
)

// MockOAuthProvider implements the OAuthProvider interface for testing.
type MockOAuthProvider struct {
	name     string
	authURL  string
	userInfo *servex.OAuthUserInfo
	err      error
}

func (m *MockOAuthProvider) Name() string { return m.name }
func (m *MockOAuthProvider) AuthURL(state string) string {
	return m.authURL + "?state=" + state
}
func (m *MockOAuthProvider) Exchange(_ context.Context, code string) (*servex.OAuthUserInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.userInfo, nil
}

func newTestAuthManagerWithOAuth(t *testing.T, providers ...servex.OAuthProvider) (*servex.AuthManager, *servex.MemoryAuthDatabase) {
	t.Helper()
	db := servex.NewMemoryAuthDatabase()
	stateKey := hex.EncodeToString(getRandomBytes(32))
	cfg := servex.AuthConfig{
		Enabled:              true,
		Database:             db,
		JWTAccessSecret:      hex.EncodeToString(getRandomBytes(32)),
		JWTRefreshSecret:     hex.EncodeToString(getRandomBytes(32)),
		AccessTokenDuration:  5 * time.Minute,
		RefreshTokenDuration: 10 * time.Minute,
		IssuerNameInJWT:      "test-issuer",
		RolesOnRegister:      []servex.UserRole{"user"},
		OAuth: servex.OAuthConfig{
			Enabled:         true,
			Providers:       providers,
			AutoLinkByEmail: true,
			StateSigningKey: stateKey,
		},
	}
	am, err := servex.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth manager with OAuth: %v", err)
	}
	return am, db
}

// performOAuthRedirect performs a redirect request and returns the state cookie and redirect location.
func performOAuthRedirect(t *testing.T, am *servex.AuthManager, providerName string) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/"+providerName, nil)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("Expected redirect (302), got %d. Body: %s", rr.Code, rr.Body.String())
	}

	// Find the state cookie
	var stateCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_servex_oauth_state" {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("Expected OAuth state cookie to be set")
	}

	return rr, stateCookie
}

func TestOAuthRedirectHandler(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
	}

	am, _ := newTestAuthManagerWithOAuth(t, provider)

	rr, stateCookie := performOAuthRedirect(t, am, "testprovider")

	// Verify redirect location contains provider auth URL
	location := rr.Header().Get("Location")
	if !strings.HasPrefix(location, "https://provider.example.com/auth?state=") {
		t.Fatalf("Expected redirect to provider auth URL, got: %s", location)
	}

	// Verify the state cookie contains state:mac format
	parts := strings.SplitN(stateCookie.Value, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("Expected state cookie in state:mac format, got: %s", stateCookie.Value)
	}

	// Verify the state in the cookie matches the state in the redirect URL
	state := parts[0]
	if !strings.Contains(location, "state="+state) {
		t.Fatalf("State in cookie does not match state in redirect URL. Cookie state: %s, URL: %s", state, location)
	}

	// Cookie should be HttpOnly and SameSite=Lax
	if !stateCookie.HttpOnly {
		t.Fatal("Expected state cookie to be HttpOnly")
	}
}

func TestOAuthRedirectHandler_ProviderNotFound(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
	}

	am, _ := newTestAuthManagerWithOAuth(t, provider)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/unknown", nil)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("Expected 404, got %d", rr.Code)
	}
}

func TestOAuthCallbackHandler(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "provider-user-123",
			Email:      "user@example.com",
			Username:   "oauthuser",
			Verified:   true,
		},
	}

	am, _ := newTestAuthManagerWithOAuth(t, provider)

	// First: perform redirect to get the state cookie
	_, stateCookie := performOAuthRedirect(t, am, "testprovider")

	// Extract state from cookie
	parts := strings.SplitN(stateCookie.Value, ":", 2)
	state := parts[0]

	// Now: perform callback with the state and code
	callbackURL := "/api/v1/auth/oauth/testprovider/callback?code=auth-code-123&state=" + state
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	// Parse the response
	var resp servex.UserLoginResponse
	decodeJsonResponse(t, rr, &resp)

	if resp.AccessToken == "" {
		t.Fatal("Expected access token in response")
	}
	if resp.Username != "oauthuser" {
		t.Fatalf("Expected username 'oauthuser', got %q", resp.Username)
	}
	if resp.ID == "" {
		t.Fatal("Expected user ID in response")
	}

	// Verify refresh token cookie is set
	var refreshCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_servexrt" {
			refreshCookie = c
			break
		}
	}
	if refreshCookie == nil {
		t.Fatal("Expected refresh token cookie to be set")
	}
}

func TestOAuthCallbackAutoLink(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "provider-user-456",
			Email:      "existing@example.com",
			Username:   "provideruser",
			Verified:   true,
		},
	}

	am, db := newTestAuthManagerWithOAuth(t, provider)

	// Create an existing user with the same email (verified)
	ctx := context.Background()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	userID, err := db.NewUser(ctx, "existinguser", string(hashedPassword), "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	err = db.UpdateUser(ctx, userID, &servex.UserDiff{
		Email:         lang.Ptr("existing@example.com"),
		EmailVerified: lang.Ptr(true),
	})
	if err != nil {
		t.Fatalf("Failed to update test user email: %v", err)
	}

	// Perform redirect to get state cookie
	_, stateCookie := performOAuthRedirect(t, am, "testprovider")
	parts := strings.SplitN(stateCookie.Value, ":", 2)
	state := parts[0]

	// Perform callback
	callbackURL := "/api/v1/auth/oauth/testprovider/callback?code=auth-code-456&state=" + state
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var resp servex.UserLoginResponse
	decodeJsonResponse(t, rr, &resp)

	// Should auto-link and log in as the existing user
	if resp.ID != userID {
		t.Fatalf("Expected existing user ID %q, got %q", userID, resp.ID)
	}
	if resp.Username != "existinguser" {
		t.Fatalf("Expected username 'existinguser', got %q", resp.Username)
	}

	// Verify the OAuth provider was linked to the existing user
	user, _, _ := db.FindByID(ctx, userID)
	if len(user.OAuthProviders) != 1 {
		t.Fatalf("Expected 1 OAuth provider, got %d", len(user.OAuthProviders))
	}
	if user.OAuthProviders[0].Provider != "testprovider" {
		t.Fatalf("Expected provider 'testprovider', got %q", user.OAuthProviders[0].Provider)
	}
}

func TestOAuthCallbackAutoLinkRefusedUnverified(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "provider-user-789",
			Email:      "unverified@example.com",
			Username:   "provideruser",
			Verified:   true,
		},
	}

	am, db := newTestAuthManagerWithOAuth(t, provider)

	// Create an existing user with the same email but NOT verified
	ctx := context.Background()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	userID, err := db.NewUser(ctx, "unverifieduser", string(hashedPassword), "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	err = db.UpdateUser(ctx, userID, &servex.UserDiff{
		Email:         lang.Ptr("unverified@example.com"),
		EmailVerified: lang.Ptr(false),
	})
	if err != nil {
		t.Fatalf("Failed to update test user email: %v", err)
	}

	// Perform redirect to get state cookie
	_, stateCookie := performOAuthRedirect(t, am, "testprovider")
	parts := strings.SplitN(stateCookie.Value, ":", 2)
	state := parts[0]

	// Perform callback
	callbackURL := "/api/v1/auth/oauth/testprovider/callback?code=auth-code-789&state=" + state
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("Expected 409, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	// Verify no OAuth provider was linked
	user, _, _ := db.FindByID(ctx, userID)
	if len(user.OAuthProviders) != 0 {
		t.Fatalf("Expected 0 OAuth providers, got %d", len(user.OAuthProviders))
	}
}

func TestOAuthStateHMACValidation(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "provider-user-999",
			Email:      "hacker@example.com",
			Username:   "hacker",
			Verified:   true,
		},
	}

	am, _ := newTestAuthManagerWithOAuth(t, provider)

	// Perform redirect to get a valid state cookie
	_, stateCookie := performOAuthRedirect(t, am, "testprovider")
	parts := strings.SplitN(stateCookie.Value, ":", 2)
	state := parts[0]

	// Tamper with the state: change the HMAC
	tamperedCookie := &http.Cookie{
		Name:  "_servex_oauth_state",
		Value: state + ":deadbeef0000000000000000000000000000000000000000000000000000dead",
	}

	callbackURL := "/api/v1/auth/oauth/testprovider/callback?code=auth-code-999&state=" + state
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(tamperedCookie)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for tampered HMAC, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	// Also test: mismatched state param vs cookie
	_, stateCookie2 := performOAuthRedirect(t, am, "testprovider")

	callbackURL2 := "/api/v1/auth/oauth/testprovider/callback?code=auth-code-999&state=wrong-state-value"
	req2 := httptest.NewRequest(http.MethodGet, callbackURL2, nil)
	req2.AddCookie(stateCookie2)
	rr2 := httptest.NewRecorder()

	router2 := mux.NewRouter()
	am.RegisterRoutes(router2)
	router2.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for mismatched state, got %d. Body: %s", rr2.Code, rr2.Body.String())
	}
}

func TestOAuthLinkHandler(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "provider-link-123",
			Email:      "link@example.com",
			Username:   "linkuser",
			Verified:   true,
		},
	}

	am, db := newTestAuthManagerWithOAuth(t, provider)

	// Create an authenticated user
	ctx := context.Background()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	userID, err := db.NewUser(ctx, "linkuser", string(hashedPassword), "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create a request with auth context
	body := `{"code": "link-code-123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/testprovider/link", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// We need to add the user context value manually since we bypass WithAuth middleware
	req = req.WithContext(context.WithValue(req.Context(), servex.UserContextKey{}, userID))

	rr := httptest.NewRecorder()

	// Use mux router to set path variables
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/auth/oauth/{provider}/link", am.OAuthLinkHandler).Methods(http.MethodPost)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	// Verify the provider was linked
	user, _, _ := db.FindByID(ctx, userID)
	if len(user.OAuthProviders) != 1 {
		t.Fatalf("Expected 1 OAuth provider, got %d", len(user.OAuthProviders))
	}
	if user.OAuthProviders[0].Provider != "testprovider" {
		t.Fatalf("Expected provider 'testprovider', got %q", user.OAuthProviders[0].Provider)
	}
	if user.OAuthProviders[0].ProviderID != "provider-link-123" {
		t.Fatalf("Expected provider ID 'provider-link-123', got %q", user.OAuthProviders[0].ProviderID)
	}
}

func TestOAuthLinkHandler_AlreadyLinked(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "provider-link-dup",
			Email:      "dup@example.com",
			Username:   "dupuser",
			Verified:   true,
		},
	}

	am, db := newTestAuthManagerWithOAuth(t, provider)

	// Create user with existing link
	ctx := context.Background()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	userID, _ := db.NewUser(ctx, "dupuser", string(hashedPassword), "user")
	_ = db.UpdateUser(ctx, userID, &servex.UserDiff{
		OAuthProviders: &[]servex.OAuthLink{{Provider: "testprovider", ProviderID: "old-id"}},
	})

	body := `{"code": "link-code-dup"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/testprovider/link", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), servex.UserContextKey{}, userID))

	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/auth/oauth/{provider}/link", am.OAuthLinkHandler).Methods(http.MethodPost)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("Expected 409, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

func TestOAuthUnlinkHandler(t *testing.T) {
	am, db := newTestAuthManagerWithOAuth(t)

	// Create user with an OAuth link
	ctx := context.Background()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	userID, err := db.NewUser(ctx, "unlinkuser", string(hashedPassword), "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	_ = db.UpdateUser(ctx, userID, &servex.UserDiff{
		OAuthProviders: &[]servex.OAuthLink{
			{Provider: "google", ProviderID: "google-123", Email: "user@gmail.com"},
			{Provider: "github", ProviderID: "github-456", Email: "user@github.com"},
		},
	})

	// Unlink google
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/oauth/google/link", nil)
	req = req.WithContext(context.WithValue(req.Context(), servex.UserContextKey{}, userID))
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/auth/oauth/{provider}/link", am.OAuthUnlinkHandler).Methods(http.MethodDelete)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	// Verify only github remains
	user, _, _ := db.FindByID(ctx, userID)
	if len(user.OAuthProviders) != 1 {
		t.Fatalf("Expected 1 OAuth provider after unlink, got %d", len(user.OAuthProviders))
	}
	if user.OAuthProviders[0].Provider != "github" {
		t.Fatalf("Expected remaining provider 'github', got %q", user.OAuthProviders[0].Provider)
	}
}

func TestOAuthUnlinkHandler_NotLinked(t *testing.T) {
	am, db := newTestAuthManagerWithOAuth(t)

	// Create user with no OAuth links
	ctx := context.Background()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	userID, _ := db.NewUser(ctx, "nolinkuser", string(hashedPassword), "user")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/oauth/google/link", nil)
	req = req.WithContext(context.WithValue(req.Context(), servex.UserContextKey{}, userID))
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/auth/oauth/{provider}/link", am.OAuthUnlinkHandler).Methods(http.MethodDelete)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("Expected 404, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

func TestOAuthCallbackExistingOAuthUser(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "returning-user-id",
			Email:      "returning@example.com",
			Username:   "returninguser",
			Verified:   true,
		},
	}

	am, db := newTestAuthManagerWithOAuth(t, provider)

	// Create an existing user already linked via OAuth
	ctx := context.Background()
	userID, err := db.NewUser(ctx, "returninguser", "", "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	_ = db.UpdateUser(ctx, userID, &servex.UserDiff{
		OAuthProviders: &[]servex.OAuthLink{
			{Provider: "testprovider", ProviderID: "returning-user-id", Email: "returning@example.com"},
		},
	})

	// Perform redirect and callback
	_, stateCookie := performOAuthRedirect(t, am, "testprovider")
	parts := strings.SplitN(stateCookie.Value, ":", 2)
	state := parts[0]

	callbackURL := "/api/v1/auth/oauth/testprovider/callback?code=return-code&state=" + state
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var resp servex.UserLoginResponse
	decodeJsonResponse(t, rr, &resp)

	if resp.ID != userID {
		t.Fatalf("Expected existing user ID %q, got %q", userID, resp.ID)
	}
	if resp.AccessToken == "" {
		t.Fatal("Expected access token in response")
	}
}

func TestOAuthCallbackNewUserNoEmail(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "no-email-user",
			Username:   "noemailuser",
			Verified:   false,
		},
	}

	am, db := newTestAuthManagerWithOAuth(t, provider)

	_, stateCookie := performOAuthRedirect(t, am, "testprovider")
	parts := strings.SplitN(stateCookie.Value, ":", 2)
	state := parts[0]

	callbackURL := "/api/v1/auth/oauth/testprovider/callback?code=no-email-code&state=" + state
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var resp servex.UserLoginResponse
	decodeJsonResponse(t, rr, &resp)

	if resp.Username != "noemailuser" {
		t.Fatalf("Expected username 'noemailuser', got %q", resp.Username)
	}

	// Verify user was created with OAuth link
	user, exists, _ := db.FindByID(context.Background(), resp.ID)
	if !exists {
		t.Fatal("Expected user to exist in database")
	}
	if len(user.OAuthProviders) != 1 {
		t.Fatalf("Expected 1 OAuth provider, got %d", len(user.OAuthProviders))
	}
}

func TestOAuthValidation(t *testing.T) {
	tests := []struct {
		name   string
		cfg    servex.AuthConfig
		errMsg string
	}{
		{
			name: "OAuth with MockAuthDatabase fails (no OAuthAuthDatabase)",
			cfg: servex.AuthConfig{
				Enabled:          true,
				Database:         NewMockAuthDatabase(),
				JWTAccessSecret:  hex.EncodeToString(getRandomBytes(32)),
				JWTRefreshSecret: hex.EncodeToString(getRandomBytes(32)),
				OAuth: servex.OAuthConfig{
					Enabled: true,
				},
			},
			errMsg: "OAuth auth requires AuthDatabase to implement OAuthAuthDatabase",
		},
		{
			name: "OAuth with MemoryAuthDatabase succeeds",
			cfg: servex.AuthConfig{
				Enabled:          true,
				Database:         servex.NewMemoryAuthDatabase(),
				JWTAccessSecret:  hex.EncodeToString(getRandomBytes(32)),
				JWTRefreshSecret: hex.EncodeToString(getRandomBytes(32)),
				OAuth: servex.OAuthConfig{
					Enabled: true,
				},
			},
			errMsg: "",
		},
		{
			name: "OAuth with invalid state signing key",
			cfg: servex.AuthConfig{
				Enabled:          true,
				Database:         servex.NewMemoryAuthDatabase(),
				JWTAccessSecret:  hex.EncodeToString(getRandomBytes(32)),
				JWTRefreshSecret: hex.EncodeToString(getRandomBytes(32)),
				OAuth: servex.OAuthConfig{
					Enabled:         true,
					StateSigningKey: "not-valid-hex!!",
				},
			},
			errMsg: "decode OAuth state signing key",
		},
		{
			name: "OAuth with short state signing key",
			cfg: servex.AuthConfig{
				Enabled:          true,
				Database:         servex.NewMemoryAuthDatabase(),
				JWTAccessSecret:  hex.EncodeToString(getRandomBytes(32)),
				JWTRefreshSecret: hex.EncodeToString(getRandomBytes(32)),
				OAuth: servex.OAuthConfig{
					Enabled:         true,
					StateSigningKey: hex.EncodeToString(getRandomBytes(16)), // Only 16 bytes
				},
			},
			errMsg: "OAuth state signing key must be at least 32 bytes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := servex.NewAuthManager(tc.cfg)
			if tc.errMsg == "" {
				if err != nil {
					t.Fatalf("Expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Expected error containing %q, got nil", tc.errMsg)
				}
				if !strings.Contains(err.Error(), tc.errMsg) {
					t.Fatalf("Expected error containing %q, got: %v", tc.errMsg, err)
				}
			}
		})
	}
}

func TestOAuthCallbackExchangeError(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
		err:     errMockEmail, // reuse a mock error
	}

	am, _ := newTestAuthManagerWithOAuth(t, provider)

	_, stateCookie := performOAuthRedirect(t, am, "testprovider")
	parts := strings.SplitN(stateCookie.Value, ":", 2)
	state := parts[0]

	callbackURL := "/api/v1/auth/oauth/testprovider/callback?code=bad-code&state=" + state
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

// decodeJsonResponseGeneric is a helper that decodes JSON into a map.
func decodeJsonResponseMap(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	bodyBytes, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		t.Fatalf("Failed to decode JSON response: %v\nBody: %s", err, string(bodyBytes))
	}
	return result
}

// TestOAuthAutoLinkCollision is a cross-feature integration test that verifies
// multiple OAuth providers can auto-link to the same existing user by email.
func TestOAuthAutoLinkCollision(t *testing.T) {
	sharedEmail := "shared@example.com"

	googleProvider := &MockOAuthProvider{
		name:    "google",
		authURL: "https://accounts.google.com/auth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "google-user-777",
			Email:      sharedEmail,
			Username:   "googleuser",
			Verified:   true,
		},
	}

	githubProvider := &MockOAuthProvider{
		name:    "github",
		authURL: "https://github.com/login/oauth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "github-user-888",
			Email:      sharedEmail,
			Username:   "githubuser",
			Verified:   true,
		},
	}

	db := servex.NewMemoryAuthDatabase()
	stateKey := hex.EncodeToString(getRandomBytes(32))
	cfg := servex.AuthConfig{
		Enabled:              true,
		Database:             db,
		JWTAccessSecret:      hex.EncodeToString(getRandomBytes(32)),
		JWTRefreshSecret:     hex.EncodeToString(getRandomBytes(32)),
		AccessTokenDuration:  5 * time.Minute,
		RefreshTokenDuration: 10 * time.Minute,
		IssuerNameInJWT:      "test-issuer",
		RolesOnRegister:      []servex.UserRole{"user"},
		OAuth: servex.OAuthConfig{
			Enabled:         true,
			Providers:       []servex.OAuthProvider{googleProvider, githubProvider},
			AutoLinkByEmail: true,
			StateSigningKey: stateKey,
		},
	}
	am, err := servex.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	router := mux.NewRouter()
	am.RegisterRoutes(router)

	// Step 1: Create a user with verified email
	ctx := context.Background()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	userID, err := db.NewUser(ctx, "localuser", string(hashedPassword), "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	err = db.UpdateUser(ctx, userID, &servex.UserDiff{
		Email:         lang.Ptr(sharedEmail),
		EmailVerified: lang.Ptr(true),
	})
	if err != nil {
		t.Fatalf("Failed to update user email: %v", err)
	}

	// Step 2: OAuth login with Google provider returning same email — should auto-link
	_, stateCookie1 := performOAuthRedirect(t, am, "google")
	parts1 := strings.SplitN(stateCookie1.Value, ":", 2)
	state1 := parts1[0]

	callbackURL1 := "/api/v1/auth/oauth/google/callback?code=google-code&state=" + state1
	req1 := httptest.NewRequest(http.MethodGet, callbackURL1, nil)
	req1.AddCookie(stateCookie1)
	rr1 := httptest.NewRecorder()
	router.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Fatalf("Google OAuth: expected 200, got %d; body: %s", rr1.Code, rr1.Body.String())
	}

	var googleResp servex.UserLoginResponse
	decodeJsonResponse(t, rr1, &googleResp)
	if googleResp.ID != userID {
		t.Fatalf("Google OAuth: expected auto-link to existing user %q, got %q", userID, googleResp.ID)
	}
	if googleResp.Username != "localuser" {
		t.Fatalf("Google OAuth: expected username 'localuser', got %q", googleResp.Username)
	}

	// Verify Google provider was linked
	user, _, _ := db.FindByID(ctx, userID)
	if len(user.OAuthProviders) != 1 {
		t.Fatalf("After Google: expected 1 OAuth provider, got %d", len(user.OAuthProviders))
	}
	if user.OAuthProviders[0].Provider != "google" {
		t.Fatalf("After Google: expected provider 'google', got %q", user.OAuthProviders[0].Provider)
	}

	// Step 3: OAuth login with GitHub provider returning same email — should also auto-link to same user
	_, stateCookie2 := performOAuthRedirect(t, am, "github")
	parts2 := strings.SplitN(stateCookie2.Value, ":", 2)
	state2 := parts2[0]

	callbackURL2 := "/api/v1/auth/oauth/github/callback?code=github-code&state=" + state2
	req2 := httptest.NewRequest(http.MethodGet, callbackURL2, nil)
	req2.AddCookie(stateCookie2)
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("GitHub OAuth: expected 200, got %d; body: %s", rr2.Code, rr2.Body.String())
	}

	var githubResp servex.UserLoginResponse
	decodeJsonResponse(t, rr2, &githubResp)
	if githubResp.ID != userID {
		t.Fatalf("GitHub OAuth: expected auto-link to same user %q, got %q", userID, githubResp.ID)
	}
	if githubResp.Username != "localuser" {
		t.Fatalf("GitHub OAuth: expected username 'localuser', got %q", githubResp.Username)
	}

	// Step 4: Verify user now has both OAuth providers linked
	user, _, _ = db.FindByID(ctx, userID)
	if len(user.OAuthProviders) != 2 {
		t.Fatalf("After both: expected 2 OAuth providers, got %d", len(user.OAuthProviders))
	}

	providerNames := make(map[string]bool)
	for _, link := range user.OAuthProviders {
		providerNames[link.Provider] = true
	}
	if !providerNames["google"] {
		t.Error("Expected 'google' provider to be linked")
	}
	if !providerNames["github"] {
		t.Error("Expected 'github' provider to be linked")
	}
}

func newTestAuthManagerWithOAuthRedirect(t *testing.T, frontendURL string, providers ...servex.OAuthProvider) (*servex.AuthManager, *servex.MemoryAuthDatabase) {
	t.Helper()
	db := servex.NewMemoryAuthDatabase()
	stateKey := hex.EncodeToString(getRandomBytes(32))
	cfg := servex.AuthConfig{
		Enabled:              true,
		Database:             db,
		JWTAccessSecret:      hex.EncodeToString(getRandomBytes(32)),
		JWTRefreshSecret:     hex.EncodeToString(getRandomBytes(32)),
		AccessTokenDuration:  5 * time.Minute,
		RefreshTokenDuration: 10 * time.Minute,
		IssuerNameInJWT:      "test-issuer",
		RolesOnRegister:      []servex.UserRole{"user"},
		OAuth: servex.OAuthConfig{
			Enabled:             true,
			Providers:           providers,
			AutoLinkByEmail:     true,
			StateSigningKey:     stateKey,
			FrontendCallbackURL: frontendURL,
		},
	}
	am, err := servex.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth manager with OAuth redirect: %v", err)
	}
	return am, db
}

func TestOAuthCallbackRedirectSuccess(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "provider-user-redirect",
			Email:      "redirect@example.com",
			Username:   "redirectuser",
			Verified:   true,
		},
	}

	am, _ := newTestAuthManagerWithOAuthRedirect(t, "https://myapp.com/auth/callback", provider)

	_, stateCookie := performOAuthRedirect(t, am, "testprovider")
	parts := strings.SplitN(stateCookie.Value, ":", 2)
	state := parts[0]

	callbackURL := "/api/v1/auth/oauth/testprovider/callback?code=auth-code-123&state=" + state
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("Expected 302 redirect, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	location := rr.Header().Get("Location")
	if !strings.HasPrefix(location, "https://myapp.com/auth/callback?") {
		t.Fatalf("Expected redirect to frontend callback URL, got: %s", location)
	}
	if !strings.Contains(location, "access_token=") {
		t.Fatalf("Expected access_token in redirect URL, got: %s", location)
	}

	// Verify refresh token cookie is still set
	var refreshCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_servexrt" {
			refreshCookie = c
			break
		}
	}
	if refreshCookie == nil {
		t.Fatal("Expected refresh token cookie to be set on redirect")
	}
}

func TestOAuthCallbackRedirectStateMismatch(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
	}

	am, _ := newTestAuthManagerWithOAuthRedirect(t, "https://myapp.com/auth/callback", provider)

	_, stateCookie := performOAuthRedirect(t, am, "testprovider")

	// Use wrong state
	callbackURL := "/api/v1/auth/oauth/testprovider/callback?code=auth-code&state=wrong-state"
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("Expected 302 redirect, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "error=state_mismatch") {
		t.Fatalf("Expected error=state_mismatch in redirect URL, got: %s", location)
	}
}

func TestOAuthCallbackRedirectExchangeError(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
		err:     errMockEmail,
	}

	am, _ := newTestAuthManagerWithOAuthRedirect(t, "https://myapp.com/auth/callback", provider)

	_, stateCookie := performOAuthRedirect(t, am, "testprovider")
	parts := strings.SplitN(stateCookie.Value, ":", 2)
	state := parts[0]

	callbackURL := "/api/v1/auth/oauth/testprovider/callback?code=bad-code&state=" + state
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("Expected 302 redirect, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "error=auth_failed") {
		t.Fatalf("Expected error=auth_failed in redirect URL, got: %s", location)
	}
}

func TestOAuthCallbackRedirect2FA(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "provider-user-2fa",
			Email:      "2fa@example.com",
			Username:   "2fauser",
			Verified:   true,
		},
	}

	db := servex.NewMemoryAuthDatabase()
	stateKey := hex.EncodeToString(getRandomBytes(32))
	encKey := hex.EncodeToString(getRandomBytes(32))
	cfg := servex.AuthConfig{
		Enabled:              true,
		Database:             db,
		JWTAccessSecret:      hex.EncodeToString(getRandomBytes(32)),
		JWTRefreshSecret:     hex.EncodeToString(getRandomBytes(32)),
		AccessTokenDuration:  5 * time.Minute,
		RefreshTokenDuration: 10 * time.Minute,
		IssuerNameInJWT:      "test-issuer",
		RolesOnRegister:      []servex.UserRole{"user"},
		OAuth: servex.OAuthConfig{
			Enabled:             true,
			Providers:           []servex.OAuthProvider{provider},
			AutoLinkByEmail:     true,
			StateSigningKey:     stateKey,
			FrontendCallbackURL: "https://myapp.com/auth/callback",
		},
		TwoFactor: servex.TwoFactorConfig{
			Enabled:       true,
			EncryptionKey: encKey,
			Issuer:        "test",
		},
	}
	am, err := servex.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Create user with OAuth link and 2FA enabled
	ctx := context.Background()
	userID, err := db.NewUser(ctx, "2fauser", "", "user")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	err = db.UpdateUser(ctx, userID, &servex.UserDiff{
		OAuthProviders:   &[]servex.OAuthLink{{Provider: "testprovider", ProviderID: "provider-user-2fa"}},
		TwoFactorEnabled: lang.Ptr(true),
		TwoFactorSecret:  lang.Ptr("test-secret"),
	})
	if err != nil {
		t.Fatalf("Failed to update user: %v", err)
	}

	_, stateCookie := performOAuthRedirect(t, am, "testprovider")
	parts := strings.SplitN(stateCookie.Value, ":", 2)
	state := parts[0]

	callbackURL := "/api/v1/auth/oauth/testprovider/callback?code=auth-code&state=" + state
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("Expected 302 redirect, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "requires_2fa=true") {
		t.Fatalf("Expected requires_2fa=true in redirect URL, got: %s", location)
	}

	// Verify 2FA pending cookie is set
	var pendingCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_servex_2fa_pending" {
			pendingCookie = c
			break
		}
	}
	if pendingCookie == nil {
		t.Fatal("Expected 2FA pending cookie to be set")
	}
}

func TestOAuthCallbackNoRedirectWithoutFrontendURL(t *testing.T) {
	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "provider-user-nofrontend",
			Email:      "nofrontend@example.com",
			Username:   "nofrontenduser",
			Verified:   true,
		},
	}

	// No FrontendCallbackURL — should return JSON
	am, _ := newTestAuthManagerWithOAuth(t, provider)

	_, stateCookie := performOAuthRedirect(t, am, "testprovider")
	parts := strings.SplitN(stateCookie.Value, ":", 2)
	state := parts[0]

	callbackURL := "/api/v1/auth/oauth/testprovider/callback?code=auth-code-123&state=" + state
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 (JSON response), got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var resp servex.UserLoginResponse
	decodeJsonResponse(t, rr, &resp)
	if resp.AccessToken == "" {
		t.Fatal("Expected access token in JSON response")
	}
}

// MockPKCEOAuthProvider implements PKCEOAuthProvider for testing.
type MockPKCEOAuthProvider struct {
	name         string
	authURL      string
	codeVerifier string
	userInfo     *servex.OAuthUserInfo
	err          error
}

func (m *MockPKCEOAuthProvider) Name() string { return m.name }
func (m *MockPKCEOAuthProvider) AuthURL(state string) string {
	url, _ := m.AuthURLWithPKCE(state)
	return url
}
func (m *MockPKCEOAuthProvider) Exchange(_ context.Context, _ string) (*servex.OAuthUserInfo, error) {
	return nil, fmt.Errorf("PKCE is required")
}
func (m *MockPKCEOAuthProvider) AuthURLWithPKCE(state string) (string, string) {
	m.codeVerifier = "test-code-verifier-" + state
	return m.authURL + "?state=" + state, m.codeVerifier
}
func (m *MockPKCEOAuthProvider) ExchangeWithPKCE(_ context.Context, code string, codeVerifier string) (*servex.OAuthUserInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	if codeVerifier == "" {
		return nil, fmt.Errorf("code_verifier is required")
	}
	return m.userInfo, nil
}

func TestOAuthPKCERedirectHandler(t *testing.T) {
	provider := &MockPKCEOAuthProvider{
		name:    "pkceprovider",
		authURL: "https://provider.example.com/auth",
	}

	am, _ := newTestAuthManagerWithOAuth(t, provider)

	rr, stateCookie := performOAuthRedirect(t, am, "pkceprovider")

	// Verify redirect location contains provider auth URL
	location := rr.Header().Get("Location")
	if !strings.HasPrefix(location, "https://provider.example.com/auth?state=") {
		t.Fatalf("Expected redirect to provider auth URL, got: %s", location)
	}

	// PKCE provider should store state:mac:codeVerifier in cookie (3 parts)
	parts := strings.SplitN(stateCookie.Value, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("Expected state cookie in state:mac:codeVerifier format (3 parts), got %d parts: %s", len(parts), stateCookie.Value)
	}

	state := parts[0]
	codeVerifier := parts[2]

	if codeVerifier == "" {
		t.Fatal("Expected code_verifier in cookie")
	}

	// Verify the state in the cookie matches the state in the redirect URL
	if !strings.Contains(location, "state="+state) {
		t.Fatalf("State in cookie does not match state in redirect URL. Cookie state: %s, URL: %s", state, location)
	}
}

func TestOAuthPKCECallbackHandler(t *testing.T) {
	provider := &MockPKCEOAuthProvider{
		name:    "pkceprovider",
		authURL: "https://provider.example.com/auth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "pkce-user-123",
			Email:      "pkce@example.com",
			Username:   "pkceuser",
			Verified:   true,
		},
	}

	am, _ := newTestAuthManagerWithOAuth(t, provider)

	// Redirect to get the state cookie with code_verifier
	_, stateCookie := performOAuthRedirect(t, am, "pkceprovider")

	// Extract state from cookie
	parts := strings.SplitN(stateCookie.Value, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("Expected 3 parts in PKCE cookie, got %d", len(parts))
	}
	state := parts[0]

	// Perform callback
	callbackURL := "/api/v1/auth/oauth/pkceprovider/callback?code=auth-code-123&state=" + state
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	am.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var resp servex.UserLoginResponse
	decodeJsonResponse(t, rr, &resp)

	if resp.AccessToken == "" {
		t.Fatal("Expected access token in response")
	}
	if resp.Username != "pkceuser" {
		t.Fatalf("Expected username 'pkceuser', got %q", resp.Username)
	}
}
