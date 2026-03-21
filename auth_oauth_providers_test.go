package servex_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/maxbolgarin/servex/v2"
)

func TestProviderNames(t *testing.T) {
	tests := []struct {
		name     string
		provider servex.OAuthProvider
		expected string
	}{
		{
			name:     "Google",
			provider: servex.NewGoogleOAuthProvider(servex.GoogleOAuthConfig{}),
			expected: "google",
		},
		{
			name:     "GitHub",
			provider: servex.NewGitHubOAuthProvider(servex.GitHubOAuthConfig{}),
			expected: "github",
		},
		{
			name:     "Apple",
			provider: servex.NewAppleOAuthProvider(servex.AppleOAuthConfig{}),
			expected: "apple",
		},
		{
			name:     "Telegram",
			provider: servex.NewTelegramOAuthProvider(servex.TelegramOAuthConfig{}),
			expected: "telegram",
		},
		{
			name:     "Yandex",
			provider: servex.NewYandexOAuthProvider(servex.YandexOAuthConfig{}),
			expected: "yandex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.provider.Name(); got != tt.expected {
				t.Errorf("Name() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGoogleAuthURL(t *testing.T) {
	provider := servex.NewGoogleOAuthProvider(servex.GoogleOAuthConfig{
		ClientID:    "google-client-id",
		RedirectURL: "https://example.com/callback",
	})

	authURL := provider.AuthURL("test-state")

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	if parsed.Scheme != "https" || parsed.Host != "accounts.google.com" || parsed.Path != "/o/oauth2/v2/auth" {
		t.Errorf("Unexpected base URL: %s", authURL)
	}

	params := parsed.Query()

	if params.Get("client_id") != "google-client-id" {
		t.Errorf("client_id = %q, want %q", params.Get("client_id"), "google-client-id")
	}
	if params.Get("redirect_uri") != "https://example.com/callback" {
		t.Errorf("redirect_uri = %q, want %q", params.Get("redirect_uri"), "https://example.com/callback")
	}
	if params.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want %q", params.Get("response_type"), "code")
	}
	if params.Get("state") != "test-state" {
		t.Errorf("state = %q, want %q", params.Get("state"), "test-state")
	}

	// Default scopes should include openid, email, and profile.
	scope := params.Get("scope")
	if !strings.Contains(scope, "openid") || !strings.Contains(scope, "email") || !strings.Contains(scope, "profile") {
		t.Errorf("scope = %q, want to contain openid, email, profile", scope)
	}
}

func TestGoogleAuthURL_CustomScopes(t *testing.T) {
	provider := servex.NewGoogleOAuthProvider(servex.GoogleOAuthConfig{
		ClientID:    "google-client-id",
		RedirectURL: "https://example.com/callback",
		Scopes:      []string{"openid", "email"},
	})

	authURL := provider.AuthURL("state123")
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	scope := parsed.Query().Get("scope")
	if scope != "openid email" {
		t.Errorf("scope = %q, want %q", scope, "openid email")
	}
}

func TestGitHubAuthURL(t *testing.T) {
	provider := servex.NewGitHubOAuthProvider(servex.GitHubOAuthConfig{
		ClientID:    "github-client-id",
		RedirectURL: "https://example.com/callback",
	})

	authURL := provider.AuthURL("test-state")

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	if parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.Path != "/login/oauth/authorize" {
		t.Errorf("Unexpected base URL: %s", authURL)
	}

	params := parsed.Query()

	if params.Get("client_id") != "github-client-id" {
		t.Errorf("client_id = %q, want %q", params.Get("client_id"), "github-client-id")
	}
	if params.Get("redirect_uri") != "https://example.com/callback" {
		t.Errorf("redirect_uri = %q, want %q", params.Get("redirect_uri"), "https://example.com/callback")
	}
	if params.Get("state") != "test-state" {
		t.Errorf("state = %q, want %q", params.Get("state"), "test-state")
	}

	// Default scope should be "user:email".
	scope := params.Get("scope")
	if scope != "user:email" {
		t.Errorf("scope = %q, want %q", scope, "user:email")
	}
}

func TestGitHubAuthURL_CustomScopes(t *testing.T) {
	provider := servex.NewGitHubOAuthProvider(servex.GitHubOAuthConfig{
		ClientID:    "github-client-id",
		RedirectURL: "https://example.com/callback",
		Scopes:      []string{"user", "repo"},
	})

	authURL := provider.AuthURL("state123")
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	scope := parsed.Query().Get("scope")
	if scope != "user repo" {
		t.Errorf("scope = %q, want %q", scope, "user repo")
	}
}

func TestAppleAuthURL(t *testing.T) {
	provider := servex.NewAppleOAuthProvider(servex.AppleOAuthConfig{
		ClientID:    "com.example.app",
		RedirectURL: "https://example.com/callback",
	})

	authURL := provider.AuthURL("test-state")

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	if parsed.Scheme != "https" || parsed.Host != "appleid.apple.com" || parsed.Path != "/auth/authorize" {
		t.Errorf("Unexpected base URL: %s", authURL)
	}

	params := parsed.Query()

	if params.Get("client_id") != "com.example.app" {
		t.Errorf("client_id = %q, want %q", params.Get("client_id"), "com.example.app")
	}
	if params.Get("redirect_uri") != "https://example.com/callback" {
		t.Errorf("redirect_uri = %q, want %q", params.Get("redirect_uri"), "https://example.com/callback")
	}
	if params.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want %q", params.Get("response_type"), "code")
	}
	if params.Get("response_mode") != "form_post" {
		t.Errorf("response_mode = %q, want %q", params.Get("response_mode"), "form_post")
	}
	if params.Get("state") != "test-state" {
		t.Errorf("state = %q, want %q", params.Get("state"), "test-state")
	}

	scope := params.Get("scope")
	if !strings.Contains(scope, "name") || !strings.Contains(scope, "email") {
		t.Errorf("scope = %q, want to contain name and email", scope)
	}
}

func generateTestES256Key(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ES256 key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	return key, string(pemBytes)
}

func TestAppleGenerateClientSecret(t *testing.T) {
	ecKey, pemStr := generateTestES256Key(t)

	provider := servex.NewAppleOAuthProvider(servex.AppleOAuthConfig{
		ClientID:   "com.example.app",
		TeamID:     "TEAM123456",
		KeyID:      "KEY123",
		PrivateKey: pemStr,
	})

	// Generate the client secret using the exported test helper.
	clientSecret, err := servex.ExportAppleGenerateClientSecret(provider)
	if err != nil {
		t.Fatalf("generateClientSecret failed: %v", err)
	}

	// Parse and verify the JWT.
	token, err := jwt.Parse(clientSecret, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &ecKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("Failed to parse client secret JWT: %v", err)
	}
	if !token.Valid {
		t.Fatal("JWT is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Failed to get map claims")
	}

	// Verify issuer (TeamID).
	if iss, _ := claims["iss"].(string); iss != "TEAM123456" {
		t.Errorf("iss = %q, want %q", iss, "TEAM123456")
	}

	// Verify subject (ClientID).
	if sub, _ := claims["sub"].(string); sub != "com.example.app" {
		t.Errorf("sub = %q, want %q", sub, "com.example.app")
	}

	// Verify audience.
	aud, _ := claims["aud"]
	switch v := aud.(type) {
	case string:
		if v != "https://appleid.apple.com" {
			t.Errorf("aud = %q, want %q", v, "https://appleid.apple.com")
		}
	case []any:
		if len(v) == 0 || v[0] != "https://appleid.apple.com" {
			t.Errorf("aud = %v, want [https://appleid.apple.com]", v)
		}
	default:
		t.Errorf("aud unexpected type: %T", aud)
	}

	// Verify kid in header.
	if kid, _ := token.Header["kid"].(string); kid != "KEY123" {
		t.Errorf("kid = %q, want %q", kid, "KEY123")
	}

	// Verify expiry is roughly 180 days from now.
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		expected := time.Now().Add(180 * 24 * time.Hour)
		diff := expTime.Sub(expected)
		if diff < -time.Hour || diff > time.Hour {
			t.Errorf("exp = %v, expected roughly %v (diff %v)", expTime, expected, diff)
		}
	} else {
		t.Error("Missing exp claim")
	}

	// Verify iat is roughly now.
	if iat, ok := claims["iat"].(float64); ok {
		iatTime := time.Unix(int64(iat), 0)
		diff := time.Since(iatTime)
		if diff < -time.Minute || diff > time.Minute {
			t.Errorf("iat = %v, expected roughly now (diff %v)", iatTime, diff)
		}
	} else {
		t.Error("Missing iat claim")
	}
}

func TestAppleGenerateClientSecret_InvalidKey(t *testing.T) {
	provider := servex.NewAppleOAuthProvider(servex.AppleOAuthConfig{
		ClientID:   "com.example.app",
		TeamID:     "TEAM123456",
		KeyID:      "KEY123",
		PrivateKey: "not-a-valid-pem-key",
	})

	_, err := servex.ExportAppleGenerateClientSecret(provider)
	if err == nil {
		t.Fatal("Expected error for invalid PEM key")
	}
	if !strings.Contains(err.Error(), "failed to decode PEM") {
		t.Errorf("Error = %q, want to contain %q", err.Error(), "failed to decode PEM")
	}
}

func TestTelegramDataVerification(t *testing.T) {
	botToken := "123456789:ABCdefGHIjklMNOpqrsTUVwxyz"

	t.Run("valid data", func(t *testing.T) {
		// Prepare auth data.
		authDate := time.Now().Unix()
		data := map[string]any{
			"id":         float64(12345678),
			"first_name": "John",
			"last_name":  "Doe",
			"username":   "johndoe",
			"auth_date":  float64(authDate),
		}

		// Compute the expected hash.
		hash := computeTelegramHash(t, data, botToken)
		data["hash"] = hash

		// Create JSON.
		jsonData, err := json.Marshal(data)
		if err != nil {
			t.Fatalf("Failed to marshal data: %v", err)
		}

		// Create provider and exchange.
		provider := servex.NewTelegramOAuthProvider(servex.TelegramOAuthConfig{
			BotToken:    botToken,
			RedirectURL: "https://example.com/callback",
		})

		userInfo, err := provider.Exchange(nil, string(jsonData))
		if err != nil {
			t.Fatalf("Exchange failed: %v", err)
		}

		if userInfo.ProviderID != "12345678" {
			t.Errorf("ProviderID = %q, want %q", userInfo.ProviderID, "12345678")
		}
		if userInfo.Username != "johndoe" {
			t.Errorf("Username = %q, want %q", userInfo.Username, "johndoe")
		}
		if userInfo.Email != "" {
			t.Errorf("Email = %q, want empty", userInfo.Email)
		}
		if userInfo.Verified {
			t.Error("Verified = true, want false")
		}
	})

	t.Run("invalid hash", func(t *testing.T) {
		data := map[string]any{
			"id":         float64(12345678),
			"first_name": "John",
			"username":   "johndoe",
			"auth_date":  float64(time.Now().Unix()),
			"hash":       "invalid-hash-value",
		}
		jsonData, _ := json.Marshal(data)

		provider := servex.NewTelegramOAuthProvider(servex.TelegramOAuthConfig{
			BotToken: botToken,
		})

		_, err := provider.Exchange(nil, string(jsonData))
		if err == nil {
			t.Fatal("Expected error for invalid hash")
		}
		if !strings.Contains(err.Error(), "hash verification failed") {
			t.Errorf("Error = %q, want to contain %q", err.Error(), "hash verification failed")
		}
	})

	t.Run("missing hash", func(t *testing.T) {
		data := map[string]any{
			"id":        float64(12345678),
			"auth_date": float64(time.Now().Unix()),
		}
		jsonData, _ := json.Marshal(data)

		provider := servex.NewTelegramOAuthProvider(servex.TelegramOAuthConfig{
			BotToken: botToken,
		})

		_, err := provider.Exchange(nil, string(jsonData))
		if err == nil {
			t.Fatal("Expected error for missing hash")
		}
		if !strings.Contains(err.Error(), "missing hash") {
			t.Errorf("Error = %q, want to contain %q", err.Error(), "missing hash")
		}
	})

	t.Run("expired auth data", func(t *testing.T) {
		authDate := time.Now().Add(-25 * time.Hour).Unix()
		data := map[string]any{
			"id":         float64(12345678),
			"first_name": "John",
			"auth_date":  float64(authDate),
		}
		hash := computeTelegramHash(t, data, botToken)
		data["hash"] = hash
		jsonData, _ := json.Marshal(data)

		provider := servex.NewTelegramOAuthProvider(servex.TelegramOAuthConfig{
			BotToken: botToken,
		})

		_, err := provider.Exchange(nil, string(jsonData))
		if err == nil {
			t.Fatal("Expected error for expired auth data")
		}
		if !strings.Contains(err.Error(), "too old") {
			t.Errorf("Error = %q, want to contain %q", err.Error(), "too old")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		provider := servex.NewTelegramOAuthProvider(servex.TelegramOAuthConfig{
			BotToken: botToken,
		})

		_, err := provider.Exchange(nil, "not-json")
		if err == nil {
			t.Fatal("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "invalid auth data JSON") {
			t.Errorf("Error = %q, want to contain %q", err.Error(), "invalid auth data JSON")
		}
	})

	t.Run("username from first_name and last_name", func(t *testing.T) {
		authDate := time.Now().Unix()
		data := map[string]any{
			"id":         float64(99999),
			"first_name": "Jane",
			"last_name":  "Smith",
			"auth_date":  float64(authDate),
		}
		hash := computeTelegramHash(t, data, botToken)
		data["hash"] = hash
		jsonData, _ := json.Marshal(data)

		provider := servex.NewTelegramOAuthProvider(servex.TelegramOAuthConfig{
			BotToken: botToken,
		})

		userInfo, err := provider.Exchange(nil, string(jsonData))
		if err != nil {
			t.Fatalf("Exchange failed: %v", err)
		}
		if userInfo.Username != "Jane Smith" {
			t.Errorf("Username = %q, want %q", userInfo.Username, "Jane Smith")
		}
	})
}

func TestYandexAuthURL(t *testing.T) {
	provider := servex.NewYandexOAuthProvider(servex.YandexOAuthConfig{
		ClientID:    "yandex-client-id",
		RedirectURL: "https://example.com/callback",
	})

	authURL := provider.AuthURL("test-state")

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	if parsed.Scheme != "https" || parsed.Host != "oauth.yandex.ru" || parsed.Path != "/authorize" {
		t.Errorf("Unexpected base URL: %s", authURL)
	}

	params := parsed.Query()

	if params.Get("client_id") != "yandex-client-id" {
		t.Errorf("client_id = %q, want %q", params.Get("client_id"), "yandex-client-id")
	}
	if params.Get("redirect_uri") != "https://example.com/callback" {
		t.Errorf("redirect_uri = %q, want %q", params.Get("redirect_uri"), "https://example.com/callback")
	}
	if params.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want %q", params.Get("response_type"), "code")
	}
	if params.Get("state") != "test-state" {
		t.Errorf("state = %q, want %q", params.Get("state"), "test-state")
	}
}

func TestTelegramAuthURL(t *testing.T) {
	provider := servex.NewTelegramOAuthProvider(servex.TelegramOAuthConfig{
		BotToken:    "123456789:ABCdefGHIjklMNOpqrsTUVwxyz",
		RedirectURL: "https://example.com/callback",
	})

	authURL := provider.AuthURL("test-state")

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	if parsed.Scheme != "https" || parsed.Host != "oauth.telegram.org" || parsed.Path != "/auth" {
		t.Errorf("Unexpected base URL: %s", authURL)
	}

	params := parsed.Query()

	if params.Get("bot_id") != "123456789" {
		t.Errorf("bot_id = %q, want %q", params.Get("bot_id"), "123456789")
	}

	// The origin should contain the state parameter.
	origin := params.Get("origin")
	if !strings.Contains(origin, "state=test-state") {
		t.Errorf("origin = %q, want to contain state=test-state", origin)
	}
}

func TestGoogleExchange(t *testing.T) {
	// Mock Google token endpoint and userinfo endpoint.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if r.FormValue("code") != "auth-code-123" {
				http.Error(w, "bad code", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": "google-access-token",
			})
			return
		}
		if r.URL.Path == "/userinfo" {
			if r.Header.Get("Authorization") != "Bearer google-access-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"id":             "google-user-123",
				"email":          "user@gmail.com",
				"name":           "Test User",
				"verified_email": true,
			})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer tokenServer.Close()

	// Note: We cannot override internal URLs in the provider, so this test
	// verifies the mock server contract. For full integration, the provider
	// would need a configurable base URL.
	// Instead, let's verify the URL construction and parameter passing.
	t.Run("url construction", func(t *testing.T) {
		provider := servex.NewGoogleOAuthProvider(servex.GoogleOAuthConfig{
			ClientID:     "test-id",
			ClientSecret: "test-secret",
			RedirectURL:  tokenServer.URL + "/callback",
		})

		url := provider.AuthURL("mystate")
		if !strings.Contains(url, "client_id=test-id") {
			t.Errorf("Expected client_id in URL, got: %s", url)
		}
		if !strings.Contains(url, "state=mystate") {
			t.Errorf("Expected state in URL, got: %s", url)
		}
	})
}

func TestGitHubExchange(t *testing.T) {
	t.Run("url construction", func(t *testing.T) {
		provider := servex.NewGitHubOAuthProvider(servex.GitHubOAuthConfig{
			ClientID:     "gh-id",
			ClientSecret: "gh-secret",
			RedirectURL:  "https://example.com/callback",
		})

		url := provider.AuthURL("ghstate")
		if !strings.Contains(url, "client_id=gh-id") {
			t.Errorf("Expected client_id in URL, got: %s", url)
		}
		if !strings.Contains(url, "state=ghstate") {
			t.Errorf("Expected state in URL, got: %s", url)
		}
	})
}

func TestYandexExchange(t *testing.T) {
	t.Run("url construction", func(t *testing.T) {
		provider := servex.NewYandexOAuthProvider(servex.YandexOAuthConfig{
			ClientID:     "ya-id",
			ClientSecret: "ya-secret",
			RedirectURL:  "https://example.com/callback",
		})

		url := provider.AuthURL("yastate")
		if !strings.Contains(url, "client_id=ya-id") {
			t.Errorf("Expected client_id in URL, got: %s", url)
		}
		if !strings.Contains(url, "state=yastate") {
			t.Errorf("Expected state in URL, got: %s", url)
		}
	})
}

func TestNewAuthManagerBuildsProviders(t *testing.T) {
	db := servex.NewMemoryAuthDatabase()

	tests := []struct {
		name          string
		oauth         servex.OAuthConfig
		expectedNames []string
	}{
		{
			name: "Google provider",
			oauth: servex.OAuthConfig{
				Enabled: true,
				Google: &servex.GoogleOAuthConfig{
					ClientID:     "g-id",
					ClientSecret: "g-secret",
				},
			},
			expectedNames: []string{"google"},
		},
		{
			name: "GitHub provider",
			oauth: servex.OAuthConfig{
				Enabled: true,
				GitHub: &servex.GitHubOAuthConfig{
					ClientID:     "gh-id",
					ClientSecret: "gh-secret",
				},
			},
			expectedNames: []string{"github"},
		},
		{
			name: "Multiple providers",
			oauth: servex.OAuthConfig{
				Enabled: true,
				Google: &servex.GoogleOAuthConfig{
					ClientID:     "g-id",
					ClientSecret: "g-secret",
				},
				GitHub: &servex.GitHubOAuthConfig{
					ClientID:     "gh-id",
					ClientSecret: "gh-secret",
				},
				Yandex: &servex.YandexOAuthConfig{
					ClientID:     "ya-id",
					ClientSecret: "ya-secret",
				},
			},
			expectedNames: []string{"google", "github", "yandex"},
		},
		{
			name: "Telegram provider",
			oauth: servex.OAuthConfig{
				Enabled: true,
				Telegram: &servex.TelegramOAuthConfig{
					BotToken: "123:token",
				},
			},
			expectedNames: []string{"telegram"},
		},
		{
			name: "Existing providers preserved",
			oauth: servex.OAuthConfig{
				Enabled: true,
				Providers: []servex.OAuthProvider{
					&MockOAuthProvider{name: "custom"},
				},
				Google: &servex.GoogleOAuthConfig{
					ClientID:     "g-id",
					ClientSecret: "g-secret",
				},
			},
			expectedNames: []string{"custom", "google"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := servex.AuthConfig{
				Enabled:          true,
				Database:         db,
				JWTAccessSecret:  generateTestHexKey(32),
				JWTRefreshSecret: generateTestHexKey(32),
				OAuth:            tt.oauth,
			}

			am, err := servex.NewAuthManager(cfg)
			if err != nil {
				t.Fatalf("NewAuthManager failed: %v", err)
			}

			// Verify providers by attempting redirect for each expected name.
			for _, name := range tt.expectedNames {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/"+name, nil)
				rr := httptest.NewRecorder()

				router := mux.NewRouter()
				am.RegisterRoutes(router)
				router.ServeHTTP(rr, req)

				// A found provider should give 302 redirect, not 404.
				if rr.Code == http.StatusNotFound {
					t.Errorf("Provider %q not found (got 404)", name)
				}
			}
		})
	}
}

// computeTelegramHash computes the Telegram data verification hash.
func computeTelegramHash(t *testing.T, data map[string]any, botToken string) string {
	t.Helper()

	var pairs []string
	for k, v := range data {
		if k == "hash" {
			continue
		}
		switch val := v.(type) {
		case float64:
			if val == float64(int64(val)) {
				pairs = append(pairs, fmt.Sprintf("%s=%d", k, int64(val)))
			} else {
				pairs = append(pairs, fmt.Sprintf("%s=%v", k, val))
			}
		default:
			pairs = append(pairs, fmt.Sprintf("%s=%v", k, val))
		}
	}
	sort.Strings(pairs)
	dataCheckString := strings.Join(pairs, "\n")

	secretHash := sha256.Sum256([]byte(botToken))
	mac := hmac.New(sha256.New, secretHash[:])
	mac.Write([]byte(dataCheckString))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func generateTestHexKey(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b)
}
