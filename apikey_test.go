package servex_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

// ---- helpers ----------------------------------------------------------------

func newTestAPIKeyAuthManager(t *testing.T) (*servex.AuthManager, *servex.MemoryAPIKeyDatabase) {
	t.Helper()
	db := servex.NewMemoryAuthDatabase()
	apiDB := servex.NewMemoryAPIKeyDatabase()
	cfg := servex.AuthConfig{
		Database:             db,
		JWTAccessSecret:      hex.EncodeToString(getRandomBytes(32)),
		JWTRefreshSecret:     hex.EncodeToString(getRandomBytes(32)),
		AccessTokenDuration:  5 * time.Minute,
		RefreshTokenDuration: 10 * time.Minute,
		IssuerNameInJWT:      "test-issuer",
		AuthBasePath:         "/api/v1/auth",
		APIKey: servex.APIKeyConfig{
			Database:   apiDB,
			Prefix:     "svx_",
			MaxPerUser: 10,
			KeyLength:  16,
		},
	}
	am, err := servex.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	return am, apiDB
}

// ---- TestMemoryAPIKeyDatabase -----------------------------------------------

func TestMemoryAPIKeyDatabase(t *testing.T) {
	ctx := context.Background()
	db := servex.NewMemoryAPIKeyDatabase()

	// CreateAPIKey should assign an ID
	now := time.Now()
	key := &servex.APIKey{
		UserID:    "user-1",
		Name:      "my key",
		KeyHash:   "hash-abc",
		KeyPrefix: "svx_abc123",
		Scopes:    []string{"read"},
		CreatedAt: now,
	}
	if err := db.CreateAPIKey(ctx, key); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if key.ID == "" {
		t.Fatal("expected ID to be set after CreateAPIKey")
	}

	// FindAPIKeyByHash — existing hash
	found, exists, err := db.FindAPIKeyByHash(ctx, "hash-abc")
	if err != nil {
		t.Fatalf("FindAPIKeyByHash: %v", err)
	}
	if !exists {
		t.Fatal("expected key to exist")
	}
	if found.Name != "my key" {
		t.Errorf("got name %q, want %q", found.Name, "my key")
	}

	// FindAPIKeyByHash — missing hash
	_, exists, err = db.FindAPIKeyByHash(ctx, "missing")
	if err != nil {
		t.Fatalf("FindAPIKeyByHash (missing): %v", err)
	}
	if exists {
		t.Error("expected key not to exist")
	}

	// ListAPIKeysByUser
	key2 := &servex.APIKey{
		UserID:    "user-1",
		Name:      "second key",
		KeyHash:   "hash-def",
		KeyPrefix: "svx_def456",
		CreatedAt: now,
	}
	if err := db.CreateAPIKey(ctx, key2); err != nil {
		t.Fatalf("CreateAPIKey (second): %v", err)
	}
	keys, err := db.ListAPIKeysByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListAPIKeysByUser: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
	keys2, _ := db.ListAPIKeysByUser(ctx, "user-99")
	if len(keys2) != 0 {
		t.Errorf("expected 0 keys for unknown user, got %d", len(keys2))
	}

	// UpdateAPIKeyLastUsed
	ts := time.Now()
	if err := db.UpdateAPIKeyLastUsed(ctx, key.ID, ts); err != nil {
		t.Fatalf("UpdateAPIKeyLastUsed: %v", err)
	}
	updated, _, _ := db.FindAPIKeyByHash(ctx, "hash-abc")
	if updated.LastUsedAt == nil {
		t.Fatal("expected LastUsedAt to be set")
	}

	// RevokeAPIKey
	if err := db.RevokeAPIKey(ctx, key.ID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	_, exists, _ = db.FindAPIKeyByHash(ctx, "hash-abc")
	if exists {
		t.Error("expected key to be gone after revoke")
	}

	// RevokeAPIKey — non-existent
	if err := db.RevokeAPIKey(ctx, "nonexistent"); err == nil {
		t.Error("expected error revoking non-existent key")
	}
}

// ---- TestAPIKeyGeneration ---------------------------------------------------

func TestAPIKeyGeneration(t *testing.T) {
	tests := []struct {
		prefix    string
		keyLength int
	}{
		{"svx_", 16},
		{"", 32},
		{"myapp_", 8},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("prefix=%q len=%d", tc.prefix, tc.keyLength), func(t *testing.T) {
			fullKey, keyHash, keyPrefix, err := servex.GenerateAPIKey(tc.prefix, tc.keyLength)
			if err != nil {
				t.Fatalf("generateAPIKey: %v", err)
			}

			// Key starts with prefix
			if len(tc.prefix) > 0 && len(fullKey) < len(tc.prefix) {
				t.Errorf("fullKey %q does not start with prefix %q", fullKey, tc.prefix)
			}

			// Hash is non-empty and 64 hex chars (SHA-256)
			if len(keyHash) != 64 {
				t.Errorf("expected 64-char hash, got %d: %s", len(keyHash), keyHash)
			}

			// Prefix is the first 12 chars of the full key (or less if shorter)
			want := fullKey
			if len(want) > 12 {
				want = want[:12]
			}
			if keyPrefix != want {
				t.Errorf("keyPrefix %q != expected %q", keyPrefix, want)
			}

			// Hashing the same key again yields the same hash
			h2 := servex.HashAPIKey(fullKey)
			if h2 != keyHash {
				t.Error("hash is not deterministic")
			}
		})
	}
}

// ---- TestAPIKeyHeaderExtraction --------------------------------------------

func TestAPIKeyHeaderExtraction(t *testing.T) {
	am, apiDB := newTestAPIKeyAuthManager(t)

	fullKey, keyHash, keyPrefix, err := servex.GenerateAPIKey("svx_", 16)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_ = apiDB.CreateAPIKey(context.Background(), &servex.APIKey{
		UserID:    "user-1",
		Name:      "test",
		KeyHash:   keyHash,
		KeyPrefix: keyPrefix,
		CreatedAt: time.Now(),
	})

	calledWithUser := ""
	handler := am.WithAPIKey(func(w http.ResponseWriter, r *http.Request) {
		calledWithUser = r.Context().Value(servex.UserContextKey{}).(string)
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name   string
		setup  func(r *http.Request)
		wantOK bool
	}{
		{
			name: "X-API-Key header",
			setup: func(r *http.Request) {
				r.Header.Set("X-API-Key", fullKey)
			},
			wantOK: true,
		},
		{
			name: "Authorization ApiKey header",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "ApiKey "+fullKey)
			},
			wantOK: true,
		},
		{
			name: "Authorization apikey (lowercase)",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "apikey "+fullKey)
			},
			wantOK: true,
		},
		{
			name:   "no header — 401",
			setup:  func(r *http.Request) {},
			wantOK: false,
		},
		{
			name: "wrong key — 401",
			setup: func(r *http.Request) {
				r.Header.Set("X-API-Key", "svx_wrong")
			},
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calledWithUser = ""
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			tc.setup(req)
			rr := httptest.NewRecorder()
			handler(rr, req)

			if tc.wantOK && rr.Code != http.StatusOK {
				t.Errorf("expected 200, got %d", rr.Code)
			}
			if tc.wantOK && calledWithUser != "user-1" {
				t.Errorf("expected userID user-1, got %q", calledWithUser)
			}
			if !tc.wantOK && rr.Code == http.StatusOK {
				t.Error("expected non-200, got 200")
			}
		})
	}
}

// ---- TestAPIKeyMiddleware ---------------------------------------------------

func TestAPIKeyMiddleware(t *testing.T) {
	am, apiDB := newTestAPIKeyAuthManager(t)

	// Create a key with scopes
	fullKey, keyHash, keyPrefix, err := servex.GenerateAPIKey("svx_", 16)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := apiDB.CreateAPIKey(context.Background(), &servex.APIKey{
		UserID:    "user-42",
		Name:      "scoped key",
		KeyHash:   keyHash,
		KeyPrefix: keyPrefix,
		Scopes:    []string{"read", "write"},
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	// Create an expired key
	expiredKey, expiredHash, expiredPrefix, _ := servex.GenerateAPIKey("svx_", 16)
	expiredAt := time.Now().Add(-time.Hour)
	_ = apiDB.CreateAPIKey(context.Background(), &servex.APIKey{
		UserID:    "user-42",
		Name:      "expired",
		KeyHash:   expiredHash,
		KeyPrefix: expiredPrefix,
		ExpiresAt: &expiredAt,
		CreatedAt: time.Now().Add(-2 * time.Hour),
	})

	echoHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	tests := []struct {
		name       string
		key        string
		scopes     []string
		wantStatus int
	}{
		{"valid key no scopes required", fullKey, nil, http.StatusOK},
		{"valid key matching scopes", fullKey, []string{"read"}, http.StatusOK},
		{"valid key all scopes", fullKey, []string{"read", "write"}, http.StatusOK},
		{"valid key missing scope", fullKey, []string{"admin"}, http.StatusForbidden},
		{"expired key", expiredKey, nil, http.StatusUnauthorized},
		{"missing key", "", nil, http.StatusUnauthorized},
		{"invalid key", "svx_garbage", nil, http.StatusUnauthorized},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := am.WithAPIKey(echoHandler, tc.scopes...)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.key != "" {
				req.Header.Set("X-API-Key", tc.key)
			}
			rr := httptest.NewRecorder()
			handler(rr, req)
			if rr.Code != tc.wantStatus {
				t.Errorf("want %d, got %d (body: %s)", tc.wantStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

// ---- TestAPIKeyEndpoints ---------------------------------------------------

func TestAPIKeyEndpoints(t *testing.T) {
	ts := servex.NewTestServer(t,
		servex.WithAuthMemoryDatabase(),
		servex.WithAuthKey(hex.EncodeToString(getRandomBytes(32)), hex.EncodeToString(getRandomBytes(32))),
		servex.WithAuthTokensDuration(5*time.Minute, 10*time.Minute),
		servex.WithAPIKeysMemoryDatabase(),
		servex.WithAPIKeyScopes("read", "write", "admin"),
	)

	// 1. Register a user
	regResp := ts.Post("/api/v1/auth/register").
		WithJSON(map[string]string{"username": "alice", "password": "password123"}).
		Do()
	if regResp.Code != http.StatusCreated {
		t.Fatalf("register: got %d, body: %s", regResp.Code, regResp.BodyString())
	}

	var loginBody servex.UserLoginResponse
	if err := regResp.JSON(&loginBody); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	token := loginBody.AccessToken

	// 2. Create an API key
	createResp := ts.Post("/api/v1/auth/api-keys").
		WithAuth(token).
		WithJSON(servex.CreateAPIKeyRequest{Name: "ci-key", Scopes: []string{"read"}}).
		Do()
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create api key: got %d, body: %s", createResp.Code, createResp.BodyString())
	}
	var created servex.CreateAPIKeyResponse
	if err := createResp.JSON(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Key == "" {
		t.Fatal("expected full key in response")
	}
	if created.ID == "" {
		t.Fatal("expected ID in response")
	}
	if len(created.Scopes) != 1 || created.Scopes[0] != "read" {
		t.Errorf("unexpected scopes: %v", created.Scopes)
	}

	// 3. Create key with invalid scope — expect 400
	badScopeResp := ts.Post("/api/v1/auth/api-keys").
		WithAuth(token).
		WithJSON(servex.CreateAPIKeyRequest{Name: "bad", Scopes: []string{"superadmin"}}).
		Do()
	if badScopeResp.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid scope, got %d", badScopeResp.Code)
	}

	// 4. List API keys
	listResp := ts.Get("/api/v1/auth/api-keys").
		WithAuth(token).
		Do()
	if listResp.Code != http.StatusOK {
		t.Fatalf("list api keys: got %d, body: %s", listResp.Code, listResp.BodyString())
	}
	var keys []servex.APIKeyResponse
	if err := json.Unmarshal(listResp.Body, &keys); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Name != "ci-key" {
		t.Errorf("expected name ci-key, got %s", keys[0].Name)
	}
	// Hash must not be exposed
	if keys[0].KeyPrefix == "" {
		t.Error("expected non-empty key prefix")
	}

	// 5. Revoke
	revokeResp := ts.Delete("/api/v1/auth/api-keys/" + created.ID).
		WithAuth(token).
		Do()
	if revokeResp.Code != http.StatusNoContent {
		t.Fatalf("revoke: got %d, body: %s", revokeResp.Code, revokeResp.BodyString())
	}

	// 6. List again — should be empty
	listResp2 := ts.Get("/api/v1/auth/api-keys").
		WithAuth(token).
		Do()
	var keys2 []servex.APIKeyResponse
	if err := json.Unmarshal(listResp2.Body, &keys2); err != nil {
		t.Fatalf("decode second list: %v", err)
	}
	if len(keys2) != 0 {
		t.Errorf("expected 0 keys after revoke, got %d", len(keys2))
	}

	// 7. Unauthenticated create — expect 401
	unauth := ts.Post("/api/v1/auth/api-keys").
		WithJSON(servex.CreateAPIKeyRequest{Name: "unauthorized"}).
		Do()
	if unauth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", unauth.Code)
	}
}

func TestAPIKeyMaxPerUser(t *testing.T) {
	ts := servex.NewTestServer(t,
		servex.WithAuthMemoryDatabase(),
		servex.WithAuthKey(hex.EncodeToString(getRandomBytes(32)), hex.EncodeToString(getRandomBytes(32))),
		servex.WithAuthTokensDuration(5*time.Minute, 10*time.Minute),
		servex.WithAPIKeysMemoryDatabase(),
		servex.WithAPIKeyMaxPerUser(2),
	)

	// Register and login
	regResp := ts.Post("/api/v1/auth/register").
		WithJSON(map[string]string{"username": "bob", "password": "password123"}).
		Do()
	var body servex.UserLoginResponse
	_ = regResp.JSON(&body)
	token := body.AccessToken

	for i := 0; i < 2; i++ {
		r := ts.Post("/api/v1/auth/api-keys").
			WithAuth(token).
			WithJSON(servex.CreateAPIKeyRequest{Name: fmt.Sprintf("key-%d", i)}).
			Do()
		if r.Code != http.StatusCreated {
			t.Fatalf("create key %d: got %d: %s", i, r.Code, r.BodyString())
		}
	}

	// Third key should fail
	r := ts.Post("/api/v1/auth/api-keys").
		WithAuth(token).
		WithJSON(servex.CreateAPIKeyRequest{Name: "overflow"}).
		Do()
	if r.Code != http.StatusConflict {
		t.Errorf("expected 409 (limit), got %d: %s", r.Code, r.BodyString())
	}
}

func TestAPIKeyContextHelper(t *testing.T) {
	am, apiDB := newTestAPIKeyAuthManager(t)

	fullKey, keyHash, keyPrefix, err := servex.GenerateAPIKey("svx_", 16)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_ = apiDB.CreateAPIKey(context.Background(), &servex.APIKey{
		UserID:    "user-1",
		Name:      "ctx test",
		KeyHash:   keyHash,
		KeyPrefix: keyPrefix,
		Scopes:    []string{"read", "write"},
		CreatedAt: time.Now(),
	})

	var gotScopes []string
	handler := am.WithAPIKey(func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		gotScopes = ctx.APIKeyScopes()
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", fullKey)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if len(gotScopes) != 2 || gotScopes[0] != "read" || gotScopes[1] != "write" {
		t.Errorf("unexpected scopes: %v", gotScopes)
	}
}
