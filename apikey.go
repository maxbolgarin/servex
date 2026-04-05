package servex

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

// APIKey represents an API key in the system.
type APIKey struct {
	ID         string     `json:"id" bson:"_id" db:"id"`
	UserID     string     `json:"user_id" bson:"user_id" db:"user_id"`
	Name       string     `json:"name" bson:"name" db:"name"`
	KeyHash    string     `json:"-" bson:"key_hash" db:"key_hash"`
	KeyPrefix  string     `json:"key_prefix" bson:"key_prefix" db:"key_prefix"`
	Scopes     []string   `json:"scopes" bson:"scopes" db:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" bson:"expires_at,omitempty" db:"expires_at"`
	CreatedAt  time.Time  `json:"created_at" bson:"created_at" db:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty" bson:"last_used_at,omitempty" db:"last_used_at"`
}

// APIKeyResponse is the response returned when listing API keys (no hash).
type APIKeyResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"key_prefix"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// CreateAPIKeyRequest is the request body for creating an API key.
type CreateAPIKeyRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes,omitempty"`
	ExpiresIn string   `json:"expires_in,omitempty"` // optional duration string, e.g. "720h" for 30 days
}

// CreateAPIKeyResponse is returned once when a key is created (contains the full key).
type CreateAPIKeyResponse struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Key       string   `json:"key"` // full key, shown only once
	KeyPrefix string   `json:"key_prefix"`
	Scopes    []string `json:"scopes"`
}

// APIKeyDatabase defines the interface for API key storage.
type APIKeyDatabase interface {
	// CreateAPIKey stores a new API key record.
	CreateAPIKey(ctx context.Context, key *APIKey) error

	// FindAPIKeyByHash looks up a key by its SHA-256 hash.
	FindAPIKeyByHash(ctx context.Context, keyHash string) (APIKey, bool, error)

	// RevokeAPIKey removes an API key by its ID.
	RevokeAPIKey(ctx context.Context, keyID string) error

	// ListAPIKeysByUser returns all API keys for a given user ID.
	ListAPIKeysByUser(ctx context.Context, userID string) ([]APIKey, error)

	// UpdateAPIKeyLastUsed updates the last-used timestamp for a key.
	UpdateAPIKeyLastUsed(ctx context.Context, keyID string, t time.Time) error
}

// APIKeyScopesContextKey is used to store API key scopes in the request context.
type APIKeyScopesContextKey struct{}

// MemoryAPIKeyDatabase is an in-memory implementation of APIKeyDatabase for development and testing.
type MemoryAPIKeyDatabase struct {
	mu           sync.RWMutex
	keys         map[string]*APIKey // keyed by ID
	keysByHash   map[string]*APIKey // keyed by hash
	keyIDCounter int
}

// NewMemoryAPIKeyDatabase creates a new in-memory API key database.
func NewMemoryAPIKeyDatabase() *MemoryAPIKeyDatabase {
	return &MemoryAPIKeyDatabase{
		keys:       make(map[string]*APIKey),
		keysByHash: make(map[string]*APIKey),
	}
}

func (db *MemoryAPIKeyDatabase) CreateAPIKey(ctx context.Context, key *APIKey) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.keyIDCounter++
	key.ID = fmt.Sprintf("apikey-%d", db.keyIDCounter)
	stored := *key
	stored.Scopes = append([]string(nil), key.Scopes...)
	db.keys[key.ID] = &stored
	hashCopy := stored
	db.keysByHash[key.KeyHash] = &hashCopy
	return nil
}

func (db *MemoryAPIKeyDatabase) FindAPIKeyByHash(ctx context.Context, keyHash string) (APIKey, bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key, exists := db.keysByHash[keyHash]
	if !exists {
		return APIKey{}, false, nil
	}
	return *key, true, nil
}

func (db *MemoryAPIKeyDatabase) RevokeAPIKey(ctx context.Context, keyID string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	key, exists := db.keys[keyID]
	if !exists {
		return fmt.Errorf("api key with id %s not found", keyID)
	}
	delete(db.keysByHash, key.KeyHash)
	delete(db.keys, keyID)
	return nil
}

func (db *MemoryAPIKeyDatabase) ListAPIKeysByUser(ctx context.Context, userID string) ([]APIKey, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var result []APIKey
	for _, key := range db.keys {
		if key.UserID == userID {
			result = append(result, *key)
		}
	}
	return result, nil
}

func (db *MemoryAPIKeyDatabase) UpdateAPIKeyLastUsed(ctx context.Context, keyID string, t time.Time) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	key, exists := db.keys[keyID]
	if !exists {
		return fmt.Errorf("api key with id %s not found", keyID)
	}
	key.LastUsedAt = &t
	if hk, ok := db.keysByHash[key.KeyHash]; ok {
		hk.LastUsedAt = &t
	}
	return nil
}

// generateAPIKey creates a new API key with the given prefix.
// Returns the full key string, its SHA-256 hash, and a short display prefix.
func GenerateAPIKey(prefix string, keyLength int) (fullKey string, keyHash string, keyPrefix string, err error) {
	randomBytes := make([]byte, keyLength)
	if _, err := crand.Read(randomBytes); err != nil {
		return "", "", "", fmt.Errorf("generate random bytes: %w", err)
	}
	fullKey = prefix + hex.EncodeToString(randomBytes)
	hash := sha256.Sum256([]byte(fullKey))
	keyHash = hex.EncodeToString(hash[:])
	prefixLen := len(fullKey)
	if prefixLen > 12 {
		prefixLen = 12
	}
	keyPrefix = fullKey[:prefixLen]
	return fullKey, keyHash, keyPrefix, nil
}

// hashAPIKey computes the SHA-256 hash of an API key string.
func HashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// WithAPIKey is middleware that authenticates requests using API keys.
// It checks X-API-Key header or Authorization: ApiKey <key> header.
// If scopes are provided, the key must have all required scopes.
func (m *AuthManager) WithAPIKey(next http.HandlerFunc, scopes ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := NewContext(w, r)

		if m.service.cfg.APIKey.Database == nil {
			ctx.InternalServerError(errors.New("API key database not configured"), "API key authentication not available")
			return
		}

		// Extract key from headers — prefer X-API-Key, fall back to Authorization: ApiKey
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "apikey") {
					apiKey = parts[1]
				}
			}
		}

		if apiKey == "" {
			ctx.Unauthorized(errors.New("missing API key"), "missing or invalid API key")
			return
		}

		keyHash := HashAPIKey(apiKey)
		keyRecord, exists, err := m.service.cfg.APIKey.Database.FindAPIKeyByHash(r.Context(), keyHash)
		if err != nil {
			ctx.InternalServerError(err, "failed to validate API key")
			return
		}
		if !exists {
			ctx.Unauthorized(errors.New("invalid API key"), "invalid API key")
			return
		}

		if keyRecord.ExpiresAt != nil && keyRecord.ExpiresAt.Before(time.Now()) {
			ctx.Unauthorized(errors.New("expired API key"), "API key has expired")
			return
		}

		// All required scopes must be present on the key
		if len(scopes) > 0 {
			keyScopes := make(map[string]bool, len(keyRecord.Scopes))
			for _, s := range keyRecord.Scopes {
				keyScopes[s] = true
			}
			for _, required := range scopes {
				if !keyScopes[required] {
					ctx.Forbidden(errors.New("insufficient scopes"), "API key missing required scope")
					return
				}
			}
		}

		// Update last used asynchronously to avoid blocking the request
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = m.service.cfg.APIKey.Database.UpdateAPIKeyLastUsed(ctx, keyRecord.ID, time.Now())
		}()

		reqCtx := context.WithValue(r.Context(), UserContextKey{}, keyRecord.UserID)
		reqCtx = context.WithValue(reqCtx, APIKeyScopesContextKey{}, keyRecord.Scopes)
		next(w, r.WithContext(reqCtx))
	}
}

// CreateAPIKeyHandler handles POST /api-keys. Requires JWT authentication.
// Creates a new API key for the authenticated user and returns it once with the full key.
func (m *AuthManager) CreateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	if m.service.cfg.APIKey.Database == nil {
		ctx.InternalServerError(errors.New("API key database not configured"), "API key authentication not available")
		return
	}

	userID := getValueFromContext[string](r, UserContextKey{})
	if userID == "" {
		ctx.Unauthorized(errUnauthorized, "not authenticated")
		return
	}

	var req CreateAPIKeyRequest
	if err := ctx.ReadJSON(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}
	if req.Name == "" {
		ctx.BadRequest(errors.New("name is required"), "name is required")
		return
	}

	cfg := m.service.cfg.APIKey

	// Validate scopes if a valid-scopes list is configured
	if len(cfg.ValidScopes) > 0 && len(req.Scopes) > 0 {
		validSet := make(map[string]bool, len(cfg.ValidScopes))
		for _, s := range cfg.ValidScopes {
			validSet[s] = true
		}
		for _, s := range req.Scopes {
			if !validSet[s] {
				ctx.BadRequest(fmt.Errorf("invalid scope: %s", s), "invalid scope")
				return
			}
		}
	}

	// Enforce per-user limit
	existing, err := cfg.Database.ListAPIKeysByUser(r.Context(), userID)
	if err != nil {
		ctx.InternalServerError(err, "failed to list API keys")
		return
	}
	if len(existing) >= cfg.MaxPerUser {
		ctx.Error(fmt.Errorf("api key limit reached: %d", cfg.MaxPerUser), http.StatusConflict, "API key limit reached")
		return
	}

	fullKey, keyHash, keyPrefix, err := GenerateAPIKey(cfg.Prefix, cfg.KeyLength)
	if err != nil {
		ctx.InternalServerError(err, "failed to generate API key")
		return
	}

	now := time.Now()
	scopes := req.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	key := &APIKey{
		UserID:    userID,
		Name:      req.Name,
		KeyHash:   keyHash,
		KeyPrefix: keyPrefix,
		Scopes:    scopes,
		CreatedAt: now,
	}

	// Parse optional expiration
	if req.ExpiresIn != "" {
		dur, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			ctx.BadRequest(err, "invalid expires_in duration")
			return
		}
		exp := now.Add(dur)
		key.ExpiresAt = &exp
	}

	if err := cfg.Database.CreateAPIKey(r.Context(), key); err != nil {
		ctx.InternalServerError(err, "failed to create API key")
		return
	}

	ctx.Response(http.StatusCreated, CreateAPIKeyResponse{
		ID:        key.ID,
		Name:      key.Name,
		Key:       fullKey,
		KeyPrefix: key.KeyPrefix,
		Scopes:    key.Scopes,
	})
}

// ListAPIKeysHandler handles GET /api-keys. Requires JWT authentication.
// Returns all API keys for the authenticated user without exposing key hashes.
func (m *AuthManager) ListAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	if m.service.cfg.APIKey.Database == nil {
		ctx.InternalServerError(errors.New("API key database not configured"), "API key authentication not available")
		return
	}

	userID := getValueFromContext[string](r, UserContextKey{})
	if userID == "" {
		ctx.Unauthorized(errUnauthorized, "not authenticated")
		return
	}

	keys, err := m.service.cfg.APIKey.Database.ListAPIKeysByUser(r.Context(), userID)
	if err != nil {
		ctx.InternalServerError(err, "failed to list API keys")
		return
	}

	resp := make([]APIKeyResponse, len(keys))
	for i, k := range keys {
		resp[i] = APIKeyResponse{
			ID:         k.ID,
			Name:       k.Name,
			KeyPrefix:  k.KeyPrefix,
			Scopes:     k.Scopes,
			ExpiresAt:  k.ExpiresAt,
			CreatedAt:  k.CreatedAt,
			LastUsedAt: k.LastUsedAt,
		}
	}

	ctx.Response(http.StatusOK, resp)
}

// RevokeAPIKeyHandler handles DELETE /api-keys/{id}. Requires JWT authentication.
// Revokes an API key by its ID.
func (m *AuthManager) RevokeAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	if m.service.cfg.APIKey.Database == nil {
		ctx.InternalServerError(errors.New("API key database not configured"), "API key authentication not available")
		return
	}

	userID := getValueFromContext[string](r, UserContextKey{})
	if userID == "" {
		ctx.Unauthorized(errUnauthorized, "not authenticated")
		return
	}

	keyID := mux.Vars(r)["id"]
	if keyID == "" {
		ctx.BadRequest(errors.New("missing key id"), "key id is required")
		return
	}

	// Verify the key belongs to the authenticated user
	keys, err := m.service.cfg.APIKey.Database.ListAPIKeysByUser(r.Context(), userID)
	if err != nil {
		ctx.InternalServerError(err, "failed to verify key ownership")
		return
	}
	found := false
	for _, k := range keys {
		if k.ID == keyID {
			found = true
			break
		}
	}
	if !found {
		ctx.NotFound(errors.New("key not found"), "API key not found")
		return
	}

	if err := m.service.cfg.APIKey.Database.RevokeAPIKey(r.Context(), keyID); err != nil {
		ctx.InternalServerError(err, "failed to revoke API key")
		return
	}

	ctx.Response(http.StatusNoContent)
}

// registerAPIKeyRoutes registers the API key management routes under the auth base path.
func (m *AuthManager) registerAPIKeyRoutes(r *mux.Router) {
	rr := r.PathPrefix(m.service.cfg.AuthBasePath).Subrouter()
	rr.HandleFunc("/api-keys", m.WithAuth(m.CreateAPIKeyHandler)).Methods(http.MethodPost)
	rr.HandleFunc("/api-keys", m.WithAuth(m.ListAPIKeysHandler)).Methods(http.MethodGet)
	rr.HandleFunc("/api-keys/{id}", m.WithAuth(m.RevokeAPIKeyHandler)).Methods(http.MethodDelete)
}
