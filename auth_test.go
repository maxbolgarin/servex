package servex_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	mr "math/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/maxbolgarin/lang"
	"github.com/maxbolgarin/servex"
	"golang.org/x/crypto/bcrypt"
)

// MockAuthDatabase provides a mock implementation of the AuthDatabase interface for testing.
type MockAuthDatabase struct {
	mu            sync.RWMutex
	users         map[string]servex.User // Map username to User
	usersByID     map[string]servex.User // Map ID to User
	userIDCounter int

	// Control flags/data for testing specific scenarios
	SimulateErrorOnNewUser        bool
	SimulateErrorOnFindByID       bool
	SimulateErrorOnFindByUsername bool
	SimulateErrorOnFindAll        bool
	SimulateErrorOnUpdateUser     bool
}

func NewMockAuthDatabase() *MockAuthDatabase {
	return &MockAuthDatabase{
		users:     make(map[string]servex.User),
		usersByID: make(map[string]servex.User),
	}
}

func (db *MockAuthDatabase) NewUser(ctx context.Context, username string, passwordHash string, roles ...servex.UserRole) (string, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.SimulateErrorOnNewUser {
		return "", fmt.Errorf("simulated NewUser error")
	}

	if _, exists := db.users[username]; exists {
		return "", fmt.Errorf("username %q already exists", username) // Or a specific error type
	}

	db.userIDCounter++
	id := fmt.Sprintf("user-%d", db.userIDCounter)
	user := servex.User{
		ID:           id,
		Username:     username,
		PasswordHash: passwordHash,
		Roles:        roles,
	}
	db.users[username] = user
	db.usersByID[id] = user
	return id, nil
}

func (db *MockAuthDatabase) FindByID(ctx context.Context, id string) (servex.User, bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.SimulateErrorOnFindByID {
		return servex.User{}, false, fmt.Errorf("simulated FindByID error")
	}

	user, exists := db.usersByID[id]
	return user, exists, nil
}

func (db *MockAuthDatabase) FindByUsername(ctx context.Context, username string) (servex.User, bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.SimulateErrorOnFindByUsername {
		return servex.User{}, false, fmt.Errorf("simulated FindByUsername error")
	}

	user, exists := db.users[username]
	return user, exists, nil
}

func (db *MockAuthDatabase) FindAll(ctx context.Context) ([]servex.User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.SimulateErrorOnFindAll {
		return nil, fmt.Errorf("simulated FindAll error")
	}

	users := make([]servex.User, 0, len(db.usersByID))
	for _, user := range db.usersByID {
		users = append(users, user)
	}
	return users, nil
}

func (db *MockAuthDatabase) UpdateUser(ctx context.Context, id string, diff *servex.UserDiff) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.SimulateErrorOnUpdateUser {
		return fmt.Errorf("simulated UpdateUser error")
	}

	user, exists := db.usersByID[id]
	if !exists {
		return fmt.Errorf("user with id %s not found", id) // Or a specific error
	}

	// Remove old username mapping if username is changing
	if diff.Username != nil && *diff.Username != user.Username {
		if _, exists := db.users[*diff.Username]; exists {
			return fmt.Errorf("new username %q already exists", *diff.Username)
		}
		delete(db.users, user.Username)
		user.Username = *diff.Username
	}

	if diff.Roles != nil {
		user.Roles = *diff.Roles
	}
	if diff.PasswordHash != nil {
		user.PasswordHash = *diff.PasswordHash
	}
	if diff.RefreshTokenHash != nil {
		user.RefreshTokenHash = *diff.RefreshTokenHash // Update refresh token hash
	}

	// Update maps
	db.users[user.Username] = user
	db.usersByID[id] = user

	return nil
}

// Helper to reset the mock database state between tests
func (db *MockAuthDatabase) Reset() {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.users = make(map[string]servex.User)
	db.usersByID = make(map[string]servex.User)
	db.userIDCounter = 0
	db.SimulateErrorOnNewUser = false
	db.SimulateErrorOnFindByID = false
	db.SimulateErrorOnFindByUsername = false
	db.SimulateErrorOnFindAll = false
	db.SimulateErrorOnUpdateUser = false
}

// Helper function to create a new AuthManager configured for testing
func newTestAuthManager(db servex.AuthDatabase) (*servex.AuthManager, servex.AuthConfig) {
	// Use the actual default path for consistency in tests
	defaultAuthPath := "/api/v1/auth"
	defaultCookieName := "_servexrt" // Default refresh token cookie name
	authCfg := servex.AuthConfig{
		Database:               db,
		JWTAccessSecret:        hex.EncodeToString(getRandomBytes(32)),
		JWTRefreshSecret:       hex.EncodeToString(getRandomBytes(32)),
		AccessTokenDuration:    5 * time.Minute,
		RefreshTokenDuration:   10 * time.Minute,
		IssuerNameInJWT:        "test-issuer",
		RolesOnRegister:        []servex.UserRole{servex.UserRole("user")},
		AuthBasePath:           defaultAuthPath,   // Explicitly set the base path
		RefreshTokenCookieName: defaultCookieName, // Explicitly set the cookie name
	}
	return servex.NewAuthManager(authCfg), authCfg
}

// Helper function to create a request with a JSON body
func newJsonRequest(method, target string, body interface{}) *http.Request {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(jsonBytes)
	}
	req := httptest.NewRequest(method, target, reqBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// Helper function to decode JSON response
func decodeJsonResponse(t *testing.T, rr *httptest.ResponseRecorder, target interface{}) {
	bodyBytes, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		t.Fatalf("Failed to decode JSON response: %v\nBody: %s", err, string(bodyBytes))
	}
}

func TestAuthManager_CreateUser(t *testing.T) {
	mockDB := NewMockAuthDatabase()
	authManager, _ := newTestAuthManager(mockDB)
	ctx := context.Background()

	tests := []struct {
		name          string
		username      string
		password      string
		roles         []servex.UserRole
		mockSetup     func()
		expectError   bool
		validateState func(t *testing.T)
	}{
		{
			name:     "Create new user successfully",
			username: "newuser",
			password: "password123",
			roles:    []servex.UserRole{servex.UserRole("user")},
			mockSetup: func() {
				mockDB.Reset()
			},
			expectError: false,
			validateState: func(t *testing.T) {
				user, exists, err := mockDB.FindByUsername(ctx, "newuser")
				if err != nil || !exists {
					t.Fatalf("Expected user 'newuser' to exist after creation, exists=%v, err=%v", exists, err)
				}
				if len(user.Roles) != 1 || user.Roles[0] != "user" {
					t.Errorf("Expected user roles to be [user], got %v", user.Roles)
				}
				err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte("password123"))
				if err != nil {
					t.Errorf("Password hash does not match original password: %v", err)
				}
			},
		},
		{
			name:     "Update existing user password and roles",
			username: "existinguser",
			password: "newpassword456",
			roles:    []servex.UserRole{servex.UserRole("admin"), servex.UserRole("editor")},
			mockSetup: func() {
				mockDB.Reset()
				// Pre-populate user
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.DefaultCost)
				_, _ = mockDB.NewUser(ctx, "existinguser", string(hashedPassword), servex.UserRole("user"))
			},
			expectError: false,
			validateState: func(t *testing.T) {
				user, exists, err := mockDB.FindByUsername(ctx, "existinguser")
				if err != nil || !exists {
					t.Fatalf("Expected user 'existinguser' to exist after update, exists=%v, err=%v", exists, err)
				}
				if len(user.Roles) != 2 || user.Roles[0] != "admin" || user.Roles[1] != "editor" {
					t.Errorf("Expected user roles to be [admin editor], got %v", user.Roles)
				}
				err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte("newpassword456"))
				if err != nil {
					t.Errorf("Password hash does not match updated password: %v", err)
				}
			},
		},
		{
			name:     "Error finding user",
			username: "erroruser",
			password: "password",
			mockSetup: func() {
				mockDB.Reset()
				mockDB.SimulateErrorOnFindByUsername = true
			},
			expectError: true,
		},
		{
			name:     "Error hashing password (should not happen often)",
			username: "hashfailuser",
			password: string(make([]byte, 80)), // Bcrypt has max password length
			mockSetup: func() {
				mockDB.Reset()
			},
			expectError: true, // Bcrypt generate error
		},
		{
			name:     "Error creating user in DB",
			username: "dbcreatefail",
			password: "password",
			mockSetup: func() {
				mockDB.Reset()
				mockDB.SimulateErrorOnNewUser = true
			},
			expectError: true,
		},
		{
			name:     "Error updating user in DB",
			username: "dbupdatefail",
			password: "password",
			mockSetup: func() {
				mockDB.Reset()
				// Pre-populate user
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.DefaultCost)
				_, _ = mockDB.NewUser(ctx, "dbupdatefail", string(hashedPassword), servex.UserRole("user"))
				mockDB.SimulateErrorOnUpdateUser = true
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mockSetup != nil {
				tt.mockSetup()
			}

			err := authManager.CreateUser(ctx, tt.username, tt.password, tt.roles...)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected an error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got: %v", err)
				}
				if tt.validateState != nil {
					tt.validateState(t)
				}
			}
		})
	}
}

func TestUserLoginRequest_Validate(t *testing.T) {
	tests := []struct {
		name      string
		req       servex.UserLoginRequest
		expectErr bool
	}{
		{"Valid request", servex.UserLoginRequest{Username: "user", Password: "pass"}, false},
		{"Missing username", servex.UserLoginRequest{Password: "pass"}, true},
		{"Missing password", servex.UserLoginRequest{Username: "user"}, true},
		{"Empty request", servex.UserLoginRequest{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.expectErr {
				t.Errorf("Validate() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

func TestUserUpdateRequest_Validate(t *testing.T) {
	username := "newuser"
	roles := servex.UserRole("admin")
	password := "newpass"

	tests := []struct {
		name      string
		req       servex.UserUpdateRequest
		expectErr bool
	}{
		{"Valid request (username)", servex.UserUpdateRequest{ID: "123", Username: &username}, false},
		{"Valid request (roles)", servex.UserUpdateRequest{ID: "123", Roles: &[]servex.UserRole{roles}}, false},
		{"Valid request (password)", servex.UserUpdateRequest{ID: "123", Password: &password}, false},
		{"Valid request (all fields)", servex.UserUpdateRequest{ID: "123", Username: &username, Roles: &[]servex.UserRole{roles}, Password: &password}, false},
		{"Missing ID", servex.UserUpdateRequest{Username: &username}, true},
		{"Missing update fields", servex.UserUpdateRequest{ID: "123"}, true},
		{"Empty request", servex.UserUpdateRequest{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.expectErr {
				t.Errorf("Validate() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

func TestAuthManager_RegisterHandler(t *testing.T) {
	mockDB := NewMockAuthDatabase()
	authManager, cfg := newTestAuthManager(mockDB)
	router := mux.NewRouter()
	authManager.RegisterRoutes(router) // Use the actual RegisterRoutes method

	tests := []struct {
		name             string
		requestBody      servex.UserLoginRequest
		mockSetup        func()
		expectStatus     int
		expectInResponse *servex.UserLoginResponse // Pointer allows nil check
		checkCookie      bool
	}{
		{
			name:             "Successful registration",
			requestBody:      servex.UserLoginRequest{Username: "testuser", Password: "password"},
			mockSetup:        func() { mockDB.Reset() },
			expectStatus:     http.StatusCreated,
			expectInResponse: &servex.UserLoginResponse{Username: "testuser", Roles: cfg.RolesOnRegister}, // ID and AccessToken are generated
			checkCookie:      true,
		},
		{
			name:        "Username already exists",
			requestBody: servex.UserLoginRequest{Username: "existing", Password: "password"},
			mockSetup: func() {
				mockDB.Reset()
				_, _ = mockDB.NewUser(context.Background(), "existing", "somehash") // Pre-populate
			},
			expectStatus: http.StatusConflict,
		},
		{
			name:         "Invalid request body (missing username)",
			requestBody:  servex.UserLoginRequest{Password: "password"},
			mockSetup:    func() { mockDB.Reset() },
			expectStatus: http.StatusBadRequest,
		},
		{
			name:        "Database error on NewUser",
			requestBody: servex.UserLoginRequest{Username: "dberroruser", Password: "password"},
			mockSetup: func() {
				mockDB.Reset()
				mockDB.SimulateErrorOnNewUser = true
			},
			expectStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mockSetup != nil {
				tt.mockSetup()
			}

			req := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/register", tt.requestBody)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectStatus, rr.Code, rr.Body.String())
			}

			if tt.expectInResponse != nil {
				var respBody servex.UserLoginResponse
				decodeJsonResponse(t, rr, &respBody)
				if respBody.Username != tt.expectInResponse.Username {
					t.Errorf("Expected username %q, got %q", tt.expectInResponse.Username, respBody.Username)
				}
				if respBody.ID == "" {
					t.Errorf("Expected non-empty ID, got empty string")
				}
				if respBody.AccessToken == "" {
					t.Errorf("Expected non-empty AccessToken, got empty string")
				}
				// Basic role check (assuming order doesn't matter)
				if len(respBody.Roles) != len(tt.expectInResponse.Roles) {
					t.Errorf("Expected %d roles, got %d", len(tt.expectInResponse.Roles), len(respBody.Roles))
				}
			}

			if tt.checkCookie {
				foundCookie := false
				for _, cookie := range rr.Result().Cookies() {
					if cookie.Name == cfg.RefreshTokenCookieName {
						foundCookie = true
						if cookie.Value == "" {
							t.Errorf("Expected non-empty refresh token cookie, got empty")
						}
						if !cookie.HttpOnly {
							t.Errorf("Expected refresh token cookie to be HttpOnly")
						}
						if cookie.Path != cfg.AuthBasePath {
							t.Errorf("Expected refresh token cookie path %q, got %q", cfg.AuthBasePath, cookie.Path)
						}
						break
					}
				}
				if !foundCookie {
					t.Errorf("Expected refresh token cookie %q to be set", cfg.RefreshTokenCookieName)
				}
			}
		})
	}
}

func TestAuthManager_LoginHandler(t *testing.T) {
	mockDB := NewMockAuthDatabase()
	authManager, cfg := newTestAuthManager(mockDB)
	router := mux.NewRouter()
	authManager.RegisterRoutes(router)

	// Pre-populate a user for login tests
	ctx := context.Background()
	validPassword := "correctpassword"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(validPassword), bcrypt.DefaultCost)
	loginRoles := []servex.UserRole{servex.UserRole("tester"), servex.UserRole("viewer")}
	_, _ = mockDB.NewUser(ctx, "loginuser", string(hashedPassword), loginRoles...)

	tests := []struct {
		name             string
		requestBody      servex.UserLoginRequest
		mockSetup        func()
		expectStatus     int
		expectInResponse *servex.UserLoginResponse // Pointer allows nil check
		checkCookie      bool
	}{
		{
			name:             "Successful login",
			requestBody:      servex.UserLoginRequest{Username: "loginuser", Password: validPassword},
			expectStatus:     http.StatusOK,
			expectInResponse: &servex.UserLoginResponse{Username: "loginuser", Roles: loginRoles}, // ID and AccessToken are generated
			checkCookie:      true,
		},
		{
			name:         "Invalid password",
			requestBody:  servex.UserLoginRequest{Username: "loginuser", Password: "wrongpassword"},
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:         "User not found",
			requestBody:  servex.UserLoginRequest{Username: "nosuchuser", Password: "password"},
			expectStatus: http.StatusUnauthorized, // Should return unauthorized for non-existent user for security
		},
		{
			name:         "Invalid request body (missing password)",
			requestBody:  servex.UserLoginRequest{Username: "loginuser"},
			expectStatus: http.StatusBadRequest,
		},
		{
			name:        "Database error on FindByUsername",
			requestBody: servex.UserLoginRequest{Username: "loginuser", Password: validPassword},
			mockSetup: func() {
				mockDB.SimulateErrorOnFindByUsername = true // Reset after test run
			},
			expectStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB.SimulateErrorOnFindByUsername = false // Ensure reset before test
			if tt.mockSetup != nil {
				tt.mockSetup()
			}

			req := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/login", tt.requestBody)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectStatus, rr.Code, rr.Body.String())
			}

			if tt.expectInResponse != nil {
				var respBody servex.UserLoginResponse
				decodeJsonResponse(t, rr, &respBody)
				if respBody.Username != tt.expectInResponse.Username {
					t.Errorf("Expected username %q, got %q", tt.expectInResponse.Username, respBody.Username)
				}
				if respBody.ID == "" {
					t.Errorf("Expected non-empty ID, got empty string")
				}
				if respBody.AccessToken == "" {
					t.Errorf("Expected non-empty AccessToken, got empty string")
				}
				// Basic role check
				if len(respBody.Roles) != len(tt.expectInResponse.Roles) {
					t.Errorf("Expected %d roles, got %d", len(tt.expectInResponse.Roles), len(respBody.Roles))
				}
			}

			if tt.checkCookie {
				foundCookie := false
				for _, cookie := range rr.Result().Cookies() {
					if cookie.Name == cfg.RefreshTokenCookieName {
						foundCookie = true
						break
					}
				}
				if !foundCookie {
					t.Errorf("Expected refresh token cookie %q to be set", cfg.RefreshTokenCookieName)
				}
			}
		})
	}
}

func TestAuthManager_GetCurrentUserHandler(t *testing.T) {
	mockDB := NewMockAuthDatabase()
	authManager, cfg := newTestAuthManager(mockDB)
	router := mux.NewRouter()
	authManager.RegisterRoutes(router) // This sets up the /me route with WithAuth implicitly

	// Create a user and generate a valid token for testing
	ctx := context.Background()
	currentUserRoles := []servex.UserRole{servex.UserRole("current"), servex.UserRole("getter")}
	currentUserID, err := mockDB.NewUser(ctx, "currentuser", "hashedpass", currentUserRoles...)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Manually generate an access token (mimicking internal logic for testing)
	accessSecretBytes, err := hex.DecodeString(cfg.JWTAccessSecret) // Decode the hex secret
	if err != nil {
		t.Fatalf("Failed to decode test access secret: %v", err)
	}
	accessClaims := jwt.MapClaims{
		"user_id": currentUserID,
		"roles":   currentUserRoles,
		"iss":     cfg.IssuerNameInJWT,
		"exp":     time.Now().Add(cfg.AccessTokenDuration).Unix(),
		"iat":     time.Now().Unix(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	validTokenString, err := accessToken.SignedString(accessSecretBytes) // Use the decoded secret bytes
	if err != nil {
		t.Fatalf("Failed to sign test token: %v", err)
	}

	expiredTokenClaims := jwt.MapClaims{
		"user_id": currentUserID,
		"roles":   currentUserRoles,
		"iss":     cfg.IssuerNameInJWT,
		"exp":     time.Now().Add(-5 * time.Minute).Unix(), // Expired
		"iat":     time.Now().Add(-10 * time.Minute).Unix(),
	}
	expiredAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredTokenClaims)
	expiredTokenString, _ := expiredAccessToken.SignedString(accessSecretBytes) // Use the decoded secret bytes

	tests := []struct {
		name             string
		authHeader       string
		mockSetup        func()
		expectStatus     int
		expectInResponse *servex.UserLoginResponse // Check subset of fields
	}{
		{
			name:         "Successful get current user",
			authHeader:   "Bearer " + validTokenString,
			expectStatus: http.StatusOK,
			expectInResponse: &servex.UserLoginResponse{
				ID:       currentUserID,
				Username: "currentuser",
				Roles:    currentUserRoles,
			},
		},
		{
			name:         "No Authorization header",
			authHeader:   "",
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:         "Malformed Authorization header",
			authHeader:   "BearerTokenWithoutSpace",
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:         "Invalid token signature",
			authHeader:   "Bearer " + validTokenString + "invalid",
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:         "Expired token",
			authHeader:   "Bearer " + expiredTokenString,
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:       "Database error finding user",
			authHeader: "Bearer " + validTokenString,
			mockSetup: func() {
				mockDB.SimulateErrorOnFindByID = true // Reset after test run
			},
			expectStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB.SimulateErrorOnFindByID = false // Reset before test
			if tt.mockSetup != nil {
				tt.mockSetup()
			}

			req := newJsonRequest(http.MethodGet, cfg.AuthBasePath+"/me", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectStatus, rr.Code, rr.Body.String())
			}

			if tt.expectInResponse != nil {
				var respBody servex.UserLoginResponse
				decodeJsonResponse(t, rr, &respBody)
				if respBody.ID != tt.expectInResponse.ID {
					t.Errorf("Expected ID %q, got %q", tt.expectInResponse.ID, respBody.ID)
				}
				if respBody.Username != tt.expectInResponse.Username {
					t.Errorf("Expected username %q, got %q", tt.expectInResponse.Username, respBody.Username)
				}
				if len(respBody.Roles) != len(tt.expectInResponse.Roles) {
					t.Errorf("Expected %d roles, got %d", len(tt.expectInResponse.Roles), len(respBody.Roles))
				} else {
					// Simple check if role strings match (ignoring order for now)
					expectedRoleStrings := make(map[string]bool)
					for _, role := range tt.expectInResponse.Roles {
						expectedRoleStrings[string(role)] = true
					}
					for _, role := range respBody.Roles {
						if !expectedRoleStrings[string(role)] {
							t.Errorf("Unexpected role %q found in response", role)
						}
					}
				}
				// Note: AccessToken should NOT be in the /me response
				if respBody.AccessToken != "" {
					t.Errorf("Expected empty AccessToken in /me response, got %q", respBody.AccessToken)
				}
			}
		})
	}
}

var (
	defaultAlphabet = []byte("0123456789abcdef")
	alphabetLen     = uint8(len(defaultAlphabet))
)

func getRandomBytes(n int) []byte {
	out := make([]byte, n)
	_, err := rand.Read(out)
	if err != nil {
		r := mr.New(mr.NewSource(time.Now().UnixNano()))
		for i := range out {
			out[i] = byte(r.Intn(math.MaxUint8))
		}
	}
	for i := range out {
		out[i] = defaultAlphabet[out[i]&(alphabetLen-1)]
	}
	return out
}

// Helper function to generate a refresh token and update the mock DB
func generateAndStoreRefreshToken(t *testing.T, cfg servex.AuthConfig, db *MockAuthDatabase, userID string) (*http.Cookie, string) {
	refreshSecretBytes, err := hex.DecodeString(cfg.JWTRefreshSecret)
	if err != nil {
		t.Fatalf("Failed to decode test refresh secret: %v", err)
	}

	expiresAt := time.Now().Add(cfg.RefreshTokenDuration)
	claims := jwt.MapClaims{
		"user_id": userID,
		// Roles are not typically included in refresh tokens in this implementation
		"is_refresh": true,
		"exp":        jwt.NewNumericDate(expiresAt).Unix(),
		"iat":        jwt.NewNumericDate(time.Now()).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(refreshSecretBytes)
	if err != nil {
		t.Fatalf("Failed to sign refresh token: %v", err)
	}

	// Hash the necessary part of the token
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(tokenString[:72]), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash refresh token: %v", err)
	}
	hashStr := string(tokenHash)

	// Update the user in the mock DB using the updated UpdateUser method
	err = db.UpdateUser(context.Background(), userID, &servex.UserDiff{
		RefreshTokenHash:      lang.Ptr(hashStr),
		RefreshTokenExpiresAt: lang.Ptr(expiresAt),
	})
	if err != nil {
		t.Fatalf("Failed to store refresh token hash in mock DB using UpdateUser: %v", err)
	}
	// Manually update RefreshTokenExpiresAt as UpdateUser still doesn't handle it
	// (Consider enhancing UpdateUser or adding a dedicated method if this becomes common)
	db.mu.Lock()
	user, exists := db.usersByID[userID]
	if !exists {
		db.mu.Unlock()
		t.Fatalf("User %s not found in mock DB after UpdateUser during refresh token generation", userID)
	}
	user.RefreshTokenExpiresAt = expiresAt
	db.usersByID[userID] = user
	db.users[user.Username] = user
	db.mu.Unlock()

	cookie := &http.Cookie{
		Name:  cfg.RefreshTokenCookieName,
		Value: tokenString,
		Path:  cfg.AuthBasePath,
	}
	return cookie, tokenString
}

func TestAuthManager_RefreshHandler(t *testing.T) {
	mockDB := NewMockAuthDatabase()
	authManager, cfg := newTestAuthManager(mockDB)
	router := mux.NewRouter()
	authManager.RegisterRoutes(router)

	// Create a user for refresh tests
	ctx := context.Background()
	refreshUserRoles := []servex.UserRole{servex.UserRole("refresher")}
	// refreshUserID, _ := mockDB.NewUser(ctx, "refreshuser", "hashedpass", refreshUserRoles) // Declared but not used

	tests := []struct {
		name             string
		cookieToSend     *http.Cookie                    // For cases without setup
		mockSetup        func(t *testing.T) *http.Cookie // Setup returns the cookie to use
		expectStatus     int
		expectInResponse bool // Check for new access token
		checkCookie      bool // Check for new refresh token cookie
	}{
		{
			name: "Successful refresh",
			mockSetup: func(t *testing.T) *http.Cookie {
				mockDB.Reset()
				uid, _ := mockDB.NewUser(ctx, "refreshsuccess", "hp", refreshUserRoles...)
				cookie, _ := generateAndStoreRefreshToken(t, cfg, mockDB, uid)
				return cookie
			},
			expectStatus:     http.StatusOK,
			expectInResponse: true,
			checkCookie:      true,
		},
		{
			name:         "No refresh token cookie",
			cookieToSend: nil,
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:         "Invalid token signature",
			cookieToSend: &http.Cookie{Name: cfg.RefreshTokenCookieName, Value: "invalid.token.sig"},
			expectStatus: http.StatusUnauthorized,
		},
		{
			name: "Expired token (JWT)",
			mockSetup: func(t *testing.T) *http.Cookie {
				mockDB.Reset()
				uid, _ := mockDB.NewUser(ctx, "refreshexpiredjwt", "hp", refreshUserRoles...)
				// Generate explicitly expired token
				refreshSecretBytes, _ := hex.DecodeString(cfg.JWTRefreshSecret)
				expiredTime := time.Now().Add(-5 * time.Minute)
				claims := jwt.MapClaims{"user_id": uid, "is_refresh": true, "exp": jwt.NewNumericDate(expiredTime).Unix()}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString(refreshSecretBytes)
				hash, _ := bcrypt.GenerateFromPassword([]byte(tokenString[:72]), bcrypt.DefaultCost)
				hashStr := string(hash)
				_ = mockDB.UpdateUser(ctx, uid, &servex.UserDiff{
					RefreshTokenHash: lang.Ptr(hashStr),
				})
				mockDB.mu.Lock() // Use mockDB from outer scope
				user := mockDB.usersByID[uid]
				user.RefreshTokenExpiresAt = time.Now().Add(cfg.RefreshTokenDuration) // DB expiry is fine
				mockDB.usersByID[uid] = user
				mockDB.mu.Unlock()
				return &http.Cookie{Name: cfg.RefreshTokenCookieName, Value: tokenString, Path: cfg.AuthBasePath}
			},
			expectStatus: http.StatusUnauthorized,
		},
		{
			name: "Expired token (DB)",
			mockSetup: func(t *testing.T) *http.Cookie {
				mockDB.Reset()
				uid, _ := mockDB.NewUser(ctx, "refreshexpireddb", "hp", refreshUserRoles...)
				cookie, _ := generateAndStoreRefreshToken(t, cfg, mockDB, uid)
				// Manually expire the token in the DB *after* generation
				mockDB.mu.Lock() // Use mockDB from outer scope
				user := mockDB.usersByID[uid]
				user.RefreshTokenExpiresAt = time.Now().Add(-1 * time.Minute)
				mockDB.usersByID[uid] = user
				mockDB.mu.Unlock()
				return cookie
			},
			expectStatus: http.StatusUnauthorized,
		},
		{
			name: "Token hash mismatch",
			mockSetup: func(t *testing.T) *http.Cookie {
				mockDB.Reset()
				uid, _ := mockDB.NewUser(ctx, "refreshmismatch", "hp", refreshUserRoles...)
				cookie, _ := generateAndStoreRefreshToken(t, cfg, mockDB, uid)
				// Directly overwrite the RefreshTokenHash in the mock DB
				mockDB.mu.Lock()
				user := mockDB.usersByID[uid]
				user.RefreshTokenHash = "thisisawronghash"
				mockDB.usersByID[uid] = user
				mockDB.users[user.Username] = user // Keep username map consistent
				mockDB.mu.Unlock()
				return cookie
			},
			expectStatus: http.StatusUnauthorized,
		},
		{
			name: "User not found",
			mockSetup: func(t *testing.T) *http.Cookie {
				mockDB.Reset()
				uid, _ := mockDB.NewUser(ctx, "refreshdeleted", "hp", refreshUserRoles...)
				cookie, _ := generateAndStoreRefreshToken(t, cfg, mockDB, uid)
				// Delete user from DB after generating token
				mockDB.mu.Lock() // Use mockDB from outer scope
				delete(mockDB.usersByID, uid)
				delete(mockDB.users, "refreshdeleted")
				mockDB.mu.Unlock()
				return cookie
			},
			expectStatus: http.StatusUnauthorized,
		},
		{
			name: "Database error on FindByID",
			mockSetup: func(t *testing.T) *http.Cookie {
				mockDB.Reset()
				uid, _ := mockDB.NewUser(ctx, "refreshfinderror", "hp", refreshUserRoles...)
				cookie, _ := generateAndStoreRefreshToken(t, cfg, mockDB, uid)
				mockDB.SimulateErrorOnFindByID = true
				return cookie
			},
			expectStatus: http.StatusUnauthorized, // Service layer wraps DB errors
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			currentCookie := tt.cookieToSend       // Use explicitly defined cookie by default
			mockDB.SimulateErrorOnFindByID = false // Reset simulation flags
			if tt.mockSetup != nil {
				currentCookie = tt.mockSetup(t) // mockSetup provides the cookie to use
			}

			req := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/refresh", nil)
			if currentCookie != nil {
				req.AddCookie(currentCookie)
			}
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectStatus, rr.Code, rr.Body.String())
			}

			if tt.expectInResponse {
				var respBody servex.UserLoginResponse
				decodeJsonResponse(t, rr, &respBody)
				if respBody.AccessToken == "" {
					t.Errorf("Expected non-empty AccessToken in refresh response")
				}
			}

			if tt.checkCookie {
				foundCookie := false
				for _, cookie := range rr.Result().Cookies() {
					if cookie.Name == cfg.RefreshTokenCookieName {
						foundCookie = true
						if cookie.Value == "" || (currentCookie != nil && cookie.Value == currentCookie.Value) {
							t.Errorf("Expected a *new*, non-empty refresh token cookie value")
						}
						break
					}
				}
				if !foundCookie {
					t.Errorf("Expected refresh token cookie %q to be set", cfg.RefreshTokenCookieName)
				}
			}
		})
	}
}

func TestAuthManager_LogoutHandler(t *testing.T) {
	mockDB := NewMockAuthDatabase()
	authManager, cfg := newTestAuthManager(mockDB)
	router := mux.NewRouter()
	authManager.RegisterRoutes(router)

	// Create a user and token for logout tests
	ctx := context.Background()
	logoutUserID, _ := mockDB.NewUser(ctx, "logoutuser", "hp", servex.UserRole("logger"))
	validCookie, _ := generateAndStoreRefreshToken(t, cfg, mockDB, logoutUserID)

	tests := []struct {
		name           string
		cookieToSend   *http.Cookie
		mockSetup      func()
		expectStatus   int
		checkDbCleared bool // Check if the refresh token hash was cleared for the user
		checkCookieSet bool // Check if the logout cookie was set
	}{
		{
			name:           "Successful logout",
			cookieToSend:   validCookie,
			expectStatus:   http.StatusNoContent,
			checkDbCleared: true,
			checkCookieSet: true,
		},
		{
			name:           "Logout with no cookie",
			cookieToSend:   nil,
			expectStatus:   http.StatusNoContent,
			checkDbCleared: false, // Should not attempt to clear if no cookie
			checkCookieSet: true,
		},
		{
			name:           "Logout with invalid token cookie",
			cookieToSend:   &http.Cookie{Name: cfg.RefreshTokenCookieName, Value: "invalid"},
			expectStatus:   http.StatusNoContent,
			checkDbCleared: false, // Should not clear DB if token is invalid
			checkCookieSet: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset DB state if needed (e.g., re-hash token before test)
			if tt.checkDbCleared {
				_, _ = generateAndStoreRefreshToken(t, cfg, mockDB, logoutUserID)
			}
			if tt.mockSetup != nil {
				tt.mockSetup()
			}

			req := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/logout", nil)
			if tt.cookieToSend != nil {
				req.AddCookie(tt.cookieToSend)
			}
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectStatus, rr.Code, rr.Body.String())
			}

			if tt.checkDbCleared {
				user, exists, _ := mockDB.FindByID(ctx, logoutUserID)
				if !exists {
					t.Fatalf("Test user %s disappeared during logout check", logoutUserID)
				}
				if user.RefreshTokenHash != "" {
					t.Errorf("Expected RefreshTokenHash to be cleared in DB after logout, but was %q", user.RefreshTokenHash)
				}
			}

			if tt.checkCookieSet {
				foundCookie := false
				for _, cookie := range rr.Result().Cookies() {
					if cookie.Name == cfg.RefreshTokenCookieName {
						foundCookie = true
						if cookie.Value != "" || cookie.MaxAge != -1 {
							t.Errorf("Expected logout cookie to have empty value and MaxAge -1, got value=%q, maxAge=%d", cookie.Value, cookie.MaxAge)
						}
						break
					}
				}
				if !foundCookie {
					t.Errorf("Expected logout cookie %q to be set", cfg.RefreshTokenCookieName)
				}
			}
		})
	}
}
