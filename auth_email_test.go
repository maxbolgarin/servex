package servex_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/maxbolgarin/lang"
	"github.com/maxbolgarin/servex/v2"
	"golang.org/x/crypto/bcrypt"
)

// MockEmailSender records email sending calls for testing.
type MockEmailSender struct {
	mu                     sync.Mutex
	VerificationEmails     []mockEmail
	PasswordResetEmails    []mockEmail
	TwoFactorCodeEmails    []mockEmail
	SimulateError          bool
}

type mockEmail struct {
	To    string
	Token string
}

func (m *MockEmailSender) SendVerificationEmail(_ context.Context, to, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.SimulateError {
		return errMockEmail
	}
	m.VerificationEmails = append(m.VerificationEmails, mockEmail{To: to, Token: token})
	return nil
}

func (m *MockEmailSender) SendPasswordResetEmail(_ context.Context, to, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.SimulateError {
		return errMockEmail
	}
	m.PasswordResetEmails = append(m.PasswordResetEmails, mockEmail{To: to, Token: token})
	return nil
}

func (m *MockEmailSender) SendTwoFactorCodeEmail(_ context.Context, to, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.SimulateError {
		return errMockEmail
	}
	m.TwoFactorCodeEmails = append(m.TwoFactorCodeEmails, mockEmail{To: to, Token: code})
	return nil
}

var errMockEmail = servex.ErrMockEmail

// newTestAuthManagerWithEmail creates an AuthManager configured with email features enabled.
func newTestAuthManagerWithEmail(t *testing.T, sender *MockEmailSender) (*servex.AuthManager, *servex.MemoryAuthDatabase) {
	t.Helper()
	db := servex.NewMemoryAuthDatabase()
	cfg := servex.AuthConfig{
		Enabled:             true,
		Database:            db,
		JWTAccessSecret:     hex.EncodeToString(getRandomBytes(32)),
		JWTRefreshSecret:    hex.EncodeToString(getRandomBytes(32)),
		AccessTokenDuration: 5 * time.Minute,
		RefreshTokenDuration: 10 * time.Minute,
		IssuerNameInJWT:     "test-issuer",
		RolesOnRegister:     []servex.UserRole{"user"},
		Email: servex.EmailConfig{
			Enabled:             true,
			Sender:              sender,
			VerifyTokenDuration: 24 * time.Hour,
			ResetTokenDuration:  time.Hour,
			ResendCooldown:      60 * time.Second,
		},
	}
	am, err := servex.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth manager with email: %v", err)
	}
	return am, db
}

// createTestUserWithEmail creates a test user in the MemoryAuthDatabase with an email address.
func createTestUserWithEmail(t *testing.T, db *servex.MemoryAuthDatabase, username, password, email string) servex.User {
	t.Helper()
	ctx := context.Background()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	id, err := db.NewUser(ctx, username, string(hashedPassword), "user")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	if email != "" {
		if err := db.UpdateUser(ctx, id, &servex.UserDiff{
			Email: lang.Ptr(email),
		}); err != nil {
			t.Fatalf("Failed to set email: %v", err)
		}
	}
	user, _, _ := db.FindByID(ctx, id)
	return user
}

// setVerificationToken sets a verification token for a user and returns the raw token.
func setVerificationToken(t *testing.T, db *servex.MemoryAuthDatabase, userID string, expiresAt time.Time) string {
	t.Helper()
	randomPart := hex.EncodeToString(getRandomBytes(32))
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(randomPart), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash token: %v", err)
	}
	if err := db.UpdateUser(context.Background(), userID, &servex.UserDiff{
		EmailVerifyTokenHash:      lang.Ptr(string(hashBytes)),
		EmailVerifyTokenExpiresAt: lang.Ptr(expiresAt),
	}); err != nil {
		t.Fatalf("Failed to set verify token: %v", err)
	}
	return userID + ":" + randomPart
}

// setResetToken sets a password reset token for a user and returns the raw token.
func setResetToken(t *testing.T, db *servex.MemoryAuthDatabase, userID string, expiresAt time.Time) string {
	t.Helper()
	randomPart := hex.EncodeToString(getRandomBytes(32))
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(randomPart), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash token: %v", err)
	}
	if err := db.UpdateUser(context.Background(), userID, &servex.UserDiff{
		PasswordResetTokenHash:      lang.Ptr(string(hashBytes)),
		PasswordResetTokenExpiresAt: lang.Ptr(expiresAt),
	}); err != nil {
		t.Fatalf("Failed to set reset token: %v", err)
	}
	return userID + ":" + randomPart
}

func TestVerifyEmailHandler(t *testing.T) {
	tests := []struct {
		name           string
		setupUser      func(t *testing.T, db *servex.MemoryAuthDatabase) string // returns token
		expectedStatus int
		checkVerified  bool // if true, verify user.EmailVerified is set
	}{
		{
			name: "valid token verifies email",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase) string {
				user := createTestUserWithEmail(t, db, "john", "password123", "john@example.com")
				return setVerificationToken(t, db, user.ID, time.Now().Add(24*time.Hour))
			},
			expectedStatus: http.StatusOK,
			checkVerified:  true,
		},
		{
			name: "expired token fails",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase) string {
				user := createTestUserWithEmail(t, db, "jane", "password123", "jane@example.com")
				return setVerificationToken(t, db, user.ID, time.Now().Add(-1*time.Hour))
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "invalid token fails",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase) string {
				createTestUserWithEmail(t, db, "bob", "password123", "bob@example.com")
				return "nonexistent-user:invalidtoken"
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "malformed token (no colon) fails",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase) string {
				createTestUserWithEmail(t, db, "alice", "password123", "alice@example.com")
				return "notokencolon"
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "wrong token value fails",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase) string {
				user := createTestUserWithEmail(t, db, "charlie", "password123", "charlie@example.com")
				setVerificationToken(t, db, user.ID, time.Now().Add(24*time.Hour))
				return user.ID + ":wrongtokenvalue"
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &MockEmailSender{}
			am, db := newTestAuthManagerWithEmail(t, sender)

			token := tc.setupUser(t, db)

			body, _ := json.Marshal(map[string]string{"token": token})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify-email", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			router := mux.NewRouter()
			am.RegisterRoutes(router)
			router.ServeHTTP(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d; body: %s", tc.expectedStatus, rr.Code, rr.Body.String())
			}

			if tc.checkVerified {
				// Extract user ID from token
				parts := strings.SplitN(token, ":", 2)
				user, _, err := db.FindByID(context.Background(), parts[0])
				if err != nil {
					t.Fatalf("Failed to find user: %v", err)
				}
				if !user.EmailVerified {
					t.Error("expected EmailVerified to be true")
				}
				if user.EmailVerifyTokenHash != "" {
					t.Error("expected EmailVerifyTokenHash to be cleared")
				}
			}
		})
	}
}

func TestResendVerificationHandler(t *testing.T) {
	tests := []struct {
		name           string
		setupUser      func(t *testing.T, db *servex.MemoryAuthDatabase, am *servex.AuthManager) (userID string)
		expectedStatus int
		checkEmailSent bool
	}{
		{
			name: "successful resend",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase, am *servex.AuthManager) string {
				user := createTestUserWithEmail(t, db, "resenduser", "password123", "resend@example.com")
				return user.ID
			},
			expectedStatus: http.StatusOK,
			checkEmailSent: true,
		},
		{
			name: "cooldown returns 429",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase, am *servex.AuthManager) string {
				user := createTestUserWithEmail(t, db, "cooldownuser", "password123", "cooldown@example.com")
				// Set last sent time to now (within cooldown)
				if err := db.UpdateUser(context.Background(), user.ID, &servex.UserDiff{
					EmailVerifyLastSentAt: lang.Ptr(time.Now()),
				}); err != nil {
					t.Fatalf("Failed to update last sent at: %v", err)
				}
				return user.ID
			},
			expectedStatus: http.StatusTooManyRequests,
		},
		{
			name: "already verified returns 400",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase, am *servex.AuthManager) string {
				user := createTestUserWithEmail(t, db, "verifieduser", "password123", "verified@example.com")
				if err := db.UpdateUser(context.Background(), user.ID, &servex.UserDiff{
					EmailVerified: lang.Ptr(true),
				}); err != nil {
					t.Fatalf("Failed to mark verified: %v", err)
				}
				return user.ID
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &MockEmailSender{}
			am, db := newTestAuthManagerWithEmail(t, sender)

			userID := tc.setupUser(t, db, am)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/resend-verification", nil)
			req.Header.Set("Content-Type", "application/json")

			// Add auth context: simulate authenticated request by setting context values
			ctx := context.WithValue(req.Context(), servex.UserContextKey{}, userID)
			ctx = context.WithValue(ctx, servex.RoleContextKey{}, []servex.UserRole{"user"})
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()

			// Call handler directly with auth context already set (bypassing WithAuth middleware)
			am.ResendVerificationHandler(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d; body: %s", tc.expectedStatus, rr.Code, rr.Body.String())
			}

			if tc.checkEmailSent {
				sender.mu.Lock()
				sent := len(sender.VerificationEmails)
				sender.mu.Unlock()
				if sent != 1 {
					t.Errorf("expected 1 verification email sent, got %d", sent)
				}
			}
		})
	}
}

func TestForgotPasswordHandler(t *testing.T) {
	tests := []struct {
		name           string
		identifier     string
		setupUser      func(t *testing.T, db *servex.MemoryAuthDatabase)
		expectedStatus int
		checkEmailSent bool
	}{
		{
			name:       "existing user with email (by email) returns 200",
			identifier: "forgot@example.com",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase) {
				createTestUserWithEmail(t, db, "forgotuser", "password123", "forgot@example.com")
			},
			expectedStatus: http.StatusOK,
			checkEmailSent: true,
		},
		{
			name:       "existing user with email (by username) returns 200",
			identifier: "forgotuser2",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase) {
				createTestUserWithEmail(t, db, "forgotuser2", "password123", "forgot2@example.com")
			},
			expectedStatus: http.StatusOK,
			checkEmailSent: true,
		},
		{
			name:       "nonexistent user returns 200 (no enumeration)",
			identifier: "nobody@example.com",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase) {
				// No user created
			},
			expectedStatus: http.StatusOK,
			checkEmailSent: false,
		},
		{
			name:       "user without email returns 200 (no email sent)",
			identifier: "noemailuser",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase) {
				createTestUserWithEmail(t, db, "noemailuser", "password123", "")
			},
			expectedStatus: http.StatusOK,
			checkEmailSent: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &MockEmailSender{}
			am, db := newTestAuthManagerWithEmail(t, sender)

			tc.setupUser(t, db)

			body, _ := json.Marshal(map[string]string{"identifier": tc.identifier})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/forgot-password", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			router := mux.NewRouter()
			am.RegisterRoutes(router)
			router.ServeHTTP(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d; body: %s", tc.expectedStatus, rr.Code, rr.Body.String())
			}

			// Verify response always has the same message
			var resp map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}
			if resp["message"] != "if the account exists, a reset link has been sent" {
				t.Errorf("unexpected message: %s", resp["message"])
			}

			sender.mu.Lock()
			sent := len(sender.PasswordResetEmails)
			sender.mu.Unlock()
			if tc.checkEmailSent && sent != 1 {
				t.Errorf("expected 1 reset email sent, got %d", sent)
			}
			if !tc.checkEmailSent && sent != 0 {
				t.Errorf("expected 0 reset emails sent, got %d", sent)
			}
		})
	}
}

func TestResetPasswordHandler(t *testing.T) {
	tests := []struct {
		name           string
		newPassword    string
		setupUser      func(t *testing.T, db *servex.MemoryAuthDatabase) string // returns token
		expectedStatus int
		checkPassword  bool // if true, verify password was changed
	}{
		{
			name:        "valid token resets password",
			newPassword: "newpassword123",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase) string {
				user := createTestUserWithEmail(t, db, "resetuser", "oldpassword123", "reset@example.com")
				return setResetToken(t, db, user.ID, time.Now().Add(time.Hour))
			},
			expectedStatus: http.StatusOK,
			checkPassword:  true,
		},
		{
			name:        "expired token fails",
			newPassword: "newpassword123",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase) string {
				user := createTestUserWithEmail(t, db, "expiredresetuser", "oldpassword123", "expired@example.com")
				return setResetToken(t, db, user.ID, time.Now().Add(-1*time.Hour))
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "invalid token fails",
			newPassword: "newpassword123",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase) string {
				createTestUserWithEmail(t, db, "badtokenuser", "oldpassword123", "badtoken@example.com")
				return "nonexistent-user:invalidtoken"
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "malformed token (no colon) fails",
			newPassword: "newpassword123",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase) string {
				createTestUserWithEmail(t, db, "malformeduser", "oldpassword123", "malformed@example.com")
				return "notokencolon"
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "short password fails",
			newPassword: "short",
			setupUser: func(t *testing.T, db *servex.MemoryAuthDatabase) string {
				user := createTestUserWithEmail(t, db, "shortpwuser", "oldpassword123", "shortpw@example.com")
				return setResetToken(t, db, user.ID, time.Now().Add(time.Hour))
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &MockEmailSender{}
			am, db := newTestAuthManagerWithEmail(t, sender)

			token := tc.setupUser(t, db)

			body, _ := json.Marshal(map[string]string{"token": token, "password": tc.newPassword})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reset-password", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			router := mux.NewRouter()
			am.RegisterRoutes(router)
			router.ServeHTTP(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d; body: %s", tc.expectedStatus, rr.Code, rr.Body.String())
			}

			if tc.checkPassword {
				parts := strings.SplitN(token, ":", 2)
				user, _, err := db.FindByID(context.Background(), parts[0])
				if err != nil {
					t.Fatalf("Failed to find user: %v", err)
				}
				// Verify new password works
				if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(tc.newPassword)); err != nil {
					t.Error("new password does not match")
				}
				// Verify reset token was cleared
				if user.PasswordResetTokenHash != "" {
					t.Error("expected PasswordResetTokenHash to be cleared")
				}
				// Verify refresh token was cleared (force re-login)
				if user.RefreshTokenHash != "" {
					t.Error("expected RefreshTokenHash to be cleared")
				}
			}
		})
	}
}

func TestNewAuthManager_EmailValidation(t *testing.T) {
	tests := []struct {
		name      string
		db        servex.AuthDatabase
		expectErr bool
		errMsg    string
	}{
		{
			name:      "MemoryAuthDatabase implements EmailAuthDatabase",
			db:        servex.NewMemoryAuthDatabase(),
			expectErr: false,
		},
		{
			name:      "MockAuthDatabase does not implement EmailAuthDatabase",
			db:        NewMockAuthDatabase(),
			expectErr: true,
			errMsg:    "email auth requires AuthDatabase to implement EmailAuthDatabase",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := servex.AuthConfig{
				Enabled:          true,
				Database:         tc.db,
				JWTAccessSecret:  hex.EncodeToString(getRandomBytes(32)),
				JWTRefreshSecret: hex.EncodeToString(getRandomBytes(32)),
				Email: servex.EmailConfig{
					Enabled: true,
					Sender:  &MockEmailSender{},
				},
			}
			_, err := servex.NewAuthManager(cfg)
			if tc.expectErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("expected error containing %q, got %q", tc.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// newTestAuthManagerWithEmailRequireVerification creates an AuthManager with email enabled and RequireVerification=true.
func newTestAuthManagerWithEmailRequireVerification(t *testing.T, sender *MockEmailSender) (*servex.AuthManager, *servex.MemoryAuthDatabase) {
	t.Helper()
	db := servex.NewMemoryAuthDatabase()
	cfg := servex.AuthConfig{
		Enabled:              true,
		Database:             db,
		JWTAccessSecret:      hex.EncodeToString(getRandomBytes(32)),
		JWTRefreshSecret:     hex.EncodeToString(getRandomBytes(32)),
		AccessTokenDuration:  5 * time.Minute,
		RefreshTokenDuration: 10 * time.Minute,
		IssuerNameInJWT:      "test-issuer",
		RolesOnRegister:      []servex.UserRole{"user"},
		Email: servex.EmailConfig{
			Enabled:             true,
			Sender:              sender,
			RequireVerification: true,
			VerifyTokenDuration: 24 * time.Hour,
			ResetTokenDuration:  time.Hour,
			ResendCooldown:      60 * time.Second,
		},
	}
	am, err := servex.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}
	return am, db
}

// newTestAuthManagerWith2FABasic creates an AuthManager with 2FA enabled (basic config for login tests).
func newTestAuthManagerWith2FABasic(t *testing.T) (*servex.AuthManager, *servex.MemoryAuthDatabase) {
	t.Helper()
	db := servex.NewMemoryAuthDatabase()
	cfg := servex.AuthConfig{
		Enabled:              true,
		Database:             db,
		JWTAccessSecret:      hex.EncodeToString(getRandomBytes(32)),
		JWTRefreshSecret:     hex.EncodeToString(getRandomBytes(32)),
		AccessTokenDuration:  5 * time.Minute,
		RefreshTokenDuration: 10 * time.Minute,
		IssuerNameInJWT:      "test-issuer",
		RolesOnRegister:      []servex.UserRole{"user"},
		TwoFactor: servex.TwoFactorConfig{
			Enabled:       true,
			EncryptionKey: hex.EncodeToString(getRandomBytes(32)),
		},
	}
	am, err := servex.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}
	return am, db
}

func TestRegisterWithEmailSendsVerification(t *testing.T) {
	sender := &MockEmailSender{}
	am, db := newTestAuthManagerWithEmail(t, sender)

	router := mux.NewRouter()
	am.RegisterRoutes(router)

	body, _ := json.Marshal(servex.RegisterRequest{
		Username: "emailuser",
		Password: "password123",
		Email:    "emailuser@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d; body: %s", rr.Code, rr.Body.String())
	}

	// Verify email sender was called
	sender.mu.Lock()
	sent := len(sender.VerificationEmails)
	var sentTo string
	if sent > 0 {
		sentTo = sender.VerificationEmails[0].To
	}
	sender.mu.Unlock()

	if sent != 1 {
		t.Fatalf("expected 1 verification email sent, got %d", sent)
	}
	if sentTo != "emailuser@example.com" {
		t.Errorf("expected email sent to emailuser@example.com, got %s", sentTo)
	}

	// Since RequireVerification is false by default, tokens should be returned
	var resp servex.UserLoginResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected accessToken in response when RequireVerification is false")
	}
	if resp.Username != "emailuser" {
		t.Errorf("expected username 'emailuser', got %q", resp.Username)
	}

	// Verify user has email and verification token stored in DB
	users, err := db.FindAll(context.Background())
	if err != nil {
		t.Fatalf("failed to find users: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	user := users[0]
	if user.Email != "emailuser@example.com" {
		t.Errorf("expected email 'emailuser@example.com', got %q", user.Email)
	}
	if user.EmailVerifyTokenHash == "" {
		t.Error("expected EmailVerifyTokenHash to be set")
	}
	if user.EmailVerifyTokenExpiresAt.IsZero() {
		t.Error("expected EmailVerifyTokenExpiresAt to be set")
	}
}

func TestRegisterWithoutEmailNoVerification(t *testing.T) {
	sender := &MockEmailSender{}
	am, _ := newTestAuthManagerWithEmail(t, sender)

	router := mux.NewRouter()
	am.RegisterRoutes(router)

	// Register without email — should behave exactly like before
	body, _ := json.Marshal(servex.RegisterRequest{
		Username: "noemailer",
		Password: "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d; body: %s", rr.Code, rr.Body.String())
	}

	// Verify no email was sent
	sender.mu.Lock()
	sent := len(sender.VerificationEmails)
	sender.mu.Unlock()
	if sent != 0 {
		t.Errorf("expected 0 verification emails sent, got %d", sent)
	}

	// Tokens should be returned normally
	var resp servex.UserLoginResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected accessToken in response")
	}
}

func TestRegisterRequireVerificationNoTokens(t *testing.T) {
	sender := &MockEmailSender{}
	am, _ := newTestAuthManagerWithEmailRequireVerification(t, sender)

	router := mux.NewRouter()
	am.RegisterRoutes(router)

	body, _ := json.Marshal(servex.RegisterRequest{
		Username: "verifyuser",
		Password: "password123",
		Email:    "verifyuser@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d; body: %s", rr.Code, rr.Body.String())
	}

	// Verify email was sent
	sender.mu.Lock()
	sent := len(sender.VerificationEmails)
	sender.mu.Unlock()
	if sent != 1 {
		t.Errorf("expected 1 verification email sent, got %d", sent)
	}

	// Response should have message, NOT accessToken
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["message"] != "check your email to verify your account" {
		t.Errorf("expected verification message, got %q", resp["message"])
	}
	if resp["accessToken"] != "" {
		t.Error("expected no accessToken in response when RequireVerification is true")
	}

	// Verify no auth cookie was set
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "_servexrt" {
			t.Error("expected no refresh token cookie when RequireVerification is true")
		}
	}
}

func TestLoginWith2FAReturnsPendingToken(t *testing.T) {
	am, db := newTestAuthManagerWith2FABasic(t)
	defer am.StopAttemptTracker()

	router := mux.NewRouter()
	am.RegisterRoutes(router)

	// Create a user with 2FA enabled
	password := "password123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	id, err := db.NewUser(context.Background(), "twofa_user", string(hashedPassword), "user")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	if err := db.UpdateUser(context.Background(), id, &servex.UserDiff{
		TwoFactorEnabled: lang.Ptr(true),
	}); err != nil {
		t.Fatalf("failed to enable 2FA: %v", err)
	}

	// Login
	body, _ := json.Marshal(servex.UserLoginRequest{
		Username: "twofa_user",
		Password: password,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	// Response should have twoFactorToken, NOT accessToken
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["twoFactorToken"] == "" {
		t.Error("expected twoFactorToken in response")
	}
	if resp["accessToken"] != "" {
		t.Error("expected no accessToken when 2FA is required")
	}

	// Verify no auth cookie was set
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "_servexrt" {
			t.Error("expected no refresh token cookie when 2FA is required")
		}
	}
}

func TestLoginWithout2FAReturnsTokensNormally(t *testing.T) {
	am, db := newTestAuthManagerWith2FABasic(t)
	defer am.StopAttemptTracker()

	router := mux.NewRouter()
	am.RegisterRoutes(router)

	// Create a user WITHOUT 2FA enabled
	password := "password123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	_, err = db.NewUser(context.Background(), "normal_user", string(hashedPassword), "user")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Login
	body, _ := json.Marshal(servex.UserLoginRequest{
		Username: "normal_user",
		Password: password,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	// Response should have accessToken, NOT twoFactorToken
	var resp servex.UserLoginResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected accessToken in response when user has 2FA disabled")
	}

	// Verify auth cookie was set
	foundCookie := false
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "_servexrt" {
			foundCookie = true
			break
		}
	}
	if !foundCookie {
		t.Error("expected refresh token cookie to be set when 2FA is not required")
	}
}

func TestGenerateEmailToken(t *testing.T) {
	token, hash, err := servex.ExportGenerateEmailToken("user-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == "" || hash == "" {
		t.Fatal("expected non-empty token and hash")
	}
	if !strings.HasPrefix(token, "user-123:") {
		t.Errorf("expected token to start with 'user-123:', got %q", token)
	}
	// Verify the hash matches the token's random part
	parts := strings.SplitN(token, ":", 2)
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(parts[1])); err != nil {
		t.Error("hash does not match token's random part")
	}
}
