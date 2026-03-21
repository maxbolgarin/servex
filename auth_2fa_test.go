package servex_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/maxbolgarin/lang"
	"github.com/maxbolgarin/servex/v2"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// newTestAuthManagerWith2FA creates an AuthManager configured with 2FA enabled.
func newTestAuthManagerWith2FA(t *testing.T) (*servex.AuthManager, servex.AuthConfig, *servex.MemoryAuthDatabase) {
	t.Helper()
	db := servex.NewMemoryAuthDatabase()
	encKey := hex.EncodeToString(getRandomBytes(32))
	cfg := servex.AuthConfig{
		Enabled:                true,
		Database:               db,
		JWTAccessSecret:        hex.EncodeToString(getRandomBytes(32)),
		JWTRefreshSecret:       hex.EncodeToString(getRandomBytes(32)),
		AccessTokenDuration:    5 * time.Minute,
		RefreshTokenDuration:   10 * time.Minute,
		IssuerNameInJWT:        "test-issuer",
		AuthBasePath:           "/api/v1/auth",
		RefreshTokenCookieName: "_servexrt",
		RolesOnRegister:        []servex.UserRole{"user"},
		TwoFactor: servex.TwoFactorConfig{
			Enabled:           true,
			EncryptionKey:     encKey,
			Issuer:            "test-app",
			BackupCodes:       5,
			MaxVerifyAttempts: 3,
		},
	}
	am, err := servex.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth manager with 2FA: %v", err)
	}
	return am, cfg, db
}

// createTestUserFor2FA creates a test user and returns the user and a valid access token.
func createTestUserFor2FA(t *testing.T, db *servex.MemoryAuthDatabase, cfg servex.AuthConfig, username, password string) (servex.User, string) {
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
	user, _, _ := db.FindByID(ctx, id)

	// Generate access token
	accessSecretBytes, err := hex.DecodeString(cfg.JWTAccessSecret)
	if err != nil {
		t.Fatalf("Failed to decode access secret: %v", err)
	}
	claims := jwt.MapClaims{
		"user_id": id,
		"roles":   []string{"user"},
		"iss":     cfg.IssuerNameInJWT,
		"exp":     time.Now().Add(cfg.AccessTokenDuration).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(accessSecretBytes)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	return user, tokenString
}

// generate2FAPendingToken creates a pending 2FA token for the given user.
func generate2FAPendingToken(t *testing.T, cfg servex.AuthConfig, userID string) string {
	t.Helper()
	accessSecretBytes, err := hex.DecodeString(cfg.JWTAccessSecret)
	if err != nil {
		t.Fatalf("Failed to decode access secret: %v", err)
	}
	claims := jwt.MapClaims{
		"user_id": userID,
		"purpose": "2fa_pending",
		"jti":     hex.EncodeToString(getRandomBytes(16)),
		"iss":     cfg.IssuerNameInJWT,
		"exp":     time.Now().Add(5 * time.Minute).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(accessSecretBytes)
	if err != nil {
		t.Fatalf("Failed to sign 2FA pending token: %v", err)
	}
	return tokenString
}

func TestAESGCMEncryptDecrypt(t *testing.T) {
	key := getRandomBytes(32)
	plaintext := "JBSWY3DPEHPK3PXP"

	encrypted, err := servex.ExportEncryptTOTPSecret(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if encrypted == plaintext {
		t.Fatal("Encrypted text should differ from plaintext")
	}

	decrypted, err := servex.ExportDecryptTOTPSecret(encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Round-trip failed: got %q, want %q", decrypted, plaintext)
	}

	// Wrong key should fail
	wrongKey := getRandomBytes(32)
	_, err = servex.ExportDecryptTOTPSecret(encrypted, wrongKey)
	if err == nil {
		t.Error("Decrypt with wrong key should fail")
	}
}

func TestAttemptTracker(t *testing.T) {
	tracker := servex.ExportNewAttemptTracker()
	defer tracker.Stop()

	jti := "test-jti-123"

	// Initial count should be 0
	if got := tracker.GetCount(jti); got != 0 {
		t.Errorf("Initial count: got %d, want 0", got)
	}

	// Increment
	if got := tracker.Increment(jti); got != 1 {
		t.Errorf("After 1st increment: got %d, want 1", got)
	}
	if got := tracker.Increment(jti); got != 2 {
		t.Errorf("After 2nd increment: got %d, want 2", got)
	}
	if got := tracker.GetCount(jti); got != 2 {
		t.Errorf("GetCount: got %d, want 2", got)
	}

	// Delete
	tracker.Delete(jti)
	if got := tracker.GetCount(jti); got != 0 {
		t.Errorf("After delete: got %d, want 0", got)
	}
}

func TestAttemptTrackerEmailCooldown(t *testing.T) {
	tracker := servex.ExportNewAttemptTracker()
	defer tracker.Stop()

	jti := "email-test-jti"

	// Should be able to send initially
	if !tracker.CanSendEmail(jti, 60*time.Second) {
		t.Error("Should be able to send email initially")
	}

	// Mark email sent
	tracker.MarkEmailSent(jti, "somehash")

	// Should NOT be able to send immediately after
	if tracker.CanSendEmail(jti, 60*time.Second) {
		t.Error("Should not be able to send email within cooldown")
	}

	// Should be able to send with zero cooldown
	if !tracker.CanSendEmail(jti, 0) {
		t.Error("Should be able to send email with zero cooldown")
	}

	// Verify email code hash is stored
	hash := tracker.GetEmailCodeHash(jti)
	if hash != "somehash" {
		t.Errorf("Email code hash: got %q, want %q", hash, "somehash")
	}
}

func TestGenerateBackupCodes(t *testing.T) {
	count := 8
	plain, hashed, err := servex.ExportGenerateBackupCodes(count)
	if err != nil {
		t.Fatalf("generateBackupCodes failed: %v", err)
	}

	if len(plain) != count {
		t.Errorf("Plain codes count: got %d, want %d", len(plain), count)
	}
	if len(hashed) != count {
		t.Errorf("Hashed codes count: got %d, want %d", len(hashed), count)
	}

	for i, code := range plain {
		if len(code) != 8 {
			t.Errorf("Code %d length: got %d, want 8", i, len(code))
		}
		// Verify hash matches plain
		if err := bcrypt.CompareHashAndPassword([]byte(hashed[i]), []byte(code)); err != nil {
			t.Errorf("Code %d hash mismatch: %v", i, err)
		}
	}

	// Verify uniqueness
	seen := make(map[string]bool)
	for _, code := range plain {
		if seen[code] {
			t.Error("Duplicate backup code found")
		}
		seen[code] = true
	}
}

func TestTwoFactorSetupHandler(t *testing.T) {
	am, cfg, db := newTestAuthManagerWith2FA(t)
	defer am.StopAttemptTracker()
	router := mux.NewRouter()
	am.RegisterRoutes(router)

	user, accessToken := createTestUserFor2FA(t, db, cfg, "setupuser", "password123")

	req := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/setup", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Secret      string   `json:"secret"`
		URL         string   `json:"url"`
		BackupCodes []string `json:"backupCodes"`
	}
	decodeJsonResponse(t, rr, &resp)

	if resp.Secret == "" {
		t.Error("Expected non-empty secret")
	}
	if resp.URL == "" {
		t.Error("Expected non-empty URL")
	}
	if len(resp.BackupCodes) != 5 {
		t.Errorf("Expected 5 backup codes, got %d", len(resp.BackupCodes))
	}

	// Verify the user's stored data was updated (secret stored, but not enabled)
	updatedUser, _, _ := db.FindByID(context.Background(), user.ID)
	if updatedUser.TwoFactorEnabled {
		t.Error("2FA should not be enabled yet after setup")
	}
	if updatedUser.TwoFactorSecret == "" {
		t.Error("2FA secret should be stored after setup")
	}
	if len(updatedUser.TwoFactorBackupCodes) != 5 {
		t.Errorf("Expected 5 hashed backup codes stored, got %d", len(updatedUser.TwoFactorBackupCodes))
	}
}

func TestTwoFactorEnableHandler(t *testing.T) {
	am, cfg, db := newTestAuthManagerWith2FA(t)
	defer am.StopAttemptTracker()
	router := mux.NewRouter()
	am.RegisterRoutes(router)

	user, accessToken := createTestUserFor2FA(t, db, cfg, "enableuser", "password123")

	// Step 1: Setup 2FA
	setupReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/setup", nil)
	setupReq.Header.Set("Authorization", "Bearer "+accessToken)
	setupRR := httptest.NewRecorder()
	router.ServeHTTP(setupRR, setupReq)

	if setupRR.Code != http.StatusOK {
		t.Fatalf("Setup failed with %d: %s", setupRR.Code, setupRR.Body.String())
	}

	var setupResp struct {
		Secret string `json:"secret"`
	}
	decodeJsonResponse(t, setupRR, &setupResp)

	// Step 2: Generate a valid TOTP code
	code, err := totp.GenerateCode(setupResp.Secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	// Step 3: Enable 2FA with the valid code
	enableReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/enable", map[string]string{"code": code})
	enableReq.Header.Set("Authorization", "Bearer "+accessToken)
	enableRR := httptest.NewRecorder()
	router.ServeHTTP(enableRR, enableReq)

	if enableRR.Code != http.StatusOK {
		t.Fatalf("Enable failed with %d: %s", enableRR.Code, enableRR.Body.String())
	}

	// Verify 2FA is now enabled
	updatedUser, _, _ := db.FindByID(context.Background(), user.ID)
	if !updatedUser.TwoFactorEnabled {
		t.Error("2FA should be enabled after enable handler")
	}

	// Step 4: Try with invalid code
	invalidReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/enable", map[string]string{"code": "000000"})
	invalidReq.Header.Set("Authorization", "Bearer "+accessToken)
	invalidRR := httptest.NewRecorder()
	router.ServeHTTP(invalidRR, invalidReq)

	// Should be 409 since already enabled
	if invalidRR.Code != http.StatusConflict {
		t.Errorf("Expected 409 for already enabled, got %d: %s", invalidRR.Code, invalidRR.Body.String())
	}
}

func TestTwoFactorDisableHandler(t *testing.T) {
	am, cfg, db := newTestAuthManagerWith2FA(t)
	defer am.StopAttemptTracker()
	router := mux.NewRouter()
	am.RegisterRoutes(router)

	_, accessToken := createTestUserFor2FA(t, db, cfg, "disableuser", "password123")

	// Setup and enable 2FA
	setupReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/setup", nil)
	setupReq.Header.Set("Authorization", "Bearer "+accessToken)
	setupRR := httptest.NewRecorder()
	router.ServeHTTP(setupRR, setupReq)

	var setupResp struct {
		Secret string `json:"secret"`
	}
	decodeJsonResponse(t, setupRR, &setupResp)

	code, _ := totp.GenerateCode(setupResp.Secret, time.Now())
	enableReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/enable", map[string]string{"code": code})
	enableReq.Header.Set("Authorization", "Bearer "+accessToken)
	enableRR := httptest.NewRecorder()
	router.ServeHTTP(enableRR, enableReq)

	if enableRR.Code != http.StatusOK {
		t.Fatalf("Enable failed: %d %s", enableRR.Code, enableRR.Body.String())
	}

	// Test disable with invalid code
	badReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/disable", map[string]string{"code": "000000"})
	badReq.Header.Set("Authorization", "Bearer "+accessToken)
	badRR := httptest.NewRecorder()
	router.ServeHTTP(badRR, badReq)

	if badRR.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for bad code, got %d: %s", badRR.Code, badRR.Body.String())
	}

	// Disable with valid TOTP code
	disableCode, _ := totp.GenerateCode(setupResp.Secret, time.Now())
	disableReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/disable", map[string]string{"code": disableCode})
	disableReq.Header.Set("Authorization", "Bearer "+accessToken)
	disableRR := httptest.NewRecorder()
	router.ServeHTTP(disableRR, disableReq)

	if disableRR.Code != http.StatusOK {
		t.Fatalf("Disable failed: %d %s", disableRR.Code, disableRR.Body.String())
	}
}

func TestTwoFactorVerifyHandler(t *testing.T) {
	am, cfg, db := newTestAuthManagerWith2FA(t)
	defer am.StopAttemptTracker()
	router := mux.NewRouter()
	am.RegisterRoutes(router)

	user, accessToken := createTestUserFor2FA(t, db, cfg, "verifyuser", "password123")

	// Setup and enable 2FA
	setupReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/setup", nil)
	setupReq.Header.Set("Authorization", "Bearer "+accessToken)
	setupRR := httptest.NewRecorder()
	router.ServeHTTP(setupRR, setupReq)

	var setupResp struct {
		Secret string `json:"secret"`
	}
	decodeJsonResponse(t, setupRR, &setupResp)

	enableCode, _ := totp.GenerateCode(setupResp.Secret, time.Now())
	enableReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/enable", map[string]string{"code": enableCode})
	enableReq.Header.Set("Authorization", "Bearer "+accessToken)
	enableRR := httptest.NewRecorder()
	router.ServeHTTP(enableRR, enableReq)

	if enableRR.Code != http.StatusOK {
		t.Fatalf("Enable failed: %d %s", enableRR.Code, enableRR.Body.String())
	}

	// Generate a pending token (simulating what LoginHandler does)
	pendingToken := generate2FAPendingToken(t, cfg, user.ID)

	// Generate valid TOTP code and verify
	verifyCode, _ := totp.GenerateCode(setupResp.Secret, time.Now())
	verifyReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/verify", servex.TwoFactorVerifyRequest{
		Token: pendingToken,
		Code:  verifyCode,
	})
	verifyRR := httptest.NewRecorder()
	router.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusOK {
		t.Fatalf("Verify failed: %d %s", verifyRR.Code, verifyRR.Body.String())
	}

	var verifyResp servex.UserLoginResponse
	decodeJsonResponse(t, verifyRR, &verifyResp)

	if verifyResp.ID != user.ID {
		t.Errorf("Expected user ID %q, got %q", user.ID, verifyResp.ID)
	}
	if verifyResp.AccessToken == "" {
		t.Error("Expected non-empty access token in verify response")
	}

	// Check that a refresh token cookie was set
	foundCookie := false
	for _, cookie := range verifyRR.Result().Cookies() {
		if cookie.Name == cfg.RefreshTokenCookieName {
			foundCookie = true
			if cookie.Value == "" {
				t.Error("Expected non-empty refresh token cookie")
			}
			break
		}
	}
	if !foundCookie {
		t.Error("Expected refresh token cookie to be set after 2FA verify")
	}
}

func TestTwoFactorVerifyWithBackupCode(t *testing.T) {
	am, cfg, db := newTestAuthManagerWith2FA(t)
	defer am.StopAttemptTracker()
	router := mux.NewRouter()
	am.RegisterRoutes(router)

	user, accessToken := createTestUserFor2FA(t, db, cfg, "backupuser", "password123")

	// Setup 2FA
	setupReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/setup", nil)
	setupReq.Header.Set("Authorization", "Bearer "+accessToken)
	setupRR := httptest.NewRecorder()
	router.ServeHTTP(setupRR, setupReq)

	var setupResp struct {
		Secret      string   `json:"secret"`
		BackupCodes []string `json:"backupCodes"`
	}
	decodeJsonResponse(t, setupRR, &setupResp)

	if len(setupResp.BackupCodes) == 0 {
		t.Fatal("No backup codes returned")
	}
	backupCode := setupResp.BackupCodes[0]

	// Enable 2FA
	enableCode, _ := totp.GenerateCode(setupResp.Secret, time.Now())
	enableReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/enable", map[string]string{"code": enableCode})
	enableReq.Header.Set("Authorization", "Bearer "+accessToken)
	enableRR := httptest.NewRecorder()
	router.ServeHTTP(enableRR, enableReq)

	if enableRR.Code != http.StatusOK {
		t.Fatalf("Enable failed: %d %s", enableRR.Code, enableRR.Body.String())
	}

	// Verify with backup code
	pendingToken := generate2FAPendingToken(t, cfg, user.ID)
	verifyReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/verify", servex.TwoFactorVerifyRequest{
		Token: pendingToken,
		Code:  backupCode,
	})
	verifyRR := httptest.NewRecorder()
	router.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusOK {
		t.Fatalf("Verify with backup code failed: %d %s", verifyRR.Code, verifyRR.Body.String())
	}

	var verifyResp servex.UserLoginResponse
	decodeJsonResponse(t, verifyRR, &verifyResp)

	if verifyResp.ID != user.ID {
		t.Errorf("Expected user ID %q, got %q", user.ID, verifyResp.ID)
	}
	if verifyResp.AccessToken == "" {
		t.Error("Expected non-empty access token")
	}

	// Verify the backup code was consumed (one fewer code in DB)
	updatedUser, _, _ := db.FindByID(context.Background(), user.ID)
	if len(updatedUser.TwoFactorBackupCodes) != 4 {
		t.Errorf("Expected 4 backup codes remaining, got %d", len(updatedUser.TwoFactorBackupCodes))
	}

	// Verify the same backup code no longer works
	pendingToken2 := generate2FAPendingToken(t, cfg, user.ID)
	verifyReq2 := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/verify", servex.TwoFactorVerifyRequest{
		Token: pendingToken2,
		Code:  backupCode,
	})
	verifyRR2 := httptest.NewRecorder()
	router.ServeHTTP(verifyRR2, verifyReq2)

	if verifyRR2.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for consumed backup code, got %d", verifyRR2.Code)
	}
}

func TestTwoFactorAttemptExhaustion(t *testing.T) {
	am, cfg, db := newTestAuthManagerWith2FA(t)
	defer am.StopAttemptTracker()
	router := mux.NewRouter()
	am.RegisterRoutes(router)

	user, accessToken := createTestUserFor2FA(t, db, cfg, "lockeduser", "password123")

	// Setup and enable 2FA
	setupReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/setup", nil)
	setupReq.Header.Set("Authorization", "Bearer "+accessToken)
	setupRR := httptest.NewRecorder()
	router.ServeHTTP(setupRR, setupReq)

	var setupResp struct {
		Secret string `json:"secret"`
	}
	decodeJsonResponse(t, setupRR, &setupResp)

	enableCode, _ := totp.GenerateCode(setupResp.Secret, time.Now())
	enableReq := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/enable", map[string]string{"code": enableCode})
	enableReq.Header.Set("Authorization", "Bearer "+accessToken)
	enableRR := httptest.NewRecorder()
	router.ServeHTTP(enableRR, enableReq)

	if enableRR.Code != http.StatusOK {
		t.Fatalf("Enable failed: %d %s", enableRR.Code, enableRR.Body.String())
	}

	// Use the same pending token for all attempts (same JTI)
	pendingToken := generate2FAPendingToken(t, cfg, user.ID)

	// Exhaust attempts (MaxVerifyAttempts = 3)
	for i := 0; i < 3; i++ {
		req := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/verify", servex.TwoFactorVerifyRequest{
			Token: pendingToken,
			Code:  "000000",
		})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("Attempt %d: expected 401, got %d: %s", i+1, rec.Code, rec.Body.String())
		}
	}

	// Next attempt should also fail (locked out)
	req := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/verify", servex.TwoFactorVerifyRequest{
		Token: pendingToken,
		Code:  "000000",
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 after exhaustion, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify the error message indicates lockout
	var errResp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err == nil {
		if errResp["message"] != "too many 2FA attempts, re-authenticate" {
			t.Errorf("Expected lockout message, got: %s", errResp["message"])
		}
	}

	// Even a valid code should fail now
	validCode, _ := totp.GenerateCode(setupResp.Secret, time.Now())
	req2 := newJsonRequest(http.MethodPost, cfg.AuthBasePath+"/2fa/verify", servex.TwoFactorVerifyRequest{
		Token: pendingToken,
		Code:  validCode,
	})
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 even with valid code after lockout, got %d", rec2.Code)
	}
}

func TestTwoFactorPendingTokenRejectedByWithAuth(t *testing.T) {
	am, cfg, db := newTestAuthManagerWith2FA(t)
	defer am.StopAttemptTracker()
	router := mux.NewRouter()
	am.RegisterRoutes(router)

	user, _ := createTestUserFor2FA(t, db, cfg, "pendinguser", "password123")

	// Enable 2FA for the user manually
	encKey, _ := hex.DecodeString(cfg.TwoFactor.EncryptionKey)
	secret := "JBSWY3DPEHPK3PXP"
	encrypted, err := servex.ExportEncryptTOTPSecret(secret, encKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if err := db.UpdateUser(context.Background(), user.ID, &servex.UserDiff{
		TwoFactorEnabled: lang.Ptr(true),
		TwoFactorSecret:  lang.Ptr(encrypted),
	}); err != nil {
		t.Fatalf("Failed to update user: %v", err)
	}

	// Generate a pending token (which has purpose "2fa_pending")
	pendingToken := generate2FAPendingToken(t, cfg, user.ID)

	// Try to access a protected route (like /me) with the pending token
	req := newJsonRequest(http.MethodGet, cfg.AuthBasePath+"/me", nil)
	req.Header.Set("Authorization", "Bearer "+pendingToken)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Should be rejected because WithAuth rejects 2fa_pending tokens
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for pending token on protected route, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestLoginWith2FA_FullFlow is a cross-feature integration test that exercises
// the full registration → login → 2FA setup → 2FA enable → login with 2FA → verify flow.
func TestLoginWith2FA_FullFlow(t *testing.T) {
	db := servex.NewMemoryAuthDatabase()
	encKey := hex.EncodeToString(getRandomBytes(32))
	cfg := servex.AuthConfig{
		Enabled:              true,
		Database:             db,
		JWTAccessSecret:      hex.EncodeToString(getRandomBytes(32)),
		JWTRefreshSecret:     hex.EncodeToString(getRandomBytes(32)),
		AccessTokenDuration:  5 * time.Minute,
		RefreshTokenDuration: 10 * time.Minute,
		IssuerNameInJWT:      "test-issuer",
		AuthBasePath:         "/api/v1/auth",
		RefreshTokenCookieName: "_servexrt",
		RolesOnRegister:      []servex.UserRole{"user"},
		Email: servex.EmailConfig{
			Enabled:             true,
			Sender:              &MockEmailSender{},
			VerifyTokenDuration: 24 * time.Hour,
			ResetTokenDuration:  time.Hour,
			ResendCooldown:      60 * time.Second,
		},
		TwoFactor: servex.TwoFactorConfig{
			Enabled:           true,
			EncryptionKey:     encKey,
			Issuer:            "test-app",
			BackupCodes:       5,
			MaxVerifyAttempts: 3,
		},
	}
	am, err := servex.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}
	defer am.StopAttemptTracker()

	router := mux.NewRouter()
	am.RegisterRoutes(router)

	// Step 1: Register a user
	regBody, _ := json.Marshal(servex.RegisterRequest{
		Username: "2fa_full_user",
		Password: "password123",
		Email:    "2fa_full@example.com",
	})
	regReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(string(regBody)))
	regReq.Header.Set("Content-Type", "application/json")
	regRR := httptest.NewRecorder()
	router.ServeHTTP(regRR, regReq)

	if regRR.Code != http.StatusCreated {
		t.Fatalf("Register: expected 201, got %d; body: %s", regRR.Code, regRR.Body.String())
	}

	var regResp servex.UserLoginResponse
	decodeJsonResponse(t, regRR, &regResp)
	if regResp.AccessToken == "" {
		t.Fatal("Register: expected accessToken in response")
	}

	// Step 2: Login to get access token
	loginBody, _ := json.Marshal(servex.UserLoginRequest{
		Username: "2fa_full_user",
		Password: "password123",
	})
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(string(loginBody)))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRR := httptest.NewRecorder()
	router.ServeHTTP(loginRR, loginReq)

	if loginRR.Code != http.StatusOK {
		t.Fatalf("Login: expected 200, got %d; body: %s", loginRR.Code, loginRR.Body.String())
	}

	var loginResp servex.UserLoginResponse
	decodeJsonResponse(t, loginRR, &loginResp)
	accessToken := loginResp.AccessToken
	if accessToken == "" {
		t.Fatal("Login: expected accessToken (2FA not yet enabled)")
	}

	// Step 3: Setup 2FA with Bearer token
	setupReq := newJsonRequest(http.MethodPost, "/api/v1/auth/2fa/setup", nil)
	setupReq.Header.Set("Authorization", "Bearer "+accessToken)
	setupRR := httptest.NewRecorder()
	router.ServeHTTP(setupRR, setupReq)

	if setupRR.Code != http.StatusOK {
		t.Fatalf("2FA setup: expected 200, got %d; body: %s", setupRR.Code, setupRR.Body.String())
	}

	var setupResp struct {
		Secret      string   `json:"secret"`
		URL         string   `json:"url"`
		BackupCodes []string `json:"backupCodes"`
	}
	decodeJsonResponse(t, setupRR, &setupResp)
	if setupResp.Secret == "" {
		t.Fatal("2FA setup: expected non-empty secret")
	}

	// Step 4: Enable 2FA with a valid TOTP code
	enableCode, err := totp.GenerateCode(setupResp.Secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}
	enableReq := newJsonRequest(http.MethodPost, "/api/v1/auth/2fa/enable", map[string]string{"code": enableCode})
	enableReq.Header.Set("Authorization", "Bearer "+accessToken)
	enableRR := httptest.NewRecorder()
	router.ServeHTTP(enableRR, enableReq)

	if enableRR.Code != http.StatusOK {
		t.Fatalf("2FA enable: expected 200, got %d; body: %s", enableRR.Code, enableRR.Body.String())
	}

	// Verify 2FA is enabled in DB
	user, _, _ := db.FindByID(context.Background(), regResp.ID)
	if !user.TwoFactorEnabled {
		t.Fatal("2FA should be enabled after enable handler")
	}

	// Step 5: Login again — should get twoFactorToken instead of accessToken
	loginReq2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(string(loginBody)))
	loginReq2.Header.Set("Content-Type", "application/json")
	loginRR2 := httptest.NewRecorder()
	router.ServeHTTP(loginRR2, loginReq2)

	if loginRR2.Code != http.StatusOK {
		t.Fatalf("Login with 2FA: expected 200, got %d; body: %s", loginRR2.Code, loginRR2.Body.String())
	}

	var login2FAResp map[string]string
	if err := json.Unmarshal(loginRR2.Body.Bytes(), &login2FAResp); err != nil {
		t.Fatalf("Failed to decode login response: %v", err)
	}
	twoFactorToken := login2FAResp["twoFactorToken"]
	if twoFactorToken == "" {
		t.Fatal("Login with 2FA: expected twoFactorToken in response")
	}
	if login2FAResp["accessToken"] != "" {
		t.Error("Login with 2FA: expected no accessToken when 2FA is required")
	}

	// Step 6: Verify with TOTP code — should get accessToken + refresh cookie
	verifyCode, err := totp.GenerateCode(setupResp.Secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code for verify: %v", err)
	}
	verifyReq := newJsonRequest(http.MethodPost, "/api/v1/auth/2fa/verify", servex.TwoFactorVerifyRequest{
		Token: twoFactorToken,
		Code:  verifyCode,
	})
	verifyRR := httptest.NewRecorder()
	router.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusOK {
		t.Fatalf("2FA verify: expected 200, got %d; body: %s", verifyRR.Code, verifyRR.Body.String())
	}

	var verifyResp servex.UserLoginResponse
	decodeJsonResponse(t, verifyRR, &verifyResp)
	if verifyResp.AccessToken == "" {
		t.Error("2FA verify: expected accessToken in response")
	}
	if verifyResp.ID != regResp.ID {
		t.Errorf("2FA verify: expected user ID %q, got %q", regResp.ID, verifyResp.ID)
	}

	// Check refresh token cookie was set
	foundRefreshCookie := false
	for _, cookie := range verifyRR.Result().Cookies() {
		if cookie.Name == "_servexrt" {
			foundRefreshCookie = true
			if cookie.Value == "" {
				t.Error("2FA verify: expected non-empty refresh token cookie")
			}
			break
		}
	}
	if !foundRefreshCookie {
		t.Error("2FA verify: expected refresh token cookie to be set")
	}
}

// TestOAuthLoginWith2FA is a cross-feature integration test that exercises
// the OAuth login flow when the user has 2FA enabled.
func TestOAuthLoginWith2FA(t *testing.T) {
	db := servex.NewMemoryAuthDatabase()
	encKey := hex.EncodeToString(getRandomBytes(32))
	stateKey := hex.EncodeToString(getRandomBytes(32))

	provider := &MockOAuthProvider{
		name:    "testprovider",
		authURL: "https://provider.example.com/auth",
		userInfo: &servex.OAuthUserInfo{
			ProviderID: "oauth-2fa-user-id",
			Email:      "oauth2fa@example.com",
			Username:   "oauth2fauser",
			Verified:   true,
		},
	}

	cfg := servex.AuthConfig{
		Enabled:              true,
		Database:             db,
		JWTAccessSecret:      hex.EncodeToString(getRandomBytes(32)),
		JWTRefreshSecret:     hex.EncodeToString(getRandomBytes(32)),
		AccessTokenDuration:  5 * time.Minute,
		RefreshTokenDuration: 10 * time.Minute,
		IssuerNameInJWT:      "test-issuer",
		AuthBasePath:         "/api/v1/auth",
		RefreshTokenCookieName: "_servexrt",
		RolesOnRegister:      []servex.UserRole{"user"},
		TwoFactor: servex.TwoFactorConfig{
			Enabled:           true,
			EncryptionKey:     encKey,
			Issuer:            "test-app",
			BackupCodes:       5,
			MaxVerifyAttempts: 3,
		},
		OAuth: servex.OAuthConfig{
			Enabled:         true,
			Providers:       []servex.OAuthProvider{provider},
			AutoLinkByEmail: true,
			StateSigningKey: stateKey,
		},
	}
	am, err := servex.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}
	defer am.StopAttemptTracker()

	router := mux.NewRouter()
	am.RegisterRoutes(router)

	// Step 1: Register a user, get access token, setup and enable 2FA
	regBody, _ := json.Marshal(servex.RegisterRequest{
		Username: "oauth2fauser_reg",
		Password: "password123",
	})
	regReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(string(regBody)))
	regReq.Header.Set("Content-Type", "application/json")
	regRR := httptest.NewRecorder()
	router.ServeHTTP(regRR, regReq)

	if regRR.Code != http.StatusCreated {
		t.Fatalf("Register: expected 201, got %d; body: %s", regRR.Code, regRR.Body.String())
	}

	var regResp servex.UserLoginResponse
	decodeJsonResponse(t, regRR, &regResp)
	accessToken := regResp.AccessToken

	// Setup 2FA
	setupReq := newJsonRequest(http.MethodPost, "/api/v1/auth/2fa/setup", nil)
	setupReq.Header.Set("Authorization", "Bearer "+accessToken)
	setupRR := httptest.NewRecorder()
	router.ServeHTTP(setupRR, setupReq)

	if setupRR.Code != http.StatusOK {
		t.Fatalf("2FA setup: expected 200, got %d; body: %s", setupRR.Code, setupRR.Body.String())
	}

	var setupResp struct {
		Secret string `json:"secret"`
	}
	decodeJsonResponse(t, setupRR, &setupResp)

	// Enable 2FA
	enableCode, _ := totp.GenerateCode(setupResp.Secret, time.Now())
	enableReq := newJsonRequest(http.MethodPost, "/api/v1/auth/2fa/enable", map[string]string{"code": enableCode})
	enableReq.Header.Set("Authorization", "Bearer "+accessToken)
	enableRR := httptest.NewRecorder()
	router.ServeHTTP(enableRR, enableReq)

	if enableRR.Code != http.StatusOK {
		t.Fatalf("2FA enable: expected 200, got %d; body: %s", enableRR.Code, enableRR.Body.String())
	}

	// Step 2: Link an OAuth provider to this user
	linkReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/testprovider/link", strings.NewReader(`{"code":"link-code-123"}`))
	linkReq.Header.Set("Content-Type", "application/json")
	linkReq = linkReq.WithContext(context.WithValue(linkReq.Context(), servex.UserContextKey{}, regResp.ID))
	linkRR := httptest.NewRecorder()

	linkRouter := mux.NewRouter()
	linkRouter.HandleFunc("/api/v1/auth/oauth/{provider}/link", am.OAuthLinkHandler).Methods(http.MethodPost)
	linkRouter.ServeHTTP(linkRR, linkReq)

	if linkRR.Code != http.StatusOK {
		t.Fatalf("OAuth link: expected 200, got %d; body: %s", linkRR.Code, linkRR.Body.String())
	}

	// Step 3: Simulate OAuth callback for that user — should redirect with twoFactorToken
	_, stateCookie := performOAuthRedirect(t, am, "testprovider")
	parts := strings.SplitN(stateCookie.Value, ":", 2)
	state := parts[0]

	callbackURL := "/api/v1/auth/oauth/testprovider/callback?code=oauth-code-123&state=" + state
	callbackReq := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	callbackReq.AddCookie(stateCookie)
	callbackRR := httptest.NewRecorder()
	router.ServeHTTP(callbackRR, callbackReq)

	// Should redirect (302) to 2FA page with twoFactorToken
	if callbackRR.Code != http.StatusFound {
		t.Fatalf("OAuth callback with 2FA: expected 302, got %d; body: %s", callbackRR.Code, callbackRR.Body.String())
	}

	location := callbackRR.Header().Get("Location")
	if !strings.Contains(location, "twoFactorToken=") {
		t.Fatalf("OAuth callback: expected redirect with twoFactorToken, got Location: %s", location)
	}

	// Extract twoFactorToken from redirect URL
	locParts := strings.SplitN(location, "twoFactorToken=", 2)
	if len(locParts) != 2 {
		t.Fatalf("Failed to extract twoFactorToken from Location: %s", location)
	}
	twoFactorToken := locParts[1]

	// Step 4: Verify with TOTP code — should get tokens
	verifyCode, _ := totp.GenerateCode(setupResp.Secret, time.Now())
	verifyReq := newJsonRequest(http.MethodPost, "/api/v1/auth/2fa/verify", servex.TwoFactorVerifyRequest{
		Token: twoFactorToken,
		Code:  verifyCode,
	})
	verifyRR := httptest.NewRecorder()
	router.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusOK {
		t.Fatalf("2FA verify after OAuth: expected 200, got %d; body: %s", verifyRR.Code, verifyRR.Body.String())
	}

	var verifyResp servex.UserLoginResponse
	decodeJsonResponse(t, verifyRR, &verifyResp)
	if verifyResp.AccessToken == "" {
		t.Error("2FA verify after OAuth: expected accessToken")
	}
	if verifyResp.ID != regResp.ID {
		t.Errorf("2FA verify after OAuth: expected user ID %q, got %q", regResp.ID, verifyResp.ID)
	}

	// Check refresh token cookie
	foundRefreshCookie := false
	for _, cookie := range verifyRR.Result().Cookies() {
		if cookie.Name == "_servexrt" {
			foundRefreshCookie = true
			break
		}
	}
	if !foundRefreshCookie {
		t.Error("2FA verify after OAuth: expected refresh token cookie")
	}
}
