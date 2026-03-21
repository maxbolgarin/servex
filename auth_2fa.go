package servex

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/maxbolgarin/lang"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// ---- AES-256-GCM encryption for TOTP secrets ----

// encryptTOTPSecret encrypts a TOTP secret using AES-256-GCM.
// The output is base64(nonce + ciphertext).
func encryptTOTPSecret(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := crand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptTOTPSecret decrypts a TOTP secret encrypted with AES-256-GCM.
// The input is base64(nonce + ciphertext).
func decryptTOTPSecret(encoded string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}

// ---- Attempt tracker ----

// attemptEntry tracks 2FA verification attempts for a single pending token.
type attemptEntry struct {
	count         int
	emailCodeHash string
	lastEmailSent time.Time
	expiresAt     time.Time
}

// attemptTracker tracks 2FA verification attempts and email cooldowns.
type attemptTracker struct {
	mu      sync.Mutex
	entries map[string]*attemptEntry
	maxAge  time.Duration
	done    chan struct{}
}

// newAttemptTracker creates a new attempt tracker and starts a cleanup goroutine.
func newAttemptTracker() *attemptTracker {
	t := &attemptTracker{
		entries: make(map[string]*attemptEntry),
		maxAge:  10 * time.Minute,
		done:    make(chan struct{}),
	}
	go t.cleanupLoop()
	return t
}

// Stop stops the cleanup goroutine.
func (t *attemptTracker) Stop() {
	close(t.done)
}

// cleanupLoop periodically removes expired entries.
func (t *attemptTracker) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.mu.Lock()
			now := time.Now()
			for jti, entry := range t.entries {
				if now.After(entry.expiresAt) {
					delete(t.entries, jti)
				}
			}
			t.mu.Unlock()
		}
	}
}

// getOrCreate returns the entry for the given jti, creating one if needed.
func (t *attemptTracker) getOrCreate(jti string) *attemptEntry {
	entry, ok := t.entries[jti]
	if !ok {
		entry = &attemptEntry{
			expiresAt: time.Now().Add(t.maxAge),
		}
		t.entries[jti] = entry
	}
	return entry
}

// increment increments the attempt count for the given jti and returns the new count.
func (t *attemptTracker) increment(jti string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.getOrCreate(jti)
	entry.count++
	return entry.count
}

// getCount returns the current attempt count for the given jti.
func (t *attemptTracker) getCount(jti string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.entries[jti]
	if !ok {
		return 0
	}
	return entry.count
}

// delete removes the entry for the given jti.
func (t *attemptTracker) delete(jti string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, jti)
}

// canSendEmail returns true if enough time has passed since the last email was sent.
func (t *attemptTracker) canSendEmail(jti string, cooldown time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.entries[jti]
	if !ok {
		return true
	}
	return time.Since(entry.lastEmailSent) >= cooldown
}

// markEmailSent records that an email code was sent, storing the bcrypt hash.
func (t *attemptTracker) markEmailSent(jti string, codeHash string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.getOrCreate(jti)
	entry.emailCodeHash = codeHash
	entry.lastEmailSent = time.Now()
}

// getEmailCodeHash returns the stored bcrypt hash of the email code for the given jti.
func (t *attemptTracker) getEmailCodeHash(jti string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.entries[jti]
	if !ok {
		return ""
	}
	return entry.emailCodeHash
}

// ---- Backup code generation ----

const backupCodeAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// generateBackupCodes generates one-time backup codes and their bcrypt hashes.
func generateBackupCodes(count int) (plainCodes []string, hashedCodes []string, err error) {
	plainCodes = make([]string, count)
	hashedCodes = make([]string, count)
	for i := 0; i < count; i++ {
		code := make([]byte, 8)
		for j := range code {
			code[j] = backupCodeAlphabet[rand.IntN(len(backupCodeAlphabet))]
		}
		plainCodes[i] = string(code)
		hash, err := bcrypt.GenerateFromPassword(code, bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, fmt.Errorf("hash backup code: %w", err)
		}
		hashedCodes[i] = string(hash)
	}
	return plainCodes, hashedCodes, nil
}

// ---- Request types ----

// TwoFactorVerifyRequest is the request body for 2FA verification during login.
type TwoFactorVerifyRequest struct {
	Token string `json:"token"`
	Code  string `json:"code"`
}

// Validate checks if the TwoFactorVerifyRequest is valid.
func (req TwoFactorVerifyRequest) Validate() error {
	if req.Token == "" {
		return fmt.Errorf("token is required")
	}
	if req.Code == "" {
		return fmt.Errorf("code is required")
	}
	return nil
}

// TwoFactorSendEmailCodeRequest is the request body for sending a 2FA email code.
type TwoFactorSendEmailCodeRequest struct {
	Token string `json:"token"`
}

// Validate checks if the TwoFactorSendEmailCodeRequest is valid.
func (req TwoFactorSendEmailCodeRequest) Validate() error {
	if req.Token == "" {
		return fmt.Errorf("token is required")
	}
	return nil
}

// twoFactorCodeRequest is the request body for enabling/disabling 2FA (code only).
type twoFactorCodeRequest struct {
	Code string `json:"code"`
}

// Validate checks if the twoFactorCodeRequest is valid.
func (req twoFactorCodeRequest) Validate() error {
	if req.Code == "" {
		return fmt.Errorf("code is required")
	}
	return nil
}

// twoFactorSetupResponse is returned by the 2FA setup handler.
type twoFactorSetupResponse struct {
	Secret      string   `json:"secret"`
	URL         string   `json:"url"`
	BackupCodes []string `json:"backupCodes"`
}

// ---- Handlers ----

// TwoFactorSetupHandler initiates 2FA setup for the authenticated user.
// It generates a TOTP key, encrypts and stores the secret, generates backup codes,
// and returns the secret, provisioning URL, and backup codes.
func (h *AuthManager) TwoFactorSetupHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	userID := getValueFromContext[string](r, UserContextKey{})
	if userID == "" {
		ctx.Unauthorized(errUnauthorized, "not authenticated")
		return
	}

	user, err := h.service.getUserByID(r.Context(), userID)
	if err != nil {
		ctx.InternalServerError(err, "failed to get user")
		return
	}

	if user.TwoFactorEnabled {
		ctx.Conflict(errTwoFactorAlreadyEnabled, errTwoFactorAlreadyEnabled.Error())
		return
	}

	// Generate TOTP key
	issuer := lang.Check(h.service.cfg.TwoFactor.Issuer, "servex")
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user.Username,
	})
	if err != nil {
		ctx.InternalServerError(err, "failed to generate TOTP key")
		return
	}

	// Encrypt the secret
	encryptedSecret, err := encryptTOTPSecret(key.Secret(), h.service.cfg.TwoFactor.encryptionKey)
	if err != nil {
		ctx.InternalServerError(err, "failed to encrypt TOTP secret")
		return
	}

	// Generate backup codes
	backupCount := lang.Check(h.service.cfg.TwoFactor.BackupCodes, 10)
	plainCodes, hashedCodes, err := generateBackupCodes(backupCount)
	if err != nil {
		ctx.InternalServerError(err, "failed to generate backup codes")
		return
	}

	// Store encrypted secret and hashed backup codes (TwoFactorEnabled stays false)
	if err := h.service.db.UpdateUser(r.Context(), userID, &UserDiff{
		TwoFactorSecret:      lang.Ptr(encryptedSecret),
		TwoFactorBackupCodes: &hashedCodes,
	}); err != nil {
		ctx.InternalServerError(err, "failed to store 2FA setup data")
		return
	}

	// Audit log
	if h.auditLogger != nil {
		h.auditLogger.LogAuthenticationEvent(AuditEvent2FASetup, r, userID, true, map[string]any{
			"username": user.Username,
		})
	}

	ctx.Response(http.StatusOK, twoFactorSetupResponse{
		Secret:      key.Secret(),
		URL:         key.URL(),
		BackupCodes: plainCodes,
	})
}

// TwoFactorEnableHandler enables 2FA for the authenticated user after verifying a TOTP code.
// The user must have called TwoFactorSetupHandler first.
func (h *AuthManager) TwoFactorEnableHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	userID := getValueFromContext[string](r, UserContextKey{})
	if userID == "" {
		ctx.Unauthorized(errUnauthorized, "not authenticated")
		return
	}

	var req twoFactorCodeRequest
	if err := ctx.ReadAndValidate(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	user, err := h.service.getUserByID(r.Context(), userID)
	if err != nil {
		ctx.InternalServerError(err, "failed to get user")
		return
	}

	if user.TwoFactorEnabled {
		ctx.Conflict(errTwoFactorAlreadyEnabled, errTwoFactorAlreadyEnabled.Error())
		return
	}

	if user.TwoFactorSecret == "" {
		ctx.BadRequest(errTwoFactorNotEnabled, "2FA setup not initiated, call setup first")
		return
	}

	// Decrypt the stored TOTP secret
	secret, err := decryptTOTPSecret(user.TwoFactorSecret, h.service.cfg.TwoFactor.encryptionKey)
	if err != nil {
		ctx.InternalServerError(err, "failed to decrypt TOTP secret")
		return
	}

	// Validate the provided TOTP code
	if !totp.Validate(req.Code, secret) {
		ctx.Unauthorized(errInvalidTwoFactorCode, errInvalidTwoFactorCode.Error())
		return
	}

	// Enable 2FA
	if err := h.service.db.UpdateUser(r.Context(), userID, &UserDiff{
		TwoFactorEnabled: lang.Ptr(true),
	}); err != nil {
		ctx.InternalServerError(err, "failed to enable 2FA")
		return
	}

	// Audit log
	if h.auditLogger != nil {
		h.auditLogger.LogAuthenticationEvent(AuditEvent2FAEnabled, r, userID, true, map[string]any{
			"username": user.Username,
		})
	}

	ctx.Response(http.StatusOK, map[string]string{"message": "2FA enabled successfully"})
}

// TwoFactorDisableHandler disables 2FA for the authenticated user.
// Requires a valid TOTP code or backup code for verification.
func (h *AuthManager) TwoFactorDisableHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	userID := getValueFromContext[string](r, UserContextKey{})
	if userID == "" {
		ctx.Unauthorized(errUnauthorized, "not authenticated")
		return
	}

	var req twoFactorCodeRequest
	if err := ctx.ReadAndValidate(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	user, err := h.service.getUserByID(r.Context(), userID)
	if err != nil {
		ctx.InternalServerError(err, "failed to get user")
		return
	}

	if !user.TwoFactorEnabled {
		ctx.BadRequest(errTwoFactorNotEnabled, errTwoFactorNotEnabled.Error())
		return
	}

	// Decrypt the stored TOTP secret
	secret, err := decryptTOTPSecret(user.TwoFactorSecret, h.service.cfg.TwoFactor.encryptionKey)
	if err != nil {
		ctx.InternalServerError(err, "failed to decrypt TOTP secret")
		return
	}

	// Try TOTP code first
	valid := totp.Validate(req.Code, secret)

	// If TOTP didn't match, try backup codes
	if !valid {
		for i, hash := range user.TwoFactorBackupCodes {
			if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Code)) == nil {
				valid = true
				// Remove the used backup code
				remaining := make([]string, 0, len(user.TwoFactorBackupCodes)-1)
				remaining = append(remaining, user.TwoFactorBackupCodes[:i]...)
				remaining = append(remaining, user.TwoFactorBackupCodes[i+1:]...)
				user.TwoFactorBackupCodes = remaining
				break
			}
		}
	}

	if !valid {
		ctx.Unauthorized(errInvalidTwoFactorCode, errInvalidTwoFactorCode.Error())
		return
	}

	// Clear 2FA fields
	emptyStr := ""
	emptyBackup := []string{}
	if err := h.service.db.UpdateUser(r.Context(), userID, &UserDiff{
		TwoFactorEnabled:     lang.Ptr(false),
		TwoFactorSecret:      &emptyStr,
		TwoFactorBackupCodes: &emptyBackup,
	}); err != nil {
		ctx.InternalServerError(err, "failed to disable 2FA")
		return
	}

	// Audit log
	if h.auditLogger != nil {
		h.auditLogger.LogAuthenticationEvent(AuditEvent2FADisabled, r, userID, true, map[string]any{
			"username": user.Username,
		})
	}

	ctx.Response(http.StatusOK, map[string]string{"message": "2FA disabled successfully"})
}

// TwoFactorVerifyHandler verifies a 2FA code during login (uses pending token, no auth required).
// Accepts TOTP codes, backup codes, and email-based codes.
func (h *AuthManager) TwoFactorVerifyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	var req TwoFactorVerifyRequest
	if err := ctx.ReadAndValidate(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	// Validate the pending token
	claims, err := h.service.validate2FAPendingToken(req.Token)
	if err != nil {
		ctx.Unauthorized(err, "invalid or expired 2FA token")
		return
	}

	// Check attempt count
	if h.attemptTracker.getCount(claims.ID) >= h.service.cfg.TwoFactor.MaxVerifyAttempts {
		// Audit log: locked out
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEvent2FALocked, r, claims.UserID, false, map[string]any{
				"reason": "max_attempts_exceeded",
			})
		}
		ctx.Unauthorized(errTwoFactorTooManyAttempts, errTwoFactorTooManyAttempts.Error())
		return
	}

	// Load user
	user, err := h.service.getUserByID(r.Context(), claims.UserID)
	if err != nil {
		ctx.InternalServerError(err, "failed to get user")
		return
	}

	// Decrypt TOTP secret
	secret, err := decryptTOTPSecret(user.TwoFactorSecret, h.service.cfg.TwoFactor.encryptionKey)
	if err != nil {
		ctx.InternalServerError(err, "failed to decrypt TOTP secret")
		return
	}

	valid := false
	usedBackup := false

	// Try TOTP
	if totp.Validate(req.Code, secret) {
		valid = true
	}

	// Try backup codes
	if !valid {
		for i, hash := range user.TwoFactorBackupCodes {
			if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Code)) == nil {
				valid = true
				usedBackup = true
				// Remove the used backup code
				remaining := make([]string, 0, len(user.TwoFactorBackupCodes)-1)
				remaining = append(remaining, user.TwoFactorBackupCodes[:i]...)
				remaining = append(remaining, user.TwoFactorBackupCodes[i+1:]...)
				if err := h.service.db.UpdateUser(r.Context(), user.ID, &UserDiff{
					TwoFactorBackupCodes: &remaining,
				}); err != nil {
					ctx.InternalServerError(err, "failed to update backup codes")
					return
				}
				break
			}
		}
	}

	// Try email code
	if !valid {
		emailHash := h.attemptTracker.getEmailCodeHash(claims.ID)
		if emailHash != "" {
			if bcrypt.CompareHashAndPassword([]byte(emailHash), []byte(req.Code)) == nil {
				valid = true
			}
		}
	}

	if !valid {
		h.attemptTracker.increment(claims.ID)
		// Audit log: failed
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEvent2FAFailed, r, claims.UserID, false, map[string]any{
				"reason": "invalid_code",
			})
		}
		ctx.Unauthorized(errInvalidTwoFactorCode, errInvalidTwoFactorCode.Error())
		return
	}

	// Success - clean up tracker
	h.attemptTracker.delete(claims.ID)

	// Generate tokens
	accessToken, refreshToken, refreshTokenExpiresAt, err := h.service.generateTokens(r.Context(), user)
	if err != nil {
		ctx.InternalServerError(err, "failed to generate tokens")
		return
	}

	h.setAuthCookie(ctx, refreshToken, refreshTokenExpiresAt)

	// Audit log: verified
	if h.auditLogger != nil {
		details := map[string]any{
			"username": user.Username,
			"user_id":  user.ID,
		}
		if usedBackup {
			details["method"] = "backup_code"
			h.auditLogger.LogAuthenticationEvent(AuditEventBackupCodeUsed, r, user.ID, true, details)
		} else {
			h.auditLogger.LogAuthenticationEvent(AuditEvent2FAVerified, r, user.ID, true, details)
		}
	}

	ctx.Response(http.StatusOK, UserLoginResponse{
		ID:          user.ID,
		Username:    user.Username,
		Roles:       user.Roles,
		AccessToken: accessToken,
	})
}

// TwoFactorSendEmailCodeHandler sends a 2FA email code (uses pending token, no auth required).
func (h *AuthManager) TwoFactorSendEmailCodeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	var req TwoFactorSendEmailCodeRequest
	if err := ctx.ReadAndValidate(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	// Validate the pending token
	claims, err := h.service.validate2FAPendingToken(req.Token)
	if err != nil {
		ctx.Unauthorized(err, "invalid or expired 2FA token")
		return
	}

	// Check email cooldown
	if !h.attemptTracker.canSendEmail(claims.ID, 60*time.Second) {
		ctx.TooManyRequests(fmt.Errorf("email cooldown"), "please wait before requesting another code")
		return
	}

	// Load user to get email
	user, err := h.service.getUserByID(r.Context(), claims.UserID)
	if err != nil {
		ctx.InternalServerError(err, "failed to get user")
		return
	}

	if user.Email == "" {
		ctx.BadRequest(fmt.Errorf("no email address"), "no email address on account")
		return
	}

	// Generate 6-digit code
	code := fmt.Sprintf("%06d", rand.IntN(1000000))

	// Hash the code
	codeHash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		ctx.InternalServerError(err, "failed to hash email code")
		return
	}

	// Store hash in tracker
	h.attemptTracker.markEmailSent(claims.ID, string(codeHash))

	// Send email
	if err := h.service.cfg.Email.Sender.SendTwoFactorCodeEmail(r.Context(), user.Email, code); err != nil {
		ctx.InternalServerError(err, "failed to send 2FA email")
		return
	}

	ctx.Response(http.StatusOK, map[string]string{"message": "verification code sent"})
}
