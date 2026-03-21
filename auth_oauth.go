package servex

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/maxbolgarin/lang"
)

// OAuthAuthDatabase is a sub-interface of AuthDatabase required when OAuthConfig.Enabled is true.
// It provides OAuth provider-based user lookup in addition to the standard AuthDatabase methods.
type OAuthAuthDatabase interface {
	FindByOAuthProvider(ctx context.Context, provider string, providerID string) (User, bool, error)
}

// oauthStateCookieName is the cookie name for storing OAuth state during the redirect flow.
const oauthStateCookieName = "_servex_oauth_state"

// oauthLinkRequest represents the request body for linking an OAuth provider to an authenticated user.
type oauthLinkRequest struct {
	Code string `json:"code"`
}

// Validate checks if the oauthLinkRequest is valid.
func (req oauthLinkRequest) Validate() error {
	if req.Code == "" {
		return fmt.Errorf("code is required")
	}
	return nil
}

// generateOAuthState generates a random state and its HMAC-SHA256 signature.
// The state is a random 32-byte hex string, and the mac is the HMAC-SHA256
// of that state using the provided signing key, hex-encoded.
func generateOAuthState(signingKey []byte) (state string, mac string, err error) {
	state = generateRandomHex(32)
	h := hmac.New(sha256.New, signingKey)
	h.Write([]byte(state))
	mac = hex.EncodeToString(h.Sum(nil))
	return state, mac, nil
}

// validateOAuthState validates an OAuth state value against its HMAC-SHA256 signature.
func validateOAuthState(state, mac string, signingKey []byte) bool {
	h := hmac.New(sha256.New, signingKey)
	h.Write([]byte(state))
	expectedMAC, err := hex.DecodeString(mac)
	if err != nil {
		return false
	}
	return hmac.Equal(h.Sum(nil), expectedMAC)
}

// setOAuthStateCookie sets a cookie containing the OAuth state and HMAC for CSRF protection.
func (h *AuthManager) setOAuthStateCookie(ctx *Context, value string) {
	ctx.SetRawCookie(&http.Cookie{
		Name:     oauthStateCookieName,
		Value:    value,
		Path:     h.service.cfg.AuthBasePath + lang.Check(h.service.cfg.OAuth.BasePath, "/oauth"),
		HttpOnly: true,
		Secure:   h.isSecureCookie(ctx),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})
}

// getAndDeleteOAuthStateCookie retrieves the OAuth state cookie, splits it into state and mac,
// and deletes the cookie by setting MaxAge=-1.
func (h *AuthManager) getAndDeleteOAuthStateCookie(r *http.Request, w http.ResponseWriter) (state, mac string, ok bool) {
	cookie, err := r.Cookie(oauthStateCookieName)
	if err != nil || cookie.Value == "" {
		return "", "", false
	}

	// Delete the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     h.service.cfg.AuthBasePath + lang.Check(h.service.cfg.OAuth.BasePath, "/oauth"),
		HttpOnly: true,
		Secure:   h.service.cfg.ForceSecureCookies || r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	parts := strings.SplitN(cookie.Value, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}

// findOAuthProvider searches the configured OAuth providers by name.
func (h *AuthManager) findOAuthProvider(name string) OAuthProvider {
	for _, p := range h.service.cfg.OAuth.Providers {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

// OAuthRedirectHandler handles the initial OAuth redirect.
// It generates a state parameter with HMAC protection, stores it in a cookie,
// and redirects the user to the OAuth provider's authorization URL.
//
// GET /oauth/{provider}
func (h *AuthManager) OAuthRedirectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	providerName := mux.Vars(r)["provider"]
	provider := h.findOAuthProvider(providerName)
	if provider == nil {
		ctx.NotFound(errOAuthProviderNotFound, errOAuthProviderNotFound.Error())
		return
	}

	state, mac, err := generateOAuthState(h.service.cfg.OAuth.stateSigningKey)
	if err != nil {
		ctx.InternalServerError(err, "failed to generate OAuth state")
		return
	}

	h.setOAuthStateCookie(ctx, state+":"+mac)

	http.Redirect(w, r, provider.AuthURL(state), http.StatusFound)
}

// OAuthCallbackHandler handles the OAuth provider callback.
// It validates the state parameter, exchanges the authorization code for user info,
// and either logs in an existing user, links to an existing account, or creates a new user.
//
// GET /oauth/{provider}/callback?code=...&state=...
func (h *AuthManager) OAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	providerName := mux.Vars(r)["provider"]
	provider := h.findOAuthProvider(providerName)
	if provider == nil {
		ctx.NotFound(errOAuthProviderNotFound, errOAuthProviderNotFound.Error())
		return
	}

	code := r.URL.Query().Get("code")
	stateParam := r.URL.Query().Get("state")

	// Validate state cookie and HMAC
	cookieState, cookieMAC, ok := h.getAndDeleteOAuthStateCookie(r, w)
	if !ok || cookieState != stateParam || !validateOAuthState(cookieState, cookieMAC, h.service.cfg.OAuth.stateSigningKey) {
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventOAuthLoginFailed, r, "", false, map[string]any{
				"provider": providerName,
				"reason":   "state_mismatch",
			})
		}
		ctx.BadRequest(errOAuthStateMismatch, errOAuthStateMismatch.Error())
		return
	}

	// Exchange the authorization code for user info
	userInfo, err := provider.Exchange(r.Context(), code)
	if err != nil {
		if h.auditLogger != nil {
			h.auditLogger.LogAuthenticationEvent(AuditEventOAuthLoginFailed, r, "", false, map[string]any{
				"provider": providerName,
				"reason":   "exchange_failed",
				"error":    err.Error(),
			})
		}
		ctx.Unauthorized(err, "OAuth authentication failed")
		return
	}

	oauthDB := h.service.db.(OAuthAuthDatabase)

	// Step a: Look up by (provider, providerID)
	existingUser, found, err := oauthDB.FindByOAuthProvider(r.Context(), providerName, userInfo.ProviderID)
	if err != nil {
		ctx.InternalServerError(err, "failed to look up OAuth user")
		return
	}

	if found {
		// User exists with this OAuth link — issue tokens (or handle 2FA)
		h.oauthIssueTokensOrRedirect2FA(ctx, r, w, existingUser, providerName)
		return
	}

	// Step c/d: Not found by provider — try auto-link by email
	if h.service.cfg.OAuth.AutoLinkByEmail && userInfo.Verified && userInfo.Email != "" {
		emailDB, emailOK := h.service.db.(EmailAuthDatabase)
		if emailOK {
			emailUser, emailFound, emailErr := emailDB.FindByEmail(r.Context(), userInfo.Email)
			if emailErr != nil {
				ctx.InternalServerError(emailErr, "failed to look up user by email")
				return
			}
			if emailFound {
				// Check if local email is verified
				if !emailUser.EmailVerified {
					if h.auditLogger != nil {
						h.auditLogger.LogAuthenticationEvent(AuditEventOAuthLoginFailed, r, emailUser.ID, false, map[string]any{
							"provider": providerName,
							"reason":   "local_email_not_verified",
						})
					}
					ctx.Conflict(errOAuthEmailNotVerified, errOAuthEmailNotVerified.Error())
					return
				}

				// Link provider to existing user
				newLinks := append(emailUser.OAuthProviders, OAuthLink{
					Provider:   providerName,
					ProviderID: userInfo.ProviderID,
					Email:      userInfo.Email,
				})
				if err := h.service.db.UpdateUser(r.Context(), emailUser.ID, &UserDiff{
					OAuthProviders: &newLinks,
				}); err != nil {
					ctx.InternalServerError(err, "failed to link OAuth provider")
					return
				}

				if h.auditLogger != nil {
					h.auditLogger.LogAuthenticationEvent(AuditEventOAuthLink, r, emailUser.ID, true, map[string]any{
						"provider":    providerName,
						"provider_id": userInfo.ProviderID,
						"auto_linked": true,
					})
				}

				h.oauthIssueTokensOrRedirect2FA(ctx, r, w, emailUser, providerName)
				return
			}
			// Not found by email either — fall through to create new user
		}
	}

	// Create new user with OAuth link
	username := userInfo.Username
	if username == "" {
		username = userInfo.Email
	}
	if username == "" {
		username = providerName + "_" + userInfo.ProviderID
	}

	// Ensure unique username
	if _, exists, _ := h.service.db.FindByUsername(r.Context(), username); exists {
		username = username + "_" + generateRandomHex(4)
	}

	userID, err := h.service.db.NewUser(r.Context(), username, "", h.service.cfg.RolesOnRegister...)
	if err != nil {
		ctx.InternalServerError(err, "failed to create OAuth user")
		return
	}

	// Set OAuth link, email, and email verified status
	oauthLink := OAuthLink{
		Provider:   providerName,
		ProviderID: userInfo.ProviderID,
		Email:      userInfo.Email,
	}
	diff := &UserDiff{
		OAuthProviders: &[]OAuthLink{oauthLink},
	}
	if userInfo.Email != "" {
		diff.Email = &userInfo.Email
		if userInfo.Verified {
			diff.EmailVerified = lang.Ptr(true)
		}
	}
	if err := h.service.db.UpdateUser(r.Context(), userID, diff); err != nil {
		ctx.InternalServerError(err, "failed to update new OAuth user")
		return
	}

	// Check RequireVerification for new unverified users
	if h.service.cfg.Email.Enabled && h.service.cfg.Email.RequireVerification && !userInfo.Verified {
		ctx.Response(http.StatusOK, map[string]string{"message": "account created, please verify your email"})
		return
	}

	newUser := User{
		ID:            userID,
		Username:      username,
		Roles:         h.service.cfg.RolesOnRegister,
		EmailVerified: userInfo.Verified,
	}

	if h.auditLogger != nil {
		h.auditLogger.LogAuthenticationEvent(AuditEventOAuthLogin, r, userID, true, map[string]any{
			"provider":    providerName,
			"provider_id": userInfo.ProviderID,
			"new_user":    true,
		})
	}

	h.oauthIssueTokens(ctx, r, newUser, providerName)
}

// oauthIssueTokensOrRedirect2FA checks 2FA status and either issues tokens or redirects for 2FA.
func (h *AuthManager) oauthIssueTokensOrRedirect2FA(ctx *Context, r *http.Request, w http.ResponseWriter, user User, providerName string) {
	// Check 2FA
	if h.service.cfg.TwoFactor.Enabled && user.TwoFactorEnabled {
		pendingToken, _, err := h.service.generate2FAPendingToken(user.ID)
		if err != nil {
			ctx.InternalServerError(err, "failed to generate 2FA token")
			return
		}
		// For browser OAuth flow, redirect with twoFactorToken query param
		redirectURL := h.service.cfg.AuthBasePath + "/2fa?twoFactorToken=" + pendingToken
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	if h.auditLogger != nil {
		h.auditLogger.LogAuthenticationEvent(AuditEventOAuthLogin, r, user.ID, true, map[string]any{
			"provider": providerName,
			"user_id":  user.ID,
		})
	}

	h.oauthIssueTokens(ctx, r, user, providerName)
}

// oauthIssueTokens generates and returns access/refresh tokens for a user after OAuth authentication.
func (h *AuthManager) oauthIssueTokens(ctx *Context, r *http.Request, user User, providerName string) {
	accessToken, refreshToken, refreshTokenExpiresAt, err := h.service.generateTokens(r.Context(), user)
	if err != nil {
		ctx.InternalServerError(err, "failed to generate tokens")
		return
	}

	h.setAuthCookie(ctx, refreshToken, refreshTokenExpiresAt)

	ctx.Response(http.StatusOK, UserLoginResponse{
		ID:          user.ID,
		Username:    user.Username,
		Roles:       user.Roles,
		AccessToken: accessToken,
	})
}

// OAuthLinkHandler links an OAuth provider to an already-authenticated user.
// The user must provide the authorization code obtained from the provider.
//
// POST /oauth/{provider}/link
// Body: {"code": "authorization_code"}
// Requires: Bearer token authentication
func (h *AuthManager) OAuthLinkHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	userID := getValueFromContext[string](r, UserContextKey{})
	if userID == "" {
		ctx.Unauthorized(errUnauthorized, "not authenticated")
		return
	}

	providerName := mux.Vars(r)["provider"]
	provider := h.findOAuthProvider(providerName)
	if provider == nil {
		ctx.NotFound(errOAuthProviderNotFound, errOAuthProviderNotFound.Error())
		return
	}

	var req oauthLinkRequest
	if err := ctx.ReadAndValidate(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	// Exchange the code for user info from the provider
	userInfo, err := provider.Exchange(r.Context(), req.Code)
	if err != nil {
		ctx.BadRequest(err, "OAuth exchange failed")
		return
	}

	// Get the current user
	user, exists, err := h.service.db.FindByID(r.Context(), userID)
	if err != nil {
		ctx.InternalServerError(err, "failed to find user")
		return
	}
	if !exists {
		ctx.Unauthorized(errUnauthorized, "user not found")
		return
	}

	// Check user doesn't already have this provider linked
	for _, link := range user.OAuthProviders {
		if link.Provider == providerName {
			ctx.Conflict(errOAuthAlreadyLinked, errOAuthAlreadyLinked.Error())
			return
		}
	}

	// Add the new OAuth link
	newLinks := append(user.OAuthProviders, OAuthLink{
		Provider:   providerName,
		ProviderID: userInfo.ProviderID,
		Email:      userInfo.Email,
	})
	if err := h.service.db.UpdateUser(r.Context(), userID, &UserDiff{
		OAuthProviders: &newLinks,
	}); err != nil {
		ctx.InternalServerError(err, "failed to link OAuth provider")
		return
	}

	if h.auditLogger != nil {
		h.auditLogger.LogAuthenticationEvent(AuditEventOAuthLink, r, userID, true, map[string]any{
			"provider":    providerName,
			"provider_id": userInfo.ProviderID,
		})
	}

	ctx.Response(http.StatusOK, map[string]string{"message": "OAuth provider linked successfully"})
}

// OAuthUnlinkHandler removes an OAuth provider link from an authenticated user.
//
// DELETE /oauth/{provider}/link
// Requires: Bearer token authentication
func (h *AuthManager) OAuthUnlinkHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	userID := getValueFromContext[string](r, UserContextKey{})
	if userID == "" {
		ctx.Unauthorized(errUnauthorized, "not authenticated")
		return
	}

	providerName := mux.Vars(r)["provider"]

	// Get the current user
	user, exists, err := h.service.db.FindByID(r.Context(), userID)
	if err != nil {
		ctx.InternalServerError(err, "failed to find user")
		return
	}
	if !exists {
		ctx.Unauthorized(errUnauthorized, "user not found")
		return
	}

	// Find and remove the matching OAuth link
	var found bool
	newLinks := make([]OAuthLink, 0, len(user.OAuthProviders))
	for _, link := range user.OAuthProviders {
		if link.Provider == providerName {
			found = true
			continue
		}
		newLinks = append(newLinks, link)
	}

	if !found {
		ctx.NotFound(errOAuthProviderNotFound, "OAuth provider not linked")
		return
	}

	if err := h.service.db.UpdateUser(r.Context(), userID, &UserDiff{
		OAuthProviders: &newLinks,
	}); err != nil {
		ctx.InternalServerError(err, "failed to unlink OAuth provider")
		return
	}

	if h.auditLogger != nil {
		h.auditLogger.LogAuthenticationEvent(AuditEventOAuthUnlink, r, userID, true, map[string]any{
			"provider": providerName,
		})
	}

	ctx.Response(http.StatusOK, map[string]string{"message": "OAuth provider unlinked successfully"})
}
