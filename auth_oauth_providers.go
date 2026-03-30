package servex

import (
	"context"
	crand "crypto/rand"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	stdjson "encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// oauthPostForm sends a POST request with form-encoded values and returns the JSON response as a map.
// oauthHTTPClient is a shared HTTP client with sensible timeouts for OAuth provider calls.
var oauthHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
}

// maxOAuthResponseSize limits OAuth provider response bodies to 1 MB.
const maxOAuthResponseSize = 1 << 20

func oauthPostForm(ctx context.Context, tokenURL string, values url.Values) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return result, nil
}

// oauthGetJSON sends a GET request with a Bearer (or custom) authorization token and returns the JSON response as a map.
func oauthGetJSON(ctx context.Context, apiURL string, authHeader string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return result, nil
}

// oauthGetJSONSlice sends a GET request with a Bearer authorization token and returns the JSON response as a slice of maps.
func oauthGetJSONSlice(ctx context.Context, apiURL string, authHeader string) ([]map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result []map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return result, nil
}

// --- Google OAuth Provider ---

// GoogleOAuthProvider implements OAuthProvider for Google OAuth 2.0.
type GoogleOAuthProvider struct {
	cfg GoogleOAuthConfig
}

// NewGoogleOAuthProvider creates a new Google OAuth provider from the given config.
func NewGoogleOAuthProvider(cfg GoogleOAuthConfig) *GoogleOAuthProvider {
	return &GoogleOAuthProvider{cfg: cfg}
}

// Name returns "google".
func (p *GoogleOAuthProvider) Name() string { return "google" }

// AuthURL returns the Google OAuth 2.0 authorization URL with the given state parameter.
func (p *GoogleOAuthProvider) AuthURL(state string) string {
	scopes := p.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	params := url.Values{
		"client_id":     {p.cfg.ClientID},
		"redirect_uri":  {p.cfg.RedirectURL},
		"response_type": {"code"},
		"scope":         {strings.Join(scopes, " ")},
		"state":         {state},
	}

	return "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
}

// Exchange exchanges the authorization code for user information from Google.
func (p *GoogleOAuthProvider) Exchange(ctx context.Context, code string) (*OAuthUserInfo, error) {
	// Exchange code for tokens.
	tokenData, err := oauthPostForm(ctx, "https://oauth2.googleapis.com/token", url.Values{
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"grant_type":    {"authorization_code"},
	})
	if err != nil {
		return nil, fmt.Errorf("google token exchange: %w", err)
	}

	accessToken, _ := tokenData["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("google token exchange: missing access_token")
	}

	// Get user info.
	userInfo, err := oauthGetJSON(ctx, "https://www.googleapis.com/oauth2/v2/userinfo", "Bearer "+accessToken)
	if err != nil {
		return nil, fmt.Errorf("google userinfo: %w", err)
	}

	id, _ := userInfo["id"].(string)
	email, _ := userInfo["email"].(string)
	name, _ := userInfo["name"].(string)
	verified, _ := userInfo["verified_email"].(bool)

	return &OAuthUserInfo{
		ProviderID: id,
		Email:      email,
		Username:   name,
		Verified:   verified,
	}, nil
}

// --- GitHub OAuth Provider ---

// GitHubOAuthProvider implements OAuthProvider for GitHub OAuth.
type GitHubOAuthProvider struct {
	cfg GitHubOAuthConfig
}

// NewGitHubOAuthProvider creates a new GitHub OAuth provider from the given config.
func NewGitHubOAuthProvider(cfg GitHubOAuthConfig) *GitHubOAuthProvider {
	return &GitHubOAuthProvider{cfg: cfg}
}

// Name returns "github".
func (p *GitHubOAuthProvider) Name() string { return "github" }

// AuthURL returns the GitHub OAuth authorization URL with the given state parameter.
func (p *GitHubOAuthProvider) AuthURL(state string) string {
	scopes := p.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"user:email"}
	}

	params := url.Values{
		"client_id":    {p.cfg.ClientID},
		"redirect_uri": {p.cfg.RedirectURL},
		"scope":        {strings.Join(scopes, " ")},
		"state":        {state},
	}

	return "https://github.com/login/oauth/authorize?" + params.Encode()
}

// Exchange exchanges the authorization code for user information from GitHub.
func (p *GitHubOAuthProvider) Exchange(ctx context.Context, code string) (*OAuthUserInfo, error) {
	// Exchange code for access token.
	tokenData, err := oauthPostForm(ctx, "https://github.com/login/oauth/access_token", url.Values{
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURL},
	})
	if err != nil {
		return nil, fmt.Errorf("github token exchange: %w", err)
	}

	accessToken, _ := tokenData["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("github token exchange: missing access_token")
	}

	// Get user profile.
	profile, err := oauthGetJSON(ctx, "https://api.github.com/user", "Bearer "+accessToken)
	if err != nil {
		return nil, fmt.Errorf("github user profile: %w", err)
	}

	// GitHub user id is a number.
	var userID string
	switch v := profile["id"].(type) {
	case float64:
		userID = strconv.FormatInt(int64(v), 10)
	case stdjson.Number:
		userID = v.String()
	default:
		userID = fmt.Sprintf("%v", v)
	}

	login, _ := profile["login"].(string)

	// Get primary verified email.
	emails, err := oauthGetJSONSlice(ctx, "https://api.github.com/user/emails", "Bearer "+accessToken)
	if err != nil {
		return nil, fmt.Errorf("github user emails: %w", err)
	}

	var email string
	var verified bool
	for _, e := range emails {
		primary, _ := e["primary"].(bool)
		if primary {
			email, _ = e["email"].(string)
			verified, _ = e["verified"].(bool)
			break
		}
	}

	return &OAuthUserInfo{
		ProviderID: userID,
		Email:      email,
		Username:   login,
		Verified:   verified,
	}, nil
}

// --- Apple OAuth Provider ---

// AppleOAuthProvider implements OAuthProvider for Apple Sign In.
type AppleOAuthProvider struct {
	cfg AppleOAuthConfig
}

// NewAppleOAuthProvider creates a new Apple Sign In provider from the given config.
func NewAppleOAuthProvider(cfg AppleOAuthConfig) *AppleOAuthProvider {
	return &AppleOAuthProvider{cfg: cfg}
}

// Name returns "apple".
func (p *AppleOAuthProvider) Name() string { return "apple" }

// AuthURL returns the Apple Sign In authorization URL with the given state parameter.
func (p *AppleOAuthProvider) AuthURL(state string) string {
	scopes := p.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"name", "email"}
	}

	params := url.Values{
		"client_id":     {p.cfg.ClientID},
		"redirect_uri":  {p.cfg.RedirectURL},
		"response_type": {"code"},
		"scope":         {strings.Join(scopes, " ")},
		"state":         {state},
		"response_mode": {"form_post"},
	}

	return "https://appleid.apple.com/auth/authorize?" + params.Encode()
}

// generateClientSecret generates a JWT client secret for Apple Sign In.
// Apple requires a short-lived ES256-signed JWT as the client_secret.
func (p *AppleOAuthProvider) generateClientSecret() (string, error) {
	block, _ := pem.Decode([]byte(p.cfg.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("apple: failed to decode PEM private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try parsing as EC private key directly.
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("apple: failed to parse private key: %w", err)
		}
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("apple: private key is not an ECDSA key")
	}

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    p.cfg.TeamID,
		Subject:   p.cfg.ClientID,
		Audience:  jwt.ClaimStrings{"https://appleid.apple.com"},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(180 * 24 * time.Hour)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = p.cfg.KeyID

	signed, err := token.SignedString(ecKey)
	if err != nil {
		return "", fmt.Errorf("apple: failed to sign client secret: %w", err)
	}

	return signed, nil
}

// Exchange exchanges the authorization code for user information from Apple.
// Apple returns an id_token JWT containing the user's sub, email, and email_verified claims.
func (p *AppleOAuthProvider) Exchange(ctx context.Context, code string) (*OAuthUserInfo, error) {
	clientSecret, err := p.generateClientSecret()
	if err != nil {
		return nil, err
	}

	tokenData, err := oauthPostForm(ctx, "https://appleid.apple.com/auth/token", url.Values{
		"client_id":     {p.cfg.ClientID},
		"client_secret": {clientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {p.cfg.RedirectURL},
	})
	if err != nil {
		return nil, fmt.Errorf("apple token exchange: %w", err)
	}

	idToken, _ := tokenData["id_token"].(string)
	if idToken == "" {
		return nil, fmt.Errorf("apple token exchange: missing id_token")
	}

	// Parse the id_token claims without verifying signature.
	// We trust Apple's response since we just received it over TLS from their token endpoint.
	claims, err := parseUnverifiedJWTClaims(idToken)
	if err != nil {
		return nil, fmt.Errorf("apple: failed to parse id_token: %w", err)
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)

	// email_verified can be a bool or a string "true"/"false" in Apple's response.
	var verified bool
	switch v := claims["email_verified"].(type) {
	case bool:
		verified = v
	case string:
		verified = v == "true"
	}

	return &OAuthUserInfo{
		ProviderID: sub,
		Email:      email,
		Username:   "", // Apple doesn't reliably provide a username in the id_token.
		Verified:   verified,
	}, nil
}

// parseUnverifiedJWTClaims parses JWT claims without verifying the signature.
// This is used for Apple's id_token where we trust the response from Apple's token endpoint.
func parseUnverifiedJWTClaims(tokenString string) (map[string]any, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (second part).
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal JWT claims: %w", err)
	}

	return claims, nil
}

// --- Telegram OAuth Provider ---

// TelegramOAuthProvider implements OAuthProvider for Telegram Login Widget.
type TelegramOAuthProvider struct {
	cfg TelegramOAuthConfig
}

// NewTelegramOAuthProvider creates a new Telegram Login Widget provider from the given config.
func NewTelegramOAuthProvider(cfg TelegramOAuthConfig) *TelegramOAuthProvider {
	return &TelegramOAuthProvider{cfg: cfg}
}

// Name returns "telegram".
func (p *TelegramOAuthProvider) Name() string { return "telegram" }

// AuthURL returns the Telegram Login Widget URL.
// Telegram uses a bot-based login widget that differs from standard OAuth2.
func (p *TelegramOAuthProvider) AuthURL(state string) string {
	params := url.Values{
		"bot_id":      {extractTelegramBotID(p.cfg.BotToken)},
		"origin":      {p.cfg.RedirectURL},
		"request_access": {"write"},
	}
	if state != "" {
		// Embed state in the return_to URL so it survives the redirect.
		returnURL := p.cfg.RedirectURL
		if strings.Contains(returnURL, "?") {
			returnURL += "&state=" + url.QueryEscape(state)
		} else {
			returnURL += "?state=" + url.QueryEscape(state)
		}
		params.Set("origin", returnURL)
	}

	return "https://oauth.telegram.org/auth?" + params.Encode()
}

// Exchange verifies Telegram login data and extracts user info.
// For Telegram, the "code" parameter is expected to be a JSON string
// containing the auth data fields from the Telegram Login Widget callback.
//
// Expected JSON format:
//
//	{"id": 12345, "first_name": "John", "last_name": "Doe", "username": "johndoe", "auth_date": 1234567890, "hash": "..."}
func (p *TelegramOAuthProvider) Exchange(_ context.Context, code string) (*OAuthUserInfo, error) {
	var data map[string]any
	if err := json.Unmarshal([]byte(code), &data); err != nil {
		return nil, fmt.Errorf("telegram: invalid auth data JSON: %w", err)
	}

	// Verify the hash.
	hash, _ := data["hash"].(string)
	if hash == "" {
		return nil, fmt.Errorf("telegram: missing hash in auth data")
	}

	if !verifyTelegramHash(data, p.cfg.BotToken) {
		return nil, fmt.Errorf("telegram: hash verification failed")
	}

	// Check auth_date freshness (allow up to 24 hours).
	if authDate, ok := telegramGetFloat64(data, "auth_date"); ok {
		if time.Now().Unix()-int64(authDate) > 86400 {
			return nil, fmt.Errorf("telegram: auth data is too old")
		}
	}

	// Extract user info.
	var userID string
	if id, ok := telegramGetFloat64(data, "id"); ok {
		userID = strconv.FormatInt(int64(id), 10)
	}

	username, _ := data["username"].(string)
	if username == "" {
		firstName, _ := data["first_name"].(string)
		lastName, _ := data["last_name"].(string)
		username = strings.TrimSpace(firstName + " " + lastName)
	}

	return &OAuthUserInfo{
		ProviderID: userID,
		Email:      "", // Telegram doesn't provide email.
		Username:   username,
		Verified:   false, // No email verification from Telegram.
	}, nil
}

// telegramGetFloat64 extracts a float64 from a map, handling both float64 and stdjson.Number.
func telegramGetFloat64(data map[string]any, key string) (float64, bool) {
	switch v := data[key].(type) {
	case float64:
		return v, true
	case stdjson.Number:
		f, err := v.Float64()
		return f, err == nil
	}
	return 0, false
}

// verifyTelegramHash verifies the Telegram Login Widget data hash.
// The verification follows Telegram's specification:
// 1. Sort all key=value pairs except "hash" alphabetically.
// 2. Join them with newlines to form the data_check_string.
// 3. Compute SHA256(bot_token) as the secret key.
// 4. Compute HMAC-SHA256(data_check_string, secret_key).
// 5. Compare with the provided hash.
func verifyTelegramHash(data map[string]any, botToken string) bool {
	hash, _ := data["hash"].(string)
	if hash == "" {
		return false
	}

	// Build data_check_string: sorted key=value pairs, excluding "hash".
	var pairs []string
	for k, v := range data {
		if k == "hash" {
			continue
		}
		switch val := v.(type) {
		case float64:
			// Render integer values without decimal point.
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

	// secret_key = SHA256(bot_token)
	secretHash := sha256.Sum256([]byte(botToken))

	// HMAC-SHA256(data_check_string, secret_key)
	mac := hmac.New(sha256.New, secretHash[:])
	mac.Write([]byte(dataCheckString))
	expectedHash := fmt.Sprintf("%x", mac.Sum(nil))

	return hmac.Equal([]byte(expectedHash), []byte(hash))
}

// extractTelegramBotID extracts the bot ID from the bot token (the part before the colon).
func extractTelegramBotID(botToken string) string {
	parts := strings.SplitN(botToken, ":", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// --- Yandex OAuth Provider ---

// YandexOAuthProvider implements OAuthProvider for Yandex OAuth.
type YandexOAuthProvider struct {
	cfg YandexOAuthConfig
}

// NewYandexOAuthProvider creates a new Yandex OAuth provider from the given config.
func NewYandexOAuthProvider(cfg YandexOAuthConfig) *YandexOAuthProvider {
	return &YandexOAuthProvider{cfg: cfg}
}

// Name returns "yandex".
func (p *YandexOAuthProvider) Name() string { return "yandex" }

// AuthURL returns the Yandex OAuth authorization URL with the given state parameter.
func (p *YandexOAuthProvider) AuthURL(state string) string {
	params := url.Values{
		"client_id":     {p.cfg.ClientID},
		"redirect_uri":  {p.cfg.RedirectURL},
		"response_type": {"code"},
		"state":         {state},
	}

	return "https://oauth.yandex.ru/authorize?" + params.Encode()
}

// Exchange exchanges the authorization code for user information from Yandex.
func (p *YandexOAuthProvider) Exchange(ctx context.Context, code string) (*OAuthUserInfo, error) {
	// Exchange code for access token.
	tokenData, err := oauthPostForm(ctx, "https://oauth.yandex.ru/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
	})
	if err != nil {
		return nil, fmt.Errorf("yandex token exchange: %w", err)
	}

	accessToken, _ := tokenData["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("yandex token exchange: missing access_token")
	}

	// Get user info.
	userInfo, err := oauthGetJSON(ctx, "https://login.yandex.ru/info", "OAuth "+accessToken)
	if err != nil {
		return nil, fmt.Errorf("yandex userinfo: %w", err)
	}

	id, _ := userInfo["id"].(string)
	email, _ := userInfo["default_email"].(string)
	login, _ := userInfo["login"].(string)

	return &OAuthUserInfo{
		ProviderID: id,
		Email:      email,
		Username:   login,
		Verified:   true, // Yandex verifies emails.
	}, nil
}

// --- PKCE helpers ---

// generateCodeVerifier generates a random PKCE code_verifier (43 characters, base64url-encoded).
func generateCodeVerifier() string {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// computeS256Challenge computes the S256 code_challenge from a code_verifier.
func computeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// --- VK ID OAuth Provider ---

// VKIDOAuthProvider implements OAuthProvider and PKCEOAuthProvider for VK ID.
type VKIDOAuthProvider struct {
	cfg VKIDOAuthConfig
}

// NewVKIDOAuthProvider creates a new VK ID OAuth provider from the given config.
func NewVKIDOAuthProvider(cfg VKIDOAuthConfig) *VKIDOAuthProvider {
	return &VKIDOAuthProvider{cfg: cfg}
}

// Name returns "vkid".
func (p *VKIDOAuthProvider) Name() string { return "vkid" }

// AuthURL returns the VK ID authorization URL. For PKCE providers, prefer AuthURLWithPKCE.
func (p *VKIDOAuthProvider) AuthURL(state string) string {
	authURL, _ := p.AuthURLWithPKCE(state)
	return authURL
}

// AuthURLWithPKCE returns the VK ID authorization URL and a PKCE code_verifier.
func (p *VKIDOAuthProvider) AuthURLWithPKCE(state string) (string, string) {
	scopes := p.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"vkid.personal_info", "email"}
	}

	codeVerifier := generateCodeVerifier()
	codeChallenge := computeS256Challenge(codeVerifier)

	params := url.Values{
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {p.cfg.RedirectURL},
		"response_type":         {"code"},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	return "https://id.vk.com/authorize?" + params.Encode(), codeVerifier
}

// Exchange returns an error because VK ID requires PKCE.
func (p *VKIDOAuthProvider) Exchange(_ context.Context, _ string) (*OAuthUserInfo, error) {
	return nil, fmt.Errorf("vkid: PKCE is required, use ExchangeWithPKCE")
}

// ExchangeWithPKCE exchanges the authorization code for user information from VK ID using PKCE.
func (p *VKIDOAuthProvider) ExchangeWithPKCE(ctx context.Context, code string, codeVerifier string) (*OAuthUserInfo, error) {
	// Exchange code for access token.
	tokenData, err := oauthPostForm(ctx, "https://id.vk.com/oauth2/auth", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {p.cfg.ClientID},
		"device_id":     {generateRandomHex(16)},
		"code_verifier": {codeVerifier},
		"redirect_uri":  {p.cfg.RedirectURL},
	})
	if err != nil {
		return nil, fmt.Errorf("vkid token exchange: %w", err)
	}

	accessToken, _ := tokenData["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("vkid token exchange: missing access_token")
	}

	// Get user info via POST.
	userInfo, err := oauthPostForm(ctx, "https://id.vk.com/oauth2/user_info", url.Values{
		"access_token": {accessToken},
		"client_id":    {p.cfg.ClientID},
	})
	if err != nil {
		return nil, fmt.Errorf("vkid userinfo: %w", err)
	}

	// VK ID may return user data inside a "user" key or at top level.
	userData := userInfo
	if u, ok := userInfo["user"].(map[string]any); ok {
		userData = u
	}

	var userID string
	switch v := userData["user_id"].(type) {
	case float64:
		userID = strconv.FormatInt(int64(v), 10)
	case string:
		userID = v
	}

	email, _ := userData["email"].(string)
	firstName, _ := userData["first_name"].(string)
	lastName, _ := userData["last_name"].(string)
	username := strings.TrimSpace(firstName + " " + lastName)

	return &OAuthUserInfo{
		ProviderID: userID,
		Email:      email,
		Username:   username,
		Verified:   true, // VK ID verifies emails.
	}, nil
}
