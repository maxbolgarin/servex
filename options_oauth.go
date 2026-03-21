package servex

import "context"

// OAuthProvider handles OAuth authentication with an external provider.
// Implement this interface to add support for custom OAuth providers beyond
// the built-in Google, GitHub, Apple, Telegram, and Yandex support.
type OAuthProvider interface {
	// Name returns the provider identifier (e.g. "google", "github").
	Name() string

	// AuthURL returns the URL to redirect the user to for authentication.
	// The state parameter is used for CSRF protection.
	AuthURL(state string) string

	// Exchange validates the authorization code and returns user information.
	Exchange(ctx context.Context, code string) (*OAuthUserInfo, error)
}

// OAuthUserInfo contains user information returned by an OAuth provider.
type OAuthUserInfo struct {
	// ProviderID is the user's unique identifier at the provider.
	ProviderID string

	// Email is the user's email address from the provider.
	Email string

	// Username is the user's display name or username from the provider.
	Username string

	// Verified indicates whether the provider has verified the user's email.
	Verified bool
}

// OAuthConfig configures OAuth social login providers.
type OAuthConfig struct {
	// Enabled activates OAuth social login features.
	Enabled bool

	// Providers is a list of custom OAuthProvider implementations.
	Providers []OAuthProvider

	// AutoLinkByEmail automatically links OAuth accounts to existing users
	// when the email address matches. Default: true.
	AutoLinkByEmail bool

	// StateSigningKey is a hex-encoded 32-byte key for HMAC-SHA256 signing of OAuth state parameters.
	// Used to prevent CSRF attacks during the OAuth flow.
	StateSigningKey string

	// BasePath is the base path for OAuth endpoints, relative to AuthBasePath.
	// Default: "/oauth".
	BasePath string

	// Google configures Google OAuth login.
	Google *GoogleOAuthConfig

	// GitHub configures GitHub OAuth login.
	GitHub *GitHubOAuthConfig

	// Apple configures Apple Sign In.
	Apple *AppleOAuthConfig

	// Telegram configures Telegram Login Widget.
	Telegram *TelegramOAuthConfig

	// Yandex configures Yandex OAuth login.
	Yandex *YandexOAuthConfig

	// stateSigningKey is the decoded state signing key (internal use).
	stateSigningKey []byte
}

// GoogleOAuthConfig configures Google OAuth 2.0 login.
type GoogleOAuthConfig struct {
	// ClientID is the Google OAuth client ID.
	ClientID string

	// ClientSecret is the Google OAuth client secret.
	ClientSecret string

	// RedirectURL is the callback URL registered with Google.
	RedirectURL string

	// Scopes are the OAuth scopes to request. Default: ["openid", "email", "profile"].
	Scopes []string
}

// GitHubOAuthConfig configures GitHub OAuth login.
type GitHubOAuthConfig struct {
	// ClientID is the GitHub OAuth app client ID.
	ClientID string

	// ClientSecret is the GitHub OAuth app client secret.
	ClientSecret string

	// RedirectURL is the callback URL registered with GitHub.
	RedirectURL string

	// Scopes are the OAuth scopes to request. Default: ["user:email"].
	Scopes []string
}

// AppleOAuthConfig configures Apple Sign In.
type AppleOAuthConfig struct {
	// ClientID is the Apple Services ID.
	ClientID string

	// TeamID is the Apple Developer Team ID.
	TeamID string

	// KeyID is the identifier of the private key.
	KeyID string

	// PrivateKey is the PEM-encoded private key for signing client secrets.
	PrivateKey string

	// RedirectURL is the callback URL registered with Apple.
	RedirectURL string

	// Scopes are the OAuth scopes to request. Default: ["name", "email"].
	Scopes []string
}

// TelegramOAuthConfig configures Telegram Login Widget.
type TelegramOAuthConfig struct {
	// BotToken is the Telegram bot token used to verify login data.
	BotToken string

	// RedirectURL is the URL to redirect to after Telegram authentication.
	RedirectURL string
}

// YandexOAuthConfig configures Yandex OAuth login.
type YandexOAuthConfig struct {
	// ClientID is the Yandex OAuth app client ID.
	ClientID string

	// ClientSecret is the Yandex OAuth app client secret.
	ClientSecret string

	// RedirectURL is the callback URL registered with Yandex.
	RedirectURL string

	// Scopes are the OAuth scopes to request.
	Scopes []string
}

// WithOAuth enables OAuth social login with custom provider implementations.
//
// Example:
//
//	server := servex.New(servex.WithOAuth(myGoogleProvider, myGitHubProvider))
//
// Each provider must implement the OAuthProvider interface.
func WithOAuth(providers ...OAuthProvider) Option {
	return func(op *Options) {
		op.Auth.OAuth.Enabled = true
		op.Auth.OAuth.Providers = append(op.Auth.OAuth.Providers, providers...)
	}
}

// WithOAuthGoogle enables Google OAuth login.
//
// Example:
//
//	server := servex.New(servex.WithOAuthGoogle(servex.GoogleOAuthConfig{
//		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
//		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
//		RedirectURL:  "https://myapp.com/oauth/google/callback",
//	}))
func WithOAuthGoogle(cfg GoogleOAuthConfig) Option {
	return func(op *Options) {
		op.Auth.OAuth.Enabled = true
		op.Auth.OAuth.Google = &cfg
	}
}

// WithOAuthGitHub enables GitHub OAuth login.
//
// Example:
//
//	server := servex.New(servex.WithOAuthGitHub(servex.GitHubOAuthConfig{
//		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
//		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
//		RedirectURL:  "https://myapp.com/oauth/github/callback",
//	}))
func WithOAuthGitHub(cfg GitHubOAuthConfig) Option {
	return func(op *Options) {
		op.Auth.OAuth.Enabled = true
		op.Auth.OAuth.GitHub = &cfg
	}
}

// WithOAuthApple enables Apple Sign In.
//
// Example:
//
//	server := servex.New(servex.WithOAuthApple(servex.AppleOAuthConfig{
//		ClientID:    os.Getenv("APPLE_CLIENT_ID"),
//		TeamID:      os.Getenv("APPLE_TEAM_ID"),
//		KeyID:       os.Getenv("APPLE_KEY_ID"),
//		PrivateKey:  os.Getenv("APPLE_PRIVATE_KEY"),
//		RedirectURL: "https://myapp.com/oauth/apple/callback",
//	}))
func WithOAuthApple(cfg AppleOAuthConfig) Option {
	return func(op *Options) {
		op.Auth.OAuth.Enabled = true
		op.Auth.OAuth.Apple = &cfg
	}
}

// WithOAuthTelegram enables Telegram Login Widget authentication.
//
// Example:
//
//	server := servex.New(servex.WithOAuthTelegram(servex.TelegramOAuthConfig{
//		BotToken:    os.Getenv("TELEGRAM_BOT_TOKEN"),
//		RedirectURL: "https://myapp.com/oauth/telegram/callback",
//	}))
func WithOAuthTelegram(cfg TelegramOAuthConfig) Option {
	return func(op *Options) {
		op.Auth.OAuth.Enabled = true
		op.Auth.OAuth.Telegram = &cfg
	}
}

// WithOAuthYandex enables Yandex OAuth login.
//
// Example:
//
//	server := servex.New(servex.WithOAuthYandex(servex.YandexOAuthConfig{
//		ClientID:     os.Getenv("YANDEX_CLIENT_ID"),
//		ClientSecret: os.Getenv("YANDEX_CLIENT_SECRET"),
//		RedirectURL:  "https://myapp.com/oauth/yandex/callback",
//	}))
func WithOAuthYandex(cfg YandexOAuthConfig) Option {
	return func(op *Options) {
		op.Auth.OAuth.Enabled = true
		op.Auth.OAuth.Yandex = &cfg
	}
}

// WithOAuthAutoLink sets whether OAuth accounts are automatically linked to existing users
// when the email address matches.
//
// Example:
//
//	// Disable auto-linking (create separate accounts for OAuth users)
//	server := servex.New(servex.WithOAuthAutoLink(false))
//
// Default: true.
func WithOAuthAutoLink(enabled bool) Option {
	return func(op *Options) {
		op.Auth.OAuth.AutoLinkByEmail = enabled
	}
}

// WithOAuthBasePath sets the base path for OAuth endpoints, relative to AuthBasePath.
//
// Example:
//
//	// OAuth endpoints at /api/v1/auth/social/google, etc.
//	server := servex.New(servex.WithOAuthBasePath("/social"))
//
// Default: "/oauth".
func WithOAuthBasePath(path string) Option {
	return func(op *Options) {
		op.Auth.OAuth.BasePath = path
	}
}

// WithOAuthStateSigningKey sets the HMAC-SHA256 signing key for OAuth state parameters.
// The key should be a hex-encoded string of at least 32 bytes.
// Used to prevent CSRF attacks during the OAuth flow.
//
// Example:
//
//	server := servex.New(servex.WithOAuthStateSigningKey(os.Getenv("OAUTH_STATE_KEY")))
func WithOAuthStateSigningKey(key string) Option {
	return func(op *Options) {
		op.Auth.OAuth.StateSigningKey = key
	}
}

// WithOAuthConfig sets the complete OAuth configuration.
// Use this when you need to configure multiple OAuth settings at once
// or when loading configuration from files or environment variables.
//
// Example:
//
//	oauthCfg := servex.OAuthConfig{
//		Enabled:         true,
//		AutoLinkByEmail: true,
//		BasePath:        "/oauth",
//		Google: &servex.GoogleOAuthConfig{
//			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
//			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
//			RedirectURL:  "https://myapp.com/oauth/google/callback",
//		},
//	}
//	server := servex.New(servex.WithOAuthConfig(oauthCfg))
func WithOAuthConfig(cfg OAuthConfig) Option {
	return func(op *Options) {
		op.Auth.OAuth = cfg
	}
}
