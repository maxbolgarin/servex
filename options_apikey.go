package servex

// APIKeyConfig holds API key authentication configuration.
// API key auth activates when Database is set (no Enabled flag needed).
type APIKeyConfig struct {
	// Database is the storage backend for API keys.
	// Set via WithAPIKeys() or WithAPIKeysMemoryDatabase().
	Database APIKeyDatabase

	// Prefix is prepended to all generated API keys. Defaults to "svx_".
	Prefix string

	// ValidScopes is the list of allowed scope values.
	// When set, scope validation is enforced on key creation.
	ValidScopes []string

	// MaxPerUser is the maximum number of API keys a single user may hold.
	// Defaults to 10.
	MaxPerUser int

	// KeyLength is the number of random bytes used when generating a key.
	// The hex-encoded output will be twice this length. Defaults to 16.
	KeyLength int
}

// WithAPIKeys enables API key authentication with the provided database backend.
func WithAPIKeys(db APIKeyDatabase) Option {
	return func(o *Options) {
		o.APIKey.Database = db
	}
}

// WithAPIKeysMemoryDatabase enables API key authentication with an in-memory database.
// Intended for development and testing — data is lost on restart.
func WithAPIKeysMemoryDatabase() Option {
	return func(o *Options) {
		o.APIKey.Database = NewMemoryAPIKeyDatabase()
	}
}

// WithAPIKeyPrefix sets the string prepended to all generated API keys.
func WithAPIKeyPrefix(prefix string) Option {
	return func(o *Options) {
		o.APIKey.Prefix = prefix
	}
}

// WithAPIKeyScopes sets the list of valid scope values.
// When configured, key creation validates that all requested scopes are in this list.
func WithAPIKeyScopes(scopes ...string) Option {
	return func(o *Options) {
		o.APIKey.ValidScopes = scopes
	}
}

// WithAPIKeyMaxPerUser sets the maximum number of API keys a single user may hold.
func WithAPIKeyMaxPerUser(n int) Option {
	return func(o *Options) {
		o.APIKey.MaxPerUser = n
	}
}

// WithAPIKeyLength sets the number of random bytes used when generating a key.
func WithAPIKeyLength(n int) Option {
	return func(o *Options) {
		o.APIKey.KeyLength = n
	}
}

// WithAPIKeyConfig replaces the entire APIKeyConfig.
func WithAPIKeyConfig(cfg APIKeyConfig) Option {
	return func(o *Options) {
		o.APIKey = cfg
	}
}
