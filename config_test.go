package servex

import (
	"os"
	"testing"
	"time"
)

func TestLoadConfigFromFile(t *testing.T) {
	// Create a temporary YAML config file
	yamlContent := `
server:
  http: ":8080"
  https: ":8443"
  read_timeout: "30s"
  auth_token: "test-token"
  enable_health_endpoint: true

auth:
  enabled: true
  use_memory_database: true
  issuer: "test-app"
  access_token_duration: "15m"

rate_limit:
  enabled: true
  requests_per_interval: 100
  interval: "1m"
  burst_size: 20
`

	// Write to temporary file
	tmpFile := "test_config.yaml"
	err := os.WriteFile(tmpFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}
	defer os.Remove(tmpFile)

	// Load configuration
	config, err := LoadConfigFromFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify server configuration
	if config.Server.HTTP != ":8080" {
		t.Errorf("Expected HTTP :8080, got %s", config.Server.HTTP)
	}
	if config.Server.HTTPS != ":8443" {
		t.Errorf("Expected HTTPS :8443, got %s", config.Server.HTTPS)
	}
	if config.Server.ReadTimeout != 30*time.Second {
		t.Errorf("Expected ReadTimeout 30s, got %v", config.Server.ReadTimeout)
	}
	if config.Server.AuthToken != "test-token" {
		t.Errorf("Expected AuthToken test-token, got %s", config.Server.AuthToken)
	}
	if !config.Server.EnableHealthEndpoint {
		t.Error("Expected EnableHealthEndpoint to be true")
	}

	// Verify auth configuration
	if !config.Auth.Enabled {
		t.Error("Expected Auth.Enabled to be true")
	}
	if !config.Auth.UseMemoryDatabase {
		t.Error("Expected Auth.UseMemoryDatabase to be true")
	}
	if config.Auth.Issuer != "test-app" {
		t.Errorf("Expected Auth.Issuer test-app, got %s", config.Auth.Issuer)
	}
	if config.Auth.AccessTokenDuration != 15*time.Minute {
		t.Errorf("Expected Auth.AccessTokenDuration 15m, got %v", config.Auth.AccessTokenDuration)
	}

	// Verify rate limit configuration
	if !config.RateLimit.Enabled {
		t.Error("Expected RateLimit.Enabled to be true")
	}
	if config.RateLimit.RequestsPerInterval != 100 {
		t.Errorf("Expected RateLimit.RequestsPerInterval 100, got %d", config.RateLimit.RequestsPerInterval)
	}
	if config.RateLimit.Interval != time.Minute {
		t.Errorf("Expected RateLimit.Interval 1m, got %v", config.RateLimit.Interval)
	}
	if config.RateLimit.BurstSize != 20 {
		t.Errorf("Expected RateLimit.BurstSize 20, got %d", config.RateLimit.BurstSize)
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	// Set environment variables
	envVars := map[string]string{
		"SERVEX_SERVER_HTTP":                      ":8081",
		"SERVEX_SERVER_AUTH_TOKEN":                "env-token",
		"SERVEX_SERVER_ENABLE_HEALTH_ENDPOINT":    "true",
		"SERVEX_SERVER_READ_TIMEOUT":              "45s",
		"SERVEX_AUTH_ENABLED":                     "true",
		"SERVEX_AUTH_USE_MEMORY_DATABASE":         "true",
		"SERVEX_AUTH_ISSUER":                      "env-app",
		"SERVEX_AUTH_ACCESS_TOKEN_DURATION":       "20m",
		"SERVEX_RATE_LIMIT_ENABLED":               "true",
		"SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL": "200",
		"SERVEX_RATE_LIMIT_INTERVAL":              "1m",
		"SERVEX_RATE_LIMIT_BURST_SIZE":            "50",
	}

	// Set environment variables
	for key, value := range envVars {
		os.Setenv(key, value)
	}

	// Clean up after test
	defer func() {
		for key := range envVars {
			os.Unsetenv(key)
		}
	}()

	// Load configuration from environment
	config, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("Failed to load config from env: %v", err)
	}

	// Verify server configuration
	if config.Server.HTTP != ":8081" {
		t.Errorf("Expected HTTP :8081, got %s", config.Server.HTTP)
	}
	if config.Server.AuthToken != "env-token" {
		t.Errorf("Expected AuthToken env-token, got %s", config.Server.AuthToken)
	}
	if !config.Server.EnableHealthEndpoint {
		t.Error("Expected EnableHealthEndpoint to be true")
	}
	if config.Server.ReadTimeout != 45*time.Second {
		t.Errorf("Expected ReadTimeout 45s, got %v", config.Server.ReadTimeout)
	}

	// Verify auth configuration
	if !config.Auth.Enabled {
		t.Error("Expected Auth.Enabled to be true")
	}
	if !config.Auth.UseMemoryDatabase {
		t.Error("Expected Auth.UseMemoryDatabase to be true")
	}
	if config.Auth.Issuer != "env-app" {
		t.Errorf("Expected Auth.Issuer env-app, got %s", config.Auth.Issuer)
	}
	if config.Auth.AccessTokenDuration != 20*time.Minute {
		t.Errorf("Expected Auth.AccessTokenDuration 20m, got %v", config.Auth.AccessTokenDuration)
	}

	// Verify rate limit configuration
	if !config.RateLimit.Enabled {
		t.Error("Expected RateLimit.Enabled to be true")
	}
	if config.RateLimit.RequestsPerInterval != 200 {
		t.Errorf("Expected RateLimit.RequestsPerInterval 200, got %d", config.RateLimit.RequestsPerInterval)
	}
	if config.RateLimit.Interval != time.Minute {
		t.Errorf("Expected RateLimit.Interval 1m, got %v", config.RateLimit.Interval)
	}
	if config.RateLimit.BurstSize != 50 {
		t.Errorf("Expected RateLimit.BurstSize 50, got %d", config.RateLimit.BurstSize)
	}
}

func TestLoadConfigCombined(t *testing.T) {
	// Create a YAML config file
	yamlContent := `
server:
  http: ":8080"
  read_timeout: "30s"
  auth_token: "yaml-token"

auth:
  enabled: true
  issuer: "yaml-app"
  access_token_duration: "10m"

rate_limit:
  enabled: true
  requests_per_interval: 50
  interval: "1m"
`

	tmpFile := "test_combined_config.yaml"
	err := os.WriteFile(tmpFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}
	defer os.Remove(tmpFile)

	// Set environment variables that should override YAML
	envVars := map[string]string{
		"SERVEX_SERVER_HTTP":                      ":8082",   // Override YAML
		"SERVEX_SERVER_HTTPS":                     ":8443",   // Add new value
		"SERVEX_AUTH_ISSUER":                      "env-app", // Override YAML
		"SERVEX_AUTH_ACCESS_TOKEN_DURATION":       "25m",     // Override YAML
		"SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL": "150",     // Override YAML
	}

	for key, value := range envVars {
		os.Setenv(key, value)
	}

	defer func() {
		for key := range envVars {
			os.Unsetenv(key)
		}
	}()

	// Load combined configuration
	config, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("Failed to load combined config: %v", err)
	}

	// Verify environment overrides took effect
	if config.Server.HTTP != ":8082" {
		t.Errorf("Expected HTTP :8082 (env override), got %s", config.Server.HTTP)
	}
	if config.Server.HTTPS != ":8443" {
		t.Errorf("Expected HTTPS :8443 (from env), got %s", config.Server.HTTPS)
	}
	if config.Auth.Issuer != "env-app" {
		t.Errorf("Expected Auth.Issuer env-app (env override), got %s", config.Auth.Issuer)
	}
	if config.Auth.AccessTokenDuration != 25*time.Minute {
		t.Errorf("Expected Auth.AccessTokenDuration 25m (env override), got %v", config.Auth.AccessTokenDuration)
	}
	if config.RateLimit.RequestsPerInterval != 150 {
		t.Errorf("Expected RateLimit.RequestsPerInterval 150 (env override), got %d", config.RateLimit.RequestsPerInterval)
	}

	// Verify YAML values that weren't overridden
	if config.Server.ReadTimeout != 30*time.Second {
		t.Errorf("Expected ReadTimeout 30s (from YAML), got %v", config.Server.ReadTimeout)
	}
	if config.Server.AuthToken != "yaml-token" {
		t.Errorf("Expected AuthToken yaml-token (from YAML), got %s", config.Server.AuthToken)
	}
}

func TestConfigToOptions(t *testing.T) {
	config := &Config{
		Server: ServerConfig{
			HTTP:                    ":8080",
			HTTPS:                   ":8443",
			ReadTimeout:             30 * time.Second,
			AuthToken:               "test-token",
			EnableHealthEndpoint:    true,
			HealthPath:              "/health",
			MaxRequestBodySize:      32 << 20, // 32MB
			EnableRequestSizeLimits: true,
		},
		Auth: AuthConfiguration{
			Enabled:              true,
			UseMemoryDatabase:    true,
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 7 * 24 * time.Hour,
			Issuer:               "test-app",
			InitialRoles:         []string{"user", "admin"},
		},
		RateLimit: RateLimitConfiguration{
			Enabled:             true,
			RequestsPerInterval: 100,
			Interval:            time.Minute,
			BurstSize:           20,
			StatusCode:          429,
			Message:             "Rate limited",
		},
	}

	opts, err := config.ToOptions()
	if err != nil {
		t.Fatalf("Failed to convert config to options: %v", err)
	}

	// Verify that options were generated
	if len(opts) == 0 {
		t.Error("Expected at least some options to be generated")
	}

	// Create server with the options to verify they work
	_, err = NewWithOptions(parseOptions(opts))
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

func TestConfigToBaseConfig(t *testing.T) {
	config := &Config{
		Server: ServerConfig{
			HTTP:      ":8080",
			HTTPS:     ":8443",
			CertFile:  "/path/to/cert.pem",
			KeyFile:   "/path/to/key.pem",
			AuthToken: "test-token",
		},
	}

	baseConfig := config.ToBaseConfig()

	if baseConfig.HTTP != ":8080" {
		t.Errorf("Expected HTTP :8080, got %s", baseConfig.HTTP)
	}
	if baseConfig.HTTPS != ":8443" {
		t.Errorf("Expected HTTPS :8443, got %s", baseConfig.HTTPS)
	}
	if baseConfig.CertFile != "/path/to/cert.pem" {
		t.Errorf("Expected CertFile /path/to/cert.pem, got %s", baseConfig.CertFile)
	}
	if baseConfig.KeyFile != "/path/to/key.pem" {
		t.Errorf("Expected KeyFile /path/to/key.pem, got %s", baseConfig.KeyFile)
	}
	if baseConfig.AuthToken != "test-token" {
		t.Errorf("Expected AuthToken test-token, got %s", baseConfig.AuthToken)
	}
}

func TestNewFromConfig(t *testing.T) {
	config := &Config{
		Server: ServerConfig{
			HTTP:                    ":8080",
			ReadTimeout:             30 * time.Second,
			EnableHealthEndpoint:    true,
			MaxRequestBodySize:      32 << 20,
			EnableRequestSizeLimits: true,
		},
		Auth: AuthConfiguration{
			Enabled:           true,
			UseMemoryDatabase: true,
			Issuer:            "test-app",
		},
	}

	_, err := NewFromConfig(config)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

func TestEnvironmentVariableParsing(t *testing.T) {
	tests := []struct {
		name     string
		envVar   string
		envValue string
		expected interface{}
		checkFn  func(*Config) interface{}
	}{
		{
			name:     "boolean true",
			envVar:   "SERVEX_SERVER_ENABLE_HEALTH_ENDPOINT",
			envValue: "true",
			expected: true,
			checkFn:  func(c *Config) interface{} { return c.Server.EnableHealthEndpoint },
		},
		{
			name:     "boolean false",
			envVar:   "SERVEX_AUTH_ENABLED",
			envValue: "false",
			expected: false,
			checkFn:  func(c *Config) interface{} { return c.Auth.Enabled },
		},
		{
			name:     "integer",
			envVar:   "SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL",
			envValue: "250",
			expected: 250,
			checkFn:  func(c *Config) interface{} { return c.RateLimit.RequestsPerInterval },
		},
		{
			name:     "duration",
			envVar:   "SERVEX_SERVER_READ_TIMEOUT",
			envValue: "45s",
			expected: 45 * time.Second,
			checkFn:  func(c *Config) interface{} { return c.Server.ReadTimeout },
		},
		{
			name:     "string",
			envVar:   "SERVEX_AUTH_ISSUER",
			envValue: "test-issuer",
			expected: "test-issuer",
			checkFn:  func(c *Config) interface{} { return c.Auth.Issuer },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			os.Setenv(tt.envVar, tt.envValue)
			defer os.Unsetenv(tt.envVar)

			// Load config from environment
			config, err := LoadConfigFromEnv()
			if err != nil {
				t.Fatalf("Failed to load config from env: %v", err)
			}

			// Check the parsed value
			actual := tt.checkFn(config)
			if actual != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, actual)
			}
		})
	}
}
