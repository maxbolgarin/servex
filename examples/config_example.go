package main

import (
	"log"
	"net/http"
	"os"

	"github.com/maxbolgarin/servex"
)

func configMain() {
	// === YAML Configuration Example ===
	yamlConfigExample()

	// === Environment Variables Example ===
	envConfigExample()

	// === Combined Configuration Example ===
	combinedConfigExample()

	// === Simple Server Start with Config File ===
	// simpleConfigFileExample()
}

func yamlConfigExample() {
	log.Println("=== YAML Configuration Example ===")

	// Create a sample YAML configuration file
	yamlContent := `
server:
  http: ":8080"
  https: ":8443"
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"
  read_timeout: "30s"
  idle_timeout: "120s"
  auth_token: "secret-api-key"
  enable_health_endpoint: true
  health_path: "/health"
  max_request_body_size: 33554432  # 32MB
  max_json_body_size: 1048576      # 1MB
  enable_request_size_limits: true

auth:
  enabled: true
  use_memory_database: true
  issuer: "my-app"
  access_token_duration: "15m"
  refresh_token_duration: "7d"
  base_path: "/api/v1/auth"
  initial_roles: ["user", "admin"]

rate_limit:
  enabled: true
  requests_per_interval: 100
  interval: "1m"
  burst_size: 20
  status_code: 429
  message: "Rate limit exceeded, please try again later"
  exclude_paths: ["/health", "/metrics"]

security:
  enabled: true
  content_security_policy: "default-src 'self'"
  x_frame_options: "DENY"
  x_content_type_options: "nosniff"
  strict_transport_security: "max-age=31536000; includeSubDomains"

cache:
  enabled: true
  cache_control: "public, max-age=3600"
  vary: "Accept-Encoding"

logging:
  disable_request_logging: false
  no_log_client_errors: true
  log_fields: ["method", "url", "status", "duration"]
`

	// Write the example config to a temporary file
	configFile := "example_config.yaml"
	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		log.Fatal("Failed to write config file:", err)
	}
	defer os.Remove(configFile) // Clean up

	// Load configuration from YAML file
	config, err := servex.LoadConfigFromFile(configFile)
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	log.Printf("Loaded config - HTTP: %s, HTTPS: %s", config.Server.HTTP, config.Server.HTTPS)
	log.Printf("Auth enabled: %v, Rate limit enabled: %v", config.Auth.Enabled, config.RateLimit.Enabled)

	// Convert config to servex options
	opts, err := config.ToOptions()
	if err != nil {
		log.Fatal("Failed to convert config to options:", err)
	}

	log.Printf("Generated %d servex options from config", len(opts))

	// Create server from config
	server, err := servex.NewFromConfig(config)
	if err != nil {
		log.Fatal("Failed to create server from config:", err)
	}

	// Setup routes
	server.HandleFunc("/api/hello", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"message": "Hello from YAML-configured server!",
			"config":  "loaded from YAML file",
		})
	})

	log.Println("Server created successfully from YAML config")
	// Note: Not starting the server in this example to avoid port conflicts
}

func envConfigExample() {
	log.Println("\n=== Environment Variables Example ===")

	// Set some environment variables
	os.Setenv("SERVEX_SERVER_HTTP", ":8081")
	os.Setenv("SERVEX_SERVER_AUTH_TOKEN", "env-secret-token")
	os.Setenv("SERVEX_SERVER_ENABLE_HEALTH_ENDPOINT", "true")
	os.Setenv("SERVEX_SERVER_HEALTH_PATH", "/status")
	os.Setenv("SERVEX_AUTH_ENABLED", "true")
	os.Setenv("SERVEX_AUTH_USE_MEMORY_DATABASE", "true")
	os.Setenv("SERVEX_AUTH_ISSUER", "env-app")
	os.Setenv("SERVEX_AUTH_ACCESS_TOKEN_DURATION", "30m")
	os.Setenv("SERVEX_AUTH_REFRESH_TOKEN_DURATION", "14d")
	os.Setenv("SERVEX_RATE_LIMIT_ENABLED", "true")
	os.Setenv("SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL", "200")
	os.Setenv("SERVEX_RATE_LIMIT_INTERVAL", "1m")
	os.Setenv("SERVEX_RATE_LIMIT_BURST_SIZE", "50")
	os.Setenv("SERVEX_SECURITY_ENABLED", "true")
	os.Setenv("SERVEX_SECURITY_X_FRAME_OPTIONS", "SAMEORIGIN")
	os.Setenv("SERVEX_LOGGING_NO_LOG_CLIENT_ERRORS", "true")

	defer func() {
		// Clean up environment variables
		envVars := []string{
			"SERVEX_SERVER_HTTP", "SERVEX_SERVER_AUTH_TOKEN", "SERVEX_SERVER_ENABLE_HEALTH_ENDPOINT",
			"SERVEX_SERVER_HEALTH_PATH", "SERVEX_AUTH_ENABLED", "SERVEX_AUTH_USE_MEMORY_DATABASE",
			"SERVEX_AUTH_ISSUER", "SERVEX_AUTH_ACCESS_TOKEN_DURATION", "SERVEX_AUTH_REFRESH_TOKEN_DURATION",
			"SERVEX_RATE_LIMIT_ENABLED", "SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL", "SERVEX_RATE_LIMIT_INTERVAL",
			"SERVEX_RATE_LIMIT_BURST_SIZE", "SERVEX_SECURITY_ENABLED", "SERVEX_SECURITY_X_FRAME_OPTIONS",
			"SERVEX_LOGGING_NO_LOG_CLIENT_ERRORS",
		}
		for _, envVar := range envVars {
			os.Unsetenv(envVar)
		}
	}()

	// Load configuration from environment variables
	config, err := servex.LoadConfigFromEnv()
	if err != nil {
		log.Fatal("Failed to load config from env:", err)
	}

	log.Printf("Loaded config from env - HTTP: %s, Auth Token: %s", config.Server.HTTP, config.Server.AuthToken)
	log.Printf("Auth enabled: %v, Rate limit: %v req/min", config.Auth.Enabled, config.RateLimit.RequestsPerInterval)

	// Create server from environment config
	server, err := servex.NewFromConfig(config)
	if err != nil {
		log.Fatal("Failed to create server from env config:", err)
	}

	// Setup routes
	server.HandleFunc("/api/env", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"message": "Hello from environment-configured server!",
			"config":  "loaded from environment variables",
		})
	})

	log.Println("Server created successfully from environment variables")
}

func combinedConfigExample() {
	log.Println("\n=== Combined YAML + Environment Variables Example ===")

	// Create a base YAML configuration
	yamlContent := `
server:
  http: ":8082"
  read_timeout: "15s"
  idle_timeout: "60s"
  enable_health_endpoint: true

auth:
  enabled: true
  use_memory_database: true
  access_token_duration: "10m"
  refresh_token_duration: "3d"

rate_limit:
  enabled: true
  requests_per_interval: 50
  interval: "1m"
  burst_size: 10
`

	configFile := "base_config.yaml"
	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		log.Fatal("Failed to write config file:", err)
	}
	defer os.Remove(configFile)

	// Set environment variables that will override YAML values
	os.Setenv("SERVEX_SERVER_HTTP", ":8083")                       // Override YAML
	os.Setenv("SERVEX_SERVER_AUTH_TOKEN", "override-secret-token") // Add new value
	os.Setenv("SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL", "150")    // Override YAML
	os.Setenv("SERVEX_AUTH_ISSUER", "combined-app")                // Add new value
	os.Setenv("SERVEX_SECURITY_ENABLED", "true")                   // Add new section
	os.Setenv("SERVEX_SECURITY_X_FRAME_OPTIONS", "DENY")

	defer func() {
		os.Unsetenv("SERVEX_SERVER_HTTP")
		os.Unsetenv("SERVEX_SERVER_AUTH_TOKEN")
		os.Unsetenv("SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL")
		os.Unsetenv("SERVEX_AUTH_ISSUER")
		os.Unsetenv("SERVEX_SECURITY_ENABLED")
		os.Unsetenv("SERVEX_SECURITY_X_FRAME_OPTIONS")
	}()

	// Load configuration from YAML file with environment overlay
	config, err := servex.LoadConfig(configFile)
	if err != nil {
		log.Fatal("Failed to load combined config:", err)
	}

	log.Printf("Combined config - HTTP: %s (env override)", config.Server.HTTP)
	log.Printf("Auth Token: %s (from env)", config.Server.AuthToken)
	log.Printf("Rate limit: %v req/min (env override)", config.RateLimit.RequestsPerInterval)
	log.Printf("Auth issuer: %s (from env)", config.Auth.Issuer)
	log.Printf("Security enabled: %v (from env)", config.Security.Enabled)

	// Create server from combined config
	server, err := servex.NewFromConfig(config)
	if err != nil {
		log.Fatal("Failed to create server from combined config:", err)
	}

	// Setup routes
	server.HandleFunc("/api/combined", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"message": "Hello from combined YAML + env configured server!",
			"config":  "YAML base with environment overrides",
		})
	})

	log.Println("Server created successfully from combined configuration")
}

// Example of starting a server directly from a config file
func simpleConfigFileExample() {
	log.Println("\n=== Simple Config File Server Start Example ===")

	// Create a minimal config file
	yamlContent := `
server:
  http: ":8084"
  enable_health_endpoint: true
  health_path: "/health"

auth:
  enabled: true
  use_memory_database: true

rate_limit:
  enabled: true
  requests_per_interval: 100
  interval: "1m"
`

	configFile := "simple_config.yaml"
	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		log.Fatal("Failed to write config file:", err)
	}
	defer os.Remove(configFile)

	// Start server directly from config file (commented out to avoid port conflicts)
	/*
		shutdown, err := servex.StartFromConfig(configFile, func(r *mux.Router) {
			r.HandleFunc("/api/simple", func(w http.ResponseWriter, r *http.Request) {
				ctx := servex.C(w, r)
				ctx.Response(200, map[string]string{
					"message": "Simple config server is running!",
				})
			}).Methods("GET")
		})
		if err != nil {
			log.Fatal("Failed to start server from config:", err)
		}
		defer shutdown()

		log.Println("Server started from config file on :8084")
		log.Println("Health endpoint available at: http://localhost:8084/health")
		log.Println("API endpoint available at: http://localhost:8084/api/simple")

		// Keep server running for demonstration
		time.Sleep(5 * time.Second)
	*/

	log.Println("Simple config file example completed (server start commented out)")
}

// Example of production-ready configuration
func productionConfigExample() {
	productionYAML := `
server:
  http: ":8080"
  https: ":8443"
  cert_file: "/etc/ssl/certs/server.crt"
  key_file: "/etc/ssl/private/server.key"
  read_timeout: "10s"
  read_header_timeout: "5s"
  idle_timeout: "120s"
  enable_health_endpoint: true
  health_path: "/health"
  max_request_body_size: 10485760      # 10MB
  max_json_body_size: 1048576          # 1MB
  max_file_upload_size: 104857600      # 100MB
  enable_request_size_limits: true

auth:
  enabled: true
  use_memory_database: false  # Use real database in production
  issuer: "production-api"
  access_token_duration: "15m"
  refresh_token_duration: "7d"
  base_path: "/api/v1/auth"
  initial_roles: ["user"]

rate_limit:
  enabled: true
  requests_per_interval: 1000
  interval: "1m"
  burst_size: 100
  status_code: 429
  message: "Rate limit exceeded. Please try again later."
  exclude_paths: ["/health", "/metrics", "/favicon.ico"]
  trusted_proxies: ["10.0.0.0/8", "172.16.0.0/12"]

security:
  enabled: true
  content_security_policy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
  x_frame_options: "DENY"
  x_content_type_options: "nosniff"
  x_xss_protection: "1; mode=block"
  strict_transport_security: "max-age=31536000; includeSubDomains; preload"
  referrer_policy: "strict-origin-when-cross-origin"

cache:
  enabled: true
  cache_control: "public, max-age=3600"
  vary: "Accept-Encoding, Accept"

logging:
  disable_request_logging: false
  no_log_client_errors: true
  log_fields: ["method", "url", "status", "duration", "ip", "user_agent"]
`

	log.Println("Production configuration example:")
	log.Println(productionYAML)
}
