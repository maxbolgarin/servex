package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/maxbolgarin/servex/v2"
)

func main() {
	fmt.Println("🚀 Servex Tutorial - Configuration")
	fmt.Println("===================================")

	// Create sample configuration files
	createSampleConfigs()

	// Example 1: Set up environment variables first
	fmt.Println("Setting up environment variables...")
	setupEnvironmentConfig()

	// Example 2: Load configuration from YAML file with environment overlay
	fmt.Println("Loading configuration from YAML file with environment variables overlay...")
	config, err := servex.LoadConfig("server.yaml")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Example 3: Create server from configuration
	server, err := servex.NewServerFromConfig(config)
	if err != nil {
		log.Fatalf("Failed to create server from config: %v", err)
	}

	// Add routes to demonstrate different configuration approaches
	server.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"message":       "Server configured from YAML and environment variables",
			"config_source": "server.yaml + environment overlay",
			"tutorial":      "08-configuration",
			"server_config": map[string]any{
				"http":                   config.Server.HTTP,
				"read_timeout":           config.Server.ReadTimeout.String(),
				"idle_timeout":           config.Server.IdleTimeout.String(),
				"enable_health_endpoint": config.Server.EnableHealthEndpoint,
				"auth_token_set":         config.Server.AuthToken != "",
			},
			"rate_limit_enabled": config.RateLimit.Enabled,
			"security_enabled":   config.Security.Enabled,
			"cache_enabled":      config.Cache.Enabled,
		})
	})

	server.HandleFunc("/api/environment", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"environment_variables": map[string]string{
				"SERVEX_SERVER_HTTP":                      os.Getenv("SERVEX_SERVER_HTTP"),
				"SERVEX_SERVER_AUTH_TOKEN":                maskToken(os.Getenv("SERVEX_SERVER_AUTH_TOKEN")),
				"SERVEX_RATE_LIMIT_ENABLED":               os.Getenv("SERVEX_RATE_LIMIT_ENABLED"),
				"SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL": os.Getenv("SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL"),
				"SERVEX_SECURITY_ENABLED":                 os.Getenv("SERVEX_SECURITY_ENABLED"),
				"SERVEX_LOGGING_DISABLE_REQUEST_LOGGING":  os.Getenv("SERVEX_LOGGING_DISABLE_REQUEST_LOGGING"),
			},
			"tutorial": "08-configuration",
		})
	})

	server.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"status": "healthy",
			"config": "loaded from server.yaml with environment overlay",
		})
	})

	// Demo page showing configuration options
	server.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := `
<!DOCTYPE html>
<html>
<head>
    <title>Configuration Demo</title>
    <style>
        body { font-family: Arial; max-width: 900px; margin: 0 auto; padding: 20px; }
        .container { background: #f8f9fa; padding: 20px; border-radius: 8px; }
        .config-box { background: white; border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; border-left: 4px solid #007bff; }
        button { background: #007bff; color: white; border: none; padding: 10px 15px; margin: 5px; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .results { background: white; border: 1px solid #ddd; padding: 15px; margin-top: 10px; border-radius: 4px; height: 200px; overflow-y: auto; }
        .info { color: blue; }
        .success { color: green; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Servex Configuration Tutorial</h1>
        <p>This demo shows how to configure your Servex server using YAML files with environment variable overlays.</p>
        
        <h2>📄 Configuration Sources</h2>
        
        <div class="config-box">
            <h3>1. YAML Configuration File</h3>
            <p>The server is configured using <code>server.yaml</code> with proper Servex structure:</p>
            <pre>
server:
  http: ":8080"
  read_timeout: "30s"
  idle_timeout: "120s"
  enable_health_endpoint: true
  health_path: "/health"
  
rate_limit:
  enabled: true
  requests_per_interval: 10
  interval: "1m"
  
security:
  enabled: true
  content_security_policy: "default-src 'self'"</pre>
        </div>
        
        <div class="config-box">
            <h3>2. Environment Variables Overlay</h3>
            <p>Configuration can be overridden with environment variables using proper SERVEX_ prefixes:</p>
            <pre>
export SERVEX_SERVER_HTTP=":8080"
export SERVEX_RATE_LIMIT_ENABLED="true"
export SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL="10"
export SERVEX_SECURITY_ENABLED="true"</pre>
        </div>
        
        <div class="config-box">
            <h3>3. Server Creation from Config</h3>
            <p>Server is created directly from configuration:</p>
            <pre>
// Load config from file with environment overlay
config, err := servex.LoadConfig("server.yaml")
if err != nil {
    log.Fatal(err)
}

// Create server from configuration
server, err := servex.NewServerFromConfig(config)
if err != nil {
    log.Fatal(err)
}</pre>
        </div>
        
        <h2>🧪 Test Configuration</h2>
        <button onclick="testConfig()">Test Config Endpoint</button>
        <button onclick="testEnvironment()">Test Environment Variables</button>
        <button onclick="testHealth()">Test Health Check</button>
        
        <div id="results" class="results">
            <div class="info">Click a button to test configuration...</div>
        </div>
        
        <h2>🔧 Configuration Files Created</h2>
        <ul>
            <li><code>server.yaml</code> - Main configuration file (production-ready)</li>
            <li><code>development.yaml</code> - Development environment config</li>
            <li><code>production.yaml</code> - Production environment config</li>
        </ul>
        
        <h2>🧪 Manual Testing</h2>
        <pre>
# Test configuration endpoint
curl http://localhost:8080/api/config

# Test environment variables
curl http://localhost:8080/api/environment

# Check health (configured via YAML)
curl http://localhost:8080/health

# Start with environment variable override
SERVEX_SERVER_HTTP=":9090" go run main.go

# Enable debug logging
SERVEX_LOGGING_DISABLE_REQUEST_LOGGING="false" go run main.go
        </pre>
    </div>

    <script>
        function log(message, type = 'info') {
            const results = document.getElementById('results');
            const div = document.createElement('div');
            div.className = type;
            div.textContent = new Date().toLocaleTimeString() + ' - ' + message;
            results.appendChild(div);
            results.scrollTop = results.scrollHeight;
        }

        function testConfig() {
            log('Testing configuration endpoint...', 'info');
            fetch('/api/config')
                .then(response => response.json())
                .then(data => {
                    log('✅ Configuration loaded: ' + data.config_source, 'success');
                    console.log('Config details:', data);
                })
                .catch(err => log('❌ Error: ' + err.message, 'error'));
        }

        function testEnvironment() {
            log('Testing environment variables...', 'info');
            fetch('/api/environment')
                .then(response => response.json())
                .then(data => {
                    log('✅ Environment variables retrieved', 'success');
                    console.log('Environment:', data.environment_variables);
                })
                .catch(err => log('❌ Error: ' + err.message, 'error'));
        }

        function testHealth() {
            log('Testing health check...', 'info');
            fetch('/health')
                .then(response => response.json())
                .then(data => {
                    log('✅ Health check passed: ' + data.status, 'success');
                })
                .catch(err => log('❌ Error: ' + err.message, 'error'));
        }
    </script>
</body>
</html>`
		servex.C(w, r).Response(200, html)
	})

	fmt.Println("🌐 Server starting on http://localhost:8080")
	fmt.Println("📄 Configuration loaded from server.yaml with environment overlay")
	fmt.Println("🔧 Available environment variables:")
	fmt.Println("    SERVEX_SERVER_HTTP - Server listen address")
	fmt.Println("    SERVEX_SERVER_AUTH_TOKEN - API authentication token")
	fmt.Println("    SERVEX_RATE_LIMIT_ENABLED - Enable/disable rate limiting")
	fmt.Println("    SERVEX_SECURITY_ENABLED - Enable/disable security headers")
	fmt.Println("")
	fmt.Println("Try these URLs:")
	fmt.Println("  → http://localhost:8080/ (configuration demo)")
	fmt.Println("  → http://localhost:8080/api/config (config info)")
	fmt.Println("  → http://localhost:8080/api/environment (env vars)")
	fmt.Println("  → http://localhost:8080/health (health check)")
	fmt.Println("")
	fmt.Println("Configuration files created:")
	fmt.Println("  → server.yaml (main config)")
	fmt.Println("  → development.yaml (dev config)")
	fmt.Println("  → production.yaml (prod config)")
	fmt.Println("")
	fmt.Println("Try custom settings: SERVEX_SERVER_HTTP=':9090' SERVEX_RATE_LIMIT_ENABLED='false' go run main.go")
	fmt.Println("Press Ctrl+C to stop")

	// Use config.Server.HTTP for the address
	address := config.Server.HTTP
	if address == "" {
		address = ":8080"
	}

	err = server.StartWithWaitSignalsHTTP(context.Background(), address)
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func setupEnvironmentConfig() {
	// Set realistic environment variables using proper SERVEX prefixes
	os.Setenv("SERVEX_SERVER_HTTP", ":8080")
	os.Setenv("SERVEX_RATE_LIMIT_ENABLED", "true")
	os.Setenv("SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL", "10")
	os.Setenv("SERVEX_SECURITY_ENABLED", "true")
	os.Setenv("SERVEX_LOGGING_DISABLE_REQUEST_LOGGING", "false")
}

func maskToken(token string) string {
	if token == "" {
		return "(not set)"
	}
	if len(token) <= 8 {
		return "****"
	}
	return token[:4] + "****" + token[len(token)-4:]
}

func createSampleConfigs() {
	// Create main server.yaml configuration file with only valid fields
	mainConfig := `# Servex Server Configuration
# This file demonstrates proper YAML configuration for Servex

server:
  http: ":8080"
  # https: ":8443"  # Uncomment and set cert_file/key_file for HTTPS
  # cert_file: "/path/to/cert.pem"
  # key_file: "/path/to/key.pem"
  
  read_timeout: "30s"
  read_header_timeout: "10s"
  idle_timeout: "120s"
  
  # Simple token-based authentication
  # auth_token: "your-secret-api-key-change-in-production"
  
  # Built-in endpoints
  enable_health_endpoint: true
  health_path: "/health"
  enable_default_metrics: true
  metrics_path: "/metrics"
  
  # Request size limits
  enable_request_size_limits: true
  max_request_body_size: 33554432    # 32MB
  max_json_body_size: 1048576        # 1MB
  max_file_upload_size: 10485760     # 10MB
  max_multipart_memory: 10485760     # 10MB
  
  # Error handling (false for production)
  send_error_to_client: false

# Rate limiting configuration
rate_limit:
  enabled: true
  requests_per_interval: 10
  interval: "1m"
  burst_size: 20
  status_code: 429
  message: "Rate limit exceeded"
  exclude_paths:
    - "/health"
    - "/metrics"

# Request filtering
filter:
  blocked_user_agents:
    - "badbot"
    - "scraper"
  blocked_ips:
    - "192.0.2.1"  # Example blocked IP
  exclude_paths:
    - "/health"
    - "/metrics"

# Security headers
security:
  enabled: true
  content_security_policy: "default-src 'self'"
  x_frame_options: "DENY"
  x_content_type_options: "nosniff"
  strict_transport_security: "max-age=31536000"
  referrer_policy: "strict-origin-when-cross-origin"

# Cache control
cache:
  enabled: true
  cache_control: "public, max-age=3600"
  exclude_paths:
    - "/api/*"

# Response compression
compression:
  enabled: true
  level: 6
  min_size: 1024
  types:
    - "text/html"
    - "text/css"
    - "application/javascript"
    - "application/json"

# Request logging
logging:
  disable_request_logging: false
  no_log_client_errors: false
  log_fields:
    - "method"
    - "url"
    - "status"
    - "duration_ms"
    - "ip"

# CORS configuration
cors:
  enabled: true
  allow_origins:
    - "*"
  allow_methods:
    - "GET"
    - "POST"
    - "PUT"
    - "DELETE"
    - "OPTIONS"
  allow_headers:
    - "Content-Type"
    - "Authorization"
  max_age: 86400

# Static file serving
static_files:
  enabled: false
  # dir: "./static"
  # url_prefix: "/static/"
  # cache_max_age: 86400
`

	// Create development.yaml configuration
	devConfig := `# Development Environment Configuration
server:
  http: ":8080"
  read_timeout: "10s"
  idle_timeout: "60s"
  send_error_to_client: true  # Show errors in development
  enable_health_endpoint: true

rate_limit:
  enabled: false  # No rate limiting in development

security:
  enabled: false  # Relaxed security for development

cache:
  enabled: false  # No caching for easier testing

compression:
  enabled: false  # No compression for debugging

logging:
  disable_request_logging: false
  no_log_client_errors: false
  log_fields:
    - "method"
    - "url"
    - "status"
    - "duration_ms"
    - "ip"
    - "user_agent"
    - "error"

cors:
  enabled: true
  allow_origins:
    - "*"
  allow_methods:
    - "GET"
    - "POST"
    - "PUT"
    - "DELETE"
    - "OPTIONS"
  allow_credentials: true
`

	// Create production.yaml configuration
	prodConfig := `# Production Environment Configuration
server:
  http: ":8080"
  # https: ":8443"
  # cert_file: "/etc/ssl/certs/server.crt"
  # key_file: "/etc/ssl/private/server.key"
  
  read_timeout: "30s"
  read_header_timeout: "10s"
  idle_timeout: "300s"
  
  enable_health_endpoint: true
  health_path: "/health"
  enable_default_metrics: true
  metrics_path: "/metrics"
  
  enable_request_size_limits: true
  max_request_body_size: 10485760     # 10MB in production
  max_json_body_size: 1048576         # 1MB
  max_file_upload_size: 5242880       # 5MB
  
  send_error_to_client: false

rate_limit:
  enabled: true
  requests_per_interval: 100
  interval: "1m"
  burst_size: 50
  status_code: 429
  exclude_paths:
    - "/health"
    - "/metrics"

filter:
  blocked_user_agents_regex:
    - ".*[Bb]ot.*"
    - ".*[Ss]craper.*"
    - ".*[Cc]rawler.*"
  exclude_paths:
    - "/health"
    - "/metrics"

security:
  enabled: true
  content_security_policy: "default-src 'self'; script-src 'self' 'unsafe-inline'"
  x_frame_options: "DENY"
  x_content_type_options: "nosniff"
  strict_transport_security: "max-age=31536000; includeSubDomains"
  referrer_policy: "strict-origin-when-cross-origin"

cache:
  enabled: true
  cache_control: "public, max-age=3600"
  exclude_paths:
    - "/api/*"
    - "/health"
    - "/metrics"

compression:
  enabled: true
  level: 6
  min_size: 1024
  types:
    - "text/html"
    - "text/css"
    - "application/javascript"
    - "application/json"
    - "text/plain"

logging:
  disable_request_logging: false
  no_log_client_errors: true  # Don't log client errors in production
  log_fields:
    - "method"
    - "url" 
    - "status"
    - "duration_ms"
    - "ip"

cors:
  enabled: true
  allow_origins:
    - "https://yourdomain.com"
    - "https://www.yourdomain.com"
  allow_methods:
    - "GET"
    - "POST"
    - "PUT"
    - "DELETE"
    - "OPTIONS"
  allow_headers:
    - "Content-Type"
    - "Authorization"
  max_age: 86400
`

	// Write configuration files
	os.WriteFile("server.yaml", []byte(mainConfig), 0644)
	os.WriteFile("development.yaml", []byte(devConfig), 0644)
	os.WriteFile("production.yaml", []byte(prodConfig), 0644)
}
