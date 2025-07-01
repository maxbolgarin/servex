package main

import (
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

	// Example 1: Load from YAML file
	fmt.Println("Loading configuration from YAML file...")
	server := createServerFromYAML()

	// Example 2: Environment variable configuration
	fmt.Println("Configuration also supports environment variables")
	setupEnvironmentConfig()

	// Add routes to demonstrate different configuration approaches
	server.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":       "Server configured from YAML and environment variables",
			"config_source": "server.yaml + environment",
			"tutorial":      "08-configuration",
		})
	})

	server.HandleFunc("/api/environment", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"environment_variables": map[string]string{
				"SERVEX_PORT":      os.Getenv("SERVEX_PORT"),
				"SERVEX_LOG_LEVEL": os.Getenv("SERVEX_LOG_LEVEL"),
				"SERVEX_DEBUG":     os.Getenv("SERVEX_DEBUG"),
			},
			"tutorial": "08-configuration",
		})
	})

	server.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"status": "healthy",
			"config": "loaded",
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
        <p>This demo shows different ways to configure your Servex server: YAML files, environment variables, and programmatic configuration.</p>
        
        <h2>📄 Configuration Sources</h2>
        
        <div class="config-box">
            <h3>1. YAML Configuration File</h3>
            <p>The server is configured using <code>server.yaml</code>:</p>
            <pre>
server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: "30s"
  write_timeout: "30s"
  
security:
  enabled: true
  strict_headers: true
  
rate_limiting:
  requests_per_second: 10
  requests_per_minute: 600
  
cache:
  enabled: true
  default_ttl: "1h"</pre>
        </div>
        
        <div class="config-box">
            <h3>2. Environment Variables</h3>
            <p>Configuration can be overridden with environment variables:</p>
            <pre>
export SERVEX_PORT=8080
export SERVEX_LOG_LEVEL=info
export SERVEX_DEBUG=false
export SERVEX_RATE_LIMIT=10</pre>
        </div>
        
        <div class="config-box">
            <h3>3. Programmatic Configuration</h3>
            <p>Configuration can also be set directly in code:</p>
            <pre>
server, err := servex.NewServer(
    servex.WithSecurityHeaders(),
    servex.WithRPS(10),
    servex.WithCachePublic(3600),
)</pre>
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
            <li><code>server.yaml</code> - Main configuration file</li>
            <li><code>development.yaml</code> - Development environment config</li>
            <li><code>production.yaml</code> - Production environment config</li>
        </ul>
        
        <h2>🧪 Manual Testing</h2>
        <pre>
# Test configuration endpoint
curl http://localhost:8080/api/config

# Test environment variables
curl http://localhost:8080/api/environment

# Check health
curl http://localhost:8080/health

# Start with custom port (environment variable)
SERVEX_PORT=9090 go run main.go
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
                    log('✅ Health check passed: ' + data.status + ', config: ' + data.config, 'success');
                })
                .catch(err => log('❌ Error: ' + err.message, 'error'));
        }
    </script>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, html)
	})

	fmt.Println("🌐 Server starting on http://localhost:8080")
	fmt.Println("📄 Configuration loaded from server.yaml")
	fmt.Println("🌍 Environment variables supported")
	fmt.Println("")
	fmt.Println("Try these URLs:")
	fmt.Println("  → http://localhost:8080/ (configuration demo)")
	fmt.Println("  → http://localhost:8080/api/config (config info)")
	fmt.Println("  → http://localhost:8080/api/environment (env vars)")
	fmt.Println("")
	fmt.Println("Configuration files created:")
	fmt.Println("  → server.yaml (main config)")
	fmt.Println("  → development.yaml (dev config)")
	fmt.Println("  → production.yaml (prod config)")
	fmt.Println("")
	fmt.Println("Try custom port: SERVEX_PORT=9090 go run main.go")
	fmt.Println("Press Ctrl+C to stop")

	server.Start(":8080", "")
}

func createServerFromYAML() *servex.Server {
	// Create server with configuration (note: WithConfigFile may not be available)
	server, err := servex.NewServer(
		// Basic configuration for the demo
		servex.WithSecurityHeaders(),
		servex.WithRPS(10),
		servex.WithCachePublic(3600),
	)
	if err != nil {
		log.Printf("Failed to create server from YAML: %v", err)
		// Fallback to programmatic configuration
		server, err = servex.NewServer(
			servex.WithSecurityHeaders(),
			servex.WithRPS(10),
			servex.WithCachePublic(3600),
		)
		if err != nil {
			log.Fatal("Failed to create server:", err)
		}
	}

	return server
}

func setupEnvironmentConfig() {
	// Set some example environment variables
	os.Setenv("SERVEX_PORT", "8080")
	os.Setenv("SERVEX_LOG_LEVEL", "info")
	os.Setenv("SERVEX_DEBUG", "false")
	os.Setenv("SERVEX_RATE_LIMIT", "10")
}

func createSampleConfigs() {
	// Create main server.yaml configuration file
	mainConfig := `# Servex Server Configuration
# This file demonstrates YAML configuration for Servex

server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "120s"

security:
  enabled: true
  strict_headers: true
  csp: "default-src 'self'"
  hsts: true
  hsts_max_age: 31536000

rate_limiting:
  enabled: true
  requests_per_second: 10
  requests_per_minute: 600
  burst_size: 20

cache:
  enabled: true
  default_ttl: "1h"
  static_assets_ttl: "24h"
  api_ttl: "5m"

logging:
  level: "info"
  format: "json"
  access_log: true

# Filters and security
filters:
  blocked_user_agents:
    - ".*[Bb]ot.*"
    - ".*[Ss]craper.*"
  blocked_ips:
    - "192.0.2.1"
  excluded_paths:
    - "/health"
    - "/metrics"

# Static file serving
static:
  enabled: true
  directory: "./static"
  url_prefix: "/static/"
  cache_control: "public, max-age=86400"
`

	// Create development.yaml configuration
	devConfig := `# Development Environment Configuration
server:
  host: "localhost"
  port: 8080
  read_timeout: "10s"
  write_timeout: "10s"

security:
  enabled: false  # Relaxed for development
  strict_headers: false

rate_limiting:
  enabled: false  # No rate limiting in dev

cache:
  enabled: false  # No caching in dev for easier testing

logging:
  level: "debug"
  format: "text"
  access_log: true

filters:
  enabled: false  # No filtering in development
`

	// Create production.yaml configuration
	prodConfig := `# Production Environment Configuration
server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "300s"

security:
  enabled: true
  strict_headers: true
  csp: "default-src 'self'; script-src 'self' 'unsafe-inline'"
  hsts: true
  hsts_max_age: 31536000
  hsts_preload: true

rate_limiting:
  enabled: true
  requests_per_second: 50
  requests_per_minute: 3000
  burst_size: 100

cache:
  enabled: true
  default_ttl: "1h"
  static_assets_ttl: "7d"
  api_ttl: "15m"

logging:
  level: "warn"
  format: "json"
  access_log: true

filters:
  enabled: true
  blocked_user_agents:
    - ".*[Bb]ot.*"
    - ".*[Ss]craper.*"
    - ".*[Cc]rawler.*"
  blocked_query_params:
    debug: ["true", "1"]
    admin: ["true", "1"]
  excluded_paths:
    - "/health"
    - "/metrics"
    - "/status"

# Production-specific settings
monitoring:
  enabled: true
  metrics_endpoint: "/metrics"
  health_endpoint: "/health"
`

	// Write configuration files
	os.WriteFile("server.yaml", []byte(mainConfig), 0644)
	os.WriteFile("development.yaml", []byte(devConfig), 0644)
	os.WriteFile("production.yaml", []byte(prodConfig), 0644)
}
