# 08 - Configuration

Learn how to configure your Servex server using YAML files with environment variable overlays. This tutorial demonstrates the proper way to load configuration from files and override settings with environment variables.

## What You'll Learn

- Loading configuration from YAML files using `servex.LoadConfig()`
- Creating servers from configuration using `servex.NewServerFromConfig()`
- Using environment variables to override YAML settings
- Proper Servex configuration structure and field names
- Different configurations for development and production
- Configuration best practices and security

## Features Demonstrated

- ✅ **YAML configuration** - Load complete server configuration from files
- ✅ **Environment variable overlay** - Override any setting with env vars
- ✅ **Multiple environments** - Development, production ready configs
- ✅ **Configuration validation** - Proper error handling and validation
- ✅ **Security best practices** - Token masking and secure defaults
- ✅ **Production ready** - Real-world configuration examples

## Running This Example

```bash
# Run with default configuration (loads server.yaml + environment overlay)
go run main.go

# Run with custom settings via environment variables
SERVEX_SERVER_HTTP=":9090" SERVEX_RATE_LIMIT_ENABLED="false" go run main.go

# Run with different config file
cp production.yaml server.yaml && go run main.go

# Visit the interactive demo
open http://localhost:8080/
```

## Configuration Architecture

Servex uses a structured configuration approach:

1. **Load YAML file** - Base configuration from file
2. **Apply environment overlay** - Environment variables override YAML settings
3. **Create server from config** - Use `NewServerFromConfig()` for complete setup

### Configuration Loading Process

```go
// 1. Load configuration from YAML with environment overlay
config, err := servex.LoadConfig("server.yaml")
if err != nil {
    log.Fatalf("Failed to load configuration: %v", err)
}

// 2. Create server from configuration
server, err := servex.NewServerFromConfig(config)
if err != nil {
    log.Fatalf("Failed to create server from config: %v", err)
}

// 3. Start server
err = server.StartWithWaitSignalsHTTP(context.Background(), config.Server.HTTP)
if err != nil {
    log.Fatal("Failed to start server:", err)
}
```

## Configuration Structure

### Complete YAML Configuration

```yaml
# server.yaml - Complete Servex configuration
server:
  http: ":8080"                           # HTTP listen address
  # https: ":8443"                        # HTTPS listen address (optional)
  # cert_file: "/path/to/cert.pem"        # TLS certificate file
  # key_file: "/path/to/key.pem"          # TLS private key file
  
  read_timeout: "30s"                     # Request read timeout
  read_header_timeout: "10s"              # Header read timeout
  idle_timeout: "120s"                    # Keep-alive timeout
  
  # auth_token: "your-secret-api-key"     # Simple bearer token auth
  
  enable_health_endpoint: true            # Enable /health endpoint
  health_path: "/health"                  # Health check path
  enable_default_metrics: true            # Enable /metrics endpoint
  metrics_path: "/metrics"                # Metrics endpoint path
  
  enable_request_size_limits: true        # Enable request size limits
  max_request_body_size: 33554432         # 32MB max request body
  max_json_body_size: 1048576             # 1MB max JSON body
  max_file_upload_size: 10485760          # 10MB max file upload
  max_multipart_memory: 10485760          # 10MB multipart memory
  
  send_error_to_client: false             # Don't expose errors (production)

# Rate limiting configuration
rate_limit:
  enabled: true                           # Enable rate limiting
  requests_per_interval: 10               # Max requests per interval
  interval: "1m"                          # Rate limit interval
  burst_size: 20                          # Burst allowance
  status_code: 429                        # Rate limit status code
  message: "Rate limit exceeded"          # Rate limit message
  exclude_paths:                          # Paths to exclude from rate limiting
    - "/health"
    - "/metrics"

# Request filtering
filter:
  blocked_user_agents:                    # Block these user agents
    - "badbot"
    - "scraper"
  blocked_ips:                            # Block these IP addresses
    - "192.0.2.1"
  exclude_paths:                          # Paths to exclude from filtering
    - "/health"
    - "/metrics"

# Security headers
security:
  enabled: true                           # Enable security headers
  content_security_policy: "default-src 'self'"    # CSP header
  x_frame_options: "DENY"                 # X-Frame-Options header
  x_content_type_options: "nosniff"       # X-Content-Type-Options header
  strict_transport_security: "max-age=31536000"    # HSTS header
  referrer_policy: "strict-origin-when-cross-origin" # Referrer policy

# Cache control
cache:
  enabled: true                           # Enable cache headers
  cache_control: "public, max-age=3600"   # Default cache control
  exclude_paths:                          # Paths to exclude from caching
    - "/api/*"

# Response compression
compression:
  enabled: true                           # Enable gzip compression
  level: 6                                # Compression level (1-9)
  min_size: 1024                          # Minimum response size to compress
  types:                                  # MIME types to compress
    - "text/html"
    - "text/css"
    - "application/javascript"
    - "application/json"

# Request logging
logging:
  disable_request_logging: false          # Enable request logging
  no_log_client_errors: false             # Log client errors (4xx)
  log_fields:                             # Fields to include in logs
    - "method"
    - "url"
    - "status"
    - "duration_ms"
    - "ip"

# CORS configuration
cors:
  enabled: true                           # Enable CORS
  allow_origins:                          # Allowed origins
    - "*"
  allow_methods:                          # Allowed HTTP methods
    - "GET"
    - "POST"
    - "PUT"
    - "DELETE"
    - "OPTIONS"
  allow_headers:                          # Allowed headers
    - "Content-Type"
    - "Authorization"
  max_age: 86400                          # Preflight cache duration

# Static file serving (optional)
static_files:
  enabled: false                          # Enable static file serving
  # dir: "./static"                       # Static files directory
  # url_prefix: "/static/"                # URL prefix for static files
  # cache_max_age: 86400                  # Static files cache duration
```

## Environment Variables

All configuration can be overridden using environment variables with the `SERVEX_` prefix:

### Server Configuration
```bash
export SERVEX_SERVER_HTTP=":8080"                      # Server listen address
export SERVEX_SERVER_HTTPS=":8443"                     # HTTPS listen address
export SERVEX_SERVER_CERT_FILE="/path/to/cert.pem"     # TLS certificate file
export SERVEX_SERVER_KEY_FILE="/path/to/key.pem"       # TLS private key file
export SERVEX_SERVER_READ_TIMEOUT="30s"                # Request read timeout
export SERVEX_SERVER_IDLE_TIMEOUT="120s"               # Keep-alive timeout
export SERVEX_SERVER_AUTH_TOKEN="your-secret-token"    # Authentication token
export SERVEX_SERVER_ENABLE_HEALTH_ENDPOINT="true"     # Enable health endpoint
export SERVEX_SERVER_SEND_ERROR_TO_CLIENT="false"      # Show errors to client
```

### Rate Limiting
```bash
export SERVEX_RATE_LIMIT_ENABLED="true"                # Enable rate limiting
export SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL="10"    # Max requests per interval
export SERVEX_RATE_LIMIT_INTERVAL="1m"                 # Rate limit interval
export SERVEX_RATE_LIMIT_BURST_SIZE="20"               # Burst allowance
```

### Security
```bash
export SERVEX_SECURITY_ENABLED="true"                  # Enable security headers
export SERVEX_SECURITY_CONTENT_SECURITY_POLICY="default-src 'self'" # CSP header
export SERVEX_SECURITY_X_FRAME_OPTIONS="DENY"          # X-Frame-Options
```

### Logging
```bash
export SERVEX_LOGGING_DISABLE_REQUEST_LOGGING="false"  # Enable request logging
export SERVEX_LOGGING_NO_LOG_CLIENT_ERRORS="false"     # Log client errors
export SERVEX_LOGGING_LOG_FIELDS="method,url,status,duration_ms,ip" # Log fields
```

## Configuration Files Created

This example creates three ready-to-use configuration files:

### server.yaml (Production Ready)
- Complete server configuration with all features
- Security headers enabled
- Rate limiting configured
- Request logging enabled
- Production-safe defaults

### development.yaml (Developer Friendly)
```yaml
server:
  http: ":8080"
  send_error_to_client: true              # Show errors for debugging
  enable_health_endpoint: true

rate_limit:
  enabled: false                          # No rate limiting in development

security:
  enabled: false                          # Relaxed security for development

cache:
  enabled: false                          # No caching for easier testing

logging:
  disable_request_logging: false
  log_fields:
    - "method"
    - "url"
    - "status"
    - "duration_ms"
    - "ip"
    - "user_agent"
    - "error"                             # Include errors for debugging
```

### production.yaml (Hardened Production)
```yaml
server:
  http: ":8080"
  read_timeout: "30s"
  idle_timeout: "300s"
  max_request_body_size: 10485760         # Smaller limits for production
  send_error_to_client: false             # Hide errors from clients

rate_limit:
  enabled: true
  requests_per_interval: 100              # Higher limits for production
  interval: "1m"

security:
  enabled: true
  content_security_policy: "default-src 'self'; script-src 'self' 'unsafe-inline'"
  strict_transport_security: "max-age=31536000; includeSubDomains"

logging:
  no_log_client_errors: true              # Don't log client errors in production

cors:
  allow_origins:                          # Restrict origins in production
    - "https://yourdomain.com"
    - "https://www.yourdomain.com"
```

## Loading Different Configurations

### Load Specific Configuration File
```go
// Load development configuration
config, err := servex.LoadConfig("development.yaml")

// Load production configuration  
config, err := servex.LoadConfig("production.yaml")

// Create server from any configuration
server, err := servex.NewServerFromConfig(config)
```

### Environment-Based Configuration
```go
// Load configuration based on environment
env := os.Getenv("ENVIRONMENT")
if env == "" {
    env = "development"
}

configFile := fmt.Sprintf("%s.yaml", env)
config, err := servex.LoadConfig(configFile)
if err != nil {
    log.Fatalf("Failed to load %s configuration: %v", env, err)
}

server, err := servex.NewServerFromConfig(config)
```

## Testing Configuration

```bash
# Test main configuration endpoint
curl http://localhost:8080/api/config

# Test environment variables display
curl http://localhost:8080/api/environment

# Test health endpoint (configured via YAML)
curl http://localhost:8080/health

# Test with environment variable override
SERVEX_SERVER_HTTP=":9090" go run main.go
curl http://localhost:9090/api/config
```

## Configuration Best Practices

### 1. Environment Variable Hierarchy
```bash
# Use environment variables for deployment-specific settings
export SERVEX_SERVER_HTTP=":${PORT:-8080}"             # Use PORT from platform
export SERVEX_SERVER_AUTH_TOKEN="${API_SECRET_TOKEN}"  # Use secret from vault
export SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL="${RATE_LIMIT:-100}"
```

### 2. Security Considerations
```yaml
server:
  # Never put secrets directly in YAML files
  # auth_token: "secret"  ❌ Don't do this
  
  # Use environment variables for secrets
  # Set SERVEX_SERVER_AUTH_TOKEN environment variable instead ✅
  
  send_error_to_client: false             # Always false in production
```

### 3. Configuration Validation
```go
config, err := servex.LoadConfig("server.yaml")
if err != nil {
    log.Fatalf("Configuration error: %v", err)
}

// Validate required settings
if config.Server.HTTP == "" && config.Server.HTTPS == "" {
    log.Fatal("Either HTTP or HTTPS server address must be configured")
}

server, err := servex.NewServerFromConfig(config)
if err != nil {
    log.Fatalf("Server creation failed: %v", err)
}
```

### 4. Graceful Server Management
```go
// Proper server lifecycle management
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// Handle shutdown signals
go func() {
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    <-sigChan
    cancel()
}()

// Start server with graceful shutdown
err = server.StartWithWaitSignalsHTTP(ctx, config.Server.HTTP)
if err != nil {
    log.Fatal("Server error:", err)
}
```

## API Endpoints

This example provides several endpoints to test configuration:

- `GET /` - Interactive configuration demo page
- `GET /api/config` - Display loaded configuration details
- `GET /api/environment` - Show environment variable values
- `GET /health` - Health check with configuration status

## What's Next?

🎯 **Continue the tutorial:** → [09-simple-proxy](../09-simple-proxy/)

In the next tutorial, you'll learn how to create reverse proxies and load balancers with Servex, including advanced proxy configurations and traffic routing. 