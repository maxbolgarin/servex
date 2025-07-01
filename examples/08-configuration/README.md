# 08 - Configuration

Learn how to configure your Servex server using YAML files, environment variables, and programmatic options. This tutorial covers all configuration approaches from development to production.

## What You'll Learn

- Loading configuration from YAML files
- Using environment variables for configuration
- Combining multiple configuration sources
- Different configurations for different environments
- Configuration best practices

## Features Demonstrated

- ✅ **YAML configuration** - Load settings from files
- ✅ **Environment variables** - Override settings with env vars
- ✅ **Multiple environments** - Dev, staging, production configs
- ✅ **Configuration priority** - How different sources are prioritized
- ✅ **Sample configs** - Ready-to-use configuration files
- ✅ **Configuration validation** - Error handling for invalid configs

## Running This Example

```bash
# Run with default configuration
go run main.go

# Run with custom port via environment variable
SERVEX_PORT=9090 go run main.go

# Visit the demo
open http://localhost:8080/
```

## Configuration Sources

Servex supports multiple configuration sources with this priority order:

1. **Programmatic configuration** (highest priority)
2. **Environment variables**
3. **YAML configuration files** (lowest priority)

### 1. YAML Files

```yaml
# server.yaml
server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: "30s"

security:
  enabled: true
  strict_headers: true

rate_limiting:
  requests_per_second: 10
```

### 2. Environment Variables

```bash
export SERVEX_PORT=8080
export SERVEX_LOG_LEVEL=info
export SERVEX_DEBUG=false
export SERVEX_RATE_LIMIT=10
```

### 3. Programmatic Configuration

```go
server, err := servex.NewServer(
    servex.WithConfigFile("server.yaml"),  // Load from file
    servex.WithSecurityHeaders(),          // Override/add settings
    servex.WithRPS(10),                    // Programmatic override
)
```

## Configuration Files Created

This example creates several sample configuration files:

### server.yaml (Main Configuration)
- Complete server configuration
- Production-ready defaults
- All major features configured

### development.yaml (Development)
- Relaxed security for easier development
- Debug logging enabled
- No rate limiting or caching

### production.yaml (Production)
- Strict security settings
- Optimized for performance
- Comprehensive monitoring

## Environment-Specific Configuration

### Development
```go
// Load development config
server, err := servex.NewServer(
    servex.WithConfigFile("development.yaml"),
)
```

### Production
```go
// Load production config
server, err := servex.NewServer(
    servex.WithConfigFile("production.yaml"),
)
```

## Common Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SERVEX_PORT` | Server port | `8080` |
| `SERVEX_HOST` | Server host | `0.0.0.0` |
| `SERVEX_LOG_LEVEL` | Logging level | `info`, `debug`, `warn` |
| `SERVEX_DEBUG` | Debug mode | `true`, `false` |
| `SERVEX_RATE_LIMIT` | Rate limit (RPS) | `10`, `100` |
| `SERVEX_CONFIG_FILE` | Config file path | `./server.yaml` |

## Configuration Sections

### Server Settings
```yaml
server:
  host: "0.0.0.0"           # Server host
  port: 8080                # Server port
  read_timeout: "30s"       # Request read timeout
  write_timeout: "30s"      # Response write timeout
  idle_timeout: "120s"      # Keep-alive timeout
```

### Security Settings
```yaml
security:
  enabled: true             # Enable security headers
  strict_headers: true      # Use strict security headers
  csp: "default-src 'self'" # Content Security Policy
  hsts: true               # HTTP Strict Transport Security
  hsts_max_age: 31536000   # HSTS max age in seconds
```

### Rate Limiting
```yaml
rate_limiting:
  enabled: true             # Enable rate limiting
  requests_per_second: 10   # Max requests per second
  requests_per_minute: 600  # Max requests per minute
  burst_size: 20           # Burst allowance
```

### Caching
```yaml
cache:
  enabled: true             # Enable caching
  default_ttl: "1h"        # Default cache TTL
  static_assets_ttl: "24h" # Static files cache TTL
  api_ttl: "5m"            # API responses cache TTL
```

### Logging
```yaml
logging:
  level: "info"            # Log level (debug, info, warn, error)
  format: "json"           # Log format (json, text)
  access_log: true         # Enable access logging
```

### Filters
```yaml
filters:
  blocked_user_agents:     # Block these user agents
    - ".*[Bb]ot.*"
    - ".*[Ss]craper.*"
  blocked_ips:             # Block these IP addresses
    - "192.0.2.1"
  excluded_paths:          # Don't filter these paths
    - "/health"
    - "/metrics"
```

## Loading Configuration

### From File
```go
server, err := servex.NewServer(
    servex.WithConfigFile("server.yaml"),
)
```

### With Environment Override
```go
// Environment variables will override file settings
os.Setenv("SERVEX_PORT", "9090")
server, err := servex.NewServer(
    servex.WithConfigFile("server.yaml"),
)
```

### Programmatic Override
```go
// Programmatic settings have highest priority
server, err := servex.NewServer(
    servex.WithConfigFile("server.yaml"),
    servex.WithRPS(50), // This overrides YAML setting
)
```

## Configuration Validation

Servex validates configuration and provides helpful error messages:

```go
server, err := servex.NewServer(
    servex.WithConfigFile("invalid.yaml"),
)
if err != nil {
    log.Printf("Configuration error: %v", err)
    // Handle error or use fallback configuration
}
```

## Testing Configuration

```bash
# Test basic configuration
curl http://localhost:8080/api/config

# Test environment variables
curl http://localhost:8080/api/environment

# Test health with config status
curl http://localhost:8080/health

# Test with different config file
SERVEX_CONFIG_FILE=production.yaml go run main.go
```

## Production Best Practices

### 1. Use Environment Variables for Secrets
```yaml
# Don't put secrets in YAML files
database:
  host: "localhost"
  # Use environment variable for password
  # password: ${DATABASE_PASSWORD}
```

### 2. Separate Configs by Environment
```
configs/
├── base.yaml          # Common settings
├── development.yaml   # Development overrides
├── staging.yaml       # Staging overrides
└── production.yaml    # Production overrides
```

### 3. Configuration Management
```go
// Load config based on environment
env := os.Getenv("ENVIRONMENT")
configFile := fmt.Sprintf("%s.yaml", env)

server, err := servex.NewServer(
    servex.WithConfigFile(configFile),
)
```

### 4. Health Checks Include Config Status
```go
server.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
    ctx.Response(200, map[string]interface{}{
        "status": "healthy",
        "config_loaded": true,
        "environment": os.Getenv("ENVIRONMENT"),
    })
})
```

## Common Patterns

### Configuration Factory
```go
func CreateServer(env string) (*servex.Server, error) {
    configFile := fmt.Sprintf("configs/%s.yaml", env)
    
    return servex.NewServer(
        servex.WithConfigFile(configFile),
        // Add environment-specific overrides
    )
}
```

### Hot Reload (Advanced)
```go
// Watch configuration file for changes
// Reload server configuration without restart
// (Implementation depends on your needs)
```

## What's Next?

🎯 **Continue the tutorial:** → [09-simple-proxy](../09-simple-proxy/)

In the next tutorial, you'll learn how to create reverse proxies and load balancers with Servex. 