# Servex Quickstart Examples

This directory contains comprehensive quickstart examples demonstrating different Servex server configurations using presets.

## Examples Included

1. **Quick Development Server** - Minimal setup for development
2. **Production-Ready Server** - Full production configuration
3. **REST API Server** - API-specific setup with proper routes
4. **Web Application Server** - Complete web app with static files
5. **Microservice Server** - Optimized for microservice deployments
6. **High-Security Server** - Maximum security configuration
7. **SSL-Enabled Server** - HTTPS setup with TLS
8. **API with Authentication** - JWT-based authentication
9. **Real-world Example** - Complex production setup

## Running the Examples

### Default (Development Server)
```bash
go run main.go
```

This runs the development server on port 8080. Visit:
- http://localhost:8080/hello - Main endpoint
- http://localhost:8080/health - Health check

### Running Different Examples

Edit the `main()` function in `main.go` to call different example functions:

```go
func main() {
    // Change this line to run different examples:
    quickDevelopmentServer()      // Default
    // productionReadyServer()    // Production setup
    // restAPIServer()            // REST API
    // webApplicationServer()     // Web app
    // microserviceServer()       // Microservice
    // highSecurityServer()       // High security
    // sslEnabledServer()         // SSL/TLS
    // apiWithAuthentication()    // Auth API
    // realWorldExampleQuickStart() // Real-world
}
```

## Example Details

### Development Server
- Port: 8080
- Features: Basic setup, health endpoint, no security restrictions
- Best for: Local development, testing

### Production Server  
- Ports: 8080 (HTTP), 8443 (HTTPS)
- Features: Security headers, rate limiting, graceful shutdown
- Best for: Production deployments

### REST API Server
- Port: 8080
- Features: API presets, structured routing, rate limiting
- Endpoints: `/api/v1/users`, `/api/v1/posts`

### Web Application Server
- Ports: 8080 (HTTP), 8443 (HTTPS)  
- Features: CSP headers, static file handling, web security
- Endpoints: `/`, `/about`, `/api/data`, `/static/*`

### Microservice Server
- Port: 8080
- Features: Fast timeouts, metrics, readiness probes
- Endpoints: `/metrics`, `/ready`, `/api/v1/*`

### High Security Server
- Port: 8443 (HTTPS only)
- Features: HSTS, bot blocking, aggressive rate limiting
- Best for: High-security applications

### SSL Server
- Port: 8443
- Features: TLS/SSL, HSTS headers
- Note: Requires `cert.pem` and `key.pem` files

### Authenticated API
- Port: 8080
- Features: JWT auth, user roles, protected endpoints
- Default credentials: admin/admin123
- Auth endpoints: `/api/v1/auth/*`

## Testing Examples

### Basic Testing
```bash
# Development server
curl http://localhost:8080/hello
curl http://localhost:8080/health

# API server
curl http://localhost:8080/api/v1/users
curl -X POST http://localhost:8080/api/v1/users -d '{"name":"test"}'

# Authentication
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### Load Testing
```bash
# Install hey for load testing
go install github.com/rakyll/hey@latest

# Test development server
hey -n 1000 -c 10 http://localhost:8080/hello

# Test with rate limiting
hey -n 200 -c 5 -q 5 http://localhost:8080/api/v1/users
```

## Customization

Each example shows how to:
- Use Servex presets for quick setup
- Add custom headers and security
- Configure rate limiting
- Set up health checks
- Handle authentication
- Implement graceful shutdown

## Prerequisites

- Go 1.24+
- Servex framework (automatically resolved via go.mod)

## Next Steps

After trying these examples:
1. Check other example directories for specific features
2. Read the [Configuration Guide](../configuration-guide/)
3. Explore [Security Examples](../security/)
4. Try [Proxy Examples](../proxy-simple/) 