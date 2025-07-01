# Servex Commands

This directory contains standalone command applications built with servex.

## Available Commands

### 1. Proxy Server (`proxy-server`)

A standalone L7 reverse proxy and API gateway that configures entirely from YAML files.

**Features:**
- Multiple load balancing strategies (round-robin, weighted, least-connections, IP hash, random)
- Health checking with automatic failover
- Traffic dumping for analysis and debugging
- Rate limiting and request filtering
- Security headers and CSRF protection
- Management endpoints for monitoring

**Usage:**
```bash
# Build the proxy server
go build -o proxy-server ./cmd/proxy-server

# Run with default config file
./proxy-server

# Run with custom config file
./proxy-server -config=my-proxy-config.yaml

# Show version
./proxy-server -version

# Show help
./proxy-server -h
```

**Configuration:**
- Copy `proxy-config.yaml` and modify for your backends
- Configure proxy rules, health checks, and load balancing
- Enable traffic dumping and monitoring features

**Management Endpoints:**
- `/proxy/status` - Proxy status and statistics
- `/proxy/backends` - Backend configuration and health
- `/proxy/config` - Current configuration (sanitized)
- `/proxy/health` - Health check with backend status
- `/health` - Simple health check
- `/metrics` - Prometheus metrics

### 2. SPA Server (`spa-server`)

A high-performance server for React, Vue, Angular and other Single Page Applications.

**Features:**
- SPA routing with fallback to index.html
- Built-in API endpoints for development
- Security headers and CSRF protection
- File upload support
- Rate limiting appropriate for web applications
- Static asset caching
- HTTPS support

**Usage:**
```bash
# Build the SPA server
go build -o spa-server ./cmd/spa-server

# Run with default settings (serves ./build on port 3000)
./spa-server

# Serve from different directory and port
./spa-server -dir=dist -port=8080

# Enable HTTPS (requires cert.pem and key.pem)
./spa-server -https -cert=server.crt -key=server.key

# Bind to specific host
./spa-server -host=127.0.0.1 -port=3000

# Custom API prefix
./spa-server -api=/api/v1

# Show version
./spa-server -version

# Show help
./spa-server -h
```

**API Endpoints:**
The SPA server includes built-in API endpoints for development:

- `GET /api/info` - Server information
- `GET /api/status` - Server status
- `GET /api/users` - Mock user list
- `GET /api/users/{id}` - Mock user details
- `POST /api/users` - Create user (mock)
- `GET /api/config` - App configuration
- `GET /api/csrf-token` - CSRF token for forms
- `POST /api/upload` - File upload endpoint
- `GET /api/search?q=query` - Search endpoint

**Static File Handling:**
- Serves all files from the build directory
- Client-side routing support (SPA mode)
- Automatic Content-Type detection
- Configurable caching for different file types
- Gzip compression support

**Development Workflow:**
1. Build your React/Vue/Angular app
2. Point SPA server to the build directory
3. Use the built-in API endpoints for development
4. Replace with real API endpoints in production

## Common Use Cases

### Proxy Server Use Cases

**API Gateway:**
```yaml
# Configure multiple microservices behind one gateway
proxy:
  rules:
    - name: "user-service"
      path_prefix: "/api/users/"
      backends: [...]
    - name: "order-service"  
      path_prefix: "/api/orders/"
      backends: [...]
```

**Load Balancer:**
```yaml
# Balance traffic across multiple backend instances
proxy:
  rules:
    - name: "web-app"
      path_prefix: "/"
      load_balancing: "weighted_round_robin"
      backends:
        - url: "http://app1:8080"
          weight: 3
        - url: "http://app2:8080"
          weight: 1
```

**Traffic Analysis:**
```yaml
# Dump traffic for debugging and analysis
proxy:
  traffic_dump:
    enabled: true
    directory: "./logs"
    sample_rate: 0.1  # Sample 10% of traffic
    include_body: true
```

### SPA Server Use Cases

**React Development:**
```bash
# After npm run build
./spa-server -dir=build -port=3000
```

**Vue Production:**
```bash
# After npm run build
./spa-server -dir=dist -port=80 -https
```

**Angular Deployment:**
```bash
# After ng build
./spa-server -dir=dist/my-app -port=8080
```

## Building and Deployment

### Build All Commands
```bash
# Build both commands
make build-commands

# Or build individually
go build -o proxy-server ./cmd/proxy-server
go build -o spa-server ./cmd/spa-server
```

### Docker Deployment
```dockerfile
# Multi-stage build example
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o proxy-server ./cmd/proxy-server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/proxy-server .
COPY --from=builder /app/cmd/proxy-server/proxy-config.yaml .
CMD ["./proxy-server"]
```

### Production Considerations

**Proxy Server:**
- Use HTTPS with proper certificates
- Configure rate limiting based on your backend capacity
- Monitor traffic dumps and rotate log files
- Set up health check alerts
- Use systemd or supervisor for process management

**SPA Server:**
- Enable HTTPS in production
- Configure proper cache headers for static assets
- Set up reverse proxy (nginx) for additional features
- Monitor API endpoint usage
- Implement proper authentication for API endpoints

## Configuration Examples

### Proxy Server - Microservices Gateway
```yaml
proxy:
  enabled: true
  rules:
    - name: "auth-service"
      path_prefix: "/api/auth/"
      backends:
        - url: "http://auth:8080"
      load_balancing: "round_robin"
      
    - name: "user-service"
      path_prefix: "/api/users/"
      backends:
        - url: "http://users:8080"
      load_balancing: "least_connections"
      
    - name: "static-assets"
      path_prefix: "/static/"
      backends:
        - url: "http://cdn:8080"
      load_balancing: "random"
```

### SPA Server - Full Stack Development
```bash
# Terminal 1: Start backend API
go run ./api-server -port=8081

# Terminal 2: Start SPA server
./spa-server -dir=build -api=/api -port=3000

# Now your React app can call /api/* endpoints
# which proxy to your backend, and all other routes
# serve the React app for client-side routing
``` 