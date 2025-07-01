# Servex Simple Proxy Example

This directory contains a simple reverse proxy example demonstrating load balancing, health checking, and traffic monitoring with Servex.

## Features Demonstrated

- **Load Balancing**: Weighted round-robin between multiple backends
- **Health Checking**: Automatic backend health monitoring
- **Traffic Dumping**: Request/response logging for debugging
- **Rate Limiting**: 100 requests per minute
- **Metrics**: Built-in metrics endpoint
- **Graceful Shutdown**: Clean server shutdown handling

## Running the Example

### Start the Proxy Server
```bash
go run main.go
```

This starts the proxy server on port 8080. Visit http://localhost:8080 for an info page.

### Backend Services Required

For the proxy to work, you need backend services running on:
- `localhost:8081` (API Backend 1, weight 2)
- `localhost:8082` (API Backend 2, weight 1) 
- `localhost:8083` (Auth Service)

## Setting Up Backend Services

### Quick Setup (One-liner)
You can use these commands to quickly start test backends:

```bash
# Backend 1 (port 8081)
echo 'package main
import ("fmt"; "net/http")
func main() {
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"status": "ok", "service": "backend-1"}`)
    })
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"message": "Hello from backend 1", "port": 8081}`)
    })
    fmt.Println("Backend 1 starting on :8081")
    http.ListenAndServe(":8081", nil)
}' > backend1.go && go run backend1.go &

# Backend 2 (port 8082)
echo 'package main
import ("fmt"; "net/http")
func main() {
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"status": "ok", "service": "backend-2"}`)
    })
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"message": "Hello from backend 2", "port": 8082}`)
    })
    fmt.Println("Backend 2 starting on :8082")
    http.ListenAndServe(":8082", nil)
}' > backend2.go && go run backend2.go &

# Auth service (port 8083)
echo 'package main
import ("fmt"; "net/http")
func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"message": "Auth service", "endpoint": "%s"}`, r.URL.Path)
    })
    fmt.Println("Auth service starting on :8083")
    http.ListenAndServe(":8083", nil)
}' > auth.go && go run auth.go &
```

### Using Docker (Alternative)
```bash
# Backend 1
docker run -d -p 8081:80 --name backend1 nginx

# Backend 2  
docker run -d -p 8082:80 --name backend2 nginx

# Simple auth service
docker run -d -p 8083:8080 --name auth httpd
```

## Testing the Proxy

### Basic Testing
```bash
# Check proxy status
curl http://localhost:8080/status

# Test API load balancing (will alternate between backends)
curl http://localhost:8080/api/users
curl http://localhost:8080/api/data
curl http://localhost:8080/api/products

# Test auth service
curl http://localhost:8080/auth/login
curl http://localhost:8080/auth/validate

# Check health endpoint
curl http://localhost:8080/health

# Check metrics
curl http://localhost:8080/metrics
```

### Load Testing
```bash
# Install hey for load testing
go install github.com/rakyll/hey@latest

# Test API load balancing
hey -n 100 -c 10 http://localhost:8080/api/users

# Test auth service
hey -n 50 -c 5 http://localhost:8080/auth/login

# Test with rate limiting (should hit 100 RPM limit)
hey -n 200 -c 20 -q 10 http://localhost:8080/api/data
```

### Monitoring Traffic
```bash
# Check traffic dumps (created in ./traffic_logs/)
ls -la ./traffic_logs/

# View traffic logs (JSON format)
tail -f ./traffic_logs/traffic_dump_000.jsonl

# Parse traffic logs
cat ./traffic_logs/traffic_dump_000.jsonl | jq '.rule'
cat ./traffic_logs/traffic_dump_000.jsonl | jq '.backend'
```

## Proxy Configuration

### Load Balancing Rules

1. **API Service** (`/api/*`)
   - Backend 1: `localhost:8081` (weight 2) - gets 2/3 of traffic
   - Backend 2: `localhost:8082` (weight 1) - gets 1/3 of traffic
   - Strategy: Weighted Round Robin
   - Health checks: `/health` every 30s
   - Timeout: 20s

2. **Auth Service** (`/auth/*`)
   - Backend: `localhost:8083` (weight 1)
   - Strategy: Round Robin
   - Timeout: 15s

### Traffic Dumping
- **Enabled**: 50% sampling rate
- **Directory**: `./traffic_logs/`
- **Includes**: Request/response bodies up to 32KB
- **Format**: JSON lines (JSONL)

### Health Checking
- **Interval**: 30 seconds
- **Timeout**: 5 seconds  
- **Retries**: 2 attempts before marking unhealthy
- **Path**: `/health` (for API backends)

## Understanding Load Balancing

### Weighted Round Robin
With weights of 2:1 for the API backends:
- Request 1 → Backend 1 (8081)
- Request 2 → Backend 1 (8081) 
- Request 3 → Backend 2 (8082)
- Request 4 → Backend 1 (8081)
- Request 5 → Backend 1 (8081)
- Request 6 → Backend 2 (8082)
- ...and so on

### Health Check Behavior
- Healthy backends receive traffic
- Unhealthy backends are removed from rotation
- Health status is checked continuously
- Backends auto-recover when health checks pass

## Endpoints

| Endpoint | Description | Cached |
|----------|-------------|---------|
| `/` | Info page with proxy documentation | No |
| `/status` | Proxy status and configuration | No |
| `/health` | Health check endpoint | No |
| `/metrics` | Prometheus-style metrics | No |
| `/api/*` | Proxied to API backends (8081/8082) | No |
| `/auth/*` | Proxied to auth service (8083) | No |

## Advanced Configuration

### Custom Headers
The proxy doesn't add custom headers by default, but you can modify the configuration:

```go
// Add to proxy rules
Headers: map[string]string{
    "X-Forwarded-By": "servex-proxy",
    "X-Request-ID": "{{request-id}}",
}
```

### Different Load Balancing Strategies
Available strategies:
- `RoundRobinStrategy` - Simple round robin
- `WeightedRoundRobinStrategy` - Weighted round robin (used in example)
- `LeastConnectionsStrategy` - Route to backend with fewest connections
- `RandomStrategy` - Random backend selection
- `WeightedRandomStrategy` - Weighted random selection
- `IPHashStrategy` - Sticky sessions based on client IP

### Timeouts
- **Global Timeout**: 30s (for all proxy requests)
- **API Service**: 20s (overrides global)
- **Auth Service**: 15s (overrides global)
- **Health Check**: 5s

## Troubleshooting

### Proxy Returns 503 "Service Unavailable"
- Check if backend services are running
- Verify health check endpoints return 200 OK
- Check logs for health check failures

### Load Balancing Not Working
- Ensure multiple backends are configured and healthy
- Check weights are set correctly
- Verify requests are going to the right endpoints

### Traffic Dumps Not Created
- Check if `./traffic_logs/` directory exists and is writable
- Verify traffic dump configuration is enabled
- Check sampling rate (set to 0.5 = 50%)

### Rate Limiting Issues
- Default limit is 100 RPM (requests per minute)
- High load testing may hit rate limits
- Check rate limit headers in responses

## Files Created

When running this example, these files/directories are created:

- `./traffic_logs/` - Directory for traffic dumps
- `backend1.go`, `backend2.go`, `auth.go` - Test backend services (if using quick setup)

## Prerequisites

- Go 1.24+
- Servex framework (automatically resolved via go.mod)
- Backend services on ports 8081, 8082, 8083

## Next Steps

After trying this simple proxy:
1. Check [Proxy Gateway Example](../proxy-gateway/) for advanced configuration
2. Explore [Security Examples](../security/) for secure proxying
3. Try [Cache Examples](../cache/) for caching proxy responses
4. Read the [Configuration Guide](../configuration-guide/) for detailed setup 