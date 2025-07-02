# Servex L7 Reverse Proxy / API Gateway

Servex includes a powerful L7 reverse proxy and API gateway with advanced features including load balancing, health checking, traffic dumping, and intelligent routing.

## Features

### ✅ Implemented Features

- **Multiple Load Balancing Strategies:**
  - Round Robin - Distributes requests evenly across backends
  - Weighted Round Robin - Distributes based on backend weights
  - Least Connections - Routes to backend with fewest active connections
  - Random - Random backend selection
  - Weighted Random - Random selection based on weights
  - IP Hash - Session affinity based on client IP

- **Health Checking:**
  - Configurable health check intervals and timeouts
  - Automatic backend failover when unhealthy
  - Retry logic with configurable retry counts
  - Health status logging and monitoring

- **Traffic Dumping:**
  - RAW HTTP request and response capture
  - Configurable sampling rates to control storage
  - Request body capture (with size limits)
  - Automatic file rotation and retention
  - JSON line format for easy analysis

- **Advanced Routing:**
  - Path prefix matching (`/api/*`)
  - Host header matching (`api.example.com`)
  - HTTP method filtering (`GET`, `POST`, etc.)
  - Custom header matching (`X-API-Version: v2`)
  - Path manipulation (strip/add prefixes)

- **Performance & Reliability:**
  - Connection pooling with configurable limits
  - Per-backend connection limits
  - Request timeouts at multiple levels
  - Efficient goroutine lifecycle management
  - Detailed proxy-specific logging

- **Integration:**
  - YAML configuration support
  - Works with all other servex features (auth, rate limiting, filtering, etc.)
  - Prometheus metrics integration
  - Structured logging with proxy-specific fields

## Quick Start

### 1. Simple Programmatic Configuration

```go
proxyConfig := servex.ProxyConfiguration{
    Enabled: true,
    Rules: []servex.ProxyRule{
        {
            Name: "api-backend",
            PathPrefix: "/api/",
            Backends: []servex.Backend{
                {URL: "http://backend1:8080", Weight: 2},
                {URL: "http://backend2:8080", Weight: 1},
            },
            LoadBalancing: servex.WeightedRoundRobinStrategy,
            StripPrefix: "/api",
        },
    },
}

server, _ := servex.New(servex.WithProxyConfig(proxyConfig))
```

### 2. YAML Configuration

```yaml
proxy:
  enabled: true
  rules:
    - name: "api-backend"
      path_prefix: "/api/"
      backends:
        - url: "http://backend1:8080"
          weight: 2
        - url: "http://backend2:8080"  
          weight: 1
      load_balancing: "weighted_round_robin"
      strip_prefix: "/api"
```

## Load Balancing Strategies

### Round Robin
Cycles through backends in order. Simple and effective for backends with similar capacity.

```go
LoadBalancing: servex.RoundRobinStrategy
```

### Weighted Round Robin
Distributes requests based on backend weights. Higher weight = more requests.

```go
LoadBalancing: servex.WeightedRoundRobinStrategy
Backends: []servex.Backend{
    {URL: "http://big-server:8080", Weight: 3},    // Gets 3x more traffic
    {URL: "http://small-server:8080", Weight: 1},  // Gets 1x traffic
}
```

### Least Connections
Routes to the backend with the fewest active connections. Best for long-running requests.

```go
LoadBalancing: servex.LeastConnectionsStrategy
```

### IP Hash (Session Affinity)
Routes based on client IP hash. Ensures the same client always goes to the same backend.

```go
LoadBalancing: servex.IPHashStrategy
```

### Random
Random backend selection. Good for stateless applications.

```go
LoadBalancing: servex.RandomStrategy
```

## Health Checking

Enable automatic health checking to ensure traffic only goes to healthy backends:

```go
HealthCheck: servex.HealthCheckConfig{
    Enabled: true,
    DefaultInterval: 30 * time.Second,
    Timeout: 5 * time.Second,
    RetryCount: 3,
}

// Per-backend health check configuration
Backend{
    URL: "http://api1:8080",
    HealthCheckPath: "/health",
    HealthCheckInterval: 30 * time.Second,
}
```

Health checks will:
- Make GET requests to `{backend_url}{health_check_path}`
- Consider 2xx responses as healthy
- Retry failed checks based on `RetryCount`
- Automatically remove unhealthy backends from rotation
- Log health status changes

## Traffic Dumping

Capture and analyze HTTP traffic for debugging and monitoring:

```go
TrafficDump: servex.TrafficDumpConfig{
    Enabled: true,
    Directory: "./traffic_dumps",
    IncludeBody: true,
    MaxBodySize: 64 * 1024,  // 64KB
    SampleRate: 0.1,         // Sample 10% of traffic
    MaxFileSize: 100 * 1024 * 1024,  // 100MB per file
    MaxFiles: 10,            // Keep 10 files
}
```

Traffic dumps include:
- Complete RAW HTTP request (headers + body)
- Client IP and request metadata
- Backend selection information
- Request timing and duration
- JSON line format for easy parsing

Example dump entry:
```json
{
  "timestamp": "2023-12-07T10:30:45Z",
  "rule": "api-backend",
  "backend": "http://api1:8080",
  "client_ip": "192.168.1.100",
  "request_id": "1701946245123-abc12345",
  "raw_request": "GET /users HTTP/1.1\r\nHost: api.example.com\r\n...",
  "request_headers": {"User-Agent": ["MyApp/1.0"]},
  "status_code": 200,
  "duration": "15ms"
}
```

## Advanced Routing

### Path-Based Routing
```go
ProxyRule{
    Name: "api-v1",
    PathPrefix: "/api/v1/",
    StripPrefix: "/api/v1",  // Remove before forwarding
    AddPrefix: "/v1",        // Add before forwarding
}
```

### Host-Based Routing  
```go
ProxyRule{
    Name: "user-service",
    Host: "users.example.com",  // Only match this host
}
```

### Header-Based Routing
```go
ProxyRule{
    Name: "api-v2",
    PathPrefix: "/api/",
    Headers: map[string]string{
        "X-API-Version": "v2",      // Only route v2 API calls
    },
}
```

### Method Filtering
```go
ProxyRule{
    Name: "read-only-api",
    PathPrefix: "/api/",
    Methods: []string{GET, "HEAD"},  // Only GET and HEAD
}
```

## Performance Configuration

### Connection Pooling
```go
ProxyConfiguration{
    MaxIdleConns: 100,           // Total idle connections
    MaxIdleConnsPerHost: 20,     // Idle connections per backend
    IdleConnTimeout: 90 * time.Second,
}
```

### Connection Limits
```go
Backend{
    URL: "http://backend:8080",
    MaxConnections: 50,          // Limit concurrent connections
}
```

### Timeouts
```go
ProxyConfiguration{
    GlobalTimeout: 30 * time.Second,  // Global default
}

ProxyRule{
    Timeout: 60 * time.Second,        // Rule-specific timeout
}
```

## Integration with Other Features

The proxy works seamlessly with all other servex features:

```go
server, _ := servex.New(
    // Proxy configuration
    servex.WithProxyConfig(proxyConfig),
    
    // Security features
    servex.WithSecurityHeaders(),
    servex.WithRPM(1000),
    
    // Request filtering
    servex.WithBlockedUserAgents("bot", "crawler"),
    
    // Authentication
    servex.WithAuthMemoryDatabase(),
    
    // Monitoring
    servex.WithHealthEndpoint(),
    servex.WithDefaultMetrics(),
    
    // Logging
    servex.WithLogFields("method", "url", "status", "duration"),
)
```

## Monitoring and Observability

### Structured Logging
The proxy includes specialized logging with proxy-specific fields:

```json
{
  "level": "info",
  "msg": "proxy request",
  "component": "proxy",
  "rule": "api-backend", 
  "backend": "http://api1:8080",
  "method": GET,
  "path": "/users",
  "status_code": 200,
  "duration_ms": 45,
  "backend_connections": 12,
  "backend_healthy": true,
  "load_balancing": "weighted_round_robin"
}
```

### Health Status Endpoints
Monitor backend health through custom endpoints:

```go
server.GET("/proxy-status", func(w http.ResponseWriter, r *http.Request) {
    servex.C(w, r).JSON(map[string]any{
        "proxy_enabled": true,
        "rules_count": len(config.Proxy.Rules),
        "traffic_dump": config.Proxy.TrafficDump.Enabled,
    })
})
```

### Metrics Integration
Proxy metrics are automatically included in the `/metrics` endpoint when using `WithDefaultMetrics()`.

## Examples

- `proxy_simple_example.go` - Basic proxy setup with two backends
- `proxy_gateway_example.go` - Comprehensive API gateway with multiple rules
- `proxy_gateway_config.yaml` - Complete YAML configuration example

## Best Practices

1. **Use Health Checks**: Always configure health checks for automatic failover
2. **Set Connection Limits**: Prevent backend overload with `MaxConnections`
3. **Configure Timeouts**: Set appropriate timeouts at global and rule levels
4. **Sample Traffic Dumps**: Use `SampleRate < 1.0` in production to limit storage
5. **Monitor Backend Health**: Set up alerts on backend health status changes
6. **Use Session Affinity**: Use `IPHashStrategy` for stateful applications
7. **Secure Backend Communication**: Use HTTPS for backend connections in production
8. **Plan for Capacity**: Configure weights based on backend capacity

## Traffic Analysis

Analyze traffic dumps with standard tools:

```bash
# Count requests per backend
jq -r '.backend' traffic_dump_001.jsonl | sort | uniq -c

# Analyze response times
jq -r '.duration' traffic_dump_001.jsonl | sort -n

# Find errors
jq 'select(.status_code >= 400)' traffic_dump_001.jsonl

# Top user agents
jq -r '.request_headers["User-Agent"][0]' traffic_dump_001.jsonl | sort | uniq -c | sort -nr
``` 