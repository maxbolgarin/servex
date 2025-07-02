# Servex Reverse Proxy & API Gateway

Transform your Go application into a powerful L7 reverse proxy and API gateway with just a few lines of code. Route traffic intelligently, ensure high availability with health checks, and monitor everything with built-in observability.

## Why Use Servex Proxy?

🚀 **Zero External Dependencies** - Pure Go implementation, no Redis or external services required  
🔄 **Smart Load Balancing** - 6 different strategies including session affinity  
💚 **Automatic Health Checks** - Detect failures and route around unhealthy backends  
📊 **Built-in Observability** - Traffic dumps, metrics, and structured logging  
⚡ **High Performance** - Connection pooling and efficient request routing  
🛡️ **Enterprise Ready** - Integrates with all Servex security and filtering features  

## Quick Start

### 1. Simple Setup (2 minutes)

Create a basic proxy that load balances between two backends:

```go
package main

import (
    "time"
    "github.com/maxbolgarin/servex/v2"
)

func main() {
    // Define your backend servers
    proxyConfig := servex.ProxyConfiguration{
        Enabled: true,
        Rules: []servex.ProxyRule{
            {
                Name: "my-api",
                PathPrefix: "/api/",
                Backends: []servex.Backend{
                    {URL: "http://backend1:8080"},
                    {URL: "http://backend2:8080"},
                },
                StripPrefix: "/api", // Remove /api before forwarding
            },
        },
    }

    // Create and start server
    server, _ := servex.New(servex.WithProxyConfig(proxyConfig))
    server.ListenAndServe(":8080")
}
```

That's it! Now requests to `/api/users` will be forwarded to either `backend1:8080/users` or `backend2:8080/users`.

### 2. YAML Configuration

For production, use YAML configuration:

```yaml
# config.yaml
proxy:
  enabled: true
  rules:
    - name: "my-api"
      path_prefix: "/api/"
      backends:
        - url: "http://backend1:8080"
        - url: "http://backend2:8080"
      strip_prefix: "/api"
```

```go
server, _ := servex.NewFromConfig("config.yaml")
server.ListenAndServe(":8080")
```

## Load Balancing Made Simple

Choose the right strategy for your use case:

### Round Robin (Default)
Perfect for backends with similar capacity. Requests are distributed evenly.

```go
LoadBalancing: servex.RoundRobinStrategy  // or just omit - it's the default
```

### Weighted Distribution
Give more traffic to powerful servers:

```go
Backends: []servex.Backend{
    {URL: "http://powerful-server:8080", Weight: 3},  // Gets 75% of traffic
    {URL: "http://smaller-server:8080", Weight: 1},   // Gets 25% of traffic
}
LoadBalancing: servex.WeightedRoundRobinStrategy
```

### Session Affinity (Sticky Sessions)
Keep users on the same backend server:

```go
LoadBalancing: servex.IPHashStrategy  // Same client IP → same backend
```

### Smart Routing
Route to the least busy server:

```go
LoadBalancing: servex.LeastConnectionsStrategy  // Best for long-running requests
```

### Random Selection
Good for stateless services:

```go
LoadBalancing: servex.RandomStrategy  // Simple and effective
```

## Health Checks & High Availability

Automatically detect and route around failed backends:

```go
proxyConfig := servex.ProxyConfiguration{
    Enabled: true,
    
    // Global health check settings
    HealthCheck: servex.HealthCheckConfig{
        Enabled: true,
        DefaultInterval: 30 * time.Second,
        Timeout: 5 * time.Second,
        RetryCount: 3,
    },
    
    Rules: []servex.ProxyRule{
        {
            Name: "api-service",
            PathPrefix: "/api/",
            Backends: []servex.Backend{
                {
                    URL: "http://backend1:8080",
                    HealthCheckPath: "/health",      // Backend exposes /health endpoint
                    HealthCheckInterval: 15 * time.Second,
                },
                {
                    URL: "http://backend2:8080",
                    HealthCheckPath: "/status",      // Different health endpoint
                    HealthCheckInterval: 30 * time.Second,
                },
            },
        },
    },
}
```

**What happens?**
- Servex checks `/health` and `/status` endpoints regularly
- If a backend returns non-2xx status, it's marked unhealthy
- Traffic automatically routes to healthy backends only
- When backends recover, they're automatically added back

## Advanced Routing

### Route by Path
```go
ProxyRule{
    Name: "user-api",
    PathPrefix: "/users/",  // Matches /users/123, /users/profile, etc.
    StripPrefix: "/users",  // Forwards as /123, /profile
    AddPrefix: "/api/v1",   // Final: /api/v1/123, /api/v1/profile
}
```

### Route by Host
```go
ProxyRule{
    Name: "api-subdomain",
    Host: "api.example.com",  // Only requests to api.example.com
}
```

### Route by HTTP Method
```go
ProxyRule{
    Name: "read-only-api",
    PathPrefix: "/api/",
    Methods: []string{"GET", "HEAD"},  // Only read operations
}
```

### Route by Headers
```go
ProxyRule{
    Name: "v2-api",
    PathPrefix: "/api/",
    Headers: map[string]string{
        "X-API-Version": "v2",  // Only v2 API requests
    },
}
```

## Traffic Analysis & Debugging

Capture and analyze HTTP traffic for debugging and monitoring:

```go
TrafficDump: servex.TrafficDumpConfig{
    Enabled: true,
    Directory: "./traffic_logs",
    SampleRate: 0.1,        // Sample 10% of traffic
    IncludeBody: true,      // Include request/response bodies
    MaxBodySize: 64 * 1024, // Limit body size to 64KB
    MaxFileSize: 100 * 1024 * 1024,  // 100MB per file
    MaxFiles: 10,           // Keep 10 files max
}
```

**Generated files contain:**
```json
{
  "timestamp": "2023-12-07T10:30:45Z",
  "rule": "api-service",
  "backend": "http://backend1:8080",
  "client_ip": "192.168.1.100",
  "method": "GET",
  "path": "/users/123",
  "status_code": 200,
  "duration": "45ms",
  "raw_request": "GET /users/123 HTTP/1.1\r\nHost: api.example.com\r\n..."
}
```

**Analyze with standard tools:**
```bash
# Find slow requests
jq 'select(.duration | gsub("ms"; "") | tonumber > 1000)' traffic_*.jsonl

# Count requests per backend
jq -r '.backend' traffic_*.jsonl | sort | uniq -c

# Find errors
jq 'select(.status_code >= 400)' traffic_*.jsonl
```

## Performance & Production Settings

### Connection Pooling
```go
ProxyConfiguration{
    MaxIdleConns: 200,           // Total idle connections across all backends
    MaxIdleConnsPerHost: 50,     // Idle connections per backend
    IdleConnTimeout: 90 * time.Second,
}
```

### Per-Backend Limits
```go
Backend{
    URL: "http://backend:8080",
    MaxConnections: 100,         // Prevent backend overload
}
```

### Timeouts
```go
ProxyConfiguration{
    GlobalTimeout: 30 * time.Second,  // Default for all requests
}

ProxyRule{
    Timeout: 60 * time.Second,        // Override for specific routes
}
```

## Complete Example

Here's a production-ready configuration:

```go
package main

import (
    "log"
    "time"
    "github.com/maxbolgarin/servex/v2"
)

func main() {
    proxyConfig := servex.ProxyConfiguration{
        Enabled: true,
        GlobalTimeout: 30 * time.Second,
        
        // Connection pooling
        MaxIdleConns: 200,
        MaxIdleConnsPerHost: 50,
        IdleConnTimeout: 90 * time.Second,
        
        // Health checking
        HealthCheck: servex.HealthCheckConfig{
            Enabled: true,
            DefaultInterval: 30 * time.Second,
            Timeout: 5 * time.Second,
            RetryCount: 3,
        },
        
        // Traffic analysis
        TrafficDump: servex.TrafficDumpConfig{
            Enabled: true,
            Directory: "./traffic_logs",
            SampleRate: 0.1,
            IncludeBody: true,
            MaxBodySize: 64 * 1024,
        },
        
        Rules: []servex.ProxyRule{
            // Main API - Weighted Round Robin
            {
                Name: "api-service",
                PathPrefix: "/api/",
                Backends: []servex.Backend{
                    {
                        URL: "http://api1:8080",
                        Weight: 3,
                        HealthCheckPath: "/health",
                        MaxConnections: 100,
                    },
                    {
                        URL: "http://api2:8080",
                        Weight: 2,
                        HealthCheckPath: "/health",
                        MaxConnections: 100,
                    },
                    {
                        URL: "http://api3:8080",
                        Weight: 1,
                        HealthCheckPath: "/health",
                        MaxConnections: 50,
                    },
                },
                LoadBalancing: servex.WeightedRoundRobinStrategy,
                StripPrefix: "/api",
                Timeout: 25 * time.Second,
                EnableTrafficDump: true,
            },
            
            // User Service - Session Affinity
            {
                Name: "user-service",
                Host: "users.example.com",
                Backends: []servex.Backend{
                    {URL: "http://users1:8080", HealthCheckPath: "/status"},
                    {URL: "http://users2:8080", HealthCheckPath: "/status"},
                },
                LoadBalancing: servex.IPHashStrategy,
                Timeout: 20 * time.Second,
            },
            
            // Static Files - Random Selection
            {
                Name: "cdn",
                PathPrefix: "/static/",
                Methods: []string{"GET", "HEAD"},
                Backends: []servex.Backend{
                    {URL: "http://cdn1:8080", MaxConnections: 200},
                    {URL: "http://cdn2:8080", MaxConnections: 200},
                    {URL: "http://cdn3:8080", MaxConnections: 200},
                },
                LoadBalancing: servex.RandomStrategy,
                StripPrefix: "/static",
                Timeout: 15 * time.Second,
            },
        },
    }

    // Create server with proxy + security features
    server, err := servex.New(
        servex.WithProxyConfig(proxyConfig),
        servex.WithHealthEndpoint(),     // /health endpoint
        servex.WithDefaultMetrics(),     // /metrics endpoint
        servex.WithSecurityHeaders(),    // Security headers
        servex.WithRPM(1000),           // Rate limiting
        servex.WithLogFields("method", "url", "status", "duration", "backend"),
    )
    if err != nil {
        log.Fatal("Failed to create server:", err)
    }

    log.Println("🚀 API Gateway starting on :8080")
    log.Fatal(server.ListenAndServe(":8080"))
}
```

## Integration with Servex Features

The proxy works seamlessly with all Servex features:

**Security & Authentication:**
```go
server, _ := servex.New(
    servex.WithProxyConfig(proxyConfig),
    servex.WithSecurityHeaders(),           // Add security headers
    servex.WithAuthMemoryDatabase(),        // Add authentication
    servex.WithBlockedUserAgents("bot"),    // Block bots
)
```

**Rate Limiting & Filtering:**
```go
server, _ := servex.New(
    servex.WithProxyConfig(proxyConfig),
    servex.WithRPM(1000),                   // 1000 requests per minute
    servex.WithBlockedIPs("1.2.3.4"),      // Block specific IPs
)
```

**Monitoring & Observability:**
```go
server, _ := servex.New(
    servex.WithProxyConfig(proxyConfig),
    servex.WithHealthEndpoint(),            // /health endpoint
    servex.WithDefaultMetrics(),            // /metrics for Prometheus
    servex.WithLogFields("backend"),        // Include backend in logs
)
```

## Monitoring Your Proxy

### Built-in Endpoints

When you enable health and metrics:

```go
servex.WithHealthEndpoint(),     // Adds /health
servex.WithDefaultMetrics(),     // Adds /metrics
```

You get:
- **`/health`** - Overall proxy health status
- **`/metrics`** - Prometheus metrics including proxy-specific metrics

### Custom Monitoring

Add your own monitoring endpoints:

```go
// Proxy status endpoint
server.GET("/proxy-status", func(w http.ResponseWriter, r *http.Request) {
    servex.C(w, r).JSON(map[string]any{
        "proxy_enabled": true,
        "rules_count": len(proxyConfig.Rules),
        "health_check_enabled": proxyConfig.HealthCheck.Enabled,
        "traffic_dump_enabled": proxyConfig.TrafficDump.Enabled,
    })
})
```

### Structured Logging

Proxy requests include detailed logging:

```json
{
  "level": "info",
  "msg": "proxy request",
  "component": "proxy",
  "rule": "api-service",
  "backend": "http://api1:8080",
  "method": "GET",
  "path": "/users/123",
  "status_code": 200,
  "duration_ms": 45,
  "client_ip": "192.168.1.100",
  "backend_healthy": true,
  "backend_connections": 12
}
```

## Common Use Cases

### 1. Microservices API Gateway
Route different API paths to different services:

```go
Rules: []servex.ProxyRule{
    {Name: "users", PathPrefix: "/api/users/", Backends: []servex.Backend{{URL: "http://user-service:8080"}}, StripPrefix: "/api/users"},
    {Name: "orders", PathPrefix: "/api/orders/", Backends: []servex.Backend{{URL: "http://order-service:8080"}}, StripPrefix: "/api/orders"},
    {Name: "payments", PathPrefix: "/api/payments/", Backends: []servex.Backend{{URL: "http://payment-service:8080"}}, StripPrefix: "/api/payments"},
}
```

### 2. High Availability Setup
Multiple backends with health checks:

```go
ProxyRule{
    Name: "ha-api",
    PathPrefix: "/api/",
    Backends: []servex.Backend{
        {URL: "http://primary:8080", Weight: 2, HealthCheckPath: "/health"},
        {URL: "http://secondary:8080", Weight: 1, HealthCheckPath: "/health"},
        {URL: "http://fallback:8080", Weight: 1, HealthCheckPath: "/health"},
    },
    LoadBalancing: servex.WeightedRoundRobinStrategy,
}
```

### 3. Blue-Green Deployments
Route traffic between versions:

```go
// Route 90% to stable, 10% to canary
ProxyRule{
    Name: "blue-green",
    PathPrefix: "/api/",
    Backends: []servex.Backend{
        {URL: "http://stable-version:8080", Weight: 9},
        {URL: "http://canary-version:8080", Weight: 1},
    },
    LoadBalancing: servex.WeightedRoundRobinStrategy,
}
```

### 4. Geographic Load Balancing
Route based on client location (using session affinity):

```go
ProxyRule{
    Name: "geo-lb",
    PathPrefix: "/api/",
    Backends: []servex.Backend{
        {URL: "http://us-east:8080"},
        {URL: "http://us-west:8080"},
        {URL: "http://eu-central:8080"},
    },
    LoadBalancing: servex.IPHashStrategy,  // Same client → same region
}
```

## Best Practices

✅ **Always use health checks** for automatic failover  
✅ **Set connection limits** to prevent backend overload  
✅ **Configure timeouts** at both global and rule levels  
✅ **Sample traffic dumps** in production (use `SampleRate < 1.0`)  
✅ **Monitor backend health** with alerts  
✅ **Use session affinity** for stateful applications  
✅ **Plan backend capacity** when setting weights  
✅ **Use HTTPS** for backend communication in production  

❌ **Don't** set `SampleRate: 1.0` in high-traffic production  
❌ **Don't** ignore connection limits  
❌ **Don't** use the same health check path for all backends  
❌ **Don't** forget to configure proper timeouts  

## Troubleshooting

### Backend Not Receiving Traffic
1. Check if backend is healthy: look for "backend unhealthy" logs
2. Verify health check endpoint is working
3. Check connection limits aren't exceeded
4. Ensure rule matching is correct (path prefix, host, headers)

### High Latency
1. Check backend response times in traffic dumps
2. Review connection pool settings
3. Consider using `LeastConnectionsStrategy` for long-running requests
4. Verify timeout settings

### Memory Usage
1. Reduce traffic dump `SampleRate`
2. Lower `MaxBodySize` for traffic dumps
3. Decrease `MaxIdleConns` if needed
4. Check for connection leaks in backends

## Examples

Complete working examples are available in the repository:

- **`examples/09-simple-proxy/`** - Basic setup with two backends
- **`examples/10-advanced-proxy/`** - Production-ready gateway with all features

## YAML Configuration Reference

For a complete YAML configuration example, see `examples/10-advanced-proxy/proxy_gateway_config.yaml`.

---

**Ready to get started?** Check out the [simple proxy example](../examples/09-simple-proxy/) or dive into the [advanced gateway setup](../examples/10-advanced-proxy/)! 