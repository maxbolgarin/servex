# 10 - Advanced Proxy

Master advanced proxy features including multiple load balancing strategies, complex routing, session affinity, and traffic analysis. This tutorial demonstrates enterprise-grade API gateway patterns.

## What You'll Learn

- Multiple load balancing strategies (weighted, least connections, IP hash, random)
- Advanced routing with path manipulation and method filtering
- Session affinity and sticky sessions
- Health checking and automatic failover
- Traffic analysis and debugging
- Connection pooling and performance optimization

## Features Demonstrated

- ✅ **Weighted Round Robin** - Distribute based on backend capacity (3:2:1 ratio)
- ✅ **Least Connections** - Route to least busy backend
- ✅ **IP Hash (Session Affinity)** - Sticky sessions for stateful apps
- ✅ **Random Selection** - Random backend for stateless content
- ✅ **Advanced Routing** - Path prefix, method filtering, host matching
- ✅ **Health Checking** - Automatic backend health monitoring
- ✅ **Traffic Dumping** - Request/response capture for debugging
- ✅ **Connection Management** - Per-backend connection limits

## Running This Example

```bash
# Run the advanced proxy
go run main.go

# Start backend services (needed for full demo)
for i in {8081..8090}; do python3 -m http.server $i &; done

# Visit the interactive demo
open http://localhost:8080/
```

## Load Balancing Strategies

### 1. Weighted Round Robin
**Endpoint:** `/api/v1/*`
**Use Case:** Backends with different capacities

```go
LoadBalancing: servex.WeightedRoundRobinStrategy
Backends: []servex.Backend{
    {URL: "http://localhost:8081", Weight: 3}, // High-capacity: 50% traffic
    {URL: "http://localhost:8082", Weight: 2}, // Medium-capacity: 33% traffic  
    {URL: "http://localhost:8083", Weight: 1}, // Low-capacity: 17% traffic
}
```

**Traffic Distribution:**
- Request 1 → Backend 1 (8081)
- Request 2 → Backend 1 (8081) 
- Request 3 → Backend 1 (8081)
- Request 4 → Backend 2 (8082)
- Request 5 → Backend 2 (8082)
- Request 6 → Backend 3 (8083)
- *Pattern repeats...*

### 2. Least Connections
**Endpoint:** `/api/v2/*`
**Use Case:** Variable request processing times

```go
LoadBalancing: servex.LeastConnectionsStrategy
```

Routes requests to the backend with the fewest active connections. Perfect for:
- Long-running requests
- Variable processing times
- Preventing backend overload

### 3. IP Hash (Session Affinity)
**Endpoint:** `/auth/*`
**Use Case:** Stateful applications requiring sticky sessions

```go
LoadBalancing: servex.IPHashStrategy
```

Same client IP always routes to the same backend. Essential for:
- User sessions
- Shopping carts
- Stateful authentication
- In-memory caches

### 4. Random Selection
**Endpoint:** `/static/*`
**Use Case:** Stateless content serving

```go
LoadBalancing: servex.RandomStrategy
```

Random backend selection. Good for:
- Static file serving
- Stateless APIs
- Content delivery networks

## Advanced Routing Features

### Path Manipulation
```go
ProxyRule{
    PathPrefix:  "/api/v1/",
    StripPrefix: "/api/v1",    // Remove from forwarded request
    AddPrefix:   "/v1",        // Add to forwarded request
}
```

### Method Filtering
```go
ProxyRule{
    Methods: []string{"GET", "POST", "PUT", "DELETE"},
}
```

### Host-Based Routing
```go
ProxyRule{
    Host: "api.example.com",   // Only route this hostname
}
```

### Header-Based Routing
```go
ProxyRule{
    Headers: map[string]string{
        "X-API-Version": "v2",  // Route based on headers
    },
}
```

## Testing Strategies

### Weighted Round Robin Test
```bash
# Send 6 requests to see 3:2:1 pattern
for i in {1..6}; do 
    curl http://localhost:8080/api/v1/test$i
done
```

### Least Connections Test
```bash
# Multiple concurrent requests
curl http://localhost:8080/api/v2/users &
curl http://localhost:8080/api/v2/posts &
curl http://localhost:8080/api/v2/comments &
wait
```

### Session Affinity Test
```bash
# Same client should get same backend
for i in {1..5}; do
    curl http://localhost:8080/auth/session$i
done
```

### Random Selection Test
```bash
# Random distribution
for i in {1..10}; do
    curl http://localhost:8080/static/file$i.css
done
```

## Health Checking Configuration

```go
HealthCheck: servex.HealthCheckConfig{
    Enabled:         true,
    DefaultInterval: 30 * time.Second,  // Check every 30s
    Timeout:         5 * time.Second,   // 5s timeout
    RetryCount:      2,                 // 2 retries before marking unhealthy
}

// Per-backend health check
Backend{
    URL:                 "http://localhost:8081",
    HealthCheckPath:     "/health",
    HealthCheckInterval: 30 * time.Second,
}
```

**Health Check Behavior:**
- Makes GET requests to `{backend_url}/health`
- Expects 2xx status codes for healthy
- Automatically removes unhealthy backends from rotation
- Backends recover automatically when health checks pass

## Traffic Dumping and Analysis

```go
TrafficDump: servex.TrafficDumpConfig{
    Enabled:     true,
    Directory:   "./traffic_dumps",
    MaxFileSize: 100 * 1024 * 1024,  // 100MB files
    MaxFiles:    5,                   // Keep 5 files
    IncludeBody: true,
    MaxBodySize: 32 * 1024,          // 32KB max body
    SampleRate:  0.3,                // Sample 30% of traffic
}
```

### Analyzing Traffic Dumps
```bash
# View traffic dumps
ls -la ./traffic_dumps/

# Count requests per backend
jq -r '.backend' traffic_dumps/*.jsonl | sort | uniq -c

# Analyze response times
jq -r '.duration' traffic_dumps/*.jsonl | sort -n

# Find errors
jq 'select(.status_code >= 400)' traffic_dumps/*.jsonl
```

## Connection Management

### Global Settings
```go
ProxyConfiguration{
    MaxIdleConns:        100,                // Total idle connections
    MaxIdleConnsPerHost: 20,                 // Per-backend idle connections
    IdleConnTimeout:     90 * time.Second,  // Connection idle timeout
    GlobalTimeout:       30 * time.Second,  // Global request timeout
}
```

### Per-Backend Limits
```go
Backend{
    MaxConnections: 50,  // Limit concurrent connections to this backend
    Timeout:       25 * time.Second,  // Backend-specific timeout
}
```

## Production Patterns

### API Gateway Configuration
```go
// Multi-service API gateway
Rules: []servex.ProxyRule{
    {
        Name:       "user-service",
        PathPrefix: "/api/users/",
        LoadBalancing: servex.WeightedRoundRobinStrategy,
        // Multiple user service backends
    },
    {
        Name:       "payment-service", 
        PathPrefix: "/api/payments/",
        LoadBalancing: servex.LeastConnectionsStrategy,
        // Payment service backends
    },
    {
        Name:       "session-service",
        PathPrefix: "/api/sessions/",
        LoadBalancing: servex.IPHashStrategy,
        // Session-aware backends
    },
}
```

### Microservices Proxy
```go
// Route to different microservices
Rules: []servex.ProxyRule{
    {Host: "users.api.com", /* user service backends */},
    {Host: "orders.api.com", /* order service backends */},
    {Host: "inventory.api.com", /* inventory service backends */},
}
```

## Monitoring and Observability

### Proxy Status Endpoint
```bash
# Check proxy configuration
curl http://localhost:8080/proxy-status
```

### Strategy Information
```bash
# View all load balancing strategies
curl http://localhost:8080/strategies
```

### Health Status
```bash
# Check overall health
curl http://localhost:8080/health

# Proxy metrics
curl http://localhost:8080/metrics
```

## Performance Optimization

### Backend Selection
- Use **Weighted Round Robin** for different capacity backends
- Use **Least Connections** for variable processing times
- Use **IP Hash** for stateful applications
- Use **Random** for simple stateless services

### Connection Tuning
- Set appropriate `MaxConnections` per backend
- Configure `IdleConnTimeout` based on traffic patterns
- Use health checks to avoid failed requests
- Sample traffic dumps in production (< 100%)

## Common Issues and Solutions

### Uneven Load Distribution
- Check backend weights in weighted round robin
- Verify health checks are working
- Monitor connection counts with least connections strategy

### Session Loss
- Use IP Hash strategy for stateful applications
- Ensure session storage is backend-specific
- Consider external session storage for true statelessness

### Backend Overload
- Implement `MaxConnections` limits
- Use health checks to detect overloaded backends
- Scale backends based on connection metrics

### Traffic Analysis
- Enable traffic dumping with appropriate sampling
- Monitor error rates per backend
- Analyze response times to identify bottlenecks

## What You've Learned

- How to implement and configure multiple load balancing strategies
- Advanced routing patterns for complex applications
- Session affinity and stateful application patterns
- Health checking and automatic failover mechanisms
- Traffic analysis and debugging techniques
- Production-ready API gateway patterns

## What's Next?

🎯 **Continue the tutorial:** → [11-location-filtering](../11-location-filtering/)

In the next tutorial, you'll learn how to implement geographic request filtering and location-based access control. 