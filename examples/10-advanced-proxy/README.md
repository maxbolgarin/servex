# Advanced Proxy Gateway

A production-ready proxy gateway example demonstrating enterprise-grade features including multiple load balancing strategies, advanced routing, health checking, traffic analysis, and comprehensive monitoring.

## Overview

This example shows how to build a complete API gateway with:

- **🔀 Multiple Load Balancing Strategies** - Weighted round-robin, least connections, IP hash, random
- **🛣️ Advanced Routing** - Path manipulation, host-based routing, method filtering, header routing
- **🏥 Health Monitoring** - Automatic health checking with failover
- **📊 Traffic Analysis** - Request/response dumping with sampling
- **🔒 Security Features** - Rate limiting, request filtering, security headers
- **📈 Observability** - Comprehensive metrics, logging, and monitoring endpoints

## Quick Start

### Option 1: Using Configuration File

```bash
# Run with YAML configuration (recommended)
go run main.go

# The server will load proxy_gateway_config.yaml automatically
# See "Configuration" section for customization
```

### Option 2: Using Command Line Options

```bash
# Show help
go run main.go -help

# Use custom config file
go run main.go -config custom-config.yaml

# Use different port
go run main.go -port :9090

# Combine options
go run main.go -config production.yaml -port :8443
```

## Load Balancing Strategies

This example demonstrates 5 different load balancing strategies for different use cases:

### 1. Weighted Round Robin (`/api/*`)
**Best for:** Backends with different capacities

```
Traffic Distribution (3:2:1 ratio):
Request 1,2,3 → Backend 1 (3 weight, 50% traffic)
Request 4,5   → Backend 2 (2 weight, 33% traffic)  
Request 6     → Backend 3 (1 weight, 17% traffic)
```

### 2. Least Connections (`/auth/*`)
**Best for:** Variable processing times
- Routes to backend with fewest active connections
- Prevents backend overload
- Ideal for long-running requests

### 3. IP Hash (`users.example.com`)
**Best for:** Session affinity / sticky sessions
- Same client IP always routes to same backend
- Essential for stateful applications
- Perfect for user sessions, shopping carts

### 4. Random (`/static/*`)
**Best for:** Stateless content serving
- Random backend selection
- Good for CDN scenarios
- Minimal overhead

### 5. Round Robin (`/payments/*`)
**Best for:** Equal capacity backends
- Evenly distributes requests
- Simple and effective
- Header-based routing support

## Key Features

### Health Checking & Failover
```yaml
# Automatic health monitoring
health_check:
  enabled: true
  default_interval: "30s"
  timeout: "5s"
  retry_count: 3
```

- Automatic backend health monitoring
- Removes unhealthy backends from rotation
- Automatic recovery when backends become healthy
- Per-backend health check paths and intervals

### Traffic Analysis
```yaml
# Production-ready traffic dumping
traffic_dump:
  enabled: true
  directory: "./traffic_dumps"
  sample_rate: 0.1  # 10% sampling for production
  max_file_size: 100MB
  max_files: 20
```

- Request/response capture for debugging
- Configurable sampling rates
- File rotation with size limits
- Body content filtering

### Security & Rate Limiting
- Rate limiting: 1000 requests/minute with burst support
- Request filtering: Blocks bots, scrapers, malicious requests
- Security headers: CSP, HSTS, frame options
- Connection limits per backend

## API Endpoints

### Proxy Endpoints
| Endpoint | Strategy | Backend Count | Features |
|----------|----------|---------------|----------|
| `/api/*` | Weighted Round Robin | 3 | Health checks, traffic dump |
| `/auth/*` | Least Connections | 2 | Path rewriting (`/auth` → `/v1`) |
| `users.example.com` | IP Hash | 2 | Session affinity |
| `/static/*` | Random | 3 | CDN optimization |
| `/payments/*` | Round Robin | 2 | Header routing (`X-API-Version: v2`) |

### Management Endpoints
| Endpoint | Description |
|----------|-------------|
| `/health` | Health check status |
| `/metrics` | Prometheus metrics |
| `/info` | Service information |
| `/proxy-status` | Proxy configuration details |
| `/strategies` | Load balancing strategies info |

## Testing the Proxy

### Test Load Balancing
```bash
# Test weighted round-robin (should see 3:2:1 pattern)
for i in {1..6}; do curl http://localhost:8080/api/test$i; done

# Test session affinity (same client should get same backend)
for i in {1..5}; do curl http://localhost:8080/auth/session$i; done

# Test with different host header
curl -H "Host: users.example.com" http://localhost:8080/profile

# Test header-based routing
curl -H "X-API-Version: v2" http://localhost:8080/payments/process
```

### Monitor Traffic
```bash
# View proxy status
curl http://localhost:8080/proxy-status

# Check health
curl http://localhost:8080/health

# View metrics
curl http://localhost:8080/metrics

# Get strategy information  
curl http://localhost:8080/strategies
```

## Configuration

### YAML Configuration File

The example includes a comprehensive YAML configuration file (`proxy_gateway_config.yaml`) that demonstrates:

- Complete proxy routing rules
- Security settings and rate limiting
- Health check configuration
- Traffic dumping settings
- Static file serving
- Monitoring configuration

Key sections:
```yaml
proxy:
  enabled: true
  traffic_dump:
    enabled: true
    sample_rate: 0.1
  health_check:
    enabled: true
    default_interval: "30s"
  rules:
    - name: "api-backend"
      path_prefix: "/api/"
      load_balancing: "weighted_round_robin"
      # ... backend definitions
```

### Environment Variables

All configuration can be overridden with environment variables:
```bash
export SERVEX_PROXY_ENABLED=true
export SERVEX_PROXY_TRAFFIC_DUMP_ENABLED=true
export SERVEX_PROXY_TRAFFIC_DUMP_SAMPLE_RATE=0.1
export SERVEX_RATE_LIMIT_ENABLED=true
export SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL=1000
```

## Production Deployment

### Docker Deployment
```bash
# Build production image
docker build -t advanced-proxy-gateway .

# Run with custom config
docker run -p 8080:8080 \
  -v $(pwd)/proxy_gateway_config.yaml:/app/config.yaml \
  advanced-proxy-gateway -config /app/config.yaml
```

### Performance Tuning

**Connection Management:**
- `max_idle_conns: 200` - Total idle connections
- `max_idle_conns_per_host: 50` - Per-backend idle connections
- `idle_conn_timeout: 90s` - Connection idle timeout

**Backend Limits:**
- `max_connections: 100` - Concurrent connections per backend
- Individual timeouts per rule/backend

**Monitoring:**
- Traffic sampling at 10% for production
- Health checks every 30 seconds
- Automatic failover with 3 retry attempts

## Troubleshooting

### Common Issues

**Uneven Load Distribution:**
- Check backend weights in weighted round-robin
- Verify health checks are working properly
- Monitor connection counts with least connections

**Session Loss:**
- Use IP hash strategy for stateful applications
- Ensure session storage is backend-specific
- Consider external session storage for scalability

**Backend Overload:**
- Implement `max_connections` limits
- Use health checks to detect overloaded backends
- Scale backends based on connection metrics

### Traffic Analysis
```bash
# View traffic dumps
ls -la ./traffic_dumps/

# Analyze request patterns
jq -r '.method + " " + .path' traffic_dumps/*.jsonl | sort | uniq -c

# Find slow requests
jq 'select(.duration > 1000)' traffic_dumps/*.jsonl

# Backend distribution
jq -r '.backend' traffic_dumps/*.jsonl | sort | uniq -c
```

## What You've Learned

- ✅ Multiple load balancing strategies and when to use each
- ✅ Advanced routing patterns (path, host, header, method-based)
- ✅ Production-ready health checking and failover
- ✅ Traffic analysis and debugging techniques
- ✅ Security best practices for proxy gateways
- ✅ Comprehensive monitoring and observability
- ✅ Configuration management (YAML + environment variables)
- ✅ Performance optimization and tuning

## Next Steps

🎯 **Continue to:** [Tutorial 11 - Location Filtering](../11-location-filtering/)

Learn how to implement geographic request filtering and location-based access control. 