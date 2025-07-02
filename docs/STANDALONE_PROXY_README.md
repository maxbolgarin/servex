# Servex Standalone Proxy Server

Run Servex as a powerful reverse proxy and load balancer using only YAML configuration - no programming required! Perfect for DevOps teams, system administrators, and anyone who needs enterprise-grade traffic management with zero code.

## 🚀 Quick Start (5 minutes)

### 1. Download Servex

```bash
# Download the latest binary (replace with actual download method)
curl -L https://github.com/maxbolgarin/servex/releases/latest/download/servex-linux-amd64 -o servex
chmod +x servex

# Or build from source
go install github.com/maxbolgarin/servex/v2/cmd/servex@latest
```

### 2. Create Your First Proxy

Create a file called `proxy.yaml`:

```yaml
# Basic load balancer configuration
server:
  http: ":8080"
  enable_health_endpoint: true

proxy:
  enabled: true
  rules:
    - name: "my-api"
      path_prefix: "/api/"
      backends:
        - url: "http://backend1.example.com:3000"
        - url: "http://backend2.example.com:3000"
      strip_prefix: "/api"
```

### 3. Start the Proxy

```bash
./servex --config proxy.yaml
```

🎉 **That's it!** Your proxy is now running on port 8080, load balancing traffic between your backends.

**Test it:**
```bash
curl http://localhost:8080/api/users
# Traffic will be routed to either backend1:3000/users or backend2:3000/users
```

## 📋 Command Line Options

```bash
# Start with configuration file
./servex --config myproxy.yaml

# Validate configuration without starting
./servex --config myproxy.yaml --validate

# Generate a sample configuration
./servex --generate --type yaml > sample-config.yaml

# Show help
./servex --help

# Override port from command line
./servex --config myproxy.yaml --port 9090

# Enable verbose output
./servex --config myproxy.yaml --verbose

# Dry run (show what would happen)
./servex --config myproxy.yaml --dry-run
```

## 🔄 Load Balancing Strategies

### Round Robin (Default)
Distributes requests evenly across all backends.

```yaml
proxy:
  enabled: true
  rules:
    - name: "round-robin-api"
      path_prefix: "/api/"
      load_balancing: "round_robin"  # or omit - it's the default
      backends:
        - url: "http://server1:8080"
        - url: "http://server2:8080"
        - url: "http://server3:8080"
```

### Weighted Round Robin
Give more traffic to powerful servers.

```yaml
proxy:
  enabled: true
  rules:
    - name: "weighted-api"
      path_prefix: "/api/"
      load_balancing: "weighted_round_robin"
      backends:
        - url: "http://powerful-server:8080"
          weight: 3  # Gets 60% of traffic (3 out of 5)
        - url: "http://medium-server:8080"
          weight: 2  # Gets 40% of traffic (2 out of 5)
```

### Least Connections
Routes to the backend with the fewest active connections. Perfect for long-running requests.

```yaml
proxy:
  enabled: true
  rules:
    - name: "least-connections-api"
      path_prefix: "/api/"
      load_balancing: "least_connections"
      backends:
        - url: "http://server1:8080"
        - url: "http://server2:8080"
```

### IP Hash (Session Affinity)
Ensures the same client always goes to the same backend server.

```yaml
proxy:
  enabled: true
  rules:
    - name: "sticky-sessions"
      path_prefix: "/app/"
      load_balancing: "ip_hash"
      backends:
        - url: "http://app1:8080"
        - url: "http://app2:8080"
```

### Random Selection
Randomly selects a backend for each request.

```yaml
proxy:
  enabled: true
  rules:
    - name: "random-api"
      path_prefix: "/api/"
      load_balancing: "random"
      backends:
        - url: "http://service1:8080"
        - url: "http://service2:8080"
```

### Weighted Random
Random selection based on backend weights.

```yaml
proxy:
  enabled: true
  rules:
    - name: "weighted-random"
      path_prefix: "/api/"
      load_balancing: "weighted_random"
      backends:
        - url: "http://primary:8080"
          weight: 7  # 70% chance
        - url: "http://backup:8080"
          weight: 3  # 30% chance
```

## 💚 Health Checks & High Availability

Automatically detect failed backends and route traffic only to healthy servers.

```yaml
server:
  http: ":8080"
  enable_health_endpoint: true

proxy:
  enabled: true
  
  # Global health check settings
  health_check:
    enabled: true
    default_interval: "30s"  # Check every 30 seconds
    timeout: "5s"           # 5 second timeout
    retry_count: 3          # Try 3 times before marking unhealthy
  
  rules:
    - name: "ha-api"
      path_prefix: "/api/"
      backends:
        - url: "http://primary:8080"
          health_check_path: "/health"    # Custom health endpoint
          health_check_interval: "15s"   # Check every 15 seconds
        - url: "http://backup:8080"
          health_check_path: "/status"   # Different health endpoint
          health_check_interval: "30s"   # Check every 30 seconds
```

**How it works:**
- Servex sends GET requests to `http://primary:8080/health` every 15 seconds
- If the response is not 2xx (200-299), the backend is marked unhealthy
- Traffic is automatically routed only to healthy backends
- When backends recover, they're automatically added back to the rotation

## 🎯 Advanced Routing

### Route by Path Pattern

```yaml
proxy:
  enabled: true
  rules:
    # API endpoints
    - name: "api-v1"
      path_prefix: "/api/v1/"
      strip_prefix: "/api/v1"     # Remove prefix before forwarding
      add_prefix: "/v1"           # Add new prefix
      backends:
        - url: "http://api-server:8080"
    
    # Static assets
    - name: "static-files"
      path_prefix: "/static/"
      strip_prefix: "/static"
      backends:
        - url: "http://cdn:8080"
```

### Route by Host (Virtual Hosts)

```yaml
proxy:
  enabled: true
  rules:
    # API subdomain
    - name: "api-subdomain"
      host: "api.example.com"
      backends:
        - url: "http://api-server:8080"
    
    # Admin subdomain
    - name: "admin-subdomain"  
      host: "admin.example.com"
      backends:
        - url: "http://admin-server:8080"
    
    # Main website
    - name: "main-site"
      host: "example.com"
      backends:
        - url: "http://web-server:8080"
```

### Route by HTTP Method

```yaml
proxy:
  enabled: true
  rules:
    # Read-only operations
    - name: "read-api"
      path_prefix: "/api/"
      methods: ["GET", "HEAD"]
      backends:
        - url: "http://read-replica1:8080"
        - url: "http://read-replica2:8080"
    
    # Write operations
    - name: "write-api"
      path_prefix: "/api/"
      methods: ["POST", "PUT", "DELETE", "PATCH"]
      backends:
        - url: "http://write-master:8080"
```

### Route by Headers

```yaml
proxy:
  enabled: true
  rules:
    # API version 2
    - name: "api-v2"
      path_prefix: "/api/"
      headers:
        "X-API-Version": "v2"
      backends:
        - url: "http://api-v2:8080"
    
    # Mobile clients
    - name: "mobile-api"
      path_prefix: "/api/"
      headers:
        "User-Agent": "MobileApp"
      backends:
        - url: "http://mobile-optimized:8080"
```

## 📊 Performance & Production Settings

### Connection Pooling

```yaml
proxy:
  enabled: true
  global_timeout: "30s"
  max_idle_conns: 200              # Total idle connections across all backends
  max_idle_conns_per_host: 50      # Idle connections per backend
  idle_conn_timeout: "90s"         # How long to keep idle connections
  
  rules:
    - name: "high-performance-api"
      path_prefix: "/api/"
      timeout: "15s"                # Faster timeout for this rule
      backends:
        - url: "http://fast-server:8080"
          max_connections: 100      # Limit concurrent connections
```

### Traffic Analysis & Debugging

```yaml
proxy:
  enabled: true
  
  # Capture traffic for analysis
  traffic_dump:
    enabled: true
    directory: "./traffic-logs"
    sample_rate: 0.1              # Sample 10% of traffic
    include_body: true            # Include request/response bodies
    max_body_size: 65536          # 64KB max body size
    max_file_size: 104857600      # 100MB per file
    max_files: 10                 # Keep 10 files max
  
  rules:
    - name: "monitored-api"
      path_prefix: "/api/"
      enable_traffic_dump: true   # Enable for this specific rule
      backends:
        - url: "http://backend:8080"
```

**Analyze traffic logs:**
```bash
# View traffic logs
tail -f traffic-logs/traffic_dump_001.jsonl

# Find slow requests
jq 'select(.duration_ms > 1000)' traffic-logs/*.jsonl

# Count requests per backend
jq -r '.backend' traffic-logs/*.jsonl | sort | uniq -c
```

## 📋 Complete Configuration Examples

### 1. Microservices API Gateway

```yaml
# microservices-gateway.yaml
server:
  http: ":8080"
  enable_health_endpoint: true
  enable_default_metrics: true

# Security and rate limiting
rate_limit:
  enabled: true
  requests_per_interval: 1000
  interval: "1m"
  exclude_paths: ["/health", "/metrics"]

security:
  enabled: true
  x_frame_options: "DENY"
  x_content_type_options: "nosniff"

proxy:
  enabled: true
  health_check:
    enabled: true
    default_interval: "30s"
    timeout: "5s"
    retry_count: 3
  
  rules:
    # User service
    - name: "user-service"
      path_prefix: "/api/users/"
      strip_prefix: "/api/users"
      load_balancing: "least_connections"
      backends:
        - url: "http://user-service-1:8080"
          health_check_path: "/health"
        - url: "http://user-service-2:8080"
          health_check_path: "/health"
    
    # Order service
    - name: "order-service"
      path_prefix: "/api/orders/"
      strip_prefix: "/api/orders"
      load_balancing: "round_robin"
      backends:
        - url: "http://order-service-1:8080"
          health_check_path: "/health"
        - url: "http://order-service-2:8080"
          health_check_path: "/health"
    
    # Payment service (session affinity)
    - name: "payment-service"
      path_prefix: "/api/payments/"
      strip_prefix: "/api/payments"
      load_balancing: "ip_hash"
      timeout: "60s"  # Longer timeout for payments
      backends:
        - url: "http://payment-service-1:8080"
          health_check_path: "/health"
        - url: "http://payment-service-2:8080"
          health_check_path: "/health"
```

```bash
./servex --config microservices-gateway.yaml
```

### 2. High Availability Load Balancer

```yaml
# ha-loadbalancer.yaml
server:
  http: ":8080"
  enable_health_endpoint: true

proxy:
  enabled: true
  global_timeout: "30s"
  
  health_check:
    enabled: true
    default_interval: "15s"  # Frequent health checks
    timeout: "3s"
    retry_count: 2
  
  rules:
    - name: "ha-web-app"
      path_prefix: "/"
      load_balancing: "weighted_round_robin"
      backends:
        # Primary datacenter (higher weight)
        - url: "http://web1.dc1.example.com:8080"
          weight: 3
          health_check_path: "/health"
          max_connections: 200
        - url: "http://web2.dc1.example.com:8080"
          weight: 3
          health_check_path: "/health"
          max_connections: 200
        
        # Secondary datacenter (lower weight)
        - url: "http://web1.dc2.example.com:8080"
          weight: 1
          health_check_path: "/health"
          max_connections: 100
        - url: "http://web2.dc2.example.com:8080"
          weight: 1
          health_check_path: "/health"
          max_connections: 100
```

### 3. Blue-Green Deployment

```yaml
# blue-green.yaml
server:
  http: ":8080"

proxy:
  enabled: true
  rules:
    - name: "blue-green-deployment"
      path_prefix: "/app/"
      strip_prefix: "/app"
      load_balancing: "weighted_round_robin"
      backends:
        # Blue environment (current stable)
        - url: "http://blue.myapp.com:8080"
          weight: 9  # 90% of traffic
          health_check_path: "/health"
        
        # Green environment (new version)
        - url: "http://green.myapp.com:8080"
          weight: 1  # 10% of traffic for testing
          health_check_path: "/health"
```

### 4. Geographic Load Balancing

```yaml
# geo-loadbalancer.yaml
server:
  http: ":8080"

proxy:
  enabled: true
  rules:
    # US East traffic (session affinity for geo-locality)
    - name: "us-east-api"
      host: "us-east.api.example.com"
      load_balancing: "ip_hash"
      backends:
        - url: "http://us-east-1:8080"
        - url: "http://us-east-2:8080"
    
    # EU traffic
    - name: "eu-api"
      host: "eu.api.example.com"
      load_balancing: "ip_hash"
      backends:
        - url: "http://eu-west-1:8080"
        - url: "http://eu-west-2:8080"
    
    # Asia Pacific traffic
    - name: "ap-api"
      host: "ap.api.example.com"
      load_balancing: "ip_hash"
      backends:
        - url: "http://ap-southeast-1:8080"
        - url: "http://ap-southeast-2:8080"
```

## 🔧 Management & Monitoring

### Built-in Endpoints

Enable health and metrics endpoints:

```yaml
server:
  http: ":8080"
  enable_health_endpoint: true    # Adds /health
  health_path: "/health"
  enable_default_metrics: true    # Adds /metrics
  metrics_path: "/metrics"
```

**Check proxy status:**
```bash
# Check overall health
curl http://localhost:8080/health

# Get Prometheus metrics
curl http://localhost:8080/metrics
```

### Logging Configuration

```yaml
# Enable detailed logging
logging:
  disable_request_logging: false
  log_fields:
    - "method"
    - "url" 
    - "status"
    - "duration"
    - "ip"
    - "backend"  # Include which backend handled the request
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY servex /usr/local/bin/servex
COPY proxy.yaml /etc/servex/proxy.yaml
EXPOSE 8080
CMD ["servex", "--config", "/etc/servex/proxy.yaml"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  proxy:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./proxy.yaml:/etc/servex/proxy.yaml:ro
      - ./traffic-logs:/var/log/servex
    healthcheck:
      test: ["CMD", "servex", "--health-check"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## 🚨 Troubleshooting

### Configuration Validation

```bash
# Validate your configuration
./servex --config proxy.yaml --validate

# Show what would happen without starting
./servex --config proxy.yaml --dry-run
```

### Common Issues

**Backend not receiving traffic:**
```bash
# Check health status
curl http://localhost:8080/health

# Enable verbose logging
./servex --config proxy.yaml --verbose

# Check if backends are accessible
curl http://your-backend:8080/health
```

**High memory usage:**
```yaml
# Reduce traffic dumping
proxy:
  traffic_dump:
    sample_rate: 0.01  # Only 1% sampling
    max_body_size: 1024  # Smaller body size
```

**Connection issues:**
```yaml
# Increase connection limits
proxy:
  max_idle_conns: 500
  max_idle_conns_per_host: 100
  
  rules:
    - name: "my-rule"
      backends:
        - url: "http://backend:8080"
          max_connections: 200  # Per-backend limit
```

## 📚 Configuration Reference

For complete configuration options, see:
- [`server_docs.yaml`](./server_docs.yaml) - Complete reference with all options
- [`proxy_gateway_config.yaml`](./proxy_gateway_config.yaml) - Advanced example configuration

## 🎯 Production Checklist

✅ **Enable health checks** on all backends  
✅ **Set connection limits** to prevent overload  
✅ **Configure proper timeouts** for your use case  
✅ **Enable monitoring** with `/health` and `/metrics` endpoints  
✅ **Use HTTPS** in production with proper certificates  
✅ **Sample traffic dumps** with `sample_rate < 1.0` in high traffic  
✅ **Set up log rotation** for traffic dumps  
✅ **Configure rate limiting** to prevent abuse  
✅ **Enable security headers** for web applications  

## 🚀 Next Steps

1. **Start simple**: Begin with basic round-robin load balancing
2. **Add health checks**: Ensure high availability with automatic failover  
3. **Tune performance**: Adjust connection pooling and timeouts for your workload
4. **Monitor traffic**: Use traffic dumps and metrics to understand your traffic patterns
5. **Scale up**: Add more backends and advanced routing rules as needed

---

**Need help?** The Servex proxy is designed to be simple yet powerful. Start with a basic configuration and gradually add features as your needs grow! 