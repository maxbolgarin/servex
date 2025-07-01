# Tutorial 12: Location-Based Rate Limiting

Learn how to apply **different rate limits to different URL patterns** in your Servex applications. Location-based rate limiting allows you to set appropriate limits for each part of your application - strict limits for authentication, moderate limits for APIs, and custom limits for specialized endpoints.

## ⚡ What You'll Learn

- Configure different rate limits for different URL patterns  
- Implement tiered rate limiting strategies
- Use burst allowances for different endpoint types
- Balance security with usability across your application
- Monitor and test rate limiting effectiveness

## 🏗️ Rate Limiting Architecture

Location-based rate limiting creates performance and security zones:

```
🔐 Auth endpoints:   5 req/min,   burst: 2   (Prevent brute force)
🔑 API endpoints:    100 req/min, burst: 20  (Reasonable API usage)  
📁 Upload endpoints: 10 req/min,  burst: 3   (Prevent abuse)
👑 Admin endpoints:  500 req/min, burst: 50  (Trust admin users)
🔍 Search endpoints: 30 req/min,  burst: 10  (Balance functionality)
🌍 Public endpoints: No limits              (Open access)
```

## 📊 Rate Limit Configuration

| Endpoint Pattern | Limit | Burst | Purpose |
|-----------------|-------|-------|---------|
| `/auth/*` | 5/min | 2 | Prevent brute force attacks |
| `/api/*` | 100/min | 20 | Reasonable API usage |
| `/upload/*` | 10/min | 3 | Prevent upload abuse |
| `/admin/*` | 500/min | 50 | Trust admin users |
| `/search/*` | 30/min | 10 | Balance search functionality |
| `/public/*` | None | - | Open public access |

## 🏃 Quick Start

```bash
# Start the server
go run main.go

# Test basic endpoint (no rate limiting)
curl http://localhost:8080/health
```

## 🧪 Testing Rate Limiting Behavior

### 1. Authentication Endpoints - Strict Limits (5/min)

**Test Normal Usage:**
```bash
# These should work (within burst limit)
curl -X POST http://localhost:8080/auth/login
curl -X POST http://localhost:8080/auth/login
```

**Test Rate Limiting:**
```bash
# Send multiple requests quickly to hit rate limit
for i in {1..10}; do
  curl -X POST http://localhost:8080/auth/login
  echo " - Request $i"
done
```

After the 3rd request, you'll see:
```json
{
  "error": "Too many authentication attempts. Please try again later."
}
```

### 2. API Endpoints - Moderate Limits (100/min)

**Test Normal Usage:**
```bash
curl http://localhost:8080/api/users
curl http://localhost:8080/api/posts  
curl http://localhost:8080/api/data
```

**Test Burst Allowance:**
```bash
# Send 25 rapid requests (should work due to burst=20)
for i in {1..25}; do
  curl -s http://localhost:8080/api/users > /dev/null
  echo "Request $i completed"
done
```

### 3. Upload Endpoints - Very Strict (10/min)

**Test Upload Limits:**
```bash
# These should work (within burst limit)
curl -X POST http://localhost:8080/upload/image
curl -X POST http://localhost:8080/upload/document
curl -X POST http://localhost:8080/upload/image

# This should trigger rate limiting
curl -X POST http://localhost:8080/upload/image
curl -X POST http://localhost:8080/upload/image
```

### 4. Admin Endpoints - High Limits (500/min)

**Test Admin Access:**
```bash
# Rapid admin requests (should handle high volume)
for i in {1..60}; do
  curl -s http://localhost:8080/admin/dashboard > /dev/null
  echo "Admin request $i"
done
```

### 5. Search Endpoints - Custom Limits (30/min)

**Test Search Functionality:**
```bash
# Search requests with query parameters
curl "http://localhost:8080/search/users?q=alice"
curl "http://localhost:8080/search/content?q=tutorial"

# Test rate limiting
for i in {1..35}; do
  curl -s "http://localhost:8080/search/users?q=test$i" > /dev/null
  echo "Search $i"
done
```

### 6. Public Endpoints - No Limits

**Test Unlimited Access:**
```bash
# These should never be rate limited
for i in {1..100}; do
  curl -s http://localhost:8080/public/info > /dev/null
  echo "Public request $i"
done
```

## 💻 Advanced Testing Scripts

### Concurrent Rate Limit Testing
```bash
#!/bin/bash
echo "Testing concurrent auth requests..."

# Launch 5 concurrent processes each making 10 requests
for proc in {1..5}; do
  (
    for req in {1..10}; do
      curl -s -X POST http://localhost:8080/auth/login
      echo "Process $proc - Request $req"
    done
  ) &
done

wait
echo "All concurrent tests completed"
```

### Rate Limit Recovery Testing
```bash
#!/bin/bash
echo "Testing rate limit recovery..."

# Hit rate limit
for i in {1..10}; do
  curl -X POST http://localhost:8080/auth/login
done

echo "Waiting 70 seconds for rate limit to reset..."
sleep 70

# Should work again
curl -X POST http://localhost:8080/auth/login
echo "Rate limit recovery test completed"
```

## 🔧 Configuration Deep Dive

### Basic Configuration Structure
```go
locationConfigs := []servex.LocationRateLimitConfig{
    {
        PathPatterns: []string{"/auth/login", "/auth/register"},
        Config: servex.RateLimitConfig{
            Enabled:             true,
            RequestsPerInterval: 5,          // 5 requests allowed
            Interval:            time.Minute, // Per minute
            BurstSize:           2,          // Up to 2 immediate requests
            StatusCode:          http.StatusTooManyRequests,
            Message:             "Too many authentication attempts.",
        },
    },
}
```

### Understanding Burst vs Rate
- **Rate Limit**: Sustained requests over time interval
- **Burst Limit**: Immediate requests allowed before rate limiting kicks in

Example with 100 req/min, burst: 20:
- First 20 requests: Immediate (burst allowance)
- Requests 21+: Limited to 100/minute rate

### Custom Rate Limit Keys
```go
Config: servex.RateLimitConfig{
    // Custom key function for user-based limiting
    KeyFunc: func(r *http.Request) string {
        // Could use user ID, API key, etc.
        userID := getUserIDFromToken(r)
        return "user:" + userID
    },
}
```

## 🎯 Real-World Use Cases

### E-commerce Platform
```go
locationConfigs := []servex.LocationRateLimitConfig{
    {
        // Order creation - prevent spam orders
        PathPatterns: []string{"/orders/create"},
        Config: servex.RateLimitConfig{
            RequestsPerInterval: 10,
            Interval:            time.Minute,
            BurstSize:           2,
        },
    },
    {
        // Product search - allow frequent searches
        PathPatterns: []string{"/products/search"},
        Config: servex.RateLimitConfig{
            RequestsPerInterval: 60,
            Interval:            time.Minute,
            BurstSize:           15,
        },
    },
    {
        // Payment endpoints - very strict
        PathPatterns: []string{"/payments/*"},
        Config: servex.RateLimitConfig{
            RequestsPerInterval: 3,
            Interval:            time.Minute,
            BurstSize:           1,
        },
    },
}
```

### Content Management System
```go
locationConfigs := []servex.LocationRateLimitConfig{
    {
        // Content publishing - moderate limits
        PathPatterns: []string{"/content/publish", "/content/update"},
        Config: servex.RateLimitConfig{
            RequestsPerInterval: 20,
            Interval:            time.Minute,
            BurstSize:           5,
        },
    },
    {
        // Media uploads - strict limits
        PathPatterns: []string{"/media/upload"},
        Config: servex.RateLimitConfig{
            RequestsPerInterval: 5,
            Interval:            time.Minute,
            BurstSize:           2,
        },
    },
    {
        // Content reading - high limits
        PathPatterns: []string{"/content/read", "/content/list"},
        Config: servex.RateLimitConfig{
            RequestsPerInterval: 200,
            Interval:            time.Minute,
            BurstSize:           50,
        },
    },
}
```

### API Gateway Pattern
```go
locationConfigs := []servex.LocationRateLimitConfig{
    {
        // Free tier API
        PathPatterns: []string{"/api/free/*"},
        Config: servex.RateLimitConfig{
            RequestsPerInterval: 100,
            Interval:            time.Hour, // Per hour
            BurstSize:           10,
        },
    },
    {
        // Premium tier API  
        PathPatterns: []string{"/api/premium/*"},
        Config: servex.RateLimitConfig{
            RequestsPerInterval: 1000,
            Interval:            time.Hour,
            BurstSize:           100,
        },
    },
    {
        // Enterprise tier API
        PathPatterns: []string{"/api/enterprise/*"},
        Config: servex.RateLimitConfig{
            RequestsPerInterval: 10000,
            Interval:            time.Hour,
            BurstSize:           1000,
        },
    },
}
```

## 📊 Monitoring Rate Limits

### Rate Limit Information Endpoint
```bash
curl http://localhost:8080/rate-limit-info
```

Returns comprehensive rate limiting configuration:
```json
{
  "title": "Location-Based Rate Limiting Demo",
  "rate_limits": {
    "authentication": {
      "patterns": ["/auth/login", "/auth/register"],
      "limit": "5 requests per minute",
      "burst": "2 requests",
      "reasoning": "Prevent brute force attacks"
    },
    "api": {
      "patterns": ["/api/*"],
      "limit": "100 requests per minute", 
      "burst": "20 requests",
      "reasoning": "Allow reasonable API usage"
    }
  }
}
```

### Production Monitoring
In production, you should monitor:
- Rate limit hit rates by endpoint
- Burst usage patterns
- False positive rate limiting
- Performance impact of rate limiting

## 🎯 Best Practices

### 1. Choosing Rate Limits
```
Authentication:  5-10 req/min  (Security priority)
API endpoints:   100-1000/min  (Usage-based)
File uploads:    5-20 req/min   (Resource protection)
Admin panels:    200-500/min   (Trust but verify)
Public content:  No limits     (Accessibility)
```

### 2. Burst Configuration
- **Low burst**: Security-critical endpoints
- **High burst**: Interactive user experiences  
- **Balanced burst**: API endpoints

### 3. Testing Strategy
1. **Load testing**: Verify limits under load
2. **Burst testing**: Test burst allowances
3. **Recovery testing**: Verify rate limit resets
4. **Edge case testing**: Test boundary conditions

### 4. Error Handling
```go
Config: servex.RateLimitConfig{
    StatusCode: http.StatusTooManyRequests,
    Message: "Rate limit exceeded. Please try again in 60 seconds.",
    
    // Optional: Custom error response
    ErrorHandler: func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Retry-After", "60")
        w.WriteHeader(http.StatusTooManyRequests)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "Rate limit exceeded",
            "retry_after": "60 seconds",
        })
    },
}
```

## ⚠️ Production Considerations

### Memory Usage
- Rate limiting uses in-memory storage
- Each unique IP/key uses memory
- Consider cleanup policies for long-running services

### Distributed Systems
- Rate limits are per-server instance
- For distributed rate limiting, consider external stores (Redis)
- Account for multiple server instances in limits

### IP vs User-Based Limiting
```go
// IP-based (default)
KeyFunc: nil  // Uses client IP

// User-based  
KeyFunc: func(r *http.Request) string {
    return getUserID(r)
}

// API key-based
KeyFunc: func(r *http.Request) string {
    return r.Header.Get("X-API-Key")
}
```

## 🔗 Integration with Other Features

### Combining with Filtering (Tutorial 11)
```go
// First apply filtering, then rate limiting
server.Use(FilterMiddleware)
server.Use(RateLimitMiddleware)
```

### Custom Rate Limit Responses
```go
Config: servex.RateLimitConfig{
    StatusCode: 429,
    Message: "Custom rate limit message",
    
    // Add rate limit headers
    ResponseHeaders: map[string]string{
        "X-RateLimit-Limit": "100",
        "X-RateLimit-Remaining": "0", 
        "X-RateLimit-Reset": "60",
    },
}
```

## ➡️ Next Steps

Ready for more advanced topics?
- **Tutorial 13**: Dynamic Filtering - Runtime filter updates
- **Tutorial 14**: Production Setup - Complete production configuration  
- **Tutorial 06**: Basic Rate Limiting - Global rate limiting

## 📚 Comparison with Other Tutorials

| Tutorial | Focus | Scope |
|----------|-------|-------|
| **Tutorial 06** | Rate Limiting | Global server limits |
| **Tutorial 11** | Location Filtering | Per-endpoint filtering |
| **Tutorial 12** | Location Rate Limiting | Per-endpoint rate limits |
| **Tutorial 13** | Dynamic Filtering | Runtime updates |

**Tutorial 12** builds on Tutorial 06 by adding **location-specific rate limiting** - different limits for different endpoints instead of global limits for the entire server.

This approach gives you **fine-grained performance control** while maintaining **optimal user experience**! ⚡ 