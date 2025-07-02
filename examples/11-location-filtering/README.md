# Tutorial 11: Location-Based Filtering & Rate Limiting

Learn how to apply **different filtering rules AND rate limits to different URL paths** in your Servex applications. This comprehensive tutorial combines security filtering with performance protection, allowing you to create layered security policies tailored to each part of your application.

## 🎯 What You'll Learn

- Configure different filtering rules for different URL patterns
- Apply different rate limits to different endpoints simultaneously  
- Implement graduated security levels across your application
- Combine IP filtering, header validation, user agent controls, and rate limiting
- Create comprehensive security and performance protection architectures
- Balance security with usability across different application areas

## 🏗️ Combined Security Architecture

Location-based filtering + rate limiting creates comprehensive protection zones:

```
🔒 /admin/*     - Maximum Security (IP + Token + User-Agent + 500 req/min)
🔑 /api/*       - API Security (IP + API Key + No Debug + 100 req/min)
🔐 /auth/*      - Auth Security (IP + User-Agent + 5 req/min)
📁 /upload/*    - Content Security (Content-Type + Size + 10 req/min)
🌍 /public/*    - Basic Security (Bot protection + 1000 req/min)
❌ /other/*     - No Protection (No filtering, no rate limits)
```

## 📋 Security & Performance Configuration

| Endpoint | Security Level | Rate Limit | Purpose |
|----------|---------------|------------|---------|
| `POST /auth/login` | High | 5 req/min | Prevent brute force + abuse |
| `POST /auth/register` | High | 5 req/min | Prevent spam registration |
| `GET /api/v1/users` | Medium | 100 req/min | API protection + performance |
| `GET /api/v2/posts` | Medium | 100 req/min | API protection + performance |
| `GET /admin/dashboard` | Maximum | 500 req/min | Trust admin users |
| `POST /upload/image` | Content | 10 req/min | Prevent upload abuse |
| `GET /public/info` | Basic | 1000 req/min | Open but protected |
| `GET /other/info` | None | None | No restrictions |

## 🏃 Quick Start

```bash
# Start the server
go run main.go

# Test basic endpoint (no filtering or rate limiting)
curl http://localhost:8080/health
```

## 🧪 Testing Combined Security & Performance

### 1. Auth Endpoints - Maximum Protection (IP + User-Agent + 5/min)

**✅ Valid Request:**
```bash
curl -X POST http://localhost:8080/auth/login \
     -H "User-Agent: MyApp/1.0"
```

**❌ Blocked - Bad User-Agent:**
```bash
curl -X POST http://localhost:8080/auth/login \
     -H "User-Agent: BadBot/1.0"
```

**⚡ Rate Limited - Too Many Requests:**
```bash
# Send 6 rapid requests to trigger rate limiting
for i in {1..6}; do
  curl -X POST http://localhost:8080/auth/login \
       -H "User-Agent: MyApp/1.0"
  echo " - Request $i"
done
```

### 2. API Endpoints - Security + Performance (IP + API Key + 100/min)

**✅ Valid Request:**
```bash
curl http://localhost:8080/api/v1/users \
     -H "X-API-Key: api-key-123"
```

**❌ Blocked - No API Key:**
```bash
curl http://localhost:8080/api/v1/users
```

**❌ Blocked - Debug Parameter:**
```bash
curl "http://localhost:8080/api/v1/users?debug=true" \
     -H "X-API-Key: api-key-123"
```

**⚡ Rate Limited - API Overuse:**
```bash
# Send 105 rapid requests to trigger API rate limiting
for i in {1..105}; do
  curl -s http://localhost:8080/api/v1/users \
       -H "X-API-Key: api-key-123" > /dev/null
  echo "API request $i"
done
```

### 3. Admin Endpoints - High Security + High Performance (All + 500/min)

**✅ Valid Request:**
```bash
curl http://localhost:8080/admin/dashboard \
     -H "Admin-Token: admin-secret-token-123" \
     -H "User-Agent: AdminConsole/1.0"
```

**❌ Blocked - Wrong Token:**
```bash
curl http://localhost:8080/admin/dashboard \
     -H "Admin-Token: wrong-token"
```

**✅ High Rate Limit - Admin Performance:**
```bash
# Admins get higher rate limits for productivity
for i in {1..100}; do
  curl -s http://localhost:8080/admin/dashboard \
       -H "Admin-Token: admin-secret-token-123" \
       -H "User-Agent: AdminConsole/1.0" > /dev/null
  echo "Admin request $i"
done
```

### 4. Upload Endpoints - Content + Performance Protection

**✅ Valid Image Upload:**
```bash
curl -X POST http://localhost:8080/upload/image \
     -H "Content-Type: image/jpeg" \
     -H "Content-Length: 1024"
```

**❌ Blocked - Invalid Content-Type:**
```bash
curl -X POST http://localhost:8080/upload/image \
     -H "Content-Type: application/exe"
```

**⚡ Rate Limited - Upload Abuse:**
```bash
# Upload rate limiting kicks in after 10 requests/minute
for i in {1..12}; do
  curl -X POST http://localhost:8080/upload/image \
       -H "Content-Type: image/jpeg" \
       -H "Content-Length: 1024"
  echo "Upload $i"
done
```

### 5. Public Endpoints - Balanced Protection

**✅ Valid Request:**
```bash
curl http://localhost:8080/public/info
```

**❌ Blocked - Known Bot:**
```bash
curl http://localhost:8080/public/info \
     -H "User-Agent: BadBot/1.0"
```

**⚡ Rate Limited - Public Overuse:**
```bash
# High rate limit (1000/min) for public access
for i in {1..1005}; do
  curl -s http://localhost:8080/public/info > /dev/null
  if [ $((i % 100)) -eq 0 ]; then
    echo "Public request $i"
  fi
done
```

## 💻 Combined Configuration Structure

```go
// Combined filtering and rate limiting configurations
locationFilterConfigs := []servex.LocationFilterConfig{
    {
        PathPatterns: []string{"/admin/*"},
        Config: servex.FilterConfig{
            AllowedIPs: []string{"127.0.0.1", "192.168.1.100"},
            AllowedHeaders: map[string][]string{
                "Admin-Token": {"admin-secret-token-123"},
            },
            AllowedUserAgentsRegex: []string{"^AdminConsole/.*"},
            StatusCode: http.StatusForbidden,
            Message: "Admin access denied",
        },
    },
}

locationRateLimitConfigs := []servex.LocationRateLimitConfig{
    {
        PathPatterns: []string{"/admin/*"},
        Config: servex.RateLimitConfig{
            Enabled:             true,
            RequestsPerInterval: 500, // High limits for admin productivity
            Interval:            time.Minute,
            BurstSize:           50,
            StatusCode:          http.StatusTooManyRequests,
            Message:             "Admin rate limit exceeded",
        },
    },
}
```

## 🎯 Security & Performance Strategies

### 1. Layered Protection Approach
```
Request Flow:
1. Location Filter Check (Security)
2. Rate Limit Check (Performance)  
3. Application Logic
```

### 2. Graduated Security Levels
- **Critical endpoints**: Strict filtering + Low rate limits
- **API endpoints**: Moderate filtering + Moderate rate limits  
- **Admin endpoints**: High filtering + High rate limits
- **Public endpoints**: Basic filtering + High rate limits

### 3. Performance Balancing
- **Authentication**: Low rate limits (prevent brute force)
- **APIs**: Moderate rate limits (reasonable usage)
- **Uploads**: Low rate limits (prevent abuse)
- **Admin**: High rate limits (productivity)
- **Public**: High rate limits (accessibility)

## 🔧 Advanced Combined Features

### Custom Rate Limit Keys with Security Context
```go
Config: servex.RateLimitConfig{
    KeyFunc: func(r *http.Request) string {
        // Different rate limiting strategies based on security context
        if isAdminUser(r) {
            return "admin:" + getUserID(r)
        }
        if hasAPIKey(r) {
            return "api:" + getAPIKey(r)
        }
        return "ip:" + getClientIP(r)
    },
}
```

### Security-Based Rate Limit Adjustments
```go
// Adjust rate limits based on security posture
if isTrustedIP(clientIP) {
    rateLimitMultiplier = 2.0 // Higher limits for trusted IPs
} else if isSuspiciousIP(clientIP) {
    rateLimitMultiplier = 0.5 // Lower limits for suspicious IPs
}
```

### Combined Error Responses
```go
// Custom handler that combines filter and rate limit information
func securityErrorHandler(w http.ResponseWriter, r *http.Request, errorType string) {
    response := map[string]any{
        "error": "Access denied",
        "type":  errorType, // "filter_blocked" or "rate_limited"
        "retry_after": 60,
        "security_policy": "Location-based protection active",
    }
    
    w.Header().Set("Retry-After", "60")
    w.WriteHeader(http.StatusForbidden)
    json.NewEncoder(w).Encode(response)
}
```

## 🏢 Real-World Combined Patterns

### E-commerce Platform Security
```go
// Product catalog - high performance, basic security
{
    PathPatterns: []string{"/products/*"},
    FilterConfig: servex.FilterConfig{
        BlockedUserAgentsRegex: []string{".*[Bb]ot.*"},
    },
    RateLimitConfig: servex.RateLimitConfig{
        RequestsPerInterval: 1000, // High throughput for browsing
        Interval:           time.Minute,
        BurstSize:          100,
    },
}

// Checkout process - moderate security, controlled performance
{
    PathPatterns: []string{"/checkout/*"},
    FilterConfig: servex.FilterConfig{
        AllowedIPs: []string{"203.0.113.0/24"}, // Trusted networks
        BlockedUserAgentsRegex: []string{".*[Bb]ot.*"},
    },
    RateLimitConfig: servex.RateLimitConfig{
        RequestsPerInterval: 50, // Controlled checkout flow
        Interval:           time.Minute,
        BurstSize:          5,
    },
}

// Payment processing - maximum security, strict performance
{
    PathPatterns: []string{"/payment/*"},
    FilterConfig: servex.FilterConfig{
        AllowedIPs: []string{"192.168.1.0/24"}, // Internal only
        AllowedHeaders: map[string][]string{
            "X-Payment-Token": {"valid-payment-session"},
        },
    },
    RateLimitConfig: servex.RateLimitConfig{
        RequestsPerInterval: 10, // Very strict for payments
        Interval:           time.Minute,
        BurstSize:          2,
    },
}
```

### API Gateway Pattern
```go
// Free tier - basic security, low performance
{
    PathPatterns: []string{"/api/free/*"},
    FilterConfig: servex.FilterConfig{
        AllowedHeaders: map[string][]string{
            "X-API-Key": {"free-tier-keys..."},
        },
    },
    RateLimitConfig: servex.RateLimitConfig{
        RequestsPerInterval: 100,
        Interval:           time.Hour,
        BurstSize:          10,
    },
}

// Premium tier - moderate security, high performance  
{
    PathPatterns: []string{"/api/premium/*"},
    FilterConfig: servex.FilterConfig{
        AllowedHeaders: map[string][]string{
            "X-API-Key": {"premium-tier-keys..."},
        },
        AllowedIPs: []string{"203.0.113.0/24"},
    },
    RateLimitConfig: servex.RateLimitConfig{
        RequestsPerInterval: 1000,
        Interval:           time.Hour,
        BurstSize:          100,
    },
}
```

## 📊 Monitoring Combined Security & Performance

### Comprehensive Status Endpoint
```bash
curl http://localhost:8080/security-performance-status
```

Returns detailed information about both filtering and rate limiting:
```json
{
  "title": "Combined Security & Performance Protection",
  "security": {
    "blocked_requests_total": 45,
    "active_filters": 5,
    "last_block_time": "2024-01-15T10:30:00Z"
  },
  "performance": {
    "rate_limited_requests": 23,
    "active_rate_limits": 5,
    "highest_usage_endpoint": "/api/v1/users",
    "last_rate_limit_time": "2024-01-15T10:25:00Z"
  },
  "endpoints": {
    "auth": {
      "security_level": "high",
      "rate_limit": "5 req/min",
      "status": "protected"
    },
    "api": {
      "security_level": "medium", 
      "rate_limit": "100 req/min",
      "status": "protected"
    }
  }
}
```

### Performance Impact Analysis
- **Filtering**: ~0.1ms overhead per request
- **Rate limiting**: ~0.2ms overhead per request
- **Combined**: ~0.3ms total overhead
- **Memory usage**: Minimal (rate limit buckets + filter rules)

## 🛡️ Security Best Practices

### Defense in Depth
1. **Network level**: Firewall rules, CDN protection
2. **Application level**: Servex filtering + rate limiting
3. **Code level**: Input validation, output encoding
4. **Data level**: Encryption, access controls

### Performance Optimization  
1. **Cache filter rules**: Pre-compile regex patterns
2. **Efficient rate limiting**: Use memory-efficient algorithms
3. **Monitor overhead**: Track middleware performance impact
4. **Optimize hot paths**: Minimize checks on high-traffic endpoints

### Operational Excellence
1. **Monitoring**: Track both security and performance metrics
2. **Alerting**: Set up alerts for unusual patterns
3. **Tuning**: Regularly adjust limits based on traffic patterns
4. **Testing**: Load test with realistic security constraints

## ⚠️ Production Considerations

### Configuration Management
- Store security rules in versioned configuration files
- Use environment variables for sensitive values
- Implement configuration hot-reloading for rapid response
- Test configuration changes in staging first

### Scaling Patterns
- Rate limiting is per-server instance by default
- Consider Redis-backed rate limiting for multi-instance deployments
- Filter rules can be shared across instances
- Monitor memory usage with large IP block lists

### Emergency Procedures
- Have emergency "lockdown" configurations ready
- Implement circuit breakers for critical endpoints
- Plan for rapid IP blocking in security incidents
- Maintain bypass mechanisms for critical operations
