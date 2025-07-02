# 06 - Rate Limiting

Protect your server from abuse and ensure fair resource usage with rate limiting. This tutorial shows how to implement different rate limiting strategies to prevent DoS attacks and manage server load.

## What You'll Learn

- How to set up basic rate limiting
- Understanding RPS (Requests Per Second) limits
- Rate limiting headers and responses
- Testing rate limiting strategies
- Best practices for production use

## Features Demonstrated

- ✅ **RPS rate limiting** - Limit requests per second per IP
- ✅ **Rate limit headers** - X-RateLimit-* headers for clients
- ✅ **429 responses** - Proper "Too Many Requests" responses
- ✅ **Interactive testing** - Web interface to test limits
- ✅ **Different endpoints** - Show how limits apply

## Running This Example

```bash
# Run the server
go run main.go

# Visit the interactive demo
open http://localhost:8080/
```

## Rate Limiting Configuration

This example uses a simple 5 RPS (requests per second) limit:

```go
server, err := servex.NewServer(
    servex.WithRPS(5), // Allow 5 requests per second per IP
)
```

## Testing Rate Limits

### Manual Testing with curl

```bash
# Single request (should work)
curl http://localhost:8080/api/test

# Check rate limit headers
curl -I http://localhost:8080/api/test
```

### Expected Responses

**Successful request (within limits):**
```
HTTP/1.1 200 OK
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 4
X-RateLimit-Reset: 1640995200
```

**Rate limited request:**
```
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1640995201
Retry-After: 1
```

### Interactive Web Testing

Visit http://localhost:8080/ for an interactive demo with:
- **Single Request** - Test one request at a time
- **Rapid Requests** - Send 10 requests quickly (triggers rate limiting)
- **Slow Requests** - Send 10 requests slowly (stays within limits)

## Rate Limiting Headers

Servex automatically adds rate limiting headers:

| Header | Description | Example |
|--------|-------------|---------|
| `X-RateLimit-Limit` | Maximum requests allowed | `5` |
| `X-RateLimit-Remaining` | Requests remaining in current window | `3` |
| `X-RateLimit-Reset` | Unix timestamp when limit resets | `1640995200` |
| `Retry-After` | Seconds to wait before retrying (on 429) | `1` |

## Rate Limiting Strategies

### 1. Requests Per Second (RPS)
```go
servex.WithRPS(10) // 10 requests per second
```
- **Best for**: APIs with consistent usage patterns
- **Pros**: Simple, predictable
- **Cons**: Can be bursty

### 2. Requests Per Minute (RPM)
```go
servex.WithRPM(300) // 300 requests per minute (5 RPS average)
```
- **Best for**: APIs that can handle bursts
- **Pros**: Allows burst traffic
- **Cons**: Less precise control

### 3. Combined Strategies
```go
servex.WithRPS(10),     // Maximum 10 RPS
servex.WithRPM(300),    // Maximum 300 RPM
```
- **Best for**: Production APIs
- **Pros**: Handles both burst and sustained load
- **Cons**: More complex

## Production Considerations

### Choosing Rate Limits

**API Endpoints:**
- **Public APIs**: 100-1000 RPM
- **Authenticated APIs**: 1000-10000 RPM
- **Internal APIs**: 10000+ RPM

**Web Applications:**
- **Login pages**: 5 requests per minute (prevent brute force)
- **Registration**: 1 request per minute
- **General pages**: 100-1000 RPM

### Excluding Endpoints

Some endpoints should typically be excluded from rate limiting:
```go
// Health checks, metrics, etc.
servex.WithRateLimitExcludePaths("/health", "/metrics")
```

### Per-User vs Per-IP

**Per-IP (default):**
- Simpler implementation
- Good for public APIs
- Can affect shared IPs (offices, NAT)

**Per-User:**
- More accurate for authenticated APIs
- Requires user identification
- Better for SaaS applications

## Common Patterns

### API Tiers
```go
// Free tier: 100 RPM
servex.WithRPM(100)

// Premium tier: 1000 RPM  
servex.WithRPM(1000)

// Enterprise: 10000 RPM
servex.WithRPM(10000)
```

### Gradual Limits
```go
// Stricter for write operations
server.HandleFunc("/api/create", handler).Methods(POST)
// with lower limits

// More lenient for read operations  
server.HandleFunc("/api/read", handler).Methods(GET)
// with higher limits
```

## Error Handling

When rate limits are exceeded:

1. **HTTP 429** response is returned
2. **Retry-After** header indicates wait time
3. **Rate limit headers** show current status
4. **Request is rejected** without processing

Clients should:
- Respect the `Retry-After` header
- Implement exponential backoff
- Monitor rate limit headers
- Handle 429 responses gracefully

## Monitoring and Alerting

Track these metrics:
- **Rate limit hit ratio** - % of requests that hit limits
- **429 response rate** - How often clients are rate limited
- **Top rate-limited IPs** - Identify potential abuse
- **Rate limit effectiveness** - Is it preventing issues?

## What's Next?

🎯 **Continue the tutorial:** → [07-request-filtering](../07-request-filtering/)

In the next tutorial, you'll learn how to filter and validate requests before they reach your handlers. 