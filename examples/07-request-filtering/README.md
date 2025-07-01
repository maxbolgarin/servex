# 07 - Request Filtering

Protect your server from malicious requests and unwanted traffic with comprehensive request filtering. This tutorial shows how to filter requests by IP, User-Agent, headers, and query parameters.

## What You'll Learn

- How to block malicious user agents (bots, scrapers)
- IP address filtering and blocking
- Query parameter validation and blocking
- Header-based filtering
- Excluding specific paths from filtering
- Testing filter effectiveness

## Features Demonstrated

- ✅ **User-Agent filtering** - Block bots, scrapers, and crawlers
- ✅ **Query parameter filtering** - Block suspicious parameters
- ✅ **IP address filtering** - Block specific IPs or ranges
- ✅ **Path exclusions** - Allow certain endpoints to bypass filters
- ✅ **Custom error responses** - Meaningful 403 responses
- ✅ **Interactive testing** - Web interface to test filters

## Running This Example

```bash
# Run the server
go run main.go

# Visit the interactive demo
open http://localhost:8080/
```

## Filter Configuration

This example demonstrates multiple filtering strategies:

```go
server, err := servex.NewServer(
    // Block bots, scrapers, crawlers
    servex.WithBlockedUserAgentsRegex(
        ".*[Bb]ot.*",       // Any bot
        ".*[Ss]craper.*",   // Any scraper  
        ".*[Cc]rawler.*",   // Any crawler
        "curl.*",           // Block curl
    ),
    
    // Block dangerous query parameters
    servex.WithBlockedQueryParams(map[string][]string{
        "debug": {"true", "1", "on"},
        "admin": {"true", "1", "on"},
    }),
    
    // Block specific IPs
    servex.WithBlockedIPs("127.0.0.2"),
    
    // Exclude health endpoints
    servex.WithFilterExcludePaths("/health", "/metrics"),
)
```

## Testing Filters

### Allowed Requests
```bash
# Normal request (should work)
curl http://localhost:8080/api/test

# Health check (bypasses all filters)
curl http://localhost:8080/health

# Check filter configuration
curl http://localhost:8080/api/status
```

### Blocked Requests
```bash
# Blocked by user-agent filter
curl -H "User-Agent: BadBot/1.0" http://localhost:8080/api/test

# Blocked by query parameter filter
curl "http://localhost:8080/api/test?debug=true"
curl "http://localhost:8080/api/test?admin=1"

# Multiple blocked parameters
curl "http://localhost:8080/api/test?debug=true&admin=on"
```

### Expected Responses

**Allowed request:**
```json
{
  "message": "Request passed all security filters!",
  "user_agent": "Mozilla/5.0...",
  "ip": "127.0.0.1:54321"
}
```

**Blocked request:**
```
HTTP/1.1 403 Forbidden
Content-Type: text/plain

Request blocked by security policy
```

## Filter Types

### 1. User-Agent Filtering

**Block specific agents:**
```go
servex.WithBlockedUserAgents("BadBot/1.0", "MaliciousBot/2.0")
```

**Block with regex patterns:**
```go
servex.WithBlockedUserAgentsRegex(
    ".*[Bb]ot.*",       // Any bot
    ".*[Ss]craper.*",   // Any scraper
    "curl.*",           // Command line tools
)
```

**Allow only specific agents:**
```go
servex.WithAllowedUserAgentsRegex(
    "Mozilla.*Chrome.*",
    "Mozilla.*Firefox.*",
    "Mozilla.*Safari.*",
)
```

### 2. IP Address Filtering

**Block specific IPs:**
```go
servex.WithBlockedIPs("203.0.113.1", "198.51.100.0/24")
```

**Allow only specific IPs:**
```go
servex.WithAllowedIPs("192.168.1.0/24", "10.0.0.0/8")
```

**Trust proxy headers:**
```go
servex.WithFilterTrustedProxies("172.16.0.0/12")
```

### 3. Query Parameter Filtering

**Block specific parameters:**
```go
servex.WithBlockedQueryParams(map[string][]string{
    "debug": {"true", "1", "on"},
    "admin": {"true", "1"},
})
```

**Block with regex:**
```go
servex.WithBlockedQueryParamsRegex(map[string][]string{
    "redirect": {"https?://[^/]*[^.].*"}, // Block open redirects
    "callback": {".*script.*"},           // Block potential XSS
})
```

### 4. Header Filtering

**Require specific headers:**
```go
servex.WithAllowedHeaders(map[string][]string{
    "X-API-Key": {"your-api-key"},
})
```

**Block dangerous headers:**
```go
servex.WithBlockedHeaders(map[string][]string{
    "X-Debug": {"true", "1"},
})
```

**Header regex filtering:**
```go
servex.WithAllowedHeadersRegex(map[string][]string{
    "Authorization": {"Bearer [A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+"},
})
```

## Path Configuration

### Include Specific Paths
```go
// Only apply filters to these paths
servex.WithFilterIncludePaths("/api/secure", "/admin")
```

### Exclude Specific Paths
```go
// Don't apply filters to these paths
servex.WithFilterExcludePaths("/health", "/metrics", "/favicon.ico")
```

## Production Patterns

### API Protection
```go
// Protect API endpoints from abuse
servex.WithBlockedUserAgentsRegex(".*[Bb]ot.*", "curl.*", "wget.*"),
servex.WithBlockedQueryParams(map[string][]string{
    "debug":    {"true", "1"},
    "test":     {"true", "1"},
    "internal": {"true", "1"},
}),
servex.WithFilterExcludePaths("/health", "/metrics"),
```

### Admin Panel Protection
```go
// Strict filtering for admin areas
servex.WithAllowedIPs("192.168.1.0/24"),      // Office network only
servex.WithFilterIncludePaths("/admin", "/dashboard"),
servex.WithAllowedUserAgentsRegex("Mozilla.*"), // Browsers only
```

### Geographic Filtering
```go
// Block traffic from specific countries (with IP ranges)
servex.WithBlockedIPs(
    "203.0.113.0/24",  // Country A
    "198.51.100.0/24", // Country B
),
```

## Security Best Practices

1. **Layer your defenses** - Use multiple filter types together
2. **Monitor filter effectiveness** - Track blocked vs allowed requests
3. **Update patterns regularly** - Add new threats as discovered
4. **Test thoroughly** - Ensure legitimate traffic isn't blocked
5. **Log blocked requests** - Investigate patterns and threats
6. **Consider false positives** - Have a process to handle legitimate blocks

## Common Use Cases

### E-commerce Sites
- Block scrapers from product pages
- Prevent price monitoring bots
- Protect checkout processes

### APIs
- Block unauthorized automation
- Prevent API abuse
- Protect against DoS attacks

### Content Sites
- Prevent content scraping
- Block unwanted crawlers
- Protect against hotlinking

## What's Next?

🎯 **Continue the tutorial:** → [08-configuration](../08-configuration/)

In the next tutorial, you'll learn how to manage server configuration with files and environment variables. 