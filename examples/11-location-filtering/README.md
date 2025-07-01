# Tutorial 11: Location-Based Filtering

Learn how to apply **different filtering rules to different URL paths** in your Servex applications. Location-based filtering allows you to have custom security policies for different parts of your application - strict rules for admin areas, API key requirements for APIs, and relaxed rules for public endpoints.

## 🎯 What You'll Learn

- Configure different filtering rules for different URL patterns
- Implement graduated security levels across your application
- Use pattern matching to target specific endpoints
- Combine IP filtering, header validation, and user agent controls
- Create layered security architectures

## 🏗️ Architecture Overview

Location-based filtering lets you define security zones in your application:

```
🔒 /admin/*     - Maximum Security (IP + Token + User-Agent)
🔑 /api/*       - API Security (IP + API Key + No Debug)
🔐 /auth/*      - Auth Security (IP + User-Agent)
📁 /upload/*    - Content Security (Content-Type + Size limits)
🌍 /public/*    - Basic Security (Bot protection only)
❌ /other/*     - No Security (No filtering rules)
```

## 📋 Available Endpoints

| Endpoint | Security Level | Requirements |
|----------|---------------|-------------|
| `POST /auth/login` | High | IP whitelist + User-Agent |
| `POST /auth/register` | High | IP whitelist + User-Agent |
| `GET /api/v1/users` | Medium | IP whitelist + API Key |
| `GET /api/v2/posts` | Medium | IP whitelist + API Key |
| `GET /admin/dashboard` | Maximum | IP + Admin Token + User-Agent |
| `GET /admin/users` | Maximum | IP + Admin Token + User-Agent |
| `POST /upload/image` | Content | Content-Type + Size + No bots |
| `POST /upload/document` | Content | Content-Type + Size + No bots |
| `GET /public/info` | Basic | Bot protection only |
| `GET /other/info` | None | No filtering |
| `GET /health` | None | No filtering |

## 🏃 Quick Start

```bash
# Start the server
go run main.go

# Test basic endpoint (no filtering)
curl http://localhost:8080/health
```

## 🧪 Testing Different Security Levels

### 1. Auth Endpoints - IP + User-Agent Filtering

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

**❌ Blocked - Wrong User-Agent:**
```bash
curl -X POST http://localhost:8080/auth/login \
     -H "User-Agent: SomeRandomBrowser/1.0"
```

### 2. API Endpoints - IP + API Key Required

**✅ Valid Request:**
```bash
curl http://localhost:8080/api/v1/users \
     -H "X-API-Key: api-key-123"
```

**❌ Blocked - No API Key:**
```bash
curl http://localhost:8080/api/v1/users
```

**❌ Blocked - Invalid API Key:**
```bash
curl http://localhost:8080/api/v1/users \
     -H "X-API-Key: wrong-key"
```

**❌ Blocked - Debug Parameter:**
```bash
curl "http://localhost:8080/api/v1/users?debug=true" \
     -H "X-API-Key: api-key-123"
```

### 3. Admin Endpoints - Maximum Security

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

**❌ Blocked - Wrong User-Agent:**
```bash
curl http://localhost:8080/admin/dashboard \
     -H "Admin-Token: admin-secret-token-123" \
     -H "User-Agent: Firefox/1.0"
```

### 4. Upload Endpoints - Content-Type Filtering

**✅ Valid Image Upload:**
```bash
curl -X POST http://localhost:8080/upload/image \
     -H "Content-Type: image/jpeg" \
     -H "Content-Length: 1024"
```

**✅ Valid Document Upload:**
```bash
curl -X POST http://localhost:8080/upload/document \
     -H "Content-Type: application/pdf" \
     -H "Content-Length: 5000"
```

**❌ Blocked - Invalid Content-Type:**
```bash
curl -X POST http://localhost:8080/upload/image \
     -H "Content-Type: application/exe"
```

**❌ Blocked - File Too Large:**
```bash
curl -X POST http://localhost:8080/upload/image \
     -H "Content-Type: image/jpeg" \
     -H "Content-Length: 99999999"
```

**❌ Blocked - Bot User-Agent:**
```bash
curl -X POST http://localhost:8080/upload/image \
     -H "Content-Type: image/jpeg" \
     -H "User-Agent: BadBot/1.0"
```

### 5. Public Endpoints - Basic Protection

**✅ Valid Request:**
```bash
curl http://localhost:8080/public/info
```

**❌ Blocked - Known Bot:**
```bash
curl http://localhost:8080/public/info \
     -H "User-Agent: BadBot/1.0"
```

### 6. No Filtering - Always Allowed

**✅ Always Works:**
```bash
curl http://localhost:8080/other/info
curl http://localhost:8080/health
```

## 💻 Configuration Structure

The location-based filtering uses this configuration structure:

```go
locationFilterConfigs := []servex.LocationFilterConfig{
    {
        // Define which paths this rule applies to
        PathPatterns: []string{"/admin/*", "/dashboard/*"},
        
        // Define the filtering rules
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
    // More rules...
}
```

## 🔧 Filter Types Available

### IP-Based Filtering
```go
AllowedIPs: []string{
    "192.168.1.0/24",  // Subnet
    "127.0.0.1",       // Specific IP
    "10.0.0.0/8",      // Large network
}
```

### Header-Based Filtering
```go
// Exact header values
AllowedHeaders: map[string][]string{
    "X-API-Key": {"key1", "key2", "key3"},
    "Admin-Token": {"secret-token"},
}

// Regex header validation
AllowedHeadersRegex: map[string][]string{
    "Content-Type": {"^image/.*", "^application/pdf$"},
    "X-API-Key": {"^key-[a-f0-9]{32}$"},
}
```

### User-Agent Filtering
```go
// Exact user agent matching
AllowedUserAgents: []string{"MyApp/1.0", "AuthClient/2.0"}
BlockedUserAgents: []string{"BadBot/1.0", "Scanner/1.0"}

// Regex user agent matching
AllowedUserAgentsRegex: []string{"^AdminConsole/.*"}
BlockedUserAgentsRegex: []string{".*[Bb]ot.*", ".*[Ss]craper.*"}
```

### Query Parameter Filtering
```go
// Block specific query parameters
BlockedQueryParams: map[string][]string{
    "debug": {"true", "1"},
    "test": {"true", "1"},
}
```

## 🏢 Real-World Use Cases

### Enterprise API Security
```go
{
    PathPatterns: []string{"/api/enterprise/*"},
    Config: servex.FilterConfig{
        // Only enterprise network
        AllowedIPs: []string{"203.0.113.0/24"},
        
        // Enterprise API keys only
        AllowedHeadersRegex: map[string][]string{
            "X-Enterprise-Key": {"^ent-[a-f0-9]{64}$"},
        },
        
        // No debug access in production
        BlockedQueryParams: map[string][]string{
            "debug": {"true", "1", "on"},
        },
    },
}
```

### Internal Admin Panel
```go
{
    PathPatterns: []string{"/internal/*"},
    Config: servex.FilterConfig{
        // Internal network only
        AllowedIPs: []string{"192.168.0.0/16", "10.0.0.0/8"},
        
        // Admin session token required
        AllowedHeaders: map[string][]string{
            "X-Admin-Session": {"valid-session-token"},
        },
        
        // Internal tools only
        AllowedUserAgentsRegex: []string{
            "^InternalTool/.*",
            "^AdminPanel/.*",
        },
    },
}
```

### File Upload Security
```go
{
    PathPatterns: []string{"/upload/*"},
    Config: servex.FilterConfig{
        // Block all bots
        BlockedUserAgentsRegex: []string{".*[Bb]ot.*"},
        
        // Only allow specific file types
        AllowedHeadersRegex: map[string][]string{
            "Content-Type": {
                "^image/(jpeg|png|gif)$",
                "^application/pdf$",
                "^text/plain$",
            },
        },
        
        // Block files > 50MB
        BlockedHeadersRegex: map[string][]string{
            "Content-Length": {"^[5-9][0-9]{7,}$"},
        },
    },
}
```

## 🔗 Pattern Matching

Location-based filtering supports these pattern types:

| Pattern | Matches | Example |
|---------|---------|---------|
| `/api/*` | Everything under /api/ | `/api/users`, `/api/v1/posts` |
| `/admin/*` | Everything under /admin/ | `/admin/dashboard`, `/admin/users` |
| `/upload/*` | Everything under /upload/ | `/upload/image`, `/upload/file` |

## 🎯 Best Practices

### 1. Security Layers
Start with the most restrictive and work down:
```
1. Admin endpoints     - Maximum security
2. API endpoints       - API key + IP filtering  
3. Auth endpoints      - IP + User-Agent filtering
4. Upload endpoints    - Content filtering
5. Public endpoints    - Basic bot protection
6. Health/Status       - No filtering
```

### 2. Testing Strategy
- Test each security level independently
- Verify blocked requests return correct errors
- Test edge cases (wrong headers, invalid IPs)
- Use automation for regression testing

### 3. Production Considerations
- Use real IP ranges (not 127.0.0.1)
- Implement proper API key management
- Monitor blocked requests
- Have bypass mechanisms for emergencies

## ⚠️ Security Notes

### IP Filtering Limitations
- Be careful with proxy servers and load balancers
- Consider `X-Forwarded-For` headers in production
- IP ranges can be large - test thoroughly

### Header Security
- Don't put secrets in URLs (use headers)
- Validate header formats with regex
- Consider header injection attacks

### Content Filtering
- File type detection is based on Content-Type header
- Implement server-side file validation too
- Consider file size limits carefully

## ➡️ Next Steps

Ready for more advanced topics?
- **Tutorial 12**: Location-Based Rate Limiting - Different rate limits per endpoint
- **Tutorial 13**: Dynamic Filtering - Runtime filter updates
- **Tutorial 14**: Production Setup - Complete production configuration

## 📚 Comparison with Other Tutorials

| Tutorial | Focus | Filtering Scope |
|----------|-------|-----------------|
| **Tutorial 07** | Request Filtering | Global server filtering |
| **Tutorial 11** | Location Filtering | Per-endpoint filtering |
| **Tutorial 12** | Location Rate Limiting | Per-endpoint rate limits |
| **Tutorial 13** | Dynamic Filtering | Runtime filter updates |

**Tutorial 11** builds on Tutorial 07 by adding **location-specific filtering** - different rules for different endpoints instead of global rules for the entire server.

This approach gives you **fine-grained security control** while maintaining **simple configuration**! 🚀 