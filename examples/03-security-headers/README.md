# 03 - Security Headers

Protect your web application from common attacks with HTTP security headers. In this tutorial, you'll learn how to secure your server against XSS, clickjacking, and other web vulnerabilities.

## Examples Included

1. **Basic Security Headers** - Standard security headers setup
2. **Strict Security Headers** - High-security configuration
3. **Custom Security Configuration** - Tailored security settings
4. **Path-Specific Security** - Apply security only to specific paths
5. **Production Security** - Complete production setup
6. **Interactive Demo** - Web-based security demonstration

## Running the Examples

### Default (Interactive Demo)
```bash
go run main.go
```

This runs an interactive web demo on port 8080. Visit http://localhost:8080 to see security headers in action.

### Running Specific Examples

Edit the `main()` function in `main.go` to call different example functions:

```go
func main() {
    // Change this line to run different examples:
    interactiveSecurityDemo()     // Default - web demo
    // basicSecurityExample()     // Basic security
    // strictSecurityExample()    // Strict security
    // customSecurityExample()    // Custom configuration
    // pathSpecificSecurityExample() // Path-specific
    // productionSecurityExample() // Production ready
}
```

## Security Headers Demonstrated

### Basic Security Headers
- **X-Content-Type-Options**: `nosniff`
- **X-Frame-Options**: `DENY`
- **X-XSS-Protection**: `1; mode=block`
- **Referrer-Policy**: `strict-origin-when-cross-origin`

### Strict Security Headers (includes basic + advanced)
- **Content-Security-Policy**: Comprehensive CSP
- **Strict-Transport-Security**: HSTS with subdomains
- **Permissions-Policy**: Control browser features

### Custom Configuration Options
- **Custom CSP**: Tailored Content Security Policy
- **HSTS Preload**: HTTP Strict Transport Security with preload
- **Path-based Application**: Include/exclude specific paths
- **Custom Headers**: Application-specific headers

## Testing Security Headers

### Basic Testing
```bash
# Check all security headers
curl -I http://localhost:8080/

# Check specific security header
curl -I http://localhost:8080/ | grep -i content-security-policy

# Test excluded endpoint (no security headers)
curl -I http://localhost:8080/health

# Compare secure vs non-secure endpoints
curl -I http://localhost:8080/api/secure
curl -I http://localhost:8080/health
```

### Browser Testing
1. Open browser developer tools
2. Go to Network tab
3. Visit http://localhost:8080
4. Check Response Headers for security headers

### Security Scanner Testing
```bash
# Test with online security scanners:
# - securityheaders.com
# - observatory.mozilla.org
# - webhint.io

# Example
curl -s "https://securityheaders.com/?q=your-domain.com&hide=on&followRedirects=on"
```

## Security Features

### Content Security Policy (CSP)
Prevents XSS attacks by controlling resource loading:
```
default-src 'self';
script-src 'self' 'unsafe-inline';
style-src 'self' 'unsafe-inline';
```

### HTTP Strict Transport Security (HSTS)
Forces HTTPS connections:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### Frame Options
Prevents clickjacking attacks:
```
X-Frame-Options: DENY
```

### Content Type Options
Prevents MIME sniffing:
```
X-Content-Type-Options: nosniff
```

## Configuration Examples

### Basic Setup
```go
server, err := servex.NewServer(
    servex.WithSecurityHeaders(),
)
```

### Strict Setup
```go
server, err := servex.NewServer(
    servex.WithStrictSecurityHeaders(),
)
```

### Custom Setup
```go
server, err := servex.NewServer(
    servex.WithSecurityConfig(servex.SecurityConfig{
        ContentSecurityPolicy: "default-src 'self'",
        XFrameOptions: "SAMEORIGIN",
        // ... more options
    }),
)
```

### Path-Specific Setup
```go
server, err := servex.NewServer(
    servex.WithStrictSecurityHeaders(),
    servex.WithSecurityIncludePaths("/api/secure/*"),
    servex.WithSecurityExcludePaths("/health", "/metrics"),
)
```

## Best Practices

1. **Start with Strict**: Use `WithStrictSecurityHeaders()` as baseline
2. **Custom CSP**: Tailor Content Security Policy to your application
3. **Path Exclusions**: Exclude monitoring endpoints from security headers
4. **HSTS Preload**: Enable for production domains
5. **Regular Testing**: Use security scanners to validate configuration

## Prerequisites

- Go 1.24+
- Servex framework (automatically resolved via go.mod)

## Next Steps

After trying these security examples:
1. Check [Cache Examples](../cache/) for secure caching
2. Explore [Proxy Examples](../proxy-simple/) for secure proxying
3. Try [Quickstart Examples](../quickstart/) for preset configurations
4. Read the [Configuration Guide](../configuration-guide/) for advanced setup 