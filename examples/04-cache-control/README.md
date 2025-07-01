# 04 - Cache Control

Learn how to optimize your web application performance with HTTP caching. This tutorial covers ETags, cache headers, and conditional requests to make your server lightning fast.

## Examples Included

1. **Basic Cache Example** - Simple public caching setup
2. **Intermediate Cache Example** - Path-based cache filtering
3. **Advanced Cache Example** - Dynamic ETags and LastModified headers
4. **Complex Cache Example** - Comprehensive configuration with all features
5. **Interactive Demo** - Web-based demonstration of cache features

## Running the Examples

### Default (Interactive Demo)
```bash
go run main.go
```

This runs an interactive web demo on port 8080. Visit http://localhost:8080 for a complete demonstration of cache features.

### Running Specific Examples

Edit the `main()` function in `main.go` to call different example functions:

```go
func main() {
    // Change this line to run different examples:
    interactiveCacheDemo()        // Default - web demo
    // basicCacheExample()        // Basic caching
    // intermediateCacheExample() // Path-based caching
    // advancedCacheExample()     // Dynamic ETags
    // complexCacheExample()      // Full configuration
    // cacheStrategyExamples()    // Cache strategies
}
```

## Example Details

### Basic Cache Example
- **Features**: Simple public caching for 1 hour
- **Configuration**: `servex.WithCachePublic(3600)`
- **Test**: `curl -I http://localhost:8080/api/status`
- **Headers**: `Cache-Control: public, max-age=3600`

### Intermediate Cache Example
- **Features**: Path-based cache inclusion/exclusion
- **Cached paths**: `/api/public/*`, `/static/*`
- **Excluded paths**: `/api/private/*`, `/admin/*`
- **Test cached**: `curl -I http://localhost:8080/api/public/data`
- **Test non-cached**: `curl -I http://localhost:8080/api/private/user`

### Advanced Cache Example
- **Features**: Dynamic ETags and Last-Modified headers
- **Dynamic ETags**: Based on content version and time
- **Conditional requests**: Supports 304 Not Modified responses
- **Test**: `curl -H 'If-None-Match: "user-profile-v1.2.3"' http://localhost:8080/api/user/profile`

### Complex Cache Example
- **Features**: All cache features combined
- **Configuration**: Comprehensive `CacheConfig` struct
- **Multiple strategies**: Different ETags for different endpoints
- **Interactive**: Web interface showing all features
- **Test URLs**: 
  - http://localhost:8080/api/v1/public/version (cached)
  - http://localhost:8080/api/v1/private/user-session (not cached)

### Cache Strategy Examples
- **WithCacheNoStore()**: No caching for sensitive data
- **WithCacheNoCache()**: Force revalidation for dynamic content  
- **WithCachePrivate(900)**: Private caching for user-specific content
- **WithCacheStaticAssets(31536000)**: Long-term caching for static assets
- **WithCacheAPI(300)**: API caching with revalidation

## Testing Cache Headers

### Basic Testing
```bash
# Check cache headers
curl -I http://localhost:8080/api/status

# Test different endpoints
curl -I http://localhost:8080/api/public/data     # Should have cache headers
curl -I http://localhost:8080/api/private/user    # Should NOT have cache headers

# Test static files
curl -I http://localhost:8080/static/app.js       # Should have cache headers
```

### Conditional Requests Testing
```bash
# Test ETag-based conditional requests
curl -H 'If-None-Match: "api-version-1.0.0"' http://localhost:8080/api/v1/public/version

# Test Last-Modified conditional requests
curl -H 'If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT' http://localhost:8080/api/user/profile

# Should return 304 Not Modified if content hasn't changed
```

### Cache Validation
```bash
# Check specific cache headers
curl -I http://localhost:8080/api/v1/public/version | grep -i cache
curl -I http://localhost:8080/api/v1/public/version | grep -i etag
curl -I http://localhost:8080/api/v1/public/version | grep -i last-modified
curl -I http://localhost:8080/api/v1/public/version | grep -i expires
curl -I http://localhost:8080/api/v1/public/version | grep -i vary
```

## Cache Configuration Options

### Basic Options
- `WithCachePublic(seconds)` - Public caching for specified duration
- `WithCachePrivate(seconds)` - Private caching for specified duration
- `WithCacheNoCache()` - Force revalidation
- `WithCacheNoStore()` - No caching at all

### Path-based Configuration
- `WithCacheIncludePaths(patterns...)` - Only cache matching paths
- `WithCacheExcludePaths(patterns...)` - Exclude paths from caching
- Supports glob patterns: `/api/public/*`, `/static/*`

### Dynamic Headers
- `WithCacheETagFunc(func)` - Generate dynamic ETags
- `WithCacheLastModifiedFunc(func)` - Generate dynamic Last-Modified headers
- `WithCacheVary(headers)` - Add Vary header for content negotiation

### Advanced Configuration
- `WithCacheConfig(config)` - Comprehensive configuration struct
- `WithCacheExpiresTime(time)` - Set specific expiration time
- `WithCacheStaticAssets(seconds)` - Optimized for static files

## Cache Headers Explained

### Cache-Control
- `public` - Can be cached by any cache
- `private` - Can only be cached by private caches (browsers)
- `no-cache` - Must revalidate with server before using
- `no-store` - Must not be cached anywhere
- `max-age=3600` - Cache for 3600 seconds (1 hour)
- `must-revalidate` - Must check with server when cache expires

### ETag
- Unique identifier for content version
- Used for conditional requests (If-None-Match)
- Returns 304 Not Modified if content unchanged

### Last-Modified
- Timestamp when content was last modified
- Used for conditional requests (If-Modified-Since)
- Returns 304 Not Modified if content unchanged

### Expires
- Absolute time when cache expires
- HTTP date format: `Wed, 21 Oct 2015 07:28:00 GMT`

### Vary
- Indicates which request headers affect caching
- Common values: `Accept-Encoding`, `User-Agent`, `Accept-Language`

## Best Practices

1. **API Endpoints**: Use short cache times (5-30 minutes) with revalidation
2. **Static Assets**: Use long cache times (1 year) with versioning
3. **Dynamic Content**: Use ETags and Last-Modified for efficient caching
4. **Sensitive Data**: Use `no-store` or `private` caching
5. **Path Patterns**: Be specific about what should/shouldn't be cached

## Prerequisites

- Go 1.24+
- Servex framework (automatically resolved via go.mod)

## Next Steps

After trying these cache examples:
1. Explore [Security Examples](../security/) for secure caching
2. Check [Static Examples](../static/) for static file caching
3. Try [Proxy Examples](../proxy-simple/) for proxy caching
4. Read the [Configuration Guide](../configuration-guide/) for advanced setup 