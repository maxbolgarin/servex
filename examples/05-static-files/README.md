# 05 - Static Files

Learn how to serve static files efficiently with Servex. This tutorial covers file serving, caching, compression, and optimization techniques for web assets.

## What You'll Learn

- How to serve static files from a directory
- Setting up cache headers for performance
- Enabling compression for faster transfers
- Security considerations for static content
- File existence checking and error handling

## Features Demonstrated

- ✅ **Static file serving** from directory
- ✅ **Cache headers** for 24-hour caching
- ✅ **Gzip compression** for smaller transfers
- ✅ **Security headers** for static content
- ✅ **File existence checking** with proper 404 handling
- ✅ **API endpoint** to list available files

## Running This Example

```bash
# Run the server
go run main.go

# The server will create sample files automatically
# Visit the demo page
open http://localhost:8080/
```

## What's Created

The example automatically creates a `./static/` directory with sample files:

- **style.css** - CSS stylesheet with styling
- **app.js** - JavaScript file with interactivity  
- **logo.txt** - Simple text file
- **data.json** - JSON data file

## Testing Static Files

### Basic File Access
```bash
# Access CSS file
curl http://localhost:8080/static/style.css

# Access JavaScript file  
curl http://localhost:8080/static/app.js

# Access text file
curl http://localhost:8080/static/logo.txt

# Access JSON file
curl http://localhost:8080/static/data.json
```

### Check Cache Headers
```bash
# Check caching headers
curl -I http://localhost:8080/static/style.css

# You should see:
# Cache-Control: public, max-age=86400
# ETag: "..."
# Last-Modified: ...
```

### Test Compression
```bash
# Request with compression
curl -H "Accept-Encoding: gzip" -I http://localhost:8080/static/app.js

# You should see:
# Content-Encoding: gzip
```

### List All Files
```bash
# Get list of available files via API
curl http://localhost:8080/api/files
```

## Code Walkthrough

### 1. Server Configuration
```go
server, err := servex.NewServer(
    servex.WithSecurityHeaders(),        // Security for static content
    servex.WithCacheStaticAssets(86400), // Cache for 24 hours
    servex.WithCompression(),            // Enable gzip compression
)
```

### 2. Static File Handler
```go
server.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
    filepath := r.URL.Path[8:] // Remove "/static/" prefix
    fullPath := "./static/" + filepath
    
    // Check if file exists
    if _, err := os.Stat(fullPath); os.IsNotExist(err) {
        http.NotFound(w, r)
        return
    }
    
    // Serve the file with proper headers
    http.ServeFile(w, r, fullPath)
})
```

### 3. File Listing API
```go
server.HandleFunc("/api/files", func(w http.ResponseWriter, r *http.Request) {
    files, err := listStaticFiles()
    ctx.Response(200, map[string]interface{}{
        "files": files,
        "base_url": "http://localhost:8080/static/",
    })
})
```

## Cache Strategy

The example uses a 24-hour cache strategy optimized for static assets:

- **Cache-Control**: `public, max-age=86400` (24 hours)
- **ETag**: Automatic generation for cache validation
- **Last-Modified**: File modification time
- **Compression**: Gzip for text-based files

## Security Features

Static files include security headers:
- **X-Content-Type-Options**: `nosniff` - Prevents MIME sniffing
- **X-Frame-Options**: `DENY` - Prevents embedding in frames
- **X-XSS-Protection**: `1; mode=block` - XSS protection

## Performance Benefits

With this setup, static files are:
- ✅ **Cached for 24 hours** - Reduces server load
- ✅ **Compressed with gzip** - ~70% size reduction for text files
- ✅ **Served with ETags** - Enables 304 Not Modified responses
- ✅ **Secured with headers** - Prevents common attacks

## Production Tips

For production deployments:

1. **Use a CDN** for global distribution
2. **Set longer cache times** for versioned assets
3. **Enable Brotli compression** alongside gzip
4. **Use HTTP/2** for better multiplexing
5. **Implement asset versioning** for cache busting

## Common Use Cases

This pattern is perfect for:
- **Web application assets** (CSS, JS, images)
- **Documentation sites** with static resources
- **API documentation** with embedded assets
- **Single-page applications** (SPAs)

## What's Next?

🎯 **Continue the tutorial:** → [06-rate-limiting](../06-rate-limiting/)

In the next tutorial, you'll learn how to protect your server from abuse with rate limiting. 