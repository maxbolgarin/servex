# 01 - Hello World

Welcome to Servex! This is your first step into the world of high-performance web servers in Go.

## What You'll Learn

- How to create a basic Servex server
- How to add simple HTTP endpoints
- How to run and test your server

## The Simplest Possible Server

This example shows the absolute minimum code needed to create a working web server with Servex:

```go
server, err := servex.NewServer()
server.HandleFunc("/", myHandler)
server.Start(":8080", "")
```

That's it! Just 3 lines of code for a complete web server.

## Running This Example

```bash
# Run the server
go run main.go

# Test it with curl
curl http://localhost:8080/
curl http://localhost:8080/health
```

## What's Happening?

1. **`servex.NewServer()`** - Creates a new server with sensible defaults
2. **`server.HandleFunc()`** - Adds an HTTP endpoint handler
3. **`servex.C(w, r)`** - Gets the Servex context for easy responses
4. **`ctx.Response()`** - Sends a JSON response with proper headers
5. **`server.Start()`** - Starts the server on the specified port

## Server Features (Even in This Simple Example!)

Even this basic server includes many features out of the box:
- ✅ **JSON responses** with proper Content-Type headers
- ✅ **Request logging** with timestamps and status codes
- ✅ **Error handling** with appropriate HTTP status codes
- ✅ **Graceful shutdown** on interrupt signals
- ✅ **Health endpoints** for monitoring

## Try These URLs

Once the server is running, try these endpoints:

### Main endpoint
```bash
curl http://localhost:8080/
```
```json
{
  "message": "Hello from Servex! 👋",
  "tutorial": "01-hello-world"
}
```

### Health check
```bash
curl http://localhost:8080/health
```
```json
{
  "status": "healthy", 
  "server": "servex"
}
```

## What's Next?

This is just the beginning! In the next tutorial, you'll learn:
- Different server presets for common use cases
- Multiple endpoints and routing
- Basic configuration options

🎯 **Ready for more?** → Continue to [02-quickstart](../02-quickstart/)

## Common Questions

**Q: Why use Servex instead of plain net/http?**
A: Servex provides production-ready features out of the box: security headers, rate limiting, caching, proxying, authentication, and much more - all with minimal configuration.

**Q: Can I use this for production?**
A: Yes! Even this simple server includes many production-ready features. However, you'll want to add security headers, rate limiting, and other features shown in later tutorials.

**Q: How do I add more endpoints?**
A: Just add more `server.HandleFunc()` calls before `server.Start()`. Check out the next tutorial for examples! 