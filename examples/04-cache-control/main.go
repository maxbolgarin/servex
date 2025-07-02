package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

func main() {
	fmt.Println("=== Servex Cache Control Examples ===")
	fmt.Println("Choose an example to run:")
	fmt.Println("1. Basic Cache Example")
	fmt.Println("2. Intermediate Cache Example (Path-based)")
	fmt.Println("3. Advanced Cache Example (Dynamic ETags)")
	fmt.Println("4. Complex Cache Example (Comprehensive)")
	fmt.Println("5. Interactive Demo (Default)")
	fmt.Println("")

	// For demo purposes, we'll run the interactive demo
	// Users can modify main() to run different examples
	fmt.Println("Running: Interactive Cache Demo")
	fmt.Println("Edit main() to run specific examples")
	interactiveCacheDemo()
}

// Interactive demo that showcases all cache features
func interactiveCacheDemo() {
	log.Println("Starting interactive cache demo server on :8080")
	log.Println("Visit http://localhost:8080 for interactive demo")

	server, err := servex.NewServer(
		servex.WithCachePublic(1800),
		servex.WithCacheIncludePaths("/api/v1/public/*", "/static/*"),
		servex.WithCacheExcludePaths("/api/v1/private/*", "/admin/*"),
		servex.WithCacheVary("Accept-Encoding"),
		servex.WithCacheETagFunc(func(r *http.Request) string {
			if r.URL.Path == "/api/v1/public/version" {
				return `"api-version-1.0.0"`
			}
			return ""
		}),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	server.Get("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, `
<!DOCTYPE html>
<html>
<head><title>Cache Examples</title></head>
<body>
    <h1>Servex Cache Control Examples</h1>
    <p>This demonstrates cache control from basic to complex configurations.</p>
    <p>Check the source code for 5 different examples:</p>
    <ol>
        <li><strong>Basic:</strong> Simple public caching</li>
        <li><strong>Intermediate:</strong> Path-based cache filtering</li>
        <li><strong>Advanced:</strong> Dynamic ETag and LastModified</li>
        <li><strong>Complex:</strong> Comprehensive configuration</li>
        <li><strong>Strategies:</strong> Different cache preset examples</li>
    </ol>
    <h2>Test Endpoints:</h2>
    <ul>
        <li><a href="/api/v1/public/version">Cached API endpoint</a></li>
        <li><a href="/api/v1/private/user">Non-cached private endpoint</a></li>
        <li><a href="/static/style.css">Cached static file</a></li>
    </ul>
    <p>Check cache headers with: <code>curl -I [url]</code></p>
</body>
</html>`)
	})

	server.Get("/api/v1/public/version", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, map[string]any{
			"version":   "1.0.0",
			"example":   "This endpoint demonstrates cache headers",
			"timestamp": time.Now().Unix(),
		})
	})

	server.Get("/api/v1/private/user", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, map[string]any{
			"user":    "private-user",
			"session": fmt.Sprintf("sess-%d", time.Now().Unix()),
			"cached":  false,
		})
	})

	server.Get("/static/style.css", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, "/* This CSS file is cached */\nbody { font-family: Arial; }")
	})

	if err := server.StartWithWaitSignalsHTTP(context.Background(), ":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 1: Basic Cache Control (Easiest)
// This example shows the simplest way to add cache control to your server
func basicCacheExample() {
	// Create a server with basic public caching for 1 hour
	server, err := servex.NewServer(
		servex.WithCachePublic(3600), // Cache for 1 hour (3600 seconds)
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	// Simple API endpoint that will be cached
	server.Get("/api/status", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, map[string]any{
			"status":    "ok",
			"timestamp": time.Now().Unix(),
			"version":   "1.0.0",
		})
	})

	// This will add "Cache-Control: public, max-age=3600" to all responses
	// Test with: curl -I http://localhost:8080/api/status

	log.Println("Basic cache example server starting on :8080")
	fmt.Println("Test with: curl -I http://localhost:8080/api/status")
	server.StartWithWaitSignalsHTTP(context.Background(), ":8080")
}

// Example 2: Cache with Path Filtering (Intermediate)
// This example shows how to apply caching only to specific paths
func intermediateCacheExample() {
	server, err := servex.NewServer(
		// Cache public content for 30 minutes
		servex.WithCachePublic(1800),

		// Only apply caching to specific paths
		servex.WithCacheIncludePaths("/api/public/*", "/static/*"),

		// Exclude sensitive paths from caching
		servex.WithCacheExcludePaths("/api/private/*", "/admin/*"),

		// Add Vary header for better cache behavior
		servex.WithCacheVary("Accept-Encoding"),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	// This endpoint will be cached (matches /api/public/*)
	server.Get("/api/public/data", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, map[string]any{
			"data":    []string{"item1", "item2", "item3"},
			"cached":  true,
			"expires": time.Now().Add(30 * time.Minute).Unix(),
		})
	})

	// This endpoint will NOT be cached (matches /api/private/*)
	server.Get("/api/private/user", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, map[string]any{
			"user":    "john.doe",
			"session": "session-" + strconv.FormatInt(time.Now().Unix(), 10),
			"cached":  false,
		})
	})

	// This static file will be cached (matches /static/*)
	server.Get("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, `console.log("This file is cached");`)
	})

	// Test with:
	// curl -I http://localhost:8080/api/public/data    (will have cache headers)
	// curl -I http://localhost:8080/api/private/user   (will NOT have cache headers)

	log.Println("Intermediate cache example server starting on :8080")
	fmt.Println("Test cached: curl -I http://localhost:8080/api/public/data")
	fmt.Println("Test non-cached: curl -I http://localhost:8080/api/private/user")
	err = server.StartWithWaitSignalsHTTP(context.Background(), ":8080")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 3: Dynamic Cache Control (Advanced)
// This example shows how to use dynamic ETag and LastModified functions
func advancedCacheExample() {
	// Simulate a data store with versioning
	userData := map[string]any{
		"id":           1,
		"name":         "John Doe",
		"email":        "john@example.com",
		"lastModified": time.Now().Add(-2 * time.Hour), // Modified 2 hours ago
		"version":      "v1.2.3",
	}

	server, err := servex.NewServer(
		// Base cache configuration
		servex.WithCachePublic(1800), // 30 minutes

		// Dynamic ETag based on request path and data version
		servex.WithCacheETagFunc(func(r *http.Request) string {
			switch r.URL.Path {
			case "/api/user/profile":
				version := userData["version"].(string)
				return fmt.Sprintf(`"user-profile-%s"`, version)
			case "/api/system/info":
				// ETag based on current hour (changes hourly)
				return fmt.Sprintf(`"system-info-%d"`, time.Now().Hour())
			default:
				return ""
			}
		}),

		// Dynamic LastModified based on actual data modification time
		servex.WithCacheLastModifiedFunc(func(r *http.Request) time.Time {
			switch r.URL.Path {
			case "/api/user/profile":
				return userData["lastModified"].(time.Time)
			case "/api/system/info":
				// Updates every hour
				now := time.Now()
				return time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
			default:
				return time.Time{}
			}
		}),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	// User profile endpoint with dynamic cache headers
	server.Get("/api/user/profile", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, userData)
	})

	// Endpoint to update user data (simulates data change)
	server.Put("/api/user/profile", func(w http.ResponseWriter, r *http.Request) {
		// Simulate updating user data
		userData["name"] = "John Doe Updated"
		userData["lastModified"] = time.Now()
		userData["version"] = "v1.2.4" // Increment version

		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, map[string]string{
			"message": "Profile updated successfully",
		})
	})

	// System info that changes hourly
	server.Get("/api/system/info", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, map[string]any{
			"system":    "servex-cache-demo",
			"uptime":    time.Since(time.Now().Truncate(time.Hour)).String(),
			"hour":      time.Now().Hour(),
			"timestamp": time.Now().Unix(),
		})
	})

	// Dynamic functions provide:
	// - Automatic ETag generation based on content version
	// - Automatic LastModified headers based on actual modification time
	// - Conditional request handling (304 Not Modified responses)

	// Test conditional requests:
	// curl -H 'If-None-Match: "user-profile-v1.2.3"' http://localhost:8080/api/user/profile
	// curl -H 'If-Modified-Since: <last-modified-date>' http://localhost:8080/api/user/profile

	log.Println("Advanced cache example server starting on :8080")
	fmt.Println("Test conditional: curl -H 'If-None-Match: \"user-profile-v1.2.3\"' http://localhost:8080/api/user/profile")
	err = server.StartWithWaitSignalsHTTP(context.Background(), ":8080")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 4: Comprehensive Cache Configuration (Complex)
// This example demonstrates all cache control features together
func complexCacheExample() {
	server, err := servex.NewServer(
		// Comprehensive cache configuration using the CacheConfig struct
		servex.WithCacheConfig(servex.CacheConfig{
			Enabled:      true,
			CacheControl: "public, max-age=1800", // 30 minutes default
			Expires:      time.Now().Add(30 * time.Minute).Format(http.TimeFormat),
			Vary:         "Accept-Encoding, User-Agent",

			// Path-based configuration
			IncludePaths: []string{"/api/v1/public/*", "/static/*", "/assets/*"},
			ExcludePaths: []string{"/api/v1/private/*", "/admin/*", "/auth/*"},

			// Dynamic ETag function for request-specific ETags
			ETagFunc: func(r *http.Request) string {
				switch r.URL.Path {
				case "/api/v1/public/version":
					return `"api-version-1.0.0"`
				case "/api/v1/public/config":
					// ETag changes based on time of day
					hour := time.Now().Hour()
					return fmt.Sprintf(`"config-%d"`, hour/6) // Changes 4 times per day
				default:
					return ""
				}
			},

			// Dynamic LastModified function
			LastModifiedFunc: func(r *http.Request) time.Time {
				switch r.URL.Path {
				case "/api/v1/public/version":
					// Static build time
					return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
				case "/api/v1/public/config":
					// Updates every 6 hours
					now := time.Now()
					return time.Date(now.Year(), now.Month(), now.Day(), (now.Hour()/6)*6, 0, 0, 0, now.Location())
				default:
					return time.Time{}
				}
			},
		}),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Root endpoint with documentation
	server.Get("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, `
<!DOCTYPE html>
<html>
<head>
    <title>Servex Cache Control - Complex Example</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .cache-demo { color: #333; background: #f5f5f5; padding: 10px; }
        pre { background: #000; color: #0f0; padding: 10px; }
    </style>
</head>
<body>
    <div class="cache-demo">
        <h1>Servex Cache Control - Complex Example</h1>
        
        <h2>Cached Endpoints (30 minutes, with dynamic headers)</h2>
        <ul>
            <li><a href="/api/v1/public/version">/api/v1/public/version</a> - Static version with fixed ETag</li>
            <li><a href="/api/v1/public/config">/api/v1/public/config</a> - Config that changes 4x daily</li>
            <li><a href="/static/style.css">/static/style.css</a> - CSS file with caching</li>
        </ul>
        
        <h2>Non-Cached Endpoints (excluded paths)</h2>
        <ul>
            <li><a href="/api/v1/private/user-session">/api/v1/private/user-session</a> - Private user data</li>
            <li><a href="/admin/stats">/admin/stats</a> - Admin statistics</li>
        </ul>
        
        <h2>Cache Features Demonstrated</h2>
        <ul>
            <li>✓ Path-based inclusion/exclusion patterns</li>
            <li>✓ Dynamic ETag generation based on content</li>
            <li>✓ Dynamic Last-Modified headers</li>
            <li>✓ Conditional request handling (304 responses)</li>
            <li>✓ Vary headers for content negotiation</li>
            <li>✓ Expires headers with proper HTTP formatting</li>
        </ul>
        
        <h2>Testing Commands</h2>
        <pre>
# Check cache headers
curl -I http://localhost:8080/api/v1/public/version

# Test conditional request
curl -H 'If-None-Match: "api-version-1.0.0"' http://localhost:8080/api/v1/public/version

# Compare cached vs non-cached
curl -I http://localhost:8080/api/v1/public/config
curl -I http://localhost:8080/api/v1/private/user-session
        </pre>
    </div>
</body>
</html>`)
	})

	// API version endpoint (cached with static ETag)
	server.Get("/api/v1/public/version", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, map[string]any{
			"version":     "1.0.0",
			"buildDate":   "2024-01-01",
			"environment": "production",
			"features":    []string{"cache", "auth", "rate-limit"},
		})
	})

	// Configuration endpoint (cached with time-based ETag)
	server.Get("/api/v1/public/config", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, map[string]any{
			"maxUploadSize": "10MB",
			"allowedTypes":  []string{"image/jpeg", "image/png", "application/pdf"},
			"rateLimit":     100,
			"timeSlot":      time.Now().Hour() / 6, // Changes 4 times per day
		})
	})

	// Private endpoint (excluded from caching)
	server.Get("/api/v1/private/user-session", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, map[string]any{
			"sessionId":   "sess-" + strconv.FormatInt(time.Now().Unix(), 10),
			"userId":      12345,
			"permissions": []string{"read", "write"},
			"expiresAt":   time.Now().Add(time.Hour).Unix(),
		})
	})

	// Static asset (cached)
	server.Get("/static/style.css", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, `
body { 
    font-family: Arial, sans-serif; 
    margin: 0; 
    padding: 20px; 
}
.cache-demo { 
    color: #333; 
    background: #f5f5f5; 
    padding: 10px; 
}`)
	})

	// Admin endpoint (excluded from caching)
	server.Get("/admin/stats", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, map[string]any{
			"activeUsers":   42,
			"requestsToday": 15420,
			"cacheHitRatio": 0.87,
			"generatedAt":   time.Now().Unix(),
		})
	})

	log.Println("Complex cache example server starting on :8080")
	fmt.Println("Visit http://localhost:8080 for interactive demo")
	err = server.StartWithWaitSignalsHTTP(context.Background(), ":8080")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 5: Cache Strategy Presets (Bonus)
// This example shows different cache strategies using servex presets
func cacheStrategyExamples() {
	fmt.Println("Cache Strategy Examples:")
	fmt.Println("This example demonstrates different cache presets.")
	fmt.Println("Check the source code for implementations:")
	fmt.Println("- WithCacheNoStore() - No caching for sensitive data")
	fmt.Println("- WithCacheNoCache() - Force revalidation")
	fmt.Println("- WithCachePrivate(900) - Private caching")
	fmt.Println("- WithCacheStaticAssets(31536000) - Long-term caching")
	fmt.Println("- WithCacheAPI(300) - API caching with revalidation")

	// For demo, create a simple server with no-cache strategy
	server, err := servex.NewServer(
		servex.WithCacheNoCache(), // Adds: no-cache, must-revalidate
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	server.Get("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(http.StatusOK, map[string]any{
			"message": "This response has no-cache headers",
			"time":    time.Now().Format(time.RFC3339),
		})
	})

	log.Println("Cache strategy example (no-cache) server starting on :8080")
	fmt.Println("Test with: curl -I http://localhost:8080/")
	err = server.StartWithWaitSignalsHTTP(context.Background(), ":8080")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
