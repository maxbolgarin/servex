package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/maxbolgarin/servex"
)

// Main function to demonstrate all cache examples
func cacheMain() {
	// Run any of these examples by uncommenting the server.Start() lines above:

	// 1. Basic example - simplest cache setup
	basicCacheExample()

	// 2. Intermediate example - path-based caching
	intermediateCacheExample()

	// 3. Advanced example - dynamic cache headers
	advancedCacheExample()

	// 4. Complex example - comprehensive configuration
	complexCacheExample()

	// 5. Strategy examples - different cache presets
	cacheStrategyExamples()

	// For demonstration, let's run the complex example
	log.Println("Starting complex cache example server on :8080")
	log.Println("Visit http://localhost:8080 for interactive demo")

	server, err := servex.New(
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

	server.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.NewContext(w, r)
		ctx.SetHeader("Content-Type", "text/html")
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
    <p>Uncomment the server.Start() lines in each example to run them individually.</p>
</body>
</html>`)
	}, "GET")

	server.HandleFunc("/api/v1/public/version", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.NewContext(w, r)
		ctx.Response(http.StatusOK, map[string]interface{}{
			"version": "1.0.0",
			"example": "This endpoint demonstrates cache headers",
		})
	}, "GET")

	if err := server.Start(":8080", ""); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 1: Basic Cache Control (Easiest)
// This example shows the simplest way to add cache control to your server
func basicCacheExample() {
	// Create a server with basic public caching for 1 hour
	server, err := servex.New(
		servex.WithCachePublic(3600), // Cache for 1 hour (3600 seconds)
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	// Simple API endpoint that will be cached
	server.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.NewContext(w, r)
		ctx.Response(http.StatusOK, map[string]interface{}{
			"status":    "ok",
			"timestamp": time.Now().Unix(),
			"version":   "1.0.0",
		})
	}, "GET")

	// This will add "Cache-Control: public, max-age=3600" to all responses
	// Test with: curl -I http://localhost:8080/api/status

	// Uncomment to run this example:
	// log.Println("Basic cache example server starting on :8080")
	// server.Start(":8080", "")
}

// Example 2: Cache with Path Filtering (Intermediate)
// This example shows how to apply caching only to specific paths
func intermediateCacheExample() {
	server, err := servex.New(
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
	server.HandleFunc("/api/public/data", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.NewContext(w, r)
		ctx.Response(http.StatusOK, map[string]interface{}{
			"data":    []string{"item1", "item2", "item3"},
			"cached":  true,
			"expires": time.Now().Add(30 * time.Minute).Unix(),
		})
	}, "GET")

	// This endpoint will NOT be cached (matches /api/private/*)
	server.HandleFunc("/api/private/user", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.NewContext(w, r)
		ctx.Response(http.StatusOK, map[string]interface{}{
			"user":    "john.doe",
			"session": "session-" + strconv.FormatInt(time.Now().Unix(), 10),
			"cached":  false,
		})
	}, "GET")

	// This static file will be cached (matches /static/*)
	server.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.NewContext(w, r)
		ctx.SetHeader("Content-Type", "application/javascript")
		ctx.Response(http.StatusOK, `console.log("This file is cached");`)
	}, "GET")

	// Test with:
	// curl -I http://localhost:8080/api/public/data    (will have cache headers)
	// curl -I http://localhost:8080/api/private/user   (will NOT have cache headers)

	// Uncomment to run this example:
	// log.Println("Intermediate cache example server starting on :8080")
	// server.Start(":8080", "")
}

// Example 3: Dynamic Cache Control (Advanced)
// This example shows how to use dynamic ETag and LastModified functions
func advancedCacheExample() {
	// Simulate a data store with versioning
	userData := map[string]interface{}{
		"id":           1,
		"name":         "John Doe",
		"email":        "john@example.com",
		"lastModified": time.Now().Add(-2 * time.Hour), // Modified 2 hours ago
		"version":      "v1.2.3",
	}

	server, err := servex.New(
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
	server.HandleFunc("/api/user/profile", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.NewContext(w, r)
		ctx.Response(http.StatusOK, userData)
	}, "GET")

	// Endpoint to update user data (simulates data change)
	server.HandleFunc("/api/user/profile", func(w http.ResponseWriter, r *http.Request) {
		// Simulate updating user data
		userData["name"] = "John Doe Updated"
		userData["lastModified"] = time.Now()
		userData["version"] = "v1.2.4" // Increment version

		ctx := servex.NewContext(w, r)
		ctx.Response(http.StatusOK, map[string]string{
			"message": "Profile updated successfully",
		})
	}, "PUT")

	// System info that changes hourly
	server.HandleFunc("/api/system/info", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.NewContext(w, r)
		ctx.Response(http.StatusOK, map[string]interface{}{
			"system":    "servex-cache-demo",
			"uptime":    time.Since(time.Now().Truncate(time.Hour)).String(),
			"hour":      time.Now().Hour(),
			"timestamp": time.Now().Unix(),
		})
	}, "GET")

	// Dynamic functions provide:
	// - Automatic ETag generation based on content version
	// - Automatic LastModified headers based on actual modification time
	// - Conditional request handling (304 Not Modified responses)

	// Test conditional requests:
	// curl -H 'If-None-Match: "user-profile-v1.2.3"' http://localhost:8080/api/user/profile
	// curl -H 'If-Modified-Since: <last-modified-date>' http://localhost:8080/api/user/profile

	// Uncomment to run this example:
	// log.Println("Advanced cache example server starting on :8080")
	// server.Start(":8080", "")
}

// Example 4: Comprehensive Cache Configuration (Complex)
// This example demonstrates all cache control features together
func complexCacheExample() {
	server, err := servex.New(
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
				switch {
				case r.URL.Path == "/api/v1/public/version":
					return `"api-version-1.0.0"`
				case r.URL.Path == "/api/v1/public/config":
					// ETag changes based on time of day
					hour := time.Now().Hour()
					return fmt.Sprintf(`"config-%d"`, hour/6) // Changes 4 times per day
				default:
					return ""
				}
			},

			// Dynamic LastModified function
			LastModifiedFunc: func(r *http.Request) time.Time {
				switch {
				case r.URL.Path == "/api/v1/public/version":
					// Static build time
					return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
				case r.URL.Path == "/api/v1/public/config":
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
	// API version endpoint (cached with static ETag)
	server.HandleFunc("/api/v1/public/version", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.NewContext(w, r)
		ctx.Response(http.StatusOK, map[string]interface{}{
			"version":     "1.0.0",
			"buildDate":   "2024-01-01",
			"environment": "production",
			"features":    []string{"cache", "auth", "rate-limit"},
		})
	}, "GET")

	// Configuration endpoint (cached with time-based ETag)
	server.HandleFunc("/api/v1/public/config", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.NewContext(w, r)
		ctx.Response(http.StatusOK, map[string]interface{}{
			"maxUploadSize": "10MB",
			"allowedTypes":  []string{"image/jpeg", "image/png", "application/pdf"},
			"rateLimit":     100,
			"timeSlot":      time.Now().Hour() / 6, // Changes 4 times per day
		})
	}, "GET")

	// Private endpoint (excluded from caching)
	server.HandleFunc("/api/v1/private/user-session", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.NewContext(w, r)
		ctx.Response(http.StatusOK, map[string]interface{}{
			"sessionId":   "sess-" + strconv.FormatInt(time.Now().Unix(), 10),
			"userId":      12345,
			"permissions": []string{"read", "write"},
			"expiresAt":   time.Now().Add(time.Hour).Unix(),
		})
	}, "GET")

	// Static asset (cached)
	server.HandleFunc("/static/style.css", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.NewContext(w, r)
		ctx.SetHeader("Content-Type", "text/css")
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
	}, "GET")

	// Admin endpoint (excluded from caching)
	server.HandleFunc("/admin/stats", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.NewContext(w, r)
		ctx.Response(http.StatusOK, map[string]interface{}{
			"activeUsers":   42,
			"requestsToday": 15420,
			"cacheHitRatio": 0.87,
			"generatedAt":   time.Now().Unix(),
		})
	}, "GET")

	// Root endpoint with documentation
	server.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.NewContext(w, r)
		ctx.SetHeader("Content-Type", "text/html")
		ctx.Response(http.StatusOK, `
<!DOCTYPE html>
<html>
<head>
    <title>Servex Cache Control - Complex Example</title>
    <link rel="stylesheet" href="/static/style.css">
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
	}, "GET")

	// This complex example showcases:
	// - Comprehensive CacheConfig usage
	// - Multiple path patterns for inclusion/exclusion
	// - Dynamic ETag generation with different strategies
	// - Dynamic LastModified headers with time-based updates
	// - Mixed content types (API, static files, admin endpoints)
	// - Conditional request handling for optimal performance

	// Uncomment to run this example:
	// log.Println("Complex cache example server starting on :8080")
	// server.Start(":8080", "")
}

// Example 5: Cache Strategy Presets (Bonus)
// This example shows different cache strategies using servex presets
func cacheStrategyExamples() {
	// Strategy 1: No caching for sensitive data
	sensitiveServer, err := servex.New(
		servex.WithCacheNoStore(), // Adds: no-store, no-cache, must-revalidate
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Strategy 2: Force revalidation for dynamic content
	dynamicServer, err := servex.New(
		servex.WithCacheNoCache(), // Adds: no-cache, must-revalidate
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Strategy 3: Private caching for user-specific content
	userServer, err := servex.New(
		servex.WithCachePrivate(900), // Adds: private, max-age=900 (15 minutes)
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Strategy 4: Long-term caching for static assets
	staticServer, err := servex.New(
		servex.WithCacheStaticAssets(31536000), // Adds: public, max-age=31536000, immutable (1 year)
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Strategy 5: API caching with revalidation
	apiServer, err := servex.New(
		servex.WithCacheAPI(300), // Adds: public, max-age=300, must-revalidate (5 minutes)
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Strategy 6: Time-based caching with specific expiration
	timedServer, err := servex.New(
		servex.WithCacheExpiresTime(time.Now().Add(time.Hour)),       // Expires in 1 hour
		servex.WithCacheLastModifiedTime(time.Now().Add(-time.Hour)), // Modified 1 hour ago
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Each server would handle specific use cases:
	// - sensitiveServer: Banking, medical records, personal data
	// - dynamicServer: Live feeds, real-time data, user notifications
	// - userServer: User dashboards, personalized content
	// - staticServer: Images, CSS, JS, fonts, static assets
	// - apiServer: Public APIs, configuration endpoints
	// - timedServer: Content with specific expiration times

	_ = sensitiveServer
	_ = dynamicServer
	_ = userServer
	_ = staticServer
	_ = apiServer
	_ = timedServer
}
