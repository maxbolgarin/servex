package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex"
)

// locationRateLimitExample demonstrates how to use location-based rate limiting
// with different rate limits for different URL paths.
func main() {
	// Set up different rate limit configurations for different locations
	locationConfigs := []servex.LocationRateLimitConfig{
		{
			// Strict rate limiting for authentication endpoints
			PathPatterns: []string{"/auth/login", "/auth/register"},
			Config: servex.RateLimitConfig{
				Enabled:             true,
				RequestsPerInterval: 5, // Only 5 attempts per minute
				Interval:            time.Minute,
				BurstSize:           2, // Allow up to 2 immediate requests
				StatusCode:          http.StatusTooManyRequests,
				Message:             "Too many login attempts. Please try again later.",
			},
		},
		{
			// Moderate rate limiting for API endpoints
			PathPatterns: []string{"/api/*"},
			Config: servex.RateLimitConfig{
				Enabled:             true,
				RequestsPerInterval: 100, // 100 requests per minute
				Interval:            time.Minute,
				BurstSize:           20, // Allow burst of 20 requests
				StatusCode:          http.StatusTooManyRequests,
				Message:             "API rate limit exceeded. Please slow down your requests.",
			},
		},
		{
			// Very strict rate limiting for file upload endpoints
			PathPatterns: []string{"/upload/*", "/files/upload"},
			Config: servex.RateLimitConfig{
				Enabled:             true,
				RequestsPerInterval: 10, // Only 10 uploads per minute
				Interval:            time.Minute,
				BurstSize:           3, // Allow 3 immediate uploads
				StatusCode:          http.StatusTooManyRequests,
				Message:             "Upload rate limit exceeded. Please wait before uploading more files.",
			},
		},
		{
			// Relaxed rate limiting for admin endpoints (trusted users)
			PathPatterns: []string{"/admin/*"},
			Config: servex.RateLimitConfig{
				Enabled:             true,
				RequestsPerInterval: 500, // 500 requests per minute
				Interval:            time.Minute,
				BurstSize:           50, // High burst allowance
				StatusCode:          http.StatusTooManyRequests,
				Message:             "Admin rate limit exceeded.",
				// You could set a custom KeyFunc here to use user ID instead of IP
				// KeyFunc: func(r *http.Request) string { return getUserID(r) },
			},
		},
	}

	// Create a server with location-based rate limiting
	// Note: We manually register the middleware instead of using presets
	server, err := servex.NewServer(
		servex.WithHealthEndpoint(),
		servex.WithSendErrorToClient(), // For better error visibility in examples
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Register the location-based rate limiting middleware
	stopRateLimit := servex.RegisterLocationBasedRateLimitMiddleware(server.Router(), locationConfigs)
	defer func() {
		if stopRateLimit != nil {
			stopRateLimit() // Clean up when the function exits
		}
	}()

	// Define example routes to test different rate limits
	server.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":   "Login endpoint - limited to 5 requests per minute",
			"endpoint":  "/auth/login",
			"rateLimit": "5 req/min, burst: 2",
		})
	})

	server.HandleFunc("/auth/register", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":   "Register endpoint - limited to 5 requests per minute",
			"endpoint":  "/auth/register",
			"rateLimit": "5 req/min, burst: 2",
		})
	})

	server.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":   "API endpoint - limited to 100 requests per minute",
			"endpoint":  "/api/users",
			"rateLimit": "100 req/min, burst: 20",
			"users":     []string{"alice", "bob", "charlie"},
		})
	})

	server.HandleFunc("/api/posts", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":   "API endpoint - limited to 100 requests per minute",
			"endpoint":  "/api/posts",
			"rateLimit": "100 req/min, burst: 20",
			"posts":     []string{"Post 1", "Post 2", "Post 3"},
		})
	})

	server.HandleFunc("/upload/image", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":   "Upload endpoint - limited to 10 requests per minute",
			"endpoint":  "/upload/image",
			"rateLimit": "10 req/min, burst: 3",
		})
	})

	server.HandleFunc("/files/upload", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":   "File upload endpoint - limited to 10 requests per minute",
			"endpoint":  "/files/upload",
			"rateLimit": "10 req/min, burst: 3",
		})
	})

	server.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":   "Admin endpoint - limited to 500 requests per minute",
			"endpoint":  "/admin/users",
			"rateLimit": "500 req/min, burst: 50",
		})
	})

	server.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":   "Public endpoint - no rate limiting applied",
			"endpoint":  "/public",
			"rateLimit": "none",
		})
	})

	// Main information endpoint
	server.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"title":       "Location-based Rate Limiting Example",
			"description": "Try these endpoints to see different rate limits in action",
			"endpoints": map[string]interface{}{
				"authentication": map[string]interface{}{
					"rateLimit": "5 req/min, burst: 2",
					"paths":     []string{"/auth/login", "/auth/register"},
				},
				"api": map[string]interface{}{
					"rateLimit": "100 req/min, burst: 20",
					"paths":     []string{"/api/users", "/api/posts"},
				},
				"uploads": map[string]interface{}{
					"rateLimit": "10 req/min, burst: 3",
					"paths":     []string{"/upload/image", "/files/upload"},
				},
				"admin": map[string]interface{}{
					"rateLimit": "500 req/min, burst: 50",
					"paths":     []string{"/admin/users"},
				},
				"public": map[string]interface{}{
					"rateLimit": "none",
					"paths":     []string{"/public"},
				},
			},
			"instructions": "Make multiple rapid requests to different endpoints to see rate limiting in action!",
		})
	})

	fmt.Println("Starting server with location-based rate limiting...")
	fmt.Println("Server running on :8080")
	fmt.Println("Try making multiple requests to different endpoints to see rate limiting in action!")

	// Start the server
	// Uncomment to run: server.Start(":8080", "")
}

// Example of how you might implement a custom key function for user-based rate limiting
// func getUserID(r *http.Request) string {
//     // In a real application, you would extract the user ID from:
//     // - JWT token
//     // - Session
//     // - API key
//     // - Database lookup
//
//     // For this example, we'll just use IP-based limiting
//     return r.RemoteAddr
// }

// Alternative example: Using global rate limiting with location exclusions
func alternativeLocationRateLimitExample() {
	// You can also combine global rate limiting with location-specific exclusions
	server, err := servex.NewServer(
		// Global rate limiting for all endpoints
		servex.WithRPM(60), // 60 requests per minute globally
		// Exclude certain paths from global rate limiting
		servex.WithRateLimitExcludePaths("/health", "/metrics", "/public/*"),
		servex.WithHealthEndpoint(),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Then add stricter location-based rate limiting on top
	locationConfigs := []servex.LocationRateLimitConfig{
		{
			// Even stricter for auth endpoints
			PathPatterns: []string{"/auth/*"},
			Config: servex.RateLimitConfig{
				Enabled:             true,
				RequestsPerInterval: 10,
				Interval:            time.Minute,
				BurstSize:           3,
			},
		},
	}

	stopRateLimit := servex.RegisterLocationBasedRateLimitMiddleware(server.Router(), locationConfigs)
	defer func() {
		if stopRateLimit != nil {
			stopRateLimit()
		}
	}()

	// This approach gives you:
	// - Global 60 RPM limit for most endpoints
	// - No limits for /health, /metrics, /public/*
	// - Extra strict 10 RPM limit for /auth/* endpoints

	// Uncomment to run: server.Start(":8081", "")
}
