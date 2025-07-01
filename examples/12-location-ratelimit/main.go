package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

func main() {
	fmt.Println("⚡ Tutorial 12: Location-Based Rate Limiting")
	fmt.Println("==========================================")
	fmt.Println("Learn how to apply different rate limits to different URL paths")
	fmt.Println()

	// Create Servex server
	server, err := servex.NewServer(
		servex.WithHealthEndpoint(),
		servex.WithSendErrorToClient(),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Configure location-based rate limiting with different limits for different paths
	locationConfigs := []servex.LocationRateLimitConfig{
		{
			// Very strict rate limiting for authentication endpoints
			PathPatterns: []string{"/auth/login", "/auth/register"},
			Config: servex.RateLimitConfig{
				Enabled:             true,
				RequestsPerInterval: 5, // Only 5 attempts per minute
				Interval:            time.Minute,
				BurstSize:           2, // Allow up to 2 immediate requests
				StatusCode:          http.StatusTooManyRequests,
				Message:             "Too many authentication attempts. Please try again later.",
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
			// Strict rate limiting for file upload endpoints
			PathPatterns: []string{"/upload/*"},
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
			},
		},
		{
			// Custom rate limiting for search endpoints
			PathPatterns: []string{"/search/*"},
			Config: servex.RateLimitConfig{
				Enabled:             true,
				RequestsPerInterval: 30, // 30 searches per minute
				Interval:            time.Minute,
				BurstSize:           10, // Allow burst of searches
				StatusCode:          http.StatusTooManyRequests,
				Message:             "Search rate limit exceeded. Too many search requests.",
			},
		},
	}

	// Register the location-based rate limiting middleware
	stopRateLimit := servex.RegisterLocationBasedRateLimitMiddleware(server.Router(), locationConfigs)
	defer func() {
		if stopRateLimit != nil {
			stopRateLimit() // Clean up when the function exits
		}
	}()

	// Authentication routes - 5 req/min, burst: 2
	server.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":       "Login endpoint",
			"rate_limit":    "5 requests per minute, burst: 2",
			"security_note": "Strict rate limiting to prevent brute force attacks",
			"timestamp":     time.Now().Format(time.RFC3339),
		})
	}).Methods("POST")

	server.HandleFunc("/auth/register", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":       "Register endpoint",
			"rate_limit":    "5 requests per minute, burst: 2",
			"security_note": "Strict rate limiting to prevent spam registration",
			"timestamp":     time.Now().Format(time.RFC3339),
		})
	}).Methods("POST")

	// API routes - 100 req/min, burst: 20
	server.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":    "Users API endpoint",
			"rate_limit": "100 requests per minute, burst: 20",
			"users": []map[string]interface{}{
				{"id": 1, "name": "Alice", "role": "admin"},
				{"id": 2, "name": "Bob", "role": "user"},
				{"id": 3, "name": "Charlie", "role": "moderator"},
			},
			"note": "Moderate rate limiting for API usage",
		})
	}).Methods("GET")

	server.HandleFunc("/api/posts", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":    "Posts API endpoint",
			"rate_limit": "100 requests per minute, burst: 20",
			"posts": []map[string]interface{}{
				{"id": 1, "title": "Rate Limiting Guide", "author": "Alice"},
				{"id": 2, "title": "API Best Practices", "author": "Bob"},
				{"id": 3, "title": "Security Patterns", "author": "Charlie"},
			},
			"note": "API endpoints allow higher throughput",
		})
	}).Methods("GET")

	server.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":    "Data API endpoint",
			"rate_limit": "100 requests per minute, burst: 20",
			"data": map[string]interface{}{
				"total_requests": "varies",
				"server_status":  "operational",
				"rate_limiting":  "location-based",
			},
		})
	}).Methods("GET")

	// Upload routes - 10 req/min, burst: 3
	server.HandleFunc("/upload/image", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":       "Image upload endpoint",
			"rate_limit":    "10 requests per minute, burst: 3",
			"max_file_size": "10MB",
			"allowed_types": []string{"image/jpeg", "image/png", "image/gif"},
			"security_note": "Strict rate limiting to prevent abuse",
		})
	}).Methods("POST")

	server.HandleFunc("/upload/document", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":       "Document upload endpoint",
			"rate_limit":    "10 requests per minute, burst: 3",
			"allowed_types": []string{"application/pdf", "text/plain"},
			"note":          "Upload endpoints have strict limits",
		})
	}).Methods("POST")

	// Admin routes - 500 req/min, burst: 50
	server.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":    "Admin dashboard",
			"rate_limit": "500 requests per minute, burst: 50",
			"stats": map[string]interface{}{
				"total_users":     150,
				"active_sessions": 45,
				"api_calls_today": 12500,
				"rate_limit_hits": 23,
			},
			"note": "Admin endpoints have higher limits",
		})
	}).Methods("GET")

	server.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":    "Admin users management",
			"rate_limit": "500 requests per minute, burst: 50",
			"total":      150,
			"note":       "Trusted admin access with relaxed limits",
		})
	}).Methods("GET")

	// Search routes - 30 req/min, burst: 10
	server.HandleFunc("/search/users", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		query := r.URL.Query().Get("q")
		ctx.Response(200, map[string]interface{}{
			"message":    "User search endpoint",
			"rate_limit": "30 requests per minute, burst: 10",
			"query":      query,
			"results": []map[string]interface{}{
				{"id": 1, "name": "Alice Johnson", "match": "name"},
				{"id": 2, "name": "Bob Alice", "match": "name"},
			},
			"note": "Search operations have custom rate limits",
		})
	}).Methods("GET")

	server.HandleFunc("/search/content", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		query := r.URL.Query().Get("q")
		ctx.Response(200, map[string]interface{}{
			"message":    "Content search endpoint",
			"rate_limit": "30 requests per minute, burst: 10",
			"query":      query,
			"results": []string{
				"Tutorial: Rate Limiting",
				"Guide: API Security",
				"Best Practices: Performance",
			},
			"note": "Search functionality with moderate limits",
		})
	}).Methods("GET")

	// Public route - no rate limiting
	server.HandleFunc("/public/info", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":    "Public information endpoint",
			"rate_limit": "None - no rate limiting applied",
			"info": map[string]interface{}{
				"version":     "1.0",
				"environment": "tutorial",
				"features":    []string{"location-rate-limiting", "security"},
			},
			"note": "Public endpoints typically have no rate limits",
		})
	}).Methods("GET")

	// Rate limit status endpoint
	server.HandleFunc("/rate-limit-info", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"title":       "Location-Based Rate Limiting Demo",
			"description": "Different rate limits for different endpoint patterns",
			"rate_limits": map[string]interface{}{
				"authentication": map[string]interface{}{
					"patterns":  []string{"/auth/login", "/auth/register"},
					"limit":     "5 requests per minute",
					"burst":     "2 requests",
					"reasoning": "Prevent brute force attacks",
				},
				"api": map[string]interface{}{
					"patterns":  []string{"/api/*"},
					"limit":     "100 requests per minute",
					"burst":     "20 requests",
					"reasoning": "Allow reasonable API usage",
				},
				"uploads": map[string]interface{}{
					"patterns":  []string{"/upload/*"},
					"limit":     "10 requests per minute",
					"burst":     "3 requests",
					"reasoning": "Prevent upload abuse",
				},
				"admin": map[string]interface{}{
					"patterns":  []string{"/admin/*"},
					"limit":     "500 requests per minute",
					"burst":     "50 requests",
					"reasoning": "Trust admin users with higher limits",
				},
				"search": map[string]interface{}{
					"patterns":  []string{"/search/*"},
					"limit":     "30 requests per minute",
					"burst":     "10 requests",
					"reasoning": "Balance search functionality with resource protection",
				},
			},
			"testing_tip": "Make multiple rapid requests to see rate limiting in action!",
		})
	}).Methods("GET")

	// Start server with helpful testing information
	fmt.Println("🌐 Server starting on http://localhost:8080")
	fmt.Println()
	fmt.Println("📊 Rate limit configuration:")
	fmt.Println("  🔐 Auth endpoints:   5 req/min,   burst: 2")
	fmt.Println("  🔑 API endpoints:    100 req/min, burst: 20")
	fmt.Println("  📁 Upload endpoints: 10 req/min,  burst: 3")
	fmt.Println("  👑 Admin endpoints:  500 req/min, burst: 50")
	fmt.Println("  🔍 Search endpoints: 30 req/min,  burst: 10")
	fmt.Println("  🌍 Public endpoints: No limits")
	fmt.Println()
	fmt.Println("📋 Available endpoints:")
	fmt.Println("  POST /auth/login, /auth/register")
	fmt.Println("  GET  /api/users, /api/posts, /api/data")
	fmt.Println("  POST /upload/image, /upload/document")
	fmt.Println("  GET  /admin/dashboard, /admin/users")
	fmt.Println("  GET  /search/users, /search/content")
	fmt.Println("  GET  /public/info")
	fmt.Println("  GET  /rate-limit-info")
	fmt.Println("  GET  /health")
	fmt.Println()
	fmt.Println("🧪 Test rate limiting with rapid requests!")
	fmt.Println("Press Ctrl+C to stop")

	if err := server.Start(":8080", ""); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
