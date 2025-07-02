package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

func main() {
	fmt.Println("🛡️  Tutorial 11: Location-Based Filtering & Rate Limiting")
	fmt.Println("=====================================================")
	fmt.Println("Learn how to apply different filtering rules AND rate limits to different URL paths")
	fmt.Println()

	// Create Servex server
	server, err := servex.NewServer(
		servex.WithHealthEndpoint(),
		servex.WithSendErrorToClient(),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Configure location-based filtering with different rules for different paths
	locationFilterConfigs := []servex.LocationFilterConfig{
		{
			// Authentication endpoints - strict security
			PathPatterns: []string{"/auth/*"},
			Config: servex.FilterConfig{
				// Only allow requests from trusted networks
				AllowedIPs: []string{
					"192.168.1.0/24", // Internal network
					"10.0.0.0/8",     // VPN network
					"127.0.0.1",      // Localhost for testing
				},
				// Require specific user agents for auth endpoints
				AllowedUserAgents: []string{
					"MyApp/1.0",
					"AuthClient/2.0",
					"curl/*", // Allow curl for testing
				},
				// Block known bad bots
				BlockedUserAgents: []string{
					"BadBot/1.0",
					"Scanner/1.0",
					"Malware/1.0",
				},
				StatusCode: http.StatusUnauthorized,
				Message:    "Authentication endpoint access denied",
			},
		},
		{
			// API endpoints - require API keys
			PathPatterns: []string{"/api/v1/*", "/api/v2/*"},
			Config: servex.FilterConfig{
				// Allow broader IP range for API access
				AllowedIPs: []string{
					"192.168.0.0/16", // Broader internal network
					"172.16.0.0/12",  // Additional private networks
					"127.0.0.1",      // Localhost for testing
				},
				// Require API key in header
				AllowedHeaders: map[string][]string{
					"X-API-Key": {"api-key-123", "api-key-456", "test-key"},
				},
				// Block requests with debug parameter in production
				BlockedQueryParams: map[string][]string{
					"debug": {"true", "1"},
					"test":  {"true", "1"},
				},
				StatusCode: http.StatusForbidden,
				Message:    "API access denied - valid API key required",
			},
		},
		{
			// Admin endpoints - very strict filtering
			PathPatterns: []string{"/admin/*"},
			Config: servex.FilterConfig{
				// Only allow from specific admin IPs
				AllowedIPs: []string{
					"127.0.0.1",     // Localhost for testing
					"192.168.1.100", // Admin workstation
				},
				// Require admin token in header
				AllowedHeaders: map[string][]string{
					"Admin-Token": {"admin-secret-token-123"},
				},
				// Use regex to allow specific admin user agents
				AllowedUserAgentsRegex: []string{
					"^AdminConsole/.*",
					"^curl/.*", // Allow curl for testing
				},
				StatusCode: http.StatusForbidden,
				Message:    "Admin access denied - unauthorized",
			},
		},
		{
			// Upload endpoints - content type restrictions
			PathPatterns: []string{"/upload/*"},
			Config: servex.FilterConfig{
				// Block known malicious user agents
				BlockedUserAgentsRegex: []string{
					".*[Bb]ot.*",
					".*[Ss]canner.*",
					".*[Cc]rawler.*",
				},
				// Require content type specification
				AllowedHeadersRegex: map[string][]string{
					"Content-Type": {
						"^image/.*",         // Allow images
						"^application/pdf$", // Allow PDFs
						"^text/plain$",      // Allow text files
					},
				},
				// Block large uploads (>= 10MB)
				BlockedHeadersRegex: map[string][]string{
					"Content-Length": {"^[0-9]{8,}$"}, // Block if 8+ digits
				},
				StatusCode: http.StatusBadRequest,
				Message:    "Upload blocked - file type or size not allowed",
			},
		},
		{
			// Public API endpoints - basic bot protection only
			PathPatterns: []string{"/public/*"},
			Config: servex.FilterConfig{
				// Just block obvious bots
				BlockedUserAgents: []string{
					"BadBot/1.0",
					"Scraper/1.0",
					"Malware/1.0",
				},
				BlockedUserAgentsRegex: []string{
					".*[Bb]ad[Bb]ot.*",
					".*[Ss]craper.*",
				},
				StatusCode: http.StatusTooManyRequests,
				Message:    "Automated requests not allowed",
			},
		},
	}

	// Configure location-based rate limiting with different limits for different paths
	locationRateLimitConfigs := []servex.LocationRateLimitConfig{
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
			// High rate limiting for public endpoints
			PathPatterns: []string{"/public/*"},
			Config: servex.RateLimitConfig{
				Enabled:             true,
				RequestsPerInterval: 1000, // 1000 requests per minute
				Interval:            time.Minute,
				BurstSize:           100, // High burst for public access
				StatusCode:          http.StatusTooManyRequests,
				Message:             "Public API rate limit exceeded.",
			},
		},
	}

	// Register the location-based filter middleware
	if _, err := servex.RegisterLocationBasedFilterMiddleware(server.Router(), locationFilterConfigs); err != nil {
		log.Fatal("Failed to register location-based filter middleware:", err)
	}

	// Register the location-based rate limiting middleware
	stopRateLimit := servex.RegisterLocationBasedRateLimitMiddleware(server.Router(), locationRateLimitConfigs)
	defer func() {
		if stopRateLimit != nil {
			stopRateLimit() // Clean up when the function exits
		}
	}()

	// Authentication routes
	server.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"message":    "Login endpoint - passed both security filters and rate limits",
			"user_agent": r.Header.Get("User-Agent"),
			"client_ip":  r.RemoteAddr,
			"security":   "Strict IP + User-Agent filtering + 5 req/min rate limit",
			"timestamp":  time.Now().Format(time.RFC3339),
		})
	}).Methods(servex.POST)

	server.HandleFunc("/auth/register", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"message":   "Registration endpoint - comprehensive protection passed",
			"security":  "Auth endpoint protection + rate limiting active",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}).Methods(servex.POST)

	// API routes
	server.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		apiKey := r.Header.Get("X-API-Key")
		ctx.Response(200, map[string]any{
			"message":   "Users API v1",
			"api_key":   apiKey,
			"client_ip": r.RemoteAddr,
			"users": []map[string]any{
				{"id": 1, "name": "Alice"},
				{"id": 2, "name": "Bob"},
			},
			"security":  "API key validation + IP filtering + 100 req/min rate limit",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}).Methods(servex.GET)

	server.HandleFunc("/api/v2/posts", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"message": "Posts API v2",
			"posts": []map[string]any{
				{"id": 1, "title": "Security & Performance", "author": "Alice"},
				{"id": 2, "title": "Location Filtering & Rate Limiting", "author": "Bob"},
			},
			"security":  "Combined API protection + performance limits",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}).Methods(servex.GET)

	// Admin routes
	server.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		adminToken := r.Header.Get("Admin-Token")
		ctx.Response(200, map[string]any{
			"message":    "Admin Dashboard",
			"token":      adminToken,
			"user_agent": r.Header.Get("User-Agent"),
			"stats": map[string]any{
				"total_users":    150,
				"active_apis":    3,
				"uptime":         "99.9%",
				"security_level": "maximum",
				"rate_limit":     "500 req/min",
			},
			"security":  "Maximum security - IP + Token + User-Agent + High rate limits",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}).Methods(servex.GET)

	server.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"message": "Admin Users Management",
			"users": []map[string]any{
				{"id": 1, "name": "Alice", "role": "admin"},
				{"id": 2, "name": "Bob", "role": "user"},
				{"id": 3, "name": "Charlie", "role": "moderator"},
			},
			"security":  "Admin access + productivity-focused rate limits",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}).Methods(servex.GET)

	// Upload routes
	server.HandleFunc("/upload/image", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		contentType := r.Header.Get("Content-Type")
		contentLength := r.Header.Get("Content-Length")
		ctx.Response(200, map[string]any{
			"message":        "Image upload endpoint",
			"content_type":   contentType,
			"content_length": contentLength,
			"allowed_types":  []string{"image/jpeg", "image/png", "image/gif"},
			"security":       "Content-Type validation + 10 req/min upload protection",
			"timestamp":      time.Now().Format(time.RFC3339),
		})
	}).Methods(servex.POST)

	server.HandleFunc("/upload/document", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"message":       "Document upload endpoint",
			"allowed_types": []string{"application/pdf", "text/plain"},
			"max_size":      "10MB",
			"security":      "Upload filtering + abuse prevention rate limiting",
			"timestamp":     time.Now().Format(time.RFC3339),
		})
	}).Methods(servex.POST)

	// Public routes
	server.HandleFunc("/public/info", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"message":    "Public information endpoint",
			"user_agent": r.Header.Get("User-Agent"),
			"info": map[string]any{
				"version":     "1.0",
				"environment": "demo",
				"features":    []string{"location-filtering", "location-rate-limiting", "combined-security"},
			},
			"security":  "Basic bot protection + 1000 req/min rate limit",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}).Methods(servex.GET)

	// Unfiltered route (no patterns match)
	server.HandleFunc("/other/info", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"message":   "Other endpoint - no location filtering or rate limiting applied",
			"security":  "No specific filtering or rate limiting rules",
			"note":      "This endpoint doesn't match any filter or rate limit patterns",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}).Methods(servex.GET)

	// Combined security and performance status endpoint
	server.HandleFunc("/security-performance-status", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"title":       "Combined Security & Performance Protection",
			"description": "Location-based filtering and rate limiting demo",
			"timestamp":   time.Now().Format(time.RFC3339),
			"security": map[string]any{
				"active_filters": 5,
				"protection_zones": map[string]string{
					"auth":   "strict_ip_user_agent",
					"api":    "ip_api_key_params",
					"admin":  "maximum_security",
					"upload": "content_type_size",
					"public": "basic_bot_protection",
				},
			},
			"performance": map[string]any{
				"active_rate_limits": 5,
				"rate_limit_zones": map[string]string{
					"auth":   "5_req_min_burst_2",
					"api":    "100_req_min_burst_20",
					"admin":  "500_req_min_burst_50",
					"upload": "10_req_min_burst_3",
					"public": "1000_req_min_burst_100",
				},
			},
			"endpoints": map[string]any{
				"auth": map[string]any{
					"security_level": "high",
					"rate_limit":     "5 req/min",
					"purpose":        "prevent_brute_force_and_abuse",
				},
				"api": map[string]any{
					"security_level": "medium",
					"rate_limit":     "100 req/min",
					"purpose":        "api_protection_and_performance",
				},
				"admin": map[string]any{
					"security_level": "maximum",
					"rate_limit":     "500 req/min",
					"purpose":        "trust_admin_users_productivity",
				},
				"upload": map[string]any{
					"security_level": "content_focused",
					"rate_limit":     "10 req/min",
					"purpose":        "prevent_upload_abuse",
				},
				"public": map[string]any{
					"security_level": "basic",
					"rate_limit":     "1000 req/min",
					"purpose":        "open_but_protected",
				},
			},
			"features": []string{
				"Location-based filtering",
				"Location-based rate limiting",
				"Graduated security levels",
				"Performance protection",
				"Layered defense architecture",
			},
		})
	}).Methods(servex.GET)

	// Start server with helpful testing information
	fmt.Println("🌐 Server starting on http://localhost:8080")
	fmt.Println()
	fmt.Println("🛡️  Security & Performance Protection:")
	fmt.Println("  → Location-based filtering rules")
	fmt.Println("  → Location-based rate limiting")
	fmt.Println("  → Graduated security levels")
	fmt.Println("  → Performance protection")
	fmt.Println()
	fmt.Println("📊 Protection configuration:")
	fmt.Println("  🔐 Auth endpoints:   IP + User-Agent + 5 req/min")
	fmt.Println("  🔑 API endpoints:    IP + API Key + 100 req/min")
	fmt.Println("  👑 Admin endpoints:  Maximum Security + 500 req/min")
	fmt.Println("  📁 Upload endpoints: Content-Type + 10 req/min")
	fmt.Println("  🌍 Public endpoints: Bot protection + 1000 req/min")
	fmt.Println("  ❌ Other endpoints:  No protection")
	fmt.Println()
	fmt.Println("📋 Available endpoints:")
	fmt.Println("  POST /auth/login, /auth/register")
	fmt.Println("  GET  /api/v1/users, /api/v2/posts")
	fmt.Println("  GET  /admin/dashboard, /admin/users")
	fmt.Println("  POST /upload/image, /upload/document")
	fmt.Println("  GET  /public/info")
	fmt.Println("  GET  /other/info")
	fmt.Println("  GET  /security-performance-status")
	fmt.Println("  GET  /health")
	fmt.Println()
	fmt.Println("🧪 Test both security filtering AND rate limiting!")
	fmt.Println("Press Ctrl+C to stop")

	if err := server.StartWithWaitSignalsHTTP(context.Background(), ":8080"); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
