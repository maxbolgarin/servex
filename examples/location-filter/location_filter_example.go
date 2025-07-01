package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/maxbolgarin/servex/v2"
)

// locationFilterExample demonstrates how to use location-based filtering
// with different filter configurations for different URL paths.
func main() {
	// Create a new router
	router := mux.NewRouter()

	// Configure location-based filtering with different rules for different paths
	locationFilterConfigs := []servex.LocationFilterConfig{
		{
			// Authentication endpoints - strict IP filtering and user agent requirements
			PathPatterns: []string{"/auth/*"},
			Config: servex.FilterConfig{
				// Only allow requests from trusted networks
				AllowedIPs: []string{
					"192.168.1.0/24", // Internal network
					"10.0.0.0/8",     // VPN network
				},
				// Require specific user agents for auth endpoints
				AllowedUserAgents: []string{
					"MyApp/1.0",
					"AuthClient/2.0",
				},
				// Block known bad bots
				BlockedUserAgents: []string{
					"BadBot/1.0",
					"Scanner/1.0",
				},
				StatusCode: http.StatusUnauthorized,
				Message:    "Authentication endpoint access denied",
			},
		},
		{
			// API endpoints - IP-based filtering with API key requirement
			PathPatterns: []string{"/api/v1/*", "/api/v2/*"},
			Config: servex.FilterConfig{
				// Allow broader IP range for API access
				AllowedIPs: []string{
					"192.168.0.0/16", // Broader internal network
					"172.16.0.0/12",  // Additional private networks
				},
				// Require API key in header
				AllowedHeaders: map[string][]string{
					"X-API-Key": {"key-123", "key-456", "key-789"},
				},
				// Block requests with debug parameter in production
				BlockedQueryParams: map[string][]string{
					"debug": {"true", "1"},
					"test":  {"true", "1"},
				},
				StatusCode: http.StatusForbidden,
				Message:    "API access denied - check your credentials",
			},
		},
		{
			// Admin endpoints - very strict filtering
			PathPatterns: []string{"/admin/*", "/dashboard/*"},
			Config: servex.FilterConfig{
				// Only allow from specific admin IPs
				AllowedIPs: []string{
					"192.168.1.100", // Admin workstation
					"192.168.1.101", // Backup admin workstation
				},
				// Require admin token in header
				AllowedHeaders: map[string][]string{
					"Admin-Token": {"admin-secret-token-123"},
				},
				// Use regex to allow specific admin user agents
				AllowedUserAgentsRegex: []string{
					"^AdminConsole/.*",
					"^Mozilla.*Admin.*",
				},
				StatusCode: http.StatusForbidden,
				Message:    "Admin access denied - unauthorized",
			},
		},
		{
			// Upload endpoints - file type and size restrictions via headers
			PathPatterns: []string{"/upload/*", "/files/*"},
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
				// Block large uploads by checking content-length header
				BlockedHeadersRegex: map[string][]string{
					"Content-Length": {"^[0-9]{8,}$"}, // Block if 8+ digits (>= 10MB)
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

	// Register the location-based filter middleware
	if _, err := servex.RegisterLocationBasedFilterMiddleware(router, locationFilterConfigs); err != nil {
		log.Fatal("Failed to register location-based filter middleware:", err)
	}

	// Add example routes for different categories

	// Authentication routes
	router.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Login endpoint - passed security filters\n")
		fmt.Fprintf(w, "User-Agent: %s\n", r.Header.Get("User-Agent"))
		fmt.Fprintf(w, "Client IP: %s\n", r.RemoteAddr)
	}).Methods("POST")

	router.HandleFunc("/auth/register", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Register endpoint - passed security filters\n")
	}).Methods("POST")

	// API routes
	router.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		fmt.Fprintf(w, "Users API - API Key: %s\n", apiKey)
		fmt.Fprintf(w, "Client IP: %s\n", r.RemoteAddr)
	}).Methods("GET")

	router.HandleFunc("/api/v2/posts", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Posts API v2 - passed security filters\n")
	}).Methods("GET")

	// Admin routes
	router.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
		adminToken := r.Header.Get("Admin-Token")
		fmt.Fprintf(w, "Admin Dashboard - Token: %s\n", adminToken)
		fmt.Fprintf(w, "User-Agent: %s\n", r.Header.Get("User-Agent"))
	}).Methods("GET")

	router.HandleFunc("/dashboard/stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Dashboard Stats - admin access granted\n")
	}).Methods("GET")

	// Upload routes
	router.HandleFunc("/upload/image", func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		contentLength := r.Header.Get("Content-Length")
		fmt.Fprintf(w, "Image upload - Content-Type: %s, Length: %s\n", contentType, contentLength)
	}).Methods("POST")

	router.HandleFunc("/files/document", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Document upload - passed security filters\n")
	}).Methods("POST")

	// Public routes
	router.HandleFunc("/public/info", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Public information - open access\n")
		fmt.Fprintf(w, "User-Agent: %s\n", r.Header.Get("User-Agent"))
	}).Methods("GET")

	// Health check route (no filtering applied)
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Service is healthy\n")
	}).Methods("GET")

	// Example route that doesn't match any filter patterns
	router.HandleFunc("/other/endpoint", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Other endpoint - no filtering applied\n")
	}).Methods("GET")

	fmt.Println("Location-based filter example server starting on :8080")
	fmt.Println("\nTry these test requests:")
	fmt.Println()

	// Auth endpoint examples
	fmt.Println("# Auth endpoints (strict IP + user agent filtering):")
	fmt.Println("curl -H 'User-Agent: MyApp/1.0' http://localhost:8080/auth/login -X POST")
	fmt.Println("curl -H 'User-Agent: BadBot/1.0' http://localhost:8080/auth/login -X POST  # Should be blocked")
	fmt.Println()

	// API endpoint examples
	fmt.Println("# API endpoints (IP filtering + API key required):")
	fmt.Println("curl -H 'X-API-Key: key-123' http://localhost:8080/api/v1/users")
	fmt.Println("curl http://localhost:8080/api/v1/users  # Should be blocked - no API key")
	fmt.Println("curl -H 'X-API-Key: key-123' 'http://localhost:8080/api/v1/users?debug=true'  # Should be blocked - debug param")
	fmt.Println()

	// Admin endpoint examples
	fmt.Println("# Admin endpoints (very strict - specific IPs + admin token + user agent):")
	fmt.Println("curl -H 'Admin-Token: admin-secret-token-123' -H 'User-Agent: AdminConsole/1.0' http://localhost:8080/admin/dashboard")
	fmt.Println("curl -H 'Admin-Token: wrong-token' http://localhost:8080/admin/dashboard  # Should be blocked")
	fmt.Println()

	// Upload endpoint examples
	fmt.Println("# Upload endpoints (content type restrictions + bot blocking):")
	fmt.Println("curl -H 'Content-Type: image/jpeg' -H 'Content-Length: 1024' http://localhost:8080/upload/image -X POST")
	fmt.Println("curl -H 'Content-Type: application/exe' http://localhost:8080/upload/image -X POST  # Should be blocked")
	fmt.Println("curl -H 'User-Agent: BadBot/1.0' http://localhost:8080/upload/image -X POST  # Should be blocked")
	fmt.Println()

	// Public endpoint examples
	fmt.Println("# Public endpoints (basic bot protection only):")
	fmt.Println("curl http://localhost:8080/public/info")
	fmt.Println("curl -H 'User-Agent: BadBot/1.0' http://localhost:8080/public/info  # Should be blocked")
	fmt.Println()

	// No filtering examples
	fmt.Println("# Endpoints with no filtering applied:")
	fmt.Println("curl http://localhost:8080/health")
	fmt.Println("curl http://localhost:8080/other/endpoint")
	fmt.Println()

	// Start the server
	// Uncomment to run: log.Fatal(http.ListenAndServe(":8080", router))
}

// alternativeLocationFilterExample shows how to combine global filtering
// with location-specific filtering for more complex security setups.
func alternativeLocationFilterExample() {
	// Create server with global filtering first
	server, err := servex.NewServer(
		// Global IP filtering - allow only internal networks
		servex.WithAllowedIPs("192.168.0.0/16", "10.0.0.0/8"),

		// Global bot protection
		servex.WithBlockedUserAgentsRegex(".*[Bb]ot.*", ".*[Ss]craper.*"),

		// Exclude public endpoints from global filtering
		servex.WithFilterExcludePaths("/public/*", "/health", "/metrics"),

		servex.WithHealthEndpoint(),
		servex.WithSendErrorToClient(),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Then add location-specific filtering on top
	locationFilterConfigs := []servex.LocationFilterConfig{
		{
			// Extra strict filtering for admin endpoints
			PathPatterns: []string{"/admin/*"},
			Config: servex.FilterConfig{
				// Require specific admin IPs (subset of global allowed IPs)
				AllowedIPs: []string{"192.168.1.100", "192.168.1.101"},

				// Require admin token
				AllowedHeaders: map[string][]string{
					"Admin-Token": {"admin-secret-123"},
				},

				StatusCode: http.StatusUnauthorized,
				Message:    "Admin access denied",
			},
		},
		{
			// API key requirement for API endpoints
			PathPatterns: []string{"/api/*"},
			Config: servex.FilterConfig{
				// API endpoints require valid API key
				AllowedHeadersRegex: map[string][]string{
					"X-API-Key": {"^key-[a-f0-9]{32}$"},
				},

				StatusCode: http.StatusForbidden,
				Message:    "Valid API key required",
			},
		},
	}

	// Register location-based filtering middleware
	if _, err := servex.RegisterLocationBasedFilterMiddleware(server.Router(), locationFilterConfigs); err != nil {
		log.Fatal("Failed to register location-based filter middleware:", err)
	}

	// Add routes
	server.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message": "API data - passed global IP + bot filters + API key check",
			"data":    []string{"item1", "item2", "item3"},
		})
	})

	server.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message": "Admin users - passed all security layers",
			"users":   []string{"admin", "user1", "user2"},
		})
	})

	server.HandleFunc("/public/info", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message": "Public info - no filtering applied",
			"info":    "This endpoint bypasses all filtering",
		})
	})

	// This approach gives you:
	// - Global IP + bot protection for most endpoints
	// - No filtering for public endpoints
	// - Extra admin token requirement for admin endpoints
	// - API key requirement for API endpoints

	fmt.Println("Alternative location-based filter example configured")
	fmt.Println("This combines global filtering with location-specific rules")

	// Uncomment to run: server.Start(":8081", "")
}
