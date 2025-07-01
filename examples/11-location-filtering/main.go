package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/maxbolgarin/servex/v2"
)

func main() {
	fmt.Println("🎯 Tutorial 11: Location-Based Filtering")
	fmt.Println("======================================")
	fmt.Println("Learn how to apply different filtering rules to different URL paths")
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

	// Register the location-based filter middleware
	if _, err := servex.RegisterLocationBasedFilterMiddleware(server.Router(), locationFilterConfigs); err != nil {
		log.Fatal("Failed to register location-based filter middleware:", err)
	}

	// Authentication routes
	server.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":    "Login endpoint - passed security filters",
			"user_agent": r.Header.Get("User-Agent"),
			"client_ip":  r.RemoteAddr,
			"security":   "Strict IP + User-Agent filtering applied",
		})
	}).Methods("POST")

	server.HandleFunc("/auth/register", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":  "Registration endpoint - security passed",
			"security": "Auth endpoint protection active",
		})
	}).Methods("POST")

	// API routes
	server.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		apiKey := r.Header.Get("X-API-Key")
		ctx.Response(200, map[string]interface{}{
			"message":   "Users API v1",
			"api_key":   apiKey,
			"client_ip": r.RemoteAddr,
			"users": []map[string]interface{}{
				{"id": 1, "name": "Alice"},
				{"id": 2, "name": "Bob"},
			},
			"security": "API key validation passed",
		})
	}).Methods("GET")

	server.HandleFunc("/api/v2/posts", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message": "Posts API v2",
			"posts": []map[string]interface{}{
				{"id": 1, "title": "Hello World", "author": "Alice"},
				{"id": 2, "title": "Location Filtering", "author": "Bob"},
			},
			"security": "API endpoint filtering active",
		})
	}).Methods("GET")

	// Admin routes
	server.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		adminToken := r.Header.Get("Admin-Token")
		ctx.Response(200, map[string]interface{}{
			"message":    "Admin Dashboard",
			"token":      adminToken,
			"user_agent": r.Header.Get("User-Agent"),
			"stats": map[string]interface{}{
				"total_users": 150,
				"active_apis": 3,
				"uptime":      "99.9%",
			},
			"security": "Maximum security - IP + Token + User-Agent validation",
		})
	}).Methods("GET")

	server.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message": "Admin Users Management",
			"users": []map[string]interface{}{
				{"id": 1, "name": "Alice", "role": "admin"},
				{"id": 2, "name": "Bob", "role": "user"},
				{"id": 3, "name": "Charlie", "role": "moderator"},
			},
			"security": "Admin access granted",
		})
	}).Methods("GET")

	// Upload routes
	server.HandleFunc("/upload/image", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		contentType := r.Header.Get("Content-Type")
		contentLength := r.Header.Get("Content-Length")
		ctx.Response(200, map[string]interface{}{
			"message":        "Image upload endpoint",
			"content_type":   contentType,
			"content_length": contentLength,
			"allowed_types":  []string{"image/jpeg", "image/png", "image/gif"},
			"security":       "Content-Type validation passed",
		})
	}).Methods("POST")

	server.HandleFunc("/upload/document", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":       "Document upload endpoint",
			"allowed_types": []string{"application/pdf", "text/plain"},
			"max_size":      "10MB",
			"security":      "Upload filtering active",
		})
	}).Methods("POST")

	// Public routes
	server.HandleFunc("/public/info", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":    "Public information endpoint",
			"user_agent": r.Header.Get("User-Agent"),
			"info": map[string]interface{}{
				"version":     "1.0",
				"environment": "demo",
				"features":    []string{"location-filtering", "security"},
			},
			"security": "Basic bot protection only",
		})
	}).Methods("GET")

	// Unfiltered route (no patterns match)
	server.HandleFunc("/other/info", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":  "Other endpoint - no location filtering applied",
			"security": "No specific filtering rules",
			"note":     "This endpoint doesn't match any filter patterns",
		})
	}).Methods("GET")

	// Start server with helpful testing information
	fmt.Println("🌐 Server starting on http://localhost:8080")
	fmt.Println()
	fmt.Println("📋 Available endpoints with different filtering rules:")
	fmt.Println()
	fmt.Println("🔐 Auth endpoints (IP + User-Agent filtering):")
	fmt.Println("  POST /auth/login")
	fmt.Println("  POST /auth/register")
	fmt.Println()
	fmt.Println("🔑 API endpoints (IP + API Key required):")
	fmt.Println("  GET  /api/v1/users")
	fmt.Println("  GET  /api/v2/posts")
	fmt.Println()
	fmt.Println("👑 Admin endpoints (IP + Token + User-Agent):")
	fmt.Println("  GET  /admin/dashboard")
	fmt.Println("  GET  /admin/users")
	fmt.Println()
	fmt.Println("📁 Upload endpoints (Content-Type filtering):")
	fmt.Println("  POST /upload/image")
	fmt.Println("  POST /upload/document")
	fmt.Println()
	fmt.Println("🌍 Public endpoints (Basic bot protection):")
	fmt.Println("  GET  /public/info")
	fmt.Println()
	fmt.Println("❌ No filtering:")
	fmt.Println("  GET  /other/info")
	fmt.Println("  GET  /health")
	fmt.Println()
	fmt.Println("🧪 Test commands available in README.md")
	fmt.Println("Press Ctrl+C to stop")

	if err := server.Start(":8080", ""); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
