package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex"
)

func securityExampleMain() {
	// Example 1: Basic security headers with default configuration
	basicSecurityExample()

	// Example 2: Strict security headers for high-security applications
	strictSecurityExample()

	// Example 3: Custom security configuration
	customSecurityExample()

	// Example 4: Path-specific security headers
	pathSpecificSecurityExample()

	// Example 5: Production-ready security configuration
	productionSecurityExample()

	// Example 6: Real-world usage example
	realWorldSecurityExample()
}

func basicSecurityExample() {
	fmt.Println("=== Basic Security Headers Example ===")

	server := servex.New(
		// Enable basic security headers with recommended defaults
		servex.WithSecurityHeaders(),
	)

	server.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Data endpoint with basic security headers")
	})

	fmt.Println("Server with basic security headers configured")
	fmt.Println("Headers applied: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, etc.")
}

func strictSecurityExample() {
	fmt.Println("\n=== Strict Security Headers Example ===")

	server := servex.New(
		// Enable strict security headers for high-security applications
		servex.WithStrictSecurityHeaders(),
	)

	server.HandleFunc("/api/secure", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Secure endpoint with strict security headers")
	})

	fmt.Println("Server with strict security headers configured")
	fmt.Println("Includes: CSP, HSTS, strict referrer policy, permissions policy, etc.")
}

func customSecurityExample() {
	fmt.Println("\n=== Custom Security Configuration Example ===")

	// Create custom security configuration
	customSecurity := servex.SecurityConfig{
		Enabled:                 true,
		ContentSecurityPolicy:   "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src 'self' 'unsafe-inline'",
		XContentTypeOptions:     "nosniff",
		XFrameOptions:           "SAMEORIGIN", // Allow framing by same origin
		XXSSProtection:          "1; mode=block",
		StrictTransportSecurity: "max-age=31536000; includeSubDomains",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		PermissionsPolicy:       "geolocation=(self), microphone=(), camera=()",
	}

	server := servex.New(
		servex.WithSecurityConfig(customSecurity),

		// Add custom headers (separate from security headers)
		servex.WithCustomHeaders(map[string]string{
			"X-API-Version":     "v1.0",
			"X-Rate-Limit-Info": "1000 requests per hour",
		}),

		// Remove server information (separate from security headers)
		servex.WithRemoveHeaders("Server", "X-Powered-By"),
	)

	server.HandleFunc("/api/custom", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Endpoint with custom security configuration")
	})

	fmt.Println("Server with custom security configuration")
}

func pathSpecificSecurityExample() {
	fmt.Println("\n=== Path-Specific Security Example ===")

	server := servex.New(
		// Apply security headers only to specific paths
		servex.WithStrictSecurityHeaders(),
		servex.WithSecurityIncludePaths("/api/v1/secure", "/admin"),

		// Exclude health and metrics endpoints
		servex.WithSecurityExcludePaths("/health", "/metrics", "/favicon.ico"),
	)

	server.HandleFunc("/api/v1/secure", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Secure API endpoint - security headers applied")
	})

	server.HandleFunc("/api/v1/public", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Public API endpoint - no security headers (not in include paths)")
	})

	server.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Health check - excluded from security headers")
	})

	fmt.Println("Server with path-specific security headers")
}

func productionSecurityExample() {
	fmt.Println("\n=== Production Security Example ===")

	// Production-ready server with comprehensive security
	server := servex.New(
		// Strict security headers
		servex.WithStrictSecurityHeaders(),

		// HSTS with preload for 1 year
		servex.WithHSTSHeader(31536000, true, true),

		// Custom CSP for a web application
		servex.WithContentSecurityPolicy(
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "+
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"img-src 'self' data: https:; "+
				"connect-src 'self' https://api.example.com; "+
				"frame-ancestors 'none'; "+
				"upgrade-insecure-requests",
		),

		// Custom headers
		servex.WithCustomHeaders(map[string]string{
			"X-API-Version":      "v2.0",
			"X-Request-Limit":    "1000/hour",
			"X-Content-Duration": "max-age=3600",
		}),

		// Remove server identification headers
		servex.WithRemoveHeaders("Server", "X-Powered-By", "X-AspNet-Version"),

		// Exclude monitoring endpoints from security headers
		servex.WithSecurityExcludePaths("/health", "/metrics", "/status", "/.well-known/"),

		// Enable rate limiting for additional security
		servex.WithRPS(100), // 100 requests per second

		// Enable request filtering for additional protection
		servex.WithBlockedUserAgentsRegex(".*[Bb]ot.*", ".*[Ss]craper.*"),
	)

	// API routes
	server.HandleFunc("/api/v2/users", handleSecureUsers)
	server.HandleFunc("/api/v2/auth/login", handleSecureLogin)
	server.HandleFunc("/api/v2/admin/dashboard", handleSecureAdminDashboard)

	// Health and monitoring (excluded from security headers)
	server.HandleFunc("/health", handleSecureHealth)
	server.HandleFunc("/metrics", handleSecureMetrics)

	fmt.Println("Production server with comprehensive security configured")

	// Example of starting the server with graceful shutdown
	fmt.Println("Starting secure server on :8443...")

	// In a real application:
	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()
	//
	// err := server.StartWithShutdown(ctx, "", ":8443") // HTTPS only for production
	// if err != nil {
	//     log.Fatal("Failed to start server:", err)
	// }
}

// Handler functions for the examples
func handleSecureUsers(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, map[string]string{
		"message": "Users API with security headers",
		"method":  r.Method,
		"path":    r.URL.Path,
	})
}

func handleSecureLogin(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, map[string]string{
		"message": "Login endpoint with security headers",
		"csrf":    "Use proper CSRF protection in production",
	})
}

func handleSecureAdminDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, map[string]string{
		"message": "Admin dashboard with strict security headers",
		"warning": "This endpoint should require additional authentication",
	})
}

func handleSecureHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "healthy", "timestamp": "%s"}`, time.Now().Format(time.RFC3339))
}

func handleSecureMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "# Metrics endpoint\nhttp_requests_total 1000\n")
}

// Real-world usage example with graceful shutdown
func realWorldSecurityExample() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create production server
	server := servex.New(
		servex.WithStrictSecurityHeaders(),
		servex.WithHSTSHeader(31536000, true, true),
		servex.WithCustomHeaders(map[string]string{
			"X-API-Version": "v1.0",
		}),
		servex.WithSecurityExcludePaths("/health", "/metrics"),
	)

	// Add routes
	server.HandleFunc("/api/data", handleSecureUsers)
	server.HandleFunc("/health", handleSecureHealth)

	// Start server with graceful shutdown
	if err := server.StartWithShutdown(ctx, ":8080", ":8443"); err != nil {
		log.Fatal("Server startup failed:", err)
	}

	fmt.Println("Server started with security headers middleware")
	fmt.Println("Security headers are automatically applied to all responses except /health and /metrics")
}
