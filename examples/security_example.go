package main

import (
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
	// === Basic Security Headers Example ===

	server, err := servex.New(
		// Enable basic security headers with recommended defaults
		servex.WithSecurityHeaders(),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	server.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Data endpoint with basic security headers"))
	})

	// Server with basic security headers configured
	// Headers applied: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, etc.
}

func strictSecurityExample() {
	// === Strict Security Headers Example ===

	server, err := servex.New(
		// Enable strict security headers for high-security applications
		servex.WithStrictSecurityHeaders(),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	server.HandleFunc("/api/secure", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Secure endpoint with strict security headers"))
	})

	// Server with strict security headers configured
	// Includes: CSP, HSTS, strict referrer policy, permissions policy, etc.
}

func customSecurityExample() {
	// === Custom Security Configuration Example ===

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

	server, err := servex.New(
		servex.WithSecurityConfig(customSecurity),

		// Add custom headers (separate from security headers)
		servex.WithCustomHeaders(map[string]string{
			"X-API-Version":     "v1.0",
			"X-Rate-Limit-Info": "1000 requests per hour",
		}),

		// Remove server information (separate from security headers)
		servex.WithRemoveHeaders("Server", "X-Powered-By"),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	server.HandleFunc("/api/custom", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Endpoint with custom security configuration"))
	})

	// Server with custom security configuration
}

func pathSpecificSecurityExample() {
	// === Path-Specific Security Example ===

	server, err := servex.New(
		// Apply security headers only to specific paths
		servex.WithStrictSecurityHeaders(),
		servex.WithSecurityIncludePaths("/api/v1/secure", "/admin"),

		// Exclude health and metrics endpoints
		servex.WithSecurityExcludePaths("/health", "/metrics", "/favicon.ico"),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	server.HandleFunc("/api/v1/secure", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Secure API endpoint - security headers applied"))
	})

	server.HandleFunc("/api/v1/public", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Public API endpoint - no security headers (not in include paths)"))
	})

	server.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Health check - excluded from security headers"))
	})

	// Server with path-specific security headers
}

func productionSecurityExample() {
	// === Production Security Example ===

	// Production-ready server with comprehensive security
	server, err := servex.New(
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
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	// API routes
	server.HandleFunc("/api/v2/users", handleSecureUsers)
	server.HandleFunc("/api/v2/auth/login", handleSecureLogin)
	server.HandleFunc("/api/v2/admin/dashboard", handleSecureAdminDashboard)

	// Health and monitoring (excluded from security headers)
	server.HandleFunc("/health", handleSecureHealth)
	server.HandleFunc("/metrics", handleSecureMetrics)

	// Production server with comprehensive security configured

	// Example of starting the server with graceful shutdown
	// Starting secure server on :8443...

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
	})
}

func handleSecureAdminDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, map[string]string{
		"message": "Admin dashboard with security headers",
	})
}

func handleSecureHealth(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func handleSecureMetrics(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("# metrics\nrequests_total 100\n"))
}

func realWorldSecurityExample() {
	// === Real-World Security Example ===

	// Example of a complete security setup for a production web application
	server, err := servex.New(
		// Start with production preset for base security
		append(servex.ProductionPreset(),
			// Enhanced security configuration
			servex.WithContentSecurityPolicy(
				"default-src 'self'; "+
					"script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "+
					"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
					"font-src 'self' https://fonts.gstatic.com; "+
					"img-src 'self' data: https: blob:; "+
					"connect-src 'self' https://api.myservice.com wss://ws.myservice.com; "+
					"media-src 'self' https://media.myservice.com; "+
					"object-src 'none'; "+
					"base-uri 'self'; "+
					"form-action 'self'; "+
					"frame-ancestors 'none'; "+
					"upgrade-insecure-requests",
			),

			// Additional request filtering
			servex.WithBlockedUserAgentsRegex(
				".*[Bb]ot.*",
				".*[Ss]craper.*",
				".*[Cc]rawler.*",
				".*[Ss]pider.*",
			),

			// Block suspicious query parameters
			servex.WithBlockedQueryParams(map[string][]string{
				"debug":    {"true", "1", "on", "yes"},
				"test":     {"true", "1", "on", "yes"},
				"admin":    {"true", "1", "on", "yes"},
				"internal": {"true", "1", "on", "yes"},
			}),

			// Custom security headers
			servex.WithCustomHeaders(map[string]string{
				"X-Download-Options":                "noopen",
				"X-Permitted-Cross-Domain-Policies": "none",
				"X-DNS-Prefetch-Control":            "off",
			}),
		)...,
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	// Application routes
	server.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"message": "Secure web application",
			"version": "1.0.0",
		})
	})

	server.HandleFunc("/api/v1/data", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"data":      []string{"item1", "item2", "item3"},
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	// Real-world production security configuration complete
	// Features enabled:
	// - Comprehensive Content Security Policy
	// - HSTS with preload for 1 year
	// - Bot and crawler blocking
	// - Debug parameter filtering
	// - Custom security headers
	// - Rate limiting (100 RPS)
	// - Server identification removal

	// To run this server:
	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()
	// server.StartWithShutdown(ctx, ":8080", ":8443")
}
