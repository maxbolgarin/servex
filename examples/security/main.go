package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex"
)

func main() {
	fmt.Println("=== Servex Security Headers Examples ===")
	fmt.Println("Choose an example to run:")
	fmt.Println("1. Basic Security Headers")
	fmt.Println("2. Strict Security Headers")
	fmt.Println("3. Custom Security Configuration")
	fmt.Println("4. Path-Specific Security")
	fmt.Println("5. Production Security (Default)")
	fmt.Println("6. Interactive Demo")
	fmt.Println("")

	// For demo purposes, we'll run the interactive security demo
	// Users can modify main() to run different examples
	fmt.Println("Running: Interactive Security Demo")
	fmt.Println("Edit main() to run specific examples")
	interactiveSecurityDemo()
}

// Interactive demo that showcases security features
func interactiveSecurityDemo() {
	log.Println("Starting interactive security demo server on :8080")
	log.Println("Visit http://localhost:8080 to see security headers in action")

	server, err := servex.NewServer(
		// Start with production-level security
		servex.WithStrictSecurityHeaders(),

		// Custom CSP for demo
		servex.WithContentSecurityPolicy(
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"frame-ancestors 'none'",
		),

		// Remove server identification
		servex.WithRemoveHeaders("Server", "X-Powered-By"),

		// Add custom headers
		servex.WithCustomHeaders(map[string]string{
			"X-API-Version": "1.0.0",
			"X-Demo":        "security-example",
		}),

		// Path-specific exclusions
		servex.WithSecurityExcludePaths("/health", "/metrics"),

		// Basic rate limiting
		servex.WithRPM(100),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Main demo page
	server.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.SetHeader("Content-Type", "text/html")
		ctx.Response(200, `
<!DOCTYPE html>
<html>
<head>
    <title>Servex Security Headers Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .security-demo { background: #f5f5f5; padding: 15px; margin: 10px 0; }
        .header-example { background: #e8f4f8; padding: 10px; margin: 5px 0; font-family: monospace; }
        ul { margin: 10px 0; }
    </style>
</head>
<body>
    <h1>Servex Security Headers Demo</h1>
    
    <div class="security-demo">
        <h2>🛡️ Security Features Active</h2>
        <p>This page demonstrates various security headers in action.</p>
        <p><strong>Check your browser's developer tools → Network tab → Response Headers</strong></p>
    </div>

    <h2>Security Headers Applied</h2>
    <div class="header-example">Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; ...</div>
    <div class="header-example">X-Content-Type-Options: nosniff</div>
    <div class="header-example">X-Frame-Options: DENY</div>
    <div class="header-example">X-XSS-Protection: 1; mode=block</div>
    <div class="header-example">Strict-Transport-Security: max-age=31536000; includeSubDomains</div>
    <div class="header-example">Referrer-Policy: strict-origin-when-cross-origin</div>

    <h2>Test Endpoints</h2>
    <ul>
        <li><a href="/api/secure">Secure API endpoint</a> (has security headers)</li>
        <li><a href="/api/data">Data API endpoint</a> (has security headers)</li>
        <li><a href="/health">Health check</a> (excluded from security headers)</li>
        <li><a href="/admin">Admin panel</a> (strict security)</li>
    </ul>

    <h2>Security Features</h2>
    <ul>
        <li>✅ Content Security Policy (CSP)</li>
        <li>✅ HTTP Strict Transport Security (HSTS)</li>
        <li>✅ X-Content-Type-Options</li>
        <li>✅ X-Frame-Options</li>
        <li>✅ X-XSS-Protection</li>
        <li>✅ Referrer Policy</li>
        <li>✅ Rate Limiting (100 RPM)</li>
        <li>✅ Server Header Removal</li>
    </ul>

    <h2>Testing Commands</h2>
    <pre>
# Check security headers
curl -I http://localhost:8080/

# Compare with excluded endpoint
curl -I http://localhost:8080/health

# Test rate limiting
for i in {1..10}; do curl http://localhost:8080/api/data; done
    </pre>
</body>
</html>`)
	})

	// Secure API endpoints
	server.HandleFunc("/api/secure", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":   "This endpoint has security headers",
			"secure":    true,
			"timestamp": time.Now().Unix(),
		})
	})

	server.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"data":    []string{"item1", "item2", "item3"},
			"headers": "security headers applied",
		})
	})

	server.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"message": "Admin panel with strict security",
			"access":  "restricted",
		})
	})

	// Health endpoint (excluded from security headers)
	server.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Metrics endpoint (excluded from security headers)
	server.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# metrics\nrequests_total 100\n"))
	})

	if err := server.Start(":8080", ""); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 1: Basic Security Headers
func basicSecurityExample() {
	server, err := servex.NewServer(
		// Enable basic security headers with recommended defaults
		servex.WithSecurityHeaders(),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	server.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Data endpoint with basic security headers"))
	})

	log.Println("Basic security example starting on :8080")
	fmt.Println("Test with: curl -I http://localhost:8080/api/data")
	server.Start(":8080", "")
}

// Example 2: Strict Security Headers
func strictSecurityExample() {
	server, err := servex.NewServer(
		// Enable strict security headers for high-security applications
		servex.WithStrictSecurityHeaders(),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	server.HandleFunc("/api/secure", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Secure endpoint with strict security headers"))
	})

	log.Println("Strict security example starting on :8080")
	fmt.Println("Test with: curl -I http://localhost:8080/api/secure")
	server.Start(":8080", "")
}

// Example 3: Custom Security Configuration
func customSecurityExample() {
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

	server, err := servex.NewServer(
		servex.WithSecurityConfig(customSecurity),

		// Add custom headers
		servex.WithCustomHeaders(map[string]string{
			"X-API-Version":     "v1.0",
			"X-Rate-Limit-Info": "1000 requests per hour",
		}),

		// Remove server information
		servex.WithRemoveHeaders("Server", "X-Powered-By"),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	server.HandleFunc("/api/custom", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Endpoint with custom security configuration"))
	})

	log.Println("Custom security example starting on :8080")
	fmt.Println("Test with: curl -I http://localhost:8080/api/custom")
	server.Start(":8080", "")
}

// Example 4: Path-Specific Security
func pathSpecificSecurityExample() {
	server, err := servex.NewServer(
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

	log.Println("Path-specific security example starting on :8080")
	fmt.Println("Test secure: curl -I http://localhost:8080/api/v1/secure")
	fmt.Println("Test public: curl -I http://localhost:8080/api/v1/public")
	fmt.Println("Test health: curl -I http://localhost:8080/health")
	server.Start(":8080", "")
}

// Example 5: Production Security
func productionSecurityExample() {
	server, err := servex.NewServer(
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

	log.Println("Production security example starting on :8080")
	fmt.Println("Test API: curl -I http://localhost:8080/api/v2/users")
	fmt.Println("Test health: curl -I http://localhost:8080/health")
	server.Start(":8080", "")
}

// Handler functions
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
