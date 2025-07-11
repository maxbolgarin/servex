package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

func main() {
	fmt.Println("=== Servex Quickstart Examples ===")
	fmt.Println("Choose an example to run:")
	fmt.Println("1. Quick Development Server")
	fmt.Println("2. Production-Ready Server")
	fmt.Println("3. REST API Server")
	fmt.Println("4. Web Application Server")
	fmt.Println("5. Microservice Server")
	fmt.Println("6. High-Security Server")
	fmt.Println("7. SSL-Enabled Server")
	fmt.Println("8. API with Authentication")
	fmt.Println("")

	// For demo purposes, we'll run the development server
	// Users can modify main() to run different examples
	fmt.Println("Running: Quick Development Server")
	quickDevelopmentServer()
}

// Example 1: Quick Development Server
func quickDevelopmentServer() {
	// === Quick Development Server ===

	// Just one line with preset - perfect for development!
	server, err := servex.NewServer(servex.DevelopmentPreset()...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	server.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"message": "Hello from development server!",
			"env":     "development",
		})
	})

	// Development server configured with:
	// - 30s read timeout
	// - Health endpoint at /health
	// - No security restrictions (for easy debugging)
	// - Client errors logged (more noise for debugging)

	fmt.Println("Starting development server on :8080")
	fmt.Println("Try: curl http://localhost:8080/hello")
	fmt.Println("Health check: curl http://localhost:8080/health")

	err = server.StartWithWaitSignalsHTTP(context.Background(), ":8080")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 2: Production-Ready Server
func productionReadyServer() {
	// === Production-Ready Server ===

	// TODO: Add TLS certificate and key to the server
	tlsCert := tls.Certificate{}

	// Production preset with additional custom options
	server, err := servex.NewServer(servex.MergeWithPreset(
		servex.ProductionPreset(tlsCert),
		// Add any custom options on top of the preset
		servex.WithCustomHeaders(map[string]string{
			"X-App-Version": "1.0.0",
		}),
	)...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	server.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"users": []string{"alice", "bob", "charlie"},
			"count": 3,
		})
	})

	server.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"status":    "operational",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	// Production server configured with:
	// - Strict security headers
	// - 100 RPS rate limiting
	// - Health endpoint at /health
	// - Server headers removed
	// - Security exclusions for monitoring endpoints

	// Start with graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Println("Starting production server on :8080 and :8443")
	err = server.StartWithWaitSignals(ctx, ":8080", ":8443")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 3: REST API Server
func restAPIServer() {
	// === REST API Server ===

	server, err := servex.NewServer(
		servex.MergeWithPreset(
			servex.APIServerPreset(),
			servex.WithCORS(),
		)...,
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// API routes
	server.HandleFunc("/api/v1/users", handleQuickUsers).Methods(servex.GET, servex.POST)
	server.HandleFunc("/api/v1/users/{id}", handleUserByID).Methods(servex.GET, servex.PUT, servex.DELETE)
	server.HandleFunc("/api/v1/posts", handlePosts).Methods(servex.GET, servex.POST)

	// API server configured with:
	// - API-friendly security headers
	// - 1000 RPM rate limiting with 50 burst
	// - Health endpoint at /api/health
	// - X-API-Version header
	// - No CSP (not needed for APIs)

	fmt.Println("Starting REST API server on :8080")
	err = server.StartWithWaitSignalsHTTP(context.Background(), ":8080")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 4: Web Application Server
func webApplicationServer() {
	// === Web Application Server ===

	// TODO: Add TLS certificate and key to the server
	tlsCert := tls.Certificate{}

	server, err := servex.NewServer(servex.WebAppPreset(tlsCert)...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Web routes
	server.HandleFunc("/", handleHomePage)
	server.HandleFunc("/about", handleAboutPage)
	server.HandleFunc("/api/data", handleAPIData)

	// Static files (would typically use http.FileServer)
	server.HandleFunc("/static/", handleStaticFiles)

	// Web application server configured with:
	// - Comprehensive web security headers
	// - Content Security Policy for web apps
	// - 50 RPS rate limiting
	// - Static file exclusions from rate limiting
	// - Common web asset exclusions

	fmt.Println("Starting web application server on :8080 and :8443")
	err = server.StartWithWaitSignals(context.Background(), ":8080", ":8443")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 5: Microservice Server
func microserviceServer() {
	// === Microservice Server ===

	server, err := servex.NewServer(servex.MicroservicePreset()...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	// Microservice endpoints
	server.HandleFunc("/api/v1/process", handleProcess)
	server.HandleFunc("/api/v1/status", handleServiceStatus)
	server.HandleFunc("/metrics", handleMetrics)
	server.HandleFunc("/ready", handleReadiness)

	// Microservice server configured with:
	// - Fast timeouts (5s read, 2s header, 30s idle)
	// - Basic security headers only
	// - 200 RPS rate limiting
	// - Health, metrics, and readiness endpoints
	// - Monitoring exclusions from security

	fmt.Println("Starting microservice server on :8080")
	err = server.StartWithWaitSignalsHTTP(context.Background(), ":8080")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 6: High-Security Server
func highSecurityServer() {
	// === High-Security Server ===

	// TODO: Add TLS certificate and key to the server
	tlsCert := tls.Certificate{}

	server, err := servex.NewServer(servex.HighSecurityPreset(tlsCert)...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Secure endpoints only
	server.HandleFunc("/api/secure/data", handleSecureData)
	server.HandleFunc("/api/secure/admin", handleSecureAdmin)

	// High-security server configured with:
	// - Strict security headers with HSTS preload
	// - Bot and scraper blocking
	// - Debug parameter blocking
	// - Aggressive rate limiting (20 RPS)
	// - All server identification headers removed

	fmt.Println("Starting high-security server on :8443 (HTTPS only)")
	err = server.StartWithWaitSignalsHTTPS(context.Background(), ":8443") // HTTPS only for high security
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 7: SSL-Enabled Server
func sslEnabledServer() {
	// === SSL-Enabled Server ===

	// TODO: Add TLS certificate and key to the server
	tlsCert := tls.Certificate{}

	// Quick SSL setup with preset
	server, err := servex.NewServer(
		servex.MergeWithPreset(
			servex.TLSPreset("cert.pem", "key.pem", tlsCert),
			servex.WithReadTimeout(10*time.Second),
			servex.WithIdleTimeout(60*time.Second),
			servex.WithMaxRequestBodySize(1024*1024),
			servex.WithCORS(),
		)...,
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	server.HandleFunc("/api/secure", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"message": "Secure HTTPS endpoint",
			"tls":     "enabled",
		})
	})

	// SSL server configured with:
	// - Production preset + SSL certificate
	// - HSTS header (1 year)
	// - All production security features

	fmt.Println("Starting SSL server on :8443")
	err = server.StartWithWaitSignalsHTTPS(context.Background(), ":8443") // HTTPS only
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 8: API with Authentication
func apiWithAuthentication() {
	// === API with Authentication ===

	server, err := servex.NewServer(
		// Enable in-memory auth database for this example
		servex.WithAuthMemoryDatabase(),

		// Add initial admin user
		servex.WithAuthInitialUsers(servex.InitialUser{
			Username: "admin",
			Password: "admin123",
			Roles:    []servex.UserRole{servex.UserRole("admin")},
		}),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	// Public endpoints
	server.HandleFunc("/api/v1/public", handlePublicData)

	// Protected endpoints
	server.HFA("/api/v1/protected", handleProtectedData, servex.UserRole("user"))
	server.HFA("/api/v1/admin", handleAdminData, servex.UserRole("admin"))

	// Authenticated API server configured with:
	// - API preset + JWT authentication
	// - Auth endpoints at /api/v1/auth/*
	// - 15-minute access tokens, 7-day refresh tokens
	// - Initial admin user created
	// - No rate limiting on auth routes

	// Available auth endpoints:
	// - POST /api/v1/auth/register
	// - POST /api/v1/auth/login
	// - POST /api/v1/auth/refresh
	// - POST /api/v1/auth/logout

	fmt.Println("Starting authenticated API server on :8080")
	fmt.Println("Login with: admin/admin123")
	err = server.StartWithWaitSignalsHTTP(context.Background(), ":8080")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Handler functions
func handleQuickUsers(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	if r.Method == servex.GET {
		ctx.Response(200, []map[string]string{
			{"id": "1", "name": "Alice"},
			{"id": "2", "name": "Bob"},
		})
	} else {
		ctx.Response(201, map[string]string{"message": "User created"})
	}
}

func handleUserByID(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, map[string]string{
		"id":   "1",
		"name": "Alice",
	})
}

func handlePosts(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, []map[string]string{
		{"id": "1", "title": "Hello World"},
	})
}

func handleHomePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<html><body><h1>Welcome to My App</h1></body></html>")
}

func handleAboutPage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<html><body><h1>About Us</h1></body></html>")
}

func handleAPIData(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, map[string]any{
		"data": []string{"item1", "item2", "item3"},
	})
}

func handleStaticFiles(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Static file content")
}

func handleProcess(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, map[string]string{
		"status": "processed",
		"id":     "12345",
	})
}

func handleServiceStatus(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, map[string]string{
		"service": "running",
		"version": "1.0.0",
	})
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "# HELP requests_total Total requests\nrequests_total 42\n")
}

func handleReadiness(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "ready")
}

func handleSecureData(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, map[string]string{
		"data":     "top secret",
		"security": "maximum",
	})
}

func handleSecureAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, map[string]string{
		"admin": "panel",
		"users": "5",
	})
}

func handlePublicData(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, map[string]string{
		"message": "This is public data",
		"access":  "open",
	})
}

func handleProtectedData(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, map[string]string{
		"message": "This is protected data",
		"access":  "authenticated",
	})
}

func handleAdminData(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, map[string]string{
		"message": "This is admin data",
		"access":  "admin-only",
	})
}
