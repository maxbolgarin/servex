package main

import (
	"crypto/tls"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex"
)

// This file demonstrates all configuration options organized by category
// Use this as a reference guide for configuring your servex server

func configurationGuideMain() {
	// 1. Quick Start with Presets
	quickStartWithPresets()

	// 2. Basic Server Configuration
	basicServerConfiguration()

	// 3. TLS/SSL Configuration
	tlsConfiguration()

	// 4. Timeout Configuration
	timeoutConfiguration()

	// 5. Authentication Configuration
	authenticationConfiguration()

	// 6. Rate Limiting Configuration
	rateLimitingConfiguration()

	// 7. Security Headers Configuration
	securityHeadersConfiguration()

	// 8. Request Filtering Configuration
	requestFilteringConfiguration()

	// 9. Logging Configuration
	loggingConfiguration()

	// 10. Custom Headers and Middleware
	customHeadersConfiguration()

	// 11. Complete Production Configuration
	completeProductionConfiguration()
}

// 1. Quick Start with Presets
func quickStartWithPresets() {
	// === 1. Quick Start with Presets ===
	// Presets combine multiple options for common use cases:

	// Development - minimal setup, no restrictions
	server, err := servex.New(servex.DevelopmentPreset()...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server
	// DevelopmentPreset(): Basic setup for development

	// Production - security, rate limiting, monitoring
	server, err = servex.New(servex.ProductionPreset()...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server
	// ProductionPreset(): Full production setup with security

	// API Server - optimized for REST APIs
	server, err = servex.New(servex.APIServerPreset()...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server
	// APIServerPreset(): Optimized for REST API servers

	// Web App - security headers for web applications
	server, err = servex.New(servex.WebAppPreset()...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server
	// WebAppPreset(): Web application with CSP and security

	// Microservice - fast timeouts, minimal security
	server, err = servex.New(servex.MicroservicePreset()...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server
	// MicroservicePreset(): Optimized for microservices

	// High Security - maximum security features
	server, err = servex.New(servex.HighSecurityPreset()...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server
	// HighSecurityPreset(): Maximum security configuration

	// SSL Setup - production + SSL certificate
	server, err = servex.New(servex.QuickTLSPreset("cert.pem", "key.pem")...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server
	// QuickTLSPreset(): Production + SSL certificate

	// Auth API - API server + JWT authentication
	server, err = servex.New(append(servex.AuthAPIPreset(),
		servex.WithAuthMemoryDatabase(),
	)...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server
	// AuthAPIPreset(): API server + JWT authentication
}

// 2. Basic Server Configuration
func basicServerConfiguration() {
	// === 2. Basic Server Configuration ===
	// Essential server options:

	server, err := servex.New(
		// Health check endpoint (recommended for all servers)
		servex.WithHealthEndpoint(),
		servex.WithHealthPath("/health"), // Custom health path

		// Custom headers for all responses
		servex.WithCustomHeaders(map[string]string{
			"X-API-Version":  "v1.0",
			"X-Service-Name": "my-service",
		}),

		// Remove server identification headers
		servex.WithRemoveHeaders("Server", "X-Powered-By"),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server

	// ✓ Health endpoint at /health
	// ✓ Custom headers added to all responses
	// ✓ Server identification headers removed
	// ✓ Internal errors not exposed to clients
}

// 3. TLS/SSL Configuration
func tlsConfiguration() {
	// === 3. TLS/SSL Configuration ===
	// Options for HTTPS setup:

	// Option 1: Certificate from files
	server1, err := servex.New(
		servex.WithCertificateFromFile("server.crt", "server.key"),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server1
	// Method 1: Certificate from files

	// Option 2: Certificate object
	cert, _ := tls.LoadX509KeyPair("server.crt", "server.key")
	server2, err := servex.New(
		servex.WithCertificate(cert),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server2
	// Method 2: Pre-loaded certificate object

	// Option 3: Certificate pointer
	server3, err := servex.New(
		servex.WithCertificatePtr(&cert),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server3
	// Method 3: Certificate pointer

	// With HSTS header for security
	server4, err := servex.New(
		servex.WithCertificateFromFile("server.crt", "server.key"),
		servex.WithHSTSHeader(31536000, true, true), // 1 year, includeSubdomains, preload
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server4
	// ✓ HSTS header for enhanced security
}

// 4. Timeout Configuration
func timeoutConfiguration() {
	// === 4. Timeout Configuration ===
	// Control server timeouts:

	server, err := servex.New(
		// Read timeout: maximum duration for reading the entire request
		servex.WithReadTimeout(30*time.Second),

		// Read header timeout: maximum duration for reading request headers
		servex.WithReadHeaderTimeout(10*time.Second),

		// Idle timeout: maximum time to wait for the next request when keep-alives are enabled
		servex.WithIdleTimeout(120*time.Second),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server

	// ReadTimeout: 30s (entire request)
	// ReadHeaderTimeout: 10s (headers only)
	// IdleTimeout: 120s (keep-alive)

	// Recommended timeouts by use case:
	// - API servers: Read 15s, Header 5s, Idle 90s
	// - Web apps: Read 30s, Header 10s, Idle 180s
	// - Microservices: Read 5s, Header 2s, Idle 30s
	// - Development: Read 30s, Header 10s, Idle 60s
}

// 5. Authentication Configuration
func authenticationConfiguration() {
	// === 5. Authentication Configuration ===
	// JWT-based authentication setup:

	// Basic auth with memory database
	server1, err := servex.New(
		servex.WithAuthMemoryDatabase(),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server1
	// Method 1: In-memory database (development/testing)

	// Custom database
	// server2 := servex.New(
	//     servex.WithAuth(myCustomDatabase),
	// )

	// Full auth configuration
	server3, err := servex.New(
		servex.WithAuthMemoryDatabase(),

		// JWT secrets (hex encoded, will be generated if not provided)
		servex.WithAuthKey("access-secret-hex", "refresh-secret-hex"),

		// Token durations
		servex.WithAuthTokensDuration(
			15*time.Minute, // Access token: 15 minutes
			7*24*time.Hour, // Refresh token: 7 days
		),

		// Auth API configuration
		servex.WithAuthBasePath("/api/v1/auth"),
		servex.WithAuthIssuer("my-service"),
		servex.WithAuthRefreshTokenCookieName("_refresh_token"),

		// Initial users
		servex.WithAuthInitialUsers(
			servex.InitialUser{
				Username: "admin",
				Password: "admin123",
				Roles:    []servex.UserRole{servex.UserRole("admin")},
			},
		),

		// Default roles for new registrations
		servex.WithAuthInitialRoles(servex.UserRole("user")),

		// Don't register default auth routes (if you want custom routes)
		// servex.WithAuthNotRegisterRoutes(true),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server3

	// ✓ JWT access tokens (15 min) and refresh tokens (7 days)
	// ✓ Auth endpoints at /api/v1/auth/*
	// ✓ Initial admin user created
	// ✓ Role-based access control

	// Available auth endpoints:
	// - POST /api/v1/auth/register
	// - POST /api/v1/auth/login
	// - POST /api/v1/auth/refresh
	// - POST /api/v1/auth/logout
	// - GET /api/v1/auth/me

	// Simple token authentication (alternative to JWT)
	server4, err := servex.New(
		servex.WithAuthToken("my-secret-token"),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server4
	// Alternative: Simple token authentication (Authorization: Bearer token)
}

// 6. Rate Limiting Configuration
func rateLimitingConfiguration() {
	// === 6. Rate Limiting Configuration ===
	// Control request rates:

	// Simple rate limiting
	server1, err := servex.New(
		servex.WithRPS(100), // 100 requests per second
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server1
	// Method 1: Simple RPS (requests per second)

	server2, err := servex.New(
		servex.WithRPM(1000), // 1000 requests per minute
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server2
	// Method 2: Simple RPM (requests per minute)

	// Advanced rate limiting
	server3, err := servex.New(
		servex.WithRequestsPerInterval(500, 5*time.Minute), // 500 requests per 5 minutes
		servex.WithBurstSize(50),                           // Allow burst of 50 requests

		// Custom response
		servex.WithRateLimitStatusCode(429),
		servex.WithRateLimitMessage("Too many requests, please slow down"),

		// Path configuration
		servex.WithRateLimitExcludePaths("/health", "/metrics"),
		servex.WithRateLimitIncludePaths("/api/v1/*"), // Only rate limit API paths

		// Proxy configuration for real IP detection
		servex.WithRateLimitTrustedProxies("10.0.0.0/8", "172.16.0.0/12"),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server3

	// ✓ Custom intervals and burst sizes
	// ✓ Path-specific rate limiting
	// ✓ Proxy-aware IP detection
	// ✓ Custom error responses
}

// 7. Security Headers Configuration
func securityHeadersConfiguration() {
	// === 7. Security Headers Configuration ===
	// Protect against common web vulnerabilities:

	// Basic security headers
	server1, err := servex.New(
		servex.WithSecurityHeaders(),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server1
	// Method 1: Basic security headers (recommended defaults)

	// Strict security headers
	server2, err := servex.New(
		servex.WithStrictSecurityHeaders(),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server2
	// Method 2: Strict security headers (high-security apps)

	// Custom security configuration
	server3, err := servex.New(
		servex.WithContentSecurityPolicy(
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' https://cdn.example.com; "+
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
		),
		servex.WithHSTSHeader(31536000, true, true), // 1 year HSTS with preload

		// Path configuration
		servex.WithSecurityExcludePaths("/health", "/api/webhook"),
		servex.WithSecurityIncludePaths("/app/*", "/api/v1/*"),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server3

	// ✓ Content Security Policy (CSP)
	// ✓ HTTP Strict Transport Security (HSTS)
	// ✓ X-Frame-Options, X-Content-Type-Options
	// ✓ Path-specific application

	// Security headers applied:
	// - Content-Security-Policy
	// - Strict-Transport-Security
	// - X-Content-Type-Options: nosniff
	// - X-Frame-Options: DENY
	// - X-XSS-Protection: 1; mode=block
	// - Referrer-Policy: strict-origin-when-cross-origin
}

// 8. Request Filtering Configuration
func requestFilteringConfiguration() {
	// === 8. Request Filtering Configuration ===
	// Filter requests based on IP, User-Agent, headers, etc.:

	server, err := servex.New(
		// IP filtering
		servex.WithAllowedIPs("192.168.1.0/24", "10.0.0.0/8"),
		servex.WithBlockedIPs("203.0.113.1", "198.51.100.0/24"),

		// User-Agent filtering
		servex.WithBlockedUserAgents("BadBot/1.0"),
		servex.WithBlockedUserAgentsRegex(".*[Bb]ot.*", ".*[Ss]craper.*"),
		servex.WithAllowedUserAgentsRegex("Mozilla.*Chrome.*", "Mozilla.*Firefox.*"),

		// Header filtering
		servex.WithAllowedHeaders(map[string][]string{
			"X-API-Key": {"api-key-12345", "api-key-67890"},
		}),
		servex.WithAllowedHeadersRegex(map[string][]string{
			"Authorization": {"Bearer [a-zA-Z0-9]+"},
		}),
		servex.WithBlockedHeaders(map[string][]string{
			"X-Debug": {"true", "1"},
		}),

		// Query parameter filtering
		servex.WithAllowedQueryParams(map[string][]string{
			"version": {"v1", "v2"},
		}),
		servex.WithBlockedQueryParams(map[string][]string{
			"debug": {"true", "1"},
			"admin": {"true", "1"},
		}),

		// Path configuration
		servex.WithFilterExcludePaths("/health", "/public/*"),
		servex.WithFilterIncludePaths("/api/v1/secure/*"),

		// Custom response
		servex.WithFilterStatusCode(403),
		servex.WithFilterMessage("Request blocked by security policy"),

		// Proxy configuration
		servex.WithFilterTrustedProxies("10.0.0.0/8"),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server

	// ✓ IP-based filtering with CIDR support
	// ✓ User-Agent filtering with regex patterns
	// ✓ Header and query parameter validation
	// ✓ Path-specific filtering
	// ✓ Proxy-aware real IP detection
}

// 9. Logging Configuration
func loggingConfiguration() {
	// === 9. Logging Configuration ===
	// Configure request and error logging:

	// Custom logger (must implement servex.Logger interface)
	logger := slog.New(slog.NewJSONHandler(nil, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	server, err := servex.New(
		// Main logger (for server events, errors, panics)
		servex.WithLogger(logger),

		// Request logger (for HTTP request logging)
		// servex.WithRequestLogger(myCustomRequestLogger),

		// Disable request logging entirely
		servex.WithDisableRequestLogging(),

		// Don't log 4xx client errors (reduces noise)
		servex.WithNoLogClientErrors(),

		// Send error details to client (only for development!)
		servex.WithSendErrorToClient(),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server
	_ = logger

	// ✓ Custom logger support
	// ✓ Separate request and error logging
	// ✓ Configurable client error logging
	// ✓ Error exposure control

	// Logger interface methods required:
	// - Debug(msg, ...args)
	// - Info(msg, ...args)
	// - Error(msg, ...args)
}

// 10. Custom Headers and Middleware
func customHeadersConfiguration() {
	// === 10. Custom Headers and Middleware ===
	// Add custom headers and remove unwanted ones:

	server, err := servex.New(
		// Add custom headers to all responses
		servex.WithCustomHeaders(map[string]string{
			"X-API-Version":     "v2.1.0",
			"X-Service-Name":    "user-service",
			"X-Rate-Limit-Info": "1000 requests per hour",
			"X-Powered-By":      "Servex",
			"Cache-Control":     "no-cache, no-store, must-revalidate",
		}),

		// Remove headers (security and cleanup)
		servex.WithRemoveHeaders(
			"Server",           // Remove server identification
			"X-Powered-By",     // Remove technology stack info
			"X-AspNet-Version", // Remove framework version
		),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	// Add custom middleware after server creation
	server.AddMiddlewares(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Custom middleware logic here
			w.Header().Set("X-Custom-Middleware", "active")
			next.ServeHTTP(w, r)
		})
	})

	_ = server

	// ✓ Custom headers added to all responses
	// ✓ Unwanted headers removed
	// ✓ Custom middleware support
}

// 11. Complete Production Configuration
func completeProductionConfiguration() {
	// === 11. Complete Production Configuration ===
	// Real-world production server setup:

	server, err := servex.New(
		// === BASIC SETUP ===
		// Timeouts
		servex.WithReadTimeout(10*time.Second),
		servex.WithReadHeaderTimeout(5*time.Second),
		servex.WithIdleTimeout(120*time.Second),

		// TLS
		servex.WithCertificateFromFile("/etc/ssl/certs/server.crt", "/etc/ssl/private/server.key"),

		// === SECURITY ===
		// Security headers
		servex.WithStrictSecurityHeaders(),
		servex.WithHSTSHeader(31536000, true, true), // 1 year HSTS with preload
		servex.WithContentSecurityPolicy(
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "+
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"img-src 'self' data: https:; "+
				"connect-src 'self' https://api.example.com",
		),

		// Request filtering
		servex.WithBlockedUserAgentsRegex(".*[Bb]ot.*", ".*[Ss]craper.*"),
		servex.WithBlockedQueryParams(map[string][]string{
			"debug": {"true", "1", "on"},
			"test":  {"true", "1", "on"},
		}),

		// === RATE LIMITING ===
		servex.WithRPS(100),
		servex.WithBurstSize(20),
		servex.WithRateLimitTrustedProxies("10.0.0.0/8", "172.16.0.0/12"),

		// === AUTHENTICATION ===
		servex.WithAuthMemoryDatabase(), // Use real database in production
		servex.WithAuthTokensDuration(15*time.Minute, 7*24*time.Hour),
		servex.WithAuthBasePath("/api/v1/auth"),
		servex.WithAuthInitialUsers(
			servex.InitialUser{
				Username: "admin",
				Password: "secure-random-password",
				Roles:    []servex.UserRole{servex.UserRole("admin")},
			},
		),

		// === MONITORING & HEALTH ===
		servex.WithHealthEndpoint(),
		servex.WithHealthPath("/health"),

		// === HEADERS ===
		servex.WithCustomHeaders(map[string]string{
			"X-API-Version":  "v1.0.0",
			"X-Service-Name": "production-api",
		}),
		servex.WithRemoveHeaders("Server", "X-Powered-By"),

		// === PATH EXCLUSIONS ===
		servex.WithSecurityExcludePaths("/health", "/metrics", "/.well-known/"),
		servex.WithRateLimitExcludePaths("/health", "/metrics"),
		servex.WithFilterExcludePaths("/health", "/metrics"),

		// === LOGGING ===
		servex.WithNoLogClientErrors(), // Don't log 4xx errors in production
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server

	// ✓ Complete production-ready configuration
	// ✓ Security: HTTPS, HSTS, CSP, request filtering
	// ✓ Performance: Rate limiting, timeouts
	// ✓ Authentication: JWT with role-based access
	// ✓ Monitoring: Health checks, custom headers
	// ✓ Logging: Structured logging with appropriate levels

	// To start this server:
	//
	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()
	//
	// err := server.StartWithShutdown(ctx, ":8080", ":8443")
	// if err != nil {
	//     log.Fatal("Server failed:", err)
	// }
}

// Example of combining preset with custom options
func presetWithCustomOptions() {
	// === Combining Presets with Custom Options ===
	// Start with a preset and add custom configuration:

	server, err := servex.New(append(
		servex.ProductionPreset(), // Start with production defaults

		// Add custom options
		servex.WithAuthMemoryDatabase(),
		servex.WithCustomHeaders(map[string]string{
			"X-Company": "ACME Corp",
		}),
		servex.WithBlockedUserAgentsRegex(".*malicious.*"),
	)...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	_ = server

	// ✓ Production preset + custom authentication
	// ✓ Production preset + custom headers
	// ✓ Production preset + additional security filtering

	// This approach gives you:
	// - Quick setup with sensible defaults
	// - Full customization capability
	// - Easy maintenance and updates
}
