package servex

import (
	"time"
)

// PresetOptions provides common server configurations for different use cases.
// These presets combine multiple options to create ready-to-use server setups.

// DevelopmentPreset returns options suitable for development environment.
// Features: basic logging, no security restrictions, no rate limiting.
func DevelopmentPreset() []Option {
	return []Option{
		WithReadTimeout(30 * time.Second),
		WithIdleTimeout(60 * time.Second),
		WithHealthEndpoint(),
		WithNoLogClientErrors(), // Don't clutter logs with 4xx errors during dev
	}
}

// ProductionPreset returns options suitable for production environment.
// Features: security headers, rate limiting, request logging, health endpoints.
func ProductionPreset() []Option {
	return []Option{
		WithReadTimeout(10 * time.Second),
		WithReadHeaderTimeout(5 * time.Second),
		WithIdleTimeout(120 * time.Second),

		// Security
		WithStrictSecurityHeaders(),
		WithRemoveHeaders("Server", "X-Powered-By"),

		// Rate limiting - conservative defaults
		WithRPS(100), // 100 requests per second

		// Health and monitoring
		WithHealthEndpoint(),
		WithHealthPath("/health"),

		// Security exclusions for monitoring
		WithSecurityExcludePaths("/health", "/metrics", "/.well-known/"),
		WithRateLimitExcludePaths("/health", "/metrics"),
	}
}

// APIServerPreset returns options for a typical REST API server.
// Features: JWT auth, API rate limiting, security headers, CORS-friendly.
func APIServerPreset() []Option {
	return []Option{
		WithReadTimeout(15 * time.Second),
		WithIdleTimeout(90 * time.Second),

		// Security headers with API-friendly settings
		WithSecurityHeaders(),
		WithContentSecurityPolicy("default-src 'none'"), // APIs don't need CSP typically
		WithCustomHeaders(map[string]string{
			"X-API-Version": "v1.0",
		}),

		// Rate limiting suitable for APIs
		WithRPM(1000), // 1000 requests per minute per client
		WithBurstSize(50),

		// Health endpoints
		WithHealthEndpoint(),
		WithHealthPath("/api/health"),

		// Exclude health from security restrictions
		WithSecurityExcludePaths("/api/health"),
		WithRateLimitExcludePaths("/api/health"),
	}
}

// WebAppPreset returns options for serving web applications.
// Features: web security headers, content protection, static file friendly.
func WebAppPreset() []Option {
	return []Option{
		WithReadTimeout(30 * time.Second),
		WithIdleTimeout(180 * time.Second),

		// Web security headers
		WithStrictSecurityHeaders(),
		WithContentSecurityPolicy(
			"default-src 'self'; " +
				"script-src 'self' 'unsafe-inline'; " +
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
				"font-src 'self' https://fonts.gstatic.com; " +
				"img-src 'self' data: https:; " +
				"connect-src 'self'",
		),

		// Rate limiting for web apps
		WithRPS(50), // 50 requests per second per user

		// Health endpoint
		WithHealthEndpoint(),

		// Exclude common web assets from restrictions
		WithSecurityExcludePaths("/health", "/favicon.ico", "/robots.txt", "/.well-known/"),
		WithRateLimitExcludePaths("/health", "/favicon.ico", "/robots.txt", "/static/"),
	}
}

// MicroservicePreset returns options for microservice environments.
// Features: minimal security (behind gateway), fast timeouts, health checks.
func MicroservicePreset() []Option {
	return []Option{
		WithReadTimeout(5 * time.Second),
		WithReadHeaderTimeout(2 * time.Second),
		WithIdleTimeout(30 * time.Second),

		// Minimal security (assuming behind API gateway)
		WithSecurityHeaders(), // Basic headers only
		WithRemoveHeaders("Server"),

		// Conservative rate limiting (assuming gateway handles this)
		WithRPS(200),

		// Health and monitoring
		WithHealthEndpoint(),
		WithHealthPath("/health"),

		// Exclude monitoring from restrictions
		WithSecurityExcludePaths("/health", "/metrics", "/ready"),
		WithRateLimitExcludePaths("/health", "/metrics", "/ready"),
	}
}

// HighSecurityPreset returns options for high-security applications.
// Features: strict security headers, request filtering, comprehensive rate limiting.
func HighSecurityPreset() []Option {
	return []Option{
		WithReadTimeout(10 * time.Second),
		WithReadHeaderTimeout(3 * time.Second),
		WithIdleTimeout(60 * time.Second),

		// Strict security
		WithStrictSecurityHeaders(),
		WithHSTSHeader(31536000, true, true), // 1 year HSTS with preload
		WithRemoveHeaders("Server", "X-Powered-By", "X-AspNet-Version"),

		// Request filtering
		WithBlockedUserAgentsRegex(
			".*[Bb]ot.*",     // Block bots
			".*[Ss]craper.*", // Block scrapers
			"curl.*",         // Block curl
		),
		WithBlockedQueryParams(map[string][]string{
			"debug": {"true", "1", "on"},
			"test":  {"true", "1", "on"},
			"admin": {"true", "1", "on"},
		}),

		// Aggressive rate limiting
		WithRPS(20), // 20 requests per second
		WithBurstSize(5),

		// Health endpoint only
		WithHealthEndpoint(),
		WithSecurityExcludePaths("/health"),
		WithRateLimitExcludePaths("/health"),
		WithFilterExcludePaths("/health"),
	}
}

// MinimalPreset returns the most basic server configuration.
// Features: just essential timeouts and health check.
func MinimalPreset() []Option {
	return []Option{
		WithReadTimeout(30 * time.Second),
		WithHealthEndpoint(),
	}
}

// QuickTLSPreset returns options for quick SSL/TLS setup.
// Use with WithCertificateFromFile() for complete HTTPS setup.
func QuickTLSPreset(certFile, keyFile string) []Option {
	return append(ProductionPreset(),
		WithCertificateFromFile(certFile, keyFile),
		WithHSTSHeader(31536000, true, false), // 1 year HSTS
	)
}

// AuthAPIPreset returns options for an API with JWT authentication.
// Use with WithAuth() or WithAuthMemoryDatabase() to enable authentication.
func AuthAPIPreset() []Option {
	return append(APIServerPreset(),
		WithAuthBasePath("/api/v1/auth"),
		WithAuthInitialRoles(UserRole("user")),                 // Default role for new users
		WithAuthTokensDuration(15*time.Minute, 7*24*time.Hour), // 15min access, 7 day refresh
		WithNoRateInAuthRoutes(),                               // Don't rate limit auth routes separately
	)
}
