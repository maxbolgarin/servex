package servex

import (
	"crypto/tls"
	"time"
)

// MergeWithPreset merges a preset with additional options.
func MergeWithPreset(preset []Option, opts ...Option) []Option {
	return append(preset, opts...)
}

// MergePresets merges multiple presets into a single slice of options.
func MergePresets(presets ...[]Option) []Option {
	var opts []Option
	for _, preset := range presets {
		opts = append(opts, preset...)
	}
	return opts
}

// PresetOptions provides common server configurations for different use cases.
// These presets combine multiple options to create ready-to-use server setups.

// DevelopmentPreset returns options suitable for development environment.
// Features: basic logging, no security restrictions, no rate limiting, detailed error reporting.
func DevelopmentPreset() []Option {
	return []Option{
		WithHealthEndpoint(),
		WithDefaultMetrics(),    // Enable metrics for development monitoring
		WithSendErrorToClient(), // Send error to client to see them in browser and better debug
	}
}

// ProductionPreset returns options suitable for production environment.
// Features: security headers, CSRF protection, rate limiting, request logging, health endpoints, metrics, compression.
func ProductionPreset(cert tls.Certificate) []Option {
	return []Option{
		WithReadTimeout(10 * time.Second),
		WithReadHeaderTimeout(5 * time.Second),
		WithIdleTimeout(120 * time.Second),
		WithCertificate(cert),

		// Security with CSRF protection
		WithStrictSecurityHeaders(),
		WithCSRFProtection(),
		WithRemoveHeaders("Server", "X-Powered-By"),
		WithHTTPSRedirect(),

		// Request size limits for production security
		WithRequestSizeLimits(),

		// Rate limiting - conservative defaults
		WithRPS(100), // 100 requests per second

		// Compression for bandwidth optimization
		WithCompression(),
		WithCompressionLevel(6), // Balanced compression

		// Health and monitoring
		WithHealthEndpoint(),
		WithDefaultMetrics(),

		// Audit logging for security events
		WithDefaultAuditLogger(),

		// Security exclusions for monitoring
		WithSecurityExcludePaths("/health", "/metrics", "/.well-known/"),
		WithRateLimitExcludePaths("/health", "/metrics"),
		WithCompressionExcludePaths("/metrics"), // Exclude metrics from compression for clarity
	}
}

// APIServerPreset returns options for a typical REST API server.
// Features: JWT auth support, API rate limiting, security headers, CORS-friendly, request size limits, compression.
func APIServerPreset() []Option {
	return []Option{
		WithReadTimeout(15 * time.Second),
		WithIdleTimeout(90 * time.Second),

		// Security headers with API-friendly settings
		WithSecurityHeaders(),
		WithContentSecurityPolicy("default-src 'none'"), // APIs don't need CSP typically

		// Request size limits appropriate for APIs
		WithMaxRequestBodySize(10 << 20), // 10 MB
		WithMaxJSONBodySize(1 << 20),     // 1 MB
		WithEnableRequestSizeLimits(true),

		// Rate limiting suitable for APIs
		WithRPM(1000), // 1000 requests per minute per client
		WithBurstSize(50),

		// Compression for API responses
		WithCompression(),
		WithCompressionLevel(4), // Fast compression for APIs

		// Cache control for API responses
		WithCacheAPI(300), // 5 minutes cache for stable API responses

		// Health endpoints
		WithHealthEndpoint(),
		WithDefaultMetrics(),

		// Audit logging for API security events
		WithDefaultAuditLogger(),

		// Exclude health from security restrictions
		WithSecurityExcludePaths("/health", "/metrics"),
		WithRateLimitExcludePaths("/health", "/metrics"),
		WithCompressionExcludePaths("/metrics"), // Keep metrics uncompressed
	}
}

// WebAppPreset returns options for serving web applications.
// Features: web security headers, CSRF protection, content protection, static file friendly, size limits, compression.
func WebAppPreset(cert tls.Certificate) []Option {
	return []Option{
		WithReadTimeout(30 * time.Second),
		WithIdleTimeout(180 * time.Second),
		WithCertificate(cert),

		// Web security headers with CSRF protection
		WithStrictSecurityHeaders(),
		WithCSRFProtection(),
		WithCSRFTokenEndpoint("/csrf-token"), // Enable token endpoint for SPAs
		WithContentSecurityPolicy(
			"default-src 'self'; " +
				"script-src 'self' 'unsafe-inline'; " +
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
				"font-src 'self' https://fonts.gstatic.com; " +
				"img-src 'self' data: https:; " +
				"connect-src 'self'",
		),
		WithRemoveHeaders("Server", "X-Powered-By"),

		// Request size limits for web applications
		WithMaxRequestBodySize(50 << 20), // 50 MB for file uploads
		WithMaxJSONBodySize(5 << 20),     // 5 MB for JSON
		WithEnableRequestSizeLimits(true),

		// Rate limiting for web apps
		WithRPS(50), // 50 requests per second per user

		// Compression for web assets and API responses
		WithCompression(),
		WithCompressionLevel(6), // Balanced compression for web content

		// Health endpoint
		WithHealthEndpoint(),
		WithDefaultMetrics(),

		// Exclude common web assets from restrictions
		WithSecurityExcludePaths("/health", "/favicon.ico", "/robots.txt", "/.well-known/", "/csrf-token", "/metrics"),
		WithRateLimitExcludePaths("/health", "/favicon.ico", "/robots.txt", "/static/", "/csrf-token", "/metrics"),
		WithCompressionExcludePaths("/metrics"), // Keep metrics uncompressed for monitoring tools
	}
}

// MicroservicePreset returns options for microservice environments.
// Features: minimal security (behind gateway), fast timeouts, health checks, size limits.
func MicroservicePreset() []Option {
	return []Option{
		WithReadTimeout(5 * time.Second),
		WithReadHeaderTimeout(2 * time.Second),
		WithIdleTimeout(30 * time.Second),

		// Minimal security (assuming behind API gateway)
		WithSecurityHeaders(), // Basic headers only

		// Request size limits for microservices
		WithMaxRequestBodySize(5 << 20), // 5 MB
		WithMaxJSONBodySize(1 << 20),    // 1 MB
		WithEnableRequestSizeLimits(true),

		// Conservative rate limiting (assuming gateway handles this)
		WithRPS(200),

		// Health and monitoring
		WithHealthEndpoint(),
		WithDefaultMetrics(),

		// Exclude monitoring from restrictions
		WithSecurityExcludePaths("/health", "/metrics"),
		WithRateLimitExcludePaths("/health", "/metrics"),
	}
}

// HighSecurityPreset returns options for high-security applications.
// Features: strict security headers, CSRF protection, request filtering, comprehensive rate limiting, audit logging.
func HighSecurityPreset(cert tls.Certificate) []Option {
	return []Option{
		WithReadTimeout(10 * time.Second),
		WithReadHeaderTimeout(3 * time.Second),
		WithIdleTimeout(60 * time.Second),
		WithCertificate(cert),

		// Strict security with CSRF protection
		WithStrictSecurityHeaders(),
		WithCSRFProtection(),
		WithCSRFCookieHttpOnly(true),         // Maximum security for CSRF cookies
		WithCSRFCookieSameSite("Strict"),     // Strictest SameSite policy
		WithHSTSHeader(31536000, true, true), // 1 year HSTS with preload
		WithRemoveHeaders("Server", "X-Powered-By"),

		// Strict request size limits
		WithStrictRequestSizeLimits(), // Smaller limits for high security

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

		// Comprehensive audit logging for security events
		WithDefaultAuditLogger(),
		WithAuditLogHeaders(true), // Include headers in audit logs

		// Health endpoint only
		WithHealthEndpoint(),
		WithSecurityExcludePaths("/health"),
		WithRateLimitExcludePaths("/health"),
		WithFilterExcludePaths("/health"),
	}
}

// TLSPreset returns options for quick SSL/TLS setup.
// Provide cert object or cert and key files.
func TLSPreset(certFile, keyFile string, cert ...tls.Certificate) []Option {
	options := []Option{
		WithHTTPSRedirect(),
		WithHSTSHeader(31536000, true, true), // 1 year HSTS with preload
	}
	if len(cert) > 0 {
		options = append(options, WithCertificate(cert[0]))
	}
	if certFile != "" && keyFile != "" {
		options = append(options, WithCertificateFromFile(certFile, keyFile))
	}
	return options
}
