package servex


// WithCORSConfig sets the complete CORS configuration.
// This allows fine-grained control over all CORS settings at once.
//
// Example:
//
//	corsConfig := servex.CORSConfig{
//		Enabled: true,
//		AllowOrigins: []string{"https://example.com", "https://app.example.com"},
//		AllowMethods: []string{GET, POST, PUT, DELETE, OPTIONS},
//		AllowHeaders: []string{"Content-Type", "Authorization"},
//		AllowCredentials: true,
//		MaxAge: 3600,
//	}
//
//	server := servex.New(servex.WithCORSConfig(corsConfig))
//
// Use this when you need to configure multiple CORS settings at once
// or when loading configuration from files or environment variables.
func WithCORSConfig(cors CORSConfig) Option {
	return func(op *Options) {
		op.CORS = cors
	}
}

// WithCORS enables CORS with permissive defaults suitable for development.
// This allows all origins, methods, and headers with credentials disabled.
//
// Example:
//
//	// Enable CORS with permissive defaults
//	server := servex.New(servex.WithCORS())
//
//	// Equivalent to:
//	server := servex.New(servex.WithCORSConfig(servex.CORSConfig{
//		Enabled: true,
//		AllowOrigins: []string{"*"},
//		AllowMethods: []string{GET, POST, PUT, DELETE, OPTIONS},
//		AllowHeaders: []string{"Content-Type", "Authorization", "X-Requested-With"},
//		AllowCredentials: false,
//		MaxAge: 3600,
//	}))
//
// Security considerations:
//   - This is permissive and suitable for development
//   - For production, use specific origins with WithCORSAllowOrigins()
//   - Never use this with credentials in production
//
// For production use, configure specific origins:
//
//	server := servex.New(
//		servex.WithCORS(),
//		servex.WithCORSAllowOrigins("https://myapp.com"),
//		servex.WithCORSAllowCredentials(true),
//	)
func WithCORS() Option {
	return func(op *Options) {
		op.CORS.Enabled = true
		op.CORS.AllowOrigins = []string{"*"}
		op.CORS.AllowMethods = []string{GET, POST, PUT, DELETE, OPTIONS}
		op.CORS.AllowHeaders = []string{"Content-Type", "Authorization", "X-Requested-With"}
		op.CORS.AllowCredentials = false
		op.CORS.MaxAge = 3600
	}
}

// WithCORSAllowOrigins sets the allowed origins for CORS requests.
// This specifies which domains are allowed to make cross-origin requests to your server.
//
// Example:
//
//	// Allow specific origins
//	server := servex.New(servex.WithCORSAllowOrigins(
//		"https://myapp.com",
//		"https://admin.myapp.com",
//	))
//
//	// Development setup with local origins
//	server := servex.New(servex.WithCORSAllowOrigins(
//		"http://localhost:3000",
//		"http://localhost:8080",
//		"https://dev.myapp.com",
//	))
//
//	// Production API serving multiple frontends
//	server := servex.New(servex.WithCORSAllowOrigins(
//		"https://app.example.com",
//		"https://admin.example.com",
//		"https://mobile.example.com",
//	))
//
// Security best practices:
//   - Always specify exact origins in production
//   - Include protocol (https://) and port if non-standard
//   - Never use "*" with credentials enabled
//   - Use environment variables for different environments
//
// This automatically enables CORS if not already enabled.
func WithCORSAllowOrigins(origins ...string) Option {
	return func(op *Options) {
		op.CORS.Enabled = true
		op.CORS.AllowOrigins = origins
	}
}

// WithCORSAllowMethods sets the allowed HTTP methods for CORS requests.
// This specifies which HTTP methods are allowed in cross-origin requests.
//
// Example:
//
//	// Full REST API support
//	server := servex.New(servex.WithCORSAllowMethods(
//		GET, POST, PUT, DELETE, PATCH, OPTIONS,
//	))
//
//	// Read-only API
//	server := servex.New(servex.WithCORSAllowMethods(GET, "HEAD", OPTIONS))
//
//	// Create and read operations only
//	server := servex.New(servex.WithCORSAllowMethods(GET, POST, OPTIONS))
//
// Common method combinations:
//   - REST API: GET, POST, PUT, DELETE, PATCH, OPTIONS
//   - Read-only: GET, HEAD, OPTIONS
//   - Read/Create: GET, POST, OPTIONS
//   - File API: GET, POST, PUT, DELETE, OPTIONS
//
// Notes:
//   - OPTIONS is automatically handled for preflight requests
//   - GET and HEAD are "simple" methods that don't trigger preflight
//   - Other methods (POST, PUT, DELETE, PATCH) trigger preflight requests
//
// This automatically enables CORS if not already enabled.
func WithCORSAllowMethods(methods ...string) Option {
	return func(op *Options) {
		op.CORS.Enabled = true
		op.CORS.AllowMethods = methods
	}
}

// WithCORSAllowHeaders sets the allowed headers for CORS requests.
// This specifies which headers can be sent in cross-origin requests.
//
// Example:
//
//	// API with authentication and custom headers
//	server := servex.New(servex.WithCORSAllowHeaders(
//		"Content-Type",
//		"Authorization",
//		"X-API-Key",
//		"X-Requested-With",
//	))
//
//	// Basic web application headers
//	server := servex.New(servex.WithCORSAllowHeaders(
//		"Content-Type",
//		"Authorization",
//		"X-CSRF-Token",
//	))
//
//	// Allow all headers (less secure but convenient for development)
//	server := servex.New(servex.WithCORSAllowHeaders("*"))
//
// Common header combinations:
//   - Basic API: Content-Type, Authorization
//   - Web app: Content-Type, Authorization, X-Requested-With, X-CSRF-Token
//   - File upload: Content-Type, Authorization, X-Filename
//   - Custom API: Content-Type, Authorization, X-API-Key, X-Client-Version
//
// Standard headers that don't need explicit allowance:
//   - Accept, Accept-Language, Content-Language
//   - Content-Type (for simple values)
//
// This automatically enables CORS if not already enabled.
func WithCORSAllowHeaders(headers ...string) Option {
	return func(op *Options) {
		op.CORS.Enabled = true
		op.CORS.AllowHeaders = headers
	}
}

// WithCORSExposeHeaders sets which response headers are exposed to client-side JavaScript.
// This allows browsers to access specific response headers in cross-origin requests.
//
// Example:
//
//	// Expose pagination headers
//	server := servex.New(servex.WithCORSExposeHeaders(
//		"X-Total-Count",
//		"X-Page-Count",
//		"X-Per-Page",
//	))
//
//	// Expose file download headers
//	server := servex.New(servex.WithCORSExposeHeaders(
//		"Content-Length",
//		"Content-Range",
//		"Content-Disposition",
//	))
//
//	// Expose custom API metadata
//	server := servex.New(servex.WithCORSExposeHeaders(
//		"X-Rate-Limit-Remaining",
//		"X-Rate-Limit-Reset",
//		"Location",
//	))
//
// Common headers to expose:
//   - Pagination: X-Total-Count, X-Page-Count, X-Per-Page
//   - Rate limiting: X-Rate-Limit-Remaining, X-Rate-Limit-Reset
//   - File operations: Content-Length, Content-Range, Content-Disposition
//   - Resource creation: Location
//   - API metadata: X-API-Version, X-Request-ID
//
// This automatically enables CORS if not already enabled.
func WithCORSExposeHeaders(headers ...string) Option {
	return func(op *Options) {
		op.CORS.Enabled = true
		op.CORS.ExposeHeaders = headers
	}
}

// WithCORSAllowCredentials enables sending credentials (cookies, auth headers) in CORS requests.
// When enabled, browsers will include credentials in cross-origin requests.
//
// Example:
//
//	// Enable credentials for authenticated API
//	server := servex.New(
//		servex.WithCORSAllowOrigins("https://app.example.com"),
//		servex.WithCORSAllowCredentials(true),
//	)
//
//	// Session-based authentication with cookies
//	server := servex.New(
//		servex.WithCORSAllowOrigins("https://frontend.example.com"),
//		servex.WithCORSAllowCredentials(true),
//		servex.WithCORSAllowHeaders("Content-Type", "X-CSRF-Token"),
//	)
//
// Security requirements when enabled:
//   - Cannot use "*" for AllowOrigins (must specify exact origins)
//   - Increases CSRF attack surface (implement CSRF protection)
//   - Consider implementing additional security measures
//
// Use cases:
//   - Session-based authentication with cookies
//   - APIs that require Authorization headers
//   - Single sign-on (SSO) systems
//   - Applications with cross-domain user sessions
//
// This automatically enables CORS if not already enabled.
func WithCORSAllowCredentials() Option {
	return func(op *Options) {
		op.CORS.Enabled = true
		op.CORS.AllowCredentials = true
	}
}

// WithCORSMaxAge sets how long browsers can cache CORS preflight responses.
// This reduces the number of preflight requests by caching the CORS policy.
//
// Example:
//
//	// Cache for 1 hour (good for development)
//	server := servex.New(servex.WithCORSMaxAge(3600))
//
//	// Cache for 1 day (good for production)
//	server := servex.New(servex.WithCORSMaxAge(86400))
//
//	// No caching (force preflight for every request)
//	server := servex.New(servex.WithCORSMaxAge(0))
//
//	// Cache for 1 week (very stable API)
//	server := servex.New(servex.WithCORSMaxAge(604800))
//
// Common values:
//   - Development: 3600 (1 hour) - allows quick policy changes
//   - Production: 86400 (1 day) - good balance of performance and flexibility
//   - Stable API: 604800 (1 week) - maximum performance
//   - Testing: 0 - no caching for immediate policy changes
//
// Benefits of longer caching:
//   - Fewer preflight requests (better performance)
//   - Reduced server load
//   - Better user experience
//
// Benefits of shorter caching:
//   - Policy changes take effect quickly
//   - Better for development and testing
//   - More responsive to security updates
//
// This automatically enables CORS if not already enabled.
func WithCORSMaxAge(seconds int) Option {
	return func(op *Options) {
		op.CORS.Enabled = true
		op.CORS.MaxAge = seconds
	}
}

// WithCORSExcludePaths sets paths that should be excluded from CORS headers.
// Requests to these paths will not have CORS headers applied.
//
// Example:
//
//	// Exclude internal and admin endpoints
//	server := servex.New(
//		servex.WithCORS(),
//		servex.WithCORSExcludePaths("/internal/*", "/admin/*"),
//	)
//
//	// Exclude non-browser endpoints
//	server := servex.New(
//		servex.WithCORS(),
//		servex.WithCORSExcludePaths("/webhooks/*", "/api/internal/*"),
//	)
//
// Common exclusions:
//   - Internal APIs: "/internal/*", "/private/*"
//   - Admin interfaces: "/admin/*", "/management/*"
//   - Webhooks: "/webhooks/*", "/callbacks/*"
//   - Health checks: "/health", "/ping", "/metrics"
//   - Server-to-server: "/api/internal/*"
//
// Path matching supports wildcards (*) for pattern matching.
// Use when different endpoints need different CORS policies or
// when some endpoints should not be accessible to browsers.
//
// This automatically enables CORS if not already enabled.
func WithCORSExcludePaths(paths ...string) Option {
	return func(op *Options) {
		op.CORS.Enabled = true
		op.CORS.ExcludePaths = paths
	}
}

// WithCORSIncludePaths sets paths that should have CORS headers applied.
// If set, only requests to these paths will receive CORS headers.
//
// Example:
//
//	// CORS only for API endpoints
//	server := servex.New(
//		servex.WithCORS(),
//		servex.WithCORSIncludePaths("/api/*"),
//	)
//
//	// CORS for specific services
//	server := servex.New(
//		servex.WithCORS(),
//		servex.WithCORSIncludePaths("/api/public/*", "/auth/*"),
//	)
//
//	// CORS for user-facing endpoints only
//	server := servex.New(
//		servex.WithCORS(),
//		servex.WithCORSIncludePaths("/app/*", "/public/*"),
//	)
//
// Use cases:
//   - Mixed application: Only API endpoints need CORS
//   - Gradual CORS adoption: Start with specific endpoints
//   - Security: Limit CORS to necessary endpoints only
//   - Performance: Reduce header overhead on internal endpoints
//
// If both IncludePaths and ExcludePaths are set:
//  1. Paths must match IncludePaths to receive CORS headers
//  2. Paths in ExcludePaths are then excluded from CORS headers
//
// Path matching supports wildcards (*) for pattern matching.
// Leave empty to apply CORS to all paths (default behavior).
//
// This automatically enables CORS if not already enabled.
func WithCORSIncludePaths(paths ...string) Option {
	return func(op *Options) {
		op.CORS.Enabled = true
		op.CORS.IncludePaths = paths
	}
}

// WithCacheConfig sets the cache control configuration for HTTP responses.
// This allows you to configure all cache-related settings at once.
//
// Example:
//
//	cacheConfig := servex.CacheConfig{
//		Enabled:      true,
//		CacheControl: "public, max-age=3600",
//		Vary:         "Accept-Encoding",
//	}
//	server := servex.New(servex.WithCacheConfig(cacheConfig))
//
// Use this when you need to configure multiple cache settings or when
// loading configuration from external sources like config files.
