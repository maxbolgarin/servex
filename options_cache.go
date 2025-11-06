package servex

import (
	"fmt"
	"net/http"
	"time"
)


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
func WithCacheConfig(cache CacheConfig) Option {
	return func(op *Options) {
		op.Cache = cache
	}
}

// WithCacheControl enables cache control headers and sets the Cache-Control header value.
// This is the most common way to enable basic caching.
//
// Example:
//
//	// Cache static assets for 1 hour
//	server := servex.New(servex.WithCacheControl("public, max-age=3600"))
//
//	// Disable caching for sensitive data
//	server := servex.New(servex.WithCacheControl("no-store"))
//
//	// Private cache for user-specific content
//	server := servex.New(servex.WithCacheControl("private, max-age=900"))
//
// Common Cache-Control values:
//   - "no-cache": Must revalidate before using cached copy
//   - "no-store": Do not cache at all (sensitive data)
//   - "public, max-age=3600": Public cache for 1 hour
//   - "private, max-age=900": Private cache for 15 minutes
//   - "public, max-age=31536000, immutable": Cache for 1 year (static assets)
func WithCacheControl(cacheControl string) Option {
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.CacheControl = cacheControl
	}
}

// WithCacheHeaders enables cache control headers with basic settings.
// This sets common cache control headers for typical web applications.
//
// Example:
//
//	// Enable basic caching with common defaults
//	server := servex.New(servex.WithCacheHeaders())
//
// This sets:
//   - Cache-Control: "public, max-age=3600" (1 hour)
//   - Vary: "Accept-Encoding" (for compression)
//
// Use this for quick setup with sensible defaults. For custom settings,
// use WithCacheControl() or WithCacheConfig() instead.
func WithCacheHeaders() Option {
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.CacheControl = "public, max-age=3600"
		op.Cache.Vary = "Accept-Encoding"
	}
}

// WithCacheExpires sets the Expires header for cache control.
// This provides a fallback for older HTTP/1.0 clients.
//
// Example:
//
//	// Set expiration time
//	expireTime := time.Now().Add(1 * time.Hour).Format(http.TimeFormat)
//	server := servex.New(servex.WithCacheExpires(expireTime))
//
//	// Combined with Cache-Control
//	server := servex.New(
//		servex.WithCacheControl("public, max-age=3600"),
//		servex.WithCacheExpires(time.Now().Add(1*time.Hour).Format(http.TimeFormat)),
//	)
//
// Note: Modern clients prefer Cache-Control over Expires. Use this only
// for compatibility with older clients or as a fallback.
func WithCacheExpires(expires string) Option {
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.Expires = expires
	}
}

// WithCacheETag sets the ETag header for cache validation.
// ETags allow clients to validate cached content without downloading.
//
// Example:
//
//	// Static ETag based on content version
//	server := servex.New(servex.WithCacheETag(`"v1.2.3"`))
//
//	// Weak ETag based on timestamp
//	server := servex.New(servex.WithCacheETag(`W/"Tue, 15 Nov 1994 12:45:26 GMT"`))
//
//	// Combined with Cache-Control
//	server := servex.New(
//		servex.WithCacheControl("public, max-age=0, must-revalidate"),
//		servex.WithCacheETag(`"33a64df551"`),
//	)
//
// ETag formats:
//   - Strong ETag: `"version123"` (content identical)
//   - Weak ETag: `W/"version123"` (content equivalent)
//
// Use ETags when you want clients to validate cached content efficiently.
func WithCacheETag(etag string) Option {
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.ETag = etag
	}
}

// WithCacheLastModified sets the Last-Modified header for cache validation.
// This indicates when the resource was last changed.
//
// Example:
//
//	// Set last modified time
//	lastMod := time.Now().AddDate(0, 0, -1).Format(http.TimeFormat)
//	server := servex.New(servex.WithCacheLastModified(lastMod))
//
//	// Combined with Cache-Control
//	server := servex.New(
//		servex.WithCacheControl("public, max-age=0, must-revalidate"),
//		servex.WithCacheLastModified(time.Now().Format(http.TimeFormat)),
//	)
//
// Benefits:
//   - Enables conditional requests (If-Modified-Since)
//   - Reduces bandwidth for unchanged resources
//   - Works well with ETags for cache validation
func WithCacheLastModified(lastModified string) Option {
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.LastModified = lastModified
	}
}

// WithCacheVary sets the Vary header to specify which request headers affect caching.
// This tells caches that the response varies based on certain request headers.
//
// Example:
//
//	// Content varies by compression
//	server := servex.New(servex.WithCacheVary("Accept-Encoding"))
//
//	// Content varies by multiple headers
//	server := servex.New(servex.WithCacheVary("Accept-Encoding, User-Agent, Accept-Language"))
//
//	// Combined with Cache-Control
//	server := servex.New(
//		servex.WithCacheControl("public, max-age=3600"),
//		servex.WithCacheVary("Accept-Encoding"),
//	)
//
// Common Vary values:
//   - "Accept-Encoding": Different compression formats
//   - "User-Agent": Different responses for different browsers
//   - "Accept": Different content types (JSON vs XML)
//   - "Authorization": Different responses for authenticated users
//   - "Accept-Language": Different languages
//
// Important: Only include headers that actually affect the response
// to avoid cache fragmentation.
func WithCacheVary(vary string) Option {
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.Vary = vary
	}
}

// WithCacheExcludePaths sets paths that should be excluded from cache control headers.
// Requests to these paths will not have cache control headers applied.
//
// Example:
//
//	// Exclude dynamic endpoints from caching
//	server := servex.New(
//		servex.WithCacheControl("public, max-age=3600"),
//		servex.WithCacheExcludePaths("/api/*", "/user/*", "/admin/*"),
//	)
//
//	// Exclude authentication and real-time endpoints
//	server := servex.New(
//		servex.WithCacheHeaders(),
//		servex.WithCacheExcludePaths("/auth/*", "/ws/*", "/stream/*"),
//	)
//
// Common exclusions:
//   - Dynamic APIs: "/api/*", "/graphql"
//   - User-specific content: "/user/*", "/profile/*"
//   - Authentication: "/auth/*", "/login", "/logout"
//   - Admin interfaces: "/admin/*"
//   - Real-time endpoints: "/ws/*", "/stream/*"
//
// Path matching supports wildcards (*) for pattern matching.
func WithCacheExcludePaths(paths ...string) Option {
	return func(op *Options) {
		op.Cache.ExcludePaths = paths
	}
}

// WithCacheIncludePaths sets paths that should have cache control headers applied.
// If set, only requests to these paths will receive cache control headers.
//
// Example:
//
//	// Cache only static assets
//	server := servex.New(
//		servex.WithCacheControl("public, max-age=31536000, immutable"),
//		servex.WithCacheIncludePaths("/static/*", "/assets/*", "/images/*"),
//	)
//
//	// Cache specific API endpoints
//	server := servex.New(
//		servex.WithCacheControl("public, max-age=300"),
//		servex.WithCacheIncludePaths("/api/public/*", "/docs/*"),
//	)
//
// Use cases:
//   - Cache only static assets: "/static/*", "/assets/*"
//   - Cache specific API endpoints: "/api/public/*"
//   - Cache documentation: "/docs/*"
//
// If both IncludePaths and ExcludePaths are set:
//  1. Paths must match IncludePaths to receive cache headers
//  2. Paths in ExcludePaths are then excluded from cache headers
//
// Path matching supports wildcards (*) for pattern matching.
func WithCacheIncludePaths(paths ...string) Option {
	return func(op *Options) {
		op.Cache.IncludePaths = paths
	}
}

// WithCacheExpiresTime sets the Expires header using a time.Time value.
// This automatically formats the time using HTTP time format (RFC 7231).
//
// Example:
//
//	// Set expiration time to 1 hour from now
//	server := servex.New(servex.WithCacheExpiresTime(time.Now().Add(time.Hour)))
//
//	// Set expiration to a specific time
//	expireTime := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)
//	server := servex.New(servex.WithCacheExpiresTime(expireTime))
//
//	// Combined with Cache-Control
//	server := servex.New(
//		servex.WithCacheControl("public, max-age=3600"),
//		servex.WithCacheExpiresTime(time.Now().Add(time.Hour)),
//	)
//
// This is more convenient than WithCacheExpires() when working with time.Time values.
func WithCacheExpiresTime(expires time.Time) Option {
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.Expires = expires.Format(http.TimeFormat)
	}
}

// WithCacheLastModifiedTime sets the Last-Modified header using a time.Time value.
// This automatically formats the time using HTTP time format (RFC 7231).
//
// Example:
//
//	// Set last modified to file modification time
//	fileInfo, _ := os.Stat("static/app.js")
//	server := servex.New(servex.WithCacheLastModifiedTime(fileInfo.ModTime()))
//
//	// Set last modified to application start time
//	server := servex.New(servex.WithCacheLastModifiedTime(time.Now()))
//
//	// Combined with Cache-Control for conditional requests
//	server := servex.New(
//		servex.WithCacheControl("public, max-age=0, must-revalidate"),
//		servex.WithCacheLastModifiedTime(time.Now().AddDate(0, 0, -1)),
//	)
//
// This is more convenient than WithCacheLastModified() when working with time.Time values.
func WithCacheLastModifiedTime(lastModified time.Time) Option {
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.LastModified = lastModified.Format(http.TimeFormat)
	}
}

// WithCacheETagFunc sets a dynamic ETag generation function.
// The function is called for each request to generate request-specific ETags.
//
// Example:
//
//	// Generate ETag based on user ID and content version
//	server := servex.New(servex.WithCacheETagFunc(func(r *http.Request) string {
//		userID := getUserID(r)
//		version := getContentVersion()
//		return `"` + userID + "-" + version + `"`
//	}))
//
//	// Generate ETag based on request path
//	server := servex.New(servex.WithCacheETagFunc(func(r *http.Request) string {
//		hash := sha256.Sum256([]byte(r.URL.Path))
//		return `"` + hex.EncodeToString(hash[:8]) + `"`
//	}))
//
//	// Weak ETag based on timestamp
//	server := servex.New(servex.WithCacheETagFunc(func(r *http.Request) string {
//		return `W/"` + time.Now().Format("20060102150405") + `"`
//	}))
//
// Use for content that varies per request or needs dynamic validation.
func WithCacheETagFunc(etagFunc func(r *http.Request) string) Option {
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.ETagFunc = etagFunc
	}
}

// WithCacheLastModifiedFunc sets a dynamic Last-Modified generation function.
// The function is called for each request to generate request-specific modification times.
//
// Example:
//
//	// Get modification time from file system
//	server := servex.New(servex.WithCacheLastModifiedFunc(func(r *http.Request) time.Time {
//		filePath := "./static" + r.URL.Path
//		if info, err := os.Stat(filePath); err == nil {
//			return info.ModTime()
//		}
//		return time.Now()
//	}))
//
//	// Get modification time from database
//	server := servex.New(servex.WithCacheLastModifiedFunc(func(r *http.Request) time.Time {
//		resourceID := getResourceID(r)
//		return getResourceModTime(resourceID)
//	}))
//
//	// Use current time for dynamic content
//	server := servex.New(servex.WithCacheLastModifiedFunc(func(r *http.Request) time.Time {
//		return time.Now().Truncate(time.Minute) // Round to minute for better caching
//	}))
//
// Use for content where modification time varies per request or resource.
func WithCacheLastModifiedFunc(lastModifiedFunc func(r *http.Request) time.Time) Option {
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.LastModifiedFunc = lastModifiedFunc
	}
}

// WithCacheNoCache enables cache control with no-cache directive.
// Forces caches to revalidate with the origin server before using cached content.
//
// Example:
//
//	// API endpoints that change frequently
//	server := servex.New(servex.WithCacheNoCache())
//
//	// Combined with ETag for efficient revalidation
//	server := servex.New(
//		servex.WithCacheNoCache(),
//		servex.WithCacheETag(`"v1.2.3"`),
//	)
//
// Use for:
//   - API responses that may change
//   - Dynamic content that should be revalidated
//   - Content where freshness is important
//
// This sets Cache-Control to "no-cache, must-revalidate".
func WithCacheNoCache() Option {
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.CacheControl = "no-cache, must-revalidate"
	}
}

// WithCacheNoStore disables all caching for sensitive content.
// Prevents any caching of the response by browsers, proxies, or CDNs.
//
// Example:
//
//	// Sensitive user data
//	server := servex.New(servex.WithCacheNoStore())
//
//	// Apply only to sensitive endpoints
//	server := servex.New(
//		servex.WithCacheNoStore(),
//		servex.WithCacheIncludePaths("/api/private/*", "/user/settings"),
//	)
//
// Use for:
//   - Personal user data
//   - Authentication endpoints
//   - Payment information
//   - Confidential content
//
// This sets Cache-Control to "no-store, no-cache, must-revalidate".
func WithCacheNoStore() Option {
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.CacheControl = "no-store, no-cache, must-revalidate"
	}
}

// WithCachePublic enables public caching with the specified max-age in seconds.
// Allows both browsers and intermediary proxies/CDNs to cache the content.
//
// Example:
//
//	// Cache static assets for 1 hour (3600 seconds)
//	server := servex.New(servex.WithCachePublic(3600))
//
//	// Cache API responses for 5 minutes (300 seconds)
//	server := servex.New(servex.WithCachePublic(300))
//
//	// Cache static assets for 1 year with immutable content
//	server := servex.New(
//		servex.WithCachePublic(31536000), // 1 year
//		servex.WithCacheIncludePaths("/static/*"),
//	)
//
// Use for:
//   - Static assets (CSS, JS, images)
//   - Public API responses
//   - Documentation
//   - Content that doesn't vary by user
//
// This sets Cache-Control to "public, max-age=<seconds>".
func WithCachePublic(maxAgeSeconds int) Option {
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.CacheControl = fmt.Sprintf("public, max-age=%d", maxAgeSeconds)
	}
}

// WithCachePrivate enables private caching with the specified max-age in seconds.
// Allows only browsers to cache the content, not intermediary proxies or CDNs.
//
// Example:
//
//	// Cache user-specific data for 15 minutes (900 seconds)
//	server := servex.New(servex.WithCachePrivate(900))
//
//	// Cache user profile for 5 minutes (300 seconds)
//	server := servex.New(servex.WithCachePrivate(300))
//
//	// Cache personalized content
//	server := servex.New(
//		servex.WithCachePrivate(1800), // 30 minutes
//		servex.WithCacheIncludePaths("/api/user/*"),
//	)
//
// Use for:
//   - User-specific content
//   - Personalized responses
//   - Content that varies by authentication
//   - Semi-sensitive data
//
// This sets Cache-Control to "private, max-age=<seconds>".
func WithCachePrivate(maxAgeSeconds int) Option {
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.CacheControl = fmt.Sprintf("private, max-age=%d", maxAgeSeconds)
	}
}

// WithCacheStaticAssets enables optimized caching for static assets.
// Sets long-term public caching with immutable directive for maximum performance.
//
// Example:
//
//	// Cache static assets for 1 year (default)
//	server := servex.New(
//		servex.WithCacheStaticAssets(0), // Uses default 1 year
//		servex.WithCacheIncludePaths("/static/*", "/assets/*"),
//	)
//
//	// Cache static assets for 6 months
//	server := servex.New(
//		servex.WithCacheStaticAssets(15552000), // 6 months
//		servex.WithCacheIncludePaths("/js/*", "/css/*", "/images/*"),
//	)
//
//	// Perfect for versioned static assets
//	server := servex.New(
//		servex.WithCacheStaticAssets(0),
//		servex.WithCacheIncludePaths("/static/v*/", "/assets/build/*"),
//		servex.WithCacheVary("Accept-Encoding"),
//	)
//
// Use for:
//   - Versioned static files (CSS, JS, images)
//   - Build artifacts with hashes in filenames
//   - Content that never changes once deployed
//   - CDN-optimized assets
//
// This sets Cache-Control to "public, max-age=<seconds>, immutable".
// If maxAgeSeconds is 0, defaults to 31536000 (1 year).
func WithCacheStaticAssets(maxAgeSeconds int) Option {
	if maxAgeSeconds <= 0 {
		maxAgeSeconds = 31536000 // Default to 1 year
	}
	return func(op *Options) {
		op.Cache.Enabled = true
		op.Cache.CacheControl = fmt.Sprintf("public, max-age=%d, immutable", maxAgeSeconds)
		// Set default Vary header for compression
		if op.Cache.Vary == "" {
			op.Cache.Vary = "Accept-Encoding"
		}
	}
}

// WithCacheAPI sets up cache control for API endpoints with the specified max age.
// This applies cache headers optimized for API responses.
// The cache control will be set to "public, max-age=<maxAgeSeconds>".
// Recommended for stable API responses that don't change frequently.
func WithCacheAPI(maxAgeSeconds int) Option {
	return func(opts *Options) {
		// Default to 300 seconds (5 minutes) if not specified
		if maxAgeSeconds <= 0 {
			maxAgeSeconds = 300
		}

		opts.Cache.Enabled = true
		opts.Cache.CacheControl = fmt.Sprintf("public, max-age=%d, must-revalidate", maxAgeSeconds)
		opts.Cache.Vary = "Accept-Encoding"
		opts.Cache.ExcludePaths = []string{
			"/auth/*",
			"/user/*",
			"/admin/*",
			"/ws/*",
			"/stream/*",
		}
	}
}

// WithMaxRequestBodySize sets the maximum allowed request body size in bytes.
// This applies to all request bodies including JSON, form data, and file uploads.
// Use 0 to disable global request size limits.
//
// Common configurations:
//   - API servers: WithMaxRequestBodySize(10 << 20) // 10 MB
//   - Web applications: WithMaxRequestBodySize(50 << 20) // 50 MB
//   - File upload services: WithMaxRequestBodySize(1 << 30) // 1 GB
//   - Microservices: WithMaxRequestBodySize(5 << 20) // 5 MB
//
// This is a global limit applied via middleware. Individual endpoints
// can use smaller limits via context methods like ReadJSONWithLimit().
