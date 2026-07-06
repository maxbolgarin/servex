package servex

import (
	"fmt"
)


// WithSecurityConfig sets the complete security headers configuration at once.
// This allows fine-grained control over all security headers applied to responses.
//
// Example:
//
//	securityConfig := servex.SecurityConfig{
//		Enabled: true,
//		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'",
//		XContentTypeOptions: "nosniff",
//		XFrameOptions: "DENY",
//		XXSSProtection: "1; mode=block",
//		StrictTransportSecurity: "max-age=31536000; includeSubDomains",
//	}
//
//	server := servex.New(servex.WithSecurityConfig(securityConfig))
//
// Use this when you need to configure multiple security headers at once
// or when loading configuration from files or environment variables.
func WithSecurityConfig(security SecurityConfig) Option {
	return func(op *Options) {
		op.Security = security
	}
}

// WithSecurityHeaders enables basic security headers with safe default values.
// This is a convenience function that applies commonly recommended security headers.
//
// Example:
//
//	// Apply basic security headers
//	server := servex.New(servex.WithSecurityHeaders())
//
// Headers applied:
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY
//   - X-XSS-Protection: 0
//   - Referrer-Policy: strict-origin-when-cross-origin
//
// Use cases:
//   - Quick security improvement
//   - Development and testing
//   - Basic web application protection
//   - Starting point for custom security headers
//
// For custom security headers or stricter settings, use WithStrictSecurityHeaders()
// or configure individual headers with specific options.
func WithSecurityHeaders() Option {
	return func(op *Options) {
		op.Security.Enabled = true
		op.Security.XContentTypeOptions = "nosniff"
		op.Security.XFrameOptions = "DENY"
		op.Security.XXSSProtection = "0"
		op.Security.ReferrerPolicy = "strict-origin-when-cross-origin"
	}
}

// WithStrictSecurityHeaders enables comprehensive security headers with strict settings.
// This applies a full set of security headers suitable for high-security environments.
//
// Example:
//
//	// Apply strict security headers
//	server := servex.New(servex.WithStrictSecurityHeaders())
//
// Headers applied:
//   - Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY
//   - X-XSS-Protection: 0
//   - Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - Permissions-Policy: camera=(), microphone=(), geolocation=()
//   - X-Permitted-Cross-Domain-Policies: none
//   - Cross-Origin-Opener-Policy: same-origin
//
// Use cases:
//   - High-security applications
//   - Financial services
//   - Healthcare applications
//   - Government systems
//   - Production web applications
//
// Warning: These strict headers may break functionality that requires:
//   - External scripts or stylesheets
//   - Iframe embedding
//   - Cross-origin requests
//   - Third-party integrations
//
// For maximum isolation (with Cross-Origin-Embedder-Policy and Cross-Origin-Resource-Policy),
// use WithMaxSecurityHeaders() instead.
// Test thoroughly and adjust headers as needed for your application.
func WithStrictSecurityHeaders() Option {
	return func(op *Options) {
		op.Security.Enabled = true
		op.Security.ContentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'"
		op.Security.XContentTypeOptions = "nosniff"
		op.Security.XFrameOptions = "DENY"
		op.Security.XXSSProtection = "0"
		op.Security.StrictTransportSecurity = "max-age=63072000; includeSubDomains; preload"
		op.Security.ReferrerPolicy = "strict-origin-when-cross-origin"
		op.Security.PermissionsPolicy = "camera=(), microphone=(), geolocation=()"
		op.Security.XPermittedCrossDomainPolicies = "none"
		op.Security.CrossOriginOpenerPolicy = "same-origin"
	}
}

// WithMaxSecurityHeaders enables maximum security headers for fully isolated applications.
// This applies the strictest possible headers including Cross-Origin isolation policies.
//
// Example:
//
//	// Apply maximum security headers
//	server := servex.New(servex.WithMaxSecurityHeaders())
//
// Headers applied:
//   - Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY
//   - X-XSS-Protection: 0
//   - Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - Permissions-Policy: camera=(), microphone=(), geolocation=()
//   - X-Permitted-Cross-Domain-Policies: none
//   - Cross-Origin-Embedder-Policy: require-corp
//   - Cross-Origin-Opener-Policy: same-origin
//   - Cross-Origin-Resource-Policy: same-origin
//
// Warning: These headers WILL break functionality that requires:
//   - Loading external scripts, styles, fonts, or images (CDN, Google Fonts, etc.)
//   - Iframe embedding from other origins
//   - Cross-origin API requests without proper CORS headers
//   - Third-party integrations (analytics, payment providers, etc.)
//
// Use WithStrictSecurityHeaders() for production sites that load external resources.
// Use this preset only for fully self-contained applications with no external dependencies.
func WithMaxSecurityHeaders() Option {
	return func(op *Options) {
		op.Security.Enabled = true
		op.Security.ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
		op.Security.XContentTypeOptions = "nosniff"
		op.Security.XFrameOptions = "DENY"
		op.Security.XXSSProtection = "0"
		op.Security.StrictTransportSecurity = "max-age=63072000; includeSubDomains; preload"
		op.Security.ReferrerPolicy = "strict-origin-when-cross-origin"
		op.Security.PermissionsPolicy = "camera=(), microphone=(), geolocation=()"
		op.Security.XPermittedCrossDomainPolicies = "none"
		op.Security.CrossOriginEmbedderPolicy = "require-corp"
		op.Security.CrossOriginOpenerPolicy = "same-origin"
		op.Security.CrossOriginResourcePolicy = "same-origin"
	}
}

// WithContentSecurityPolicy sets the Content-Security-Policy header to prevent XSS attacks.
// CSP controls which resources (scripts, styles, images, etc.) can be loaded by the browser.
//
// Example:
//
//	// Basic CSP allowing only same-origin resources
//	server := servex.New(servex.WithContentSecurityPolicy("default-src 'self'"))
//
//	// CSP allowing external CDNs
//	server := servex.New(servex.WithContentSecurityPolicy(
//		"default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'",
//	))
//
//	// CSP for API-only server (no resources)
//	server := servex.New(servex.WithContentSecurityPolicy("default-src 'none'"))
//
// Common CSP directives:
//   - default-src: Default policy for all resource types
//   - script-src: JavaScript sources
//   - style-src: CSS sources
//   - img-src: Image sources
//   - connect-src: AJAX, WebSocket, EventSource sources
//   - font-src: Font sources
//   - object-src: Plugin sources (usually set to 'none')
//   - media-src: Video/audio sources
//   - frame-src: Iframe sources
//
// Common values:
//   - 'self': Same origin as the document
//   - 'none': No resources allowed
//   - 'unsafe-inline': Allow inline scripts/styles (not recommended)
//   - 'unsafe-eval': Allow eval() (not recommended)
//   - https://example.com: Specific domains
//
// Security note: CSP is one of the most effective defenses against XSS attacks.
// Start with a restrictive policy and gradually allow necessary resources.
func WithContentSecurityPolicy(policy string) Option {
	return func(op *Options) {
		op.Security.Enabled = true
		op.Security.ContentSecurityPolicy = policy
	}
}

// WithHSTSHeader sets the Strict-Transport-Security header to enforce HTTPS connections.
// HSTS prevents protocol downgrade attacks and cookie hijacking.
//
// Parameters:
//   - maxAge: Maximum age in seconds (typically 31536000 for 1 year)
//   - includeSubdomains: Whether to apply to all subdomains
//   - preload: Whether to include in browser HSTS preload lists
//
// Example:
//
//	// Basic HSTS for 1 year
//	server := servex.New(servex.WithHSTSHeader(31536000, false, false))
//	// Header: Strict-Transport-Security: max-age=31536000
//
//	// HSTS with subdomains for 1 year
//	server := servex.New(servex.WithHSTSHeader(31536000, true, false))
//	// Header: Strict-Transport-Security: max-age=31536000; includeSubDomains
//
//	// Full HSTS with preload
//	server := servex.New(servex.WithHSTSHeader(63072000, true, true))
//	// Header: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
//
// Recommended values:
//   - Development: 300 (5 minutes) or 0 to disable
//   - Staging: 86400 (1 day)
//   - Production: 31536000 (1 year) or more
//
// Important considerations:
//   - Only enable HSTS when you're confident HTTPS works correctly
//   - Once enabled, browsers will refuse HTTP connections for the duration
//   - Preload requires HTTPS to be working perfectly
//   - Use short max-age initially, increase gradually
//
// Warning: Incorrect HSTS configuration can make your site inaccessible.
// Test thoroughly before using long max-age values or preload.
func WithHSTSHeader(maxAge int, includeSubdomains, preload bool) Option {
	return func(op *Options) {
		op.Security.Enabled = true
		hstsValue := fmt.Sprintf("max-age=%d", maxAge)
		if includeSubdomains {
			hstsValue += "; includeSubDomains"
		}
		if preload {
			hstsValue += "; preload"
		}
		op.Security.StrictTransportSecurity = hstsValue
	}
}

// WithSecurityExcludePaths excludes specific paths from security headers.
// Requests to these paths will not receive security headers.
//
// Example:
//
//	// Exclude API endpoints from security headers
//	server := servex.New(
//		servex.WithSecurityHeaders(),
//		servex.WithSecurityExcludePaths("/api/*", "/webhooks/*"),
//	)
//
//	// Exclude development tools
//	server := servex.New(
//		servex.WithStrictSecurityHeaders(),
//		servex.WithSecurityExcludePaths("/debug/*", "/metrics", "/health"),
//	)
//
// Common exclusions:
//   - API endpoints: "/api/*" (may not need web security headers)
//   - Webhooks: "/webhooks/*" (external services)
//   - Health checks: "/health", "/ping"
//   - Metrics: "/metrics", "/prometheus"
//   - Development: "/debug/*", "/dev/*"
//   - Static assets: "/static/*" (may need different CSP)
//
// Use cases:
//   - API endpoints that don't serve HTML
//   - Third-party integrations
//   - Resources with specific security requirements
//   - Legacy endpoints with compatibility issues
//
// Path matching supports wildcards (*) for pattern matching.
func WithSecurityExcludePaths(paths ...string) Option {
	return func(op *Options) {
		op.Security.ExcludePaths = append(op.Security.ExcludePaths, paths...)
	}
}

// WithSecurityIncludePaths specifies which paths should receive security headers.
// If set, only requests to these paths will get security headers applied.
//
// Example:
//
//	// Only apply security headers to web pages
//	server := servex.New(
//		servex.WithSecurityHeaders(),
//		servex.WithSecurityIncludePaths("/", "/login", "/dashboard/*"),
//	)
//
//	// Apply to specific web applications
//	server := servex.New(
//		servex.WithStrictSecurityHeaders(),
//		servex.WithSecurityIncludePaths("/webapp/*", "/admin/*"),
//	)
//
// If both IncludePaths and ExcludePaths are set:
//  1. Paths must match IncludePaths to receive headers
//  2. Paths in ExcludePaths are then excluded from headers
//
// Use cases:
//   - Mixed API and web application
//   - Multiple applications on same server
//   - Granular security control
//   - Progressive security header rollout
//
// Path matching supports wildcards (*) for pattern matching.
func WithSecurityIncludePaths(paths ...string) Option {
	return func(op *Options) {
		op.Security.IncludePaths = append(op.Security.IncludePaths, paths...)
	}
}

// WithCSRFProtection enables CSRF (Cross-Site Request Forgery) protection with default settings.
// This provides protection against CSRF attacks for web applications.
//
// Example:
//
//	// Enable CSRF protection with defaults
//	server := servex.New(servex.WithCSRFProtection())
//
//	// Combined with other security features
//	server := servex.New(
//		servex.WithStrictSecurityHeaders(),
//		servex.WithCSRFProtection(),
//	)
//
// Default settings:
//   - Token name: "X-CSRF-Token"
//   - Cookie name: "csrf_token"
//   - Cookie HttpOnly: true (recommended for security)
//   - Cookie SameSite: "Lax"
//   - Safe methods: GET, HEAD, OPTIONS, TRACE
//
// Use cases:
//   - Web applications with forms
//   - Single Page Applications (SPAs)
//   - Any application accepting requests from browsers
//   - APIs that need CSRF protection
//
// For custom CSRF settings, use WithCSRFConfig() instead.
func WithCSRFProtection() Option {
	return func(op *Options) {
		op.Security.Enabled = true
		op.Security.CSRFEnabled = true
		op.Security.CSRFTokenName = "X-CSRF-Token"
		op.Security.CSRFCookieName = "csrf_token"
		httpOnly := true
		op.Security.CSRFCookieHttpOnly = &httpOnly
		op.Security.CSRFCookieSameSite = "Lax"
		op.Security.CSRFCookiePath = "/"
		op.Security.CSRFCookieMaxAge = 86400 // 24 hours
		op.Security.CSRFErrorMessage = "CSRF token validation failed"
		op.Security.CSRFSafeMethods = []string{GET, "HEAD", OPTIONS, "TRACE"}
	}
}

// WithCSRFTokenName sets the name for the CSRF token in headers and form fields.
//
// Example:
//
//	// Use Rails/Django style token name
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFTokenName("X-CSRF-Token"),
//	)
//
//	// Use Angular style token name
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFTokenName("X-XSRF-TOKEN"),
//	)
//
//	// Use form field name
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFTokenName("csrf_token"),
//	)
//
// Common token names:
//   - "X-CSRF-Token": Rails, Django, standard header
//   - "X-XSRF-TOKEN": Angular default
//   - "csrf_token": Common form field name
//   - "_token": Laravel style
//
// The middleware will look for the token in:
//  1. Request header with this name
//  2. Form field with this name
//  3. URL query parameter with this name (fallback)
func WithCSRFTokenName(tokenName string) Option {
	return func(op *Options) {
		op.Security.CSRFTokenName = tokenName
	}
}

// WithCSRFCookieName sets the name for the CSRF cookie.
//
// Example:
//
//	// Use standard cookie name
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookieName("csrf_token"),
//	)
//
//	// Use Angular style (readable by JavaScript)
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookieName("XSRF-TOKEN"),
//		servex.WithCSRFCookieHttpOnly(false),
//	)
//
//	// Use Express.js style
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookieName("_csrf"),
//	)
//
// Common cookie names:
//   - "csrf_token": Standard, secure
//   - "XSRF-TOKEN": Angular compatible
//   - "_csrf": Express.js style
//   - "csrftoken": Django style
//
// Choose names that don't conflict with your application's other cookies.
func WithCSRFCookieName(cookieName string) Option {
	return func(op *Options) {
		op.Security.CSRFCookieName = cookieName
	}
}

// WithCSRFCookieHttpOnly sets whether the CSRF cookie is HTTP-only.
// The cookie is HttpOnly by default; call this with false only when a SPA
// must read the token from document.cookie (double-submit cookie pattern).
//
// Example:
//
//	// Maximum security (recommended for server-side apps)
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookieHttpOnly(true),
//		servex.WithCSRFTokenEndpoint("/csrf-token"),
//	)
//
//	// JavaScript accessible (for SPAs)
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookieHttpOnly(false),
//	)
//
// Security considerations:
//   - true: More secure, prevents XSS token theft, requires server-side token injection
//   - false: JavaScript can read the token, but vulnerable to XSS attacks
//
// When HttpOnly is true:
//   - Use WithCSRFTokenEndpoint() to provide tokens to JavaScript
//   - Inject tokens into HTML templates server-side
//   - Maximum protection against XSS token theft
//
// When HttpOnly is false:
//   - JavaScript can read document.cookie to get the token
//   - Useful for SPAs and AJAX-heavy applications
//   - Consider additional XSS protections
func WithCSRFCookieHttpOnly(httpOnly bool) Option {
	return func(op *Options) {
		op.Security.CSRFCookieHttpOnly = &httpOnly
	}
}

// WithCSRFCookieSameSite sets the SameSite attribute for the CSRF cookie.
//
// Example:
//
//	// Maximum protection (may break some legitimate usage)
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookieSameSite("Strict"),
//	)
//
//	// Balanced protection (recommended)
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookieSameSite("Lax"),
//	)
//
//	// Cross-site requests allowed (requires Secure=true)
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookieSameSite("None"),
//		servex.WithCSRFCookieSecure(true),
//	)
//
// SameSite options:
//   - "Strict": Maximum protection, blocks all cross-site requests
//   - "Lax": Good protection with better usability (recommended)
//   - "None": Allows cross-site requests, requires Secure=true
//
// "Lax" provides good CSRF protection while maintaining usability for most applications.
func WithCSRFCookieSameSite(sameSite string) Option {
	return func(op *Options) {
		op.Security.CSRFCookieSameSite = sameSite
		// Automatically set Secure=true when SameSite=None
		if sameSite == "None" {
			op.Security.CSRFCookieSecure = true
		}
	}
}

// WithCSRFCookieSecure sets whether the CSRF cookie requires HTTPS.
//
// Example:
//
//	// Production HTTPS setup
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookieSecure(true),
//	)
//
//	// Development HTTP setup
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookieSecure(false),
//	)
//
// Security recommendations:
//   - true: Required for production HTTPS sites
//   - false: Only for development with HTTP
//
// The Secure flag is automatically set to true when SameSite="None".
// For production applications, always use HTTPS and set this to true.
func WithCSRFCookieSecure(secure bool) Option {
	return func(op *Options) {
		op.Security.CSRFCookieSecure = secure
	}
}

// WithCSRFCookiePath sets the path attribute for the CSRF cookie.
//
// Example:
//
//	// Cookie available for entire site
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookiePath("/"),
//	)
//
//	// Cookie only for application section
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookiePath("/app"),
//	)
//
//	// Cookie only for API endpoints
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookiePath("/api"),
//	)
//
// Common paths:
//   - "/": Cookie available for entire site (default)
//   - "/app": Cookie only for application section
//   - "/api": Cookie only for API endpoints
//
// Use specific paths to limit cookie scope and improve security.
// The cookie will only be sent for requests under the specified path.
func WithCSRFCookiePath(path string) Option {
	return func(op *Options) {
		op.Security.CSRFCookiePath = path
	}
}

// WithCSRFCookieMaxAge sets the maximum age for the CSRF cookie in seconds.
//
// Example:
//
//	// Short-lived session (1 hour)
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookieMaxAge(3600),
//	)
//
//	// Daily session (24 hours)
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookieMaxAge(86400),
//	)
//
//	// Session cookie (expires when browser closes)
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookieMaxAge(0),
//	)
//
// Common values:
//   - 3600: 1 hour (short-lived, more secure)
//   - 86400: 1 day (balance of security and usability)
//   - 604800: 1 week (longer sessions)
//   - 0: Session cookie (expires when browser closes)
//
// Shorter durations improve security but may affect user experience.
// Choose based on your application's session management requirements.
func WithCSRFCookieMaxAge(maxAge int) Option {
	return func(op *Options) {
		op.Security.CSRFCookieMaxAge = maxAge
	}
}

// WithCSRFTokenEndpoint enables an endpoint to retrieve CSRF tokens via AJAX.
//
// Example:
//
//	// Standard CSRF token endpoint
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFTokenEndpoint("/csrf-token"),
//	)
//
//	// Custom endpoint path
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFTokenEndpoint("/api/csrf"),
//	)
//
//	// For SPAs with HttpOnly cookies
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFCookieHttpOnly(true),
//		servex.WithCSRFTokenEndpoint("/api/v1/csrf-token"),
//	)
//
// The endpoint will:
//   - Use GET method
//   - Return JSON: {"csrf_token": "abc123..."}
//   - Set the CSRF cookie
//   - Bypass CSRF validation (safe since it's read-only)
//
// Use cases:
//   - SPAs that need to fetch tokens dynamically
//   - AJAX applications with HttpOnly cookies
//   - Mobile apps that need CSRF tokens
//   - Dynamic forms that load after page load
func WithCSRFTokenEndpoint(endpoint string) Option {
	return func(op *Options) {
		op.Security.CSRFTokenEndpoint = endpoint
	}
}

// WithCSRFErrorMessage sets the message returned when CSRF validation fails.
//
// Example:
//
//	// Generic message (recommended for security)
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFErrorMessage("Invalid request. Please refresh and try again."),
//	)
//
//	// More specific message
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFErrorMessage("CSRF token missing or invalid"),
//	)
//
//	// User-friendly message
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFErrorMessage("Security validation failed. Please reload the page."),
//	)
//
// Best practices:
//   - Keep messages generic to avoid information disclosure
//   - Include guidance for legitimate users
//   - Consider localization for international applications
//   - Avoid revealing technical implementation details
//
// The message is returned as plain text in the response body with a 403 Forbidden status.
func WithCSRFErrorMessage(message string) Option {
	return func(op *Options) {
		op.Security.CSRFErrorMessage = message
	}
}

// WithCSRFSafeMethods sets the HTTP methods that bypass CSRF validation.
//
// Example:
//
//	// Default safe methods (recommended)
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFSafeMethods(GET, "HEAD", OPTIONS, "TRACE"),
//	)
//
//	// More restrictive (only GET and HEAD)
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFSafeMethods(GET, "HEAD"),
//	)
//
//	// Allow additional methods (use with caution)
//	server := servex.New(
//		servex.WithCSRFProtection(),
//		servex.WithCSRFSafeMethods(GET, "HEAD", OPTIONS, "TRACE", "PROPFIND"),
//	)
//
// Default safe methods: GET, HEAD, OPTIONS, TRACE
//
// These methods are considered safe because they shouldn't have side effects.
// All other methods (POST, PUT, PATCH, DELETE) will require CSRF tokens.
//
// Only modify this if you have specific requirements or use non-standard HTTP methods.
// Adding methods like POST to safe methods defeats the purpose of CSRF protection.
func WithCSRFSafeMethods(methods ...string) Option {
	return func(op *Options) {
		op.Security.CSRFSafeMethods = methods
	}
}

// WithCustomHeaders sets custom HTTP headers that will be added to all responses.
// These headers are applied after security headers and can override them.
//
// Example:
//
//	// Add custom API headers
//	server := servex.New(servex.WithCustomHeaders(map[string]string{
//		"X-API-Version": "v1.0",
//		"X-Service-Name": "user-service",
//		"X-Environment": "production",
//	}))
//
//	// Add caching headers
//	server := servex.New(servex.WithCustomHeaders(map[string]string{
//		"Cache-Control": "no-cache, no-store, must-revalidate",
//		"Pragma": "no-cache",
//		"Expires": "0",
//	}))
//
//	// Add CORS headers (basic example)
//	server := servex.New(servex.WithCustomHeaders(map[string]string{
//		"Access-Control-Allow-Origin": "*",
//		"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
//		"Access-Control-Allow-Headers": "Content-Type, Authorization",
//	}))
//
// Use cases:
//   - API versioning headers
//   - Service identification
//   - Custom caching policies
//   - CORS configuration
//   - Application-specific headers
//   - Debugging and monitoring headers
//
// Note: Custom headers can override security headers if they have the same name.
// For security headers, prefer using the dedicated security options instead.
func WithCustomHeaders(headers map[string]string) Option {
	return func(op *Options) {
		if op.CustomHeaders == nil {
			op.CustomHeaders = make(map[string]string)
		}
		for k, v := range headers {
			op.CustomHeaders[k] = v
		}
	}
}

// WithRemoveHeaders removes specific headers from responses.
// This is useful for removing server identification headers or other unwanted headers.
//
// Example:
//
//	// Remove server identification headers
//	server := servex.New(servex.WithRemoveHeaders("Server", "X-Powered-By"))
//
//	// Remove additional headers for security
//	server := servex.New(servex.WithRemoveHeaders(
//		"Server",
//		"X-Powered-By",
//		"X-AspNet-Version",
//		"X-AspNetMvc-Version",
//	))
//
//	// Remove caching headers
//	server := servex.New(servex.WithRemoveHeaders("ETag", "Last-Modified"))
//
// Common headers to remove:
//   - "Server": Web server software identification
//   - "X-Powered-By": Technology stack identification
//   - "X-AspNet-Version": ASP.NET version (if proxying)
//   - "X-AspNetMvc-Version": ASP.NET MVC version
//   - "X-Generator": Content generator identification
//
// Use cases:
//   - Security through obscurity
//   - Reduce information disclosure
//   - Clean up response headers
//   - Remove redundant headers
//   - Compliance requirements
//
// Note: This removes headers that might be added by the Go HTTP server,
// middleware, or upstream proxies. Some headers like "Server" are added
// by the Go standard library and will be removed by this option.
func WithRemoveHeaders(headers ...string) Option {
	return func(op *Options) {
		op.HeadersToRemove = append(op.HeadersToRemove, headers...)
	}
}
