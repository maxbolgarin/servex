package servex

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	// ListenAddressRegexp is used to match "ip:port" or ":port" strings or kuber domains with port.
	ListenAddressRegexp = regexp.MustCompile(`^[\w\-\/:@\.]*:[0-9]{1,5}$`)

	defaultReadTimeout    = 60 * time.Second
	defaultIdleTimeout    = 180 * time.Second
	defaultMaxHeaderBytes = 1 << 20 // 1 MB
)

type Option func(*Options)

// Options represents the configuration for a server.
type Options struct {
	// Certificate is the TLS certificate for HTTPS server support.
	// This enables HTTPS support when the server is started with an HTTPS address.
	// Use WithCertificate() to set a pre-loaded certificate, or WithCertificateFromFile()
	// to load from files. If not set, only HTTP will be available.
	//
	// Example:
	//   cert, _ := tls.LoadX509KeyPair("server.crt", "server.key")
	//   options.Certificate = &cert
	Certificate *tls.Certificate

	// CertFilePath is the path to the TLS certificate file for loading at server startup.
	// The file should contain the PEM-encoded certificate chain.
	// Used with KeyFilePath to enable HTTPS. Set via WithCertificateFromFile().
	//
	// Examples:
	//   - "/etc/ssl/certs/server.crt"
	//   - "./certs/certificate.pem"
	//   - "/path/to/fullchain.pem" (Let's Encrypt style)
	CertFilePath string

	// KeyFilePath is the path to the TLS private key file for loading at server startup.
	// The file should contain the PEM-encoded private key.
	// Used with CertFilePath to enable HTTPS. Set via WithCertificateFromFile().
	//
	// Examples:
	//   - "/etc/ssl/private/server.key"
	//   - "./certs/private.pem"
	//   - "/path/to/privkey.pem" (Let's Encrypt style)
	KeyFilePath string

	// ReadTimeout is the maximum duration for reading the entire request, including the body.
	// This timeout starts when the connection is accepted and ends when the request body
	// is fully read. Set via WithReadTimeout().
	//
	// Recommended values:
	//   - API servers: 10-30 seconds
	//   - Web applications: 30-60 seconds
	//   - File upload services: 5-15 minutes
	//   - Microservices: 5-15 seconds
	//
	// Default: 60 seconds if not set or zero.
	ReadTimeout time.Duration

	// ReadHeaderTimeout is the maximum duration for reading request headers.
	// This timeout is specifically for reading the HTTP headers, not the body.
	// After headers are read, ReadTimeout takes over for the body. Set via WithReadHeaderTimeout().
	//
	// Recommended values:
	//   - Most applications: 2-10 seconds
	//   - High-performance APIs: 2-5 seconds
	//   - Development: 10-30 seconds
	//
	// Default: 60 seconds if not set or zero.
	ReadHeaderTimeout time.Duration

	// IdleTimeout is the maximum duration that idle Keep-Alive connections will be kept open.
	// After this timeout, idle connections are closed. Set via WithIdleTimeout().
	//
	// Recommended values:
	//   - Web applications: 120-180 seconds
	//   - APIs with frequent requests: 60-120 seconds
	//   - Microservices: 30-60 seconds
	//   - WebSocket services: 300+ seconds
	//
	// Default: 180 seconds if not set or zero.
	IdleTimeout time.Duration

	// MaxHeaderBytes is the maximum size of request headers in bytes.
	// This controls the maximum number of bytes the server will read parsing the request header's keys and values,
	// including the request line. It does not limit the size of the request body.
	// Set via WithMaxHeaderBytes().
	//
	// Recommended values:
	//   - Most applications: 1 MB (1 << 20)
	//   - API servers: 512 KB - 1 MB
	//   - Applications with large headers: 2-4 MB
	//   - Restrictive applications: 256 KB
	//
	// Default: 1 MB (1 << 20) if not set or zero.
	//
	// Setting this helps prevent attacks where clients send extremely large headers
	// to consume server resources. A reasonable limit protects against slowloris-style attacks.
	MaxHeaderBytes int

	// AuthToken enables simple token-based authentication using the Authorization header.
	// When set, the server will check for "Authorization: Bearer <token>" headers on
	// protected routes. Set via WithAuthToken().
	//
	// Use cases:
	//   - Simple API authentication
	//   - Service-to-service communication
	//   - Development and testing
	//
	// For advanced authentication with user management, JWT tokens, and roles,
	// use the Auth field instead.
	AuthToken string

	// Logger is a custom logger for server events, errors, and panics.
	// The logger must implement the servex.Logger interface. Set via WithLogger().
	//
	// If not set, servex will create a JSON logger that writes to stderr.
	//
	// The logger receives:
	//   - Server startup/shutdown events (Info level)
	//   - Request errors and panics (Error level)
	//   - Debug information when available (Debug level)
	Logger Logger

	// RequestLogger is a custom logger specifically for HTTP request logging.
	// This is separate from the main logger and focuses on request/response details.
	// Set via WithRequestLogger().
	//
	// If not set, it will use the main Logger in debug level for successful requests.
	//
	// Use for:
	//   - Structured request logging
	//   - Access logs
	//   - Request metrics
	//   - Audit trails
	RequestLogger RequestLogger

	// DisableRequestLogging disables HTTP request logging completely.
	// No requests will be logged regardless of status or errors.
	// Set to true via WithNoRequestLog() or WithDisableRequestLogging().
	//
	// Use when:
	//   - You have external request logging (load balancer, proxy)
	//   - You want to reduce log volume
	//   - Performance is critical and logging overhead matters
	//   - You're implementing custom request logging middleware
	DisableRequestLogging bool

	// NoLogClientErrors disables logging of client errors (HTTP status codes 400-499).
	// Server errors (5xx) and successful requests will still be logged if request logging is enabled.
	// Set to true via WithNoLogClientErrors().
	//
	// Use to:
	//   - Reduce log noise from bad requests
	//   - Focus on server-side issues
	//   - Improve log readability in production
	NoLogClientErrors bool

	// LogFields specifies which fields to include in request logs.
	// If empty, all available fields will be logged (default behavior).
	// Set via WithLogFields().
	//
	// Available fields (use exported constants):
	//   - servex.RequestIDLogField: Request ID
	//   - servex.IPLogField: Client IP address
	//   - servex.UserAgentLogField: User-Agent header
	//   - servex.URLLogField: Request URL
	//   - servex.MethodLogField: HTTP method (GET, POST, etc.)
	//   - servex.ProtoLogField: HTTP protocol version
	//   - servex.ErrorLogField: Error information
	//   - servex.ErrorMessageLogField: Error message
	//   - servex.StatusLogField: HTTP status code
	//   - servex.DurationLogField: Request duration in milliseconds
	//
	// Use to:
	//   - Reduce log verbosity
	//   - Focus on specific metrics
	//   - Comply with privacy requirements
	//   - Optimize log storage costs
	LogFields []string

	// SendErrorToClient configures the server to include detailed error information
	// in HTTP responses when errors occur. This includes Go error messages and stack traces.
	// Set to true via WithSendErrorToClient().
	//
	// Security considerations:
	//   - NEVER enable this in production
	//   - Error details can reveal system information
	//   - Use only for development and testing
	//
	// When enabled, responses might include:
	//   - Internal error messages
	//   - Stack traces for panics
	//   - Database connection errors
	//   - File system errors
	SendErrorToClient bool

	// Auth is the JWT-based authentication configuration with user management, roles, and JWT tokens.
	// Set via WithAuth(), WithAuthMemoryDatabase(), or WithAuthConfig().
	//
	// When configured, this automatically registers these endpoints:
	//   - POST /api/v1/auth/register - User registration
	//   - POST /api/v1/auth/login - User login
	//   - POST /api/v1/auth/refresh - Token refresh
	//   - POST /api/v1/auth/logout - User logout
	//   - GET /api/v1/auth/me - Current user info
	//
	// Use for:
	//   - Multi-user applications
	//   - Role-based access control
	//   - Persistent user data
	//   - Production authentication systems
	Auth AuthConfig

	// RateLimit is the rate limiting configuration to control request frequency per client.
	// Set via WithRateLimitConfig(), WithRPS(), WithRPM(), or other rate limiting options.
	//
	// If RequestsPerInterval is not set, rate limiting will be disabled.
	//
	// Common configurations:
	//   - Public APIs: 60-1000 RPM
	//   - Internal APIs: 1000-10000 RPM
	//   - File uploads: 10-100 RPM
	//   - Authentication: 10-60 RPM
	RateLimit RateLimitConfig

	// Filter is the request filtering configuration for IP addresses, User-Agents, headers, and query parameters.
	// Set via WithFilterConfig() or individual filter options like WithAllowedIPs(), WithBlockedUserAgents(), etc.
	//
	// Use for:
	//   - IP whitelisting/blacklisting
	//   - Bot protection
	//   - Geographic restrictions
	//   - Header-based filtering
	//   - Query parameter validation
	Filter FilterConfig

	// Security is the security headers configuration for web application protection.
	// Set via WithSecurityConfig(), WithSecurityHeaders(), WithStrictSecurityHeaders(), or individual header options.
	//
	// Common headers include:
	//   - Content-Security-Policy
	//   - X-Frame-Options
	//   - X-Content-Type-Options
	//   - Strict-Transport-Security
	//   - X-XSS-Protection
	//
	// Use for:
	//   - XSS protection
	//   - Clickjacking prevention
	//   - MIME type sniffing protection
	//   - HTTPS enforcement
	Security SecurityConfig

	// CustomHeaders are custom HTTP headers that will be added to all responses.
	// These headers are applied after security headers and can override them.
	// Set via WithCustomHeaders().
	//
	// Use for:
	//   - API versioning headers
	//   - Service identification
	//   - Custom caching policies
	//   - CORS configuration
	//   - Application-specific headers
	CustomHeaders map[string]string

	// AuditLogger is the security audit logger for logging security events.
	// Set via WithAuditLogger() or WithDefaultAuditLogger().
	//
	// Use for:
	//   - Security event logging and monitoring
	//   - Compliance requirements (SOX, GDPR, HIPAA)
	//   - Threat detection and analysis
	//   - Forensic investigation
	//   - Regulatory audit trails
	AuditLogger AuditLogger

	// EnableDefaultAuditLogger indicates that default audit logging was requested
	// even if the logger wasn't available when WithDefaultAuditLogger() was called
	EnableDefaultAuditLogger bool

	// HeadersToRemove specifies headers to remove from responses.
	// This is useful for removing server identification headers or other unwanted headers.
	// Set via WithRemoveHeaders().
	//
	// Common headers to remove:
	//   - "Server": Web server software identification
	//   - "X-Powered-By": Technology stack identification
	//   - "X-AspNet-Version": ASP.NET version (if proxying)
	//
	// Use for:
	//   - Security through obscurity
	//   - Reduce information disclosure
	//   - Clean up response headers
	HeadersToRemove []string

	// Cache is the cache control configuration for HTTP caching headers.
	// Set via WithCacheConfig(), WithCacheControl(), or other cache-related options.
	//
	// Controls browser and proxy caching behavior through standard HTTP headers:
	//   - Cache-Control: Main caching directive
	//   - Expires: Absolute expiration time
	//   - ETag: Entity tag for cache validation
	//   - Last-Modified: Resource modification time
	//   - Vary: Headers that affect caching
	//
	// Use for:
	//   - Performance optimization
	//   - Reduced server load
	//   - Improved user experience
	//   - CDN optimization
	Cache CacheConfig

	// StaticFiles is the static file serving configuration for serving web assets and SPAs.
	// Set via WithStaticFiles(), WithSPAMode(), or WithStaticFileConfig().
	//
	// Use for:
	//   - Serving React/Vue/Angular apps
	//   - Static asset serving (CSS, JS, images)
	//   - Single Page Application (SPA) routing
	//   - Progressive Web App (PWA) support
	//
	// Common use cases:
	//   - React app with API routes: Serve build/ folder with API at /api/*
	//   - Documentation site: Serve docs/ folder
	//   - Static website: Serve public/ folder
	//   - Mixed SPA + API: Client routing with server API endpoints
	StaticFiles StaticFileConfig

	// MaxRequestBodySize is the maximum allowed request body size in bytes.
	// This applies to all request bodies including JSON, form data, and file uploads.
	// Set via WithMaxRequestBodySize().
	//
	// Default values if not set:
	//   - 32 MB for general request bodies
	//   - Use 0 to disable global request size limits
	//
	// Common configurations:
	//   - API servers: 1-10 MB
	//   - Web applications: 10-50 MB
	//   - File upload services: 100 MB - 1 GB
	//   - Microservices: 1-5 MB
	//
	// This is a global limit applied via middleware. Individual endpoints
	// can use smaller limits via context methods like ReadJSONWithLimit().
	MaxRequestBodySize int64

	// MaxJSONBodySize is the maximum allowed JSON request body size in bytes.
	// This specifically applies to JSON payloads and takes precedence over MaxRequestBodySize for JSON.
	// Set via WithMaxJSONBodySize().
	//
	// Default: 1 MB if not set
	//
	// Recommended values:
	//   - API servers: 1-5 MB
	//   - Configuration APIs: 100 KB - 1 MB
	//   - Data import APIs: 5-50 MB
	//   - Real-time APIs: 100 KB - 1 MB
	//
	// Smaller JSON limits help prevent JSON parsing attacks and reduce memory usage.
	MaxJSONBodySize int64

	// MaxFileUploadSize is the maximum allowed file upload size in bytes.
	// This applies to multipart form uploads and file uploads.
	// Set via WithMaxFileUploadSize().
	//
	// Default: 100 MB if not set
	//
	// Common configurations:
	//   - Profile images: 5-10 MB
	//   - Document uploads: 50-200 MB
	//   - Media files: 500 MB - 2 GB
	//   - Data imports: 100 MB - 1 GB
	//
	// Consider your server's available memory and disk space when setting this limit.
	MaxFileUploadSize int64

	// MaxMultipartMemory is the maximum memory used for multipart form parsing in bytes.
	// Files larger than this are stored in temporary files on disk.
	// Set via WithMaxMultipartMemory().
	//
	// Default: 10 MB if not set
	//
	// Balance considerations:
	//   - Higher values: Faster processing, more memory usage
	//   - Lower values: Slower processing, less memory usage, more disk I/O
	//
	// Recommended: 10-50 MB for most applications
	MaxMultipartMemory int64

	// EnableRequestSizeLimits enables global request size limit middleware.
	// When enabled, all requests are checked against the configured size limits.
	// Set via WithEnableRequestSizeLimits() or WithRequestSizeLimits().
	//
	// When disabled, only individual endpoint size limits (via context methods) are enforced.
	//
	// Use cases for disabling:
	//   - Fine-grained control per endpoint
	//   - Custom size limit middleware
	//   - Performance-critical applications
	//   - Legacy compatibility
	EnableRequestSizeLimits bool

	// EnableHealthEndpoint enables an automatic health check endpoint that returns server status.
	// This creates a simple endpoint that responds with "OK" and HTTP 200 status.
	// Set to true via WithHealthEndpoint().
	//
	// The health endpoint:
	//   - Returns 200 OK with "OK" body when server is running
	//   - Bypasses authentication and filtering
	//   - Suitable for load balancer health checks
	//   - Kubernetes liveness/readiness probes
	EnableHealthEndpoint bool

	// HealthPath is the path for the health check endpoint.
	// Only used when EnableHealthEndpoint is true. Set via WithHealthPath().
	//
	// Common health check paths:
	//   - "/health" (default)
	//   - "/ping"
	//   - "/status"
	//   - "/healthz" (Kubernetes style)
	//
	// Default: "/health" if EnableHealthEndpoint is true and this is empty.
	HealthPath string

	// Metrics is a custom metrics collector that will be called on each HTTP request.
	// The metrics handler receives the http.Request for each incoming request.
	// Set via WithMetrics().
	//
	// Use for:
	//   - Prometheus metrics collection
	//   - Custom analytics
	//   - Request counting and monitoring
	//   - Performance tracking
	Metrics Metrics

	// MetricsPath is the path for the default metrics endpoint.
	// Only used when EnableDefaultMetrics is true. Set via WithDefaultMetrics().
	//
	// Common metrics paths:
	//   - "/metrics" (default, Prometheus style)
	//   - "/stats"
	//   - "/status/metrics"
	//   - "/monitoring/metrics"
	//
	// Default: "/metrics" if EnableDefaultMetrics is true and this is empty.
	MetricsPath string

	// EnableDefaultMetrics enables the default metrics endpoint.
	EnableDefaultMetrics bool

	// HTTPSRedirect is the HTTPS redirection configuration.
	// When true, all HTTP requests will be automatically redirected to HTTPS.
	HTTPSRedirect HTTPSRedirectConfig

	// CORS is the Cross-Origin Resource Sharing configuration for handling cross-origin requests.
	// Set via WithCORS(), WithCORSAllowOrigins(), or WithCORSConfig().
	//
	// CORS enables web applications running at one domain to access resources from another domain.
	// This is essential for modern web applications, SPAs, and APIs that serve different frontends.
	//
	// Use for:
	//   - API servers serving web applications
	//   - Microservices accessed by different frontends
	//   - Public APIs accessed by third-party applications
	//   - Development servers with frontend/backend separation
	CORS CORSConfig

	// Proxy is the reverse proxy configuration
	Proxy ProxyConfiguration

	// Compression is the HTTP response compression configuration.
	// Set via WithCompression(), WithCompressionConfig(), or other compression options.
	//
	// Controls automatic compression of HTTP response bodies using gzip or deflate encoding.
	// Compression reduces bandwidth usage and improves performance for text-based content.
	//
	// Use for:
	//   - API responses (JSON, XML)
	//   - Static assets (CSS, JS, HTML)
	//   - Large text responses
	//   - Bandwidth optimization
	Compression CompressionConfig
}

// CompressionConfig holds the HTTP response compression configuration.
// This configuration enables automatic compression of response bodies
// using gzip or deflate encoding based on client Accept-Encoding headers.
//
// Example configuration:
//
//	compression := CompressionConfig{
//		Enabled: true,
//		Level: 6,
//		MinSize: 1024,
//		Types: []string{"text/html", "application/json", "text/css", "application/javascript"},
//		ExcludePaths: []string{"/api/binary/*", "/downloads/*"},
//	}
type CompressionConfig struct {
	// Enabled determines whether response compression is active.
	// Must be set to true for compression to be applied.
	// Set via WithCompression() or WithCompressionConfig().
	Enabled bool

	// Level sets the compression level for gzip encoding.
	// Valid range: 1-9 where 1 is fastest and 9 is best compression.
	// Set via WithCompressionLevel().
	//
	// Recommended values:
	//   - 1: Fastest compression, lower CPU usage
	//   - 6: Default balance of speed and compression (recommended)
	//   - 9: Best compression, higher CPU usage
	//
	// Default: 6 if not set.
	Level int

	// MinSize is the minimum response size in bytes to trigger compression.
	// Responses smaller than this size will not be compressed.
	// Set via WithCompressionMinSize().
	//
	// Common values:
	//   - 1024: 1KB (good default)
	//   - 512: Compress smaller responses
	//   - 4096: Only compress larger responses
	//   - 0: Compress all responses regardless of size
	//
	// Default: 1024 bytes if not set.
	MinSize int

	// Types is a list of MIME types that should be compressed.
	// Only responses with these content types will be compressed.
	// Set via WithCompressionTypes().
	//
	// Common MIME types for compression:
	//   - "text/html": HTML pages
	//   - "text/css": CSS stylesheets
	//   - "application/javascript": JavaScript files
	//   - "application/json": JSON API responses
	//   - "text/xml": XML responses
	//   - "text/plain": Plain text
	//   - "image/svg+xml": SVG images
	//
	// If empty, defaults to common text-based types.
	Types []string

	// ExcludePaths are paths that should be excluded from compression.
	// Responses for these paths will not be compressed regardless of other settings.
	// Set via WithCompressionExcludePaths().
	//
	// Common exclusions:
	//   - "/api/binary/*": Binary API endpoints
	//   - "/downloads/*": File download endpoints
	//   - "/images/*": Image files (already compressed)
	//   - "/videos/*": Video files (already compressed)
	//
	// Path matching supports wildcards (*) for pattern matching.
	ExcludePaths []string

	// IncludePaths are paths that should have compression applied.
	// If set, only responses for these paths will be compressed.
	// Set via WithCompressionIncludePaths().
	//
	// If both IncludePaths and ExcludePaths are set:
	//   1. Paths must match IncludePaths to be considered for compression
	//   2. Paths in ExcludePaths are then excluded from compression
	//
	// Use cases:
	//   - Compress only API endpoints: "/api/*"
	//   - Compress only static assets: "/static/*"
	//   - Compress specific content: "/docs/*", "/help/*"
	//
	// Path matching supports wildcards (*) for pattern matching.
	// Leave empty to apply compression to all paths (default behavior).
	IncludePaths []string
}

// AuthConfig holds the JWT-based authentication configuration with user management, roles, and JWT tokens.
// This configuration enables a complete authentication system with automatic endpoint registration.
//
// When authentication is enabled, the following endpoints are automatically registered:
//   - POST {AuthBasePath}/register - User registration
//   - POST {AuthBasePath}/login - User login
//   - POST {AuthBasePath}/refresh - Token refresh
//   - POST {AuthBasePath}/logout - User logout
//   - GET {AuthBasePath}/me - Current user info
//
// Example configuration:
//
//	auth := AuthConfig{
//		Database: myAuthDatabase,
//		AccessTokenDuration: 15 * time.Minute,
//		RefreshTokenDuration: 7 * 24 * time.Hour,
//		AuthBasePath: "/api/v1/auth",
//		IssuerNameInJWT: "my-app",
//		RolesOnRegister: []UserRole{"user"},
//	}
type AuthConfig struct {
	// Enabled indicates whether authentication is enabled.
	Enabled bool

	// Database is the interface for user data persistence.
	// Must implement AuthDatabase interface for user CRUD operations.
	// Set via WithAuth() or WithAuthMemoryDatabase().
	//
	// The database handles:
	//   - User creation and retrieval
	//   - Password hashing and verification
	//   - Role management
	//   - Session tracking
	//
	// Use WithAuthMemoryDatabase() for development/testing (data is lost on restart).
	// Use WithAuth() with a persistent database implementation for production.
	Database AuthDatabase

	// JWTAccessSecret is the secret key used for signing access tokens (hex encoded).
	// Set via WithAuthKey(). If empty, a random key will be generated.
	//
	// Security requirements:
	//   - Use strong, randomly generated keys
	//   - Different from refresh token secret
	//   - Store securely (environment variables, key management systems)
	//   - Rotate periodically in production
	//
	// Example: "your-32-byte-hex-encoded-access-key"
	JWTAccessSecret string

	// JWTRefreshSecret is the secret key used for signing refresh tokens (hex encoded).
	// Set via WithAuthKey(). If empty, a random key will be generated.
	//
	// Security requirements:
	//   - Use strong, randomly generated keys
	//   - Different from access token secret
	//   - Store securely (environment variables, key management systems)
	//   - Rotate periodically in production
	//
	// Example: "your-32-byte-hex-encoded-refresh-key"
	JWTRefreshSecret string

	// AccessTokenDuration specifies the validity duration for access tokens.
	// Set via WithAuthTokensDuration(). Defaults to 5 minutes if not set.
	//
	// Recommended patterns:
	//   - Web apps: 15-60 min
	//   - APIs: 5-30 min
	//   - Mobile apps: 30-60 min
	//   - High security: 5-15 min
	//
	// Shorter tokens improve security but require more refresh operations.
	AccessTokenDuration time.Duration

	// RefreshTokenDuration specifies the validity duration for refresh tokens.
	// Set via WithAuthTokensDuration(). Defaults to 7 days if not set.
	//
	// Recommended patterns:
	//   - Web apps: 7-30 days
	//   - APIs: 1-7 days
	//   - Mobile apps: 30-90 days
	//   - High security: 1-3 days
	//
	// Longer refresh tokens improve user experience but increase security risk if compromised.
	RefreshTokenDuration time.Duration

	// IssuerNameInJWT is the issuer name included in JWT token claims.
	// This helps identify which service issued the token and can be used for validation.
	// Set via WithAuthIssuer(). Defaults to "testing" if not set.
	//
	// Use descriptive names like:
	//   - Application name: "user-service", "payment-api"
	//   - Environment-specific: "my-app-prod", "my-app-staging"
	//   - Domain-based: "api.mycompany.com"
	//
	// The issuer appears in the JWT "iss" claim and can be verified by clients.
	IssuerNameInJWT string

	// RefreshTokenCookieName is the name of the HTTP cookie used to store refresh tokens.
	// Set via WithAuthRefreshTokenCookieName(). Defaults to "_servexrt" if not set.
	//
	// Cookie characteristics:
	//   - HttpOnly: Cannot be accessed by JavaScript
	//   - Secure: Only sent over HTTPS (in production)
	//   - SameSite: Protection against CSRF attacks
	//   - Expires: Set to refresh token duration
	//
	// Choose names that don't conflict with your application's other cookies.
	RefreshTokenCookieName string

	// AuthBasePath is the base path for authentication API endpoints.
	// All auth routes will be registered under this path.
	// Set via WithAuthBasePath(). Defaults to "/api/v1/auth" if not set.
	//
	// Registered endpoints under the base path:
	//   - POST {basePath}/register
	//   - POST {basePath}/login
	//   - POST {basePath}/refresh
	//   - POST {basePath}/logout
	//   - GET {basePath}/me
	//
	// Examples: "/auth", "/api/v2/auth", "/users/auth"
	AuthBasePath string

	// RolesOnRegister are the default roles assigned to newly registered users.
	// These roles are automatically assigned when users register through the /register endpoint.
	// Set via WithAuthInitialRoles().
	//
	// Common role patterns:
	//   - Basic: ["user"]
	//   - Hierarchical: ["user", "member", "premium"]
	//   - Functional: ["reader", "writer", "admin"]
	//
	// Users can have multiple roles. Additional roles can be assigned later
	// through user management endpoints or database operations.
	RolesOnRegister []UserRole

	// InitialUsers is a list of initial users to be created when the server starts.
	// This is useful for creating admin accounts or seeding the database with test users.
	// Set via WithAuthInitialUsers().
	//
	// Security considerations:
	//   - Use strong passwords
	//   - Consider loading from environment variables
	//   - Remove or change default passwords in production
	//   - Limit to essential accounts only
	//
	// The users are created if they don't already exist in the database.
	InitialUsers []InitialUser

	// NotRegisterRoutes prevents automatic registration of default authentication routes.
	// Set to true via WithAuthNotRegisterRoutes() when you want to implement custom auth endpoints.
	//
	// When enabled, you must implement your own:
	//   - User registration endpoint
	//   - Login endpoint
	//   - Token refresh endpoint
	//   - Logout endpoint
	//   - User profile endpoint
	//
	// You can still use the AuthManager methods for token generation and validation.
	NotRegisterRoutes bool

	// accessSecret is the decoded access secret key (internal use).
	// This field is populated automatically from JWTAccessSecret during initialization.
	accessSecret []byte

	// refreshSecret is the decoded refresh secret key (internal use).
	// This field is populated automatically from JWTRefreshSecret during initialization.
	refreshSecret []byte
}

// InitialUser represents a user to be created during server startup.
// This is used with AuthConfig.InitialUsers to seed the database with admin accounts
// or test users. Set via WithAuthInitialUsers().
//
// Example usage:
//
//	initialUsers := []InitialUser{
//		{
//			Username: "admin",
//			Password: "secure-admin-password",
//			Roles:    []UserRole{"admin", "user"},
//		},
//		{
//			Username: "testuser",
//			Password: "test-password",
//			Roles:    []UserRole{"user"},
//		},
//	}
//
// Security considerations:
//   - Use strong, unique passwords
//   - Consider loading passwords from environment variables
//   - Remove or change default passwords in production
//   - Limit to essential accounts only
type InitialUser struct {
	// Username is the unique username for the user.
	// This will be used for login and user identification.
	//
	// Requirements:
	//   - Must be unique across all users
	//   - Should follow your application's username policy
	//   - Cannot be empty
	//
	// Examples: "admin", "testuser", "service-account"
	Username string

	// Password is the plain text password for the user.
	// The password will be automatically hashed before storing in the database.
	//
	// Security considerations:
	//   - Use strong passwords (consider password generators)
	//   - Minimum 8 characters recommended
	//   - Include mix of letters, numbers, and symbols
	//   - Never commit passwords to source control
	//   - Consider loading from environment variables
	//
	// Example: os.Getenv("ADMIN_PASSWORD") or "SecurePassword123!"
	Password string

	// Roles are the roles assigned to the user upon creation.
	// These roles determine the user's permissions and access levels.
	//
	// Common roles:
	//   - "admin": Full system access
	//   - "user": Standard user access
	//   - "moderator": Content management access
	//   - "api": API-only access
	//
	// Users can have multiple roles for fine-grained permissions.
	// Additional roles can be assigned later through user management.
	Roles []UserRole
}

// RateLimitConfig holds configuration for the rate limiter middleware.
// This controls request frequency per client using a token bucket algorithm.
//
// Rate limiting helps protect your server from:
//   - DDoS attacks
//   - Brute force attempts
//   - Resource exhaustion
//   - Abusive clients
//
// Example configurations:
//
//	// API server: 100 requests per minute with burst of 20
//	rateLimit := RateLimitConfig{
//		RequestsPerInterval: 100,
//		Interval:           time.Minute,
//		BurstSize:          20,
//		StatusCode:         429,
//		Message:           "Rate limit exceeded. Try again later.",
//	}
//
//	// High-security: 10 requests per second, no burst
//	rateLimit := RateLimitConfig{
//		RequestsPerInterval: 10,
//		Interval:           time.Second,
//		BurstSize:          1,
//	}
type RateLimitConfig struct {
	// Enabled indicates whether rate limiting is enabled.
	Enabled bool

	// RequestsPerInterval is the number of requests allowed per time interval.
	// Set via WithRPM(), WithRPS(), or WithRequestsPerInterval().
	// If not set or zero, rate limiting will be disabled.
	//
	// Common values:
	//   - Public APIs: 60-1000 per minute
	//   - Internal APIs: 1000-10000 per minute
	//   - File uploads: 10-100 per minute
	//   - Authentication: 10-60 per minute
	//
	// The rate limiter uses a token bucket algorithm, refilling tokens at a constant rate.
	RequestsPerInterval int

	// Interval is the time window for the rate limit.
	// Set via WithRPM() (1 minute), WithRPS() (1 second), or WithRequestsPerInterval().
	// If not set, defaults to 1 minute.
	//
	// Common intervals:
	//   - time.Second: For high-frequency APIs
	//   - time.Minute: Most common, good balance
	//   - time.Hour: For very restrictive limits
	//   - 5*time.Minute: Custom business requirements
	//
	// Shorter intervals provide more responsive limiting but require more memory.
	Interval time.Duration

	// BurstSize is the maximum number of requests that can be made immediately.
	// This allows clients to exceed the normal rate limit temporarily by "bursting".
	// Set via WithBurstSize(). If not set, defaults to RequestsPerInterval.
	//
	// How it works:
	//   - Clients can make up to BurstSize requests immediately
	//   - After bursting, they must wait for tokens to refill
	//   - Tokens refill at the configured rate (RequestsPerInterval/Interval)
	//
	// Use cases:
	//   - Handle traffic spikes gracefully
	//   - Allow batch operations
	//   - Improve user experience for bursty clients
	//   - Balance performance with protection
	BurstSize int

	// StatusCode is the HTTP status code returned when rate limit is exceeded.
	// Set via WithRateLimitStatusCode(). Defaults to 429 (Too Many Requests) if not set.
	//
	// Common status codes:
	//   - 429 Too Many Requests (recommended)
	//   - 503 Service Unavailable
	//   - 502 Bad Gateway (for proxy scenarios)
	//
	// The 429 status code is specifically designed for rate limiting and is
	// understood by most HTTP clients and libraries.
	StatusCode int

	// Message is the response body returned when rate limit is exceeded.
	// Set via WithRateLimitMessage(). Defaults to "rate limit exceeded, try again later." if not set.
	//
	// Best practices:
	//   - Be clear about the limit
	//   - Suggest when to retry
	//   - Keep messages user-friendly
	//   - Include contact information for questions
	//
	// The message is returned as plain text in the response body.
	Message string

	// KeyFunc is a custom function to extract the rate limit key from requests.
	// This determines how clients are identified for rate limiting purposes.
	// Set via WithRateLimitKeyFunc().
	//
	// Default behavior uses client IP address. Custom key functions enable:
	//   - User-based rate limiting (requires authentication)
	//   - API key-based limits
	//   - Different limits for different client types
	//   - Combined identification strategies
	//
	// Example functions:
	//   - IP-based: func(r *http.Request) string { return r.RemoteAddr }
	//   - User-based: func(r *http.Request) string { return getUserID(r) }
	//   - API key-based: func(r *http.Request) string { return r.Header.Get("X-API-Key") }
	KeyFunc func(r *http.Request) string

	// ExcludePaths are paths that should be excluded from rate limiting.
	// Requests to these paths will not be counted against rate limits.
	// Set via WithRateLimitExcludePaths().
	//
	// Common exclusions:
	//   - Health checks: "/health", "/ping"
	//   - Metrics: "/metrics", "/stats"
	//   - Static files: "/static/*", "/assets/*"
	//   - Documentation: "/docs/*", "/swagger/*"
	//   - Infrastructure: "/robots.txt", "/favicon.ico"
	//
	// Path matching supports wildcards (*) for pattern matching.
	ExcludePaths []string

	// IncludePaths are paths that should be included in rate limiting.
	// If set, only requests to these paths will be rate limited. All other paths are excluded.
	// Set via WithRateLimitIncludePaths().
	//
	// If both IncludePaths and ExcludePaths are set:
	//   1. Paths must match IncludePaths to be rate limited
	//   2. Paths in ExcludePaths are then excluded from rate limiting
	//
	// Use cases:
	//   - Protect only sensitive endpoints
	//   - Apply different limits to different API versions
	//   - Rate limit only external-facing endpoints
	//   - Granular control over protection
	IncludePaths []string

	// TrustedProxies is a list of trusted proxy IP addresses or CIDR ranges
	// for accurate client IP detection in rate limiting.
	// Set via WithRateLimitTrustedProxies().
	//
	// How it works:
	//   - Without trusted proxies: Uses r.RemoteAddr (proxy IP)
	//   - With trusted proxies: Uses X-Forwarded-For or X-Real-IP headers
	//
	// Common proxy ranges:
	//   - AWS ALB: Check AWS documentation for current ranges
	//   - Cloudflare: Use Cloudflare's published IP ranges
	//   - Internal load balancers: Your internal network ranges
	//   - Docker networks: 172.16.0.0/12, 10.0.0.0/8
	//
	// Security note: Only list IPs you actually trust. Malicious clients
	// can spoof X-Forwarded-For headers if the proxy IP is trusted.
	TrustedProxies []string
}

// FilterConfig holds configuration for request filtering middleware.
// This enables filtering requests based on IP addresses, User-Agents, headers, and query parameters.
//
// Request filtering helps protect your server from:
//   - Malicious IP addresses
//   - Bot and scraper traffic
//   - Invalid or dangerous requests
//   - Geographic restrictions
//   - Content-based attacks
//
// Example configuration:
//
//	filter := FilterConfig{
//		AllowedIPs: []string{"192.168.1.0/24", "10.0.0.0/8"},
//		BlockedUserAgents: []string{"BadBot", "Scraper"},
//		AllowedHeaders: map[string][]string{
//			"X-API-Version": {"v1", "v2"},
//		},
//		StatusCode: 403,
//		Message: "Access denied by security filter",
//	}
//
// This is a pure data structure without any logic - the filtering logic is implemented
// in the middleware that uses this configuration.
type FilterConfig struct {
	// AllowedIPs is a list of IP addresses or CIDR ranges that are allowed.
	// Only requests from these IPs will be allowed. All other IPs are blocked.
	// Set via WithAllowedIPs().
	//
	// IP formats supported:
	//   - Single IP: "192.168.1.100"
	//   - CIDR range: "10.0.0.0/8", "192.168.1.0/24"
	//   - IPv6: "2001:db8::1", "2001:db8::/32"
	//
	// Use cases:
	//   - Restrict admin interfaces to office IPs
	//   - Allow only partner/client IPs
	//   - Internal-only APIs
	//   - Development/staging environment protection
	//
	// If empty, all IPs are allowed unless blocked by BlockedIPs.
	AllowedIPs []string

	// BlockedIPs is a list of IP addresses or CIDR ranges that are blocked.
	// Requests from these IPs will be denied with the configured status code.
	// Set via WithBlockedIPs().
	//
	// IP formats supported:
	//   - Single IP: "192.168.1.100"
	//   - CIDR range: "10.0.0.0/8", "192.168.1.0/24"
	//   - IPv6: "2001:db8::1", "2001:db8::/32"
	//
	// Use cases:
	//   - Block known malicious IPs
	//   - Prevent competitor scraping
	//   - Geographic restrictions
	//   - Temporary IP bans
	//
	// Note: BlockedIPs takes precedence over AllowedIPs.
	// If an IP is in both lists, it will be blocked.
	BlockedIPs []string

	// AllowedUserAgents is a list of exact User-Agent strings that are allowed.
	// Only requests with these exact User-Agent headers will be allowed.
	// Set via WithAllowedUserAgents().
	//
	// For pattern matching instead of exact strings, use AllowedUserAgentsRegex.
	//
	// Use cases:
	//   - Restrict API to your apps only
	//   - Block automated scrapers
	//   - Allow only supported browsers
	//   - Partner API access control
	//
	// If empty, all User-Agents are allowed unless blocked by BlockedUserAgents.
	AllowedUserAgents []string

	// AllowedUserAgentsRegex is a list of regex patterns for allowed User-Agents.
	// Only requests with User-Agent headers matching these patterns will be allowed.
	// Set via WithAllowedUserAgentsRegex().
	//
	// Regex features:
	//   - Use standard Go regex syntax
	//   - Case-sensitive matching
	//   - ^ and $ for exact matching
	//   - \d+ for version numbers
	//   - | for alternatives
	//
	// This is more flexible than AllowedUserAgents for version-aware filtering.
	//
	// Examples:
	//   - `Chrome/\d+\.\d+` - Any Chrome browser
	//   - `^MyApp/\d+\.\d+ \((iOS|Android)\)$` - Your app with any version
	AllowedUserAgentsRegex []string

	// BlockedUserAgents is a list of exact User-Agent strings that are blocked.
	// Requests with these exact User-Agent headers will be denied.
	// Set via WithBlockedUserAgents().
	//
	// For pattern matching instead of exact strings, use BlockedUserAgentsRegex.
	//
	// Use cases:
	//   - Block automated scrapers
	//   - Prevent bot traffic
	//   - Block specific tools
	//   - Temporary user-agent bans
	//
	// Note: BlockedUserAgents takes precedence over AllowedUserAgents.
	BlockedUserAgents []string

	// BlockedUserAgentsRegex is a list of regex patterns for blocked User-Agents.
	// Requests with User-Agent headers matching these patterns will be denied.
	// Set via WithBlockedUserAgentsRegex().
	//
	// Regex features:
	//   - (?i) for case-insensitive matching
	//   - Use standard Go regex syntax
	//   - ^ and $ for exact matching
	//   - | for alternatives
	//
	// Examples:
	//   - `(?i)(bot|crawler|spider|scraper)` - Block all bots and crawlers
	//   - `^(curl|wget|python-requests)` - Block command line tools
	//
	// Note: BlockedUserAgentsRegex takes precedence over AllowedUserAgentsRegex.
	BlockedUserAgentsRegex []string

	// AllowedHeaders is a map of header names to exact allowed values.
	// Only requests with headers matching the specified exact values will be allowed.
	// Set via WithAllowedHeaders().
	//
	// Header matching:
	//   - Header names are case-insensitive
	//   - Values must match exactly (case-sensitive)
	//   - Multiple allowed values per header
	//   - All specified headers must be present
	//
	// Use cases:
	//   - API version enforcement
	//   - Content-Type validation
	//   - Custom authentication schemes
	//   - Partner-specific headers
	//
	// For pattern matching instead of exact values, use AllowedHeadersRegex.
	AllowedHeaders map[string][]string

	// AllowedHeadersRegex is a map of header names to regex patterns for allowed values.
	// Only requests with headers matching the specified patterns will be allowed.
	// Set via WithAllowedHeadersRegex().
	//
	// Regex features:
	//   - Header names are case-insensitive
	//   - Use standard Go regex syntax
	//   - ^ and $ for exact matching
	//   - Multiple patterns per header (OR logic)
	//
	// Examples:
	//   - "Authorization": [`^Bearer [A-Za-z0-9+/=]+$`] - Any Bearer token
	//   - "X-API-Version": [`^v\d+\.\d+$`] - Semantic versioning
	//
	// This is more flexible than AllowedHeaders for pattern-based validation.
	AllowedHeadersRegex map[string][]string

	// BlockedHeaders is a map of header names to exact blocked values.
	// Requests with headers matching the specified exact values will be denied.
	// Set via WithBlockedHeaders().
	//
	// Header matching:
	//   - Header names are case-insensitive
	//   - Values must match exactly (case-sensitive)
	//   - Multiple blocked values per header
	//   - Any matching header causes blocking
	//
	// Use cases:
	//   - Block deprecated API versions
	//   - Security header filtering
	//   - Malicious request detection
	//   - Legacy client blocking
	//
	// Note: BlockedHeaders takes precedence over AllowedHeaders.
	BlockedHeaders map[string][]string

	// BlockedHeadersRegex is a map of header names to regex patterns for blocked values.
	// Requests with headers matching the specified patterns will be denied.
	// Set via WithBlockedHeadersRegex().
	//
	// Regex features:
	//   - Header names are case-insensitive
	//   - (?i) for case-insensitive pattern matching
	//   - Use standard Go regex syntax
	//   - Multiple patterns per header (OR logic)
	//
	// Examples:
	//   - "X-Forwarded-For": [`(10\.0\.0\.|192\.168\.)`] - Block internal IPs
	//   - "User-Agent": [`(?i)(bot|crawler|spider)`] - Block bots
	//
	// Note: BlockedHeadersRegex takes precedence over AllowedHeadersRegex.
	BlockedHeadersRegex map[string][]string

	// AllowedQueryParams is a map of query parameter names to exact allowed values.
	// Only requests with query parameters matching the specified exact values will be allowed.
	// Set via WithAllowedQueryParams().
	//
	// Parameter matching:
	//   - Parameter names are case-sensitive
	//   - Values must match exactly (case-sensitive)
	//   - Multiple allowed values per parameter
	//   - All specified parameters must be present
	//
	// Use cases:
	//   - API parameter validation
	//   - Prevent SQL injection via query params
	//   - Business logic validation
	//   - Feature flag enforcement
	//
	// For pattern matching instead of exact values, use AllowedQueryParamsRegex.
	AllowedQueryParams map[string][]string

	// AllowedQueryParamsRegex is a map of query parameter names to regex patterns for allowed values.
	// Only requests with query parameters matching the specified patterns will be allowed.
	// Set via WithAllowedQueryParamsRegex().
	//
	// Regex features:
	//   - Parameter names are case-sensitive
	//   - Use standard Go regex syntax
	//   - ^ and $ for exact matching
	//   - Multiple patterns per parameter (OR logic)
	//
	// Examples:
	//   - "id": [`^\d+$`] - Numeric IDs only
	//   - "email": [`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`] - Email format
	//   - "uuid": [`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`] - UUID format
	//
	// This is more flexible than AllowedQueryParams for format validation.
	AllowedQueryParamsRegex map[string][]string

	// BlockedQueryParams is a map of query parameter names to exact blocked values.
	// Requests with query parameters matching the specified exact values will be denied.
	// Set via WithBlockedQueryParams().
	//
	// Parameter matching:
	//   - Parameter names are case-sensitive
	//   - Values must match exactly (case-sensitive)
	//   - Multiple blocked values per parameter
	//   - Any matching parameter causes blocking
	//
	// Use cases:
	//   - Security parameter filtering
	//   - Debug mode blocking in production
	//   - Malicious query detection
	//   - Legacy parameter deprecation
	//
	// Note: BlockedQueryParams takes precedence over AllowedQueryParams.
	BlockedQueryParams map[string][]string

	// BlockedQueryParamsRegex is a map of query parameter names to regex patterns for blocked values.
	// Requests with query parameters matching the specified patterns will be denied.
	// Set via WithBlockedQueryParamsRegex().
	//
	// Regex features:
	//   - Parameter names are case-sensitive
	//   - (?i) for case-insensitive pattern matching
	//   - Use standard Go regex syntax
	//   - Multiple patterns per parameter (OR logic)
	//
	// Examples:
	//   - "search": [`(?i)(union|select|drop|delete|insert|update)`] - Block SQL injection
	//   - "callback": [`(?i)(<script|javascript:|vbscript:)`] - Block script injection
	//   - "query": [`.{1000,}`] - Block excessive length
	//
	// Note: BlockedQueryParamsRegex takes precedence over AllowedQueryParamsRegex.
	BlockedQueryParamsRegex map[string][]string

	// ExcludePaths are paths that should be excluded from request filtering.
	// Requests to these paths will bypass all filtering rules.
	// Set via WithFilterExcludePaths().
	//
	// Common exclusions:
	//   - Health checks: "/health", "/ping"
	//   - Public APIs: "/public/*", "/api/public/*"
	//   - Documentation: "/docs/*", "/swagger/*"
	//   - Static assets: "/static/*", "/assets/*"
	//   - Monitoring: "/metrics", "/status"
	//
	// Path matching supports wildcards (*) for pattern matching.
	// Excluded paths bypass ALL filtering rules (IP, User-Agent, headers, query params).
	ExcludePaths []string

	// IncludePaths are paths that should be included in request filtering.
	// If set, only requests to these paths will be subject to filtering rules.
	// Set via WithFilterIncludePaths().
	//
	// If both IncludePaths and ExcludePaths are set:
	//   1. Paths must match IncludePaths to be filtered
	//   2. Paths in ExcludePaths are then excluded from filtering
	//
	// Use cases:
	//   - Protect only sensitive endpoints
	//   - Apply filtering to specific API versions
	//   - Filter only external-facing endpoints
	//   - Granular security control
	//
	// Path matching supports wildcards (*) for pattern matching.
	IncludePaths []string

	// StatusCode is the HTTP status code returned when requests are blocked by filters.
	// Set via WithFilterStatusCode(). Default is 403 (Forbidden) if not set.
	//
	// Common status codes:
	//   - 403 Forbidden (recommended) - Clear about blocking
	//   - 404 Not Found - Hides endpoint existence
	//   - 401 Unauthorized - Suggests authentication needed
	//   - 429 Too Many Requests - Can mislead attackers
	//
	// Choose based on your security strategy and user experience needs.
	StatusCode int

	// Message is the response body returned when requests are blocked by filters.
	// Set via WithFilterMessage(). Default is "Request blocked by security filter" if not set.
	//
	// Best practices:
	//   - Be clear but not too specific about the filter
	//   - Include contact information for legitimate users
	//   - Avoid revealing security implementation details
	//   - Keep messages user-friendly
	//
	// The message is returned as plain text in the response body.
	Message string

	// TrustedProxies is a list of trusted proxy IP addresses or CIDR ranges
	// for accurate client IP detection in filtering.
	// Set via WithFilterTrustedProxies().
	//
	// How it works:
	//   - Without trusted proxies: Uses r.RemoteAddr (proxy IP) for IP filtering
	//   - With trusted proxies: Uses X-Forwarded-For or X-Real-IP headers
	//
	// Common proxy ranges:
	//   - AWS ALB: Check AWS documentation for current ranges
	//   - Cloudflare: Use Cloudflare's published IP ranges
	//   - Internal load balancers: Your internal network ranges
	//   - Docker networks: 172.16.0.0/12, 10.0.0.0/8
	//
	// Security considerations:
	//   - Only list IPs you actually trust
	//   - Malicious clients can spoof X-Forwarded-For headers
	//   - Ensure proxy properly validates and forwards real client IPs
	TrustedProxies []string
}

// SecurityConfig holds configuration for security headers middleware.
// SecurityConfig holds configuration for security headers middleware.
// These headers protect web applications from common security vulnerabilities.
//
// Security headers help prevent:
//   - Cross-site scripting (XSS) attacks
//   - Clickjacking attacks
//   - MIME type sniffing vulnerabilities
//   - Cross-origin policy violations
//   - Content injection attacks
//
// Example configuration:
//
//	security := SecurityConfig{
//		Enabled: true,
//		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'",
//		XFrameOptions: "DENY",
//		XContentTypeOptions: "nosniff",
//		StrictTransportSecurity: "max-age=31536000; includeSubDomains",
//	}
//
// Use WithStrictSecurityHeaders() for a preset of maximum security headers.
type SecurityConfig struct {
	// Enabled determines whether security headers middleware is active.
	// Must be set to true for any security headers to be applied.
	// Set via WithSecurityHeaders(), WithStrictSecurityHeaders(), or WithSecurityConfig().
	//
	// When disabled, no security headers will be added to responses,
	// even if individual header values are configured.
	Enabled bool

	// CSRF Protection Configuration
	// CSRF protection helps prevent Cross-Site Request Forgery attacks by requiring
	// a secret token to be included with state-changing requests.

	// CSRFEnabled determines whether CSRF protection is active.
	// When enabled, CSRF tokens are required for POST, PUT, PATCH, DELETE requests.
	// Set via WithCSRFProtection(), WithStrictSecurityHeaders(), or WithSecurityConfig().
	//
	// CSRF protection works by:
	//   1. Generating a secure random token for each session
	//   2. Setting the token in a cookie and/or providing it via an endpoint
	//   3. Requiring the token in a header or form field for state-changing requests
	//   4. Validating that the token matches the expected value
	//
	// Use cases:
	//   - Web applications with forms and AJAX requests
	//   - APIs that accept requests from browsers
	//   - Any application vulnerable to CSRF attacks
	CSRFEnabled bool

	// CSRFTokenName is the name of the CSRF token in headers and form fields.
	// Set via WithCSRFTokenName() or WithSecurityConfig().
	//
	// Common names:
	//   - "X-CSRF-Token" (default, Rails/Django style)
	//   - "X-XSRF-TOKEN" (Angular style)
	//   - "csrf_token" (for form fields)
	//   - "_token" (Laravel style)
	//
	// The middleware will look for the token in:
	//   1. Request header with this name
	//   2. Form field with this name (for multipart/form-data and application/x-www-form-urlencoded)
	//   3. URL query parameter with this name (as fallback)
	CSRFTokenName string

	// CSRFCookieName is the name of the cookie that stores the CSRF token.
	// Set via WithCSRFCookieName() or WithSecurityConfig().
	//
	// Common names:
	//   - "csrf_token" (default)
	//   - "XSRF-TOKEN" (Angular style, readable by JavaScript)
	//   - "_csrf" (Express.js style)
	//
	// The cookie is used to store the expected CSRF token value.
	// For maximum security, set CSRFCookieHttpOnly to true.
	CSRFCookieName string

	// CSRFCookieHttpOnly determines if the CSRF cookie is HTTP-only.
	// Set via WithCSRFCookieHttpOnly() or WithSecurityConfig().
	//
	// Security trade-offs:
	//   - true (recommended): More secure, prevents XSS token theft, but requires server-side token injection
	//   - false: Allows JavaScript access, enables SPA token retrieval, but vulnerable to XSS
	//
	// When true:
	//   - Use CSRFTokenEndpoint to provide tokens to JavaScript
	//   - Inject tokens into HTML templates server-side
	//
	// When false:
	//   - JavaScript can read document.cookie to get the token
	//   - Useful for SPAs and AJAX-heavy applications
	CSRFCookieHttpOnly bool

	// CSRFCookieSameSite sets the SameSite attribute for the CSRF cookie.
	// Set via WithCSRFCookieSameSite() or WithSecurityConfig().
	//
	// Options:
	//   - "Strict": Maximum protection, may break some legitimate cross-site usage
	//   - "Lax" (recommended): Good protection with better usability
	//   - "None": Least protection, requires Secure=true, allows cross-site requests
	//
	// "Lax" provides good CSRF protection while maintaining usability.
	CSRFCookieSameSite string

	// CSRFCookieSecure determines if the CSRF cookie requires HTTPS.
	// Set via WithCSRFCookieSecure() or WithSecurityConfig().
	//
	// Recommendations:
	//   - true: Required for production HTTPS sites
	//   - false: Only for development with HTTP
	//
	// Automatically set to true when SameSite=None.
	CSRFCookieSecure bool

	// CSRFCookiePath sets the path attribute for the CSRF cookie.
	// Set via WithCSRFCookiePath() or WithSecurityConfig().
	//
	// Common values:
	//   - "/" (default): Cookie available for entire site
	//   - "/app": Cookie only for application section
	//   - "/api": Cookie only for API endpoints
	//
	// Use specific paths to limit cookie scope and improve security.
	CSRFCookiePath string

	// CSRFCookieMaxAge sets the maximum age for the CSRF cookie in seconds.
	// Set via WithCSRFCookieMaxAge() or WithSecurityConfig().
	//
	// Common values:
	//   - 3600: 1 hour (short-lived, more secure)
	//   - 86400: 1 day (balance of security and usability)
	//   - 604800: 1 week (longer sessions)
	//   - 0: Session cookie (expires when browser closes)
	//
	// Shorter durations improve security but may affect user experience.
	CSRFCookieMaxAge int

	// CSRFTokenEndpoint enables an endpoint to retrieve CSRF tokens via AJAX.
	// Set via WithCSRFTokenEndpoint() or WithSecurityConfig().
	//
	// When set, creates an endpoint (e.g., "/csrf-token") that returns:
	//   {"csrf_token": "abc123..."}
	//
	// Use cases:
	//   - SPAs that need to fetch tokens dynamically
	//   - AJAX applications with HttpOnly cookies
	//   - Mobile apps that need CSRF tokens
	//
	// The endpoint:
	//   - Uses GET method
	//   - Returns JSON with the token
	//   - Sets the CSRF cookie
	//   - Bypasses CSRF validation (safe since it's read-only)
	CSRFTokenEndpoint string

	// CSRFErrorMessage is the message returned when CSRF validation fails.
	// Set via WithCSRFErrorMessage() or WithSecurityConfig().
	//
	// Default: "CSRF token validation failed"
	//
	// Best practices:
	//   - Keep messages generic to avoid information disclosure
	//   - Include guidance for legitimate users
	//   - Consider localization for international applications
	CSRFErrorMessage string

	// CSRFSafeMethods lists HTTP methods that bypass CSRF validation.
	// Set via WithCSRFSafeMethods() or WithSecurityConfig().
	//
	// Default: [GET, "HEAD", OPTIONS, "TRACE"]
	//
	// These methods are considered safe because they shouldn't have side effects.
	// POST, PUT, PATCH, DELETE require CSRF tokens by default.
	//
	// Only modify this if you have specific requirements.
	CSRFSafeMethods []string

	// ContentSecurityPolicy sets the Content-Security-Policy header for XSS protection.
	// This header controls which resources the browser is allowed to load.
	// Set via WithContentSecurityPolicy() or WithStrictSecurityHeaders().
	//
	// Common policies:
	//   - Basic: "default-src 'self'"
	//   - With inline scripts: "default-src 'self'; script-src 'self' 'unsafe-inline'"
	//   - Strict: "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'"
	//   - API-only: "default-src 'none'; frame-ancestors 'none'"
	//
	// Use CSP generators or testing tools to create appropriate policies.
	// Start with a restrictive policy and gradually add exceptions as needed.
	ContentSecurityPolicy string

	// XContentTypeOptions sets the X-Content-Type-Options header to prevent MIME sniffing.
	// This prevents browsers from interpreting files differently than declared by Content-Type.
	// Set via WithSecurityHeaders(), WithStrictSecurityHeaders(), or WithSecurityConfig().
	//
	// Standard value: "nosniff"
	//
	// Benefits:
	//   - Prevents MIME confusion attacks
	//   - Ensures Content-Type headers are respected
	//   - Reduces risk of drive-by downloads
	//   - Essential for file upload applications
	XContentTypeOptions string

	// XFrameOptions sets the X-Frame-Options header to prevent clickjacking attacks.
	// This controls whether the page can be displayed in frames/iframes.
	// Set via WithSecurityHeaders(), WithStrictSecurityHeaders(), or WithSecurityConfig().
	//
	// Options:
	//   - "DENY": Page cannot be framed at all
	//   - "SAMEORIGIN": Page can only be framed by same origin
	//   - "ALLOW-FROM uri": Page can only be framed by specified URI
	//
	// Use "DENY" for maximum security unless you specifically need framing.
	XFrameOptions string

	// XXSSProtection sets the X-XSS-Protection header for legacy XSS protection.
	// Modern browsers rely more on CSP, but this provides additional protection.
	// Set via WithSecurityHeaders(), WithStrictSecurityHeaders(), or WithSecurityConfig().
	//
	// Common values:
	//   - "1": Enable XSS filtering (basic)
	//   - "1; mode=block": Enable XSS filtering and block rather than sanitize
	//   - "0": Disable XSS filtering (not recommended)
	//
	// Note: This header is deprecated in favor of CSP but still useful for older browsers.
	XXSSProtection string

	// StrictTransportSecurity sets the HSTS header to enforce HTTPS usage.
	// This tells browsers to only access the site over HTTPS for a specified time.
	// Set via WithHSTSHeader(), WithStrictSecurityHeaders(), or WithSecurityConfig().
	//
	// Format: "max-age=<seconds>; includeSubDomains; preload"
	//
	// Common configurations:
	//   - Basic: "max-age=31536000" (1 year)
	//   - With subdomains: "max-age=31536000; includeSubDomains"
	//   - Maximum security: "max-age=63072000; includeSubDomains; preload" (2 years)
	//
	// Only set this if your site fully supports HTTPS and you're ready to commit to it.
	StrictTransportSecurity string

	// ReferrerPolicy sets the Referrer-Policy header to control referrer information.
	// This controls how much referrer information is sent with requests.
	// Set via WithStrictSecurityHeaders() or WithSecurityConfig().
	//
	// Options:
	//   - "no-referrer": Never send referrer information
	//   - "same-origin": Send referrer only for same-origin requests
	//   - "strict-origin": Send origin only, and only for HTTPS-to-HTTPS
	//   - "strict-origin-when-cross-origin": Full URL for same-origin, origin only for cross-origin
	//   - "unsafe-url": Always send full URL (not recommended)
	//
	// Balance privacy protection with functionality needs.
	ReferrerPolicy string

	// PermissionsPolicy sets the Permissions-Policy header to control browser features.
	// This restricts access to browser APIs and features for enhanced privacy/security.
	// Set via WithStrictSecurityHeaders() or WithSecurityConfig().
	//
	// Format: "feature=(allowlist)"
	//
	// Examples:
	//   - Block all: "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
	//   - Self only: "geolocation=(self), microphone=(self), camera=(self)"
	//   - Specific origins: "geolocation=(\"https://maps.example.com\")"
	//
	// Common features: geolocation, microphone, camera, payment, usb, magnetometer, gyroscope
	PermissionsPolicy string

	// XPermittedCrossDomainPolicies sets the X-Permitted-Cross-Domain-Policies header.
	// This controls cross-domain access for Flash and PDF files.
	// Set via WithStrictSecurityHeaders() or WithSecurityConfig().
	//
	// Options:
	//   - "none": No cross-domain access allowed (recommended)
	//   - "master-only": Only master policy file is allowed
	//   - "by-content-type": Policy files served with appropriate content type
	//   - "all": All policy files allowed (not recommended)
	//
	// Use "none" unless you specifically need cross-domain Flash/PDF functionality.
	XPermittedCrossDomainPolicies string

	// CrossOriginEmbedderPolicy sets the Cross-Origin-Embedder-Policy header.
	// This header allows a document to control which cross-origin resources can be embedded.
	// Set via WithStrictSecurityHeaders() or WithSecurityConfig().
	//
	// Options:
	//   - "require-corp": Embedded resources must explicitly opt-in to being embedded
	//   - "unsafe-none": No restrictions (default behavior)
	//
	// Use "require-corp" for applications that need to isolate their context
	// from potentially malicious cross-origin resources.
	CrossOriginEmbedderPolicy string

	// CrossOriginOpenerPolicy sets the Cross-Origin-Opener-Policy header.
	// This header controls the opener relationship for windows opened via links.
	// Set via WithStrictSecurityHeaders() or WithSecurityConfig().
	//
	// Options:
	//   - "same-origin": Retain opener only for same-origin navigation
	//   - "same-origin-allow-popups": Like same-origin but allows popups
	//   - "unsafe-none": No restrictions (default)
	//
	// Use "same-origin" to prevent cross-origin pages from accessing your window object.
	CrossOriginOpenerPolicy string

	// CrossOriginResourcePolicy sets the Cross-Origin-Resource-Policy header.
	// This header controls which cross-origin requests can include this resource.
	// Set via WithStrictSecurityHeaders() or WithSecurityConfig().
	//
	// Options:
	//   - "same-site": Resource can be loaded by same-site requests only
	//   - "same-origin": Resource can be loaded by same-origin requests only
	//   - "cross-origin": Resource can be loaded by any origin
	//
	// Use "same-site" or "same-origin" for sensitive resources that shouldn't
	// be embeddable by other origins.
	CrossOriginResourcePolicy string

	// ExcludePaths are paths that should be excluded from security headers.
	// Requests to these paths will not have security headers applied.
	// Set via WithSecurityExcludePaths().
	//
	// Common exclusions:
	//   - API endpoints that need different policies: "/api/*"
	//   - Legacy applications: "/legacy/*"
	//   - Third-party integrations: "/webhooks/*"
	//   - Public assets that need embedding: "/public/*"
	//   - Development tools: "/debug/*"
	//
	// Path matching supports wildcards (*) for pattern matching.
	ExcludePaths []string

	// IncludePaths are paths that should have security headers applied.
	// If set, only requests to these paths will receive security headers.
	// Set via WithSecurityIncludePaths().
	//
	// If both IncludePaths and ExcludePaths are set:
	//   1. Paths must match IncludePaths to receive security headers
	//   2. Paths in ExcludePaths are then excluded from security headers
	//
	// Use cases:
	//   - Apply security headers only to web UI: "/app/*", "/dashboard/*"
	//   - Secure only public-facing endpoints: "/public/*"
	//   - Protect specific application sections: "/admin/*", "/user/*"
	//
	// Path matching supports wildcards (*) for pattern matching.
	IncludePaths []string
}

// CacheConfig represents cache control configuration for HTTP responses.
type CacheConfig struct {
	// Enabled determines whether cache control headers middleware is active.
	// Must be set to true for any cache control headers to be applied.
	// Set via WithCacheControl(), WithCacheHeaders(), or WithCacheConfig().
	//
	// When disabled, no cache control headers will be added to responses,
	// even if individual header values are configured.
	Enabled bool

	// CacheControl sets the Cache-Control header to control caching behavior.
	// This is the primary header for controlling HTTP caching.
	// Set via WithCacheControl() or WithCacheConfig().
	//
	// Common values:
	//   - "no-cache": Must revalidate before using cached copy
	//   - "no-store": Do not cache at all (sensitive data)
	//   - "public, max-age=3600": Public cache for 1 hour
	//   - "private, max-age=900": Private cache for 15 minutes
	//   - "public, max-age=31536000, immutable": Cache for 1 year (static assets)
	//
	// Format: "directive1, directive2, directive3=value"
	//
	// Common directives:
	//   - public/private: Who can cache
	//   - max-age=<seconds>: Cache lifetime
	//   - no-cache: Must revalidate
	//   - no-store: Never cache
	//   - must-revalidate: Revalidate when stale
	//   - immutable: Content never changes
	CacheControl string

	// Expires sets the Expires header with an absolute expiration time.
	// This provides a fallback for older HTTP/1.0 clients that don't support Cache-Control.
	// Modern clients prefer Cache-Control over Expires.
	// Set via WithCacheExpires(), WithCacheExpiresTime(), or WithCacheConfig().
	//
	// Format: HTTP date format (RFC 7231)
	// Examples:
	//   - "Wed, 21 Oct 2025 07:28:00 GMT"
	//   - Generated from time.Now().Add(duration).Format(http.TimeFormat)
	//
	// Note: If both Cache-Control max-age and Expires are present,
	// Cache-Control takes precedence in HTTP/1.1 clients.
	Expires string

	// ETag sets the ETag header for cache validation.
	// ETags allow clients to validate cached content without downloading.
	// Set via WithCacheETag() or WithCacheConfig().
	//
	// For dynamic ETags that change per request, use ETagFunc instead.
	//
	// ETag formats:
	//   - Strong ETag: `"version123"` (content identical)
	//   - Weak ETag: `W/"version123"` (content equivalent)
	//
	// Use cases:
	//   - Static files: Hash of file content
	//   - Dynamic content: Hash of data or version
	//   - APIs: Resource version or last modified timestamp
	//
	// Examples:
	//   - `"33a64df551"` (hash-based)
	//   - `"v1.2.3"` (version-based)
	//   - `W/"Tue, 15 Nov 1994 12:45:26 GMT"` (weak, timestamp-based)
	ETag string

	// ETagFunc is a function that generates ETags dynamically per request.
	// This allows for request-specific or content-specific ETags.
	// Takes precedence over the static ETag field if both are set.
	// Set via WithCacheETagFunc().
	//
	// Example:
	//   ETagFunc: func(r *http.Request) string {
	//     return `"` + getUserID(r) + "-" + getContentVersion() + `"`
	//   }
	//
	// Use cases:
	//   - User-specific content hashing
	//   - Content-based ETags (hash of response data)
	//   - Request-dependent versioning
	//   - Dynamic resource validation
	ETagFunc func(r *http.Request) string

	// LastModified sets the Last-Modified header for cache validation.
	// This indicates when the resource was last changed.
	// Set via WithCacheLastModified(), WithCacheLastModifiedTime(), or WithCacheConfig().
	//
	// For dynamic LastModified times that change per request, use LastModifiedFunc instead.
	//
	// Format: HTTP date format (RFC 7231)
	// Examples:
	//   - "Wed, 21 Oct 2015 07:28:00 GMT"
	//   - Generated from time.Format(http.TimeFormat)
	//
	// Use cases:
	//   - Static files: File modification time
	//   - Dynamic content: Data update timestamp
	//   - APIs: Resource last update time
	//
	// Benefits:
	//   - Enables conditional requests (If-Modified-Since)
	//   - Reduces bandwidth for unchanged resources
	//   - Improves cache efficiency
	LastModified string

	// LastModifiedFunc is a function that generates Last-Modified times dynamically per request.
	// This allows for request-specific or content-specific modification times.
	// Takes precedence over the static LastModified field if both are set.
	// Set via WithCacheLastModifiedFunc().
	//
	// Example:
	//   LastModifiedFunc: func(r *http.Request) time.Time {
	//     return getContentModTime(r.URL.Path)
	//   }
	//
	// Use cases:
	//   - File-based LastModified times
	//   - Database record modification times
	//   - Request-dependent timestamps
	//   - Dynamic resource validation
	LastModifiedFunc func(r *http.Request) time.Time

	// Vary sets the Vary header to specify which request headers affect caching.
	// This tells caches that the response varies based on certain request headers.
	// Set via WithCacheVary() or WithCacheConfig().
	//
	// Common values:
	//   - "Accept-Encoding": Different compression formats
	//   - "User-Agent": Different responses for different browsers
	//   - "Accept": Different content types (JSON vs XML)
	//   - "Authorization": Different responses for authenticated users
	//   - "Accept-Language": Different languages
	//
	// Multiple headers: "Accept-Encoding, User-Agent, Accept-Language"
	//
	// Use cases:
	//   - Content negotiation (compression, format, language)
	//   - User-specific content
	//   - Authentication-dependent responses
	//
	// Important: Only include headers that actually affect the response
	// to avoid cache fragmentation.
	Vary string

	// ExcludePaths are paths that should be excluded from cache control headers.
	// Requests to these paths will not have cache control headers applied.
	// Set via WithCacheExcludePaths().
	//
	// Common exclusions:
	//   - Dynamic APIs: "/api/*", "/graphql"
	//   - User-specific content: "/user/*", "/profile/*"
	//   - Authentication: "/auth/*", "/login", "/logout"
	//   - Admin interfaces: "/admin/*"
	//   - Real-time endpoints: "/ws/*", "/stream/*"
	//
	// Path matching supports wildcards (*) for pattern matching.
	// Use when different endpoints need different caching strategies.
	ExcludePaths []string

	// IncludePaths are paths that should have cache control headers applied.
	// If set, only requests to these paths will receive cache control headers.
	// Set via WithCacheIncludePaths().
	//
	// If both IncludePaths and ExcludePaths are set:
	//   1. Paths must match IncludePaths to receive cache headers
	//   2. Paths in ExcludePaths are then excluded from cache headers
	//
	// Use cases:
	//   - Cache only static assets: "/static/*", "/assets/*"
	//   - Cache specific API endpoints: "/api/public/*"
	//   - Cache documentation: "/docs/*"
	//
	// Path matching supports wildcards (*) for pattern matching.
	// Useful for applying cache headers only to specific content types.
	IncludePaths []string
}

// StaticFileConfig holds configuration for serving static files and Single Page Applications (SPAs).
type StaticFileConfig struct {
	// Enabled determines whether static file serving is active.
	// Must be set to true for static files to be served.
	// Set via WithStaticFiles(), WithSPAMode(), or WithStaticFileConfig().
	Enabled bool

	// Dir is the directory containing static files to serve.
	// This is typically the build output directory for React/Vue/Angular apps.
	// Set via WithStaticFiles().
	//
	// Common examples:
	//   - "build": React build output
	//   - "dist": Vue/Angular build output
	//   - "public": Static website files
	//   - "static": General static assets
	//
	// Files in this directory will be served at the root path unless URLPrefix is set.
	Dir string

	// URLPrefix is the URL path prefix for serving static files.
	// If empty, files are served from the root path.
	// Set via WithStaticFiles() or WithStaticFileConfig().
	//
	// Examples:
	//   - "" (empty): Files served from root (e.g., /app.js)
	//   - "/static": Files served under /static (e.g., /static/app.js)
	//   - "/assets": Files served under /assets (e.g., /assets/app.js)
	//
	// For SPAs, this is usually empty so the app is served from the root.
	URLPrefix string

	// SPAMode enables Single Page Application mode with client-side routing support.
	// When enabled, requests that don't match existing files or API routes
	// will be served the IndexFile to support client-side routing.
	// Set via WithSPAMode().
	//
	// Use cases:
	//   - React Router applications
	//   - Vue Router applications
	//   - Angular routing
	//   - Any SPA with client-side routing
	//
	// When SPAMode is true, API routes should be registered before enabling static files.
	SPAMode bool

	// IndexFile is the fallback file to serve for SPA client-side routing.
	// This file is served when a request doesn't match an existing file or API route.
	// Only used when SPAMode is true. Set via WithSPAMode() or WithStaticFileConfig().
	//
	// Common values:
	//   - "index.html": Standard for most SPAs
	//   - "app.html": Custom entry point
	//
	// Default: "index.html" if SPAMode is true and this is empty.
	IndexFile string

	// StripPrefix removes the specified prefix from the URL before looking up files.
	// This is useful when serving files from a subdirectory but accessing them via a different URL structure.
	// Set via WithStaticFileConfig().
	//
	// Example:
	//   - URLPrefix: "/app"
	//   - StripPrefix: "/app"
	//   - Request: "/app/index.html" → looks for file at "index.html" in Dir
	StripPrefix string

	// ExcludePaths are URL paths that should not be served as static files.
	// These paths will be skipped by the static file handler, allowing other handlers to process them.
	// Set via WithStaticFileConfig().
	//
	// Common exclusions:
	//   - "/api/*": API endpoints
	//   - "/auth/*": Authentication endpoints
	//   - "/admin/*": Admin interfaces
	//   - "/ws/*": WebSocket endpoints
	//
	// Path matching supports wildcards (*) for pattern matching.
	// API routes registered before static files are automatically excluded.
	ExcludePaths []string

	// CacheMaxAge sets the Cache-Control max-age directive for static files (in seconds).
	// This controls how long browsers and proxies cache static files.
	// Set via WithStaticFileConfig().
	//
	// Common values:
	//   - 3600: 1 hour (development)
	//   - 86400: 1 day (staging)
	//   - 31536000: 1 year (production, for versioned assets)
	//   - 0: No caching
	//
	// Different file types can have different cache policies by using the CacheRules field.
	CacheMaxAge int

	// CacheRules defines cache policies for different file types or paths.
	// The key is a file extension (e.g., ".js", ".css") or path pattern (e.g., "/images/*").
	// The value is the max-age in seconds.
	// Set via WithStaticFileConfig().
	//
	// Example:
	//   map[string]int{
	//     ".js":        31536000, // 1 year for JS files
	//     ".css":       31536000, // 1 year for CSS files
	//     ".html":      3600,     // 1 hour for HTML files
	//     "/images/*":  2592000,  // 30 days for images
	//   }
	//
	// More specific rules override general rules. CacheRules override CacheMaxAge.
	CacheRules map[string]int

	securityHeadersForStaticFiles SecurityConfig
}

// HTTPSRedirectConfig holds configuration for automatic HTTP to HTTPS redirection.
// This enables server-level enforcement of HTTPS connections by automatically
// redirecting all HTTP requests to their HTTPS equivalent.
//
// Security benefits:
//   - Enforces encrypted connections
//   - Prevents accidental plain-text transmission
//   - Improves SEO rankings (search engines prefer HTTPS)
//   - Required for modern web features (Service Workers, Geolocation, etc.)
//
// Example configuration:
//
//	httpsRedirect := HTTPSRedirectConfig{
//		Enabled: true,
//		Permanent: true,
//		TrustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12"},
//		ExcludePaths: []string{"/health", "/.well-known/*"},
//	}
type HTTPSRedirectConfig struct {
	// Enabled determines whether HTTP to HTTPS redirection is active.
	// Must be set to true for automatic HTTPS redirection to work.
	// Set via WithHTTPSRedirect() or WithHTTPSRedirectPermanent().
	Enabled bool

	// Permanent determines the type of redirect to use.
	// If true, uses HTTP 301 (permanent redirect) for better SEO.
	// If false, uses HTTP 302 (temporary redirect) for testing/development.
	// Set via WithHTTPSRedirect() or WithHTTPSRedirectPermanent().
	//
	// Recommended values:
	//   - Production: true (301 permanent redirect)
	//   - Development/Testing: false (302 temporary redirect)
	//
	// Default: true (permanent redirect)
	Permanent bool

	// TrustedProxies is a list of trusted proxy IP addresses or CIDR ranges
	// for accurate HTTP/HTTPS detection when behind load balancers or proxies.
	// Set via WithHTTPSRedirectTrustedProxies().
	//
	// When behind proxies, the server cannot detect HTTPS from r.TLS alone.
	// This setting allows checking X-Forwarded-Proto and similar headers
	// only when the request comes from trusted proxy IPs.
	//
	// Common proxy ranges:
	//   - AWS ALB: Check AWS documentation for current ranges
	//   - Cloudflare: Use Cloudflare's published IP ranges
	//   - Internal load balancers: Your internal network ranges
	//   - Docker networks: 172.16.0.0/12, 10.0.0.0/8
	//
	// Security note: Only list IPs you actually trust. Malicious clients
	// can spoof X-Forwarded-Proto headers if the proxy IP is trusted.
	TrustedProxies []string

	// ExcludePaths are paths that should be excluded from HTTPS redirection.
	// Requests to these paths will not be redirected to HTTPS.
	// Set via WithHTTPSRedirectExcludePaths().
	//
	// Common exclusions:
	//   - Health checks: "/health", "/ping" (for load balancers that use HTTP)
	//   - Let's Encrypt challenges: "/.well-known/acme-challenge/*"
	//   - Development endpoints: "/debug/*"
	//   - Legacy integrations that require HTTP: "/legacy/*"
	//
	// Path matching supports wildcards (*) for pattern matching.
	// Use sparingly - most paths should use HTTPS for security.
	ExcludePaths []string

	// IncludePaths are paths that should be included in HTTPS redirection.
	// If set, only requests to these paths will be redirected to HTTPS.
	// Set via WithHTTPSRedirectIncludePaths().
	//
	// If both IncludePaths and ExcludePaths are set:
	//   1. Paths must match IncludePaths to be considered for redirection
	//   2. Paths in ExcludePaths are then excluded from redirection
	//
	// Use cases:
	//   - Gradual HTTPS migration: Start with specific paths
	//   - Mixed HTTP/HTTPS applications: Only secure sensitive areas
	//   - Testing HTTPS setup: Limit scope during testing
	//
	// Path matching supports wildcards (*) for pattern matching.
	// Leave empty to redirect all paths (recommended for production).
	IncludePaths []string
}

// CORSConfig holds configuration for Cross-Origin Resource Sharing (CORS).
// This enables web applications running at one domain to access resources from another domain.
// This is essential for modern web applications, SPAs, and APIs that serve different frontends.
//
// Example configuration:
//
//	corsConfig := CORSConfig{
//		Enabled: true,
//		AllowOrigins: []string{"https://example.com", "https://app.example.com"},
//		AllowMethods: []string{GET, POST, PUT, DELETE, OPTIONS},
//		AllowHeaders: []string{"Content-Type", "Authorization"},
//		AllowCredentials: true,
//		MaxAge: 3600,
//	}
type CORSConfig struct {
	// Enabled determines whether CORS middleware is active.
	// Must be set to true for any CORS headers to be applied.
	// Set via WithCORS(), WithCORSAllowOrigins(), or WithCORSConfig().
	Enabled bool

	// AllowOrigins is a list of origins that are allowed to access the resource.
	// Origins should include the protocol, domain, and port (if not standard).
	// Set via WithCORSAllowOrigins().
	//
	// Examples:
	//   - []string{"*"}: Allow all origins (not recommended for production with credentials)
	//   - []string{"https://example.com"}: Allow specific origin
	//   - []string{"https://app.example.com", "https://admin.example.com"}: Multiple origins
	//   - []string{"http://localhost:3000", "http://localhost:8080"}: Development origins
	//
	// Security considerations:
	//   - Use specific origins instead of "*" when possible
	//   - Never use "*" with AllowCredentials: true
	//   - Include protocol (https://) and port if non-standard
	//
	// If empty, defaults to "*" (all origins allowed).
	AllowOrigins []string

	// AllowMethods is a list of HTTP methods that are allowed for cross-origin requests.
	// Set via WithCORSAllowMethods().
	//
	// Common values:
	//   - []string{GET, POST, PUT, DELETE, OPTIONS}: Full REST API
	//   - []string{GET, POST, OPTIONS}: Read and create operations
	//   - []string{GET, OPTIONS}: Read-only API
	//
	// Notes:
	//   - OPTIONS is automatically included for preflight requests
	//   - HEAD and GET are considered "simple" methods by browsers
	//   - Other methods trigger preflight requests
	//
	// If empty, defaults to common REST methods: GET, POST, PUT, DELETE, OPTIONS.
	AllowMethods []string

	// AllowHeaders is a list of headers that are allowed in cross-origin requests.
	// Set via WithCORSAllowHeaders().
	//
	// Common headers:
	//   - []string{"Content-Type", "Authorization"}: Basic API headers
	//   - []string{"Content-Type", "Authorization", "X-Requested-With"}: AJAX headers
	//   - []string{"*"}: Allow all headers (less secure)
	//
	// Standard headers that don't require explicit allowance:
	//   - Accept, Accept-Language, Content-Language
	//   - Content-Type (for simple values like text/plain, application/x-www-form-urlencoded)
	//
	// Custom headers and complex Content-Type values need explicit allowance.
	//
	// If empty, defaults to common headers: Content-Type, Authorization, X-Requested-With.
	AllowHeaders []string

	// ExposeHeaders is a list of headers that are exposed to the client.
	// These headers can be accessed by JavaScript in the browser.
	// Set via WithCORSExposeHeaders().
	//
	// Common headers to expose:
	//   - []string{"Content-Length", "Content-Range"}: File download information
	//   - []string{"X-Total-Count", "X-Page-Count"}: Pagination metadata
	//   - []string{"Location"}: Resource creation location
	//
	// By default, only simple response headers are exposed to clients.
	// Custom headers need to be explicitly listed here to be accessible.
	//
	// If empty, no additional headers are exposed beyond the defaults.
	ExposeHeaders []string

	// AllowCredentials indicates whether credentials (cookies, HTTP authentication, client-side SSL certificates)
	// are allowed to be included in cross-origin requests.
	// Set via WithCORSAllowCredentials().
	//
	// Security implications:
	//   - When true, browsers include cookies and authorization headers
	//   - Cannot use "*" for AllowOrigins when this is true
	//   - Enables authenticated cross-origin requests
	//   - Increases CSRF risk if not properly handled
	//
	// Use cases:
	//   - APIs that use session cookies for authentication
	//   - Applications with cross-origin authenticated requests
	//   - Single sign-on systems
	//
	// Default: false (safer for public APIs)
	AllowCredentials bool

	// MaxAge is the maximum number of seconds that the results of a preflight request can be cached.
	// This affects how long browsers cache CORS preflight responses.
	// Set via WithCORSMaxAge().
	//
	// Common values:
	//   - 3600: 1 hour (good for development)
	//   - 86400: 1 day (good for production)
	//   - 0: No caching (forces preflight for every request)
	//
	// Benefits of longer caching:
	//   - Fewer preflight requests (better performance)
	//   - Reduced server load
	//
	// Benefits of shorter caching:
	//   - Faster policy changes take effect
	//   - Better for development
	//
	// Default: 3600 seconds (1 hour) if not set.
	MaxAge int

	// ExcludePaths are paths that should be excluded from CORS headers.
	// Requests to these paths will not have CORS headers applied.
	// Set via WithCORSExcludePaths().
	//
	// Common exclusions:
	//   - "/internal/*": Internal endpoints not meant for browsers
	//   - "/admin/*": Admin endpoints with different CORS needs
	//   - "/webhooks/*": Webhook endpoints that don't need CORS
	//
	// Path matching supports wildcards (*) for pattern matching.
	// Use when different endpoints need different CORS policies.
	ExcludePaths []string

	// IncludePaths are paths that should have CORS headers applied.
	// If set, only requests to these paths will receive CORS headers.
	// Set via WithCORSIncludePaths().
	//
	// If both IncludePaths and ExcludePaths are set:
	//   1. Paths must match IncludePaths to receive CORS headers
	//   2. Paths in ExcludePaths are then excluded from CORS headers
	//
	// Use cases:
	//   - Apply CORS only to API endpoints: "/api/*"
	//   - CORS for specific services: "/auth/*", "/users/*"
	//   - Public endpoints only: "/public/*"
	//
	// Path matching supports wildcards (*) for pattern matching.
	// Leave empty to apply CORS to all paths (default behavior).
	IncludePaths []string
}

// HTTP method shortcuts
// HTTP methods shortcuts
const (
	// GET is the HTTP GET method.
	GET = http.MethodGet

	// HEAD is the HTTP HEAD method.
	HEAD = http.MethodHead

	// POST is the HTTP POST method.
	POST = http.MethodPost

	// PUT is the HTTP PUT method.
	PUT = http.MethodPut

	// PATCH is the HTTP PATCH method.
	PATCH = http.MethodPatch

	// DELETE is the HTTP DELETE method.
	DELETE = http.MethodDelete

	// CONNECT is the HTTP CONNECT method.
	CONNECT = http.MethodConnect

	// OPTIONS is the HTTP OPTIONS method.
	OPTIONS = http.MethodOptions

	// TRACE is the HTTP TRACE method.
	TRACE = http.MethodTrace
)

// BaseConfig represents the base configuration for a server that can be loaded from
// configuration files (YAML/JSON) or environment variables. This provides a simple
// way to configure servers without using the functional options pattern.
//
// The struct tags enable automatic loading from:
//   - YAML files (yaml tag)
//   - JSON files (json tag)
//   - Environment variables (env tag)
//
// Example YAML configuration:
//
//	# server.yaml
//	http: ":8080"
//	https: ":8443"
//	cert_file: "/path/to/cert.pem"
//	key_file: "/path/to/key.pem"
//	auth_token: "secret-api-key"
//
// Example JSON configuration:
//
//	{
//	  "http": ":8080",
//	  "https": ":8443",
//	  "cert_file": "/path/to/cert.pem",
//	  "key_file": "/path/to/key.pem",
//	  "auth_token": "secret-api-key"
//	}
//
// Example environment variables:
//
//	export SERVER_HTTP=":8080"
//	export SERVER_HTTPS=":8443"
//	export SERVER_CERT_FILE="/path/to/cert.pem"
//	export SERVER_KEY_FILE="/path/to/key.pem"
//	export SERVER_AUTH_TOKEN="secret-api-key"
//
// Example usage:
//
//	// Load from file
//	var config BaseConfig
//	data, _ := os.ReadFile("server.yaml")
//	yaml.Unmarshal(data, &config)
//
//	// Validate configuration
//	if err := config.Validate(); err != nil {
//		log.Fatal(err)
//	}
//
//	// Convert to servex options
//	var opts []servex.Option
//	if config.AuthToken != "" {
//		opts = append(opts, servex.WithAuthToken(config.AuthToken))
//	}
//	if config.CertFile != "" && config.KeyFile != "" {
//		opts = append(opts, servex.WithCertificateFromFile(config.CertFile, config.KeyFile))
//	}
//
//	server := servex.New(opts...)
//	server.Start(config.HTTP, config.HTTPS)
//
// Use this when:
//   - Loading configuration from external files
//   - Using environment-based configuration
//   - Deploying with container orchestration
//   - Following 12-factor app principles
//   - Need simple, declarative configuration
type BaseConfig struct {
	// HTTP is the address to start the HTTP listener on.
	//
	// Format: "host:port" where host is optional
	// Examples:
	//   - ":8080" - Listen on all interfaces, port 8080
	//   - "localhost:8080" - Listen on localhost only
	//   - "0.0.0.0:8080" - Explicitly listen on all interfaces
	//   - "192.168.1.100:8080" - Listen on specific IP
	//
	// Leave empty to disable HTTP listener.
	HTTP string `yaml:"http" json:"http" env:"SERVER_HTTP"`

	// HTTPS is the address to start the HTTPS listener on.
	//
	// Format: "host:port" where host is optional
	// Examples:
	//   - ":8443" - Listen on all interfaces, port 8443
	//   - "localhost:8443" - Listen on localhost only
	//   - "0.0.0.0:8443" - Explicitly listen on all interfaces
	//   - "192.168.1.100:8443" - Listen on specific IP
	//
	// Requires CertFile and KeyFile to be set for TLS.
	// Leave empty to disable HTTPS listener.
	HTTPS string `yaml:"https" json:"https" env:"SERVER_HTTPS"`

	// CertFile is the path to the TLS certificate file for HTTPS.
	//
	// The file should contain the PEM-encoded certificate chain.
	// Examples:
	//   - "/etc/ssl/certs/server.crt"
	//   - "./certs/certificate.pem"
	//   - "/path/to/fullchain.pem" (Let's Encrypt style)
	//
	// Required when HTTPS is enabled.
	// Must be readable by the application.
	CertFile string `yaml:"cert_file" json:"cert_file" env:"SERVER_CERT_FILE"`

	// KeyFile is the path to the TLS private key file for HTTPS.
	//
	// The file should contain the PEM-encoded private key.
	// Examples:
	//   - "/etc/ssl/private/server.key"
	//   - "./certs/private.pem"
	//   - "/path/to/privkey.pem" (Let's Encrypt style)
	//
	// Required when HTTPS is enabled.
	// Must be readable by the application and kept secure.
	// Should have restricted file permissions (e.g., 600).
	KeyFile string `yaml:"key_file" json:"key_file" env:"SERVER_KEY_FILE"`

	// AuthToken is a simple bearer token for API authentication.
	//
	// When set, the server will check for "Authorization: Bearer <token>"
	// headers on protected routes.
	//
	// Examples:
	//   - "sk-1234567890abcdef" - API key style
	//   - "secret-development-token" - Development token
	//   - Load from environment: os.Getenv("API_SECRET")
	//
	// Security considerations:
	//   - Use strong, randomly generated tokens
	//   - Rotate tokens periodically
	//   - Never commit tokens to source control
	//   - Use environment variables in production
	//
	// For more advanced authentication, use the JWT authentication system instead.
	AuthToken string `yaml:"auth_token" json:"auth_token" env:"SERVER_AUTH_TOKEN"`
}

// Validate checks if the BaseConfig contains valid configuration values.
// It ensures that addresses are properly formatted and at least one listener is configured.
//
// Validation rules:
//   - At least one of HTTP or HTTPS must be set (not both empty)
//   - HTTP address must match the format "host:port" if set
//   - HTTPS address must match the format "host:port" if set
//   - Host can be empty (defaults to all interfaces)
//   - Port must be valid (1-65535)
//
// Example valid configurations:
//
//	// HTTP only
//	config := BaseConfig{HTTP: ":8080"}
//	err := config.Validate() // nil
//
//	// HTTPS only
//	config := BaseConfig{
//		HTTPS: ":8443",
//		CertFile: "cert.pem",
//		KeyFile: "key.pem",
//	}
//	err := config.Validate() // nil
//
//	// Both HTTP and HTTPS
//	config := BaseConfig{
//		HTTP: ":8080",
//		HTTPS: ":8443",
//		CertFile: "cert.pem",
//		KeyFile: "key.pem",
//	}
//	err := config.Validate() // nil
//
// Example invalid configurations:
//
//	// No listeners configured
//	config := BaseConfig{}
//	err := config.Validate() // "at least one of http or https should be set"
//
//	// Invalid HTTP address format
//	config := BaseConfig{HTTP: "invalid-address"}
//	err := config.Validate() // "invalid http address"
//
//	// Invalid HTTPS address format
//	config := BaseConfig{
//		HTTP: ":8080",
//		HTTPS: "not-a-valid:address:format",
//	}
//	err := config.Validate() // "invalid https address"
//
// Note: This method only validates address formats. It does not check:
//   - Whether the ports are available
//   - Whether certificate files exist or are valid
//   - Whether the application has permission to bind to the ports
//   - Whether the certificate and key files match
//
// These runtime checks happen when the server actually starts.
//
// Returns nil if the configuration is valid, or an error describing
// what is invalid about the configuration.
func (c *BaseConfig) Validate() error {
	if c.HTTP == "" && c.HTTPS == "" {
		return errors.New("at least one of http or https should be set")
	}

	if c.HTTP != "" {
		if !ListenAddressRegexp.MatchString(c.HTTP) {
			return fmt.Errorf("invalid http address=%q", c.HTTP)
		}
	}

	if c.HTTPS != "" {
		if !ListenAddressRegexp.MatchString(c.HTTPS) {
			return fmt.Errorf("invalid https address=%q", c.HTTPS)
		}
	}

	return nil
}

// GetTLSConfig creates a secure TLS configuration for HTTPS servers using the provided certificate.
// The configuration follows security best practices and enables modern TLS features.
//
// Security features enabled:
//   - TLS 1.2 minimum version (blocks older, insecure versions)
//   - HTTP/2 support with ALPN negotiation
//   - Server cipher suite preferences (server chooses best cipher)
//   - Only secure ECDHE cipher suites (perfect forward secrecy)
//   - P-256 elliptic curve preference (widely supported and secure)
//
// Example usage:
//
//	// Load certificate
//	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Create secure TLS config
//	tlsConfig := servex.GetTLSConfig(&cert)
//
//	// Use with HTTP server
//	server := &http.Server{
//			Addr:      ":8443",
//			TLSConfig: tlsConfig,
//			Handler:   myHandler,
//		}
//	server.ListenAndServeTLS("", "") // Cert already in TLS config
//
// Example with servex:
//
//	cert, _ := tls.LoadX509KeyPair("server.crt", "server.key")
//	server := servex.New(servex.WithCertificate(cert))
//	// GetTLSConfig is used internally by servex
//
// Security considerations:
//   - Only allows TLS 1.2+ (blocks TLS 1.0, 1.1 which have vulnerabilities)
//   - Uses only ECDHE cipher suites for perfect forward secrecy
//   - Prefers server cipher suite selection for optimal security
//   - Enables HTTP/2 for better performance
//
// Cipher suites included (in order of preference):
//   - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
//   - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
//   - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
//   - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
//
// These cipher suites provide:
//   - ECDHE: Elliptic Curve Diffie-Hellman (perfect forward secrecy)
//   - AES-GCM: Authenticated encryption (confidentiality + integrity)
//   - SHA256/384: Secure hash algorithms
//
// Parameters:
//   - cert: TLS certificate to use. If nil, returns nil (no TLS)
//
// Returns:
//   - *tls.Config: Secure TLS configuration, or nil if cert is nil
//
// Note: This configuration is suitable for production use and follows
// current security recommendations. It may reject very old clients
// that don't support TLS 1.2 or modern cipher suites.
func GetTLSConfig(cert *tls.Certificate) *tls.Config {
	if cert == nil {
		return nil
	}
	return &tls.Config{
		Certificates:             []tls.Certificate{*cert},
		NextProtos:               []string{"h2", "http/1.1"}, // enable HTTP2
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12, // use only new TLS
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // only secure ciphers
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
		},
	}
}

func parseOptions(opts []Option) Options {
	// Initialize with sensible defaults
	out := Options{
		// Enable health endpoint by default for production readiness
		EnableHealthEndpoint: true,
		HealthPath:           "/health",
	}
	for _, opt := range opts {
		opt(&out)
	}
	return out
}

// WithProxyConfig sets the reverse proxy configuration.
// This enables L7 reverse proxy/API gateway functionality with load balancing,
// traffic dumping, health checking, and advanced routing capabilities.
//
// Example:
//
//	proxyConfig := ProxyConfiguration{
//	  Enabled: true,
//	  Rules: []ProxyRule{
//	    {
//	      Name: "api-backend",
//	      PathPrefix: "/api/",
//	      Backends: []Backend{
//	        {URL: "http://backend1:8080", Weight: 2},
//	        {URL: "http://backend2:8080", Weight: 1},
//	      },
//	      LoadBalancing: WeightedRoundRobinStrategy,
//	      StripPrefix: "/api",
//	    },
//	  },
//	  TrafficDump: TrafficDumpConfig{
//	    Enabled: true,
//	    Directory: "./traffic_dumps",
//	    IncludeBody: true,
//	  },
//	}
//	server, _ := servex.New(servex.WithProxyConfig(proxyConfig))
//
// Features:
//   - Multiple load balancing strategies (round-robin, weighted, least-connections, etc.)
//   - Health checking with automatic backend failover
//   - Traffic dumping for analysis and debugging
//   - Path-based and header-based routing
//   - Connection pooling and timeout management
//   - RAW HTTP request logging
func WithProxyConfig(proxy ProxyConfiguration) Option {
	return func(opts *Options) {
		opts.Proxy = proxy
	}
}

// MIME type constants
const (
	// MIMETypeAAC defines the MIME type for AAC audio.
	MIMETypeAAC = "audio/aac"

	// MIMETypeABW defines the MIME type for AbiWord documents.
	MIMETypeABW = "application/x-abiword"

	// MIMETypeAPNG defines the MIME type for Animated Portable Network Graphics (APNG).
	MIMETypeAPNG = "image/apng"

	// MIMETypeARC defines the MIME type for Archive documents (multiple files embedded).
	MIMETypeARC = "application/x-freearc"

	// MIMETypeAVIF defines the MIME type for AVIF images.
	MIMETypeAVIF = "image/avif"

	// MIMETypeAVI defines the MIME type for AVI (Audio Video Interleave).
	MIMETypeAVI = "video/x-msvideo"

	// MIMETypeAZW defines the MIME type for Amazon Kindle eBook format.
	MIMETypeAZW = "application/vnd.amazon.ebook"

	// MIMETypeBIN defines the MIME type for any kind of binary data.
	MIMETypeBIN = "application/octet-stream"

	// MIMETypeBMP defines the MIME type for Windows OS/2 Bitmap Graphics.
	MIMETypeBMP = "image/bmp"

	// MIMETypeBZ defines the MIME type for BZip archives.
	MIMETypeBZ = "application/x-bzip"

	// MIMETypeBZ2 defines the MIME type for BZip2 archives.
	MIMETypeBZ2 = "application/x-bzip2"

	// MIMETypeCDA defines the MIME type for CD audio.
	MIMETypeCDA = "application/x-cdf"

	// MIMETypeCSH defines the MIME type for C-Shell scripts.
	MIMETypeCSH = "application/x-csh"

	// MIMETypeCSS defines the MIME type for Cascading Style Sheets (CSS).
	MIMETypeCSS = "text/css"

	// MIMETypeCSV defines the MIME type for Comma-separated values (CSV).
	MIMETypeCSV = "text/csv"

	// MIMETypeDOC defines the MIME type for Microsoft Word.
	MIMETypeDOC = "application/msword"

	// MIMETypeDOCX defines the MIME type for Microsoft Word (OpenXML).
	MIMETypeDOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

	// MIMETypeEOT defines the MIME type for MS Embedded OpenType fonts.
	MIMETypeEOT = "application/vnd.ms-fontobject"

	// MIMETypeEPUB defines the MIME type for Electronic publications (EPUB).
	MIMETypeEPUB = "application/epub+zip"

	// MIMETypeGZ defines the MIME type for GZip Compressed Archives.
	MIMETypeGZ = "application/gzip"

	// MIMETypeGIF defines the MIME type for Graphics Interchange Format (GIF).
	MIMETypeGIF = "image/gif"

	// MIMETypeHTML defines the MIME type for HyperText Markup Language (HTML).
	MIMETypeHTML = "text/html"

	// MIMETypeICO defines the MIME type for Icon format.
	MIMETypeICO = "image/vnd.microsoft.icon"

	// MIMETypeICS defines the MIME type for iCalendar format.
	MIMETypeICS = "text/calendar"

	// MIMETypeJAR defines the MIME type for Java Archives (JAR).
	MIMETypeJAR = "application/java-archive"

	// MIMETypeJPEG defines the MIME type for JPEG images.
	MIMETypeJPEG = "image/jpeg"

	// MIMETypeJS defines the MIME type for JavaScript.
	MIMETypeJS = "text/javascript"

	// MIMETypeJSON defines the MIME type for JSON format.
	MIMETypeJSON = "application/json"

	// MIMETypeJSONLD defines the MIME type for JSON-LD format.
	MIMETypeJSONLD = "application/ld+json"

	// MIMETypeMIDI defines the MIME type for Musical Instrument Digital Interface (MIDI).
	MIMETypeMIDI = "audio/midi"

	// MIMETypeMJS defines the MIME type for JavaScript modules.
	MIMETypeMJS = "text/javascript"

	// MIMETypeMP3 defines the MIME type for MP3 audio.
	MIMETypeMP3 = "audio/mpeg"

	// MIMETypeMP4 defines the MIME type for MP4 video.
	MIMETypeMP4 = "video/mp4"

	// MIMETypeMPEG defines the MIME type for MPEG Video.
	MIMETypeMPEG = "video/mpeg"

	// MIMETypeMPKG defines the MIME type for Apple Installer Packages.
	MIMETypeMPKG = "application/vnd.apple.installer+xml"

	// MIMETypeODP defines the MIME type for OpenDocument presentation documents.
	MIMETypeODP = "application/vnd.oasis.opendocument.presentation"

	// MIMETypeODS defines the MIME type for OpenDocument spreadsheet documents.
	MIMETypeODS = "application/vnd.oasis.opendocument.spreadsheet"

	// MIMETypeODT defines the MIME type for OpenDocument text documents.
	MIMETypeODT = "application/vnd.oasis.opendocument.text"

	// MIMETypeOGA defines the MIME type for Ogg audio.
	MIMETypeOGA = "audio/ogg"

	// MIMETypeOGV defines the MIME type for Ogg video.
	MIMETypeOGV = "video/ogg"

	// MIMETypeOGX defines the MIME type for Ogg.
	MIMETypeOGX = "application/ogg"

	// MIMETypeOPUS defines the MIME type for Opus audio in Ogg container.
	MIMETypeOPUS = "audio/ogg"

	// MIMETypeOTF defines the MIME type for OpenType fonts.
	MIMETypeOTF = "font/otf"

	// MIMETypePNG defines the MIME type for Portable Network Graphics.
	MIMETypePNG = "image/png"

	// MIMETypePDF defines the MIME type for Adobe Portable Document Format (PDF).
	MIMETypePDF = "application/pdf"

	// MIMETypePHP defines the MIME type for Hypertext Preprocessor (Personal Home Page).
	MIMETypePHP = "application/x-httpd-php"

	// MIMETypePPT defines the MIME type for Microsoft PowerPoint.
	MIMETypePPT = "application/vnd.ms-powerpoint"

	// MIMETypePPTX defines the MIME type for Microsoft PowerPoint (OpenXML).
	MIMETypePPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation"

	// MIMETypeRAR defines the MIME type for RAR archives.
	MIMETypeRAR = "application/vnd.rar"

	// MIMETypeRTF defines the MIME type for Rich Text Format (RTF).
	MIMETypeRTF = "application/rtf"

	// MIMETypeSH defines the MIME type for Bourne shell scripts.
	MIMETypeSH = "application/x-sh"

	// MIMETypeSVG defines the MIME type for Scalable Vector Graphics (SVG).
	MIMETypeSVG = "image/svg+xml"

	// MIMETypeTAR defines the MIME type for Tape Archives (TAR).
	MIMETypeTAR = "application/x-tar"

	// MIMETypeTIFF defines the MIME type for Tagged Image File Format (TIFF).
	MIMETypeTIFF = "image/tiff"

	// MIMETypeTS defines the MIME type for MPEG transport stream.
	MIMETypeTS = "video/mp2t"

	// MIMETypeTTF defines the MIME type for TrueType Fonts.
	MIMETypeTTF = "font/ttf"

	// MIMETypeTXT defines the MIME type for Plain Text.
	MIMETypeTXT = "text/plain"

	// MIMETypeText is an alias for MIMETypeTXT.
	MIMETypeText = MIMETypeTXT

	// MIMETypePlain is an alias for MIMETypeTXT.
	MIMETypePlain = MIMETypeTXT

	// MIMETypeVSD defines the MIME type for Microsoft Visio.
	MIMETypeVSD = "application/vnd.visio"

	// MIMETypeWAV defines the MIME type for Waveform Audio Format.
	MIMETypeWAV = "audio/wav"

	// MIMETypeWEBA defines the MIME type for WEBM audio.
	MIMETypeWEBA = "audio/webm"

	// MIMETypeWEBM defines the MIME type for WEBM video.
	MIMETypeWEBM = "video/webm"

	// MIMETypeWEBP defines the MIME type for WEBP images.
	MIMETypeWEBP = "image/webp"

	// MIMETypeWOFF defines the MIME type for Web Open Font Format (WOFF).
	MIMETypeWOFF = "font/woff"

	// MIMETypeWOFF2 defines the MIME type for Web Open Font Format (WOFF2).
	MIMETypeWOFF2 = "font/woff2"

	// MIMETypeXHTML defines the MIME type for XHTML.
	MIMETypeXHTML = "application/xhtml+xml"

	// MIMETypeXLS defines the MIME type for Microsoft Excel.
	MIMETypeXLS = "application/vnd.ms-excel"

	// MIMETypeXLSX defines the MIME type for Microsoft Excel (OpenXML).
	MIMETypeXLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

	// MIMETypeXML defines the MIME type for XML.
	MIMETypeXML = "application/xml"

	// MIMETypeXUL defines the MIME type for XUL.
	MIMETypeXUL = "application/vnd.mozilla.xul+xml"

	// MIMETypeZIP defines the MIME type for ZIP archives.
	MIMETypeZIP = "application/zip"

	// MIMEType3GP defines the MIME type for 3GPP audio/video containers.
	MIMEType3GP = "video/3gpp"

	// MIMEType3G2 defines the MIME type for 3GPP2 audio/video containers.
	MIMEType3G2 = "video/3gpp2"

	// MIMEType7Z defines the MIME type for 7-zip archives.
	MIMEType7Z = "application/x-7z-compressed"
)

// Validate checks the options for consistency and common configuration errors.
// It returns an error if any configuration is invalid or potentially problematic.
func (opts *Options) Validate() error {
	var errors []string

	// Certificate validation
	if opts.Certificate != nil && (opts.CertFilePath != "" || opts.KeyFilePath != "") {
		errors = append(errors, "cannot specify both Certificate and CertFilePath/KeyFilePath")
	}

	// Auth validation
	if opts.Auth.Enabled {
		if opts.Auth.Database == nil {
			errors = append(errors, "auth database is required when auth is enabled")
		}
		if opts.Auth.AccessTokenDuration <= 0 {
			errors = append(errors, "access token duration must be positive")
		}
		if opts.Auth.RefreshTokenDuration <= 0 {
			errors = append(errors, "refresh token duration must be positive")
		}
		if opts.Auth.AccessTokenDuration >= opts.Auth.RefreshTokenDuration {
			errors = append(errors, "refresh token duration should be longer than access token duration")
		}
	}

	// Rate limit validation
	if opts.RateLimit.Enabled {
		if opts.RateLimit.RequestsPerInterval <= 0 {
			errors = append(errors, "requests per interval must be positive when rate limiting is enabled")
		}
		if opts.RateLimit.Interval <= 0 {
			errors = append(errors, "rate limit interval must be positive")
		}
	}

	// Size limit validation
	if opts.EnableRequestSizeLimits {
		if opts.MaxRequestBodySize <= 0 {
			errors = append(errors, "max request body size must be positive when size limits are enabled")
		}
		if opts.MaxJSONBodySize > opts.MaxRequestBodySize {
			errors = append(errors, "max JSON body size cannot exceed max request body size")
		}
		if opts.MaxFileUploadSize > opts.MaxRequestBodySize {
			errors = append(errors, "max file upload size cannot exceed max request body size")
		}
	}

	// Security validation
	if opts.Security.Enabled {
		if opts.Security.ContentSecurityPolicy != "" {
			// Basic CSP validation - could be more comprehensive
			if !strings.Contains(opts.Security.ContentSecurityPolicy, "default-src") &&
				!strings.Contains(opts.Security.ContentSecurityPolicy, "script-src") {
				errors = append(errors, "CSP should include at least default-src or script-src directive")
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed: %s", strings.Join(errors, "; "))
	}

	return nil
}
