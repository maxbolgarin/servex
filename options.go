package servex

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/maxbolgarin/lang"
)

var (
	// ListenAddressRegexp is used to match "ip:port" or ":port" strings or kuber domains with port.
	ListenAddressRegexp = regexp.MustCompile(`^[\w\-\/:@\.]*:[0-9]{1,5}$`)

	defaultReadTimeout = 60 * time.Second
	defaultIdleTimeout = 180 * time.Second
)

// Metrics is an interface for collecting metrics on each request.
// [Metrics.HandleRequest] is called on each request.
type Metrics interface {
	// HandleRequest is called on each request to collect metrics.
	HandleRequest(r *http.Request)
}

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
}

// WithCertificate sets the TLS certificate for the server from a pre-loaded tls.Certificate.
// This enables HTTPS support on the server. You must start the server with an HTTPS address
// for the certificate to be used.
//
// Example:
//
//	cert, _ := tls.LoadX509KeyPair("server.crt", "server.key")
//	options.Certificate = &cert
//	server := servex.New(servex.WithCertificate(cert))
//	server.Start("", ":8443") // HTTPS only
//
// Use this when you have already loaded the certificate in memory, perhaps for
// certificate rotation or when loading from embedded files.
func WithCertificate(cert tls.Certificate) Option {
	return func(op *Options) {
		op.Certificate = &cert
	}
}

// WithCertificatePtr sets the TLS certificate for the server from a pointer to tls.Certificate.
// This enables HTTPS support on the server. You must start the server with an HTTPS address
// for the certificate to be used.
//
// Example:
//
//	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
//	if err != nil {
//		log.Fatal(err)
//	}
//	server := servex.New(servex.WithCertificatePtr(&cert))
//	server.Start("", ":8443") // HTTPS only
//
// Use this when you need to pass a certificate pointer, useful when sharing
// certificate instances or when the certificate is managed externally.
func WithCertificatePtr(cert *tls.Certificate) Option {
	return func(op *Options) {
		op.Certificate = cert
	}
}

// WithCertificateFromFile configures the server to load TLS certificate from files.
// This enables HTTPS support on the server. The certificate files will be loaded
// when the server starts. You must start the server with an HTTPS address for
// the certificate to be used.
//
// Parameters:
//   - certFilePath: Path to the PEM-encoded certificate file
//   - keyFilePath: Path to the PEM-encoded private key file
//
// Example:
//
//	// Load certificate from files
//	server := servex.New(servex.WithCertificateFromFile("server.crt", "server.key"))
//	server.Start(":8080", ":8443") // Both HTTP and HTTPS
//
//	// HTTPS only server
//	server := servex.New(servex.WithCertificateFromFile("cert.pem", "key.pem"))
//	server.Start("", ":8443") // HTTPS only
//
// This is the most common way to configure TLS certificates. Ensure the files
// are readable by the application and contain valid PEM-encoded data.
func WithCertificateFromFile(certFilePath, keyFilePath string) Option {
	return func(op *Options) {
		op.CertFilePath = certFilePath
		op.KeyFilePath = keyFilePath
	}
}

// WithReadTimeout sets the maximum duration for reading the entire request, including the body.
// This timeout starts when the connection is accepted and ends when the request body
// is fully read. It includes time for reading headers and body.
//
// A zero or negative value sets the default of 60 seconds.
//
// Example:
//
//	// Short timeout for API servers
//	server := servex.New(servex.WithReadTimeout(10 * time.Second))
//
//	// Longer timeout for file upload endpoints
//	server := servex.New(servex.WithReadTimeout(5 * time.Minute))
//
// Recommended values:
//   - API servers: 10-30 seconds
//   - Web applications: 30-60 seconds
//   - File upload services: 5-15 minutes
//   - Microservices: 5-15 seconds
//
// Setting this too low may cause legitimate requests to timeout.
// Setting this too high may allow slow clients to exhaust server resources.
func WithReadTimeout(tm time.Duration) Option {
	return func(op *Options) {
		op.ReadTimeout = lang.If(tm <= 0, defaultReadTimeout, tm)
	}
}

// WithReadHeaderTimeout sets the maximum duration for reading request headers.
// This timeout is specifically for reading the HTTP headers, not the body.
// After headers are read, ReadTimeout takes over for the body.
//
// A zero or negative value sets the default of 60 seconds.
//
// Example:
//
//	// Fast header timeout for performance
//	server := servex.New(servex.WithReadHeaderTimeout(5 * time.Second))
//
//	// Combined with read timeout
//	server := servex.New(
//		servex.WithReadHeaderTimeout(5 * time.Second),
//		servex.WithReadTimeout(30 * time.Second),
//	)
//
// Recommended values:
//   - Most applications: 2-10 seconds
//   - High-performance APIs: 2-5 seconds
//   - Development: 10-30 seconds
//
// This should typically be shorter than ReadTimeout since headers are usually small.
// Protects against slow header attacks where clients send headers very slowly.
func WithReadHeaderTimeout(tm time.Duration) Option {
	return func(op *Options) {
		op.ReadHeaderTimeout = lang.If(tm <= 0, defaultReadTimeout, tm)
	}
}

// WithIdleTimeout sets the maximum duration that idle Keep-Alive connections
// will be kept open. After this timeout, idle connections are closed.
//
// A zero or negative value sets the default of 180 seconds.
//
// Example:
//
//	// Short idle timeout for high-throughput servers
//	server := servex.New(servex.WithIdleTimeout(30 * time.Second))
//
//	// Longer timeout for persistent connections
//	server := servex.New(servex.WithIdleTimeout(5 * time.Minute))
//
// Recommended values:
//   - Web applications: 120-180 seconds
//   - APIs with frequent requests: 60-120 seconds
//   - Microservices: 30-60 seconds
//   - WebSocket services: 300+ seconds
//
// Shorter timeouts reduce resource usage but may impact performance for
// clients making frequent requests. Longer timeouts improve performance
// but consume more server resources.
func WithIdleTimeout(tm time.Duration) Option {
	return func(op *Options) {
		op.IdleTimeout = lang.If(tm <= 0, defaultIdleTimeout, tm)
	}
}

// WithAuthToken enables simple token-based authentication using the Authorization header.
// When set, the server will check for "Authorization: Bearer <token>" headers on
// protected routes and compare against this token.
//
// Example:
//
//	// Enable simple token auth
//	server := servex.New(servex.WithAuthToken("my-secret-api-key"))
//
//	// Client usage:
//	// curl -H "Authorization: Bearer my-secret-api-key" http://localhost:8080/api/protected
//
// Use this for:
//   - Simple API authentication
//   - Service-to-service communication
//   - Development and testing
//
// For more advanced authentication with user management, JWT tokens, and roles,
// use WithAuth() or WithAuthMemoryDatabase() instead.
//
// Note: This is a simple string comparison. For production use with multiple
// users or complex authorization, consider using the full JWT authentication system.
func WithAuthToken(t string) Option {
	return func(op *Options) {
		op.AuthToken = t
	}
}

// WithMetrics sets a custom metrics collector that will be called on each HTTP request.
// The metrics handler receives the http.Request for each incoming request.
//
// Example:
//
//	type MyMetrics struct {
//		requestCount int64
//	}
//
//	func (m *MyMetrics) HandleRequest(r *http.Request) {
//		atomic.AddInt64(&m.requestCount, 1)
//		// Log request details, update counters, etc.
//	}
//
//	metrics := &MyMetrics{}
//	server := servex.New(servex.WithMetrics(metrics))
//
// Use this for:
//   - Prometheus metrics collection
//   - Custom analytics
//   - Request counting and monitoring
//   - Performance tracking
//
// The metrics handler is called for every request, so ensure it's fast and non-blocking.
func WithMetrics(m Metrics) Option {
	return func(op *Options) {
		op.Metrics = m
	}
}

// WithLogger sets a custom logger for server events, errors, and panics.
// The logger must implement the [Logger] interface. Set via WithLogger().
//
// If not set, servex will create a JSON logger that writes to stderr.
//
// The logger receives:
//   - Server startup/shutdown events (Info level)
//   - Request errors and panics (Error level)
//   - Debug information when available (Debug level)
func WithLogger(l Logger) Option {
	return func(op *Options) {
		op.Logger = l
	}
}

// WithRequestLogger sets a custom logger specifically for HTTP request logging.
// This is separate from the main logger and focuses on request/response details.
//
// If not set, it will use the main Logger in debug level for successful requests.
//
// Use for:
//   - Structured request logging
//   - Access logs
//   - Request metrics
//   - Audit trails
func WithRequestLogger(r RequestLogger) Option {
	return func(op *Options) {
		op.RequestLogger = r
	}
}

// WithNoRequestLog disables HTTP request logging completely.
// No requests will be logged regardless of status or errors.
//
// Example:
//
//	// Disable all request logging
//	server := servex.New(servex.WithNoRequestLog())
//
// Use this when:
//   - You have external request logging (load balancer, proxy)
//   - You want to reduce log volume
//   - Performance is critical and logging overhead matters
//   - You're implementing custom request logging middleware
//
// Note: This only disables request logging. Server events, errors, and panics
// will still be logged through the main logger.
func WithNoRequestLog() Option {
	return func(op *Options) {
		op.RequestLogger = &noopRequestLogger{}
		op.DisableRequestLogging = true
	}
}

// WithDisableRequestLogging disables HTTP request logging completely.
// This is an alias for WithNoRequestLog().
//
// Example:
//
//	server := servex.New(servex.WithDisableRequestLogging())
//
// See WithNoRequestLog() for detailed documentation.
func WithDisableRequestLogging() Option {
	return func(op *Options) {
		op.RequestLogger = &noopRequestLogger{}
		op.DisableRequestLogging = true
	}
}

// WithNoLogClientErrors disables logging of client errors (HTTP status codes 400-499).
// Server errors (5xx) and successful requests will still be logged if request logging is enabled.
//
// Example:
//
//	// Don't log 404s, 400s, etc. to reduce noise
//	server := servex.New(servex.WithNoLogClientErrors())
//
// Use this to:
//   - Reduce log noise from bad requests
//   - Focus on server-side issues
//   - Improve log readability in production
//
// Commonly filtered errors include:
//   - 400 Bad Request
//   - 401 Unauthorized
//   - 403 Forbidden
//   - 404 Not Found
//   - 429 Too Many Requests
func WithNoLogClientErrors() Option {
	return func(op *Options) {
		op.NoLogClientErrors = true
	}
}

// WithSendErrorToClient configures the server to include detailed error information
// in HTTP responses when errors occur. This includes Go error messages and stack traces.
//
// Example:
//
//	// Development server with detailed errors
//	server := servex.New(servex.WithSendErrorToClient())
//
//	// Production server (don't send error details)
//	server := servex.New() // Default is false
//
// When enabled, responses might include:
//   - Internal error messages
//   - Stack traces for panics
//   - Database connection errors
//   - File system errors
//
// Security considerations:
//   - NEVER enable this in production
//   - Error details can reveal system information
//   - Use only for development and testing
//   - Consider using structured error responses instead
//
// For production, implement proper error handling that returns safe, user-friendly
// error messages while logging detailed errors server-side.
func WithSendErrorToClient() Option {
	return func(op *Options) {
		op.SendErrorToClient = true
	}
}

// WithLogFields specifies which fields to include in request logs.
// If not set, all available fields will be logged (default behavior).
//
// Example:
//
//	// Log only essential fields
//	server := servex.New(servex.WithLogFields(
//		servex.MethodLogField,
//		servex.URLLogField,
//		servex.StatusLogField,
//		servex.DurationLogField,
//	))
//
//	// Log minimal fields for privacy compliance
//	server := servex.New(servex.WithLogFields(
//		servex.MethodLogField,
//		servex.StatusLogField,
//		servex.DurationLogField,
//	))
//
// Available fields:
//   - RequestIDLogField: Request ID
//   - IPLogField: Client IP address
//   - UserAgentLogField: User-Agent header
//   - URLLogField: Request URL
//   - MethodLogField: HTTP method (GET, POST, etc.)
//   - ProtoLogField: HTTP protocol version
//   - ErrorLogField: Error information
//   - ErrorMessageLogField: Error message
//   - StatusLogField: HTTP status code
//   - DurationLogField: Request duration in milliseconds
//
// Use this to:
//   - Reduce log verbosity and storage costs
//   - Focus on specific metrics or debugging needs
//   - Comply with privacy regulations (e.g., exclude IP addresses)
//   - Optimize performance by logging fewer fields
//
// Note: This only affects the default BaseRequestLogger. Custom RequestLogger
// implementations are not affected by this setting.
func WithLogFields(fields ...string) Option {
	return func(op *Options) {
		op.LogFields = fields
	}
}

// ReadCertificate is a function that reads a TLS certificate from the given cert and key bytes
// and returns a [tls.Certificate] instance.
func ReadCertificate(cert, key []byte) (tls.Certificate, error) {
	return tls.X509KeyPair(cert, key)
}

// ReadCertificateFromFile is a function that reads a TLS certificate from the given cert and key files
// and returns a [tls.Certificate] instance.
func ReadCertificateFromFile(certFile, keyFile string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}

// WithAuth enables JWT-based authentication with a custom database implementation.
// This activates the full authentication system with user management, roles, and JWT tokens.
//
// The database must implement the AuthDatabase interface for user persistence.
//
// Example:
//
//	// Custom database implementation
//	type MyAuthDB struct {
//		users map[string]*User
//	}
//
//	func (db *MyAuthDB) CreateUser(ctx context.Context, user User) error {
//		// Implementation
//	}
//	// ... implement other AuthDatabase methods
//
//	server := servex.New(servex.WithAuth(&MyAuthDB{}))
//
// This automatically registers these endpoints:
//   - POST /api/v1/auth/register - User registration
//   - POST /api/v1/auth/login - User login
//   - POST /api/v1/auth/refresh - Token refresh
//   - POST /api/v1/auth/logout - User logout
//   - GET /api/v1/auth/me - Current user info
//
// Use this for:
//   - Multi-user applications
//   - Role-based access control
//   - Persistent user data
//   - Production authentication systems
func WithAuth(db AuthDatabase) Option {
	return func(op *Options) {
		op.Auth.Enabled = true
		op.Auth.Database = db
	}
}

// WithAuthMemoryDatabase enables JWT authentication with an in-memory user database.
// This is convenient for development, testing, and applications that don't need
// persistent user data.
//
// WARNING: All users and sessions will be lost when the application restarts.
// NOT RECOMMENDED FOR PRODUCTION USE.
//
// Example:
//
//	// Development server with auth
//	server := servex.New(
//		servex.WithAuthMemoryDatabase(),
//		servex.WithAuthInitialUsers(servex.InitialUser{
//			Username: "admin",
//			Password: "admin123",
//			Roles:    []servex.UserRole{"admin"},
//		}),
//	)
//
// This automatically registers the same endpoints as WithAuth().
//
// Use this for:
//   - Development and testing
//   - Prototypes and demos
//   - Applications with temporary users
//   - Learning and experimentation
//
// For production, implement a persistent database and use WithAuth() instead.
func WithAuthMemoryDatabase() Option {
	return func(op *Options) {
		op.Auth.Enabled = true
		op.Auth.Database = NewMemoryAuthDatabase()
	}
}

// WithAuthConfig sets the complete authentication configuration at once.
// This allows fine-grained control over all authentication settings.
//
// Example:
//
//	authConfig := servex.AuthConfig{
//		Enabled:                 true,
//		Database:                myDB,
//		AccessTokenDuration:     15 * time.Minute,
//		RefreshTokenDuration:    7 * 24 * time.Hour,
//		AuthBasePath:           "/auth",
//		IssuerNameInJWT:        "my-app",
//		RefreshTokenCookieName: "_refresh",
//		RolesOnRegister:        []servex.UserRole{"user"},
//		InitialUsers: []servex.InitialUser{
//			{Username: "admin", Password: "secure-password", Roles: []servex.UserRole{"admin"}},
//		},
//	}
//
//	server := servex.New(servex.WithAuthConfig(authConfig))
//
// Use this when you need to configure multiple authentication settings at once
// or when loading configuration from files or environment variables.
func WithAuthConfig(auth AuthConfig) Option {
	return func(op *Options) {
		op.Auth = auth
	}
}

// WithAuthKey sets the JWT signing keys for access and refresh tokens.
// Keys should be hex-encoded strings. If empty, random keys will be generated.
//
// Example:
//
//	// Use specific keys (recommended for production)
//	accessKey := "your-32-byte-hex-encoded-access-key"
//	refreshKey := "your-32-byte-hex-encoded-refresh-key"
//	server := servex.New(servex.WithAuthKey(accessKey, refreshKey))
//
//	// Generate random keys (development only)
//	server := servex.New(servex.WithAuthKey("", ""))
//
// Key requirements:
//   - Use strong, randomly generated keys
//   - Access and refresh keys should be different
//   - Store keys securely (environment variables, key management systems)
//   - Rotate keys periodically in production
//
// Security considerations:
//   - Never hardcode keys in source code
//   - Use environment variables or secure configuration
//   - Different keys for different environments
//   - Consider key rotation strategies
func WithAuthKey(accessKey, refreshKey string) Option {
	return func(op *Options) {
		op.Auth.JWTAccessSecret = accessKey
		op.Auth.JWTRefreshSecret = refreshKey
	}
}

// WithAuthIssuer sets the issuer name included in JWT token claims.
// This helps identify which service issued the token and can be used for validation.
//
// Example:
//
//	// Set application name as issuer
//	server := servex.New(servex.WithAuthIssuer("my-api-service"))
//
//	// Environment-specific issuer
//	issuer := fmt.Sprintf("my-app-%s", os.Getenv("ENVIRONMENT"))
//	server := servex.New(servex.WithAuthIssuer(issuer))
//
// The issuer appears in the JWT "iss" claim and can be verified by clients.
// Default is "testing" if not set.
//
// Use descriptive names like:
//   - Application name: "user-service", "payment-api"
//   - Environment-specific: "my-app-prod", "my-app-staging"
//   - Domain-based: "api.mycompany.com"
func WithAuthIssuer(issuer string) Option {
	return func(op *Options) {
		op.Auth.IssuerNameInJWT = issuer
	}
}

// WithAuthBasePath sets the base path for authentication API endpoints.
// All auth routes will be registered under this path.
//
// Example:
//
//	// Custom auth path
//	server := servex.New(servex.WithAuthBasePath("/auth"))
//	// Endpoints: /auth/login, /auth/register, etc.
//
//	// API versioned path
//	server := servex.New(servex.WithAuthBasePath("/api/v2/auth"))
//	// Endpoints: /api/v2/auth/login, /api/v2/auth/register, etc.
//
// Default is "/api/v1/auth" if not set.
//
// Registered endpoints under the base path:
//   - POST {basePath}/register
//   - POST {basePath}/login
//   - POST {basePath}/refresh
//   - POST {basePath}/logout
//   - GET {basePath}/me
func WithAuthBasePath(path string) Option {
	return func(op *Options) {
		op.Auth.AuthBasePath = path
	}
}

// WithAuthInitialRoles sets the default roles assigned to newly registered users.
// These roles are automatically assigned when users register through the /register endpoint.
//
// Example:
//
//	// All new users get "user" role
//	server := servex.New(servex.WithAuthInitialRoles(servex.UserRole("user")))
//
//	// Multiple default roles
//	server := servex.New(servex.WithAuthInitialRoles(
//		servex.UserRole("user"),
//		servex.UserRole("customer"),
//	))
//
// Common role patterns:
//   - Basic: "user"
//   - Hierarchical: "user", "member", "premium"
//   - Functional: "reader", "writer", "admin"
//
// Users can have multiple roles. Additional roles can be assigned later
// through user management endpoints or database operations.
func WithAuthInitialRoles(roles ...UserRole) Option {
	return func(op *Options) {
		op.Auth.RolesOnRegister = roles
	}
}

// WithAuthRefreshTokenCookieName sets the name of the HTTP cookie used to store refresh tokens.
// The refresh token cookie is httpOnly and secure, providing protection against XSS attacks.
//
// Example:
//
//	// Custom cookie name
//	server := servex.New(servex.WithAuthRefreshTokenCookieName("_my_refresh_token"))
//
//	// Short name for bandwidth
//	server := servex.New(servex.WithAuthRefreshTokenCookieName("_rt"))
//
// Default is "_servexrt" if not set.
//
// Cookie characteristics:
//   - HttpOnly: Cannot be accessed by JavaScript
//   - Secure: Only sent over HTTPS (in production)
//   - SameSite: Protection against CSRF attacks
//   - Expires: Set to refresh token duration
//
// Choose names that don't conflict with your application's other cookies.
func WithAuthRefreshTokenCookieName(name string) Option {
	return func(op *Options) {
		op.Auth.RefreshTokenCookieName = name
	}
}

// WithAuthTokensDuration sets the validity duration for access and refresh tokens.
// Access tokens should be short-lived for security, while refresh tokens can be longer.
//
// Example:
//
//	// Typical web application
//	server := servex.New(servex.WithAuthTokensDuration(
//		15*time.Minute,  // Access token: 15 minutes
//		7*24*time.Hour,  // Refresh token: 7 days
//	))
//
//	// High-security application
//	server := servex.New(servex.WithAuthTokensDuration(
//		5*time.Minute,   // Access token: 5 minutes
//		24*time.Hour,    // Refresh token: 1 day
//	))
//
//	// Development environment
//	server := servex.New(servex.WithAuthTokensDuration(
//		1*time.Hour,     // Access token: 1 hour
//		30*24*time.Hour, // Refresh token: 30 days
//	))
//
// Recommended patterns:
//   - Web apps: 15-60 min access, 7-30 days refresh
//   - APIs: 5-30 min access, 1-7 days refresh
//   - Mobile apps: 30-60 min access, 30-90 days refresh
//   - High security: 5-15 min access, 1-3 days refresh
//
// Shorter access tokens improve security but require more refresh operations.
func WithAuthTokensDuration(accessDuration, refreshDuration time.Duration) Option {
	return func(op *Options) {
		op.Auth.AccessTokenDuration = accessDuration
		op.Auth.RefreshTokenDuration = refreshDuration
	}
}

// WithAuthNotRegisterRoutes prevents automatic registration of default authentication routes.
// Use this when you want to implement custom authentication endpoints or integrate
// with existing authentication systems.
//
// Example:
//
//	// Disable default auth routes
//	server := servex.New(
//		servex.WithAuthMemoryDatabase(),
//		servex.WithAuthNotRegisterRoutes(true),
//	)
//
//	// Register custom auth routes
//	server.HandleFunc("/custom/login", myCustomLoginHandler)
//	server.HandleFunc("/custom/register", myCustomRegisterHandler)
//
// When enabled, you must implement your own:
//   - User registration endpoint
//   - Login endpoint
//   - Token refresh endpoint
//   - Logout endpoint
//   - User profile endpoint
//
// You can still use the AuthManager methods for token generation and validation.
// This gives you full control over request/response formats and business logic.
func WithAuthNotRegisterRoutes(notRegisterRoutes bool) Option {
	return func(op *Options) {
		op.Auth.NotRegisterRoutes = notRegisterRoutes
	}
}

// WithAuthInitialUsers creates initial users in the database when the server starts.
// This is useful for creating admin accounts or seeding the database with test users.
//
// Example:
//
//	// Create admin user on startup
//	server := servex.New(
//		servex.WithAuthMemoryDatabase(),
//		servex.WithAuthInitialUsers(servex.InitialUser{
//			Username: "admin",
//			Password: "secure-admin-password",
//			Roles:    []servex.UserRole{"admin", "user"},
//		}),
//	)
//
//	// Multiple initial users
//	server := servex.New(
//		servex.WithAuthMemoryDatabase(),
//		servex.WithAuthInitialUsers(
//			servex.InitialUser{
//				Username: "admin",
//				Password: "admin-pass",
//				Roles:    []servex.UserRole{"admin"},
//			},
//			servex.InitialUser{
//				Username: "testuser",
//				Password: "test-pass",
//				Roles:    []servex.UserRole{"user"},
//			},
//		),
//	)
//
// Security considerations:
//   - Use strong passwords
//   - Consider loading from environment variables
//   - Remove or change default passwords in production
//   - Limit to essential accounts only
//
// The users are created if they don't already exist in the database.
func WithAuthInitialUsers(users ...InitialUser) Option {
	return func(op *Options) {
		op.Auth.InitialUsers = users
	}
}

// WithRateLimitConfig sets the complete rate limiting configuration at once.
// This allows fine-grained control over all rate limiting settings.
//
// Example:
//
//	rateLimitConfig := servex.RateLimitConfig{
//		Enabled:             true,
//		RequestsPerInterval: 100,
//		Interval:            time.Minute,
//		BurstSize:           20,
//		StatusCode:          429,
//		Message:             "Rate limit exceeded. Try again later.",
//		ExcludePaths:        []string{"/health", "/metrics"},
//		TrustedProxies:      []string{"10.0.0.0/8"},
//	}
//
//	server := servex.New(servex.WithRateLimitConfig(rateLimitConfig))
//
// Use this when you need to configure multiple rate limiting settings at once
// or when loading configuration from files or environment variables.
func WithRateLimitConfig(rateLimit RateLimitConfig) Option {
	return func(op *Options) {
		op.RateLimit = rateLimit
	}
}

// WithRPM sets rate limiting to allow a specific number of requests per minute.
// This is a convenience function for simple rate limiting configuration.
//
// Example:
//
//	// Allow 1000 requests per minute per client
//	server := servex.New(servex.WithRPM(1000))
//
//	// Strict rate limiting for public APIs
//	server := servex.New(servex.WithRPM(60)) // 1 request per second average
//
// Equivalent to:
//
//	servex.WithRequestsPerInterval(rpm, time.Minute)
//
// Common RPM values:
//   - Public APIs: 60-1000 RPM
//   - Internal APIs: 1000-10000 RPM
//   - File uploads: 10-100 RPM
//   - Authentication: 10-60 RPM
func WithRPM(rpm int) Option {
	return func(op *Options) {
		op.RateLimit.RequestsPerInterval = rpm
		op.RateLimit.Interval = time.Minute
		op.RateLimit.Enabled = true
	}
}

// WithRPS sets rate limiting to allow a specific number of requests per second.
// This is a convenience function for simple rate limiting configuration.
//
// Example:
//
//	// Allow 10 requests per second per client
//	server := servex.New(servex.WithRPS(10))
//
//	// High-throughput API
//	server := servex.New(servex.WithRPS(100))
//
// Equivalent to:
//
//	servex.WithRequestsPerInterval(rps, time.Second)
//
// Common RPS values:
//   - Web applications: 1-10 RPS
//   - APIs: 10-100 RPS
//   - High-performance APIs: 100-1000 RPS
//   - Microservices: 50-500 RPS
func WithRPS(rps int) Option {
	return func(op *Options) {
		op.RateLimit.RequestsPerInterval = rps
		op.RateLimit.Interval = time.Second
		op.RateLimit.Enabled = true
	}
}

// WithRequestsPerInterval sets custom rate limiting with a specific number of requests
// allowed per time interval. This provides maximum flexibility for rate limiting configuration.
//
// Example:
//
//	// 500 requests per 5 minutes
//	server := servex.New(servex.WithRequestsPerInterval(500, 5*time.Minute))
//
//	// 50 requests per 30 seconds
//	server := servex.New(servex.WithRequestsPerInterval(50, 30*time.Second))
//
//	// 1000 requests per hour
//	server := servex.New(servex.WithRequestsPerInterval(1000, time.Hour))
//
// Use cases:
//   - Custom business requirements
//   - Unusual time windows
//   - Integration with external rate limits
//   - Compliance with API provider limits
//
// The rate limiter uses a token bucket algorithm, refilling tokens at a constant rate.
func WithRequestsPerInterval(requestsPerInterval int, interval time.Duration) Option {
	return func(op *Options) {
		op.RateLimit.RequestsPerInterval = requestsPerInterval
		op.RateLimit.Interval = interval
		op.RateLimit.Enabled = true
	}
}

// WithBurstSize sets the maximum burst size for rate limiting.
// This allows clients to exceed the normal rate limit temporarily by "bursting".
//
// Example:
//
//	// 10 RPS with burst of 50 requests
//	server := servex.New(
//		servex.WithRPS(10),
//		servex.WithBurstSize(50),
//	)
//
//	// No bursting allowed
//	server := servex.New(
//		servex.WithRPS(10),
//		servex.WithBurstSize(1),
//	)
//
// How it works:
//   - Clients can make up to burstSize requests immediately
//   - After bursting, they must wait for tokens to refill
//   - Tokens refill at the configured rate (RPS/RPM)
//
// Use cases:
//   - Handle traffic spikes gracefully
//   - Allow batch operations
//   - Improve user experience for bursty clients
//   - Balance performance with protection
//
// If not set, defaults to the requests per interval value.
func WithBurstSize(burstSize int) Option {
	return func(op *Options) {
		op.RateLimit.BurstSize = burstSize
		op.RateLimit.Enabled = true
	}
}

// WithRateLimitStatusCode sets the HTTP status code returned when rate limit is exceeded.
// Default is 429 (Too Many Requests) if not set.
//
// Example:
//
//	// Use standard 429 status
//	server := servex.New(
//		servex.WithRPS(10),
//		servex.WithRateLimitStatusCode(429),
//	)
//
//	// Use 503 Service Unavailable
//	server := servex.New(
//		servex.WithRPS(10),
//		servex.WithRateLimitStatusCode(503),
//	)
//
// Common status codes:
//   - 429 Too Many Requests (recommended)
//   - 503 Service Unavailable
//   - 502 Bad Gateway (for proxy scenarios)
//
// The 429 status code is specifically designed for rate limiting and is
// understood by most HTTP clients and libraries.
func WithRateLimitStatusCode(statusCode int) Option {
	return func(op *Options) {
		op.RateLimit.StatusCode = statusCode
		op.RateLimit.Enabled = true
	}
}

// WithRateLimitMessage sets the response message when rate limit is exceeded.
// Default is "rate limit exceeded, try again later." if not set.
//
// Example:
//
//	// Custom rate limit message
//	server := servex.New(
//		servex.WithRPS(10),
//		servex.WithRateLimitMessage("Too many requests. Please slow down and try again in a few moments."),
//	)
//
//	// Include retry information
//	server := servex.New(
//		servex.WithRPM(100),
//		servex.WithRateLimitMessage("Rate limit exceeded. Maximum 100 requests per minute allowed."),
//	)
//
// Best practices:
//   - Be clear about the limit
//   - Suggest when to retry
//   - Keep messages user-friendly
//   - Include contact information for questions
//
// The message is returned as plain text in the response body.
func WithRateLimitMessage(message string) Option {
	return func(op *Options) {
		op.RateLimit.Message = message
		op.RateLimit.Enabled = true
	}
}

// WithRateLimitKeyFunc sets a custom function to extract the rate limit key from requests.
// This determines how clients are identified for rate limiting purposes.
//
// Example:
//
//	// Rate limit by IP address
//	server := servex.New(
//		servex.WithRPS(10),
//		servex.WithRateLimitKeyFunc(func(r *http.Request) string {
//			return r.RemoteAddr
//		}),
//	)
//
//	// Rate limit by API key
//	server := servex.New(
//		servex.WithRPS(100),
//		servex.WithRateLimitKeyFunc(func(r *http.Request) string {
//			apiKey := r.Header.Get("X-API-Key")
//			if apiKey == "" {
//				return r.RemoteAddr // Fallback to IP
//			}
//			return "api:" + apiKey
//		}),
//	)
//
//	// Rate limit by user ID (requires auth)
//	server := servex.New(
//		servex.WithRPS(50),
//		servex.WithRateLimitKeyFunc(func(r *http.Request) string {
//			userID := r.Context().Value("userID")
//			if userID != nil {
//				return "user:" + userID.(string)
//			}
//			return r.RemoteAddr
//		}),
//	)
//
// Default behavior uses client IP address. Custom key functions enable:
//   - User-based rate limiting
//   - API key-based limits
//   - Different limits for different client types
//   - Combined identification strategies
func WithRateLimitKeyFunc(keyFunc func(r *http.Request) string) Option {
	return func(op *Options) {
		op.RateLimit.KeyFunc = keyFunc
		op.RateLimit.Enabled = true
	}
}

// WithRateLimitExcludePaths excludes specific paths from rate limiting.
// Requests to these paths will not be counted against rate limits.
//
// Example:
//
//	// Exclude monitoring endpoints
//	server := servex.New(
//		servex.WithRPS(10),
//		servex.WithRateLimitExcludePaths("/health", "/metrics", "/status"),
//	)
//
//	// Exclude static assets
//	server := servex.New(
//		servex.WithRPS(100),
//		servex.WithRateLimitExcludePaths("/static/*", "/assets/*", "/favicon.ico"),
//	)
//
// Common exclusions:
//   - Health checks: "/health", "/ping"
//   - Metrics: "/metrics", "/stats"
//   - Static files: "/static/*", "/assets/*"
//   - Documentation: "/docs/*", "/swagger/*"
//   - Infrastructure: "/robots.txt", "/favicon.ico"
//
// Path matching supports wildcards (*) for pattern matching.
func WithRateLimitExcludePaths(paths ...string) Option {
	return func(op *Options) {
		op.RateLimit.ExcludePaths = append(op.RateLimit.ExcludePaths, paths...)
		op.RateLimit.Enabled = true
	}
}

// WithRateLimitIncludePaths specifies which paths should be rate limited.
// If set, only requests to these paths will be rate limited. All other paths are excluded.
//
// Example:
//
//	// Only rate limit API endpoints
//	server := servex.New(
//		servex.WithRPS(100),
//		servex.WithRateLimitIncludePaths("/api/*"),
//	)
//
//	// Rate limit specific sensitive endpoints
//	server := servex.New(
//		servex.WithRPS(5),
//		servex.WithRateLimitIncludePaths("/api/auth/*", "/api/admin/*"),
//	)
//
// If both IncludePaths and ExcludePaths are set:
//  1. Paths must match IncludePaths to be rate limited
//  2. Paths in ExcludePaths are then excluded from rate limiting
//
// Use cases:
//   - Protect only sensitive endpoints
//   - Apply different limits to different API versions
//   - Rate limit only external-facing endpoints
//   - Granular control over protection
func WithRateLimitIncludePaths(paths ...string) Option {
	return func(op *Options) {
		op.RateLimit.IncludePaths = append(op.RateLimit.IncludePaths, paths...)
		op.RateLimit.Enabled = true
	}
}

// WithRateLimitTrustedProxies sets trusted proxy IP addresses or CIDR ranges
// for accurate client IP detection in rate limiting.
//
// Example:
//
//	// Trust load balancer IPs
//	server := servex.New(
//		servex.WithRPS(10),
//		servex.WithRateLimitTrustedProxies("10.0.0.0/8", "172.16.0.0/12"),
//	)
//
//	// Trust specific proxy servers
//	server := servex.New(
//		servex.WithRPS(100),
//		servex.WithRateLimitTrustedProxies("192.168.1.100", "192.168.1.101"),
//	)
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
func WithRateLimitTrustedProxies(proxies ...string) Option {
	return func(op *Options) {
		op.RateLimit.TrustedProxies = append(op.RateLimit.TrustedProxies, proxies...)
		op.RateLimit.Enabled = true
	}
}

// WithFilterConfig sets the complete request filtering configuration at once.
// This allows fine-grained control over all filtering settings for IP addresses,
// User-Agents, headers, and query parameters.
//
// Example:
//
//	filterConfig := servex.FilterConfig{
//		AllowedIPs: []string{"10.0.0.0/8", "192.168.1.100"},
//		BlockedUserAgents: []string{"BadBot", "Scraper"},
//		AllowedHeaders: map[string][]string{
//			"X-API-Version": {"v1", "v2"},
//		},
//		StatusCode: 403,
//		Message: "Access denied by security filter",
//		ExcludePaths: []string{"/health", "/public/*"},
//	}
//
//	server := servex.New(servex.WithFilterConfig(filterConfig))
//
// Use this when you need to configure multiple filtering settings at once
// or when loading configuration from files or environment variables.
func WithFilterConfig(filter FilterConfig) Option {
	return func(op *Options) {
		op.Filter = filter
	}
}

// WithAllowedIPs restricts access to specific IP addresses or CIDR ranges.
// Only requests from these IPs will be allowed. All other IPs are blocked.
//
// Example:
//
//	// Allow specific office IPs
//	server := servex.New(servex.WithAllowedIPs(
//		"192.168.1.0/24",    // Office network
//		"203.0.113.100",     // VPN gateway
//		"10.0.0.0/8",        // Internal network
//	))
//
//	// Allow only localhost
//	server := servex.New(servex.WithAllowedIPs("127.0.0.1", "::1"))
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
// If empty, all IPs are allowed unless blocked by WithBlockedIPs().
func WithAllowedIPs(ips ...string) Option {
	return func(op *Options) {
		op.Filter.AllowedIPs = append(op.Filter.AllowedIPs, ips...)
	}
}

// WithBlockedIPs blocks access from specific IP addresses or CIDR ranges.
// Requests from these IPs will be denied with a 403 Forbidden response.
//
// Example:
//
//	// Block known malicious IPs
//	server := servex.New(servex.WithBlockedIPs(
//		"203.0.113.0/24",    // Known spam network
//		"198.51.100.50",     // Specific malicious IP
//		"192.0.2.0/24",      // Blocked range
//	))
//
//	// Block competitors from scraping
//	server := servex.New(servex.WithBlockedIPs("competitor-ip-range"))
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
func WithBlockedIPs(ips ...string) Option {
	return func(op *Options) {
		op.Filter.BlockedIPs = append(op.Filter.BlockedIPs, ips...)
	}
}

// WithAllowedUserAgents restricts access to specific User-Agent strings.
// Only requests with these exact User-Agent headers will be allowed.
//
// Example:
//
//	// Allow only your mobile app
//	server := servex.New(servex.WithAllowedUserAgents(
//		"MyApp/1.0 (iOS)",
//		"MyApp/1.0 (Android)",
//	))
//
//	// Allow specific browsers
//	server := servex.New(servex.WithAllowedUserAgents(
//		"Mozilla/5.0 Chrome/120.0.0.0",
//		"Mozilla/5.0 Safari/537.36",
//	))
//
// For pattern matching instead of exact strings, use WithAllowedUserAgentsRegex().
//
// Use cases:
//   - Restrict API to your apps only
//   - Block automated scrapers
//   - Allow only supported browsers
//   - Partner API access control
//
// If empty, all User-Agents are allowed unless blocked by WithBlockedUserAgents().
func WithAllowedUserAgents(userAgents ...string) Option {
	return func(op *Options) {
		op.Filter.AllowedUserAgents = append(op.Filter.AllowedUserAgents, userAgents...)
	}
}

// WithAllowedUserAgentsRegex restricts access using User-Agent regex patterns.
// Only requests with User-Agent headers matching these patterns will be allowed.
//
// Example:
//
//	// Allow any Chrome browser
//	server := servex.New(servex.WithAllowedUserAgentsRegex(
//		`Chrome/\d+\.\d+`,
//	))
//
//	// Allow your app with any version
//	server := servex.New(servex.WithAllowedUserAgentsRegex(
//		`^MyApp/\d+\.\d+ \((iOS|Android)\)$`,
//	))
//
//	// Allow major browsers
//	server := servex.New(servex.WithAllowedUserAgentsRegex(
//		`(Chrome|Firefox|Safari|Edge)/\d+`,
//	))
//
// Regex features:
//   - Use standard Go regex syntax
//   - Case-sensitive matching
//   - ^ and $ for exact matching
//   - \d+ for version numbers
//   - | for alternatives
//
// This is more flexible than WithAllowedUserAgents() for version-aware filtering.
func WithAllowedUserAgentsRegex(patterns ...string) Option {
	return func(op *Options) {
		op.Filter.AllowedUserAgentsRegex = append(op.Filter.AllowedUserAgentsRegex, patterns...)
	}
}

// WithBlockedUserAgents blocks access from specific User-Agent strings.
// Requests with these exact User-Agent headers will be denied.
//
// Example:
//
//	// Block common bots
//	server := servex.New(servex.WithBlockedUserAgents(
//		"Googlebot",
//		"Bingbot",
//		"facebookexternalhit",
//		"Twitterbot",
//	))
//
//	// Block scrapers
//	server := servex.New(servex.WithBlockedUserAgents(
//		"curl/7.68.0",
//		"wget",
//		"python-requests",
//		"scrapy",
//	))
//
// For pattern matching instead of exact strings, use WithBlockedUserAgentsRegex().
//
// Use cases:
//   - Block automated scrapers
//   - Prevent bot traffic
//   - Block specific tools
//   - Temporary user-agent bans
//
// Note: BlockedUserAgents takes precedence over AllowedUserAgents.
func WithBlockedUserAgents(userAgents ...string) Option {
	return func(op *Options) {
		op.Filter.BlockedUserAgents = append(op.Filter.BlockedUserAgents, userAgents...)
	}
}

// WithBlockedUserAgentsRegex blocks access using User-Agent regex patterns.
// Requests with User-Agent headers matching these patterns will be denied.
//
// Example:
//
//	// Block all bots and crawlers
//	server := servex.New(servex.WithBlockedUserAgentsRegex(
//		`(?i)(bot|crawler|spider|scraper)`,
//	))
//
//	// Block command line tools
//	server := servex.New(servex.WithBlockedUserAgentsRegex(
//		`^(curl|wget|python-requests)`,
//	))
//
//	// Block old browser versions
//	server := servex.New(servex.WithBlockedUserAgentsRegex(
//		`MSIE [1-9]\.`,  // IE 9 and below
//	))
//
// Regex features:
//   - (?i) for case-insensitive matching
//   - Use standard Go regex syntax
//   - ^ and $ for exact matching
//   - | for alternatives
//
// Note: BlockedUserAgentsRegex takes precedence over AllowedUserAgentsRegex.
func WithBlockedUserAgentsRegex(patterns ...string) Option {
	return func(op *Options) {
		op.Filter.BlockedUserAgentsRegex = append(op.Filter.BlockedUserAgentsRegex, patterns...)
	}
}

// WithAllowedHeaders restricts requests based on header values.
// Only requests with headers matching the specified exact values will be allowed.
//
// Example:
//
//	// Require specific API version
//	server := servex.New(servex.WithAllowedHeaders(map[string][]string{
//		"X-API-Version": {"v1", "v2"},
//		"Content-Type":  {"application/json"},
//	}))
//
//	// Require authentication header
//	server := servex.New(servex.WithAllowedHeaders(map[string][]string{
//		"Authorization": {"Bearer token1", "Bearer token2"},
//	}))
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
// For pattern matching instead of exact values, use WithAllowedHeadersRegex().
func WithAllowedHeaders(headers map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.AllowedHeaders == nil {
			op.Filter.AllowedHeaders = make(map[string][]string)
		}
		for k, v := range headers {
			op.Filter.AllowedHeaders[k] = append(op.Filter.AllowedHeaders[k], v...)
		}
	}
}

// WithAllowedHeadersRegex restricts requests based on header regex patterns.
// Only requests with headers matching the specified patterns will be allowed.
//
// Example:
//
//	// Allow any Bearer token
//	server := servex.New(servex.WithAllowedHeadersRegex(map[string][]string{
//		"Authorization": {`^Bearer [A-Za-z0-9+/=]+$`},
//	}))
//
//	// Allow semantic versioning
//	server := servex.New(servex.WithAllowedHeadersRegex(map[string][]string{
//		"X-API-Version": {`^v\d+\.\d+$`},  // v1.0, v2.1, etc.
//	}))
//
//	// Validate custom headers
//	server := servex.New(servex.WithAllowedHeadersRegex(map[string][]string{
//		"X-Request-ID": {`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`},
//	}))
//
// Regex features:
//   - Header names are case-insensitive
//   - Use standard Go regex syntax
//   - ^ and $ for exact matching
//   - Multiple patterns per header (OR logic)
//
// This is more flexible than WithAllowedHeaders() for pattern-based validation.
func WithAllowedHeadersRegex(headers map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.AllowedHeadersRegex == nil {
			op.Filter.AllowedHeadersRegex = make(map[string][]string)
		}
		for k, v := range headers {
			op.Filter.AllowedHeadersRegex[k] = append(op.Filter.AllowedHeadersRegex[k], v...)
		}
	}
}

// WithBlockedHeaders blocks requests based on header values.
// Requests with headers matching the specified exact values will be denied.
//
// Example:
//
//	// Block suspicious headers
//	server := servex.New(servex.WithBlockedHeaders(map[string][]string{
//		"X-Forwarded-For": {"malicious-proxy-ip"},
//		"User-Agent":      {"BadBot/1.0"},
//	}))
//
//	// Block old API versions
//	server := servex.New(servex.WithBlockedHeaders(map[string][]string{
//		"X-API-Version": {"v0.1", "v0.2"},
//	}))
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
func WithBlockedHeaders(headers map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.BlockedHeaders == nil {
			op.Filter.BlockedHeaders = make(map[string][]string)
		}
		for k, v := range headers {
			op.Filter.BlockedHeaders[k] = append(op.Filter.BlockedHeaders[k], v...)
		}
	}
}

// WithBlockedHeadersRegex blocks requests based on header regex patterns.
// Requests with headers matching the specified patterns will be denied.
//
// Example:
//
//	// Block requests with suspicious X-Forwarded-For
//	server := servex.New(servex.WithBlockedHeadersRegex(map[string][]string{
//		"X-Forwarded-For": {`(10\.0\.0\.|192\.168\.)`},  // Block internal IPs
//	}))
//
//	// Block old user agents
//	server := servex.New(servex.WithBlockedHeadersRegex(map[string][]string{
//		"User-Agent": {`(?i)(bot|crawler|spider)`},
//	}))
//
// Regex features:
//   - Header names are case-insensitive
//   - (?i) for case-insensitive pattern matching
//   - Use standard Go regex syntax
//   - Multiple patterns per header (OR logic)
//
// Note: BlockedHeadersRegex takes precedence over AllowedHeadersRegex.
func WithBlockedHeadersRegex(headers map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.BlockedHeadersRegex == nil {
			op.Filter.BlockedHeadersRegex = make(map[string][]string)
		}
		for k, v := range headers {
			op.Filter.BlockedHeadersRegex[k] = append(op.Filter.BlockedHeadersRegex[k], v...)
		}
	}
}

// WithAllowedQueryParams restricts requests based on query parameter values.
// Only requests with query parameters matching the specified exact values will be allowed.
//
// Example:
//
//	// Require specific API version
//	server := servex.New(servex.WithAllowedQueryParams(map[string][]string{
//		"version": {"v1", "v2"},
//		"format":  {"json", "xml"},
//	}))
//
//	// Require valid sort parameters
//	server := servex.New(servex.WithAllowedQueryParams(map[string][]string{
//		"sort": {"name", "date", "price"},
//		"order": {"asc", "desc"},
//	}))
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
// For pattern matching instead of exact values, use WithAllowedQueryParamsRegex().
func WithAllowedQueryParams(params map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.AllowedQueryParams == nil {
			op.Filter.AllowedQueryParams = make(map[string][]string)
		}
		for k, v := range params {
			op.Filter.AllowedQueryParams[k] = append(op.Filter.AllowedQueryParams[k], v...)
		}
	}
}

// WithAllowedQueryParamsRegex restricts requests based on query parameter regex patterns.
// Only requests with query parameters matching the specified patterns will be allowed.
//
// Example:
//
//	// Allow numeric IDs only
//	server := servex.New(servex.WithAllowedQueryParamsRegex(map[string][]string{
//		"id": {`^\d+$`},
//		"page": {`^[1-9]\d*$`},  // Positive integers only
//	}))
//
//	// Validate email format
//	server := servex.New(servex.WithAllowedQueryParamsRegex(map[string][]string{
//		"email": {`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`},
//	}))
//
//	// Allow UUID format
//	server := servex.New(servex.WithAllowedQueryParamsRegex(map[string][]string{
//		"uuid": {`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`},
//	}))
//
// Regex features:
//   - Parameter names are case-sensitive
//   - Use standard Go regex syntax
//   - ^ and $ for exact matching
//   - Multiple patterns per parameter (OR logic)
//
// This is more flexible than WithAllowedQueryParams() for format validation.
func WithAllowedQueryParamsRegex(params map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.AllowedQueryParamsRegex == nil {
			op.Filter.AllowedQueryParamsRegex = make(map[string][]string)
		}
		for k, v := range params {
			op.Filter.AllowedQueryParamsRegex[k] = append(op.Filter.AllowedQueryParamsRegex[k], v...)
		}
	}
}

// WithBlockedQueryParams blocks requests based on query parameter values.
// Requests with query parameters matching the specified exact values will be denied.
//
// Example:
//
//	// Block dangerous parameters
//	server := servex.New(servex.WithBlockedQueryParams(map[string][]string{
//		"debug": {"true", "1"},
//		"admin": {"true", "1"},
//	}))
//
//	// Block SQL injection attempts
//	server := servex.New(servex.WithBlockedQueryParams(map[string][]string{
//		"id": {"'; DROP TABLE users; --"},
//	}))
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
func WithBlockedQueryParams(params map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.BlockedQueryParams == nil {
			op.Filter.BlockedQueryParams = make(map[string][]string)
		}
		for k, v := range params {
			op.Filter.BlockedQueryParams[k] = append(op.Filter.BlockedQueryParams[k], v...)
		}
	}
}

// WithBlockedQueryParamsRegex blocks requests based on query parameter regex patterns.
// Requests with query parameters matching the specified patterns will be denied.
//
// Example:
//
//	// Block SQL injection patterns
//	server := servex.New(servex.WithBlockedQueryParamsRegex(map[string][]string{
//		"search": {`(?i)(union|select|drop|delete|insert|update)`},
//	}))
//
//	// Block script injection
//	server := servex.New(servex.WithBlockedQueryParamsRegex(map[string][]string{
//		"callback": {`(?i)(<script|javascript:|vbscript:)`},
//	}))
//
//	// Block excessive length
//	server := servex.New(servex.WithBlockedQueryParamsRegex(map[string][]string{
//		"query": {`.{1000,}`},  // Block queries longer than 1000 chars
//	}))
//
// Regex features:
//   - Parameter names are case-sensitive
//   - (?i) for case-insensitive pattern matching
//   - Use standard Go regex syntax
//   - Multiple patterns per parameter (OR logic)
//
// Note: BlockedQueryParamsRegex takes precedence over AllowedQueryParamsRegex.
func WithBlockedQueryParamsRegex(params map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.BlockedQueryParamsRegex == nil {
			op.Filter.BlockedQueryParamsRegex = make(map[string][]string)
		}
		for k, v := range params {
			op.Filter.BlockedQueryParamsRegex[k] = append(op.Filter.BlockedQueryParamsRegex[k], v...)
		}
	}
}

// WithFilterExcludePaths excludes specific paths from request filtering.
// Requests to these paths will bypass all filtering rules.
//
// Example:
//
//	// Exclude public endpoints from filtering
//	server := servex.New(
//		servex.WithAllowedIPs("192.168.1.0/24"),
//		servex.WithFilterExcludePaths("/health", "/public/*", "/docs/*"),
//	)
//
//	// Exclude monitoring from strict filtering
//	server := servex.New(
//		servex.WithBlockedUserAgents("curl"),
//		servex.WithFilterExcludePaths("/metrics", "/status", "/ping"),
//	)
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
func WithFilterExcludePaths(paths ...string) Option {
	return func(op *Options) {
		op.Filter.ExcludePaths = append(op.Filter.ExcludePaths, paths...)
	}
}

// WithFilterIncludePaths specifies which paths should be filtered.
// If set, only requests to these paths will be subject to filtering rules.
//
// Example:
//
//	// Only filter admin endpoints
//	server := servex.New(
//		servex.WithAllowedIPs("192.168.1.0/24"),
//		servex.WithFilterIncludePaths("/admin/*", "/api/admin/*"),
//	)
//
//	// Filter only sensitive API endpoints
//	server := servex.New(
//		servex.WithBlockedUserAgents("curl", "wget"),
//		servex.WithFilterIncludePaths("/api/sensitive/*", "/api/payment/*"),
//	)
//
// If both IncludePaths and ExcludePaths are set:
//  1. Paths must match IncludePaths to be filtered
//  2. Paths in ExcludePaths are then excluded from filtering
//
// Use cases:
//   - Protect only sensitive endpoints
//   - Apply filtering to specific API versions
//   - Filter only external-facing endpoints
//   - Granular security control
//
// Path matching supports wildcards (*) for pattern matching.
func WithFilterIncludePaths(paths ...string) Option {
	return func(op *Options) {
		op.Filter.IncludePaths = append(op.Filter.IncludePaths, paths...)
	}
}

// WithFilterStatusCode sets the HTTP status code returned when requests are blocked by filters.
// Default is 403 (Forbidden) if not set.
//
// Example:
//
//	// Use standard 403 Forbidden
//	server := servex.New(
//		servex.WithAllowedIPs("192.168.1.0/24"),
//		servex.WithFilterStatusCode(403),
//	)
//
//	// Use 404 to hide the existence of endpoints
//	server := servex.New(
//		servex.WithBlockedUserAgents("BadBot"),
//		servex.WithFilterStatusCode(404),
//	)
//
//	// Use 429 to indicate rate limiting (misleading but sometimes useful)
//	server := servex.New(
//		servex.WithBlockedIPs("malicious-range"),
//		servex.WithFilterStatusCode(429),
//	)
//
// Common status codes:
//   - 403 Forbidden (recommended) - Clear about blocking
//   - 404 Not Found - Hides endpoint existence
//   - 401 Unauthorized - Suggests authentication needed
//   - 429 Too Many Requests - Can mislead attackers
//
// Choose based on your security strategy and user experience needs.
func WithFilterStatusCode(statusCode int) Option {
	return func(op *Options) {
		op.Filter.StatusCode = statusCode
	}
}

// WithFilterMessage sets the response message when requests are blocked by filters.
// Default is "Request blocked by security filter" if not set.
//
// Example:
//
//	// Generic security message
//	server := servex.New(
//		servex.WithAllowedIPs("192.168.1.0/24"),
//		servex.WithFilterMessage("Access denied for security reasons"),
//	)
//
//	// Specific filter message
//	server := servex.New(
//		servex.WithBlockedUserAgents("BadBot"),
//		servex.WithFilterMessage("Your user agent is not allowed"),
//	)
//
//	// Helpful message with contact info
//	server := servex.New(
//		servex.WithAllowedHeaders(map[string][]string{"X-API-Key": {"validkey"}}),
//		servex.WithFilterMessage("Missing or invalid API key. Contact support@example.com for access."),
//	)
//
// Best practices:
//   - Be clear but not too specific about the filter
//   - Include contact information for legitimate users
//   - Avoid revealing security implementation details
//   - Keep messages user-friendly
//
// The message is returned as plain text in the response body.
func WithFilterMessage(message string) Option {
	return func(op *Options) {
		op.Filter.Message = message
	}
}

// WithFilterTrustedProxies sets trusted proxy IP addresses or CIDR ranges
// for accurate client IP detection in filtering.
//
// Example:
//
//	// Trust load balancer IPs for filtering
//	server := servex.New(
//		servex.WithAllowedIPs("192.168.1.0/24"),
//		servex.WithFilterTrustedProxies("10.0.0.0/8", "172.16.0.0/12"),
//	)
//
//	// Trust specific proxy servers
//	server := servex.New(
//		servex.WithBlockedIPs("malicious-range"),
//		servex.WithFilterTrustedProxies("192.168.1.100", "192.168.1.101"),
//	)
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
//   - Consider using separate trusted proxy lists for different purposes
func WithFilterTrustedProxies(proxies ...string) Option {
	return func(op *Options) {
		op.Filter.TrustedProxies = append(op.Filter.TrustedProxies, proxies...)
	}
}

// WithHealthEndpoint enables an automatic health check endpoint that returns server status.
// This creates a simple endpoint that responds with "OK" and HTTP 200 status.
//
// Example:
//
//	// Enable health endpoint at default path
//	server := servex.New(servex.WithHealthEndpoint())
//	// Available at: GET /health
//
//	// Custom health path
//	server := servex.New(
//		servex.WithHealthEndpoint(),
//		servex.WithHealthPath("/status"),
//	)
//	// Available at: GET /status
//
// The health endpoint:
//   - Returns 200 OK with "OK" body when server is running
//   - Bypasses authentication and filtering
//   - Suitable for load balancer health checks
//   - Kubernetes liveness/readiness probes
//   - Monitoring systems
//
// Use cases:
//   - Load balancer health checks
//   - Kubernetes probes
//   - Monitoring and alerting
//   - Service discovery
//   - Uptime monitoring
//
// For custom health logic, implement your own endpoint instead of using this option.
func WithHealthEndpoint() Option {
	return func(op *Options) {
		op.EnableHealthEndpoint = true
		if op.HealthPath == "" {
			op.HealthPath = "/health"
		}
	}
}

// WithHealthPath sets a custom path for the health check endpoint.
// This only works when WithHealthEndpoint() is also used.
//
// Example:
//
//	// Custom health check path
//	server := servex.New(
//		servex.WithHealthEndpoint(),
//		servex.WithHealthPath("/ping"),
//	)
//	// Available at: GET /ping
//
//	// Health check for specific service
//	server := servex.New(
//		servex.WithHealthEndpoint(),
//		servex.WithHealthPath("/api/v1/health"),
//	)
//	// Available at: GET /api/v1/health
//
// Common health check paths:
//   - "/health" (default)
//   - "/ping"
//   - "/status"
//   - "/healthz" (Kubernetes style)
//   - "/alive"
//   - "/ready"
//
// Default is "/health" if not specified.
// The path should start with "/" and be unique to avoid conflicts.
func WithHealthPath(path string) Option {
	return func(op *Options) {
		op.HealthPath = path
		// Enable health endpoint if path is set
		if path != "" {
			op.EnableHealthEndpoint = true
		}
	}
}

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
//   - X-XSS-Protection: 1; mode=block
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
		op.Security.XXSSProtection = "1; mode=block"
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
//   - Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY
//   - X-XSS-Protection: 1; mode=block
//   - Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - Permissions-Policy: camera=(), microphone=(), geolocation=()
//   - X-Permitted-Cross-Domain-Policies: none
//   - Cross-Origin-Embedder-Policy: require-corp
//   - Cross-Origin-Opener-Policy: same-origin
//   - Cross-Origin-Resource-Policy: same-site
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
// Test thoroughly and adjust headers as needed for your application.
func WithStrictSecurityHeaders() Option {
	return func(op *Options) {
		op.Security.Enabled = true
		op.Security.ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
		op.Security.XContentTypeOptions = "nosniff"
		op.Security.XFrameOptions = "DENY"
		op.Security.XXSSProtection = "1; mode=block"
		op.Security.StrictTransportSecurity = "max-age=31536000; includeSubDomains; preload"
		op.Security.ReferrerPolicy = "strict-origin-when-cross-origin"
		op.Security.PermissionsPolicy = "camera=(), microphone=(), geolocation=()"
		op.Security.XPermittedCrossDomainPolicies = "none"
		op.Security.CrossOriginEmbedderPolicy = "require-corp"
		op.Security.CrossOriginOpenerPolicy = "same-origin"
		op.Security.CrossOriginResourcePolicy = "same-site"
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
// Important: Only include headers that actually affect the response to avoid cache fragmentation.
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
func WithMaxRequestBodySize(size int64) Option {
	return func(opts *Options) {
		opts.MaxRequestBodySize = size
		opts.EnableRequestSizeLimits = true
	}
}

// WithMaxJSONBodySize sets the maximum allowed JSON request body size in bytes.
// This specifically applies to JSON payloads and takes precedence over MaxRequestBodySize for JSON.
//
// Recommended values:
//   - API servers: WithMaxJSONBodySize(5 << 20) // 5 MB
//   - Configuration APIs: WithMaxJSONBodySize(1 << 20) // 1 MB
//   - Data import APIs: WithMaxJSONBodySize(50 << 20) // 50 MB
//   - Real-time APIs: WithMaxJSONBodySize(1 << 20) // 1 MB
//
// Smaller JSON limits help prevent JSON parsing attacks and reduce memory usage.
func WithMaxJSONBodySize(size int64) Option {
	return func(opts *Options) {
		opts.MaxJSONBodySize = size
		opts.EnableRequestSizeLimits = true
	}
}

// WithMaxFileUploadSize sets the maximum allowed file upload size in bytes.
// This applies to multipart form uploads and file uploads.
//
// Common configurations:
//   - Profile images: WithMaxFileUploadSize(10 << 20) // 10 MB
//   - Document uploads: WithMaxFileUploadSize(200 << 20) // 200 MB
//   - Media files: WithMaxFileUploadSize(2 << 30) // 2 GB
//   - Data imports: WithMaxFileUploadSize(1 << 30) // 1 GB
//
// Consider your server's available memory and disk space when setting this limit.
func WithMaxFileUploadSize(size int64) Option {
	return func(opts *Options) {
		opts.MaxFileUploadSize = size
		opts.EnableRequestSizeLimits = true
	}
}

// WithMaxMultipartMemory sets the maximum memory used for multipart form parsing in bytes.
// Files larger than this are stored in temporary files on disk.
//
// Balance considerations:
//   - Higher values: Faster processing, more memory usage
//   - Lower values: Slower processing, less memory usage, more disk I/O
//
// Recommended: 10-50 MB for most applications
// Example: WithMaxMultipartMemory(32 << 20) // 32 MB
func WithMaxMultipartMemory(size int64) Option {
	return func(opts *Options) {
		opts.MaxMultipartMemory = size
	}
}

// WithEnableRequestSizeLimits enables global request size limit middleware.
// When enabled, all requests are checked against the configured size limits.
// Individual endpoints can still use smaller limits via context methods.
//
// Use cases for disabling:
//   - Fine-grained control per endpoint
//   - Custom size limit middleware
//   - Performance-critical applications
//   - Legacy compatibility
func WithEnableRequestSizeLimits(enable bool) Option {
	return func(opts *Options) {
		opts.EnableRequestSizeLimits = enable
	}
}

// WithRequestSizeLimits configures comprehensive request size limits with commonly used defaults.
// This is a convenience function that sets up reasonable defaults for most applications.
//
// Default limits set:
//   - MaxRequestBodySize: 32 MB
//   - MaxJSONBodySize: 1 MB
//   - MaxFileUploadSize: 100 MB
//   - MaxMultipartMemory: 10 MB
//   - EnableRequestSizeLimits: true
//
// Use individual WithMax* functions for custom limits.
func WithRequestSizeLimits() Option {
	return func(opts *Options) {
		opts.MaxRequestBodySize = 32 << 20 // 32 MB
		opts.MaxJSONBodySize = 1 << 20     // 1 MB
		opts.MaxFileUploadSize = 100 << 20 // 100 MB
		opts.MaxMultipartMemory = 10 << 20 // 10 MB
		opts.EnableRequestSizeLimits = true
	}
}

// WithStrictRequestSizeLimits configures strict request size limits for security-sensitive applications.
// This sets more restrictive limits than the default WithRequestSizeLimits().
//
// Strict limits set:
//   - MaxRequestBodySize: 5 MB
//   - MaxJSONBodySize: 512 KB
//   - MaxFileUploadSize: 10 MB
//   - MaxMultipartMemory: 5 MB
//   - EnableRequestSizeLimits: true
//
// Use for applications where security is more important than convenience.
func WithStrictRequestSizeLimits() Option {
	return func(opts *Options) {
		opts.MaxRequestBodySize = 5 << 20 // 5 MB
		opts.MaxJSONBodySize = 512 << 10  // 512 KB
		opts.MaxFileUploadSize = 10 << 20 // 10 MB
		opts.MaxMultipartMemory = 5 << 20 // 5 MB
		opts.EnableRequestSizeLimits = true
	}
}

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
	out := Options{}
	for _, opt := range opts {
		opt(&out)
	}
	return out
}

// WithStaticFileConfig sets the static file serving configuration.
// This provides full control over all static file serving options.
// Use this when you need granular control over file serving behavior.
//
// For simpler setups, consider using WithStaticFiles() or WithSPAMode() instead.
//
// Example:
//
//	cfg := servex.StaticFileConfig{
//		Enabled:      true,
//		Dir:          "build",
//		SPAMode:      true,
//		IndexFile:    "index.html",
//		CacheMaxAge:  3600,
//		ExcludePaths: []string{"/api/*"},
//		CacheRules: map[string]int{
//			".js":  31536000, // 1 year
//			".css": 31536000, // 1 year
//			".html": 3600,    // 1 hour
//		},
//	}
//	server, _ := servex.New(servex.WithStaticFileConfig(cfg))
func WithStaticFileConfig(config StaticFileConfig) Option {
	return func(o *Options) {
		o.StaticFiles = config
	}
}

// WithStaticFiles enables static file serving from the specified directory.
// This is a simple way to serve static files from a directory.
//
// Parameters:
//   - dir: Directory containing static files to serve
//   - urlPrefix: URL path prefix (empty for root, e.g., "/static")
//
// For SPA support with client-side routing, use WithSPAMode() instead.
//
// Examples:
//
//	// Serve files from "public/" at root path
//	servex.WithStaticFiles("public", "")
//
//	// Serve files from "assets/" under "/static" path
//	servex.WithStaticFiles("assets", "/static")
//
//	// Complete example
//	server, _ := servex.New(servex.WithStaticFiles("build", ""))
func WithStaticFiles(dir, urlPrefix string) Option {
	return func(o *Options) {
		o.StaticFiles = StaticFileConfig{
			Enabled:   true,
			Dir:       dir,
			URLPrefix: urlPrefix,
			SPAMode:   false,
		}
	}
}

// WithSPAMode enables Single Page Application (SPA) mode for serving React, Vue, Angular apps.
// This serves static files from the directory and provides fallback routing for client-side navigation.
//
// In SPA mode:
//   - Static files are served normally (JS, CSS, images, etc.)
//   - API routes continue to work (register them before calling this)
//   - All other routes serve the index file for client-side routing
//
// Parameters:
//   - dir: Directory containing SPA build files (e.g., "build", "dist")
//   - indexFile: Fallback file for client-side routing (typically "index.html")
//
// Usage pattern:
//  1. Register your API routes first
//  2. Enable SPA mode last
//
// Examples:
//
//	// React app setup
//	server, _ := servex.New(servex.WithSPAMode("build", "index.html"))
//	server.GET("/api/users", handleUsers)      // API routes work
//	server.GET("/about", handleUsers)          // Serves index.html for client routing
//
//	// Vue app setup
//	server, _ := servex.New(servex.WithSPAMode("dist", "index.html"))
func WithSPAMode(dir, indexFile string) Option {
	return func(o *Options) {
		if indexFile == "" {
			indexFile = "index.html"
		}
		o.StaticFiles = StaticFileConfig{
			Enabled:   true,
			Dir:       dir,
			SPAMode:   true,
			IndexFile: indexFile,
		}
	}
}

// WithStaticFileCache sets cache policies for static files.
// This controls how long browsers and proxies cache static files.
//
// Parameters:
//   - maxAge: Default cache duration in seconds
//   - rules: File extension or path-specific cache rules
//
// The rules map allows different cache durations for different file types:
//   - Key: File extension (e.g., ".js", ".css") or path pattern (e.g., "/images/*")
//   - Value: Cache duration in seconds
//
// Example:
//
//	// Basic cache setup
//	servex.WithStaticFileCache(3600, nil) // 1 hour for all files
//
//	// Advanced cache setup with rules
//	rules := map[string]int{
//		".js":        31536000, // 1 year for JS files
//		".css":       31536000, // 1 year for CSS files
//		".html":      3600,     // 1 hour for HTML files
//		"/images/*":  2592000,  // 30 days for images
//	}
//	servex.WithStaticFileCache(86400, rules) // 1 day default, custom rules
func WithStaticFileCache(maxAge int, rules map[string]int) Option {
	return func(o *Options) {
		if !o.StaticFiles.Enabled {
			return // Only apply if static files are enabled
		}
		o.StaticFiles.CacheMaxAge = maxAge
		if rules != nil {
			o.StaticFiles.CacheRules = rules
		}
	}
}

// WithStaticFileExclusions sets paths that should not be served as static files.
// These paths will be skipped by the static file handler, allowing API routes to handle them.
//
// This is useful when you want to exclude certain paths from static file serving,
// such as API endpoints that should be handled by custom handlers.
//
// Parameters:
//   - paths: List of path patterns to exclude (supports wildcards with *)
//
// Common exclusions:
//   - "/api/*": All API endpoints
//   - "/auth/*": Authentication endpoints
//   - "/admin/*": Admin interfaces
//   - "/ws/*": WebSocket endpoints
//
// Note: API routes registered before static files are automatically excluded.
//
// Example:
//
//	server, _ := servex.New(
//		servex.WithSPAMode("build", "index.html"),
//		servex.WithStaticFileExclusions("/api/*", "/auth/*"),
//	)
func WithStaticFileExclusions(paths ...string) Option {
	return func(o *Options) {
		if !o.StaticFiles.Enabled {
			return // Only apply if static files are enabled
		}
		o.StaticFiles.ExcludePaths = append(o.StaticFiles.ExcludePaths, paths...)
	}
}

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
