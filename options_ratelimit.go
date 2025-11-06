package servex

import (
	"net/http"
	"time"
)

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
