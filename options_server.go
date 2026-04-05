package servex

import (
	"crypto/tls"
	"time"

	"github.com/maxbolgarin/lang"
)

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

// WithMaxHeaderBytes sets the maximum size of request headers the server will accept.
// This controls the maximum number of bytes the server will read parsing the request header's
// keys and values, including the request line. It does not limit the size of the request body.
//
// Example:
//
//	// Set max header size to 2 MB
//	server := servex.New(servex.WithMaxHeaderBytes(2 << 20))
//
//	// Use with other timeouts for comprehensive protection
//	server := servex.New(
//		servex.WithMaxHeaderBytes(1 << 20),    // 1 MB max headers
//		servex.WithReadHeaderTimeout(10 * time.Second),
//		servex.WithReadTimeout(30 * time.Second),
//	)
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
func WithMaxHeaderBytes(size int) Option {
	return func(op *Options) {
		op.MaxHeaderBytes = lang.If(size <= 0, defaultMaxHeaderBytes, size)
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

// WithNoLogClientErrors disables logging of client errors in error level (HTTP status codes 400-499).
// Server errors (5xx) will still be logged in error level if request logging is enabled.
//
// Example:
//
//	// Don't log 404s, 400s, etc. in error level to reduce noise
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

// WithErrorHandler sets a custom error response handler that replaces the default JSON format.
// Use this to customize how errors are sent to clients (e.g., add error codes, change structure).
//
// The handler is called by [Context.Error] and all status-specific helpers (BadRequest, NotFound, etc.).
// It receives the response writer, request, error, status code, message, and optional key-value fields.
// The handler is responsible for writing the complete HTTP response including status code and body.
//
// Example:
//
//	servex.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error, code int, msg string, fields ...any) {
//	    w.Header().Set("Content-Type", "application/json")
//	    w.WriteHeader(code)
//	    json.NewEncoder(w).Encode(map[string]any{
//	        "error": map[string]any{
//	            "code":    code,
//	            "message": msg,
//	        },
//	    })
//	})
func WithErrorHandler(handler func(w http.ResponseWriter, r *http.Request, err error, code int, msg string, fields ...any)) Option {
	return func(op *Options) {
		op.ErrorHandler = handler
	}
}

// WithDebug enables debug mode for development.
// When enabled, it sends detailed error information to clients and keeps all logging verbose,
// including client errors (4xx) at error level.
//
// When debug mode is off (default, production), client errors (4xx) such as 401 Unauthorized
// are logged at debug level instead of error level to reduce log noise.
//
// This is a convenience option that combines:
//   - WithSendErrorToClient() — include error details in HTTP responses
//   - Verbose client error logging at error level
//
// Example:
//
//	// Development server with full debug output
//	server := servex.New(servex.WithDebug())
//
//	// Production server (default) — quiet client error logging
//	server := servex.New()
func WithDebug() Option {
	return func(op *Options) {
		op.IsDebug = true
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

// WithAuditLogger sets a custom audit logger for security events.
// The audit logger is used to log authentication events, rate limiting violations,
// filter blocks, CSRF attacks, and other security-related events.
//
// Example:
//
//	// Custom audit logger that sends to external SIEM
//	type SIEMAuditLogger struct {
//		client *siem.Client
//	}
//
//	func (s *SIEMAuditLogger) LogSecurityEvent(event servex.AuditEvent) {
//		s.client.SendEvent(event)
//	}
//
//	server := servex.New(
//		servex.WithAuditLogger(&SIEMAuditLogger{client: siemClient}),
//	)
//
// Use for:
//   - Integration with Security Information and Event Management (SIEM) systems
//   - Custom audit log formatting and routing
//   - Compliance with specific regulatory requirements
//   - Integration with threat intelligence platforms
func WithAuditLogger(logger AuditLogger) Option {
	return func(op *Options) {
		op.AuditLogger = logger
	}
}

// WithDefaultAuditLogger enables default audit logging using the server's logger.
// This creates a DefaultAuditLogger that logs security events using structured logging.
//
// Example:
//
//	// Enable basic audit logging
//	server := servex.New(
//		servex.WithDefaultAuditLogger(),
//	)
//
//	// Enable audit logging with headers included (be careful with sensitive data)
//	server := servex.New(
//		servex.WithDefaultAuditLogger(),
//		servex.WithAuditLogHeaders(true),
//	)
//
// The default audit logger will:
//   - Log authentication events (login, logout, token validation)
//   - Log rate limiting violations
//   - Log request filtering blocks (IP, User-Agent, etc.)
//   - Log CSRF protection events
//   - Log suspicious activities
//
// All events are logged with structured fields for easy parsing and analysis.
func WithDefaultAuditLogger() Option {
	return func(op *Options) {
		op.EnableDefaultAuditLogger = true
		if op.Logger != nil {
			op.AuditLogger = NewDefaultAuditLogger(op.Logger)
		}
		// If no logger is set yet, the audit logger will be created in NewWithOptions
	}
}

// WithAuditLogHeaders configures whether to include HTTP headers in audit logs.
// This should be used carefully as headers may contain sensitive information.
//
// Example:
//
//	// Include headers in audit logs (for detailed security analysis)
//	server := servex.New(
//		servex.WithDefaultAuditLogger(),
//		servex.WithAuditLogHeaders(true),
//	)
//
// When enabled, the audit logger will include non-sensitive headers in security events.
// Sensitive headers like Authorization, Cookie, X-API-Key are always excluded.
func WithAuditLogHeaders(include bool) Option {
	return func(op *Options) {
		if op.AuditLogger == nil {
			// Enable default audit logging with headers setting
			op.EnableDefaultAuditLogger = true
			op.AuditLogger = &DefaultAuditLogger{IncludeHeaders: include}
		} else if dal, ok := op.AuditLogger.(*DefaultAuditLogger); ok {
			dal.IncludeHeaders = include
		}
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
