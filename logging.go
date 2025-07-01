package servex

import (
	"net/http"
	"sync"
	"time"
)

const (
	// RequestIDLogField adds request ID to logs.
	RequestIDLogField = "request_id"
	// IPLogField adds remote IP address to logs.
	IPLogField = "ip"
	// UserAgentLogField adds client's User-Agent to logs.
	UserAgentLogField = "user_agent"
	// URLLogField adds request URL to logs.
	URLLogField = "url"
	// MethodLogField adds request method to logs like GET or POST.
	MethodLogField = "method"
	// ProtoLogField adds request protocol to logs like HTTP/1.1 or HTTP/2.
	ProtoLogField = "proto"
	// ErrorLogField adds error information to logs.
	ErrorLogField = "error"
	// ErrorMessageLogField adds error message to logs.
	ErrorMessageLogField = "error_message"
	// StatusLogField adds HTTP status code to logs.
	StatusLogField = "status"
	// DurationLogField adds request duration in milliseconds to logs.
	DurationLogField = "duration_ms"
)

// Pre-allocated string constants to avoid allocations
const (
	requestIDFieldKey = "request_id"
	ipFieldKey        = "ip"
	userAgentFieldKey = "user_agent"
	urlFieldKey       = "url"
	methodFieldKey    = "method"
	protoFieldKey     = "proto"
	errorFieldKey     = "error"
	errorMsgFieldKey  = "error_message"
	statusFieldKey    = "status"
	durationFieldKey  = "duration_ms"
	httpMsg           = "http"
	httpsMsg          = "https"
)

// Pools for reusing various objects to reduce memory allocation and GC pressure
var (
	logFieldsPool = sync.Pool{
		New: func() any {
			// Pre-allocate slice with reasonable capacity for most common use cases
			return make([]any, 0, 24) // Capacity for ~12 key-value pairs
		},
	}
	requestLogBundlePool = sync.Pool{
		New: func() any {
			return &RequestLogBundle{}
		},
	}
)

// getLogFields retrieves a field slice from the pool.
// The slice is reset to zero length but retains its capacity.
func getLogFields() []any {
	fields := logFieldsPool.Get().([]any)
	return fields[:0] // Reset length while keeping capacity
}

// putLogFields returns a field slice to the pool after use.
// The slice is cleared to prevent memory leaks from retained references.
func putLogFields(fields []any) {
	// Clear all elements to prevent memory leaks
	for i := range fields {
		fields[i] = nil
	}
	// Only return to pool if capacity is reasonable to prevent memory bloat
	if cap(fields) <= 48 { // Allow some growth but prevent excessive capacity
		logFieldsPool.Put(fields[:0])
	}
}

// appendFieldPair efficiently appends a key-value pair to the fields slice.
// This helper reduces code duplication and ensures consistent field handling.
func appendFieldPair(fields []any, key string, value any) []any {
	return append(fields, key, value)
}

// Logger is an interface for logger to log messages.
type Logger interface {
	// Debug is using to log successful requests.
	Debug(msg string, fields ...any)
	// Info is using to log 'http(s) server started'
	Info(msg string, fields ...any)
	// Error is using to log request errors, panics, serve errors and shutodwn in StartContext errors
	Error(msg string, fields ...any)
}

type ErrorLogger interface {
	// Error is using to log request errors, panics, serve errors and shutodwn in StartContext errors
	Error(msg string, fields ...any)
}

// RequestLogger is an interface for logging requests.
// [RequestLogger.Log] is called at the end of each request after returning from handler.
type RequestLogger interface {
	Log(RequestLogBundle)
}

// RequestLogBundle represents a bundle of information for logging a request.
type RequestLogBundle struct {
	Request           *http.Request
	RequestID         string
	Error             error
	ErrorMessage      string
	StatusCode        int
	StartTime         time.Time
	NoLogClientErrors bool
}

// getRequestLogBundle gets a RequestLogBundle from the pool
func getRequestLogBundle() *RequestLogBundle {
	return requestLogBundlePool.Get().(*RequestLogBundle)
}

// putRequestLogBundle returns a RequestLogBundle to the pool after resetting it
func putRequestLogBundle(bundle *RequestLogBundle) {
	// Reset the bundle
	*bundle = RequestLogBundle{}
	requestLogBundlePool.Put(bundle)
}

// LogFields returns a slice of fields to set to logger using With method.
// You can add fieldsToInclude to set exact fields that you need.
// By default it returns all fields.
// NOTE: The caller is responsible for calling putLogFields() to return the slice to the pool.
func (ctx *Context) LogFields(fieldsToInclude ...string) []any {
	fields := getLogFields()

	if len(fieldsToInclude) == 0 {
		// Add all default fields efficiently using pre-allocated constants
		return append(fields,
			requestIDFieldKey, getOrSetRequestID(ctx.r),
			ipFieldKey, ctx.r.RemoteAddr,
			userAgentFieldKey, ctx.r.UserAgent(),
			urlFieldKey, ctx.r.URL.String(),
			methodFieldKey, ctx.r.Method,
			protoFieldKey, ctx.r.Proto,
		)
	}

	// Add only requested fields using optimized field appending
	for _, field := range fieldsToInclude {
		switch field {
		case RequestIDLogField:
			fields = appendFieldPair(fields, requestIDFieldKey, getOrSetRequestID(ctx.r))
		case IPLogField:
			fields = appendFieldPair(fields, ipFieldKey, ctx.r.RemoteAddr)
		case UserAgentLogField:
			fields = appendFieldPair(fields, userAgentFieldKey, ctx.r.UserAgent())
		case URLLogField:
			fields = appendFieldPair(fields, urlFieldKey, ctx.r.URL.String())
		case MethodLogField:
			fields = appendFieldPair(fields, methodFieldKey, ctx.r.Method)
		case ProtoLogField:
			fields = appendFieldPair(fields, protoFieldKey, ctx.r.Proto)
		}
	}
	return fields
}

// LogFieldsWithCleanup returns log fields and a cleanup function.
// This is a convenience method that automatically handles pool cleanup.
// Usage: fields, cleanup := ctx.LogFieldsWithCleanup(); defer cleanup()
func (ctx *Context) LogFieldsWithCleanup(fieldsToInclude ...string) ([]any, func()) {
	fields := ctx.LogFields(fieldsToInclude...)
	return fields, func() { putLogFields(fields) }
}

type BaseRequestLogger struct {
	Logger
	// FieldsToInclude specifies which fields to include in logs.
	// If empty, all available fields will be logged (default behavior).
	// Use the exported *LogField constants to specify fields.
	FieldsToInclude []string
}

func (l *BaseRequestLogger) Log(r RequestLogBundle) {
	duration := time.Since(r.StartTime)
	statusCode := r.StatusCode
	if statusCode == 0 {
		statusCode = 200 // Default status code
	}

	// Don't log successful requests at error level
	isError := r.Error != nil || statusCode >= 500
	isClientError := statusCode >= 400 && statusCode < 500

	// Skip logging client errors if configured
	if isClientError && r.NoLogClientErrors {
		return
	}

	// Get log fields from pool
	fields := getLogFields()
	defer putLogFields(fields)

	// Always include basic fields
	fields = append(fields, "method", r.Request.Method)
	fields = append(fields, "url", r.Request.URL.String())
	fields = append(fields, "status", statusCode)
	fields = append(fields, "duration_ms", duration.Milliseconds())

	// Add optional fields based on configuration
	if l.shouldIncludeField(RequestIDLogField) {
		fields = append(fields, "request_id", r.RequestID)
	}
	if l.shouldIncludeField(IPLogField) {
		fields = append(fields, "ip", r.Request.RemoteAddr)
	}
	if l.shouldIncludeField(UserAgentLogField) {
		fields = append(fields, "user_agent", r.Request.UserAgent())
	}
	if l.shouldIncludeField(ProtoLogField) {
		fields = append(fields, "proto", r.Request.Proto)
	}

	// Add error information if present
	if r.Error != nil && l.shouldIncludeField(ErrorLogField) {
		fields = append(fields, "error", r.Error.Error())
	}
	if r.ErrorMessage != "" && l.shouldIncludeField(ErrorMessageLogField) {
		fields = append(fields, "error_message", r.ErrorMessage)
	}

	// Use pre-allocated message constants
	msg := httpMsg
	if r.Request != nil && r.Request.TLS != nil {
		msg = httpsMsg
	}

	// Log at appropriate level
	if isError {
		l.Logger.Error(msg, fields...)
	} else if isClientError {
		l.Logger.Info(msg, fields...)
	} else {
		l.Logger.Debug(msg, fields...)
	}
}

// shouldIncludeField checks if a field should be included in logs
func (l *BaseRequestLogger) shouldIncludeField(field string) bool {
	if len(l.FieldsToInclude) == 0 {
		return true // Include all fields if none specified
	}
	for _, f := range l.FieldsToInclude {
		if f == field {
			return true
		}
	}
	return false
}

type noopRequestLogger struct{}

func (l *noopRequestLogger) Log(RequestLogBundle) {}
