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
	fields := getLogFields()
	defer putLogFields(fields)

	// If specific fields are configured, use selective inclusion
	if len(l.FieldsToInclude) > 0 {
		fields = l.addSelectiveFields(fields, r)
	} else {
		// Default behavior: add all fields (backwards compatibility)
		fields = l.addAllFields(fields, r)
	}

	// Use pre-allocated message constants
	msg := httpMsg
	if r.Request != nil && r.Request.TLS != nil {
		msg = httpsMsg
	}

	if r.Error == nil {
		l.Logger.Debug(msg, fields...)
		return
	}

	if r.NoLogClientErrors && r.StatusCode >= 400 && r.StatusCode < 500 {
		l.Logger.Debug(msg, fields...)
		return
	}

	l.Logger.Error(msg, fields...)
}

// addSelectiveFields adds only the fields specified in FieldsToInclude
func (l *BaseRequestLogger) addSelectiveFields(fields []any, r RequestLogBundle) []any {
	for _, field := range l.FieldsToInclude {
		switch field {
		case RequestIDLogField:
			if r.RequestID != "" {
				fields = appendFieldPair(fields, requestIDFieldKey, r.RequestID)
			}
		case IPLogField:
			if r.Request != nil {
				fields = appendFieldPair(fields, ipFieldKey, r.Request.RemoteAddr)
			}
		case UserAgentLogField:
			if r.Request != nil {
				fields = appendFieldPair(fields, userAgentFieldKey, r.Request.UserAgent())
			}
		case URLLogField:
			if r.Request != nil {
				fields = appendFieldPair(fields, urlFieldKey, r.Request.URL.String())
			}
		case MethodLogField:
			if r.Request != nil {
				fields = appendFieldPair(fields, methodFieldKey, r.Request.Method)
			}
		case ProtoLogField:
			if r.Request != nil {
				fields = appendFieldPair(fields, protoFieldKey, r.Request.Proto)
			}
		// Meta fields that are always available
		case ErrorLogField:
			if r.Error != nil {
				fields = appendFieldPair(fields, errorFieldKey, r.Error)
			}
		case ErrorMessageLogField:
			if r.ErrorMessage != "" {
				fields = appendFieldPair(fields, errorMsgFieldKey, r.ErrorMessage)
			}
		case StatusLogField:
			if r.StatusCode != 0 {
				fields = appendFieldPair(fields, statusFieldKey, r.StatusCode)
			}
		case DurationLogField:
			if !r.StartTime.IsZero() {
				fields = appendFieldPair(fields, durationFieldKey, time.Since(r.StartTime).Milliseconds())
			}
		}
	}
	return fields
}

// addAllFields adds all available fields (original behavior)
func (l *BaseRequestLogger) addAllFields(fields []any, r RequestLogBundle) []any {
	// Build fields efficiently using the pooled slice and pre-allocated constants
	if r.Error != nil {
		fields = appendFieldPair(fields, errorFieldKey, r.Error)
	}
	if r.ErrorMessage != "" {
		fields = appendFieldPair(fields, errorMsgFieldKey, r.ErrorMessage)
	}
	if r.RequestID != "" {
		fields = appendFieldPair(fields, requestIDFieldKey, r.RequestID)
	}
	if r.StatusCode != 0 {
		fields = appendFieldPair(fields, statusFieldKey, r.StatusCode)
	}
	if !r.StartTime.IsZero() {
		fields = appendFieldPair(fields, durationFieldKey, time.Since(r.StartTime).Milliseconds())
	}
	if r.Request != nil {
		// Add all request fields in one operation for better performance
		fields = append(fields,
			ipFieldKey, r.Request.RemoteAddr,
			userAgentFieldKey, r.Request.UserAgent(),
			urlFieldKey, r.Request.URL.String(),
			methodFieldKey, r.Request.Method,
			protoFieldKey, r.Request.Proto,
		)
	}
	return fields
}

type noopRequestLogger struct{}

func (l *noopRequestLogger) Log(RequestLogBundle) {}
