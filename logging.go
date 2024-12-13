package servex

import (
	"net/http"
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
)

// Logger is an interface for logger to log messages.
type Logger interface {
	// Debug is using to log successful requests.
	Debug(msg string, fields ...any)
	// Info is using to log 'http(s) server started'
	Info(msg string, fields ...any)
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
	Request      *http.Request
	RequestID    string
	Error        error
	ErrorMessage string
	StatusCode   int
	StartTime    time.Time
}

// LogFields returns a slice of fields to set to logger using With method.
// You can add fieldsToInclude to set exact fields that you need.
// By default it returns all fields.
func (ctx *Context) LogFields(fieldsToInclude ...string) []any {
	if len(fieldsToInclude) == 0 {
		fields := make([]any, 0, 12)
		return append(fields,
			"request_id", getOrSetRequestID(ctx.r),
			"ip", ctx.r.RemoteAddr,
			"user_agent", ctx.r.UserAgent(),
			"url", ctx.r.URL.String(),
			"method", ctx.r.Method,
			"proto", ctx.r.Proto,
		)
	}
	fields := make([]any, 0, len(fieldsToInclude)*2)
	for _, field := range fieldsToInclude {
		switch field {
		case RequestIDLogField:
			fields = append(fields, "request_id", getOrSetRequestID(ctx.r))
		case IPLogField:
			fields = append(fields, "ip", ctx.r.RemoteAddr)
		case UserAgentLogField:
			fields = append(fields, "user_agent", ctx.r.UserAgent())
		case URLLogField:
			fields = append(fields, "url", ctx.r.URL.String())
		case MethodLogField:
			fields = append(fields, "method", ctx.r.Method)
		case ProtoLogField:
			fields = append(fields, "proto", ctx.r.Proto)
		}
	}
	return fields
}

func (l *requestLogger) Log(r RequestLogBundle) {
	fields := make([]any, 0, 20)
	if r.Error != nil {
		fields = append(fields, "error", r.Error)
	}
	if r.ErrorMessage != "" {
		fields = append(fields, "error_message", r.ErrorMessage)
	}
	if r.RequestID != "" {
		fields = append(fields, "request_id", r.RequestID)
	}
	if r.StatusCode != 0 {
		fields = append(fields, "status", r.StatusCode)
	}
	if !r.StartTime.IsZero() {
		fields = append(fields, "duration_ms", time.Since(r.StartTime).Milliseconds())
	}
	if r.Request != nil {
		fields = append(fields, "ip", r.Request.RemoteAddr)
		fields = append(fields, "user_agent", r.Request.UserAgent())
		fields = append(fields, "url", r.Request.URL.String())
		fields = append(fields, "method", r.Request.Method)
		fields = append(fields, "proto", r.Request.Proto)
	}

	msg := "http"
	if r.Request != nil && r.Request.TLS != nil {
		msg = "https"
	}

	if r.Error != nil {
		l.Logger.Error(msg, fields...)
	} else {
		l.Logger.Debug(msg, fields...)
	}
}

type requestLogger struct {
	Logger
}
