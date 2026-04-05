package servex

import (
	"context"
	"net/http"

	"github.com/maxbolgarin/lang"
)

const (
	defaultMaxMemoryMultipartForm = 10 << 20 // 10 MB
	// Request size limits to prevent DoS attacks (internal defaults)
	defaultMaxRequestBodySize  = 32 << 20  // 32 MB - default max request body size
	defaultMaxJSONBodySize     = 1 << 20   // 1 MB - default max JSON body size
	defaultMaxFormBodySize     = 10 << 20  // 10 MB - default max form body size
	defaultMaxUsernameBodySize = 1024      // 1 KB - default max body size for username extraction
	defaultMaxFileUploadSize   = 100 << 20 // 100 MB - default max file upload size
)

// ErrorResponse represents a JSON for an error response.
type ErrorResponse struct {
	Message string `json:"message"`
}

// Context provides a convenient wrapper around http.ResponseWriter and *http.Request
// with additional utilities for common HTTP operations.
//
// Context simplifies common tasks such as:
//   - Reading and parsing request data (JSON, files, form values)
//   - Writing responses (JSON, files, error responses)
//   - Extracting client information (IP, headers, cookies)
//   - Managing request lifecycle (logging, error handling)
//
// The Context is designed to be used within HTTP handlers and provides
// type-safe methods with built-in security features like size limits
// and input validation.
//
// Example usage:
//
//	func userHandler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//
//		var user User
//		if err := ctx.ReadJSON(&user); err != nil {
//			ctx.BadRequest(err, "Invalid JSON")
//			return
//		}
//
//		// Process user...
//
//		ctx.JSON(map[string]string{"status": "created"})
//	}
type Context struct {
	context.Context
	w http.ResponseWriter
	r *http.Request

	isSendErrorToClient bool
	isSetContentType    bool
	errorHandler        func(w http.ResponseWriter, r *http.Request, err error, code int, msg string, fields ...any)

	// Server-configured size limits (used as defaults)
	maxRequestBodySize int64
	maxJSONBodySize    int64
	maxFileUploadSize  int64
	maxMultipartMemory int64
}

// C creates a new Context for the HTTP request and response.
//
// This is a convenient shortcut for NewContext() and is the most common
// way to create a Context in HTTP handlers.
//
// Parameters:
//   - w: The HTTP response writer
//   - r: The HTTP request
//   - opts: Optional server options for configuration (usually omitted in handlers)
//
// Example:
//
//	func apiHandler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//
//		userID := ctx.Path("id")
//		if userID == "" {
//			ctx.BadRequest(nil, "Missing user ID")
//			return
//		}
//
//		ctx.JSON(map[string]string{"user_id": userID})
//	}
func C(w http.ResponseWriter, r *http.Request, opts ...Options) *Context {
	return NewContext(w, r, opts...)
}

// NewContext creates a new Context for the HTTP request and response.
//
// Parameters:
//   - w: The HTTP response writer
//   - r: The HTTP request
//   - opts: Optional server options for configuration
//
// Example:
//
//	func apiHandler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.NewContext(w, r)
//
//		userID := ctx.Path("id")
//		if userID == "" {
//			ctx.BadRequest(nil, "Missing user ID")
//			return
//		}
//
//		ctx.JSON(map[string]string{"user_id": userID})
//	}
func NewContext(w http.ResponseWriter, r *http.Request, optsRaw ...Options) *Context {
	opts := lang.First(optsRaw)

	ctx := &Context{
		w:                   w,
		r:                   r,
		isSendErrorToClient: opts.SendErrorToClient,
		errorHandler:        opts.ErrorHandler,
		maxRequestBodySize:  lang.Check(opts.MaxRequestBodySize, defaultMaxRequestBodySize),
		maxJSONBodySize:     lang.Check(opts.MaxJSONBodySize, defaultMaxJSONBodySize),
		maxFileUploadSize:   lang.Check(opts.MaxFileUploadSize, defaultMaxFileUploadSize),
		maxMultipartMemory:  lang.Check(opts.MaxMultipartMemory, defaultMaxMemoryMultipartForm),
	}

	if r != nil {
		ctx.Context = r.Context()
	}

	return ctx
}

// C returns a new context for the provided request.
// It is a shortcut for [C] with server options.
func (s *Server) C(w http.ResponseWriter, r *http.Request) *Context {
	return C(w, r, s.opts)
}

// NewContext returns a new context for the provided request.
// It is a shortcut for [NewContext] with server options.
func (s *Server) NewContext(w http.ResponseWriter, r *http.Request) *Context {
	return NewContext(w, r, s.opts)
}

func (ctx *Context) setError(err error, code int, msg string) {
	// Also store the error details directly on the loggingResponseWriter if possible
	if lrw, ok := ctx.w.(*loggingResponseWriter); ok {
		lrw.loggedError = err
		lrw.loggedMsg = msg
		lrw.loggedCode = code
		lrw.errorCodeSet = true // Mark that these values were explicitly set
		return
	}
	rCtx := context.WithValue(ctx.r.Context(), errorKey{}, err)
	rCtx = context.WithValue(rCtx, msgKey{}, msg)
	rCtx = context.WithValue(rCtx, codeKey{}, code)
	ctx.r = ctx.r.WithContext(rCtx)
}

func (ctx *Context) setNoLog() {
	if lrw, ok := ctx.w.(*loggingResponseWriter); ok {
		lrw.noLog = true
		return
	}
	ctx.r = ctx.r.WithContext(context.WithValue(ctx.r.Context(), noLogKey{}, true))
}

// https://pkg.go.dev/context#WithValue
// The provided key must be comparable and should not be of type string or any other built-in type
// to avoid collisions between packages using context. Users of WithValue should define their own types for keys.
// To avoid allocating when assigning to an any, context keys often have concrete type struct{}.
type (
	requestIDKey struct{}
	errorKey     struct{}
	msgKey       struct{}
	codeKey      struct{}
	noLogKey     struct{}

	sendErrorToClientKey struct{}
	noLogClientErrorsKey struct{}
)

// getValueFromContext returns a value from the context of the request.
// It is a shortcut for [context.Value] with error handling.
func getValueFromContext[T any](r *http.Request, key any) (empty T) {
	raw := r.Context().Value(key)
	if raw == nil {
		return empty
	}
	res, ok := raw.(T)
	if !ok {
		return empty
	}
	return res
}
