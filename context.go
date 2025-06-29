package servex

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	mr "math/rand"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	jsoniter "github.com/json-iterator/go"
	"github.com/maxbolgarin/lang"
)

const defaultMaxMemoryMultipartForm = 10 << 20 // 10 MB

// ErrorResponse represents a JSON for an error response.
type ErrorResponse struct {
	Message string `json:"message"`
}

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// Read reads the request body.
func Read(r *http.Request) ([]byte, error) {
	return io.ReadAll(r.Body)
}

// ReadJSON reads a JSON from the request body to a variable of the provided type.
func ReadJSON[T any](r *http.Request) (T, error) {
	var req T
	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		return req, fmt.Errorf("read: %w", err)
	}
	if err := json.Unmarshal(bytes, &req); err != nil {
		return req, fmt.Errorf("unmarshal: %w", err)
	}
	return req, nil
}

// ReadAndValidate reads a JSON from the request body to a variable of the provided type and validates it.
func ReadAndValidate[T interface{ Validate() error }](r *http.Request) (T, error) {
	var req T
	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		return req, fmt.Errorf("read: %w", err)
	}
	if err := json.Unmarshal(bytes, &req); err != nil {
		return req, fmt.Errorf("unmarshal: %w", err)
	}
	if err := req.Validate(); err != nil {
		return req, fmt.Errorf("invalid body: %w", err)
	}
	return req, nil
}

// ReadFile reads a file from the request body.
// fileKey is the key of the file in the request.
// It returns the file bytes, the file header and an error.
func ReadFile(r *http.Request, fileKey string) ([]byte, *multipart.FileHeader, error) {
	err := r.ParseMultipartForm(defaultMaxMemoryMultipartForm)
	if err != nil {
		return nil, nil, fmt.Errorf("parse multipart form: %w", err)
	}

	file, header, err := r.FormFile(fileKey)
	if err != nil {
		return nil, nil, fmt.Errorf("get file: %w", err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, nil, fmt.Errorf("read file: %w", err)
	}

	return bytes, header, nil
}

// Context holds data and methods for handling HTTP request.
type Context struct {
	context.Context
	w http.ResponseWriter
	r *http.Request

	isSendErrorToClient bool
	isSetContentType    bool
}

// NewContext returns a new context for the provided request.
func NewContext(w http.ResponseWriter, r *http.Request) *Context {
	ctx := &Context{
		w: w,
		r: r,
	}
	if r != nil {
		ctx.Context = r.Context()
	}
	return ctx
}

// C returns a new context for the provided request.
// It is a shortcut for [NewContext].
func C(w http.ResponseWriter, r *http.Request) *Context {
	return NewContext(w, r)
}

// RequestID returns the request ID for the request.
func (ctx *Context) RequestID() string {
	return getOrSetRequestID(ctx.r)
}

// SetSendErrorToClient add golang error to response body in case of error.
func (ctx *Context) SetSendErrorToClient(sendErrorToClient bool) {
	ctx.isSendErrorToClient = sendErrorToClient
}

// APIVersion returns the API version of the handler from the path.
// It returns an empty string if not found.
func (ctx *Context) APIVersion() string {
	for s := range strings.SplitSeq(ctx.r.URL.Path, "/") {
		if len(s) > 1 && s[0] == 'v' {
			if _, err := strconv.Atoi(s[1:]); err == nil {
				return s
			}
		}
	}
	return ""
}

// Query returns the value of the query parameter for the given key.
// Query is a parameter from the URL, e.g. "abc/?key=value".
func (ctx *Context) Query(key string) string {
	return ctx.r.URL.Query().Get(key)
}

// Path returns the value of the path parameter for the given key.
// Path parameters are the variables from the URL like "/{key}".
func (ctx *Context) Path(key string) string {
	return mux.Vars(ctx.r)[key]
}

// Header returns the value of the request header with the given name.
// If multiple values are present, they are joined with a comma and space ", ".
func (ctx *Context) Header(key string) string {
	return strings.Join(ctx.r.Header.Values(key), ", ")
}

// SetHeader sets the value of the response header with the given name.
// If multiple values are provided, they are added to the header.
func (ctx *Context) SetHeader(key string, value ...string) {
	if len(value) == 0 {
		return
	}
	ctx.w.Header().Set(key, value[0])
	if len(value) > 1 {
		for _, v := range value[1:] {
			ctx.w.Header().Add(key, v)
		}
	}
}

// SetContentType sets the Content-Type header.
func (ctx *Context) SetContentType(mimeType string, charset ...string) {
	if ctx.isSetContentType {
		return
	}
	if len(charset) > 0 {
		ctx.w.Header().Set("Content-Type", mimeType+"; charset="+charset[0])
	} else {
		ctx.w.Header().Set("Content-Type", mimeType)
	}
	ctx.isSetContentType = true
}

// Cookie returns the cookie with the given name.
func (ctx *Context) Cookie(key string) (*http.Cookie, error) {
	return ctx.r.Cookie(key)
}

// SetCookie sets the cookie with the given name, value, maxAge, secure and httpOnly.
// maxAge is the time in seconds until the cookie expires. If maxAge < 0, the cookie is deleted.
// secure specifies if the cookie should only be transmitted over HTTPS.
// httpOnly prevents the cookie from being accessed through JavaScript, enhancing security against XSS attacks.
func (ctx *Context) SetCookie(name, value string, maxAge int, secure, httpOnly bool) {
	http.SetCookie(ctx.w, &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   maxAge,
		Secure:   secure,
		HttpOnly: httpOnly,
	})
}

// SetRawCookie sets the cookie with the given [http.Cookie].
func (ctx *Context) SetRawCookie(c *http.Cookie) {
	http.SetCookie(ctx.w, c)
}

// FormValue returns the value of the form field for the given key.
func (ctx *Context) FormValue(key string) string {
	if err := ctx.r.ParseForm(); err == nil {
		return ctx.r.FormValue(key)
	}
	return ""
}

// ParseUnixFromQuery parses unix timestamp from query params to time.Time.
func (ctx *Context) ParseUnixFromQuery(key string) (time.Time, error) {
	raw := ctx.r.URL.Query().Get(key)
	if raw == "" {
		return time.Time{}, errors.New("there is no value in query")
	}
	number, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse int: %w", err)
	}
	return time.Unix(number, 0), nil
}

// Read reads the request body.
// It is a shortcut for [io.ReadAll].
func (ctx *Context) Read() ([]byte, error) {
	return io.ReadAll(ctx.r.Body)
}

// Body returns the request body.
// It is a shortcut for [io.ReadAll] without error handling.
func (ctx *Context) Body() []byte {
	bytes, err := io.ReadAll(ctx.r.Body)
	if err != nil {
		return nil
	}
	return bytes
}

// ReadJSON reads a JSON from the request body.
// You should provide a pointer to the variable.
func (ctx *Context) ReadJSON(body any) error {
	bytes, err := io.ReadAll(ctx.r.Body)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if err := json.Unmarshal(bytes, body); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}

// ReadAndValidate reads a JSON from the request body and variable and validate it.
// You should provide a pointer to the variable.
func (ctx *Context) ReadAndValidate(body interface{ Validate() error }) error {
	if err := ctx.ReadJSON(body); err != nil {
		return err
	}
	if err := body.Validate(); err != nil {
		return fmt.Errorf("invalid body: %w", err)
	}
	return nil
}

// ReadFile reads a file from the request body.
// fileKey is the key of the file in the request.
// It returns the file bytes, the file header and an error.
func (ctx *Context) ReadFile(fileKey string) ([]byte, *multipart.FileHeader, error) {
	return ReadFile(ctx.r, fileKey)
}

// NoLog marks to not log the request after returning from the handler.
func (ctx *Context) NoLog() {
	ctx.setNoLog()
}

// Response writes provided status code and body to the [http.ResponseWriter].
// Body may be []byte, string or an object, that can be marshalled to JSON.
// It will write nothing in case of body==nil sending response headers with status code only.
// Method sets Content-Type and Content-Length headers.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
func (ctx *Context) Response(code int, bodyRaw ...any) {
	body := lang.First(bodyRaw)
	if body == nil {
		ctx.w.WriteHeader(code)
		return
	}

	var toWrite []byte
	switch b := body.(type) {
	case []byte:
		toWrite = b
		ctx.SetContentType(http.DetectContentType(b))

	case string:
		toWrite = []byte(b)
		ctx.SetContentType(MIMETypeText, "utf-8")

	default:
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			// Log the marshalling error if possible (though Context doesn't have logger)
			// For now, write a plain 500 response directly, avoiding recursive ctx.Error call.
			// Note: This error hides the original intended response code.
			msg := `{"message":"Internal Server Error: Failed to marshal response JSON"}`
			http.Error(ctx.w, msg, http.StatusInternalServerError)
			// Set error context for logging middleware, even though we short-circuited
			ctx.setError(fmt.Errorf("marshal response: %w", err), http.StatusInternalServerError, msg)
			return
		}
		toWrite = jsonBytes

		ctx.SetContentType(MIMETypeJSON)
	}

	ctx.SetHeader("Content-Length", strconv.Itoa(len(toWrite)))
	ctx.w.WriteHeader(code)

	_, err := ctx.w.Write(toWrite)
	if err != nil {
		// Log the write error if possible (though Context doesn't have logger)
		// Cannot call ctx.Error as headers are already written.
		// We can potentially set the error in context for logging, though the request is mostly finished.
		ctx.setError(fmt.Errorf("write response: %w", err), http.StatusInternalServerError, "failed to write response body")
		// No return here, let the handler finish, but the response is likely broken.
	}
}

// ResponseFile writes the file to the [http.ResponseWriter].
// It sets the Content-Type header to the provided mime type.
// It sets the Content-Disposition header to "attachment; filename=" + filename (safely sanitized).
// It sets the Content-Length header to the length of the body.
func (ctx *Context) ResponseFile(filename string, mimeType string, body []byte) {
	ctx.SetContentType(mimeType)
	ctx.SetHeader("Content-Disposition", formatContentDisposition(filename))
	ctx.SetHeader("Content-Length", strconv.Itoa(len(body)))
	ctx.w.WriteHeader(http.StatusOK)
	_, err := ctx.w.Write(body)
	if err != nil {
		// Log the write error if possible (though Context doesn't have logger)
		// Cannot call ctx.Error as headers are already written.
		// We can potentially set the error in context for logging, though the request is mostly finished.
		ctx.setError(fmt.Errorf("write response: %w", err), http.StatusInternalServerError, "failed to write response body")
		// No return here, let the handler finish, but the response is likely broken.
	}
}

// BadRequest handles an error by returning an HTTP error response with status code 400.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
// It is a shortcut for [Context.Error].
func (ctx *Context) BadRequest(err error, msg string, args ...any) {
	ctx.Error(err, http.StatusBadRequest, msg, args...)
}

// Unauthorized handles an error by returning an HTTP error response with status code 401.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
// It is a shortcut for [Context.Error].
func (ctx *Context) Unauthorized(err error, msg string, args ...any) {
	ctx.Error(err, http.StatusUnauthorized, msg, args...)
}

// Forbidden handles an error by returning an HTTP error response with status code 403.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
// It is a shortcut for [Context.Error].
func (ctx *Context) Forbidden(err error, msg string, args ...any) {
	ctx.Error(err, http.StatusForbidden, msg, args...)
}

// NotFound handles an error by returning an HTTP error response with status code 404.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
// It is a shortcut for [Context.Error].
func (ctx *Context) NotFound(err error, msg string, args ...any) {
	ctx.Error(err, http.StatusNotFound, msg, args...)
}

// NotAcceptable handles an error by returning an HTTP error response with status code 406.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
// It is a shortcut for [Context.Error].
func (ctx *Context) NotAcceptable(err error, msg string, args ...any) {
	ctx.Error(err, http.StatusNotAcceptable, msg, args...)
}

// Conflict handles an error by returning an HTTP error response with status code 409.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
// It is a shortcut for [Context.Error].
func (ctx *Context) Conflict(err error, msg string, args ...any) {
	ctx.Error(err, http.StatusConflict, msg, args...)
}

// StatusUnprocessableEntity handles an error by returning an HTTP error response with status code 422.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
// It is a shortcut for [Context.Error].
func (ctx *Context) UnprocessableEntity(err error, msg string, args ...any) {
	ctx.Error(err, http.StatusUnprocessableEntity, msg, args...)
}

// TooManyRequests handles an error by returning an HTTP error response with status code 429.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
// It is a shortcut for [Context.Error].
func (ctx *Context) TooManyRequests(err error, msg string, args ...any) {
	ctx.Error(err, http.StatusTooManyRequests, msg, args...)
}

// InternalServerError handles an error by returning an HTTP error response with status code 500.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
// It is a shortcut for [Context.Error].
func (ctx *Context) InternalServerError(err error, msg string, args ...any) {
	ctx.Error(err, http.StatusInternalServerError, msg, args...)
}

// NotImplemented handles an error by returning an HTTP error response with status code 501.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
// It is a shortcut for [Context.Error].
func (ctx *Context) NotImplemented(err error, msg string, args ...any) {
	ctx.Error(err, http.StatusNotImplemented, msg, args...)
}

// BadGateway handles an error by returning an HTTP error response with status code 502.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
// It is a shortcut for [Context.Error].
func (ctx *Context) BadGateway(err error, msg string, args ...any) {
	ctx.Error(err, http.StatusBadGateway, msg, args...)
}

// ServiceUnavailable handles an error by returning an HTTP error response with status code 503.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
// It is a shortcut for [Context.Error].
func (ctx *Context) ServiceUnavailable(err error, msg string, args ...any) {
	ctx.Error(err, http.StatusServiceUnavailable, msg, args...)
}

// Error handles an error by returning an HTTP error response.
// You should use this method during error handling in HTTP handlers.
// Method sets Content-Type and Content-Length headers.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
func (ctx *Context) Error(err error, code int, msg string, args ...any) {
	if err == nil {
		return
	}
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}

	ctx.setError(err, code, msg)

	isSendErrorToClient := getValueFromContext[bool](ctx.r, sendErrorToClientKey{})
	if isSendErrorToClient || ctx.isSendErrorToClient {
		msg = fmt.Sprintf("%s: %s", msg, err.Error())
	}

	body := ErrorResponse{
		Message: msg,
	}
	jsonBytes, err := json.Marshal(body)
	if err != nil {
		jsonBytes = []byte(`{"message":"failed to marshal error response"}`)
	}

	ctx.SetHeader("Content-Length", strconv.Itoa(len(jsonBytes)))
	ctx.SetContentType(MIMETypeJSON)
	ctx.w.WriteHeader(code)

	if _, writeErr := ctx.w.Write(jsonBytes); writeErr != nil {
		// Log the write error if possible (though Context doesn't have logger)
		// Cannot call ctx.Error as headers are already written.
		// We can potentially set the error in context for logging, though the request is mostly finished.
		ctx.setError(fmt.Errorf("write error response: %w", writeErr), code, "failed to write error response body, original error: "+err.Error())
		// No return here, let the handler finish, but the response is likely broken.
	}
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

func getOrSetRequestID(r *http.Request) string {
	rIDHeader := r.Header.Get("X-Request-ID")
	if rIDHeader != "" {
		return rIDHeader
	}

	requestID := getValueFromContext[string](r, requestIDKey{})
	if requestID == "" {
		return generateAndSetRequestID(r)
	}

	return requestID
}

func generateAndSetRequestID(r *http.Request) string {
	ctx := r.Context()
	requestID := string(getRandomBytes(12))
	ctx = context.WithValue(ctx, requestIDKey{}, requestID)
	*r = *r.WithContext(ctx)
	return requestID
}

var (
	defaultAlphabet = []byte("0123456789abcdef")
	alphabetLen     = uint8(len(defaultAlphabet))
)

func getRandomBytes(n int) []byte {
	out := make([]byte, n)
	_, err := rand.Read(out)
	if err != nil {
		r := mr.New(mr.NewSource(time.Now().UnixNano()))
		for i := range out {
			out[i] = byte(r.Intn(math.MaxUint8))
		}
	}
	for i := range out {
		out[i] = defaultAlphabet[out[i]&(alphabetLen-1)]
	}
	return out
}

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

// sanitizeFilename sanitizes a filename for use in HTTP headers to prevent header injection attacks.
// It removes or replaces characters that could be used for CRLF injection and other attacks.
func sanitizeFilename(filename string) string {
	if filename == "" {
		return "download"
	}

	// Remove or replace dangerous characters that could lead to header injection
	// Replace CRLF characters and other control characters
	replacer := strings.NewReplacer(
		"\r", "",
		"\n", "",
		"\t", "_",
		"\"", "'", // Replace quotes to avoid breaking quoted strings
		"\\", "_", // Replace backslashes
		":", "_", // Replace colons to prevent URLs in attacks
		"/", "_", // Replace slashes to prevent paths in attacks
	)

	sanitized := replacer.Replace(filename)

	// Remove any remaining control characters (ASCII 0-31 and 127)
	var cleaned strings.Builder
	for _, r := range sanitized {
		if r >= 32 && r != 127 {
			cleaned.WriteRune(r)
		}
	}

	result := cleaned.String()

	// If result is empty or contains only underscores/whitespace, use default
	if result == "" || strings.Trim(result, "_ \t") == "" {
		return "download"
	}

	return result
}

// formatContentDisposition safely formats a Content-Disposition header value with the given filename.
// This follows RFC 6266 recommendations and prevents header injection attacks.
func formatContentDisposition(filename string) string {
	sanitized := sanitizeFilename(filename)

	// Use simple filename format for ASCII filenames
	// For more complex cases, RFC 6266 suggests using filename* parameter with encoding,
	// but for this security fix, we'll use the simpler approach
	return fmt.Sprintf("attachment; filename=\"%s\"", sanitized)
}
