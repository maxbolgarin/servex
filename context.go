package servex

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	mr "math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	jsoniter "github.com/json-iterator/go"
	"github.com/maxbolgarin/lang"
)

// TODO: disable http2

// ErrorResponse represents a JSON for an error response.
type ErrorResponse struct {
	Message string `json:"message"`
}

var json = jsoniter.ConfigCompatibleWithStandardLibrary

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

// Context holds data and methods for handling HTTP request.
type Context struct {
	context.Context
	w http.ResponseWriter
	r *http.Request
}

// NewContext returns a new context for the provided request.
func NewContext(w http.ResponseWriter, r *http.Request) *Context {
	return &Context{
		Context: r.Context(),
		w:       w,
		r:       r,
	}
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

// APIVersion returns the API version of the handler from the path.
// It returns an empty string if not found.
func (ctx *Context) APIVersion() string {
	splitted := strings.Split(ctx.r.URL.Path, "/")
	for _, s := range splitted {
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
func (ctx *Context) Header(key string) string {
	return ctx.r.Header.Get(key)
}

// SetHeader sets the value of the request header with the given name.
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
func (ctx *Context) Read() ([]byte, error) {
	return io.ReadAll(ctx.r.Body)
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

// NoLog marks to not log the request after returning from the handler.
func (ctx *Context) NoLog() {
	setNoLog(ctx.r)
}

// SetContentType sets the Content-Type header.
func (ctx *Context) SetContentType(mimeType string) {
	ctx.w.Header().Set("Content-Type", mimeType)
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
		ctx.SetContentType(MIMETypeText)

	default:
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			ctx.Error(err, http.StatusInternalServerError, "cannot marshal response")
			return
		}
		toWrite = jsonBytes

		ctx.SetContentType(MIMETypeJSON)
	}

	ctx.SetHeader("Content-Length", strconv.Itoa(len(toWrite)))
	ctx.w.WriteHeader(code)

	_, err := ctx.w.Write(toWrite)
	if err != nil {
		ctx.Error(err, http.StatusInternalServerError, "cannot write response")
		return
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
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}

	setError(ctx.r, err, code, msg)

	body := []byte(`{"message":"` + msg + `"}`)

	ctx.SetHeader("Content-Length", strconv.Itoa(len(body)))
	ctx.SetContentType(MIMETypeJSON)
	ctx.w.WriteHeader(code)

	if _, err := ctx.w.Write(body); err != nil {
		http.Error(ctx.w, "cannot write error message", http.StatusInternalServerError)
	}
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
)

func getOrSetRequestID(r *http.Request) string {
	rIDHeader := r.Header.Get("X-Request-ID")
	if rIDHeader != "" {
		return rIDHeader
	}
	ctx := r.Context()

	requestIDRaw := ctx.Value(requestIDKey{})
	if requestIDRaw == nil {
		return generateAndSetRequestID(r)
	}

	requestID, ok := requestIDRaw.(string)
	if !ok {
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

func setError(r *http.Request, err error, code int, msg string) {
	ctx := context.WithValue(r.Context(), errorKey{}, err)
	ctx = context.WithValue(ctx, msgKey{}, msg)
	ctx = context.WithValue(ctx, codeKey{}, code)
	*r = *r.WithContext(ctx)
}

func setNoLog(r *http.Request) {
	ctx := context.WithValue(r.Context(), noLogKey{}, true)
	*r = *r.WithContext(ctx)
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
