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
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	jsoniter "github.com/json-iterator/go"
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

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// Read reads the request body with default size limit to prevent DoS attacks.
func Read(r *http.Request) ([]byte, error) {
	return ReadWithLimit(r, defaultMaxRequestBodySize)
}

// ReadWithLimit reads the request body with a specific size limit.
func ReadWithLimit(r *http.Request, maxSize int64) ([]byte, error) {
	if maxSize <= 0 {
		maxSize = defaultMaxRequestBodySize
	}

	bytes, err := io.ReadAll(io.LimitReader(r.Body, maxSize))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	// Check if we hit the size limit
	if int64(len(bytes)) >= maxSize {
		return nil, fmt.Errorf("request body too large (max: %d bytes)", maxSize)
	}

	return bytes, nil
}

// ReadJSON reads a JSON from the request body to a variable of the provided type with size limits.
func ReadJSON[T any](r *http.Request) (T, error) {
	return ReadJSONWithLimit[T](r, defaultMaxJSONBodySize)
}

// ReadJSONWithLimit reads a JSON from the request body with a specific size limit.
func ReadJSONWithLimit[T any](r *http.Request, maxSize int64) (T, error) {
	var req T
	if maxSize <= 0 {
		maxSize = defaultMaxJSONBodySize
	}

	bytes, err := io.ReadAll(io.LimitReader(r.Body, maxSize))
	if err != nil {
		return req, fmt.Errorf("read: %w", err)
	}

	// Check if we hit the size limit
	if int64(len(bytes)) >= maxSize {
		return req, fmt.Errorf("request body too large (max: %d bytes)", maxSize)
	}

	if err := json.Unmarshal(bytes, &req); err != nil {
		return req, fmt.Errorf("unmarshal: %w", err)
	}
	return req, nil
}

// ReadAndValidate reads a JSON from the request body to a variable of the provided type and validates it with size limits.
func ReadAndValidate[T interface{ Validate() error }](r *http.Request) (T, error) {
	return ReadAndValidateWithLimit[T](r, defaultMaxJSONBodySize)
}

// ReadAndValidateWithLimit reads and validates a JSON from the request body with a specific size limit.
func ReadAndValidateWithLimit[T interface{ Validate() error }](r *http.Request, maxSize int64) (T, error) {
	var req T
	if maxSize <= 0 {
		maxSize = defaultMaxJSONBodySize
	}

	bytes, err := io.ReadAll(io.LimitReader(r.Body, maxSize))
	if err != nil {
		return req, fmt.Errorf("read: %w", err)
	}

	// Check if we hit the size limit
	if int64(len(bytes)) >= maxSize {
		return req, fmt.Errorf("request body too large (max: %d bytes)", maxSize)
	}

	if err := json.Unmarshal(bytes, &req); err != nil {
		return req, fmt.Errorf("unmarshal: %w", err)
	}
	if err := req.Validate(); err != nil {
		return req, fmt.Errorf("invalid body: %w", err)
	}
	return req, nil
}

// ReadFile reads a file from the request body with configurable size limits.
func ReadFile(r *http.Request, fileKey string) ([]byte, *multipart.FileHeader, error) {
	return ReadFileWithLimit(r, fileKey, defaultMaxMemoryMultipartForm, defaultMaxFileUploadSize)
}

// ReadFileWithLimit reads a file from the request body with specific size limits.
func ReadFileWithLimit(r *http.Request, fileKey string, maxMemory, maxFileSize int64) ([]byte, *multipart.FileHeader, error) {
	if maxMemory <= 0 {
		maxMemory = defaultMaxMemoryMultipartForm
	}
	if maxFileSize <= 0 {
		maxFileSize = defaultMaxFileUploadSize
	}

	err := r.ParseMultipartForm(maxMemory)
	if err != nil {
		return nil, nil, fmt.Errorf("parse multipart form: %w", err)
	}

	file, header, err := r.FormFile(fileKey)
	if err != nil {
		return nil, nil, fmt.Errorf("get file: %w", err)
	}
	defer file.Close()

	// Check file size before reading
	if header.Size > maxFileSize {
		return nil, nil, fmt.Errorf("file too large: %d bytes (max: %d bytes)", header.Size, maxFileSize)
	}

	bytes, err := io.ReadAll(io.LimitReader(file, maxFileSize))
	if err != nil {
		return nil, nil, fmt.Errorf("read file: %w", err)
	}

	// Double-check actual read size
	if int64(len(bytes)) > maxFileSize {
		return nil, nil, fmt.Errorf("file too large after reading: %d bytes (max: %d bytes)", len(bytes), maxFileSize)
	}

	return bytes, header, nil
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

// RequestID returns the request ID for the request.
func (ctx *Context) RequestID() string {
	return getOrSetRequestID(ctx.r)
}

// APIVersion returns the API version of the handler from the path.
// It returns an empty string if not found.
// Example:
//
//	// Route definition: server.GET("/api/v1/users", handler)
//	// Request: GET /api/v1/users
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//		version := ctx.APIVersion() // "v1"
//	}
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

// Query returns the value of a URL query parameter.
//
// Query parameters are the key-value pairs that appear after the "?" in a URL.
// For example, in "GET /users?page=2&limit=10", this method can extract
// "page" and "limit" values.
//
// Parameters:
//   - key: The name of the query parameter
//
// Returns the first value associated with the key, or an empty string
// if the parameter doesn't exist.
//
// Example:
//
//	// URL: /api/users?page=2&limit=10&sort=name
//	page := ctx.Query("page")     // "2"
//	limit := ctx.Query("limit")   // "10"
//	sort := ctx.Query("sort")     // "name"
//	missing := ctx.Query("foo")   // ""
func (ctx *Context) Query(key string) string {
	return ctx.r.URL.Query().Get(key)
}

// Path returns the value of a URL path parameter.
//
// Path parameters are variables embedded in the URL path pattern, defined
// using curly braces in route definitions. They are extracted when the
// route matches the incoming request.
//
// Parameters:
//   - key: The name of the path parameter (without curly braces)
//
// Returns the value extracted from the URL path, or an empty string
// if the parameter doesn't exist in the route.
//
// Example:
//
//	// Route definition: server.GET("/users/{id}/posts/{postID}", handler)
//	// Request: GET /users/123/posts/456
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//
//		userID := ctx.Path("id")       // "123"
//		postID := ctx.Path("postID")   // "456"
//		missing := ctx.Path("foo")     // ""
//
//		ctx.JSON(map[string]string{
//			"user_id": userID,
//			"post_id": postID,
//		})
//	}
func (ctx *Context) Path(key string) string {
	return mux.Vars(ctx.r)[key]
}

// Header returns the value of the request header with the given name.
// If multiple values are present, they are joined with a comma and space ", ".
// Example:
//
//	// Request: GET /api/users
//	// Header: X-API-Key: abc, def
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//		apiKey := ctx.Header("X-API-Key") // "abc, def"
//	}
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

// SetDeleteCookie sets the cookie with the given name to be deleted.
func (ctx *Context) SetDeleteCookie(name string) {
	http.SetCookie(ctx.w, &http.Cookie{
		Name:   name,
		Value:  "",
		MaxAge: -1,
	})
}

// FormValue returns the value of the form field for the given key.
// Example:
//
//	// Request: POST /api/users
//	// Form: name=John&age=30
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//		name := ctx.FormValue("name") // "John"
//		age := ctx.FormValue("age")   // "30"
//	}
func (ctx *Context) FormValue(key string) string {
	if err := ctx.r.ParseForm(); err == nil {
		return ctx.r.FormValue(key)
	}
	return ""
}

// RemoteAddr returns the remote address of the request.
// This is the direct connection address and may be a proxy IP.
// For real client IP detection, use ClientIP() instead.
func (ctx *Context) RemoteAddr() string {
	return ctx.r.RemoteAddr
}

// ClientIP returns the real client IP address, considering proxy headers.
// It checks common proxy headers in order of preference and validates IP addresses.
// Falls back to RemoteAddr if no valid IP is found in headers.
//
// Headers checked (in order):
//   - CF-Connecting-IP (Cloudflare)
//   - True-Client-IP (Akamai, Cloudflare)
//   - X-Real-IP (nginx)
//   - X-Forwarded-For (first valid IP)
//   - X-Client-IP
//   - X-Forwarded
//   - X-Cluster-Client-IP
//   - Forwarded (RFC 7239)
//
// Example:
//
//	clientIP := servex.C(w, r).ClientIP()
func (ctx *Context) ClientIP() string {
	return extractClientIP(ctx.r)
}

// ClientIPWithTrustedProxies returns the real client IP address, but only trusts
// proxy headers if the request comes from a trusted proxy network.
// This is more secure when you know which proxies to trust.
//
// Example:
//
//	trustedNets := []string{"10.0.0.0/8", "172.16.0.0/12"}
//	clientIP := servex.C(w, r).ClientIPWithTrustedProxies(trustedNets)
func (ctx *Context) ClientIPWithTrustedProxies(trustedProxies []string) string {
	return extractClientIPWithTrustedProxies(ctx.r, trustedProxies)
}

// ParseUnixFromQuery parses unix timestamp from query params to time.Time.
// Example:
//
//	// Request: GET /api/users?created_at=1714732800
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//		createdAt, err := ctx.ParseUnixFromQuery("created_at") // time.Unix(1714732800, 0)
//	}

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

// Body returns the request body as bytes with default size limit.
// Be careful with this method as it reads the entire body into memory.
// Use ReadWithLimit for better control over memory usage.
// Example:
//
//	// Request: POST /api/users
//	// Body: {"name": "John", "age": 30}
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//		body := ctx.Body() // []byte(`{"name": "John", "age": 30}`)
//	}
func (ctx *Context) Body() []byte {
	bytes, err := ctx.Read()
	if err != nil {
		return nil
	}
	return bytes
}

// Read reads the request body with size limit to prevent DoS attacks.
// It is a shortcut for ReadWithLimit with configured default size.
// Example:
//
//	// Request: POST /api/users
//	// Body: {"name": "John", "age": 30}
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//		body, err := ctx.Read() // []byte(`{"name": "John", "age": 30}`)
//	}
func (ctx *Context) Read() ([]byte, error) {
	return ctx.ReadWithLimit(ctx.maxRequestBodySize)
}

// ReadWithLimit reads the request body with a specific size limit.
// Example:
//
//	// Request: POST /api/users
//	// Body: {"name": "John", "age": 30}
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//		body, err := ctx.ReadWithLimit(1024) // []byte(`{"name": "John", "age": 30}`)
//	}
func (ctx *Context) ReadWithLimit(maxSize int64) ([]byte, error) {
	if maxSize <= 0 {
		maxSize = ctx.maxRequestBodySize
	}

	bytes, err := io.ReadAll(io.LimitReader(ctx.r.Body, maxSize))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	// Check if we hit the size limit
	if int64(len(bytes)) >= maxSize {
		return nil, fmt.Errorf("request body too large (max: %d bytes)", maxSize)
	}

	return bytes, nil
}

// ReadJSON reads and parses JSON from the request body into the provided variable.
//
// The method automatically applies size limits to prevent DoS attacks and
// validates that the content is valid JSON. You must provide a pointer to
// the variable where the JSON should be unmarshaled.
//
// Features:
//   - Automatic size limiting (configurable via WithMaxJSONBodySize)
//   - Memory-safe reading with io.LimitReader
//   - Detailed error messages for debugging
//
// Parameters:
//   - body: Pointer to the variable where JSON will be unmarshaled
//
// Example:
//
//	type User struct {
//		Name  string `json:"name"`
//		Email string `json:"email"`
//	}
//
//	func createUser(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//
//		var user User
//		if err := ctx.ReadJSON(&user); err != nil {
//			ctx.BadRequest(err, "Invalid JSON payload")
//			return
//		}
//
//		// Process user...
//		ctx.JSON(map[string]string{"status": "created"})
//	}
func (ctx *Context) ReadJSON(body any) error {
	return ctx.ReadJSONWithLimit(body, ctx.maxJSONBodySize)
}

// ReadJSONWithLimit reads and parses JSON from the request body into the provided variable.
//
// The method applies size limits to prevent DoS attacks and
// validates that the content is valid JSON. You must provide a pointer to
// the variable where the JSON should be unmarshaled.
//
// Features:
//   - Automatic size limiting (configurable via WithMaxJSONBodySize)
//   - Memory-safe reading with io.LimitReader
//   - Detailed error messages for debugging
//
// Parameters:
//   - body: Pointer to the variable where JSON will be unmarshaled
//
// Example:
//
//	type User struct {
//		Name  string `json:"name"`
//		Email string `json:"email"`
//	}
//
//	func createUser(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//
//		var user User
//		if err := ctx.ReadJSONWithLimit(&user, 1024); err != nil {
//			ctx.BadRequest(err, "Invalid JSON payload")
//			return
//		}
//
//		// Process user...
//		ctx.JSON(map[string]string{"status": "created"})
//	}
func (ctx *Context) ReadJSONWithLimit(body any, maxSize int64) error {
	if maxSize <= 0 {
		maxSize = ctx.maxJSONBodySize
	}

	bytes, err := io.ReadAll(io.LimitReader(ctx.r.Body, maxSize))
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	// Check if we hit the size limit
	if int64(len(bytes)) >= maxSize {
		return fmt.Errorf("request body too large (max: %d bytes)", maxSize)
	}

	if err := json.Unmarshal(bytes, body); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}

// ReadAndValidate reads a JSON from the request body to the provided variable and validates it with size limits.
// You should provide a pointer to the variable.
// Example:
//
//	type User struct {
//		Name  string `json:"name"`
//		Email string `json:"email"`
//	}
//
//	func (u *User) Validate() error {
//		if u.Name == "" {
//			return errors.New("name is required")
//		}
//		return nil
//	}
//
//	func createUser(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//
//		var user User
//		if err := ctx.ReadAndValidate(&user); err != nil {
//			ctx.BadRequest(err, "Invalid JSON payload")
//			return
//		}
//
//		// Process user...
//		ctx.JSON(map[string]string{"status": "created"})
//	}
func (ctx *Context) ReadAndValidate(body interface{ Validate() error }) error {
	return ctx.ReadAndValidateWithLimit(body, ctx.maxJSONBodySize)
}

// ReadAndValidateWithLimit reads a JSON from the request body to the provided variable and validates it with size limits.
// You should provide a pointer to the variable.
// Example:
//
//	type User struct {
//		Name  string `json:"name"`
//		Email string `json:"email"`
//	}
//
//	func (u *User) Validate() error {
//		if u.Name == "" {
//			return errors.New("name is required")
//		}
//		return nil
//	}
//
//	func createUser(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//
//		var user User
//		if err := ctx.ReadAndValidateWithLimit(&user, 1024); err != nil {
//			ctx.BadRequest(err, "Invalid JSON payload")
//			return
//		}
//
//		// Process user...
//		ctx.JSON(map[string]string{"status": "created"})
//	}
func (ctx *Context) ReadAndValidateWithLimit(body interface{ Validate() error }, maxSize int64) error {
	if err := ctx.ReadJSONWithLimit(body, maxSize); err != nil {
		return err
	}
	if err := body.Validate(); err != nil {
		return fmt.Errorf("invalid body: %w", err)
	}
	return nil
}

// ReadFile reads a file from the request body with configurable size limits.
//
// Parameters:
//   - fileKey: The key of the file in the request
//
// Example:
//
//	// Request: POST /api/users
//	// Form: file=user.txt
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//		file, header, err := ctx.ReadFile("file") // []byte(`user.txt`), *multipart.FileHeader, nil
//	}
func (ctx *Context) ReadFile(fileKey string) ([]byte, *multipart.FileHeader, error) {
	return ReadFileWithLimit(ctx.r, fileKey, ctx.maxMultipartMemory, ctx.maxFileUploadSize)
}

// ReadFileWithLimit reads a file from the request body with specific size limits.
//
// Parameters:
//   - fileKey: The key of the file in the request
//   - maxMemory: The maximum memory to use for the file
//   - maxFileSize: The maximum size of the file
//
// Example:
//
//	// Request: POST /api/users
//	// Form: file=user.txt
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//		file, header, err := ctx.ReadFileWithLimit("file", 1024, 1024) // []byte(`user.txt`), *multipart.FileHeader, nil
//	}
func (ctx *Context) ReadFileWithLimit(fileKey string, maxMemory, maxFileSize int64) ([]byte, *multipart.FileHeader, error) {
	return ReadFileWithLimit(ctx.r, fileKey, maxMemory, maxFileSize)
}

// NoLog marks to not log the request after returning from the handler.
func (ctx *Context) NoLog() {
	ctx.setNoLog()
}

// Response writes an HTTP response with the specified status code and optional body.
//
// This is the primary method for sending responses. It automatically handles
// content type detection, header setting, and proper HTTP response formatting.
//
// Supported body types:
//   - []byte: Written directly with detected content type
//   - string: Written as text/plain with UTF-8 charset
//   - any other type: Marshaled to JSON with application/json content type
//   - nil: Sends only status code with no body
//
// Features:
//   - Automatic Content-Type header setting
//   - Content-Length header calculation
//   - JSON marshaling with error handling
//   - Memory-efficient for large responses
//
// Parameters:
//   - code: HTTP status code (e.g., 200, 404, 500)
//   - bodyRaw: Optional response body (supports multiple types)
//
// Example:
//
//	// JSON response
//	ctx.Response(200, map[string]string{"message": "success"})
//
//	// String response
//	ctx.Response(200, "Hello, World!")
//
//	// Byte response (e.g., file content)
//	ctx.Response(200, fileBytes)
//
//	// Status-only response
//	ctx.Response(204)
//
// Note: Do not modify the ResponseWriter after calling this method.
// This method should typically be the last operation in your handler.
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
// Parameters:
//   - filename: The name of the file
//   - mimeType: The mime type of the file
//   - body: The body of the file
//
// Example:
//
//	// Request: GET /api/users/123/avatar.png
//	// Response: 200 OK
//	// Content-Type: image/png
//	// Content-Disposition: attachment; filename="avatar.png"
//	// Content-Length: 12345
//	// Body: file content
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//		ctx.ResponseFile("avatar.png", "image/png", fileBytes)
//	}
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

// JSON is an alias for [Context.Response] with 200 code.
func (ctx *Context) JSON(bodyRaw any) {
	ctx.Response(http.StatusOK, bodyRaw)
}

// BadRequest handles an error by returning an HTTP error response with status code 400.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) BadRequest(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusBadRequest, msg, fields...)
}

// Unauthorized handles an error by returning an HTTP error response with status code 401.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) Unauthorized(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusUnauthorized, msg, fields...)
}

// Forbidden handles an error by returning an HTTP error response with status code 403.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) Forbidden(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusForbidden, msg, fields...)
}

// NotFound handles an error by returning an HTTP error response with status code 404.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) NotFound(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusNotFound, msg, fields...)
}

// MethodNotAllowed handles an error by returning an HTTP error response with status code 405.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// It sends a 'Method not allowed' error response.
//
// It is a shortcut for [Context.Error].
func (ctx *Context) MethodNotAllowed(fields ...any) {
	ctx.Error(nil, http.StatusMethodNotAllowed, "Method not allowed", fields...)
}

// NotAcceptable handles an error by returning an HTTP error response with status code 406.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) NotAcceptable(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusNotAcceptable, msg, fields...)
}

// Conflict handles an error by returning an HTTP error response with status code 409.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) Conflict(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusConflict, msg, fields...)
}

// MethodConflict handles an error by returning an HTTP error response with status code 409.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) PreconditionFailed(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusPreconditionFailed, msg, fields...)
}

// RequestEntityTooLarge handles an error by returning an HTTP error response with status code 413.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) RequestEntityTooLarge(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusRequestEntityTooLarge, msg, fields...)
}

// UnsupportedMediaType handles an error by returning an HTTP error response with status code 415.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) UnsupportedMediaType(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusUnsupportedMediaType, msg, fields...)
}

// StatusUnprocessableEntity handles an error by returning an HTTP error response with status code 422.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) UnprocessableEntity(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusUnprocessableEntity, msg, fields...)
}

// TooManyRequests handles an error by returning an HTTP error response with status code 429.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) TooManyRequests(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusTooManyRequests, msg, fields...)
}

// InternalServerError handles an error by returning an HTTP error response with status code 500.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) InternalServerError(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusInternalServerError, msg, fields...)
}

// NotImplemented handles an error by returning an HTTP error response with status code 501.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) NotImplemented(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusNotImplemented, msg, fields...)
}

// BadGateway handles an error by returning an HTTP error response with status code 502.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) BadGateway(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusBadGateway, msg, fields...)
}

// ServiceUnavailable handles an error by returning an HTTP error response with status code 503.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) ServiceUnavailable(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusServiceUnavailable, msg, fields...)
}

// Error handles errors by sending standardized HTTP error responses.
//
// This method provides consistent error handling across your application
// with proper logging integration and optional client error exposure.
// It formats error messages and manages error context for middleware.
//
// Features:
//   - Consistent error response format
//   - Integration with logging middleware
//   - Configurable error exposure to clients
//   - Support for formatted error messages
//   - Automatic HTTP status code handling
//
// Parameters:
//   - err: The underlying error (logged but not always exposed to client)
//   - code: HTTP status code (400, 401, 404, 500, etc.)
//   - msg: User-friendly error message (can include format verbs)
//   - fields: Optional key-value pairs for additional error context
//
// The response format is JSON: {"message": "error description", "field1": "value1", "field2": "value2"}
//
// Example:
//
//	// Simple error
//	ctx.Error(err, 400, "Invalid request")
//
//	// Formatted error message
//	ctx.Error(err, 404, "User not found", "user_id", userID) -> {"message": "User not found", "user_id": "123"}
//
//	// Use helper methods for common cases
//	ctx.BadRequest(err, "Invalid JSON payload")
//	ctx.NotFound(err, "Resource not found")
//	ctx.InternalServerError(err, "Database connection failed", "database_name", "users") -> {"message": "Database connection failed", "database_name": "users"}
//
// Note: Do not modify the ResponseWriter after calling this method.
// This method should typically be followed by a return statement.
func (ctx *Context) Error(err error, code int, msg string, fields ...any) {
	if err != nil {
		ctx.setError(err, code, msg)

		isSendErrorToClient := getValueFromContext[bool](ctx.r, sendErrorToClientKey{})
		if isSendErrorToClient || ctx.isSendErrorToClient {
			msg = fmt.Sprintf("%s: %s", msg, err.Error())
		}
	}

	body := map[string]any{
		"message": msg,
	}
	for i := 0; i < len(fields); i += 2 {
		if i+1 >= len(fields) {
			break
		}
		if key, ok := fields[i].(string); ok {
			body[key] = fields[i+1]
		}
	}

	jsonBytes, marshalErr := json.Marshal(body)
	if marshalErr != nil {
		jsonBytes = []byte(`{"message":"failed to marshal error response"}`)
	}

	ctx.SetHeader("Content-Length", strconv.Itoa(len(jsonBytes)))
	ctx.SetContentType(MIMETypeJSON)
	ctx.w.WriteHeader(code)

	if _, writeErr := ctx.w.Write(jsonBytes); writeErr != nil {
		// Log the write error if possible (though Context doesn't have logger)
		// Cannot call ctx.Error as headers are already written.
		// We can potentially set the error in context for logging, though the request is mostly finished.
		ctx.setError(fmt.Errorf("write error response: %w", writeErr), code,
			"failed to write error response body, original error: "+err.Error())
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
		// Fallback to crypto/rand with a different approach
		fallbackBytes := make([]byte, n)
		if _, fallbackErr := rand.Read(fallbackBytes); fallbackErr != nil {
			// If crypto/rand completely fails, use time-based seed as last resort
			r := mr.New(mr.NewSource(time.Now().UnixNano()))
			for i := range out {
				out[i] = byte(r.Intn(math.MaxUint8))
			}
		} else {
			out = fallbackBytes
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

// Pre-allocated proxy headers slice to avoid allocations on each call
var proxyHeaders = [8]string{
	"CF-Connecting-IP",    // Cloudflare
	"True-Client-IP",      // Akamai, Cloudflare
	"X-Real-IP",           // nginx
	"X-Forwarded-For",     // Standard proxy header (first IP)
	"X-Client-IP",         // Some proxies
	"X-Forwarded",         // RFC 7239
	"X-Cluster-Client-IP", // GCP, Azure
	"Forwarded",           // RFC 7239 (parse for= parameter)
}

// extractClientIP extracts the real client IP from request headers.
// It checks common proxy headers in order of preference and validates IP addresses.
// Falls back to RemoteAddr if no valid IP is found in headers.
func extractClientIP(r *http.Request) string {
	// Check headers in order of preference using pre-allocated slice
	for i := range proxyHeaders {
		header := proxyHeaders[i]
		if value := r.Header.Get(header); value != "" {
			// Handle special parsing for different headers
			switch header {
			case "X-Forwarded-For":
				if ip := parseXForwardedFor(value); ip != "" {
					return ip
				}
			case "Forwarded":
				if ip := parseForwardedHeader(value); ip != "" {
					return ip
				}
			default:
				if ip := parseAndValidateIP(value); ip != "" {
					return ip
				}
			}
		}
	}

	// Fall back to RemoteAddr
	remoteAddr := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// extractClientIPWithTrustedProxies extracts client IP but only trusts proxy headers
// if the request comes from a trusted proxy network.
func extractClientIPWithTrustedProxies(r *http.Request, trustedProxies []string) string {
	// Get remote address
	remoteAddr := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteAddr = host
	}

	// Parse trusted proxy networks
	var trustedNets []*net.IPNet
	for _, proxy := range trustedProxies {
		_, network, err := net.ParseCIDR(proxy)
		if err == nil {
			trustedNets = append(trustedNets, network)
		} else {
			// Try as single IP
			if ip := net.ParseIP(proxy); ip != nil {
				var network *net.IPNet
				if ip.To4() != nil {
					_, network, _ = net.ParseCIDR(proxy + "/32")
				} else {
					_, network, _ = net.ParseCIDR(proxy + "/128")
				}
				if network != nil {
					trustedNets = append(trustedNets, network)
				}
			}
		}
	}

	// Check if request comes from trusted proxy
	if len(trustedNets) > 0 {
		remoteIP := net.ParseIP(remoteAddr)
		if remoteIP != nil {
			for _, trustedNet := range trustedNets {
				if trustedNet.Contains(remoteIP) {
					// Request comes from trusted proxy, check headers
					return extractClientIP(r)
				}
			}
		}
	}

	// Not from trusted proxy, return remote address
	return remoteAddr
}

// parseXForwardedFor parses X-Forwarded-For header and returns the first valid IP.
// X-Forwarded-For format: client, proxy1, proxy2
func parseXForwardedFor(value string) string {
	ips := strings.Split(value, ",")
	for _, ip := range ips {
		if cleaned := parseAndValidateIP(ip); cleaned != "" {
			return cleaned
		}
	}
	return ""
}

// parseForwardedHeader parses RFC 7239 Forwarded header and extracts the "for" parameter.
// Forwarded format: for=192.0.2.60;proto=http;by=203.0.113.43
func parseForwardedHeader(value string) string {
	// Simple parsing for the "for" parameter
	parts := strings.Split(value, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "for=") {
			forValue := strings.TrimPrefix(part, "for=")
			// Remove quotes if present
			forValue = strings.Trim(forValue, "\"")
			// Handle IPv6 brackets: [2001:db8::1]:8080 -> 2001:db8::1
			if strings.HasPrefix(forValue, "[") && strings.Contains(forValue, "]") {
				if idx := strings.Index(forValue, "]"); idx > 0 {
					forValue = forValue[1:idx]
				}
			}
			// Remove port if present
			if host, _, err := net.SplitHostPort(forValue); err == nil {
				forValue = host
			}
			if ip := parseAndValidateIP(forValue); ip != "" {
				return ip
			}
		}
	}
	return ""
}

// parseAndValidateIP parses and validates an IP address from a header value.
// It handles IPv4, IPv6, and removes common artifacts like ports.
func parseAndValidateIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	// Handle IPv6 brackets
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = value[1 : len(value)-1]
	}

	// Try to split host:port in case there's a port
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}

	// Validate IP
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}

	return ""
}
