package servex

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/gorilla/mux"
	jsoniter "github.com/json-iterator/go"
)

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
	defer func() { _ = file.Close() }()

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

// Cookie returns the cookie with the given name.
func (ctx *Context) Cookie(key string) (*http.Cookie, error) {
	return ctx.r.Cookie(key)
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

	bytes, err := io.ReadAll(io.LimitReader(ctx.r.Body, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	// Check if we hit the size limit
	if int64(len(bytes)) > maxSize {
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

	bytes, err := io.ReadAll(io.LimitReader(ctx.r.Body, maxSize+1))
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	// Check if we hit the size limit
	if int64(len(bytes)) > maxSize {
		return fmt.Errorf("request body too large (max: %d bytes)", maxSize)
	}

	if err := json.Unmarshal(bytes, body); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
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

// EmailVerified returns whether the authenticated user's email is verified.
// This value is embedded in the JWT access token at token creation time.
// Returns false if user is not authenticated or field is not set.
func (ctx *Context) EmailVerified() bool {
	return getValueFromContext[bool](ctx.r, EmailVerifiedContextKey{})
}

// TwoFactorEnabled returns whether the authenticated user has 2FA enabled.
// This value is embedded in the JWT access token at token creation time.
// Returns false if user is not authenticated or field is not set.
func (ctx *Context) TwoFactorEnabled() bool {
	return getValueFromContext[bool](ctx.r, TwoFactorEnabledContextKey{})
}

// UpgradeWebSocket upgrades the HTTP connection to a WebSocket connection.
// This is a low-level escape hatch; prefer server.WS() for most use cases.
//
// Example:
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//		conn, err := ctx.UpgradeWebSocket(nil)
//		if err != nil {
//			ctx.BadRequest(err, "websocket upgrade failed")
//			return
//		}
//		defer conn.Close(servex.StatusNormalClosure, "")
//		// use raw coder/websocket API
//	}
func (ctx *Context) UpgradeWebSocket(opts *websocket.AcceptOptions) (*websocket.Conn, error) {
	return websocket.Accept(ctx.w, ctx.r, opts)
}
