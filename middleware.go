package servex

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"compress/flate"
	"compress/gzip"

	"github.com/gorilla/mux"
)

// MiddlewareRouter represents a router that supports adding middleware functions.
// This interface is typically implemented by router packages like gorilla/mux
// and allows servex to register its middleware functions with different router implementations.
//
// The middleware functions registered through this interface provide essential
// features like logging, security headers, rate limiting, authentication, and more.
type MiddlewareRouter interface {
	// Use adds one or more middleware functions to the router.
	// Middleware functions are executed in the order they are added.
	Use(middleware ...mux.MiddlewareFunc)
}

// RegisterLoggingMiddleware registers a middleware that logs incoming requests.
// It logs details such as request method, path, status code, duration, and any errors encountered during processing.
// It also integrates with a Metrics handler if provided.
// If the logger is nil, it defaults to a BaseRequestLogger using slog.Default().
// Requests can be excluded from logging by calling ctx.NoLog() within the handler.
func RegisterLoggingMiddleware(router MiddlewareRouter, logger RequestLogger, metrics Metrics, noLogClientErrors ...bool) {
	if logger == nil {
		logger = &BaseRequestLogger{
			Logger: slog.Default(),
		}
	}
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			if metrics != nil {
				metrics.HandleRequest(r)
			}

			// Wrap the response writer to capture status code if not set by Error()
			lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK} // Default to 200 OK

			next.ServeHTTP(lrw, r)

			if metrics != nil {
				metrics.HandleResponse(r, w, lrw.statusCode, time.Since(start))
			}

			// Check for NoLog flag from both context and loggingResponseWriter
			noLog := getValueFromContext[bool](r, noLogKey{}) || lrw.noLog
			if noLog {
				return
			}

			logBundle := getRequestLogBundle()
			defer putRequestLogBundle(logBundle)

			logBundle.Request = r
			logBundle.RequestID = getOrSetRequestID(r)
			logBundle.StartTime = start
			logBundle.NoLogClientErrors = getValueFromContext[bool](r, noLogClientErrorsKey{})
			if len(noLogClientErrors) > 0 {
				logBundle.NoLogClientErrors = noLogClientErrors[0]
			}

			// Check if error details were explicitly set on the response writer wrapper
			if lrw.errorCodeSet {
				logBundle.Error = lrw.loggedError
				logBundle.ErrorMessage = lrw.loggedMsg
				logBundle.StatusCode = lrw.loggedCode
			} else {
				// Fallback: Try reading from context (might be incorrect if handler modified request context pointer)
				// and use the status code captured by the wrapper.
				logBundle.Error = getValueFromContext[error](r, errorKey{})
				logBundle.ErrorMessage = getValueFromContext[string](r, msgKey{})
				logBundle.StatusCode = getValueFromContext[int](r, codeKey{})
			}

			logger.Log(*logBundle)
		})
	})
}

// RegisterRecoverMiddleware registers a middleware that recovers from panics in HTTP handlers.
// If a panic occurs, it logs the error and stack trace using the provided logger
// (defaulting to slog.Default() if nil) and sends a 500 Internal Server Error response
// only if no response headers have been written yet.
func RegisterRecoverMiddleware(router MiddlewareRouter, logger ErrorLogger) {
	if logger == nil {
		logger = slog.Default()
	}
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				panicErr := recover()
				if panicErr == nil {
					return // No panic occurred
				}

				// Log the error and the stack trace regardless of response status
				err := fmt.Errorf("panic recovered: %v", panicErr)
				logger.Error(string(debug.Stack()), "error", err)

				// Check if headers have already been written
				headersWritten := false
				if lrw, ok := w.(*loggingResponseWriter); ok {
					headersWritten = lrw.wroteHeader
				} else {
					// Fallback check: Inspect the header map directly.
					// This isn't foolproof but better than nothing if not using loggingResponseWriter.
					if len(w.Header()) > 0 {
						// Heuristic: If headers exist, assume they might have been written or are about to be.
						// It's safer not to try writing again in this ambiguous case.
						headersWritten = true
					}
				}

				// Send a 500 response only if headers haven't been written yet.
				if !headersWritten {
					w.WriteHeader(http.StatusInternalServerError)
					// Optionally write a generic error message to the body
					_, _ = w.Write([]byte("Internal Server Error"))
					// We avoid calling C(w, r).Error here to prevent potential double logging
					// and issues if C() itself has complex behavior or panics.
				}
			}()
			next.ServeHTTP(w, r)
		})
	})
}

// RegisterSimpleAuthMiddleware registers a middleware for simple token-based authentication.
// It checks the "Authorization" header for a token matching the provided authToken.
// It supports both "Bearer <token>" and "<token>" formats.
// If the authToken is empty, no middleware is registered.
// If the header is missing or the token is invalid, it responds with 401 Unauthorized.
func RegisterSimpleAuthMiddleware(router MiddlewareRouter, authToken string, opts ...Options) {
	if authToken == "" {
		return // Don't register auth middleware if no token is configured
	}
	authTokenBytes := []byte(authToken)

	// Use provided options or empty options if none provided
	var serverOpts Options
	if len(opts) > 0 {
		serverOpts = opts[0]
	}

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				err := errors.New("missing Authorization header")
				C(w, r, serverOpts).Error(err, http.StatusUnauthorized, "Authorization header required")
				return
			}

			tokenSpl := strings.SplitN(authHeader, " ", 2)
			var providedToken string
			if len(tokenSpl) == 2 && strings.ToLower(tokenSpl[0]) == "bearer" {
				providedToken = tokenSpl[1]
			} else if len(tokenSpl) == 1 {
				// Support token directly in the header without "Bearer" prefix
				providedToken = tokenSpl[0]
			} else {
				err := errors.New("invalid Authorization header format")
				C(w, r, serverOpts).Error(err, http.StatusUnauthorized, "Invalid Authorization header format")
				return
			}

			if subtle.ConstantTimeCompare([]byte(providedToken), authTokenBytes) == 1 {
				next.ServeHTTP(w, r) // Token is valid, proceed to the next handler
				return
			}

			// Token is invalid
			err := errors.New("invalid auth token provided")
			C(w, r, serverOpts).Error(err, http.StatusUnauthorized, "Invalid auth token")
		})
	})
}

// RegisterRequestSizeLimitMiddleware registers a middleware that enforces request body size limits.
// This helps prevent DoS attacks by limiting the maximum size of request bodies.
// If request size limits are not enabled in options, no middleware is registered.
// Requests exceeding limits are rejected with 413 Request Entity Too Large.
func RegisterRequestSizeLimitMiddleware(router MiddlewareRouter, opts Options) {
	if !opts.EnableRequestSizeLimits {
		return // Don't register middleware if size limits are disabled
	}

	// Set defaults if not configured
	maxRequestBodySize := opts.MaxRequestBodySize
	if maxRequestBodySize <= 0 {
		maxRequestBodySize = defaultMaxRequestBodySize // 32 MB default
	}

	maxJSONBodySize := opts.MaxJSONBodySize
	if maxJSONBodySize <= 0 {
		maxJSONBodySize = defaultMaxJSONBodySize // 1 MB default
	}

	maxMultipartMemory := opts.MaxMultipartMemory
	if maxMultipartMemory <= 0 {
		maxMultipartMemory = defaultMaxMemoryMultipartForm // 10 MB default
	}

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if Content-Length header is missing (chunked encoding, etc.)
			if r.ContentLength == -1 {
				// For chunked encoding, we'll let the individual read functions handle limits
				next.ServeHTTP(w, r)
				return
			}

			// Check general request body size limit
			if r.ContentLength > maxRequestBodySize {
				err := fmt.Errorf("request body too large: %d bytes (max: %d bytes)", r.ContentLength, maxRequestBodySize)
				C(w, r, opts).Error(err, http.StatusRequestEntityTooLarge, "Request body too large")
				return
			}

			// Check JSON-specific limits for JSON content types
			contentType := r.Header.Get("Content-Type")
			if strings.Contains(strings.ToLower(contentType), "application/json") {
				if r.ContentLength > maxJSONBodySize {
					err := fmt.Errorf("JSON body too large: %d bytes (max: %d bytes)", r.ContentLength, maxJSONBodySize)
					C(w, r, opts).Error(err, http.StatusRequestEntityTooLarge, "JSON body too large")
					return
				}
			}

			// For multipart forms, set the maximum memory before processing
			if strings.Contains(strings.ToLower(contentType), "multipart/form-data") {
				// This affects how much memory is used before writing to disk
				// The actual size check happens in the ReadFile functions
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
			} else {
				// For other content types, wrap the body with a size limit
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
			}

			next.ServeHTTP(w, r)
		})
	})
}

// loggingResponseWriter wraps http.ResponseWriter to capture the status code
// and potentially error details set via ctx.Error.
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
	// Fields to store details from ctx.Error
	loggedError  error
	loggedMsg    string
	loggedCode   int
	noLog        bool
	errorCodeSet bool // Flag to indicate if code/error/msg were explicitly set by ctx.Error
}

// WriteHeader captures the status code and calls the original WriteHeader.
func (lrw *loggingResponseWriter) WriteHeader(code int) {
	if lrw.wroteHeader {
		return
	}
	lrw.statusCode = code
	// Only mark the status code as explicitly set by ctx.Error if the flag is true
	if !lrw.errorCodeSet {
		lrw.loggedCode = code // Keep track of the written code even if not set by Error()
	}
	lrw.ResponseWriter.WriteHeader(code)
	lrw.wroteHeader = true
}

// Write calls the original Write and ensures WriteHeader(200) is called if not already.
func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	if !lrw.wroteHeader {
		lrw.WriteHeader(http.StatusOK) // Default to 200 OK if Write is called before WriteHeader
	}
	return lrw.ResponseWriter.Write(b)
}

func registerOptsMiddleware(router MiddlewareRouter, opts Options) {
	if !opts.NoLogClientErrors && !opts.SendErrorToClient {
		return
	}
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if opts.NoLogClientErrors {
				r = r.WithContext(context.WithValue(r.Context(), noLogClientErrorsKey{}, true))
			}
			if opts.SendErrorToClient {
				r = r.WithContext(context.WithValue(r.Context(), sendErrorToClientKey{}, true))
			}
			next.ServeHTTP(w, r)
		})
	})
}

// RegisterSecurityHeadersMiddleware adds security headers to HTTP responses.
// It implements common security headers to protect against various attacks.
// If the config is empty or disabled, no middleware will be registered.
func RegisterSecurityHeadersMiddleware(router MiddlewareRouter, cfg SecurityConfig) {
	if !cfg.Enabled {
		return // Don't register security headers middleware if disabled
	}

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the path should have security headers applied
			if !shouldApplySecurityHeaders(r, cfg) {
				next.ServeHTTP(w, r)
				return
			}

			// Apply security headers before handler
			applySecurityHeaders(w, cfg)

			// Execute the handler
			next.ServeHTTP(w, r)
		})
	})

	// Register CSRF protection if enabled
	if cfg.CSRFEnabled {
		RegisterCSRFMiddleware(router, cfg)
	}
}

// RegisterCSRFMiddleware adds CSRF (Cross-Site Request Forgery) protection middleware.
// This middleware provides comprehensive CSRF protection for web applications.
func RegisterCSRFMiddleware(router MiddlewareRouter, cfg SecurityConfig) {
	// Set defaults for CSRF configuration
	tokenName := cfg.CSRFTokenName
	if tokenName == "" {
		tokenName = "X-CSRF-Token"
	}

	cookieName := cfg.CSRFCookieName
	if cookieName == "" {
		cookieName = "csrf_token"
	}

	cookiePath := cfg.CSRFCookiePath
	if cookiePath == "" {
		cookiePath = "/"
	}

	errorMessage := cfg.CSRFErrorMessage
	if errorMessage == "" {
		errorMessage = "CSRF token validation failed"
	}

	safeMethods := cfg.CSRFSafeMethods
	if len(safeMethods) == 0 {
		safeMethods = []string{GET, HEAD, OPTIONS, TRACE}
	}

	// Create safe methods map for faster lookup
	safeMethodsMap := make(map[string]bool)
	for _, method := range safeMethods {
		safeMethodsMap[strings.ToUpper(method)] = true
	}

	// Register CSRF token endpoint if configured
	if cfg.CSRFTokenEndpoint != "" {
		registerCSRFTokenEndpoint(router, cfg.CSRFTokenEndpoint, cookieName, cookiePath, cfg)
	}

	// Register CSRF validation middleware
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CSRF validation for safe methods
			if safeMethodsMap[strings.ToUpper(r.Method)] {
				// Set CSRF cookie for safe methods to establish token
				if _, err := r.Cookie(cookieName); err != nil {
					setCSRFCookie(w, cookieName, cookiePath, cfg)
				}
				next.ServeHTTP(w, r)
				return
			}

			// Skip CSRF validation for token endpoint
			if cfg.CSRFTokenEndpoint != "" && r.URL.Path == cfg.CSRFTokenEndpoint {
				next.ServeHTTP(w, r)
				return
			}

			// Check if the path should have CSRF protection applied
			if !shouldApplySecurityHeaders(r, cfg) {
				next.ServeHTTP(w, r)
				return
			}

			// Validate CSRF token
			if !validateCSRFToken(r, tokenName, cookieName) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(errorMessage))
				return
			}

			// Token is valid, proceed with request
			next.ServeHTTP(w, r)
		})
	})
}

// registerCSRFTokenEndpoint creates an endpoint that returns CSRF tokens for SPAs and AJAX applications.
func registerCSRFTokenEndpoint(router MiddlewareRouter, endpoint, cookieName, cookiePath string, cfg SecurityConfig) {
	if endpoint == "" {
		endpoint = "/csrf-token"
	}
	// We need to add the endpoint to the router if it's a *mux.Router
	if muxRouter, ok := router.(*mux.Router); ok {
		muxRouter.HandleFunc(endpoint, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != GET {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			// Generate and set CSRF token
			token := setCSRFCookie(w, cookieName, cookiePath, cfg)

			// Return token as JSON
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"csrf_token": "%s"}`, token)
		}).Methods(GET)
	}
}

// setCSRFCookie generates a new CSRF token and sets it as a cookie.
func setCSRFCookie(w http.ResponseWriter, cookieName, cookiePath string, cfg SecurityConfig) string {
	// Generate secure random token
	token := generateCSRFToken()

	// Create cookie
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     cookiePath,
		HttpOnly: cfg.CSRFCookieHttpOnly,
		Secure:   cfg.CSRFCookieSecure,
		SameSite: parseSameSite(cfg.CSRFCookieSameSite),
	}

	// Set MaxAge if configured
	if cfg.CSRFCookieMaxAge > 0 {
		cookie.MaxAge = cfg.CSRFCookieMaxAge
		cookie.Expires = time.Now().Add(time.Duration(cfg.CSRFCookieMaxAge) * time.Second)
	}

	// Set cookie
	http.SetCookie(w, cookie)

	return token
}

// validateCSRFToken validates the CSRF token from the request.
func validateCSRFToken(r *http.Request, tokenName, cookieName string) bool {
	// Get expected token from cookie
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	expectedToken := cookie.Value

	// Extract token from request (try multiple sources)
	var providedToken string

	// 1. Try header
	providedToken = r.Header.Get(tokenName)

	// 2. Try form field if not found in header
	if providedToken == "" {
		if err := r.ParseForm(); err == nil {
			providedToken = r.FormValue(tokenName)
		}
	}

	// 3. Try multipart form if still not found
	if providedToken == "" {
		if err := r.ParseMultipartForm(32 << 20); err == nil { // 32MB max
			if r.MultipartForm != nil && r.MultipartForm.Value != nil {
				if values := r.MultipartForm.Value[tokenName]; len(values) > 0 {
					providedToken = values[0]
				}
			}
		}
	}

	// 4. Try query parameter as fallback
	if providedToken == "" {
		providedToken = r.URL.Query().Get(tokenName)
	}

	// Validate token using constant-time comparison
	if providedToken == "" || expectedToken == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(providedToken), []byte(expectedToken)) == 1
}

// generateCSRFToken generates a cryptographically secure random token.
func generateCSRFToken() string {
	// Generate 32 bytes of random data
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to time-based token if crypto/rand fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	// Encode as base64 URL-safe string
	return base64.URLEncoding.EncodeToString(bytes)
}

// parseSameSite converts string to http.SameSite enum.
func parseSameSite(sameSite string) http.SameSite {
	switch strings.ToLower(sameSite) {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode // Default to Lax for security and usability balance
	}
}

// shouldApplySecurityHeaders determines if security headers should be applied based on the path.
func shouldApplySecurityHeaders(r *http.Request, cfg SecurityConfig) bool {
	return matchPath(r.URL.Path, cfg.ExcludePaths, cfg.IncludePaths, true)
}

// applySecurityHeaders applies the configured security headers to the response.
func applySecurityHeaders(w http.ResponseWriter, cfg SecurityConfig) {
	header := w.Header()

	// Content Security Policy
	if cfg.ContentSecurityPolicy != "" {
		header.Set("Content-Security-Policy", cfg.ContentSecurityPolicy)
	}

	// X-Content-Type-Options
	if cfg.XContentTypeOptions != "" {
		header.Set("X-Content-Type-Options", cfg.XContentTypeOptions)
	}

	// X-Frame-Options
	if cfg.XFrameOptions != "" {
		header.Set("X-Frame-Options", cfg.XFrameOptions)
	}

	// X-XSS-Protection
	if cfg.XXSSProtection != "" {
		header.Set("X-XSS-Protection", cfg.XXSSProtection)
	}

	// Strict-Transport-Security
	if cfg.StrictTransportSecurity != "" {
		header.Set("Strict-Transport-Security", cfg.StrictTransportSecurity)
	}

	// Referrer-Policy
	if cfg.ReferrerPolicy != "" {
		header.Set("Referrer-Policy", cfg.ReferrerPolicy)
	}

	// Permissions-Policy
	if cfg.PermissionsPolicy != "" {
		header.Set("Permissions-Policy", cfg.PermissionsPolicy)
	}

	// X-Permitted-Cross-Domain-Policies
	if cfg.XPermittedCrossDomainPolicies != "" {
		header.Set("X-Permitted-Cross-Domain-Policies", cfg.XPermittedCrossDomainPolicies)
	}

	// Cross-Origin-Embedder-Policy
	if cfg.CrossOriginEmbedderPolicy != "" {
		header.Set("Cross-Origin-Embedder-Policy", cfg.CrossOriginEmbedderPolicy)
	}

	// Cross-Origin-Opener-Policy
	if cfg.CrossOriginOpenerPolicy != "" {
		header.Set("Cross-Origin-Opener-Policy", cfg.CrossOriginOpenerPolicy)
	}

	// Cross-Origin-Resource-Policy
	if cfg.CrossOriginResourcePolicy != "" {
		header.Set("Cross-Origin-Resource-Policy", cfg.CrossOriginResourcePolicy)
	}
}

// RegisterCustomHeadersMiddleware adds custom headers to HTTP responses.
// This is separate from security headers to maintain separation of concerns.
func RegisterCustomHeadersMiddleware(router MiddlewareRouter, customHeaders map[string]string) {
	if len(customHeaders) == 0 {
		return // No custom headers to add
	}

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Apply custom headers before handler
			header := w.Header()
			for name, value := range customHeaders {
				if value != "" {
					header.Set(name, value)
				}
			}

			next.ServeHTTP(w, r)
		})
	})
}

// RegisterHeaderRemovalMiddleware removes specified headers from HTTP responses.
// Headers are removed after the handler executes to ensure proper removal
// of headers that might be set by the handler.
func RegisterHeaderRemovalMiddleware(router MiddlewareRouter, headersToRemove []string) {
	if len(headersToRemove) == 0 {
		return // No headers to remove
	}

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Execute the handler first
			next.ServeHTTP(w, r)

			// Remove headers after handler execution
			for _, headerName := range headersToRemove {
				w.Header().Del(headerName)
			}
		})
	})
}

// RegisterCacheControlMiddleware adds cache control headers to HTTP responses.
// It implements common HTTP caching headers to control browser and proxy caching behavior.
// If the config is empty or disabled, no middleware will be registered.
func RegisterCacheControlMiddleware(router MiddlewareRouter, cfg CacheConfig) {
	if !cfg.Enabled {
		return // Don't register cache control middleware if disabled
	}

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the path should have cache control headers applied
			if !shouldApplyCacheHeaders(r, cfg) {
				next.ServeHTTP(w, r)
				return
			}

			// Apply cache control headers and handle conditional requests
			if applyCacheHeaders(w, r, cfg) {
				return // Conditional request was handled with 304 Not Modified
			}

			// Execute the handler
			next.ServeHTTP(w, r)
		})
	})
}

// shouldApplyCacheHeaders determines if cache headers should be applied based on the path.
func shouldApplyCacheHeaders(r *http.Request, cfg CacheConfig) bool {
	return matchPath(r.URL.Path, cfg.ExcludePaths, cfg.IncludePaths, true)
}

// applyCacheHeaders applies the configured cache control headers to the response.
// Returns true if a conditional request was handled with 304 Not Modified.
func applyCacheHeaders(w http.ResponseWriter, r *http.Request, cfg CacheConfig) bool {
	header := w.Header()

	// ETag header - dynamic function takes precedence over static value
	var etag string
	if cfg.ETagFunc != nil {
		if dynamicETag := cfg.ETagFunc(r); dynamicETag != "" {
			etag = dynamicETag
			header.Set("ETag", etag)
		}
	} else if cfg.ETag != "" {
		etag = cfg.ETag
		header.Set("ETag", etag)
	}

	// Last-Modified header - dynamic function takes precedence over static value
	var lastModified string
	if cfg.LastModifiedFunc != nil {
		lastModTime := cfg.LastModifiedFunc(r)
		if !lastModTime.IsZero() {
			lastModified = lastModTime.Format(http.TimeFormat)
			header.Set("Last-Modified", lastModified)
		}
	} else if cfg.LastModified != "" {
		lastModified = cfg.LastModified
		header.Set("Last-Modified", lastModified)
	}

	// Handle conditional requests
	if handleConditionalRequest(w, r, etag, lastModified) {
		return true // Request was handled with 304 Not Modified
	}

	// Cache-Control header
	if cfg.CacheControl != "" {
		header.Set("Cache-Control", cfg.CacheControl)
	}

	// Expires header
	if cfg.Expires != "" {
		header.Set("Expires", cfg.Expires)
	}

	// Vary header
	if cfg.Vary != "" {
		header.Set("Vary", cfg.Vary)
	}

	return false // No conditional request was handled, continue normally
}

// handleConditionalRequest checks for conditional request headers and returns true if a 304 response was sent.
func handleConditionalRequest(w http.ResponseWriter, r *http.Request, etag, lastModified string) bool {
	// Handle If-None-Match (ETag-based conditional requests)
	if etag != "" {
		ifNoneMatch := r.Header.Get("If-None-Match")
		if ifNoneMatch != "" {
			// Check for exact match or wildcard
			if ifNoneMatch == "*" || ifNoneMatch == etag {
				w.WriteHeader(http.StatusNotModified)
				return true
			}
			// Handle comma-separated list of ETags
			for _, tag := range strings.Split(ifNoneMatch, ",") {
				tag = strings.TrimSpace(tag)
				if tag == etag {
					w.WriteHeader(http.StatusNotModified)
					return true
				}
			}
		}
	}

	// Handle If-Modified-Since (Last-Modified-based conditional requests)
	if lastModified != "" {
		ifModifiedSince := r.Header.Get("If-Modified-Since")
		if ifModifiedSince != "" {
			// Parse both timestamps
			lastModTime, err1 := time.Parse(http.TimeFormat, lastModified)
			ifModTime, err2 := time.Parse(http.TimeFormat, ifModifiedSince)

			if err1 == nil && err2 == nil {
				// If the resource hasn't been modified since the client's timestamp
				if !lastModTime.After(ifModTime) {
					w.WriteHeader(http.StatusNotModified)
					return true
				}
			}
		}
	}

	return false // No conditional request matched
}

// matchPath checks if a request path should be included or excluded based on the provided patterns.
// It supports both exact string matching and wildcard pattern matching (using filepath.Match).
// Returns true if the path should be processed, false if it should be skipped.
//
// Parameters:
//   - path: the request path to check
//   - excludePaths: list of paths/patterns to exclude (takes precedence)
//   - includePaths: list of paths/patterns to include (only checked if excludePaths don't match)
//   - useWildcards: if true, uses filepath.Match for pattern matching; if false, uses exact string matching
//
// Logic:
//  1. If path matches any exclude pattern, return false
//  2. If include patterns are specified and path doesn't match any, return false
//  3. Otherwise, return true (default behavior is to process the path)
func matchPath(path string, excludePaths, includePaths []string, useWildcards bool) bool {
	// Check if path is in the excluded list
	for _, excludePath := range excludePaths {
		var matched bool
		if useWildcards {
			matched, _ = filepath.Match(excludePath, path)
		} else {
			matched = excludePath == path
		}
		if matched {
			return false
		}
	}

	// If include paths are specified, check if this path is included
	if len(includePaths) > 0 {
		for _, includePath := range includePaths {
			var matched bool
			if useWildcards {
				matched, _ = filepath.Match(includePath, path)
			} else {
				matched = includePath == path
			}
			if matched {
				return true
			}
		}
		return false // Path not in include list
	}

	// By default, process all paths not explicitly excluded
	return true
}

// RegisterHTTPSRedirectMiddleware adds HTTP to HTTPS redirection middleware to the router.
// This middleware automatically redirects all HTTP requests to their HTTPS equivalent
// to enforce secure connections across the entire application.
// If the config is disabled, no middleware will be registered.
func RegisterHTTPSRedirectMiddleware(router MiddlewareRouter, cfg HTTPSRedirectConfig) {
	if !cfg.Enabled {
		return // Don't register HTTPS redirect middleware if disabled
	}

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the path should be redirected to HTTPS
			if !shouldRedirectToHTTPS(r, cfg) {
				next.ServeHTTP(w, r)
				return
			}

			// Check if the request is already HTTPS
			if isHTTPSRequest(r, cfg.TrustedProxies) {
				next.ServeHTTP(w, r)
				return
			}

			// Perform HTTP to HTTPS redirect
			httpsURL := "https://" + r.Host + r.RequestURI

			// Choose redirect status code
			statusCode := http.StatusMovedPermanently // 301
			if !cfg.Permanent {
				statusCode = http.StatusFound // 302
			}

			w.Header().Set("Location", httpsURL)
			w.WriteHeader(statusCode)
		})
	})
}

// shouldRedirectToHTTPS determines if a request path should be redirected to HTTPS
// based on the configuration's include and exclude paths.
func shouldRedirectToHTTPS(r *http.Request, cfg HTTPSRedirectConfig) bool {
	return matchPath(r.URL.Path, cfg.ExcludePaths, cfg.IncludePaths, true)
}

// isHTTPSRequest checks if the current request is already using HTTPS.
// It considers both direct TLS connections and proxy headers for load balancer scenarios.
func isHTTPSRequest(r *http.Request, trustedProxies []string) bool {
	// Direct TLS connection
	if r.TLS != nil {
		return true
	}

	// Check proxy headers only if the request comes from a trusted proxy
	if len(trustedProxies) > 0 {
		remoteAddr := r.RemoteAddr
		if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
			remoteAddr = host
		}

		// Check if request comes from trusted proxy
		if isFromTrustedHTTPSProxy(remoteAddr, trustedProxies) {
			return isHTTPSFromProxyHeaders(r)
		}
	}

	return false
}

// isFromTrustedHTTPSProxy checks if the remote address is from a trusted proxy for HTTPS redirection.
func isFromTrustedHTTPSProxy(remoteAddr string, trustedProxies []string) bool {
	remoteIP := net.ParseIP(remoteAddr)
	if remoteIP == nil {
		return false
	}

	for _, proxy := range trustedProxies {
		// Try parsing as CIDR
		_, network, err := net.ParseCIDR(proxy)
		if err == nil {
			if network.Contains(remoteIP) {
				return true
			}
			continue
		}

		// Try parsing as single IP
		proxyIP := net.ParseIP(proxy)
		if proxyIP != nil && proxyIP.Equal(remoteIP) {
			return true
		}
	}

	return false
}

// isHTTPSFromProxyHeaders checks standard proxy headers to determine if the original request was HTTPS.
func isHTTPSFromProxyHeaders(r *http.Request) bool {
	// Check X-Forwarded-Proto header (most common)
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return strings.ToLower(proto) == "https"
	}

	// Check X-Forwarded-Ssl header (some load balancers)
	if ssl := r.Header.Get("X-Forwarded-Ssl"); ssl != "" {
		return strings.ToLower(ssl) == "on"
	}

	// Check X-Url-Scheme header (some proxies)
	if scheme := r.Header.Get("X-Url-Scheme"); scheme != "" {
		return strings.ToLower(scheme) == "https"
	}

	// Check Front-End-Https header (Microsoft IIS)
	if frontEnd := r.Header.Get("Front-End-Https"); frontEnd != "" {
		return strings.ToLower(frontEnd) == "on"
	}

	// Check X-Forwarded-Port header (if it's the standard HTTPS port)
	if port := r.Header.Get("X-Forwarded-Port"); port == "443" {
		return true
	}

	return false
}

// RegisterCORSMiddleware registers a middleware that handles Cross-Origin Resource Sharing (CORS).
// It supports preflight requests, origin validation, method and header restrictions,
// credentials handling, and path-based filtering.
// If CORS is not enabled in the configuration, no middleware is registered.
func RegisterCORSMiddleware(router MiddlewareRouter, opts Options) {
	cfg := opts.CORS
	if !cfg.Enabled {
		return // Don't register CORS middleware if disabled
	}

	// Set defaults if not configured
	allowOrigins := cfg.AllowOrigins
	if len(allowOrigins) == 0 {
		allowOrigins = []string{"*"} // Default to allow all origins
	}

	allowMethods := cfg.AllowMethods
	if len(allowMethods) == 0 {
		allowMethods = []string{GET, POST, PUT, DELETE, OPTIONS, "HEAD", PATCH}
	}

	allowHeaders := cfg.AllowHeaders
	if len(allowHeaders) == 0 {
		allowHeaders = []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"}
	}

	// Create maps for faster lookup
	allowedOrigins := make(map[string]bool)
	hasWildcard := false
	for _, origin := range allowOrigins {
		if origin == "*" {
			hasWildcard = true
			break
		}
		allowedOrigins[origin] = true
	}

	allowedMethods := make(map[string]bool)
	for _, method := range allowMethods {
		allowedMethods[strings.ToUpper(method)] = true
	}

	// Register a catch-all OPTIONS handler for preflight requests if the router supports it
	if muxRouter, ok := router.(*mux.Router); ok {
		muxRouter.PathPrefix("/").Methods(OPTIONS).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only handle preflight requests (those with Access-Control-Request-Method header)
			if r.Header.Get("Access-Control-Request-Method") == "" {
				// Not a preflight request, return 404
				w.WriteHeader(http.StatusNotFound)
				return
			}

			// Check if CORS should be applied to this path
			if !shouldApplyCORS(r, cfg) {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			origin := r.Header.Get("Origin")
			var allowedOrigin string
			if origin != "" {
				if hasWildcard {
					allowedOrigin = "*"
				} else if allowedOrigins[origin] {
					allowedOrigin = origin
				} else {
					// Origin not allowed
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}

			// Validate requested method
			requestedMethod := r.Header.Get("Access-Control-Request-Method")
			if !methodAllowedCORS(requestedMethod, allowMethods) {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			// Validate requested headers
			requestedHeaders := r.Header.Get("Access-Control-Request-Headers")
			if requestedHeaders != "" {
				headers := strings.Split(requestedHeaders, ",")
				for i, header := range headers {
					headers[i] = strings.TrimSpace(header)
				}
				if !headersAllowedCORS(headers, allowHeaders) {
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}

			// Set CORS headers
			if allowedOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			}

			if cfg.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				// When credentials are allowed, origin cannot be "*"
				if allowedOrigin == "*" && origin != "" {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
			}

			// Set preflight response headers
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(allowMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowHeaders, ", "))

			if cfg.MaxAge > 0 {
				w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", cfg.MaxAge))
			}

			w.WriteHeader(http.StatusOK)
		})
	}

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if CORS should be applied to this path
			if !shouldApplyCORS(r, cfg) {
				next.ServeHTTP(w, r)
				return
			}

			origin := r.Header.Get("Origin")

			// Validate origin
			var allowedOrigin string
			if origin != "" {
				if hasWildcard {
					allowedOrigin = "*"
				} else if allowedOrigins[origin] {
					allowedOrigin = origin
				} else {
					// Origin not allowed, proceed without CORS headers
					next.ServeHTTP(w, r)
					return
				}
			}

			// Set CORS headers
			if allowedOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			}

			if cfg.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				// When credentials are allowed, origin cannot be "*"
				if allowedOrigin == "*" && origin != "" {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
			}

			if len(cfg.ExposeHeaders) > 0 {
				w.Header().Set("Access-Control-Expose-Headers", strings.Join(cfg.ExposeHeaders, ", "))
			}

			// Handle preflight requests
			if r.Method == OPTIONS {
				// Check if this is a preflight request
				if r.Header.Get("Access-Control-Request-Method") != "" {
					// This is a preflight request
					// Validate requested method
					requestedMethod := r.Header.Get("Access-Control-Request-Method")
					if !methodAllowedCORS(requestedMethod, allowMethods) {
						w.WriteHeader(http.StatusMethodNotAllowed)
						return
					}

					// Validate requested headers
					requestedHeaders := r.Header.Get("Access-Control-Request-Headers")
					if requestedHeaders != "" {
						headers := strings.Split(requestedHeaders, ",")
						for i, header := range headers {
							headers[i] = strings.TrimSpace(header)
						}
						if !headersAllowedCORS(headers, allowHeaders) {
							w.WriteHeader(http.StatusForbidden)
							return
						}
					}

					// Set preflight response headers
					w.Header().Set("Access-Control-Allow-Methods", strings.Join(allowMethods, ", "))
					w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowHeaders, ", "))

					if cfg.MaxAge > 0 {
						w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", cfg.MaxAge))
					}

					w.WriteHeader(http.StatusOK)
					return
				}
				// For non-preflight OPTIONS requests, continue to the next handler
			}

			// Continue with the request
			next.ServeHTTP(w, r)
		})
	})
}

// shouldApplyCORS determines if CORS headers should be applied to the request
// based on the configured include/exclude paths.
func shouldApplyCORS(r *http.Request, cfg CORSConfig) bool {
	path := r.URL.Path

	// If include paths are specified, path must match one of them
	if len(cfg.IncludePaths) > 0 {
		return matchPath(path, nil, cfg.IncludePaths, true)
	}

	// If exclude paths are specified, path must not match any of them
	if len(cfg.ExcludePaths) > 0 {
		return !matchPath(path, cfg.ExcludePaths, nil, true)
	}

	// Apply CORS to all paths by default
	return true
}

// originAllowedCORS checks if an origin is allowed based on the allowed origins list.
func originAllowedCORS(origin string, allowOrigins []string) bool {
	if origin == "" {
		return false
	}

	for _, allowed := range allowOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

// methodAllowedCORS checks if a method is allowed based on the allowed methods list.
// The comparison is case-insensitive.
func methodAllowedCORS(method string, allowMethods []string) bool {
	if len(allowMethods) == 0 {
		return true // Allow all when no methods specified
	}

	method = strings.ToUpper(method)
	for _, allowed := range allowMethods {
		if strings.ToUpper(allowed) == method {
			return true
		}
	}
	return false
}

// headersAllowedCORS checks if all requested headers are allowed.
// The comparison is case-insensitive.
func headersAllowedCORS(headers []string, allowHeaders []string) bool {
	if len(allowHeaders) == 0 {
		return true // Allow all when no headers specified
	}

	if len(headers) == 0 {
		return true // No headers requested
	}

	// Create a map for case-insensitive lookup
	allowedMap := make(map[string]bool)
	for _, header := range allowHeaders {
		allowedMap[strings.ToLower(header)] = true
	}

	// Check if all requested headers are allowed
	for _, header := range headers {
		if !allowedMap[strings.ToLower(header)] {
			return false
		}
	}
	return true
}

// RegisterCompressionMiddleware adds HTTP response compression middleware.
// It compresses response bodies using gzip or deflate encoding based on client Accept-Encoding headers.
// This can significantly reduce bandwidth usage and improve response times for text-based content.
func RegisterCompressionMiddleware(router MiddlewareRouter, cfg CompressionConfig) {
	if !cfg.Enabled {
		return // Don't register compression middleware if disabled
	}

	// Set defaults if not configured
	level := cfg.Level
	if level < 1 || level > 9 {
		level = 6 // Default compression level
	}

	minSize := cfg.MinSize
	if minSize < 0 {
		minSize = 1024 // Default 1KB minimum
	}

	// Default MIME types if none specified
	types := cfg.Types
	if len(types) == 0 {
		types = []string{
			"text/html",
			"text/css",
			"text/plain",
			"text/xml",
			"application/json",
			"application/javascript",
			"application/xml",
			"image/svg+xml",
		}
	}

	// Convert types to map for faster lookup
	compressibleTypes := make(map[string]bool)
	for _, mimeType := range types {
		compressibleTypes[strings.ToLower(mimeType)] = true
	}

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path should be compressed
			if !shouldApplyCompression(r, cfg) {
				next.ServeHTTP(w, r)
				return
			}

			// Check if client accepts compression
			acceptEncoding := r.Header.Get("Accept-Encoding")
			if acceptEncoding == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Determine which compression encoding to use
			var encoding string
			if strings.Contains(acceptEncoding, "gzip") {
				encoding = "gzip"
			} else if strings.Contains(acceptEncoding, "deflate") {
				encoding = "deflate"
			} else {
				// Client doesn't accept compression
				next.ServeHTTP(w, r)
				return
			}

			// Create compression response writer
			crw := &compressionResponseWriter{
				ResponseWriter:    w,
				encoding:          encoding,
				level:             level,
				minSize:           minSize,
				compressibleTypes: compressibleTypes,
				buf:               make([]byte, 0),
			}

			// Ensure cleanup
			defer crw.Close()

			// Process request with compression
			next.ServeHTTP(crw, r)
		})
	})
}

// shouldApplyCompression checks if compression should be applied to the request
func shouldApplyCompression(r *http.Request, cfg CompressionConfig) bool {
	return matchPath(r.URL.Path, cfg.ExcludePaths, cfg.IncludePaths, true)
}

// compressionResponseWriter wraps http.ResponseWriter to provide compression
type compressionResponseWriter struct {
	http.ResponseWriter
	encoding          string
	level             int
	minSize           int
	compressibleTypes map[string]bool
	writer            io.Writer
	buf               []byte
	headerWritten     bool
	compressed        bool
}

// Header returns the header map for the response
func (crw *compressionResponseWriter) Header() http.Header {
	return crw.ResponseWriter.Header()
}

// WriteHeader writes the status code and determines if compression should be used
func (crw *compressionResponseWriter) WriteHeader(statusCode int) {
	if crw.headerWritten {
		return
	}
	crw.headerWritten = true

	// Don't compress if content-encoding is already set
	if crw.Header().Get("Content-Encoding") != "" {
		crw.compressed = true
		crw.ResponseWriter.WriteHeader(statusCode)
		return
	}

	// Check content length if specified in headers
	if contentLengthStr := crw.Header().Get("Content-Length"); contentLengthStr != "" {
		if contentLength, err := strconv.Atoi(contentLengthStr); err == nil {
			if contentLength < crw.minSize {
				// Response too small to compress
				crw.compressed = true
				crw.ResponseWriter.WriteHeader(statusCode)
				return
			}
			// Content is large enough, we can set up compression immediately
			crw.setupCompressionIfNeeded()
		}
	}

	// If no content-length specified, defer compression decision until we have content
	crw.ResponseWriter.WriteHeader(statusCode)
}

// Write writes data to the response
func (crw *compressionResponseWriter) Write(data []byte) (int, error) {
	if !crw.headerWritten {
		crw.WriteHeader(http.StatusOK)
	}

	if crw.writer != nil {
		// Already determined to compress
		return crw.writer.Write(data)
	}

	if crw.compressed {
		// Already determined not to compress
		return crw.ResponseWriter.Write(data)
	}

	// Buffer data until we have enough to make a decision
	crw.buf = append(crw.buf, data...)

	// If we have enough data, make compression decision
	if len(crw.buf) >= crw.minSize {
		crw.setupCompressionIfNeeded()
		if crw.writer != nil {
			n, err := crw.writer.Write(crw.buf)
			crw.buf = nil // Clear buffer
			return n, err
		} else {
			n, err := crw.ResponseWriter.Write(crw.buf)
			crw.buf = nil // Clear buffer
			return n, err
		}
	}

	// Return length of data written to buffer
	return len(data), nil
}

// setupCompressionIfNeeded initializes the compression writer if content type is compressible
func (crw *compressionResponseWriter) setupCompressionIfNeeded() {
	if crw.writer != nil || crw.compressed {
		return
	}

	// Check content type
	contentType := crw.Header().Get("Content-Type")
	if contentType != "" {
		mainType := strings.Split(contentType, ";")[0]
		mainType = strings.TrimSpace(strings.ToLower(mainType))

		if !crw.compressibleTypes[mainType] {
			crw.compressed = true
			return
		}
	}

	crw.setupCompression()
}

// setupCompression initializes the compression writer
func (crw *compressionResponseWriter) setupCompression() {
	if crw.writer != nil || crw.compressed {
		return
	}

	// Set compression headers
	crw.Header().Set("Content-Encoding", crw.encoding)
	crw.Header().Set("Vary", "Accept-Encoding")
	crw.Header().Del("Content-Length") // Remove content-length as it will change

	// Create compression writer
	switch crw.encoding {
	case "gzip":
		gzipWriter, err := gzip.NewWriterLevel(crw.ResponseWriter, crw.level)
		if err != nil {
			crw.compressed = true
			return
		}
		crw.writer = gzipWriter
	case "deflate":
		deflateWriter, err := flate.NewWriter(crw.ResponseWriter, crw.level)
		if err != nil {
			crw.compressed = true
			return
		}
		crw.writer = deflateWriter
	default:
		crw.compressed = true
		return
	}
}

// Close flushes and closes the compression writer
func (crw *compressionResponseWriter) Close() error {
	// Handle remaining buffered data
	if len(crw.buf) > 0 {
		if crw.writer == nil && !crw.compressed {
			// Check if buffered content is below minimum size
			if len(crw.buf) < crw.minSize {
				// Content too small to compress, write directly without compression
				crw.ResponseWriter.Write(crw.buf)
				crw.buf = nil
				return nil
			}

			// Content is large enough, set up compression and write buffered data
			crw.setupCompression()
			if crw.writer != nil {
				crw.writer.Write(crw.buf)
			} else {
				// Compression setup failed, write directly
				crw.ResponseWriter.Write(crw.buf)
			}
			crw.buf = nil
		}
	}

	if crw.writer != nil {
		// Close compression writer
		switch w := crw.writer.(type) {
		case *gzip.Writer:
			return w.Close()
		case *flate.Writer:
			return w.Close()
		}
	}

	return nil
}

// enhancedUniversalResponseWriter wraps http.ResponseWriter to track response status
type enhancedUniversalResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	bytesWritten  int
	headerWritten bool
}

func (w *enhancedUniversalResponseWriter) WriteHeader(code int) {
	if !w.headerWritten {
		w.statusCode = code
		w.headerWritten = true
		w.ResponseWriter.WriteHeader(code)
	}
}

func (w *enhancedUniversalResponseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += n
	return n, err
}

// registerUniversalMiddleware provides more sophisticated universal middleware
func registerUniversalMiddleware(router MiddlewareRouter) {
	if muxRouter, ok := router.(*mux.Router); ok {
		// Store original NotFoundHandler
		originalNotFound := muxRouter.NotFoundHandler

		// Add response wrapper middleware
		router.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Wrap the response writer
				wrapper := &enhancedUniversalResponseWriter{
					ResponseWriter: w,
					statusCode:     0,
				}

				// Call next handler
				next.ServeHTTP(wrapper, r)

				// If no status was written (which shouldn't happen with our catch-all),
				// this would be where we could handle it
			})
		})

		// Set custom NotFoundHandler
		muxRouter.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if originalNotFound != nil {
				originalNotFound.ServeHTTP(w, r)
			} else {
				http.NotFound(w, r)
			}
		})
	}
}
