package servex

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// MiddlewareRouter is an interface representing a router that supports adding middleware.
// This is typically implemented by router packages like gorilla/mux.
type MiddlewareRouter interface {
	// Use adds one or more middleware functions to the router.
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

			noLog := getValueFromContext[bool](r, noLogKey{})
			if noLog {
				return
			}

			logBundle := RequestLogBundle{
				Request:           r,
				RequestID:         getOrSetRequestID(r),
				StartTime:         start,
				NoLogClientErrors: getValueFromContext[bool](r, noLogClientErrorsKey{}),
			}
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

			logger.Log(logBundle)
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
func RegisterSimpleAuthMiddleware(router MiddlewareRouter, authToken string) {
	if authToken == "" {
		return // Don't register auth middleware if no token is configured
	}
	authTokenBytes := []byte(authToken)
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				err := errors.New("missing Authorization header")
				C(w, r).Error(err, http.StatusUnauthorized, "Authorization header required")
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
				C(w, r).Error(err, http.StatusUnauthorized, "Invalid Authorization header format")
				return
			}

			if subtle.ConstantTimeCompare([]byte(providedToken), authTokenBytes) == 1 {
				next.ServeHTTP(w, r) // Token is valid, proceed to the next handler
				return
			}

			// Token is invalid
			err := errors.New("invalid auth token provided")
			C(w, r).Error(err, http.StatusUnauthorized, "Invalid auth token")
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
