package servex

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	stdpath "path"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/gorilla/mux"
	"github.com/klauspost/compress/zstd"
)

var compressionBufPool = sync.Pool{New: func() any { b := make([]byte, 0, 4096); return &b }}

// compressionEncoder creates compression writers for a specific encoding.
type compressionEncoder struct {
	name      string
	priority  int // higher = preferred when client has no preference
	pool      sync.Pool
	newWriter func(w io.Writer, level int) (io.WriteCloser, error)
}

// defaultEncoders is the ordered list of supported encoders (highest priority first).
// Priority order: zstd > br > gzip > deflate.
var defaultEncoders = []*compressionEncoder{
	{
		name:     "zstd",
		priority: 40,
		newWriter: func(w io.Writer, level int) (io.WriteCloser, error) {
			var opts []zstd.EOption
			switch {
			case level <= 3:
				opts = append(opts, zstd.WithEncoderLevel(zstd.SpeedFastest))
			case level <= 6:
				opts = append(opts, zstd.WithEncoderLevel(zstd.SpeedDefault))
			default:
				opts = append(opts, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
			}
			return zstd.NewWriter(w, opts...)
		},
	},
	{
		name:     "br",
		priority: 30,
		newWriter: func(w io.Writer, level int) (io.WriteCloser, error) {
			return brotli.NewWriterLevel(w, level), nil
		},
	},
	{
		name:     "gzip",
		priority: 20,
		newWriter: func(w io.Writer, level int) (io.WriteCloser, error) {
			return gzip.NewWriterLevel(w, level)
		},
	},
	{
		name:     "deflate",
		priority: 10,
		newWriter: func(w io.Writer, level int) (io.WriteCloser, error) {
			return flate.NewWriter(w, level)
		},
	},
}

// encodingPreference represents a client's preference for an encoding.
type encodingPreference struct {
	name    string
	quality float64
}

// parseAcceptEncoding parses the Accept-Encoding header into a list of preferences.
// Example: "gzip;q=0.8, br, zstd;q=0.5" -> [{br, 1.0}, {gzip, 0.8}, {zstd, 0.5}]
func parseAcceptEncoding(header string) []encodingPreference {
	var prefs []encodingPreference
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := part
		quality := 1.0

		if idx := strings.Index(part, ";"); idx >= 0 {
			name = strings.TrimSpace(part[:idx])
			qPart := strings.TrimSpace(part[idx+1:])
			if strings.HasPrefix(qPart, "q=") {
				if q, err := strconv.ParseFloat(qPart[2:], 64); err == nil {
					quality = q
				}
			}
		}

		if quality > 0 {
			prefs = append(prefs, encodingPreference{name: strings.ToLower(name), quality: quality})
		}
	}
	return prefs
}

// selectEncoder picks the best encoder based on client Accept-Encoding preferences
// and available encoders.
func selectEncoder(acceptEncoding string, enabledEncoders []*compressionEncoder) *compressionEncoder {
	prefs := parseAcceptEncoding(acceptEncoding)
	if len(prefs) == 0 {
		return nil
	}

	// Build a set of acceptable encodings with quality values.
	accepted := make(map[string]float64, len(prefs))
	for _, p := range prefs {
		accepted[p.name] = p.quality
	}

	// Check for wildcard.
	wildcardQ, hasWildcard := accepted["*"]

	// Find best matching encoder: score = quality * 1000 + priority (breaks quality ties).
	var best *compressionEncoder
	bestScore := -1.0
	for _, enc := range enabledEncoders {
		q, ok := accepted[enc.name]
		if !ok && hasWildcard {
			q = wildcardQ
			ok = true
		}
		if !ok || q <= 0 {
			continue
		}
		score := q*1000 + float64(enc.priority)
		if score > bestScore {
			bestScore = score
			best = enc
		}
	}
	return best
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
			logBundle.TraceID = getValueFromContext[string](r, traceIDKey{})
			logBundle.SpanID = getValueFromContext[string](r, spanIDKey{})
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

// RegisterCacheControlMiddleware adds cache control headers to HTTP responses.
// It implements common HTTP caching headers to control browser and proxy caching behavior.
// If the config is empty or disabled, no middleware will be registered.
func RegisterCacheControlMiddleware(router MiddlewareRouter, cfg CacheConfig) {
	if !cfg.isActive() {
		return
	}

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip cache control for WebSocket upgrade requests
			if isWebSocketUpgrade(r) {
				next.ServeHTTP(w, r)
				return
			}

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
//   - useWildcards: if true, uses path.Match for pattern matching; if false, uses exact string matching
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
			matched, _ = stdpath.Match(excludePath, path)
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
				matched, _ = stdpath.Match(includePath, path)
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

// RegisterCORSMiddleware registers a middleware that handles Cross-Origin Resource Sharing (CORS).
// It supports preflight requests, origin validation, method and header restrictions,
// credentials handling, and path-based filtering.
// If CORS is not enabled in the configuration, no middleware is registered.
func RegisterCORSMiddleware(router MiddlewareRouter, opts Options) {
	cfg := opts.CORS
	if !cfg.isActive() {
		return
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
	if !cfg.isActive() {
		return
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
			// Skip compression for WebSocket upgrade requests
			if isWebSocketUpgrade(r) {
				next.ServeHTTP(w, r)
				return
			}

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

			// Build list of enabled encoders.
			enabledEncoders := defaultEncoders
			if len(cfg.EnabledEncodings) > 0 {
				enabledEncoderSet := make(map[string]bool, len(cfg.EnabledEncodings))
				for _, name := range cfg.EnabledEncodings {
					enabledEncoderSet[strings.ToLower(name)] = true
				}
				filtered := make([]*compressionEncoder, 0, len(cfg.EnabledEncodings))
				for _, enc := range defaultEncoders {
					if enabledEncoderSet[enc.name] {
						filtered = append(filtered, enc)
					}
				}
				enabledEncoders = filtered
			}

			// Select best encoding based on Accept-Encoding header.
			encoder := selectEncoder(acceptEncoding, enabledEncoders)
			if encoder == nil {
				// Client doesn't accept any supported encoding.
				next.ServeHTTP(w, r)
				return
			}

			// Create compression response writer
			bufPtr := compressionBufPool.Get().(*[]byte)
			buf := (*bufPtr)[:0]
			crw := &compressionResponseWriter{
				ResponseWriter:    w,
				encoder:           encoder,
				level:             level,
				minSize:           minSize,
				compressibleTypes: compressibleTypes,
				buf:               buf,
				bufPtr:            bufPtr,
			}

			// Ensure cleanup
			defer func() { _ = crw.Close() }()

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
	encoder           *compressionEncoder
	level             int
	minSize           int
	compressibleTypes map[string]bool
	writer            io.WriteCloser
	buf               []byte
	bufPtr            *[]byte
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

// setupCompression initializes the compression writer using the selected encoder.
func (crw *compressionResponseWriter) setupCompression() {
	if crw.writer != nil || crw.compressed {
		return
	}

	// Set compression headers.
	crw.Header().Set("Content-Encoding", crw.encoder.name)
	crw.Header().Set("Vary", "Accept-Encoding")
	crw.Header().Del("Content-Length") // Remove content-length as it will change after compression.

	// Try to get a writer from the per-encoder pool and reset it.
	if w, ok := crw.encoder.pool.Get().(io.WriteCloser); ok {
		reset := false
		switch rw := w.(type) {
		case *gzip.Writer:
			rw.Reset(crw.ResponseWriter)
			reset = true
		case *flate.Writer:
			rw.Reset(crw.ResponseWriter)
			reset = true
		case *brotli.Writer:
			rw.Reset(crw.ResponseWriter)
			reset = true
		case *zstd.Encoder:
			rw.Reset(crw.ResponseWriter)
			reset = true
		}
		if reset {
			crw.writer = w
			return
		}
		// Unknown type — fall through to create a new writer.
		crw.encoder.pool.Put(w)
	}

	// Create a new compression writer.
	w, err := crw.encoder.newWriter(crw.ResponseWriter, crw.level)
	if err != nil {
		crw.compressed = true
		return
	}
	crw.writer = w
}

// Close flushes and closes the compression writer
func (crw *compressionResponseWriter) Close() error {
	// Handle remaining buffered data
	if len(crw.buf) > 0 {
		if crw.writer == nil && !crw.compressed {
			// Check if buffered content is below minimum size
			if len(crw.buf) < crw.minSize {
				// Content too small to compress, write directly without compression
				if _, err := crw.ResponseWriter.Write(crw.buf); err != nil {
					return fmt.Errorf("write uncompressed buffer: %w", err)
				}
				crw.buf = nil
				crw.returnBuf()
				return nil
			}

			// Content is large enough, set up compression and write buffered data
			crw.setupCompression()
			if crw.writer != nil {
				if _, err := crw.writer.Write(crw.buf); err != nil {
					return fmt.Errorf("write compressed buffer: %w", err)
				}
			} else {
				// Compression setup failed, write directly
				if _, err := crw.ResponseWriter.Write(crw.buf); err != nil {
					crw.returnBuf()
					return fmt.Errorf("write buffer after compression setup failed: %w", err)
				}
			}
			crw.buf = nil
		}
	}

	if crw.writer != nil {
		err := crw.writer.Close()
		// Reset the writer to discard and return it to the per-encoder pool.
		switch rw := crw.writer.(type) {
		case *gzip.Writer:
			rw.Reset(io.Discard)
			crw.encoder.pool.Put(rw)
		case *flate.Writer:
			rw.Reset(io.Discard)
			crw.encoder.pool.Put(rw)
		case *brotli.Writer:
			rw.Reset(io.Discard)
			crw.encoder.pool.Put(rw)
		case *zstd.Encoder:
			rw.Reset(io.Discard)
			crw.encoder.pool.Put(rw)
		}
		crw.writer = nil // prevent double-close
		crw.returnBuf()
		return err
	}

	crw.returnBuf()
	return nil
}

func (crw *compressionResponseWriter) returnBuf() {
	if crw.bufPtr != nil {
		*crw.bufPtr = (*crw.bufPtr)[:0]
		compressionBufPool.Put(crw.bufPtr)
		crw.bufPtr = nil
	}
}

// Hijack implements http.Hijacker so WebSocket upgrades work through this wrapper.
func (crw *compressionResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := crw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}

// Flush implements http.Flusher so SSE streaming works through this wrapper.
// If data is still buffered (below minSize threshold), it is flushed as uncompressed
// to avoid delaying SSE events and keep-alive pings.
func (crw *compressionResponseWriter) Flush() {
	// Drain buffered data that hasn't reached the compression threshold.
	// This is critical for SSE: small events must be sent immediately.
	if len(crw.buf) > 0 && crw.writer == nil && !crw.compressed {
		data := crw.buf
		crw.buf = nil
		crw.compressed = true // skip compression for this stream
		_, _ = crw.ResponseWriter.Write(data)
	}
	// Flush the compressor if active.
	type compFlusher interface{ Flush() error }
	if f, ok := crw.writer.(compFlusher); ok {
		_ = f.Flush()
	}
	if fl, ok := crw.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}
