package servex

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

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

	// Note: MaxMultipartMemory is handled by ParseMultipartForm in context.go
	// and doesn't need to be enforced here in the middleware

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check general request body size limit when Content-Length is known
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

			// Wrap the body with a size limit for all content types,
			// including chunked-encoding requests where ContentLength is -1
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

			next.ServeHTTP(w, r)
		})
	})
}
