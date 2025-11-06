package servex

import (
	"context"
	"net/http"

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
