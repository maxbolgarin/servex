package servex

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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

			noLog := GetFromContext[bool](r, noLogKey{})
			if noLog {
				return
			}

			logBundle := RequestLogBundle{
				Request:           r,
				RequestID:         getOrSetRequestID(r),
				StartTime:         start,
				NoLogClientErrors: GetFromContext[bool](r, noLogClientErrorsKey{}),
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
				logBundle.Error = GetFromContext[error](r, errorKey{})
				logBundle.ErrorMessage = GetFromContext[string](r, msgKey{})
				logBundle.StatusCode = GetFromContext[int](r, codeKey{})
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
