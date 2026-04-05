package servex

import (
	"crypto/rand"
	"math"
	mr "math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RequestID returns the request ID for the request.
func (ctx *Context) RequestID() string {
	return getOrSetRequestID(ctx.r)
}

// TraceID returns the W3C trace ID for this request, or an empty string if
// trace propagation is not enabled.
func (ctx *Context) TraceID() string {
	return getValueFromContext[string](ctx.r, traceIDKey{})
}

// SpanID returns the W3C span ID generated for this request, or an empty string if
// trace propagation is not enabled.
func (ctx *Context) SpanID() string {
	return getValueFromContext[string](ctx.r, spanIDKey{})
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

// NoLog marks to not log the request after returning from the handler.
func (ctx *Context) NoLog() {
	ctx.setNoLog()
}

// APIKeyScopes returns the API key scopes stored in the request context.
// Returns nil if the request was not authenticated via an API key.
func (ctx *Context) APIKeyScopes() []string {
	return getValueFromContext[[]string](ctx.r, APIKeyScopesContextKey{})
}

func getOrSetRequestID(r *http.Request) string {
	rIDHeader := r.Header.Get("X-Request-ID")
	if rIDHeader != "" {
		return rIDHeader
	}

	requestID := getValueFromContext[string](r, requestIDKey{})
	if requestID == "" {
		requestID = string(getRandomBytes(12))
		r.Header.Set("X-Request-ID", requestID)
	}

	return requestID
}

var (
	defaultAlphabet = []byte("0123456789abcdef")
	alphabetLen     = uint8(len(defaultAlphabet))
)

func getRandomBytes(n int) []byte {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
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
