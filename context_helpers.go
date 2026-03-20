package servex

import (
	"context"
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
