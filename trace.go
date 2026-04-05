package servex

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
)

// RegisterTracePropagationMiddleware adds W3C Trace Context (traceparent/tracestate)
// middleware to the router. It parses incoming traceparent headers, generates a new
// span ID per request, stores trace/span IDs in the request context, and sets
// traceparent/tracestate response headers for downstream propagation.
//
// Trace context follows the W3C Trace Context specification (https://www.w3.org/TR/trace-context/).
// The traceparent header format is: 00-{trace-id}-{parent-id}-{flags}
func RegisterTracePropagationMiddleware(router MiddlewareRouter) {
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tc, ok := parseTraceparent(r.Header.Get("traceparent"))
			if !ok {
				tc.TraceID = generateTraceID()
				tc.Sampled = true
			}
			tc.SpanID = generateSpanID()

			// Store in request context
			ctx := r.Context()
			ctx = context.WithValue(ctx, traceIDKey{}, tc.TraceID)
			ctx = context.WithValue(ctx, spanIDKey{}, tc.SpanID)
			r = r.WithContext(ctx)

			// Skip response headers for WebSocket upgrade requests — the upgrade
			// response is controlled by the WebSocket library and extra headers
			// may violate the protocol.
			if !isWebSocketUpgrade(r) {
				flags := "00"
				if tc.Sampled {
					flags = "01"
				}
				w.Header().Set("traceparent", "00-"+tc.TraceID+"-"+tc.SpanID+"-"+flags)
				if ts := r.Header.Get("tracestate"); ts != "" {
					w.Header().Set("tracestate", ts)
				}
			}

			next.ServeHTTP(w, r)
		})
	})
}


// traceContext holds parsed W3C trace context.
type traceContext struct {
	TraceID string // 32 hex chars (128 bits)
	SpanID  string // 16 hex chars (64 bits)
	Sampled bool
}

// parseTraceparent parses a W3C traceparent header.
// Format: {version}-{trace-id}-{parent-id}-{flags}
// Returns zero traceContext and false if the header is absent or malformed.
func parseTraceparent(header string) (traceContext, bool) {
	if header == "" {
		return traceContext{}, false
	}

	parts := strings.Split(header, "-")
	// Version "00" requires exactly 4 fields. Future versions (01+) may append
	// additional fields per W3C Trace Context spec §4.2 (forward compatibility).
	if len(parts) < 4 {
		return traceContext{}, false
	}

	version := parts[0]
	traceID := parts[1]
	parentID := parts[2]
	flags := parts[3]

	// Validate version: must be 2 hex chars, "ff" is invalid per spec.
	// Accept future versions per W3C spec §4.2 (forward compatibility).
	if len(version) != 2 || !isValidHex(version) || version == "ff" {
		return traceContext{}, false
	}

	// Version "00" must have exactly 4 fields — extra fields are invalid.
	if version == "00" && len(parts) != 4 {
		return traceContext{}, false
	}

	// Validate trace-id: 32 hex chars, not all zeros
	if len(traceID) != 32 || !isValidHex(traceID) || isAllZeros(traceID) {
		return traceContext{}, false
	}

	// Validate parent-id: 16 hex chars, not all zeros
	if len(parentID) != 16 || !isValidHex(parentID) || isAllZeros(parentID) {
		return traceContext{}, false
	}

	// Parse flags byte (bit 0 = sampled)
	if len(flags) != 2 || !isValidHex(flags) {
		return traceContext{}, false
	}
	flagByte, _ := strconv.ParseUint(flags, 16, 8)
	sampled := flagByte&0x01 != 0

	return traceContext{
		TraceID: traceID,
		SpanID:  parentID, // Incoming parent-id becomes our reference
		Sampled: sampled,
	}, true
}

// generateTraceID generates a cryptographically random 128-bit trace ID as 32 hex chars.
func generateTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// generateSpanID generates a cryptographically random 64-bit span ID as 16 hex chars.
func generateSpanID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func isValidHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isAllZeros(s string) bool {
	for _, c := range s {
		if c != '0' {
			return false
		}
	}
	return true
}
