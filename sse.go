package servex

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
)

// SSEHandler is a function that handles a Server-Sent Events connection.
// It is called after the SSE response headers are written.
// The function should run for the lifetime of the connection;
// when it returns, the connection is closed.
type SSEHandler func(sse *SSEConn)

// SSEConn wraps an HTTP response for Server-Sent Events streaming.
// It provides methods for sending events, setting event types, and
// accessing the original HTTP request metadata.
type SSEConn struct {
	w  http.ResponseWriter
	fl http.Flusher
	r  *http.Request
	mu sync.Mutex // serialises writes
}

// Send sends a data-only SSE event.
// Multiple calls to Send will send multiple events.
// It is safe for concurrent use.
func (sse *SSEConn) Send(data string) error {
	sse.mu.Lock()
	defer sse.mu.Unlock()
	if _, err := fmt.Fprintf(sse.w, "data: %s\n\n", data); err != nil {
		return err
	}
	sse.fl.Flush()
	return nil
}

// SendEvent sends a named SSE event with the given event type and data.
// It is safe for concurrent use.
func (sse *SSEConn) SendEvent(event, data string) error {
	sse.mu.Lock()
	defer sse.mu.Unlock()
	if _, err := fmt.Fprintf(sse.w, "event: %s\ndata: %s\n\n", event, data); err != nil {
		return err
	}
	sse.fl.Flush()
	return nil
}

// SendEventWithID sends a named SSE event with an ID.
// Clients use the ID to resume from the last received event via the Last-Event-ID header.
// It is safe for concurrent use.
func (sse *SSEConn) SendEventWithID(id, event, data string) error {
	sse.mu.Lock()
	defer sse.mu.Unlock()
	if _, err := fmt.Fprintf(sse.w, "id: %s\nevent: %s\ndata: %s\n\n", id, event, data); err != nil {
		return err
	}
	sse.fl.Flush()
	return nil
}

// SendJSON marshals v as JSON and sends it as a data-only SSE event.
// It is safe for concurrent use.
func (sse *SSEConn) SendJSON(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("sse: marshal json: %w", err)
	}
	return sse.Send(string(data))
}

// SendEventJSON marshals v as JSON and sends it as a named SSE event.
// It is safe for concurrent use.
func (sse *SSEConn) SendEventJSON(event string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("sse: marshal json: %w", err)
	}
	return sse.SendEvent(event, string(data))
}

// SendComment sends a comment line (prefixed with ':'). Comments are ignored by clients
// but can be used as keep-alive pings to prevent connection timeouts.
// It is safe for concurrent use.
func (sse *SSEConn) SendComment(comment string) error {
	sse.mu.Lock()
	defer sse.mu.Unlock()
	if _, err := fmt.Fprintf(sse.w, ": %s\n\n", comment); err != nil {
		return err
	}
	sse.fl.Flush()
	return nil
}

// SetRetry sends a retry directive telling the client how many milliseconds
// to wait before reconnecting after a disconnection.
// It is safe for concurrent use.
func (sse *SSEConn) SetRetry(ms int) error {
	sse.mu.Lock()
	defer sse.mu.Unlock()
	if _, err := fmt.Fprintf(sse.w, "retry: %d\n\n", ms); err != nil {
		return err
	}
	sse.fl.Flush()
	return nil
}

// --- Request metadata ---

// Path returns a path parameter from the request (gorilla/mux).
func (sse *SSEConn) Path(key string) string {
	return mux.Vars(sse.r)[key]
}

// Query returns a URL query parameter from the request.
func (sse *SSEConn) Query(key string) string {
	return sse.r.URL.Query().Get(key)
}

// Header returns a header value from the request.
func (sse *SSEConn) Header(key string) string {
	return sse.r.Header.Get(key)
}

// LastEventID returns the Last-Event-ID header from the request.
// Clients send this when reconnecting to resume from the last received event.
func (sse *SSEConn) LastEventID() string {
	return sse.r.Header.Get("Last-Event-ID")
}

// UserID returns the authenticated user ID from the request context.
// Returns an empty string if the request was not authenticated.
func (sse *SSEConn) UserID() string {
	return getValueFromContext[string](sse.r, UserContextKey{})
}

// UserRoles returns the authenticated user's roles from the request context.
// Returns nil if the request was not authenticated.
func (sse *SSEConn) UserRoles() []UserRole {
	return getValueFromContext[[]UserRole](sse.r, RoleContextKey{})
}

// ClientIP returns the client's IP address from the request.
func (sse *SSEConn) ClientIP() string {
	return extractClientIP(sse.r)
}

// Request returns the original HTTP request.
func (sse *SSEConn) Request() *http.Request {
	return sse.r
}

// Done returns a channel that is closed when the client disconnects.
// Use this to detect when the client has gone away.
func (sse *SSEConn) Done() <-chan struct{} {
	return sse.r.Context().Done()
}

// --- Server integration ---

// SSE registers a Server-Sent Events route at the given path.
// The handler is called after SSE response headers are written.
// The handler should block until the connection is done (client disconnects).
//
// Example:
//
//	server.SSE("/events", func(sse *servex.SSEConn) {
//		for {
//			select {
//			case msg := <-updates:
//				if err := sse.SendJSON(msg); err != nil {
//					return
//				}
//			case <-sse.Done():
//				return
//			}
//		}
//	})
func (s *Server) SSE(path string, handler SSEHandler) *mux.Route {
	return s.HandleFunc(path, s.sseHandler(handler), GET)
}

// SSEWithAuth registers a Server-Sent Events route with authentication.
// Auth middleware validates the request before starting the SSE stream.
func (s *Server) SSEWithAuth(path string, handler SSEHandler, roles ...UserRole) *mux.Route {
	return s.HandleFunc(path, s.WithAuth(s.sseHandler(handler), roles...), GET)
}

func (s *Server) sseHandler(handler SSEHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		// Set SSE headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering
		w.WriteHeader(http.StatusOK)
		fl.Flush()

		sse := &SSEConn{
			w:  w,
			fl: fl,
			r:  r,
		}

		// Call user handler (blocks until connection done)
		handler(sse)
	}
}
