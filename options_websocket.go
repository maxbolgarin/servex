package servex

import "time"

// WebSocketConfig holds configuration for WebSocket connections.
// WebSocket support is activated lazily when server.WS() or server.WSHub() is called.
// These options just set parameters — there is no Enabled flag.
//
// Example:
//
//	server, _ := servex.NewServer(
//		servex.WithWebSocketMaxMessageSize(64 << 10),
//		servex.WithWebSocketPingInterval(20 * time.Second),
//	)
//	server.WS("/ws/echo", echoHandler) // WebSocket is now active
type WebSocketConfig struct {
	// MaxMessageSize is the maximum size of a single WebSocket message in bytes.
	// Messages exceeding this limit cause the connection to close with StatusMessageTooBig.
	//
	// Default: 32768 (32 KB)
	MaxMessageSize int64

	// PingInterval is how often the server sends ping frames to clients.
	// Set to negative value to disable server-initiated pings.
	//
	// Default: 30s
	PingInterval time.Duration

	// PongTimeout is how long to wait for a pong response before closing the connection.
	// Must be less than PingInterval when both are set.
	//
	// Default: 10s
	PongTimeout time.Duration

	// AllowedOrigins controls which origins may connect via WebSocket.
	// Checked during the HTTP upgrade handshake. If empty, all origins are allowed.
	AllowedOrigins []string

	// EnableCompression enables per-message deflate compression (RFC 7692).
	//
	// Default: false
	EnableCompression bool
}

// WebSocket defaults.
const (
	defaultWSMaxMessageSize = 32 << 10 // 32 KB
	defaultWSPingInterval   = 30 * time.Second
	defaultWSPongTimeout    = 10 * time.Second
)

// WithWebSocketConfig sets the full WebSocket configuration.
func WithWebSocketConfig(cfg WebSocketConfig) Option {
	return func(o *Options) {
		o.WebSocket = cfg
	}
}

// WithWebSocketMaxMessageSize sets the maximum size of a single WebSocket message.
func WithWebSocketMaxMessageSize(size int64) Option {
	return func(o *Options) {
		o.WebSocket.MaxMessageSize = size
	}
}

// WithWebSocketPingInterval sets how often the server sends ping frames.
// Set to negative value to disable server-initiated pings.
func WithWebSocketPingInterval(d time.Duration) Option {
	return func(o *Options) {
		o.WebSocket.PingInterval = d
	}
}

// WithWebSocketPongTimeout sets how long to wait for a pong response.
func WithWebSocketPongTimeout(d time.Duration) Option {
	return func(o *Options) {
		o.WebSocket.PongTimeout = d
	}
}

// WithWebSocketAllowedOrigins sets which origins may connect via WebSocket.
func WithWebSocketAllowedOrigins(origins ...string) Option {
	return func(o *Options) {
		o.WebSocket.AllowedOrigins = origins
	}
}

// WithWebSocketCompression enables per-message deflate compression (RFC 7692).
func WithWebSocketCompression() Option {
	return func(o *Options) {
		o.WebSocket.EnableCompression = true
	}
}
