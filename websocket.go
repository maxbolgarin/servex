package servex

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/gorilla/mux"
)

// MessageType represents the type of a WebSocket message.
// Re-exported from coder/websocket so users do not need to import the underlying library.
type MessageType = websocket.MessageType

const (
	// MessageText is a text WebSocket message (UTF-8 encoded).
	MessageText MessageType = websocket.MessageText
	// MessageBinary is a binary WebSocket message.
	MessageBinary MessageType = websocket.MessageBinary
)

// StatusCode represents a WebSocket close status code.
// Re-exported from coder/websocket for convenience.
type StatusCode = websocket.StatusCode

// Common WebSocket close status codes.
const (
	StatusNormalClosure   StatusCode = websocket.StatusNormalClosure
	StatusGoingAway       StatusCode = websocket.StatusGoingAway
	StatusProtocolError   StatusCode = websocket.StatusProtocolError
	StatusPolicyViolation StatusCode = websocket.StatusPolicyViolation
	StatusMessageTooBig   StatusCode = websocket.StatusMessageTooBig
	StatusInternalError   StatusCode = websocket.StatusInternalError
)

// WSHandler is a function that handles a WebSocket connection.
// It is called after a successful HTTP-to-WebSocket upgrade.
// The function should run for the lifetime of the connection;
// when it returns, the connection is closed gracefully.
type WSHandler func(ws *WSConn)

// WSConn wraps a WebSocket connection with typed read/write helpers,
// room management, and access to the original HTTP request metadata.
type WSConn struct {
	conn   *websocket.Conn
	r      *http.Request
	id     string
	hub    *WSHub
	cfg    WebSocketConfig
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex // serialises writes

	closeOnce sync.Once // guards connection close to prevent double-close

	metrics *builtinMetrics // optional, for recording WS metrics
}

// --- Low-level read/write ---

// Read reads the next WebSocket message. It blocks until a message is received.
func (ws *WSConn) Read() (MessageType, []byte, error) {
	typ, data, err := ws.conn.Read(ws.ctx)
	if err != nil {
		if ws.metrics != nil && !IsCloseError(err) {
			ws.metrics.wsError()
		}
		return typ, nil, err
	}
	if ws.metrics != nil {
		ws.metrics.wsMsgRecv()
	}
	return typ, data, nil
}

// Write writes a WebSocket message. It is safe for concurrent use.
func (ws *WSConn) Write(typ MessageType, data []byte) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	err := ws.conn.Write(ws.ctx, typ, data)
	if err != nil {
		if ws.metrics != nil && !IsCloseError(err) {
			ws.metrics.wsError()
		}
		return err
	}
	if ws.metrics != nil {
		ws.metrics.wsMsgSent()
	}
	return nil
}

// --- Typed helpers ---

// ReadJSON reads the next WebSocket message and unmarshals it as JSON.
func (ws *WSConn) ReadJSON(v any) error {
	_, data, err := ws.Read()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// WriteJSON marshals v as JSON and writes it as a text WebSocket message.
// It is safe for concurrent use.
func (ws *WSConn) WriteJSON(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("websocket: marshal json: %w", err)
	}
	return ws.Write(MessageText, data)
}

// ReadText reads the next text WebSocket message.
func (ws *WSConn) ReadText() (string, error) {
	typ, data, err := ws.Read()
	if err != nil {
		return "", err
	}
	if typ != MessageText {
		return "", fmt.Errorf("websocket: expected text message, got binary")
	}
	return string(data), nil
}

// WriteText writes a text WebSocket message. It is safe for concurrent use.
func (ws *WSConn) WriteText(s string) error {
	return ws.Write(MessageText, []byte(s))
}

// --- Request metadata ---

// Path returns a path parameter from the upgrade request (gorilla/mux).
func (ws *WSConn) Path(key string) string {
	return mux.Vars(ws.r)[key]
}

// Query returns a URL query parameter from the upgrade request.
func (ws *WSConn) Query(key string) string {
	return ws.r.URL.Query().Get(key)
}

// Header returns a header value from the upgrade request.
func (ws *WSConn) Header(key string) string {
	return ws.r.Header.Get(key)
}

// UserID returns the authenticated user ID from the upgrade request context.
// Returns an empty string if the request was not authenticated.
func (ws *WSConn) UserID() string {
	return getValueFromContext[string](ws.r, UserContextKey{})
}

// UserRoles returns the authenticated user's roles from the upgrade request context.
// Returns nil if the request was not authenticated.
func (ws *WSConn) UserRoles() []UserRole {
	return getValueFromContext[[]UserRole](ws.r, RoleContextKey{})
}

// ClientIP returns the client's IP address from the upgrade request.
func (ws *WSConn) ClientIP() string {
	return extractClientIP(ws.r)
}

// RequestID returns the request ID from the upgrade request.
func (ws *WSConn) RequestID() string {
	return getOrSetRequestID(ws.r)
}

// --- Connection lifecycle ---

// ID returns the unique connection identifier.
func (ws *WSConn) ID() string {
	return ws.id
}

// Context returns the connection's context, derived from the upgrade request context.
// The context is cancelled when the connection is closed.
func (ws *WSConn) Context() context.Context {
	return ws.ctx
}

// Close performs a graceful WebSocket close with the given status code and reason.
// It routes through closeOnce to prevent double-close races with shutdown.
func (ws *WSConn) Close(code StatusCode, reason string) error {
	ws.cancel()
	var err error
	ws.closeOnce.Do(func() {
		err = ws.conn.Close(code, reason)
	})
	return err
}

// CloseNow immediately closes the WebSocket connection without sending a close frame.
// It routes through closeOnce to prevent double-close races with shutdown.
func (ws *WSConn) CloseNow() error {
	ws.cancel()
	var err error
	ws.closeOnce.Do(func() {
		err = ws.conn.CloseNow()
	})
	return err
}

// shutdown cancels the context and force-closes the connection exactly once.
// Safe to call multiple times — subsequent calls are no-ops.
func (ws *WSConn) shutdown() {
	ws.closeOnce.Do(func() {
		ws.cancel()
		ws.conn.CloseNow()
	})
}

// --- Room operations ---

// JoinRoom adds this connection to a room in the hub.
// No-op if the connection is already shutting down.
func (ws *WSConn) JoinRoom(room string) {
	if ws.ctx.Err() != nil {
		return
	}
	ws.hub.joinRoom(ws.id, room)
}

// LeaveRoom removes this connection from a room in the hub.
func (ws *WSConn) LeaveRoom(room string) {
	ws.hub.leaveRoom(ws.id, room)
}

// Rooms returns the list of rooms this connection has joined.
func (ws *WSConn) Rooms() []string {
	return ws.hub.connRooms(ws.id)
}

// --- Ping/pong ---

func (ws *WSConn) pingLoop() {
	interval := ws.cfg.PingInterval
	if interval <= 0 {
		interval = defaultWSPingInterval
	}
	pongTimeout := ws.cfg.PongTimeout
	if pongTimeout <= 0 {
		pongTimeout = defaultWSPongTimeout
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ws.ctx.Done():
			return
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ws.ctx, pongTimeout)
			err := ws.conn.Ping(pingCtx)
			cancel()
			if err != nil {
				ws.shutdown()
				return
			}
		}
	}
}

// --- WSHub ---

// WSHub manages all active WebSocket connections and room membership.
// It is safe for concurrent use. Access via server.WSHub().
type WSHub struct {
	mu    sync.RWMutex
	conns map[string]*WSConn            // connID -> conn
	rooms map[string]map[string]*WSConn // room -> connID -> conn
}

func newWSHub() *WSHub {
	return &WSHub{
		conns: make(map[string]*WSConn),
		rooms: make(map[string]map[string]*WSConn),
	}
}

func (h *WSHub) register(ws *WSConn) {
	h.mu.Lock()
	h.conns[ws.id] = ws
	h.mu.Unlock()
}

func (h *WSHub) unregister(connID string) {
	h.mu.Lock()
	delete(h.conns, connID)
	h.mu.Unlock()
}

func (h *WSHub) joinRoom(connID, room string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ws, ok := h.conns[connID]
	if !ok {
		return
	}
	if h.rooms[room] == nil {
		h.rooms[room] = make(map[string]*WSConn)
	}
	h.rooms[room][connID] = ws
}

func (h *WSHub) leaveRoom(connID, room string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if members, ok := h.rooms[room]; ok {
		delete(members, connID)
		if len(members) == 0 {
			delete(h.rooms, room)
		}
	}
}

func (h *WSHub) leaveAllRooms(connID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for room, members := range h.rooms {
		delete(members, connID)
		if len(members) == 0 {
			delete(h.rooms, room)
		}
	}
}

// connRooms returns the list of rooms a connection has joined.
func (h *WSHub) connRooms(connID string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var result []string
	for room, members := range h.rooms {
		if _, ok := members[connID]; ok {
			result = append(result, room)
		}
	}
	sort.Strings(result)
	return result
}

// BroadcastAll sends a JSON message to all connected WebSocket clients.
func (h *WSHub) BroadcastAll(msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("websocket: marshal json: %w", err)
	}

	h.mu.RLock()
	conns := make([]*WSConn, 0, len(h.conns))
	for _, ws := range h.conns {
		conns = append(conns, ws)
	}
	h.mu.RUnlock()

	var firstErr error
	for _, ws := range conns {
		if err := ws.Write(MessageText, data); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// BroadcastRoom sends a JSON message to all connections in the specified room.
func (h *WSHub) BroadcastRoom(room string, msg any) error {
	return h.broadcastRoom(room, "", msg)
}

// BroadcastRoomExcept sends a JSON message to all connections in the room
// except the connection with the given ID.
func (h *WSHub) BroadcastRoomExcept(room, excludeConnID string, msg any) error {
	return h.broadcastRoom(room, excludeConnID, msg)
}

func (h *WSHub) broadcastRoom(room, excludeID string, msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("websocket: marshal json: %w", err)
	}

	h.mu.RLock()
	members := h.rooms[room]
	conns := make([]*WSConn, 0, len(members))
	for id, ws := range members {
		if id != excludeID {
			conns = append(conns, ws)
		}
	}
	h.mu.RUnlock()

	var firstErr error
	for _, ws := range conns {
		if err := ws.Write(MessageText, data); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Send sends a JSON message to a specific connection by ID.
func (h *WSHub) Send(connID string, msg any) error {
	h.mu.RLock()
	ws, ok := h.conns[connID]
	h.mu.RUnlock()
	if !ok {
		return fmt.Errorf("websocket: connection %s not found", connID)
	}
	return ws.WriteJSON(msg)
}

// ConnCount returns the total number of active WebSocket connections.
func (h *WSHub) ConnCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.conns)
}

// RoomCount returns the number of connections in the specified room.
func (h *WSHub) RoomCount(room string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.rooms[room])
}

// Rooms returns the names of all active rooms.
func (h *WSHub) Rooms() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	result := make([]string, 0, len(h.rooms))
	for room := range h.rooms {
		result = append(result, room)
	}
	sort.Strings(result)
	return result
}

// CloseAll closes all active WebSocket connections with the given status code and reason.
func (h *WSHub) CloseAll(code StatusCode, reason string) {
	h.mu.Lock()
	conns := make([]*WSConn, 0, len(h.conns))
	for _, ws := range h.conns {
		conns = append(conns, ws)
	}
	h.conns = make(map[string]*WSConn)
	h.rooms = make(map[string]map[string]*WSConn)
	h.mu.Unlock()

	for _, ws := range conns {
		_ = ws.Close(code, reason)
	}
}

// IsCloseError returns true if the error indicates a normal WebSocket closure
// (StatusNormalClosure or StatusGoingAway).
func IsCloseError(err error) bool {
	status := websocket.CloseStatus(err)
	return status == websocket.StatusNormalClosure || status == websocket.StatusGoingAway
}

// isWebSocketUpgrade returns true if the request is a WebSocket upgrade request.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// generateWSConnID generates a 128-bit hex-encoded connection ID.
func generateWSConnID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// --- Server integration ---

// getBuiltinMetrics extracts the builtinMetrics from the server's metrics, if any.
func (s *Server) getBuiltinMetrics() *builtinMetrics {
	if m, ok := s.opts.Metrics.(*builtinMetrics); ok {
		return m
	}
	if c, ok := s.opts.Metrics.(*compositeMetrics); ok {
		return c.getBuiltinMetrics()
	}
	return nil
}

func (s *Server) initWSHub() {
	s.wsOnce.Do(func() {
		s.wsHub = newWSHub()
	})
}

// WSHub returns the WebSocket connection hub for broadcasting and room management.
// Calling this method lazily initializes WebSocket support if not already active.
func (s *Server) WSHub() *WSHub {
	s.initWSHub()
	return s.wsHub
}

// WS registers a WebSocket route at the given path.
// The handler is called in a new goroutine after a successful HTTP-to-WebSocket upgrade.
//
// Example:
//
//	server.WS("/ws/echo", func(ws *servex.WSConn) {
//		for {
//			typ, data, err := ws.Read()
//			if err != nil {
//				return
//			}
//			ws.Write(typ, data)
//		}
//	})
func (s *Server) WS(path string, handler WSHandler) *mux.Route {
	s.initWSHub()
	return s.HandleFunc(path, s.wsUpgradeHandler(handler), "GET")
}

// WSWithAuth registers a WebSocket route with authentication.
// Auth middleware validates the upgrade request before upgrading.
// If roles are provided, the user must have at least one of the specified roles.
//
// Example:
//
//	server.WSWithAuth("/ws/admin", func(ws *servex.WSConn) {
//		userID := ws.UserID()
//		// handle admin WebSocket connection
//	}, "admin")
func (s *Server) WSWithAuth(path string, handler WSHandler, roles ...UserRole) *mux.Route {
	s.initWSHub()
	return s.HandleFuncWithAuth(path, s.wsUpgradeHandler(handler), roles...)
}

func (s *Server) wsUpgradeHandler(handler WSHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := s.opts.WebSocket

		// Build accept options
		acceptOpts := &websocket.AcceptOptions{
			CompressionMode: websocket.CompressionDisabled,
		}
		if cfg.EnableCompression {
			acceptOpts.CompressionMode = websocket.CompressionContextTakeover
		}
		// If we have custom AllowedOrigins, let coder/websocket know.
		// If AllowedOrigins contains "*", skip origin check entirely.
		if len(cfg.AllowedOrigins) > 0 {
			for _, o := range cfg.AllowedOrigins {
				if o == "*" {
					acceptOpts.InsecureSkipVerify = true
					break
				}
			}
			if !acceptOpts.InsecureSkipVerify {
				acceptOpts.OriginPatterns = cfg.AllowedOrigins
			}
		}

		// Upgrade
		conn, err := websocket.Accept(w, r, acceptOpts)
		if err != nil {
			if s.opts.Logger != nil {
				s.opts.Logger.Error("websocket upgrade failed", "error", err, "path", r.URL.Path)
			}
			if bm := s.getBuiltinMetrics(); bm != nil {
				bm.wsError()
			}
			return // websocket.Accept already wrote the HTTP error
		}

		// Set read limit
		maxMsg := cfg.MaxMessageSize
		if maxMsg <= 0 {
			maxMsg = defaultWSMaxMessageSize
		}
		conn.SetReadLimit(maxMsg)

		// Create WSConn with 128-bit random ID
		ctx, cancel := context.WithCancel(r.Context())
		ws := &WSConn{
			conn:    conn,
			r:       r,
			id:      generateWSConnID(),
			hub:     s.wsHub,
			cfg:     cfg,
			ctx:     ctx,
			cancel:  cancel,
			metrics: s.getBuiltinMetrics(),
		}

		// Register with hub and record metrics
		s.wsHub.register(ws)
		if ws.metrics != nil {
			ws.metrics.wsConnect()
		}

		// Ensure cleanup runs even if handler panics
		defer func() {
			s.wsHub.leaveAllRooms(ws.id)
			s.wsHub.unregister(ws.id)
			ws.shutdown() // cancel ctx + close conn (once)
			if ws.metrics != nil {
				ws.metrics.wsDisconnect()
			}
		}()

		// Start ping/pong if configured (default is enabled)
		var pingWg sync.WaitGroup
		pingInterval := cfg.PingInterval
		if pingInterval == 0 {
			pingInterval = defaultWSPingInterval
		}
		if pingInterval > 0 {
			pingWg.Add(1)
			go func() {
				defer pingWg.Done()
				ws.pingLoop()
			}()
		}

		// Call user handler (blocks until connection done)
		handler(ws)

		// Wait for ping goroutine to exit before cleanup runs
		pingWg.Wait()
	}
}
