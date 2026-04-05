package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

// This example demonstrates a multi-room real-time chat application
// with JWT authentication, typing indicators, user presence, and message history.
//
// Run:
//
//	go run main.go
//
// Test:
//
//	# 1. Login to get an access token
//	TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
//	  -H "Content-Type: application/json" \
//	  -d '{"username":"alice","password":"alice123"}' | jq -r .accessToken)
//
//	# 2. Connect via WebSocket (use wscat or similar tool)
//	wscat -H "Authorization: Bearer $TOKEN" \
//	  "ws://localhost:8080/ws/chat?room=general"
//
//	# 3. Send a message:  {"type":"message","content":"Hello everyone!"}
//	# 4. Send typing:     {"type":"typing"}
//
//	# 5. List rooms
//	curl -s http://localhost:8080/api/rooms \
//	  -H "Authorization: Bearer $TOKEN" | jq .
//
//	# 6. Get room history
//	curl -s http://localhost:8080/api/rooms/general/history \
//	  -H "Authorization: Bearer $TOKEN" | jq .
func main() {
	chat := NewChatServer()

	server, err := servex.NewServer(
		servex.WithAuthMemoryDatabase(),
		servex.WithAuthInitialUsers(
			servex.InitialUser{
				Username: "alice",
				Password: "alice123",
				Roles:    []servex.UserRole{"user"},
			},
			servex.InitialUser{
				Username: "bob",
				Password: "bob123",
				Roles:    []servex.UserRole{"user"},
			},
		),
		servex.WithCORS(),
		servex.WithWebSocketAllowedOrigins("*"),
		servex.WithHealthEndpoint(),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Store hub reference for use in handlers
	chat.hub = server.WSHub()

	// WebSocket chat endpoint (requires authentication)
	server.WSWithAuth("/ws/chat", chat.HandleChat, "user")

	// REST endpoints for room info
	server.GetWithAuth("/api/rooms", chat.ListRooms, "user")
	server.GetWithAuth("/api/rooms/{room}/history", chat.RoomHistory, "user")

	fmt.Println("Servex WebSocket Chat Server")
	fmt.Println("Server: http://localhost:8080")
	fmt.Println()
	fmt.Println("Auth endpoints:")
	fmt.Println("  POST /api/v1/auth/register    - Register new user")
	fmt.Println("  POST /api/v1/auth/login       - Login (alice/alice123 or bob/bob123)")
	fmt.Println("  POST /api/v1/auth/refresh     - Refresh token")
	fmt.Println()
	fmt.Println("Chat endpoints:")
	fmt.Println("  WS   /ws/chat?room=general    - WebSocket chat (Bearer auth)")
	fmt.Println("  GET  /api/rooms               - List active rooms")
	fmt.Println("  GET  /api/rooms/{room}/history - Room message history")
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")

	if err := server.StartWithWaitSignalsHTTP(context.Background(), ":8080"); err != nil {
		log.Fatal(err)
	}
}

// ChatMessage is the JSON protocol for WebSocket communication.
type ChatMessage struct {
	Type    string `json:"type"`              // message, typing, join, leave, presence
	Room    string `json:"room,omitempty"`    // room name
	Content string `json:"content,omitempty"` // message text
	User    string `json:"user,omitempty"`    // username
	Time    string `json:"time,omitempty"`    // ISO 8601 timestamp
	Online  int    `json:"online,omitempty"`  // online count (for presence messages)
}

const maxHistory = 50

// ChatServer manages rooms, message history, and user connections.
type ChatServer struct {
	hub *servex.WSHub

	mu      sync.RWMutex
	history map[string][]ChatMessage // room -> last N messages
}

func NewChatServer() *ChatServer {
	return &ChatServer{
		history: make(map[string][]ChatMessage),
	}
}

// HandleChat is the WebSocket handler for chat connections.
func (cs *ChatServer) HandleChat(ws *servex.WSConn) {
	userID := ws.UserID()
	room := ws.Query("room")
	if room == "" {
		room = "general"
	}

	// Join room and notify others
	ws.JoinRoom(room)

	joinMsg := ChatMessage{
		Type: "join",
		Room: room,
		User: userID,
		Time: time.Now().UTC().Format(time.RFC3339),
	}
	cs.addToHistory(room, joinMsg)
	cs.hub.BroadcastRoomExcept(room, ws.ID(), joinMsg)

	// Send message history to the new connection
	cs.mu.RLock()
	msgs := cs.history[room]
	cs.mu.RUnlock()
	for _, m := range msgs {
		ws.WriteJSON(m)
	}

	// Broadcast updated presence
	cs.broadcastPresence(room)

	// Read loop — runs until the client disconnects or an error occurs
	for {
		var msg ChatMessage
		if err := ws.ReadJSON(&msg); err != nil {
			break
		}
		msg.Room = room
		msg.User = userID
		msg.Time = time.Now().UTC().Format(time.RFC3339)

		switch msg.Type {
		case "message":
			cs.addToHistory(room, msg)
			cs.hub.BroadcastRoom(room, msg)
		case "typing":
			cs.hub.BroadcastRoomExcept(room, ws.ID(), msg)
		}
	}

	// Cleanup on disconnect
	ws.LeaveRoom(room)

	leaveMsg := ChatMessage{
		Type: "leave",
		Room: room,
		User: userID,
		Time: time.Now().UTC().Format(time.RFC3339),
	}
	cs.addToHistory(room, leaveMsg)
	cs.hub.BroadcastRoom(room, leaveMsg)
	cs.broadcastPresence(room)
}

// ListRooms returns all known rooms with message counts.
func (cs *ChatServer) ListRooms(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)

	cs.mu.RLock()
	defer cs.mu.RUnlock()

	type roomInfo struct {
		Name     string `json:"name"`
		Online   int    `json:"online"`
		Messages int    `json:"messages"`
	}

	rooms := make([]roomInfo, 0, len(cs.history))
	for name, msgs := range cs.history {
		rooms = append(rooms, roomInfo{
			Name:     name,
			Online:   cs.hub.RoomCount(name),
			Messages: len(msgs),
		})
	}

	ctx.JSON(rooms)
}

// RoomHistory returns the message history for a specific room.
func (cs *ChatServer) RoomHistory(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	room := ctx.Path("room")

	cs.mu.RLock()
	msgs := cs.history[room]
	cs.mu.RUnlock()

	if msgs == nil {
		msgs = []ChatMessage{}
	}
	ctx.JSON(msgs)
}

func (cs *ChatServer) addToHistory(room string, msg ChatMessage) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.history[room] = append(cs.history[room], msg)
	if len(cs.history[room]) > maxHistory {
		cs.history[room] = cs.history[room][len(cs.history[room])-maxHistory:]
	}
}

func (cs *ChatServer) broadcastPresence(room string) {
	cs.hub.BroadcastRoom(room, ChatMessage{
		Type:   "presence",
		Room:   room,
		Online: cs.hub.RoomCount(room),
		Time:   time.Now().UTC().Format(time.RFC3339),
	})
}
