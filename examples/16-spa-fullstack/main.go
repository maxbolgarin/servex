package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

// This example demonstrates a full-stack application: a minimal SPA frontend
// served with fallback routing, a JSON API backend with JWT auth,
// and WebSocket for real-time notifications.
//
// Run:
//
//	go run main.go
//
// Then open http://localhost:8080 in your browser.
//
// The SPA handles client-side routing — refreshing on any path
// returns index.html, while /api/* and /ws/* are handled by the backend.
//
// Test API directly:
//
//	TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
//	  -H "Content-Type: application/json" \
//	  -d '{"username":"demo","password":"demo1234"}' | jq -r .accessToken)
//
//	# Create a note
//	curl -s -X POST http://localhost:8080/api/notes \
//	  -H "Authorization: Bearer $TOKEN" \
//	  -H "Content-Type: application/json" \
//	  -d '{"title":"My Note","content":"Hello world"}' | jq .
//
//	# List notes
//	curl -s http://localhost:8080/api/notes \
//	  -H "Authorization: Bearer $TOKEN" | jq .
func main() {
	store := NewNoteStore()

	server, err := servex.NewServer(servex.MergeWithPreset(
		servex.WebAppPreset(),
		servex.WithSPAMode("frontend", "index.html"),
		servex.WithAuthMemoryDatabase(),
		servex.WithAuthInitialUsers(servex.InitialUser{
			Username: "demo",
			Password: "demo1234",
			Roles:    []servex.UserRole{"user"},
		}),
		servex.WithWebSocketAllowedOrigins("*"),
	)...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Store hub reference for broadcasting notifications
	store.hub = server.WSHub()

	// API routes
	api := server.Group("/api")
	api.GetWithAuth("/notes", store.ListNotes, "user")
	api.PostWithAuth("/notes", store.CreateNote, "user")
	api.DeleteWithAuth("/notes/{id}", store.DeleteNote, "user")

	// WebSocket for real-time notifications
	server.WSWithAuth("/ws/notifications", func(ws *servex.WSConn) {
		// Each user gets their own notification room
		ws.JoinRoom("notifications:" + ws.UserID())
		// Block until the connection closes
		<-ws.Context().Done()
	}, "user")

	fmt.Println("Servex SPA Full-Stack Application")
	fmt.Println("Open: http://localhost:8080")
	fmt.Println()
	fmt.Println("  Login: demo / demo1234")
	fmt.Println()
	fmt.Println("API:")
	fmt.Println("  POST /api/v1/auth/{register,login,refresh,logout}")
	fmt.Println("  GET  /api/notes")
	fmt.Println("  POST /api/notes")
	fmt.Println("  DELETE /api/notes/{id}")
	fmt.Println("  WS   /ws/notifications")
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")

	if err := server.StartWithWaitSignalsHTTP(context.Background(), ":8080"); err != nil {
		log.Fatal(err)
	}
}

// Note represents a note in the system.
type Note struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	OwnerID   string    `json:"owner_id"`
	CreatedAt time.Time `json:"created_at"`
}

// NoteStore is a thread-safe in-memory note store.
type NoteStore struct {
	hub    *servex.WSHub
	mu     sync.RWMutex
	notes  map[string]*Note
	nextID int
}

func NewNoteStore() *NoteStore {
	return &NoteStore{
		notes: make(map[string]*Note),
	}
}

// ListNotes returns all notes belonging to the authenticated user.
func (s *NoteStore) ListNotes(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	userID := r.Context().Value(servex.UserContextKey{}).(string)

	s.mu.RLock()
	var result []*Note
	for _, n := range s.notes {
		if n.OwnerID == userID {
			result = append(result, n)
		}
	}
	s.mu.RUnlock()

	if result == nil {
		result = []*Note{}
	}
	ctx.JSON(result)
}

// CreateNote creates a new note.
func (s *NoteStore) CreateNote(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	userID := r.Context().Value(servex.UserContextKey{}).(string)

	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if err := ctx.ReadJSON(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}
	if req.Title == "" {
		ctx.BadRequest(nil, "title is required")
		return
	}

	s.mu.Lock()
	s.nextID++
	note := &Note{
		ID:        strconv.Itoa(s.nextID),
		Title:     req.Title,
		Content:   req.Content,
		OwnerID:   userID,
		CreatedAt: time.Now().UTC(),
	}
	s.notes[note.ID] = note
	s.mu.Unlock()

	// Notify the user via WebSocket
	s.hub.BroadcastRoom("notifications:"+userID, map[string]any{
		"type": "note_created",
		"note": note,
	})

	ctx.Response(http.StatusCreated, note)
}

// DeleteNote deletes a note belonging to the authenticated user.
func (s *NoteStore) DeleteNote(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	userID := r.Context().Value(servex.UserContextKey{}).(string)
	id := ctx.Path("id")

	s.mu.Lock()
	note, ok := s.notes[id]
	if !ok {
		s.mu.Unlock()
		ctx.NotFound(nil, "note not found")
		return
	}
	if note.OwnerID != userID {
		s.mu.Unlock()
		ctx.Forbidden(nil, "access denied")
		return
	}
	delete(s.notes, id)
	s.mu.Unlock()

	// Notify the user via WebSocket
	s.hub.BroadcastRoom("notifications:"+userID, map[string]any{
		"type":    "note_deleted",
		"note_id": id,
	})

	ctx.Response(http.StatusNoContent)
}
