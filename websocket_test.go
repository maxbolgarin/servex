package servex

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/gorilla/mux"
)

func newTestWSServer(t *testing.T, opts ...Option) (*Server, *httptest.Server) {
	t.Helper()
	server, err := NewServer(opts...)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(server.router)
	t.Cleanup(ts.Close)
	return server, ts
}

func dialWS(t *testing.T, ts *httptest.Server, path string) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(ts.URL, "http") + path
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("websocket.Dial: %v", err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}

func TestWSEchoText(t *testing.T) {
	srv, ts := newTestWSServer(t, WithWebSocketPingInterval(-1))

	srv.WS("/ws/echo", func(ws *WSConn) {
		for {
			typ, data, err := ws.Read()
			if err != nil {
				return
			}
			if err := ws.Write(typ, data); err != nil {
				return
			}
		}
	})

	conn := dialWS(t, ts, "/ws/echo")
	ctx := context.Background()

	// Send and receive text
	msg := "hello websocket"
	if err := conn.Write(ctx, MessageText, []byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}

	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if typ != MessageText {
		t.Errorf("expected text message, got %v", typ)
	}
	if string(data) != msg {
		t.Errorf("expected %q, got %q", msg, string(data))
	}
}

func TestWSEchoBinary(t *testing.T) {
	srv, ts := newTestWSServer(t, WithWebSocketPingInterval(-1))

	srv.WS("/ws/echo-bin", func(ws *WSConn) {
		for {
			typ, data, err := ws.Read()
			if err != nil {
				return
			}
			if err := ws.Write(typ, data); err != nil {
				return
			}
		}
	})

	conn := dialWS(t, ts, "/ws/echo-bin")
	ctx := context.Background()

	payload := []byte{0x00, 0x01, 0x02, 0xFF}
	if err := conn.Write(ctx, MessageBinary, payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if typ != MessageBinary {
		t.Errorf("expected binary message, got %v", typ)
	}
	if string(data) != string(payload) {
		t.Errorf("expected %v, got %v", payload, data)
	}
}

func TestWSJSON(t *testing.T) {
	type TestMsg struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	srv, ts := newTestWSServer(t, WithWebSocketPingInterval(-1))

	srv.WS("/ws/json", func(ws *WSConn) {
		var msg TestMsg
		if err := ws.ReadJSON(&msg); err != nil {
			return
		}
		msg.Value *= 2
		if err := ws.WriteJSON(msg); err != nil {
			return
		}
	})

	conn := dialWS(t, ts, "/ws/json")
	ctx := context.Background()

	// Send JSON
	input := TestMsg{Name: "test", Value: 21}
	data, _ := json.Marshal(input)
	if err := conn.Write(ctx, MessageText, data); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read JSON response
	_, respData, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp TestMsg
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Name != "test" || resp.Value != 42 {
		t.Errorf("expected {test, 42}, got %+v", resp)
	}
}

func TestWSReadText(t *testing.T) {
	srv, ts := newTestWSServer(t, WithWebSocketPingInterval(-1))

	srv.WS("/ws/text", func(ws *WSConn) {
		text, err := ws.ReadText()
		if err != nil {
			return
		}
		if err := ws.WriteText("echo: " + text); err != nil {
			return
		}
	})

	conn := dialWS(t, ts, "/ws/text")
	ctx := context.Background()

	if err := conn.Write(ctx, MessageText, []byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "echo: hello" {
		t.Errorf("expected 'echo: hello', got %q", string(data))
	}
}

func TestWSPathAndQuery(t *testing.T) {
	srv, ts := newTestWSServer(t, WithWebSocketPingInterval(-1))

	srv.WS("/ws/room/{room_id}", func(ws *WSConn) {
		roomID := ws.Path("room_id")
		name := ws.Query("name")
		if err := ws.WriteText(roomID + ":" + name); err != nil {
			return
		}
	})

	url := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws/room/abc?name=alice"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "abc:alice" {
		t.Errorf("expected 'abc:alice', got %q", string(data))
	}
}

func TestWSHubBroadcastRoom(t *testing.T) {
	srv, ts := newTestWSServer(t, WithWebSocketPingInterval(-1))

	ready := make(chan struct{})
	var readyCount int
	var readyMu sync.Mutex

	srv.WS("/ws/chat/{room}", func(ws *WSConn) {
		room := ws.Path("room")
		ws.JoinRoom(room)
		defer ws.LeaveRoom(room)

		readyMu.Lock()
		readyCount++
		if readyCount >= 2 {
			close(ready)
		}
		readyMu.Unlock()

		// Echo loop
		for {
			var msg map[string]string
			if err := ws.ReadJSON(&msg); err != nil {
				return
			}
			ws.hub.BroadcastRoomExcept(room, ws.ID(), msg)
		}
	})

	// Connect two clients to same room
	conn1 := dialWS(t, ts, "/ws/chat/lobby")
	conn2 := dialWS(t, ts, "/ws/chat/lobby")

	// Wait for both to be in the room
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for connections")
	}

	// Verify room count
	if count := srv.WSHub().RoomCount("lobby"); count != 2 {
		t.Errorf("expected 2 in room, got %d", count)
	}

	// Send from conn1, should arrive at conn2
	ctx := context.Background()
	data, _ := json.Marshal(map[string]string{"msg": "hello from 1"})
	if err := conn1.Write(ctx, MessageText, data); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, respData, err := conn2.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp map[string]string
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["msg"] != "hello from 1" {
		t.Errorf("expected 'hello from 1', got %q", resp["msg"])
	}
}

func TestWSHubBroadcastAll(t *testing.T) {
	srv, ts := newTestWSServer(t, WithWebSocketPingInterval(-1))

	connIDCh := make(chan string, 1)

	srv.WS("/ws/all", func(ws *WSConn) {
		connIDCh <- ws.ID() // registration completes before handler is called
		for {
			if _, _, err := ws.Read(); err != nil {
				return
			}
		}
	})

	conn := dialWS(t, ts, "/ws/all")
	<-connIDCh // wait for handler entry (registration already done)

	hub := srv.WSHub()
	if err := hub.BroadcastAll(map[string]string{"type": "broadcast"}); err != nil {
		t.Fatalf("broadcast: %v", err)
	}

	ctx := context.Background()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var msg map[string]string
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if msg["type"] != "broadcast" {
		t.Errorf("expected broadcast, got %+v", msg)
	}
}

func TestWSHubSend(t *testing.T) {
	srv, ts := newTestWSServer(t, WithWebSocketPingInterval(-1))

	connIDCh := make(chan string, 1)

	srv.WS("/ws/send", func(ws *WSConn) {
		connIDCh <- ws.ID()
		for {
			if _, _, err := ws.Read(); err != nil {
				return
			}
		}
	})

	conn := dialWS(t, ts, "/ws/send")

	connID := <-connIDCh
	hub := srv.WSHub()

	if err := hub.Send(connID, map[string]string{"direct": "msg"}); err != nil {
		t.Fatalf("send: %v", err)
	}

	ctx := context.Background()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var msg map[string]string
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if msg["direct"] != "msg" {
		t.Errorf("expected direct msg, got %+v", msg)
	}
}

func TestWSHubSendNotFound(t *testing.T) {
	srv, _ := newTestWSServer(t, WithWebSocketPingInterval(-1))
	hub := srv.WSHub()
	err := hub.Send("nonexistent", "test")
	if err == nil {
		t.Error("expected error for nonexistent connection")
	}
}

func TestWSHubConnCount(t *testing.T) {
	srv, ts := newTestWSServer(t, WithWebSocketPingInterval(-1))

	connIDCh := make(chan string, 3)

	srv.WS("/ws/count", func(ws *WSConn) {
		connIDCh <- ws.ID()
		for {
			if _, _, err := ws.Read(); err != nil {
				return
			}
		}
	})

	dialWS(t, ts, "/ws/count")
	dialWS(t, ts, "/ws/count")
	dialWS(t, ts, "/ws/count")

	// Wait for all 3 handlers to start (registration already done by then)
	for i := 0; i < 3; i++ {
		<-connIDCh
	}

	hub := srv.WSHub()
	if c := hub.ConnCount(); c != 3 {
		t.Errorf("expected 3 connections, got %d", c)
	}
}

func TestWSHubRooms(t *testing.T) {
	srv, ts := newTestWSServer(t, WithWebSocketPingInterval(-1))

	ready := make(chan struct{})

	srv.WS("/ws/rooms", func(ws *WSConn) {
		ws.JoinRoom("room-a")
		ws.JoinRoom("room-b")
		close(ready)
		for {
			if _, _, err := ws.Read(); err != nil {
				return
			}
		}
	})

	dialWS(t, ts, "/ws/rooms")
	<-ready // JoinRoom calls completed

	hub := srv.WSHub()
	rooms := hub.Rooms()
	if len(rooms) != 2 {
		t.Fatalf("expected 2 rooms, got %d: %v", len(rooms), rooms)
	}
	if rooms[0] != "room-a" || rooms[1] != "room-b" {
		t.Errorf("expected [room-a, room-b], got %v", rooms)
	}
}

func TestWSConnRooms(t *testing.T) {
	srv, ts := newTestWSServer(t, WithWebSocketPingInterval(-1))

	roomsCh := make(chan []string, 1)

	srv.WS("/ws/conn-rooms", func(ws *WSConn) {
		ws.JoinRoom("alpha")
		ws.JoinRoom("beta")
		roomsCh <- ws.Rooms()
		ws.LeaveRoom("alpha")
		roomsCh <- ws.Rooms()
		for {
			if _, _, err := ws.Read(); err != nil {
				return
			}
		}
	})

	dialWS(t, ts, "/ws/conn-rooms")

	rooms1 := <-roomsCh
	if len(rooms1) != 2 {
		t.Errorf("expected 2 rooms, got %d", len(rooms1))
	}

	rooms2 := <-roomsCh
	if len(rooms2) != 1 || rooms2[0] != "beta" {
		t.Errorf("expected [beta], got %v", rooms2)
	}
}

func TestWSOriginAllowed(t *testing.T) {
	// coder/websocket uses OriginPatterns which match against the Origin header's host
	srv, ts := newTestWSServer(t, WithWebSocketAllowedOrigins("*"))

	srv.WS("/ws/origin", func(ws *WSConn) {
		ws.WriteText("ok")
	})

	// Any origin should be allowed with "*"
	url := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws/origin"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": []string{"http://anything.com"}},
	})
	if err != nil {
		t.Fatalf("should succeed with wildcard origin: %v", err)
	}
	conn.CloseNow()
}

func TestWSOriginBlocked(t *testing.T) {
	// Only allow specific origin pattern
	srv, ts := newTestWSServer(t, WithWebSocketAllowedOrigins("allowed.com"))

	srv.WS("/ws/origin-blocked", func(ws *WSConn) {
		ws.WriteText("should not reach here")
	})

	url := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws/origin-blocked"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": []string{"http://evil.com"}},
	})
	if err == nil {
		t.Fatal("expected error for blocked origin")
	}
}

func TestWSConcurrentWrites(t *testing.T) {
	srv, ts := newTestWSServer(t, WithWebSocketPingInterval(-1))

	srv.WS("/ws/concurrent", func(ws *WSConn) {
		// Write from multiple goroutines
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ws.WriteText("msg")
			}()
		}
		wg.Wait()
	})

	conn := dialWS(t, ts, "/ws/concurrent")
	ctx := context.Background()

	received := 0
	for received < 10 {
		_, _, err := conn.Read(ctx)
		if err != nil {
			break
		}
		received++
	}
	if received != 10 {
		t.Errorf("expected 10 messages, got %d", received)
	}
}

func TestWSCloseAll(t *testing.T) {
	srv, ts := newTestWSServer(t, WithWebSocketPingInterval(-1))

	connIDCh := make(chan string, 1)

	srv.WS("/ws/close-all", func(ws *WSConn) {
		connIDCh <- ws.ID()
		for {
			if _, _, err := ws.Read(); err != nil {
				return
			}
		}
	})

	conn := dialWS(t, ts, "/ws/close-all")
	<-connIDCh

	srv.WSHub().CloseAll(StatusGoingAway, "test shutdown")

	ctx := context.Background()
	_, _, err := conn.Read(ctx)
	if err == nil {
		t.Error("expected read error after CloseAll")
	}
}

func TestWSIsCloseError(t *testing.T) {
	srv, ts := newTestWSServer(t, WithWebSocketPingInterval(-1))

	srv.WS("/ws/close-normal", func(ws *WSConn) {
		ws.Close(StatusNormalClosure, "done")
	})

	conn := dialWS(t, ts, "/ws/close-normal")
	ctx := context.Background()
	_, _, err := conn.Read(ctx)
	if err == nil {
		t.Fatal("expected close error")
	}
	if !IsCloseError(err) {
		t.Errorf("expected close error, got: %v", err)
	}
}

func TestWSMessageSizeLimit(t *testing.T) {
	srv, ts := newTestWSServer(t,
		WithWebSocketMaxMessageSize(100),
		WithWebSocketPingInterval(-1),
	)

	srv.WS("/ws/limit", func(ws *WSConn) {
		for {
			if _, _, err := ws.Read(); err != nil {
				return
			}
		}
	})

	conn := dialWS(t, ts, "/ws/limit")
	ctx := context.Background()

	// Send a message that exceeds the limit
	bigMsg := make([]byte, 200)
	if err := conn.Write(ctx, MessageText, bigMsg); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Server should close the connection
	_, _, err := conn.Read(ctx)
	if err == nil {
		t.Error("expected error after exceeding message size limit")
	}
}

func TestWSWithAuthNoToken(t *testing.T) {
	srv, ts := newTestWSServer(t,
		WithAuthMemoryDatabase(),
		WithAuthKey(
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		),
		WithAuthTokensDuration(15*time.Minute, 7*24*time.Hour),
		WithWebSocketPingInterval(-1),
	)

	srv.WSWithAuth("/ws/protected", func(ws *WSConn) {
		ws.WriteText("should not reach")
	})

	// Try to connect without auth token
	url := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws/protected"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, resp, err := websocket.Dial(ctx, url, nil)
	if err == nil {
		t.Fatal("expected error for unauthenticated request")
	}
	if resp != nil && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestWSLazyInit(t *testing.T) {
	srv, _ := newTestWSServer(t)

	// Hub should not exist before first WS call
	if srv.wsHub != nil {
		t.Error("wsHub should be nil before any WS call")
	}

	// Calling WSHub() should lazily init
	hub := srv.WSHub()
	if hub == nil {
		t.Fatal("WSHub() returned nil")
	}
	if srv.wsHub != hub {
		t.Error("wsHub should be set after WSHub() call")
	}
}

func TestWSCompressionSkip(t *testing.T) {
	// Verify that isWebSocketUpgrade detects upgrade requests
	req := httptest.NewRequest("GET", "/ws/test", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")

	if !isWebSocketUpgrade(req) {
		t.Error("should detect WebSocket upgrade")
	}

	req2 := httptest.NewRequest("GET", "/api/test", nil)
	if isWebSocketUpgrade(req2) {
		t.Error("should not detect normal request as WebSocket upgrade")
	}
}

func TestWSValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{
			name:    "valid config",
			opts:    []Option{WithWebSocketPingInterval(30 * time.Second), WithWebSocketPongTimeout(10 * time.Second)},
			wantErr: false,
		},
		{
			name:    "pong >= ping",
			opts:    []Option{WithWebSocketPingInterval(5 * time.Second), WithWebSocketPongTimeout(10 * time.Second)},
			wantErr: true,
		},
		{
			name:    "pong == ping",
			opts:    []Option{WithWebSocketPingInterval(5 * time.Second), WithWebSocketPongTimeout(5 * time.Second)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewServer(tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewServer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWSUpgradeWebSocket(t *testing.T) {
	router := mux.NewRouter()

	router.HandleFunc("/ws/raw", func(w http.ResponseWriter, r *http.Request) {
		ctx := C(w, r)
		conn, err := ctx.UpgradeWebSocket(nil)
		if err != nil {
			ctx.InternalServerError(err, "upgrade failed")
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")

		_, data, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		conn.Write(r.Context(), MessageText, data)
	})

	ts := httptest.NewServer(router)
	defer ts.Close()

	url := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws/raw"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()

	if err := conn.Write(ctx, MessageText, []byte("raw test")); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "raw test" {
		t.Errorf("expected 'raw test', got %q", string(data))
	}
}
