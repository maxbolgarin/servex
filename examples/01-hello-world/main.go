package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/maxbolgarin/servex/v2"
)

func main() {
	fmt.Println("🚀 Servex Tutorial - Hello World")
	fmt.Println("===================================")

	// Create the simplest possible server - just one line!
	server, err := servex.NewServer()
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Add a simple hello endpoint
	server.GET("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.JSON(map[string]string{
			"message":  "Hello from Servex! 👋",
			"tutorial": "01-hello-world",
		})
	})

	// Start the server
	fmt.Println("🌐 Server starting on http://localhost:8080")
	fmt.Println("Try these URLs:")
	fmt.Println("  → http://localhost:8080/")
	fmt.Println("")
	fmt.Println("Press Ctrl+C to stop")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	err = server.StartHTTP(":8080")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
	defer server.Shutdown(ctx)

	<-ctx.Done()
	fmt.Println("👋 Server stopped")
}
