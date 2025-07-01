package main

import (
	"fmt"
	"log"
	"net/http"

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
	server.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"message":  "Hello from Servex! 👋",
			"tutorial": "01-hello-world",
		})
	})

	// Add a health check endpoint
	server.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"status": "healthy",
			"server": "servex",
		})
	})

	// Start the server
	fmt.Println("🌐 Server starting on http://localhost:8080")
	fmt.Println("Try these URLs:")
	fmt.Println("  → http://localhost:8080/")
	fmt.Println("  → http://localhost:8080/health")
	fmt.Println("")
	fmt.Println("Press Ctrl+C to stop")

	server.Start(":8080", "")
}
