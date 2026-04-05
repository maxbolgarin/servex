package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

// This example demonstrates all available presets.
// Run with an argument to select a preset:
//
//	go run main.go             # development (default)
//	go run main.go production  # production
//	go run main.go api         # REST API
//	go run main.go micro       # microservice
//	go run main.go auth        # API with authentication
func main() {
	preset := "development"
	if len(os.Args) > 1 {
		preset = os.Args[1]
	}

	switch preset {
	case "development", "dev":
		runDevelopment()
	case "production", "prod":
		runProduction()
	case "api":
		runAPI()
	case "micro", "microservice":
		runMicroservice()
	case "auth":
		runAuth()
	default:
		fmt.Println("Servex Quickstart - Available presets:")
		fmt.Println("  go run main.go              development server")
		fmt.Println("  go run main.go production   production with security + rate limiting")
		fmt.Println("  go run main.go api          REST API with CORS + caching")
		fmt.Println("  go run main.go micro        microservice with fast timeouts")
		fmt.Println("  go run main.go auth         API with JWT authentication")
		os.Exit(1)
	}
}

// runDevelopment starts a server with DevelopmentPreset.
// Features: health endpoint, metrics, debug mode (errors sent to client).
func runDevelopment() {
	server, err := servex.NewServer(servex.DevelopmentPreset()...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	server.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"message": "Hello from development server!",
			"env":     "development",
		})
	})

	fmt.Println("Servex Quickstart - Development Server")
	fmt.Println("Server: http://localhost:8080")
	fmt.Println("Try: curl http://localhost:8080/hello")
	fmt.Println("Press Ctrl+C to stop")

	if err := server.StartWithWaitSignalsHTTP(context.Background(), ":8080"); err != nil {
		log.Fatal(err)
	}
}

// runProduction starts a server with ProductionPreset.
// Features: strict security headers, CSRF, 100 rps rate limiting,
// compression, health/metrics, audit logging.
func runProduction() {
	server, err := servex.NewServer(servex.MergeWithPreset(
		servex.ProductionPreset(),
		servex.WithCustomHeaders(map[string]string{
			"X-App-Version": "1.0.0",
		}),
	)...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	server.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"users": []string{"alice", "bob", "charlie"},
			"count": 3,
		})
	})

	server.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"status":    "operational",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	fmt.Println("Servex Quickstart - Production Server")
	fmt.Println("Server: http://localhost:8080")
	fmt.Println("Try: curl http://localhost:8080/api/users")
	fmt.Println("Press Ctrl+C to stop")

	if err := server.StartWithWaitSignalsHTTP(context.Background(), ":8080"); err != nil {
		log.Fatal(err)
	}
}

// runAPI starts a server with APIServerPreset.
// Features: CORS, 1000 rpm rate limiting, compression,
// 10 MB body limit, 1 MB JSON limit, API caching (5 min).
func runAPI() {
	server, err := servex.NewServer(
		servex.MergeWithPreset(
			servex.APIServerPreset(),
			servex.WithCORS(),
		)...,
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	server.HandleFunc("/api/v1/users", handleUsers).Methods(servex.GET, servex.POST)
	server.HandleFunc("/api/v1/users/{id}", handleUserByID).Methods(servex.GET)
	server.HandleFunc("/api/v1/posts", handlePosts).Methods(servex.GET)

	fmt.Println("Servex Quickstart - REST API Server")
	fmt.Println("Server: http://localhost:8080")
	fmt.Println("Try: curl http://localhost:8080/api/v1/users")
	fmt.Println("Press Ctrl+C to stop")

	if err := server.StartWithWaitSignalsHTTP(context.Background(), ":8080"); err != nil {
		log.Fatal(err)
	}
}

// runMicroservice starts a server with MicroservicePreset.
// Features: fast timeouts (5s read, 30s idle), basic security,
// 5 MB body limit, 200 rps rate limiting.
func runMicroservice() {
	server, err := servex.NewServer(servex.MicroservicePreset()...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	server.HandleFunc("/api/v1/process", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"status": "processed",
			"id":     "12345",
		})
	})

	server.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"service": "running",
			"version": "1.0.0",
		})
	})

	fmt.Println("Servex Quickstart - Microservice Server")
	fmt.Println("Server: http://localhost:8080")
	fmt.Println("Try: curl http://localhost:8080/api/v1/process")
	fmt.Println("Press Ctrl+C to stop")

	if err := server.StartWithWaitSignalsHTTP(context.Background(), ":8080"); err != nil {
		log.Fatal(err)
	}
}

// runAuth starts an API server with JWT authentication.
// Features: in-memory auth database, auto-registered auth endpoints,
// initial admin user, protected routes with role-based access.
func runAuth() {
	server, err := servex.NewServer(
		servex.WithAuthMemoryDatabase(),
		servex.WithAuthInitialUsers(servex.InitialUser{
			Username: "admin",
			Password: "admin123",
			Roles:    []servex.UserRole{"admin"},
		}),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Public endpoint
	server.HandleFunc("/api/v1/public", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"message": "This is public data",
		})
	})

	// Protected endpoints (require authentication)
	server.HFA("/api/v1/protected", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"message": "Authenticated!",
			"user":    r.Context().Value(servex.UserContextKey{}).(string),
		})
	}, "user")

	server.HFA("/api/v1/admin", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"message": "Admin access granted",
			"user":    r.Context().Value(servex.UserContextKey{}).(string),
		})
	}, "admin")

	fmt.Println("Servex Quickstart - Auth API Server")
	fmt.Println("Server: http://localhost:8080")
	fmt.Println("Auth endpoints: POST /api/v1/auth/{register,login,refresh,logout}")
	fmt.Println("Login: admin / admin123")
	fmt.Println("Press Ctrl+C to stop")

	if err := server.StartWithWaitSignalsHTTP(context.Background(), ":8080"); err != nil {
		log.Fatal(err)
	}
}

// Handlers

func handleUsers(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	if r.Method == servex.GET {
		ctx.Response(200, []map[string]string{
			{"id": "1", "name": "Alice"},
			{"id": "2", "name": "Bob"},
		})
	} else {
		ctx.Response(201, map[string]string{"message": "User created"})
	}
}

func handleUserByID(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, map[string]string{
		"id":   ctx.Path("id"),
		"name": "Alice",
	})
}

func handlePosts(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	ctx.Response(200, []map[string]string{
		{"id": "1", "title": "Hello World"},
	})
}
