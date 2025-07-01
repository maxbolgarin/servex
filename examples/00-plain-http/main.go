package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

func main() {
	fmt.Println("🚀 Plain HTTP + Servex Context Tutorial")
	fmt.Println("=====================================")
	fmt.Println("Demonstrates using Servex context utilities with standard net/http")
	fmt.Println()

	// Create standard net/http ServeMux
	mux := http.NewServeMux()

	// Register handlers
	mux.HandleFunc("/api/users", usersHandler)
	mux.HandleFunc("/api/search", searchHandler)
	mux.HandleFunc("/api/status", statusHandler)
	mux.HandleFunc("/api/error", errorHandler)
	mux.HandleFunc("/health", healthHandler)

	// Start server
	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	fmt.Println("🌐 Server starting on http://localhost:8080")
	fmt.Println()
	fmt.Println("📋 Available endpoints:")
	fmt.Println("  GET  /health            - Health check")
	fmt.Println("  GET  /api/users         - List users")
	fmt.Println("  POST /api/users         - Create user")
	fmt.Println("  GET  /api/search?q=...  - Search with query params")
	fmt.Println("  GET  /api/status        - Status with custom headers")
	fmt.Println("  GET  /api/error?type=...    - Test error handling")
	fmt.Println()
	fmt.Println("🧪 Test commands:")
	fmt.Println("  curl http://localhost:8080/health")
	fmt.Println("  curl http://localhost:8080/api/users")
	fmt.Println("  curl -X POST http://localhost:8080/api/users \\")
	fmt.Println("       -H 'Content-Type: application/json' \\")
	fmt.Println("       -d '{\"name\":\"Dave\",\"email\":\"dave@example.com\"}'")
	fmt.Println("  curl 'http://localhost:8080/api/search?q=servex'")
	fmt.Println("  curl -I http://localhost:8080/api/status")
	fmt.Println("  curl 'http://localhost:8080/api/error?type=404'")
	fmt.Println()
	fmt.Println("💡 This is plain net/http enhanced with Servex context utilities!")
	fmt.Println("Press Ctrl+C to stop")

	log.Fatal(server.ListenAndServe())
}

type userSchema struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// usersHandler demonstrates JSON responses and request parsing
func usersHandler(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)

	switch r.Method {
	case servex.GET:
		// Easy JSON response with proper headers
		ctx.JSON(map[string]any{
			"users": []userSchema{
				{ID: 1, Name: "Alice", Email: "alice@example.com"},
				{ID: 2, Name: "Bob", Email: "bob@example.com"},
				{ID: 3, Name: "Charlie", Email: "charlie@example.com"},
			},
			"total": 3,
			"note":  "Using Servex context with plain net/http",
		})

	case servex.POST:
		// Easy request body parsing
		var user userSchema
		if err := ctx.ReadJSON(&user); err != nil {
			ctx.BadRequest(err, "Invalid JSON")
			return
		}

		// Validate required fields
		if user.Name == "" || user.Email == "" {
			ctx.BadRequest(nil, "Name and email are required")
			return
		}

		// Simulate creating user
		user.ID = 4

		ctx.Response(http.StatusCreated, map[string]any{
			"message": "User created successfully",
			"user":    user,
		})

	default:
		ctx.MethodNotAllowed()
	}
}

type searchResult struct {
	Query   string   `json:"query"`
	Page    string   `json:"page"`
	Results []string `json:"results"`
	Note    string   `json:"note"`
}

// searchHandler demonstrates query parameter handling
func searchHandler(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)

	// Easy query parameter access
	query := ctx.Query("q")
	if query == "" {
		ctx.BadRequest(nil, "Query parameter 'q' is required")
		return
	}

	// Optional parameters with defaults
	page := ctx.Query("page")
	if page == "" {
		page = "1"
	}

	out := searchResult{
		Query: query,
		Page:  page,
		Results: []string{
			fmt.Sprintf("Result 1 for '%s'", query),
			fmt.Sprintf("Result 2 for '%s'", query),
		},
		Note: "Query parameters handled with Servex context",
	}

	ctx.JSON(out)
}

// statusHandler demonstrates custom headers
func statusHandler(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)

	// Set custom headers easily
	ctx.SetHeader("X-API-Version", "1.0")
	ctx.SetHeader("X-Server-Type", "plain-http")
	ctx.SetHeader("X-Powered-By", "Servex Context")

	ctx.JSON(map[string]any{
		"status":    "operational",
		"timestamp": time.Now().Format(time.RFC3339),
		"features": []string{
			"Easy JSON responses",
			"Request body parsing",
			"Custom headers",
			"Error handling",
		},
	})
}

// errorHandler demonstrates error handling
func errorHandler(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)

	errorType := ctx.Query("type")

	switch errorType {
	case "400":
		ctx.BadRequest(nil, "Bad Request example", "code", "INVALID_REQUEST")
	case "404":
		ctx.NotFound(nil, "Resource not found example", "code", "NOT_FOUND")
	case "500":
		ctx.InternalServerError(nil, "Internal server error example", "code", "INTERNAL_ERROR")
	default:
		ctx.BadRequest(nil, "Add ?type=400, ?type=404, or ?type=500 to test errors")
	}
}

// healthHandler demonstrates simple health check
func healthHandler(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)

	ctx.Response(200, map[string]any{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
		"server": "Plain net/http + Servex context",
	})
}
