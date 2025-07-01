package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/maxbolgarin/servex"
)

var (
	buildDir    = flag.String("dir", "build", "Directory containing the React build files")
	port        = flag.String("port", "3000", "Port to serve on")
	host        = flag.String("host", "", "Host to bind to (empty for all interfaces)")
	apiPrefix   = flag.String("api", "/api", "API prefix for backend endpoints")
	indexFile   = flag.String("index", "index.html", "Index file for SPA routing")
	version     = flag.Bool("version", false, "Show version information")
	enableHTTPS = flag.Bool("https", false, "Enable HTTPS (requires cert.pem and key.pem)")
	certFile    = flag.String("cert", "cert.pem", "Path to TLS certificate file")
	keyFile     = flag.String("key", "key.pem", "Path to TLS key file")
)

const appVersion = "1.0.0"

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("Servex SPA Server v%s\n", appVersion)
		fmt.Println("A high-performance SPA server for React applications")
		os.Exit(0)
	}

	// Check if build directory exists
	if _, err := os.Stat(*buildDir); os.IsNotExist(err) {
		log.Fatalf("Build directory not found: %s", *buildDir)
	}

	// Check for index file
	indexPath := filepath.Join(*buildDir, *indexFile)
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		log.Fatalf("Index file not found: %s", indexPath)
	}

	// Construct listen address
	listenAddr := *host + ":" + *port

	// Configure SPA server
	server, err := servex.NewServer(
		// SPA configuration with client-side routing
		servex.WithSPAMode(*buildDir, *indexFile),

		// Security headers for web applications
		servex.WithSecurityHeaders(),

		// CSRF protection
		servex.WithCSRFProtection(),

		// Rate limiting (generous for SPA)
		servex.WithRPM(600), // 600 requests per minute

		// Request size limits appropriate for web apps
		servex.WithMaxRequestBodySize(50*1024*1024), // 50MB for file uploads
		servex.WithMaxJSONBodySize(10*1024*1024),    // 10MB for JSON
		servex.WithRequestSizeLimits(),

		// Health and metrics endpoints
		servex.WithHealthEndpoint(),
		servex.WithDefaultMetrics(),

		// Static file caching
		servex.WithCacheStaticAssets(86400), // 1 day for static assets

		// Enhanced logging for web applications
		servex.WithLogFields("method", "url", "status", "duration", "ip", "user_agent"),

		// HTTPS configuration if enabled
		conditionalHTTPS(),
	)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Add API endpoints
	addAPIEndpoints(server)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received shutdown signal, gracefully shutting down...")
		cancel()
	}()

	// Log startup information
	logStartupInfo(listenAddr)

	// Start server
	var httpsAddr string
	if *enableHTTPS {
		httpsAddr = listenAddr
		listenAddr = "" // Disable HTTP when HTTPS is enabled
	}

	log.Println("Starting SPA server...")
	if err := server.StartWithShutdown(ctx, listenAddr, httpsAddr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}

	log.Println("SPA server shutdown complete")
}

func conditionalHTTPS() servex.Option {
	if *enableHTTPS {
		// Check if certificate files exist
		if _, err := os.Stat(*certFile); os.IsNotExist(err) {
			log.Fatalf("Certificate file not found: %s", *certFile)
		}
		if _, err := os.Stat(*keyFile); os.IsNotExist(err) {
			log.Fatalf("Key file not found: %s", *keyFile)
		}
		return servex.WithCertificateFromFile(*certFile, *keyFile)
	}
	return func(opts *servex.Options) {} // No-op option
}

func addAPIEndpoints(server *servex.Server) {
	// API info endpoint
	server.GET(*apiPrefix+"/info", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]interface{}{
			"service":    "servex-spa",
			"version":    appVersion,
			"timestamp":  time.Now().Format(time.RFC3339),
			"build_dir":  *buildDir,
			"index_file": *indexFile,
			"api_prefix": *apiPrefix,
		})
	})

	// Server status endpoint
	server.GET(*apiPrefix+"/status", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().Format(time.RFC3339),
			"uptime":    time.Since(time.Now()).String(), // Would be calculated from start time
		})
	})

	// Example API endpoints for a typical React app
	server.GET(*apiPrefix+"/users", func(w http.ResponseWriter, r *http.Request) {
		// Mock user data
		users := []map[string]interface{}{
			{"id": 1, "name": "John Doe", "email": "john@example.com", "role": "admin"},
			{"id": 2, "name": "Jane Smith", "email": "jane@example.com", "role": "user"},
			{"id": 3, "name": "Bob Johnson", "email": "bob@example.com", "role": "user"},
		}
		servex.C(w, r).JSON(users)
	})

	server.GET(*apiPrefix+"/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		userID := servex.C(w, r).Path("id")

		// Mock user lookup
		user := map[string]interface{}{
			"id":         userID,
			"name":       "User " + userID,
			"email":      fmt.Sprintf("user%s@example.com", userID),
			"role":       "user",
			"created_at": "2023-01-01T00:00:00Z",
			"updated_at": time.Now().Format(time.RFC3339),
		}

		servex.C(w, r).JSON(user)
	})

	// Example POST endpoint
	server.POST(*apiPrefix+"/users", func(w http.ResponseWriter, r *http.Request) {
		var userData map[string]interface{}
		if err := servex.C(w, r).ReadJSON(&userData); err != nil {
			servex.C(w, r).BadRequest(err, "Invalid JSON")
			return
		}

		// Mock user creation
		userData["id"] = time.Now().Unix() // Simple ID generation
		userData["created_at"] = time.Now().Format(time.RFC3339)
		userData["updated_at"] = time.Now().Format(time.RFC3339)

		w.WriteHeader(http.StatusCreated)
		servex.C(w, r).JSON(userData)
	})

	// Example configuration endpoint
	server.GET(*apiPrefix+"/config", func(w http.ResponseWriter, r *http.Request) {
		config := map[string]interface{}{
			"app_name":    "React SPA",
			"environment": "development",
			"features": map[string]bool{
				"user_registration": true,
				"social_login":      false,
				"file_upload":       true,
				"real_time_chat":    false,
			},
			"limits": map[string]interface{}{
				"max_file_size":  "50MB",
				"max_users":      1000,
				"api_rate_limit": 600,
			},
		}
		servex.C(w, r).JSON(config)
	})

	// CSRF token endpoint (for forms)
	server.GET(*apiPrefix+"/csrf-token", func(w http.ResponseWriter, r *http.Request) {
		// This would return the CSRF token for the session
		servex.C(w, r).JSON(map[string]interface{}{
			"csrf_token": "mock-csrf-token-" + fmt.Sprintf("%d", time.Now().Unix()),
			"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	})

	// Example file upload endpoint
	server.POST(*apiPrefix+"/upload", func(w http.ResponseWriter, r *http.Request) {
		// Parse multipart form
		err := r.ParseMultipartForm(10 << 20) // 10MB max
		if err != nil {
			servex.C(w, r).BadRequest(err, "Failed to parse form")
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			servex.C(w, r).BadRequest(err, "No file uploaded")
			return
		}
		defer file.Close()

		// Mock file processing
		result := map[string]interface{}{
			"filename":     header.Filename,
			"size":         header.Size,
			"content_type": header.Header.Get("Content-Type"),
			"upload_id":    fmt.Sprintf("upload_%d", time.Now().Unix()),
			"url":          fmt.Sprintf("/uploads/%s", header.Filename),
			"uploaded_at":  time.Now().Format(time.RFC3339),
		}

		servex.C(w, r).JSON(result)
	})

	// Example search endpoint
	server.GET(*apiPrefix+"/search", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		if query == "" {
			servex.C(w, r).BadRequest(fmt.Errorf("query parameter 'q' is required"), "Missing search query")
			return
		}

		// Mock search results
		results := []map[string]interface{}{
			{
				"id":    1,
				"title": fmt.Sprintf("Result for '%s' #1", query),
				"type":  "article",
				"score": 0.95,
			},
			{
				"id":    2,
				"title": fmt.Sprintf("Result for '%s' #2", query),
				"type":  "page",
				"score": 0.87,
			},
		}

		servex.C(w, r).JSON(map[string]interface{}{
			"query":   query,
			"results": results,
			"total":   len(results),
		})
	})
}

func logStartupInfo(listenAddr string) {
	log.Println("=== Servex SPA Server ===")
	log.Printf("Version: %s", appVersion)
	log.Printf("Build directory: %s", *buildDir)
	log.Printf("Index file: %s", *indexFile)

	if *enableHTTPS {
		log.Printf("HTTPS server: https://%s", listenAddr)
		log.Printf("Certificate: %s", *certFile)
		log.Printf("Key: %s", *keyFile)
	} else {
		log.Printf("HTTP server: http://%s", listenAddr)
	}

	log.Println("\n=== API Endpoints ===")
	log.Printf("API prefix: %s", *apiPrefix)
	log.Printf("  %s/info        - Server information", *apiPrefix)
	log.Printf("  %s/status      - Server status", *apiPrefix)
	log.Printf("  %s/users       - User management", *apiPrefix)
	log.Printf("  %s/config      - App configuration", *apiPrefix)
	log.Printf("  %s/csrf-token  - CSRF token", *apiPrefix)
	log.Printf("  %s/upload      - File upload", *apiPrefix)
	log.Printf("  %s/search      - Search endpoint", *apiPrefix)

	log.Println("\n=== Management Endpoints ===")
	log.Println("  /health         - Health check")
	log.Println("  /metrics        - Prometheus metrics")

	log.Println("\n=== SPA Configuration ===")
	log.Println("  - Client-side routing enabled")
	log.Println("  - All non-API routes serve index.html")
	log.Println("  - Static assets cached for 1 day")
	log.Println("  - CSRF protection enabled")
	log.Println("  - Rate limiting: 600 requests/minute")
	log.Println()

	// Check for common React build files
	commonFiles := []string{"static/js", "static/css", "manifest.json", "favicon.ico"}
	log.Println("=== Build Directory Contents ===")
	for _, file := range commonFiles {
		fullPath := filepath.Join(*buildDir, file)
		if _, err := os.Stat(fullPath); err == nil {
			log.Printf("  ✓ %s", file)
		} else {
			log.Printf("  ✗ %s (not found)", file)
		}
	}
	log.Println()
}
