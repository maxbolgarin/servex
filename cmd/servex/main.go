package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/maxbolgarin/servex"
)

// Version information (set during build)
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	var (
		configFile = flag.String("config", "server.yaml", "Path to configuration file")
		version    = flag.Bool("version", false, "Show version information")
		validate   = flag.Bool("validate", false, "Validate configuration and exit")
		help       = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	if *version {
		showVersion()
		return
	}

	// Load configuration
	config, err := loadConfiguration(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Validate configuration if requested
	if *validate {
		fmt.Printf("Configuration file '%s' is valid ✓\n", *configFile)
		return
	}

	// Create server from configuration
	server, err := servex.NewFromConfig(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	go handleShutdownSignals(cancel)

	fmt.Printf("🚀 Starting Servex Server v%s\n", Version)
	if httpAddress := config.Server.HTTP; httpAddress != "" {
		fmt.Printf("   HTTP:  %s\n", httpAddress)
	}
	if httpsAddress := config.Server.HTTPS; httpsAddress != "" {
		fmt.Printf("   HTTPS: %s\n", httpsAddress)
	}
	fmt.Printf("   Config: %s\n", *configFile)
	fmt.Println()

	// Register default routes for standalone mode
	registerStandaloneRoutes(server)

	// Start server with graceful shutdown
	if err := server.StartWithShutdown(ctx, config.Server.HTTP, config.Server.HTTPS); err != nil {
		log.Fatalf("Server error: %v", err)
	}

	<-ctx.Done()

	fmt.Println("\n👋 Server shutdown gracefully")
}

// loadConfiguration loads config from file and environment variables
func loadConfiguration(configFile string) (*servex.Config, error) {
	// Check if config file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		fmt.Printf("⚠️  Configuration file '%s' not found, using environment variables only\n", configFile)
		return servex.LoadConfigFromEnv()
	}

	// Load from file with environment overrides
	config, err := servex.LoadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("load config from file: %w", err)
	}

	fmt.Printf("✓ Loaded configuration from '%s'\n", configFile)
	return config, nil
}

// registerStandaloneRoutes registers default routes for standalone deployment
func registerStandaloneRoutes(server *servex.Server) {
	// Default API info endpoint
	server.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"service":    "servex",
			"version":    Version,
			"build_time": BuildTime,
			"git_commit": GitCommit,
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
		})
	}).Methods("GET")

	// Status endpoint
	server.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"uptime":    time.Since(startTime).String(),
		})
	}).Methods("GET")

	// Configuration info (non-sensitive)
	server.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)

		// Only show non-sensitive configuration info
		info := map[string]interface{}{
			"version": Version,
			"features": map[string]bool{
				"auth_enabled":    server.IsAuthEnabled(),
				"tls_enabled":     server.IsTLS(),
				"health_endpoint": true,
			},
		}

		ctx.Response(200, info)
	}).Methods("GET")

	// File upload test endpoint (if no other handlers registered)
	server.HandleFunc("/api/test/upload", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)

		if r.Method != "POST" {
			ctx.Error(fmt.Errorf("method not allowed"), 405, "Only POST method allowed")
			return
		}

		// Parse multipart form
		if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB max
			ctx.Error(err, 400, "Failed to parse multipart form")
			return
		}

		files := r.MultipartForm.File["file"]
		if len(files) == 0 {
			ctx.Error(fmt.Errorf("no file provided"), 400, "No file in 'file' field")
			return
		}

		ctx.Response(200, map[string]interface{}{
			"message":        "File upload test successful",
			"files_received": len(files),
			"first_file": map[string]interface{}{
				"filename": files[0].Filename,
				"size":     files[0].Size,
				"headers":  files[0].Header,
			},
		})
	})
}

// handleShutdownSignals handles graceful shutdown
func handleShutdownSignals(cancel context.CancelFunc) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)

	sig := <-signals
	fmt.Printf("\n🛑 Received signal: %s\n", sig)
	fmt.Println("📴 Shutting down server...")

	cancel()
}

// showVersion displays version information
func showVersion() {
	fmt.Printf("Servex HTTP Server\n")
	fmt.Printf("Version:    %s\n", Version)
	fmt.Printf("Build time: %s\n", BuildTime)
	fmt.Printf("Git commit: %s\n", GitCommit)
}

// showHelp displays usage information
func showHelp() {
	fmt.Printf("Servex - Enterprise HTTP Server\n\n")
	fmt.Printf("USAGE:\n")
	fmt.Printf("  servex [OPTIONS]\n\n")
	fmt.Printf("OPTIONS:\n")
	fmt.Printf("  -config string    Path to configuration file (default: server.yaml)\n")
	fmt.Printf("  -validate         Validate configuration and exit\n")
	fmt.Printf("  -version          Show version information\n")
	fmt.Printf("  -help             Show this help message\n\n")
	fmt.Printf("EXAMPLES:\n")
	fmt.Printf("  servex                          # Start with server.yaml\n")
	fmt.Printf("  servex -config prod.yaml        # Start with custom config\n")
	fmt.Printf("  servex -validate                # Validate server.yaml\n")
	fmt.Printf("  servex -validate -config prod.yaml  # Validate custom config\n\n")
	fmt.Printf("ENVIRONMENT VARIABLES:\n")
	fmt.Printf("  All configuration options can be set via environment variables.\n")
	fmt.Printf("  See documentation for complete list of SERVEX_* variables.\n\n")
	fmt.Printf("CONFIGURATION:\n")
	fmt.Printf("  Example configuration file: https://github.com/maxbolgarin/servex/tree/main/examples/server.yaml\n")
}

var startTime = time.Now()
