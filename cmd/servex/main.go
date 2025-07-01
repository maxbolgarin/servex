package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/maxbolgarin/servex/v2"
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
	server, err := servex.NewServerFromConfig(config)
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
		fmt.Printf("\tHTTP:  %s\n", httpAddress)
	}
	if httpsAddress := config.Server.HTTPS; httpsAddress != "" {
		fmt.Printf("\tHTTPS: %s\n", httpsAddress)
	}
	fmt.Printf("\tConfig: %s\n\n", *configFile)

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
	fmt.Printf("  Example configuration file: https://github.com/maxbolgarin/servex/v2/tree/main/examples/server.yaml\n")
}

var startTime = time.Now()
