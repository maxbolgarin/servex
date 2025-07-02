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

	"github.com/maxbolgarin/servex/v2"
)

const (
	defaultConfigFile = "proxy_gateway_config.yaml"
	defaultPort       = ":8080"
	serviceName       = "advanced-proxy-gateway"
	serviceVersion    = "1.0.0"
)

func main() {
	// Parse command line flags
	var (
		configFile = flag.String("config", defaultConfigFile, "Configuration file path")
		port       = flag.String("port", defaultPort, "Server port")
		help       = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	// Setup logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Starting %s v%s", serviceName, serviceVersion)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling for graceful shutdown
	setupGracefulShutdown(cancel)

	// Initialize and start server
	if err := runServer(ctx, *configFile, *port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}

	log.Println("Server shutdown complete")
}

func runServer(ctx context.Context, configFile, port string) error {
	// Create server with configuration
	server, err := createServer(configFile)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// Register custom endpoints
	registerCustomEndpoints(server)

	// Print startup information
	printStartupInfo(port)

	// Start server with graceful shutdown
	return server.StartWithWaitSignalsHTTP(ctx, port)
}

func createServer(configFile string) (*servex.Server, error) {
	// Try to load from config file first
	if _, err := os.Stat(configFile); err == nil {
		log.Printf("Loading configuration from: %s", configFile)
		config, err := servex.LoadConfig(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
		return servex.NewServerFromConfig(config)
	}

	// Fallback to programmatic configuration
	log.Printf("Config file %s not found, using programmatic configuration", configFile)
	return createProgrammaticServer()
}

func createProgrammaticServer() (*servex.Server, error) {
	// Advanced proxy configuration
	proxyConfig := servex.ProxyConfiguration{
		Enabled: true,

		// Global connection settings
		GlobalTimeout:       30 * time.Second,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,

		// Traffic analysis and debugging
		TrafficDump: servex.TrafficDumpConfig{
			Enabled:     true,
			Directory:   "./traffic_dumps",
			MaxFileSize: 100 * 1024 * 1024, // 100MB
			MaxFiles:    20,
			IncludeBody: true,
			MaxBodySize: 64 * 1024, // 64KB
			SampleRate:  0.1,       // 10% sampling for production
		},

		// Health monitoring
		HealthCheck: servex.HealthCheckConfig{
			Enabled:         true,
			DefaultInterval: 30 * time.Second,
			Timeout:         5 * time.Second,
			RetryCount:      3,
		},

		// Proxy routing rules - demonstrating different strategies
		Rules: createProxyRules(),
	}

	// Create server with production-ready middleware
	return servex.NewServer(
		// Core proxy functionality
		servex.WithProxyConfig(proxyConfig),

		// Monitoring and health
		servex.WithHealthEndpoint(),
		servex.WithDefaultMetrics(),

		// Security hardening
		servex.WithSecurityHeaders(),
		servex.WithRPM(1000), // 1000 requests per minute

		// Request filtering
		servex.WithBlockedUserAgentsRegex(`(?i)(bot|crawler|spider|scraper|curl|wget)`),

		// Comprehensive logging
		servex.WithLogFields("method", "url", "status", "duration", "ip", "user_agent", "backend"),

		// Performance optimizations
		servex.WithMaxRequestBodySize(64*1024*1024), // 64MB
	)
}

func createProxyRules() []servex.ProxyRule {
	return []servex.ProxyRule{
		// Main API backend - Weighted Round Robin
		{
			Name:       "api-backend",
			PathPrefix: "/api/",
			Methods:    []string{servex.GET, servex.POST, servex.PUT, servex.DELETE, servex.PATCH},
			Backends: []servex.Backend{
				{
					URL:                 "http://api1.internal:8080",
					Weight:              3, // 50% of traffic
					HealthCheckPath:     "/health",
					HealthCheckInterval: 30 * time.Second,
					MaxConnections:      100,
				},
				{
					URL:                 "http://api2.internal:8080",
					Weight:              2, // 33% of traffic
					HealthCheckPath:     "/health",
					HealthCheckInterval: 30 * time.Second,
					MaxConnections:      100,
				},
				{
					URL:                 "http://api3.internal:8080",
					Weight:              1, // 17% of traffic
					HealthCheckPath:     "/health",
					HealthCheckInterval: 30 * time.Second,
					MaxConnections:      50,
				},
			},
			LoadBalancing:     servex.WeightedRoundRobinStrategy,
			StripPrefix:       "/api",
			Timeout:           25 * time.Second,
			EnableTrafficDump: true,
		},

		// Authentication service - Least Connections
		{
			Name:       "auth-service",
			PathPrefix: "/auth/",
			Methods:    []string{servex.POST, servex.PUT},
			Backends: []servex.Backend{
				{
					URL:                 "http://auth1.internal:8081",
					Weight:              1,
					HealthCheckPath:     "/ping",
					HealthCheckInterval: 15 * time.Second,
					MaxConnections:      50,
				},
				{
					URL:                 "http://auth2.internal:8081",
					Weight:              1,
					HealthCheckPath:     "/ping",
					HealthCheckInterval: 15 * time.Second,
					MaxConnections:      50,
				},
			},
			LoadBalancing:     servex.LeastConnectionsStrategy,
			StripPrefix:       "/auth",
			AddPrefix:         "/v1",
			Timeout:           10 * time.Second,
			EnableTrafficDump: true,
		},

		// User service - IP Hash (Session Affinity)
		{
			Name: "user-service",
			Host: "users.example.com",
			Backends: []servex.Backend{
				{
					URL:                 "http://users1.internal:8082",
					Weight:              1,
					HealthCheckPath:     "/status",
					HealthCheckInterval: 45 * time.Second,
					MaxConnections:      75,
				},
				{
					URL:                 "http://users2.internal:8082",
					Weight:              1,
					HealthCheckPath:     "/status",
					HealthCheckInterval: 45 * time.Second,
					MaxConnections:      75,
				},
			},
			LoadBalancing: servex.IPHashStrategy,
			Timeout:       20 * time.Second,
		},

		// Static CDN - Random Selection
		{
			Name:       "static-cdn",
			PathPrefix: "/static/",
			Methods:    []string{servex.GET, servex.HEAD},
			Backends: []servex.Backend{
				{
					URL:            "http://cdn1.internal:8083",
					Weight:         1,
					MaxConnections: 200,
				},
				{
					URL:            "http://cdn2.internal:8083",
					Weight:         1,
					MaxConnections: 200,
				},
				{
					URL:            "http://cdn3.internal:8083",
					Weight:         1,
					MaxConnections: 200,
				},
			},
			LoadBalancing: servex.RandomStrategy,
			StripPrefix:   "/static",
			Timeout:       15 * time.Second,
		},

		// Payment service - Round Robin with headers
		{
			Name:       "payment-service",
			PathPrefix: "/payments/",
			Methods:    []string{servex.POST, servex.GET},
			Headers:    map[string]string{"X-API-Version": "v2"},
			Backends: []servex.Backend{
				{
					URL:                 "http://payments1.internal:8084",
					Weight:              1,
					HealthCheckPath:     "/health",
					HealthCheckInterval: 20 * time.Second,
					MaxConnections:      30,
				},
				{
					URL:                 "http://payments2.internal:8084",
					Weight:              1,
					HealthCheckPath:     "/health",
					HealthCheckInterval: 20 * time.Second,
					MaxConnections:      30,
				},
			},
			LoadBalancing:     servex.RoundRobinStrategy,
			StripPrefix:       "/payments",
			Timeout:           30 * time.Second,
			EnableTrafficDump: true,
		},
	}
}

func registerCustomEndpoints(server *servex.Server) {
	// Service information endpoint
	server.GET("/info", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]any{
			"service":   serviceName,
			"version":   serviceVersion,
			"timestamp": time.Now().Format(time.RFC3339),
			"uptime":    time.Since(startTime).String(),
		})
	})

	// Proxy status and configuration
	server.GET("/proxy-status", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]any{
			"proxy_enabled":    true,
			"rules_count":      5, // Update based on actual rules
			"traffic_dump":     true,
			"health_check":     true,
			"load_strategies":  []string{"weighted_round_robin", "least_connections", "ip_hash", "random"},
			"monitoring_paths": []string{"/health", "/metrics", "/info", "/proxy-status"},
		})
	})

	// Load balancing strategies information
	server.GET("/strategies", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]any{
			"strategies": map[string]string{
				"weighted_round_robin": "Distributes requests based on backend weights",
				"least_connections":    "Routes to backend with fewest active connections",
				"ip_hash":              "Provides session affinity based on client IP",
				"random":               "Randomly selects backend for each request",
				"round_robin":          "Evenly distributes requests across backends",
			},
			"endpoints": map[string]string{
				"/api/*":            "weighted_round_robin",
				"/auth/*":           "least_connections",
				"users.example.com": "ip_hash",
				"/static/*":         "random",
				"/payments/*":       "round_robin",
			},
		})
	})
}

var startTime = time.Now()

func setupGracefulShutdown(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, initiating graceful shutdown...", sig)
		cancel()
	}()
}

func printStartupInfo(port string) {
	log.Printf("🚀 %s v%s starting on %s", serviceName, serviceVersion, port)
	log.Println("📊 Monitoring endpoints:")
	log.Println("   → /health       - Health check")
	log.Println("   → /metrics      - Prometheus metrics")
	log.Println("   → /info         - Service information")
	log.Println("   → /proxy-status - Proxy configuration")
	log.Println("   → /strategies   - Load balancing info")
	log.Println("")
	log.Println("🔀 Proxy endpoints:")
	log.Println("   → /api/*        - API backends (weighted round-robin)")
	log.Println("   → /auth/*       - Auth services (least connections)")
	log.Println("   → users.example.com - User service (IP hash)")
	log.Println("   → /static/*     - CDN backends (random)")
	log.Println("   → /payments/*   - Payment service (round-robin)")
	log.Println("")
	log.Println("🔧 Features enabled:")
	log.Println("   ✅ Health checking with automatic failover")
	log.Println("   ✅ Traffic dumping with 10% sampling")
	log.Println("   ✅ Security headers and rate limiting")
	log.Println("   ✅ Request filtering and monitoring")
	log.Println("   ✅ Comprehensive logging and metrics")
}

func showHelp() {
	fmt.Printf(`%s v%s - Advanced Proxy Gateway

USAGE:
    %s [OPTIONS]

OPTIONS:
    -config string    Configuration file path (default: %s)
    -port string      Server port (default: %s)
    -help            Show this help message

EXAMPLES:
    # Run with default configuration
    %s

    # Run with custom config file
    %s -config /etc/proxy/config.yaml

    # Run on different port
    %s -port :9090

    # Run with custom config and port
    %s -config custom.yaml -port :8443

CONFIGURATION:
    The server can be configured either via YAML file or programmatically.
    When a config file is provided and exists, it takes precedence.
    Otherwise, the server uses built-in programmatic configuration.

ENDPOINTS:
    /health           - Health check endpoint
    /metrics          - Prometheus metrics
    /info             - Service information
    /proxy-status     - Proxy configuration status
    /strategies       - Load balancing strategies info

For more information, see the README.md file.
`, serviceName, serviceVersion, os.Args[0], defaultConfigFile, defaultPort, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}
