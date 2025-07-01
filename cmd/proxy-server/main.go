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

var (
	configFile = flag.String("config", "proxy-config.yaml", "Path to YAML configuration file")
	version    = flag.Bool("version", false, "Show version information")
)

const appVersion = "1.0.0"

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("Servex Proxy Server v%s\n", appVersion)
		fmt.Println("A high-performance L7 reverse proxy and API gateway")
		os.Exit(0)
	}

	// Check if config file exists
	if _, err := os.Stat(*configFile); os.IsNotExist(err) {
		log.Fatalf("Configuration file not found: %s", *configFile)
	}

	// Load configuration from YAML file
	log.Printf("Loading configuration from: %s", *configFile)
	config, err := servex.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Validate proxy configuration
	if !config.Proxy.Enabled {
		log.Fatal("Proxy is not enabled in configuration file")
	}

	if len(config.Proxy.Rules) == 0 {
		log.Fatal("No proxy rules defined in configuration file")
	}

	// Create server from configuration
	log.Println("Initializing proxy server...")
	server, err := servex.NewFromConfig(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Add management endpoints
	addManagementEndpoints(server, config)

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

	// Get server configuration
	baseConfig := config.ToBaseConfig()

	// Log startup information
	logStartupInfo(config, baseConfig)

	// Start server
	log.Println("Starting proxy server...")
	if err := server.StartWithShutdown(ctx, baseConfig.HTTP, baseConfig.HTTPS); err != nil {
		log.Fatalf("Server failed: %v", err)
	}

	log.Println("Proxy server shutdown complete")
}

func addManagementEndpoints(server *servex.Server, config *servex.Config) {
	// Proxy status endpoint
	server.GET("/proxy/status", func(w http.ResponseWriter, r *http.Request) {
		status := map[string]interface{}{
			"service":       "servex-proxy",
			"version":       appVersion,
			"timestamp":     time.Now().Format(time.RFC3339),
			"proxy_enabled": config.Proxy.Enabled,
			"rules_count":   len(config.Proxy.Rules),
			"traffic_dump":  config.Proxy.TrafficDump.Enabled,
			"health_check":  config.Proxy.HealthCheck.Enabled,
		}

		if config.Proxy.TrafficDump.Enabled {
			status["dump_directory"] = config.Proxy.TrafficDump.Directory
			status["sample_rate"] = config.Proxy.TrafficDump.SampleRate
		}

		servex.C(w, r).JSON(status)
	})

	// Backend status endpoint
	server.GET("/proxy/backends", func(w http.ResponseWriter, r *http.Request) {
		backends := make(map[string]interface{})

		for i := range config.Proxy.Rules {
			rule := &config.Proxy.Rules[i]
			ruleInfo := map[string]interface{}{
				"name":           rule.Name,
				"path_prefix":    rule.PathPrefix,
				"host":           rule.Host,
				"load_balancing": rule.LoadBalancing,
				"timeout":        rule.Timeout.String(),
				"backend_count":  len(rule.Backends),
				"backends":       make([]map[string]interface{}, 0),
			}

			for i := range rule.Backends {
				backend := &rule.Backends[i]
				backendInfo := map[string]interface{}{
					"url":                   backend.URL,
					"weight":                backend.Weight,
					"max_connections":       backend.MaxConnections,
					"health_check_path":     backend.HealthCheckPath,
					"health_check_interval": backend.HealthCheckInterval.String(),
				}
				ruleInfo["backends"] = append(ruleInfo["backends"].([]map[string]interface{}), backendInfo)
			}

			backends[rule.Name] = ruleInfo
		}

		servex.C(w, r).JSON(backends)
	})

	// Configuration endpoint (for debugging)
	server.GET("/proxy/config", func(w http.ResponseWriter, r *http.Request) {
		// Return sanitized configuration (without sensitive data)
		sanitizedConfig := map[string]interface{}{
			"proxy": map[string]interface{}{
				"enabled":                 config.Proxy.Enabled,
				"global_timeout":          config.Proxy.GlobalTimeout.String(),
				"max_idle_conns":          config.Proxy.MaxIdleConns,
				"max_idle_conns_per_host": config.Proxy.MaxIdleConnsPerHost,
				"idle_conn_timeout":       config.Proxy.IdleConnTimeout.String(),
				"traffic_dump":            config.Proxy.TrafficDump,
				"health_check":            config.Proxy.HealthCheck,
				"rules_count":             len(config.Proxy.Rules),
			},
			"rate_limit": map[string]interface{}{
				"enabled":               config.RateLimit.Enabled,
				"requests_per_interval": config.RateLimit.RequestsPerInterval,
				"interval":              config.RateLimit.Interval.String(),
			},
			"security": map[string]interface{}{
				"enabled": config.Security.Enabled,
			},
			"filter": map[string]interface{}{
				"blocked_user_agents_regex": config.Filter.BlockedUserAgentsRegex,
			},
		}

		servex.C(w, r).JSON(sanitizedConfig)
	})

	// Health endpoint with backend health
	server.GET("/proxy/health", func(w http.ResponseWriter, r *http.Request) {
		health := map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().Format(time.RFC3339),
			"uptime":    time.Since(time.Now()).String(), // This would be calculated from start time
			"rules":     make(map[string]interface{}),
		}

		for i := range config.Proxy.Rules {
			rule := &config.Proxy.Rules[i]
			ruleHealth := map[string]interface{}{
				"total_backends":     len(rule.Backends),
				"healthy_backends":   0, // This would be calculated from actual backend health
				"unhealthy_backends": 0,
			}

			// Note: In a real implementation, you'd get actual health status from the proxy manager
			health["rules"].(map[string]interface{})[rule.Name] = ruleHealth
		}

		servex.C(w, r).JSON(health)
	})
}

func logStartupInfo(config *servex.Config, baseConfig servex.BaseConfig) {
	log.Println("=== Servex Proxy Server ===")
	log.Printf("Version: %s", appVersion)
	log.Printf("Config file: %s", *configFile)

	if baseConfig.HTTP != "" {
		log.Printf("HTTP server: %s", baseConfig.HTTP)
	}
	if baseConfig.HTTPS != "" {
		log.Printf("HTTPS server: %s", baseConfig.HTTPS)
	}

	log.Println("\n=== Proxy Configuration ===")
	log.Printf("Rules: %d", len(config.Proxy.Rules))

	for i := range config.Proxy.Rules {
		rule := &config.Proxy.Rules[i]
		log.Printf("Rule '%s':", rule.Name)
		if rule.PathPrefix != "" {
			log.Printf("  Path: %s", rule.PathPrefix)
		}
		if rule.Host != "" {
			log.Printf("  Host: %s", rule.Host)
		}
		log.Printf("  Backends: %d", len(rule.Backends))
		log.Printf("  Load Balancing: %s", rule.LoadBalancing)
		log.Printf("  Timeout: %s", rule.Timeout)

		for i := range rule.Backends {
			backend := &rule.Backends[i]
			log.Printf("    Backend %d: %s (weight: %d)", i+1, backend.URL, backend.Weight)
			if backend.HealthCheckPath != "" {
				log.Printf("      Health check: %s (every %s)", backend.HealthCheckPath, backend.HealthCheckInterval)
			}
		}
	}

	if config.Proxy.TrafficDump.Enabled {
		log.Println("\n=== Traffic Dumping ===")
		log.Printf("Directory: %s", config.Proxy.TrafficDump.Directory)
		log.Printf("Sample rate: %.1f%%", config.Proxy.TrafficDump.SampleRate*100)
		log.Printf("Include body: %v", config.Proxy.TrafficDump.IncludeBody)
	}

	if config.RateLimit.Enabled {
		log.Println("\n=== Rate Limiting ===")
		log.Printf("Limit: %d requests per %s", config.RateLimit.RequestsPerInterval, config.RateLimit.Interval)
	}

	log.Println("\n=== Management Endpoints ===")
	log.Println("  /proxy/status   - Proxy status and statistics")
	log.Println("  /proxy/backends - Backend configuration and health")
	log.Println("  /proxy/config   - Current configuration")
	log.Println("  /proxy/health   - Health check with backend status")
	log.Println("  /health         - Simple health check")
	log.Println("  /metrics        - Prometheus metrics")
	log.Println()
}
