package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex"
)

func main() {
	// Configure the reverse proxy with multiple rules and backends
	proxyConfig := servex.ProxyConfiguration{
		Enabled: true,

		// Global settings
		GlobalTimeout:       30 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,

		// Traffic dumping configuration
		TrafficDump: servex.TrafficDumpConfig{
			Enabled:     true,
			Directory:   "./traffic_dumps",
			MaxFileSize: 100 * 1024 * 1024, // 100MB
			MaxFiles:    10,
			IncludeBody: true,
			MaxBodySize: 64 * 1024, // 64KB
			SampleRate:  1.0,       // Dump all traffic
		},

		// Health check configuration
		HealthCheck: servex.HealthCheckConfig{
			Enabled:         true,
			DefaultInterval: 30 * time.Second,
			Timeout:         5 * time.Second,
			RetryCount:      3,
		},

		// Proxy rules
		Rules: []servex.ProxyRule{
			{
				Name:       "api-backend",
				PathPrefix: "/api/",
				Methods:    []string{"GET", "POST", "PUT", "DELETE"},
				Backends: []servex.Backend{
					{
						URL:                 "http://api1.example.com:8080",
						Weight:              2,
						HealthCheckPath:     "/health",
						HealthCheckInterval: 30 * time.Second,
						MaxConnections:      50,
					},
					{
						URL:                 "http://api2.example.com:8080",
						Weight:              1,
						HealthCheckPath:     "/health",
						HealthCheckInterval: 30 * time.Second,
						MaxConnections:      50,
					},
					{
						URL:                 "http://api3.example.com:8080",
						Weight:              3,
						HealthCheckPath:     "/health",
						HealthCheckInterval: 30 * time.Second,
						MaxConnections:      100,
					},
				},
				LoadBalancing:     servex.WeightedRoundRobinStrategy,
				StripPrefix:       "/api",
				Timeout:           25 * time.Second,
				EnableTrafficDump: true,
			},
			{
				Name:       "auth-service",
				PathPrefix: "/auth/",
				Methods:    []string{"POST"},
				Backends: []servex.Backend{
					{
						URL:                 "http://auth1.example.com:8081",
						Weight:              1,
						HealthCheckPath:     "/ping",
						HealthCheckInterval: 15 * time.Second,
						MaxConnections:      30,
					},
					{
						URL:                 "http://auth2.example.com:8081",
						Weight:              1,
						HealthCheckPath:     "/ping",
						HealthCheckInterval: 15 * time.Second,
						MaxConnections:      30,
					},
				},
				LoadBalancing:     servex.LeastConnectionsStrategy,
				StripPrefix:       "/auth",
				AddPrefix:         "/v1",
				Timeout:           10 * time.Second,
				EnableTrafficDump: true,
			},
			{
				Name: "user-service",
				Host: "users.myapp.com",
				Backends: []servex.Backend{
					{
						URL:                 "http://users1.internal:8082",
						Weight:              1,
						HealthCheckPath:     "/status",
						HealthCheckInterval: 45 * time.Second,
						MaxConnections:      25,
					},
					{
						URL:                 "http://users2.internal:8082",
						Weight:              1,
						HealthCheckPath:     "/status",
						HealthCheckInterval: 45 * time.Second,
						MaxConnections:      25,
					},
				},
				LoadBalancing: servex.IPHashStrategy, // Session affinity
				Timeout:       20 * time.Second,
			},
			{
				Name:       "static-content",
				PathPrefix: "/static/",
				Methods:    []string{"GET", "HEAD"},
				Backends: []servex.Backend{
					{
						URL:            "http://cdn1.example.com:8083",
						Weight:         1,
						MaxConnections: 100,
					},
					{
						URL:            "http://cdn2.example.com:8083",
						Weight:         1,
						MaxConnections: 100,
					},
					{
						URL:            "http://cdn3.example.com:8083",
						Weight:         1,
						MaxConnections: 100,
					},
				},
				LoadBalancing: servex.RandomStrategy,
				StripPrefix:   "/static",
				Timeout:       15 * time.Second,
			},
		},
	}

	// Create server with proxy and other middleware
	server, err := servex.NewServer(
		servex.WithProxyConfig(proxyConfig),
		servex.WithHealthEndpoint(),
		servex.WithDefaultMetrics(),

		// Security features
		servex.WithSecurityHeaders(),
		servex.WithRPM(1000), // 1000 requests per minute

		// Filtering
		servex.WithBlockedUserAgentsRegex("(?i)(bot|crawler|spider|scraper)"),

		// Logging
		servex.WithLogFields("method", "url", "status", "duration", "ip", "user_agent"),

		// Error handling
		servex.WithSendErrorToClient(), // Only for development
	)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Register some non-proxy routes (these will not be proxied)
	server.GET("/info", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]interface{}{
			"service":   "api-gateway",
			"version":   "1.0.0",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	server.GET("/proxy-status", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]interface{}{
			"proxy_enabled": true,
			"rules_count":   len(proxyConfig.Rules),
			"traffic_dump":  proxyConfig.TrafficDump.Enabled,
			"health_check":  proxyConfig.HealthCheck.Enabled,
		})
	})

	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Println("Starting API Gateway on :8080")
	log.Println("Proxy endpoints:")
	log.Println("  - /api/* -> API backends (weighted round-robin)")
	log.Println("  - /auth/* -> Auth services (least connections)")
	log.Println("  - users.myapp.com/* -> User service (IP hash)")
	log.Println("  - /static/* -> CDN backends (random)")
	log.Println("Non-proxy endpoints:")
	log.Println("  - /info -> Server information")
	log.Println("  - /proxy-status -> Proxy configuration status")
	log.Println("  - /health -> Health check")
	log.Println("  - /metrics -> Prometheus metrics")

	if err := server.StartWithShutdown(ctx, ":8080", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
