package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex"
)

func main() {
	// Simple proxy configuration with two rules
	proxyConfig := servex.ProxyConfiguration{
		Enabled:         true,
		GlobalTimeout:   30 * time.Second,
		MaxIdleConns:    50,
		IdleConnTimeout: 90 * time.Second,

		// Enable traffic dumping
		TrafficDump: servex.TrafficDumpConfig{
			Enabled:     true,
			Directory:   "./traffic_logs",
			IncludeBody: true,
			MaxBodySize: 32 * 1024, // 32KB
			SampleRate:  0.5,       // Sample 50% of traffic
		},

		// Enable health checking
		HealthCheck: servex.HealthCheckConfig{
			Enabled:         true,
			DefaultInterval: 30 * time.Second,
			Timeout:         5 * time.Second,
			RetryCount:      2,
		},

		Rules: []servex.ProxyRule{
			{
				Name:       "api-service",
				PathPrefix: "/api/",
				Backends: []servex.Backend{
					{
						URL:                 "http://localhost:8081",
						Weight:              2,
						HealthCheckPath:     "/health",
						HealthCheckInterval: 30 * time.Second,
					},
					{
						URL:                 "http://localhost:8082",
						Weight:              1,
						HealthCheckPath:     "/health",
						HealthCheckInterval: 30 * time.Second,
					},
				},
				LoadBalancing:     servex.WeightedRoundRobinStrategy,
				StripPrefix:       "/api",
				Timeout:           20 * time.Second,
				EnableTrafficDump: true,
			},
			{
				Name:       "auth-service",
				PathPrefix: "/auth/",
				Backends: []servex.Backend{
					{
						URL:    "http://localhost:8083",
						Weight: 1,
					},
				},
				LoadBalancing: servex.RoundRobinStrategy,
				StripPrefix:   "/auth",
				Timeout:       15 * time.Second,
			},
		},
	}

	// Create server with proxy
	server, err := servex.New(
		servex.WithProxyConfig(proxyConfig),
		servex.WithHealthEndpoint(),
		servex.WithDefaultMetrics(),
		servex.WithRPM(100), // Rate limit: 100 requests per minute
	)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Add a status endpoint
	server.GET("/status", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]interface{}{
			"proxy_enabled": true,
			"rules":         len(proxyConfig.Rules),
			"timestamp":     time.Now().Format(time.RFC3339),
		})
	})

	// Start the proxy server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Println("Starting simple proxy server on :8080")
	log.Println("Proxy rules:")
	log.Println("  /api/* -> localhost:8081 (weight 2), localhost:8082 (weight 1)")
	log.Println("  /auth/* -> localhost:8083")
	log.Println("Endpoints:")
	log.Println("  /status -> Proxy status")
	log.Println("  /health -> Health check")
	log.Println("  /metrics -> Metrics")

	if err := server.StartWithShutdown(ctx, ":8080", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

/*
To test this example, you can create simple backend servers:

# Backend 1 (port 8081)
curl -X POST http://localhost:8081/health -d '{"status": "ok"}'

# Backend 2 (port 8082)
curl -X POST http://localhost:8082/health -d '{"status": "ok"}'

# Auth service (port 8083)
curl -X POST http://localhost:8083/login -d '{"username": "test"}'

Then test the proxy:
curl http://localhost:8080/api/users      # -> goes to 8081 or 8082 (weighted)
curl http://localhost:8080/auth/login     # -> goes to 8083
curl http://localhost:8080/status         # -> proxy status
curl http://localhost:8080/health         # -> health check
curl http://localhost:8080/metrics        # -> metrics

Check traffic dumps in ./traffic_logs/ directory.
*/
