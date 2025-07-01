package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

func main() {
	log.Println("=== Servex Simple Proxy Example ===")
	log.Println("This example demonstrates a simple reverse proxy with load balancing.")
	log.Println("")

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
	server, err := servex.NewServer(
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
			"message":       "Proxy server is running",
		})
	})

	// Add a simple info endpoint
	server.GET("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.SetHeader("Content-Type", "text/html")
		ctx.Response(200, `
<!DOCTYPE html>
<html>
<head><title>Servex Simple Proxy</title></head>
<body>
    <h1>Servex Simple Proxy Example</h1>
    <p>This proxy server demonstrates:</p>
    <ul>
        <li>Load balancing between multiple backends</li>
        <li>Health checking of backend services</li>
        <li>Traffic dumping for debugging</li>
        <li>Rate limiting and metrics</li>
    </ul>
    <h2>Proxy Rules:</h2>
    <ul>
        <li><strong>/api/*</strong> → localhost:8081 (weight 2), localhost:8082 (weight 1)</li>
        <li><strong>/auth/*</strong> → localhost:8083</li>
    </ul>
    <h2>Endpoints:</h2>
    <ul>
        <li><a href="/status">/status</a> - Proxy status</li>
        <li><a href="/health">/health</a> - Health check</li>
        <li><a href="/metrics">/metrics</a> - Metrics</li>
    </ul>
    <p><strong>Note:</strong> You need to start backend services on ports 8081, 8082, and 8083 for the proxy to work.</p>
</body>
</html>`)
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
	log.Println("  / -> Info page")
	log.Println("")
	log.Println("Traffic dumps will be saved to ./traffic_logs/")
	log.Println("")
	log.Println("To test, start backend services on ports 8081, 8082, 8083")
	log.Println("Then visit: http://localhost:8080")

	if err := server.StartWithShutdown(ctx, ":8080", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

/*
To test this example, you can create simple backend servers:

# Backend 1 (port 8081) - Simple Go server
echo 'package main
import ("fmt"; "net/http")
func main() {
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"status": "ok", "service": "backend-1"}`)
    })
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"message": "Hello from backend 1", "port": 8081}`)
    })
    fmt.Println("Backend 1 starting on :8081")
    http.ListenAndServe(":8081", nil)
}' > backend1.go && go run backend1.go &

# Backend 2 (port 8082) - Simple Go server
echo 'package main
import ("fmt"; "net/http")
func main() {
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"status": "ok", "service": "backend-2"}`)
    })
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"message": "Hello from backend 2", "port": 8082}`)
    })
    fmt.Println("Backend 2 starting on :8082")
    http.ListenAndServe(":8082", nil)
}' > backend2.go && go run backend2.go &

# Auth service (port 8083) - Simple Go server
echo 'package main
import ("fmt"; "net/http")
func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"message": "Auth service", "endpoint": "%s"}`, r.URL.Path)
    })
    fmt.Println("Auth service starting on :8083")
    http.ListenAndServe(":8083", nil)
}' > auth.go && go run auth.go &

Then test the proxy:
curl http://localhost:8080/api/users      # -> goes to 8081 or 8082 (weighted)
curl http://localhost:8080/auth/login     # -> goes to 8083
curl http://localhost:8080/status         # -> proxy status
curl http://localhost:8080/health         # -> health check
curl http://localhost:8080/metrics        # -> metrics

Check traffic dumps in ./traffic_logs/ directory.
*/
