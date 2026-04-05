package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

// This example demonstrates a production-ready microservice template
// with health checks, metrics, rate limiting, scanner blocking,
// graceful shutdown, and environment-based configuration.
//
// Run:
//
//	go run main.go
//
// Environment variables:
//
//	PORT=:8080              # HTTP port (default :8080)
//	ENVIRONMENT=production  # Environment name (default development)
//	RATE_LIMIT_RPS=100      # Requests per second (default 100)
//
// Test:
//
//	# Health check (Kubernetes probe)
//	curl -s http://localhost:8080/health | jq .
//
//	# Service info
//	curl -s http://localhost:8080/api/v1/info | jq .
//
//	# Process a request
//	curl -s -X POST http://localhost:8080/api/v1/process \
//	  -H "Content-Type: application/json" \
//	  -d '{"data":"hello world"}' | jq .
//
//	# Service status with counters
//	curl -s http://localhost:8080/api/v1/status | jq .
//
//	# Metrics (Prometheus-compatible)
//	curl -s http://localhost:8080/metrics
func main() {
	port := envOr("PORT", ":8080")
	env := envOr("ENVIRONMENT", "development")
	rps := envIntOr("RATE_LIMIT_RPS", 100)

	server, err := servex.NewServer(servex.MergePresets(
		servex.ProductionPreset(),
		servex.ScannerBlockPreset(),
		[]servex.Option{
			servex.WithRPS(rps),
			servex.WithBurstSize(rps * 2),
			servex.WithCustomHeaders(map[string]string{
				"X-Service-Name":    serviceName,
				"X-Service-Version": serviceVersion,
			}),
		},
	)...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	svc := &service{
		env:       env,
		startTime: time.Now(),
	}

	api := server.Group("/api/v1")
	api.GET("/info", svc.infoHandler)
	api.POST("/process", svc.processHandler)
	api.GET("/status", svc.statusHandler)

	fmt.Printf("[%s] Starting %s v%s (env=%s, rps=%d)\n",
		time.Now().Format(time.RFC3339), serviceName, serviceVersion, env, rps)
	fmt.Printf("[%s] Endpoints:\n", time.Now().Format(time.RFC3339))
	fmt.Printf("  Health:  http://localhost%s/health\n", port)
	fmt.Printf("  Metrics: http://localhost%s/metrics\n", port)
	fmt.Printf("  Info:    http://localhost%s/api/v1/info\n", port)
	fmt.Printf("  Process: http://localhost%s/api/v1/process\n", port)
	fmt.Printf("  Status:  http://localhost%s/api/v1/status\n", port)
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")

	if err := server.StartWithWaitSignalsHTTP(context.Background(), port); err != nil {
		log.Fatal(err)
	}
}

const (
	serviceName    = "example-microservice"
	serviceVersion = "1.0.0"
)

type service struct {
	env           string
	startTime     time.Time
	requestCount  atomic.Int64
	processedCount atomic.Int64
}

// infoHandler returns service metadata.
func (s *service) infoHandler(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	s.requestCount.Add(1)

	ctx.JSON(map[string]any{
		"service":     serviceName,
		"version":     serviceVersion,
		"environment": s.env,
		"uptime":      time.Since(s.startTime).Round(time.Second).String(),
		"go_version":  runtime.Version(),
		"num_cpu":     runtime.NumCPU(),
		"goroutines":  runtime.NumGoroutine(),
	})
}

// processHandler simulates a work endpoint.
func (s *service) processHandler(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	s.requestCount.Add(1)

	var req struct {
		Data string `json:"data"`
	}
	if err := ctx.ReadJSON(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}
	if req.Data == "" {
		ctx.BadRequest(nil, "data field is required")
		return
	}

	// Simulate processing
	time.Sleep(50 * time.Millisecond)
	s.processedCount.Add(1)

	ctx.JSON(map[string]any{
		"status":       "processed",
		"data_length":  len(req.Data),
		"processed_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// statusHandler returns operational status with request counters.
func (s *service) statusHandler(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	s.requestCount.Add(1)

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	ctx.JSON(map[string]any{
		"status":          "healthy",
		"uptime":          time.Since(s.startTime).Round(time.Second).String(),
		"total_requests":  s.requestCount.Load(),
		"total_processed": s.processedCount.Load(),
		"memory": map[string]any{
			"alloc_mb":       float64(m.Alloc) / 1024 / 1024,
			"sys_mb":         float64(m.Sys) / 1024 / 1024,
			"num_gc":         m.NumGC,
			"goroutines":     runtime.NumGoroutine(),
		},
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
