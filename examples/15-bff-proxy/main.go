package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

// This example demonstrates a Backend-for-Frontend (BFF) gateway that
// aggregates three mock microservices with load balancing, health checks,
// and circuit breakers.
//
// Architecture:
//
//	Client → BFF Gateway (:8080)
//	           ├─ /api/users/*    → User Service    (:9001, :9002) weighted round-robin
//	           ├─ /api/products/* → Product Service  (:9003)        round-robin
//	           ├─ /api/orders/*   → Order Service    (:9004)        least-connections
//	           └─ /bff/dashboard  → Aggregation endpoint (calls all three)
//
// Run:
//
//	go run main.go
//
// Test:
//
//	# Direct proxy to user service (load balanced across 2 instances)
//	curl -s http://localhost:8080/api/users/ | jq .
//
//	# Direct proxy to product service
//	curl -s http://localhost:8080/api/products/ | jq .
//
//	# Direct proxy to order service
//	curl -s http://localhost:8080/api/orders/ | jq .
//
//	# BFF aggregation endpoint (calls all backends, combines results)
//	curl -s http://localhost:8080/bff/dashboard | jq .
//
//	# Backend health status
//	curl -s http://localhost:8080/bff/status | jq .
//
//	# Gateway health
//	curl -s http://localhost:8080/health | jq .
func main() {
	// Start mock backend services
	go startUserService(":9001", "user-1")
	go startUserService(":9002", "user-2")
	go startProductService(":9003")
	go startOrderService(":9004")
	time.Sleep(100 * time.Millisecond) // let backends start

	proxyConfig := servex.ProxyConfiguration{
		Enabled:       true,
		GlobalTimeout: 10 * time.Second,
		MaxIdleConns:  50,
		HealthCheck: servex.HealthCheckConfig{
			Enabled:         true,
			DefaultInterval: 15 * time.Second,
			Timeout:         3 * time.Second,
		},
		CircuitBreaker: servex.CircuitBreakerConfig{
			Enabled:   true,
			Threshold: 5,
			Timeout:   30 * time.Second,
		},
		Rules: []servex.ProxyRule{
			{
				Name:          "users",
				PathPrefix:    "/api/users",
				StripPrefix:   "/api/users",
				LoadBalancing: servex.WeightedRoundRobinStrategy,
				Backends: []servex.Backend{
					{URL: "http://localhost:9001", Weight: 2, HealthCheckPath: "/health"},
					{URL: "http://localhost:9002", Weight: 1, HealthCheckPath: "/health"},
				},
			},
			{
				Name:          "products",
				PathPrefix:    "/api/products",
				StripPrefix:   "/api/products",
				LoadBalancing: servex.RoundRobinStrategy,
				Backends: []servex.Backend{
					{URL: "http://localhost:9003", HealthCheckPath: "/health"},
				},
			},
			{
				Name:          "orders",
				PathPrefix:    "/api/orders",
				StripPrefix:   "/api/orders",
				LoadBalancing: servex.LeastConnectionsStrategy,
				Backends: []servex.Backend{
					{URL: "http://localhost:9004", HealthCheckPath: "/health"},
				},
			},
		},
	}

	server, err := servex.NewServer(servex.MergePresets(
		servex.MicroservicePreset(),
		servex.ScannerBlockPreset(),
		[]servex.Option{
			servex.WithProxyConfig(proxyConfig),
			servex.WithCORS(),
		},
	)...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// BFF aggregation endpoints (custom handlers alongside proxy rules)
	server.GET("/bff/dashboard", dashboardHandler)
	server.GET("/bff/status", statusHandler)

	fmt.Println("Servex BFF Proxy Gateway")
	fmt.Println("Gateway: http://localhost:8080")
	fmt.Println()
	fmt.Println("Proxy routes:")
	fmt.Println("  /api/users/*    → :9001, :9002 (weighted round-robin 2:1)")
	fmt.Println("  /api/products/* → :9003 (round-robin)")
	fmt.Println("  /api/orders/*   → :9004 (least-connections)")
	fmt.Println()
	fmt.Println("BFF endpoints:")
	fmt.Println("  GET /bff/dashboard — Aggregated data from all services")
	fmt.Println("  GET /bff/status    — Backend health status")
	fmt.Println("  GET /health        — Gateway health")
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")

	if err := server.StartWithWaitSignalsHTTP(context.Background(), ":8080"); err != nil {
		log.Fatal(err)
	}
}

// dashboardHandler aggregates data from all three backend services.
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)

	type result struct {
		key  string
		data json.RawMessage
		err  error
	}

	endpoints := map[string]string{
		"users":    "http://localhost:9001/",
		"products": "http://localhost:9003/",
		"orders":   "http://localhost:9004/",
	}

	ch := make(chan result, len(endpoints))
	client := &http.Client{Timeout: 5 * time.Second}

	for key, url := range endpoints {
		go func(key, url string) {
			resp, err := client.Get(url)
			if err != nil {
				ch <- result{key: key, err: err}
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			ch <- result{key: key, data: body, err: err}
		}(key, url)
	}

	dashboard := make(map[string]any)
	for range endpoints {
		res := <-ch
		if res.err != nil {
			dashboard[res.key] = map[string]string{"error": res.err.Error()}
		} else {
			var data any
			json.Unmarshal(res.data, &data)
			dashboard[res.key] = data
		}
	}
	dashboard["aggregated_at"] = time.Now().UTC().Format(time.RFC3339)

	ctx.JSON(dashboard)
}

// statusHandler shows the health status of each backend.
func statusHandler(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)

	backends := []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}{
		{"user-1", "http://localhost:9001/health"},
		{"user-2", "http://localhost:9002/health"},
		{"products", "http://localhost:9003/health"},
		{"orders", "http://localhost:9004/health"},
	}

	type backendStatus struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Healthy bool   `json:"healthy"`
		Latency string `json:"latency,omitempty"`
	}

	client := &http.Client{Timeout: 2 * time.Second}
	var wg sync.WaitGroup
	results := make([]backendStatus, len(backends))

	for i, b := range backends {
		wg.Add(1)
		go func(i int, name, url string) {
			defer wg.Done()
			start := time.Now()
			resp, err := client.Get(url)
			latency := time.Since(start)

			results[i] = backendStatus{
				Name:    name,
				URL:     url,
				Healthy: err == nil && resp != nil && resp.StatusCode == 200,
				Latency: latency.Round(time.Millisecond).String(),
			}
			if resp != nil {
				resp.Body.Close()
			}
		}(i, b.Name, b.URL)
	}
	wg.Wait()

	ctx.JSON(map[string]any{
		"backends":   results,
		"checked_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// --- Mock Backend Services ---

func startUserService(addr, instanceID string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "instance": instanceID})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"instance": instanceID,
			"users": []map[string]any{
				{"id": "u1", "name": "Alice Johnson", "email": "alice@example.com"},
				{"id": "u2", "name": "Bob Smith", "email": "bob@example.com"},
				{"id": "u3", "name": "Charlie Brown", "email": "charlie@example.com"},
			},
		})
	})
	http.ListenAndServe(addr, mux)
}

func startProductService(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"products": []map[string]any{
				{"id": "p1", "name": "Laptop Pro", "price": 1299.99, "stock": 45},
				{"id": "p2", "name": "Wireless Mouse", "price": 29.99, "stock": 200},
				{"id": "p3", "name": "USB-C Hub", "price": 49.99, "stock": 150},
			},
		})
	})
	http.ListenAndServe(addr, mux)
}

func startOrderService(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"orders": []map[string]any{
				{"id": "o1", "user_id": "u1", "product_id": "p1", "quantity": 1, "status": "shipped"},
				{"id": "o2", "user_id": "u2", "product_id": "p2", "quantity": 3, "status": "pending"},
				{"id": "o3", "user_id": "u1", "product_id": "p3", "quantity": 2, "status": "delivered"},
			},
		})
	})
	http.ListenAndServe(addr, mux)
}
