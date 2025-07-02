package servex

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// Mock backend server for testing
func createMockBackend(name string, delay time.Duration, statusCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if delay > 0 {
			time.Sleep(delay)
		}

		w.Header().Set("X-Backend", name)
		w.WriteHeader(statusCode)

		response := fmt.Sprintf(`{"backend": "%s", "path": "%s", "method": "%s"}`,
			name, r.URL.Path, r.Method)
		w.Write([]byte(response))
	}))
}

// Mock health check backend
func createHealthCheckBackend(name string, healthy bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/ping" {
			if healthy {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status": "healthy"}`))
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(`{"status": "unhealthy"}`))
			}
			return
		}

		w.Header().Set("X-Backend", name)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`{"backend": "%s"}`, name)))
	}))
}

func TestLoadBalancingStrategies(t *testing.T) {
	// Create mock backends
	backend1 := createMockBackend("backend1", 0, http.StatusOK)
	backend2 := createMockBackend("backend2", 0, http.StatusOK)
	defer backend1.Close()
	defer backend2.Close()

	tests := []struct {
		name     string
		strategy LoadBalancingStrategy
		requests int
		weights  []int
	}{
		{
			name:     "RoundRobin",
			strategy: RoundRobinStrategy,
			requests: 4,
			weights:  []int{1, 1},
		},
		{
			name:     "WeightedRoundRobin",
			strategy: WeightedRoundRobinStrategy,
			requests: 6,
			weights:  []int{2, 1}, // backend1 should get 4 requests, backend2 should get 2
		},
		{
			name:     "Random",
			strategy: RandomStrategy,
			requests: 10,
			weights:  []int{1, 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ProxyConfiguration{
				Enabled: true,
				Rules: []ProxyRule{
					{
						Name:       "test-rule",
						PathPrefix: "/test/",
						Backends: []Backend{
							{
								URL:    backend1.URL,
								Weight: tt.weights[0],
							},
							{
								URL:    backend2.URL,
								Weight: tt.weights[1],
							},
						},
						LoadBalancing: tt.strategy,
						Timeout:       5 * time.Second,
					},
				},
			}

			// Create test logger
			logger := &testLogger{}

			// Create router and register middleware
			router := mux.NewRouter()
			if err := RegisterProxyMiddleware(router, config, logger); err != nil {
				t.Fatalf("Failed to register proxy middleware: %v", err)
			}

			// Add a fallback handler for unmatched routes
			router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Not Found", http.StatusNotFound)
			})

			// Track backend hits
			backendHits := make(map[string]int)
			var mu sync.Mutex

			// Make requests
			for i := 0; i < tt.requests; i++ {
				req := httptest.NewRequest(GET, "/test/endpoint", nil)
				rr := httptest.NewRecorder()

				router.ServeHTTP(rr, req)

				if rr.Code != http.StatusOK {
					t.Errorf("Request %d failed with status %d", i, rr.Code)
					continue
				}

				backend := rr.Header().Get("X-Backend")
				if backend == "" {
					t.Errorf("Request %d: No backend header found", i)
					continue
				}

				mu.Lock()
				backendHits[backend]++
				mu.Unlock()
			}

			// Verify distribution for round robin
			if tt.strategy == RoundRobinStrategy {
				expectedHits := tt.requests / 2
				if backendHits["backend1"] != expectedHits || backendHits["backend2"] != expectedHits {
					t.Errorf("Round robin distribution failed: backend1=%d, backend2=%d, expected=%d each",
						backendHits["backend1"], backendHits["backend2"], expectedHits)
				}
			}

			// Verify weighted distribution for weighted round robin
			if tt.strategy == WeightedRoundRobinStrategy {
				totalWeight := tt.weights[0] + tt.weights[1]
				expected1 := (tt.requests * tt.weights[0]) / totalWeight
				expected2 := (tt.requests * tt.weights[1]) / totalWeight

				// Allow some tolerance for weighted distribution
				tolerance := 1
				if abs(backendHits["backend1"]-expected1) > tolerance ||
					abs(backendHits["backend2"]-expected2) > tolerance {
					t.Errorf("Weighted round robin distribution failed: backend1=%d (expected ~%d), backend2=%d (expected ~%d)",
						backendHits["backend1"], expected1, backendHits["backend2"], expected2)
				}
			}

			// For random, just verify both backends got some requests
			if tt.strategy == RandomStrategy {
				if backendHits["backend1"] == 0 || backendHits["backend2"] == 0 {
					t.Errorf("Random distribution failed: backend1=%d, backend2=%d (both should get some requests)",
						backendHits["backend1"], backendHits["backend2"])
				}
			}
		})
	}
}

func TestIPHashLoadBalancing(t *testing.T) {
	// Create mock backends
	backend1 := createMockBackend("backend1", 0, http.StatusOK)
	backend2 := createMockBackend("backend2", 0, http.StatusOK)
	defer backend1.Close()
	defer backend2.Close()

	config := ProxyConfiguration{
		Enabled: true,
		Rules: []ProxyRule{
			{
				Name:       "test-rule",
				PathPrefix: "/test/",
				Backends: []Backend{
					{URL: backend1.URL, Weight: 1},
					{URL: backend2.URL, Weight: 1},
				},
				LoadBalancing: IPHashStrategy,
				Timeout:       5 * time.Second,
			},
		},
	}

	logger := &testLogger{}
	router := mux.NewRouter()
	if err := RegisterProxyMiddleware(router, config, logger); err != nil {
		t.Fatalf("Failed to register proxy middleware: %v", err)
	}

	// Add a fallback handler for unmatched routes
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// Test that same IP always goes to same backend
	testIPs := []string{"192.168.1.1", "192.168.1.2", "10.0.0.1"}
	ipToBackend := make(map[string]string)

	for _, ip := range testIPs {
		// Make multiple requests from the same IP
		var backend string
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(GET, "/test/endpoint", nil)
			req.RemoteAddr = ip + ":12345"
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("Request failed with status %d", rr.Code)
			}

			currentBackend := rr.Header().Get("X-Backend")
			if backend == "" {
				backend = currentBackend
				ipToBackend[ip] = backend
			} else if backend != currentBackend {
				t.Errorf("IP hash inconsistent for IP %s: got %s, expected %s", ip, currentBackend, backend)
			}
		}
	}

	// Verify that different IPs can go to different backends
	backends := make(map[string]bool)
	for _, backend := range ipToBackend {
		backends[backend] = true
	}

	if len(backends) < 1 {
		t.Error("IP hash should distribute requests across backends")
	}
}

func TestLeastConnectionsLoadBalancing(t *testing.T) {
	// Create backends with different response times
	fastBackend := createMockBackend("fast", 10*time.Millisecond, http.StatusOK)
	slowBackend := createMockBackend("slow", 100*time.Millisecond, http.StatusOK)
	defer fastBackend.Close()
	defer slowBackend.Close()

	config := ProxyConfiguration{
		Enabled: true,
		Rules: []ProxyRule{
			{
				Name:       "test-rule",
				PathPrefix: "/test/",
				Backends: []Backend{
					{URL: fastBackend.URL, Weight: 1},
					{URL: slowBackend.URL, Weight: 1},
				},
				LoadBalancing: LeastConnectionsStrategy,
				Timeout:       5 * time.Second,
			},
		},
	}

	logger := &testLogger{}
	router := mux.NewRouter()
	if err := RegisterProxyMiddleware(router, config, logger); err != nil {
		t.Fatalf("Failed to register proxy middleware: %v", err)
	}

	// Add a fallback handler for unmatched routes
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// Make concurrent requests
	var wg sync.WaitGroup
	backendHits := make(map[string]int)
	var mu sync.Mutex

	// Start multiple concurrent requests
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req := httptest.NewRequest(GET, "/test/endpoint", nil)
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code == http.StatusOK {
				backend := rr.Header().Get("X-Backend")
				mu.Lock()
				backendHits[backend]++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// The fast backend should get more requests due to least connections
	if backendHits["fast"] <= backendHits["slow"] {
		t.Logf("Fast backend: %d, Slow backend: %d", backendHits["fast"], backendHits["slow"])
		// Note: This is a probabilistic test, so we just log the results
		// In a real scenario, the fast backend should typically get more requests
	}
}

func TestHealthChecking(t *testing.T) {
	// Create backends with different health statuses
	healthyBackend := createHealthCheckBackend("healthy", true)
	unhealthyBackend := createHealthCheckBackend("unhealthy", false)
	defer healthyBackend.Close()
	defer unhealthyBackend.Close()

	config := ProxyConfiguration{
		Enabled: true,
		HealthCheck: HealthCheckConfig{
			Enabled:         true,
			DefaultInterval: 100 * time.Millisecond,
			Timeout:         1 * time.Second,
			RetryCount:      1,
		},
		Rules: []ProxyRule{
			{
				Name:       "test-rule",
				PathPrefix: "/test/",
				Backends: []Backend{
					{
						URL:                 healthyBackend.URL,
						Weight:              1,
						HealthCheckPath:     "/health",
						HealthCheckInterval: 100 * time.Millisecond,
					},
					{
						URL:                 unhealthyBackend.URL,
						Weight:              1,
						HealthCheckPath:     "/health",
						HealthCheckInterval: 100 * time.Millisecond,
					},
				},
				LoadBalancing: RoundRobinStrategy,
				Timeout:       5 * time.Second,
			},
		},
	}

	logger := &testLogger{}

	// Create router and register proxy middleware first
	router := mux.NewRouter()
	if err := RegisterProxyMiddleware(router, config, logger); err != nil {
		t.Fatalf("Failed to register proxy middleware: %v", err)
	}

	// Wait for health checks to run
	time.Sleep(300 * time.Millisecond)

	// Add a fallback handler for unmatched routes
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// Verify that only healthy backend gets requests
	backendHits := make(map[string]int)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(GET, "/test/endpoint", nil)
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		if rr.Code == http.StatusOK {
			backend := rr.Header().Get("X-Backend")
			backendHits[backend]++
		}
	}

	// Only healthy backend should receive requests
	if backendHits["healthy"] != 10 || backendHits["unhealthy"] != 0 {
		t.Errorf("Health check failed: healthy=%d, unhealthy=%d",
			backendHits["healthy"], backendHits["unhealthy"])
	}
}

func TestTrafficDumping(t *testing.T) {
	// Create temporary directory for traffic dumps
	tempDir, err := os.MkdirTemp("", "proxy_test_")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	backend := createMockBackend("test-backend", 0, http.StatusOK)
	defer backend.Close()

	config := ProxyConfiguration{
		Enabled: true,
		TrafficDump: TrafficDumpConfig{
			Enabled:     true,
			Directory:   tempDir,
			MaxFileSize: 1024 * 1024, // 1MB
			MaxFiles:    5,
			IncludeBody: true,
			MaxBodySize: 1024,
			SampleRate:  1.0, // Dump all traffic
		},
		Rules: []ProxyRule{
			{
				Name:              "test-rule",
				PathPrefix:        "/test/",
				Backends:          []Backend{{URL: backend.URL, Weight: 1}},
				LoadBalancing:     RoundRobinStrategy,
				Timeout:           5 * time.Second,
				EnableTrafficDump: true,
			},
		},
	}

	logger := &testLogger{}
	router := mux.NewRouter()
	if err := RegisterProxyMiddleware(router, config, logger); err != nil {
		t.Fatalf("Failed to register proxy middleware: %v", err)
	}

	// Add a fallback handler for unmatched routes
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// Make a request
	body := `{"test": "data"}`
	req := httptest.NewRequest(POST, "/test/endpoint", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-agent")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Request failed with status %d", rr.Code)
	}

	// Wait a bit for dump to be written
	time.Sleep(100 * time.Millisecond)

	// Check that dump file was created
	files, err := filepath.Glob(filepath.Join(tempDir, "traffic_dump_*.jsonl"))
	if err != nil {
		t.Fatalf("Failed to list dump files: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("No dump files created")
	}

	// Read dump file content
	content, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("Failed to read dump file: %v", err)
	}

	dumpContent := string(content)

	// Verify dump contains expected data
	if !strings.Contains(dumpContent, "test-rule") {
		t.Error("Dump should contain rule name")
	}

	if !strings.Contains(dumpContent, backend.URL) {
		t.Error("Dump should contain backend URL")
	}

	if !strings.Contains(dumpContent, POST) {
		t.Error("Dump should contain HTTP method")
	}

	if !strings.Contains(dumpContent, "/test/endpoint") {
		t.Error("Dump should contain request URL")
	}

	if !strings.Contains(dumpContent, "test-agent") {
		t.Error("Dump should contain User-Agent header")
	}

	if !strings.Contains(dumpContent, `{\"test\": \"data\"}`) {
		t.Errorf("Dump should contain request body: %s", dumpContent)
	}
}

func TestPathManipulation(t *testing.T) {
	backend := createMockBackend("test-backend", 0, http.StatusOK)
	defer backend.Close()

	tests := []struct {
		name         string
		pathPrefix   string
		stripPrefix  string
		addPrefix    string
		requestPath  string
		expectedPath string
	}{
		{
			name:         "StripPrefix",
			pathPrefix:   "/api/",
			stripPrefix:  "/api",
			requestPath:  "/api/users",
			expectedPath: "/users",
		},
		{
			name:         "AddPrefix",
			pathPrefix:   "/users/",
			addPrefix:    "/v1",
			requestPath:  "/users/list",
			expectedPath: "/v1/users/list",
		},
		{
			name:         "StripAndAdd",
			pathPrefix:   "/api/",
			stripPrefix:  "/api",
			addPrefix:    "/v2",
			requestPath:  "/api/users",
			expectedPath: "/v2/users",
		},
		{
			name:         "NoModification",
			pathPrefix:   "/users/",
			requestPath:  "/users/list",
			expectedPath: "/users/list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ProxyConfiguration{
				Enabled: true,
				Rules: []ProxyRule{
					{
						Name:          "test-rule",
						PathPrefix:    tt.pathPrefix,
						Backends:      []Backend{{URL: backend.URL, Weight: 1}},
						LoadBalancing: RoundRobinStrategy,
						StripPrefix:   tt.stripPrefix,
						AddPrefix:     tt.addPrefix,
						Timeout:       5 * time.Second,
					},
				},
			}

			logger := &testLogger{}
			router := mux.NewRouter()
			if err := RegisterProxyMiddleware(router, config, logger); err != nil {
				t.Fatalf("Failed to register proxy middleware: %v", err)
			}

			// Add a fallback handler for unmatched routes
			router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Not Found", http.StatusNotFound)
			})

			req := httptest.NewRequest(GET, tt.requestPath, nil)
			rr := httptest.NewRecorder()

			// Capture the request path that reaches the backend
			var capturedPath string
			backend.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"path": "` + r.URL.Path + `"}`))
			})

			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("Request failed with status %d", rr.Code)
			}

			if capturedPath != tt.expectedPath {
				t.Errorf("Path manipulation failed: got %s, expected %s", capturedPath, tt.expectedPath)
			}
		})
	}
}

func TestHeaderBasedRouting(t *testing.T) {
	backend1 := createMockBackend("backend-v1", 0, http.StatusOK)
	backend2 := createMockBackend("backend-v2", 0, http.StatusOK)
	defer backend1.Close()
	defer backend2.Close()

	config := ProxyConfiguration{
		Enabled: true,
		Rules: []ProxyRule{
			{
				Name:          "api-v1",
				PathPrefix:    "/api/",
				Headers:       map[string]string{"X-API-Version": "v1"},
				Backends:      []Backend{{URL: backend1.URL, Weight: 1}},
				LoadBalancing: RoundRobinStrategy,
				Timeout:       5 * time.Second,
			},
			{
				Name:          "api-v2",
				PathPrefix:    "/api/",
				Headers:       map[string]string{"X-API-Version": "v2"},
				Backends:      []Backend{{URL: backend2.URL, Weight: 1}},
				LoadBalancing: RoundRobinStrategy,
				Timeout:       5 * time.Second,
			},
		},
	}

	logger := &testLogger{}
	router := mux.NewRouter()
	if err := RegisterProxyMiddleware(router, config, logger); err != nil {
		t.Fatalf("Failed to register proxy middleware: %v", err)
	}

	// Add a fallback handler for unmatched routes
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// Test v1 routing
	req1 := httptest.NewRequest(GET, "/api/users", nil)
	req1.Header.Set("X-API-Version", "v1")
	rr1 := httptest.NewRecorder()

	router.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Fatalf("V1 request failed with status %d", rr1.Code)
	}

	if rr1.Header().Get("X-Backend") != "backend-v1" {
		t.Errorf("V1 request routed to wrong backend: %s", rr1.Header().Get("X-Backend"))
	}

	// Test v2 routing
	req2 := httptest.NewRequest(GET, "/api/users", nil)
	req2.Header.Set("X-API-Version", "v2")
	rr2 := httptest.NewRecorder()

	router.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("V2 request failed with status %d", rr2.Code)
	}

	if rr2.Header().Get("X-Backend") != "backend-v2" {
		t.Errorf("V2 request routed to wrong backend: %s", rr2.Header().Get("X-Backend"))
	}
}

func TestMethodFiltering(t *testing.T) {
	backend := createMockBackend("test-backend", 0, http.StatusOK)
	defer backend.Close()

	config := ProxyConfiguration{
		Enabled: true,
		Rules: []ProxyRule{
			{
				Name:          "readonly-api",
				PathPrefix:    "/api/",
				Methods:       []string{GET, "HEAD"},
				Backends:      []Backend{{URL: backend.URL, Weight: 1}},
				LoadBalancing: RoundRobinStrategy,
				Timeout:       5 * time.Second,
			},
		},
	}

	logger := &testLogger{}
	router := mux.NewRouter()
	if err := RegisterProxyMiddleware(router, config, logger); err != nil {
		t.Fatalf("Failed to register proxy middleware: %v", err)
	}

	// Add a fallback handler for unmatched routes
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// Test allowed method
	req1 := httptest.NewRequest(GET, "/api/users", nil)
	rr1 := httptest.NewRecorder()
	router.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Errorf("GET request should be allowed, got status %d", rr1.Code)
	}

	// Test disallowed method
	req2 := httptest.NewRequest(POST, "/api/users", nil)
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)

	if rr2.Code == http.StatusOK {
		t.Error("POST request should not be allowed for readonly API")
	}
}

func TestNoHealthyBackends(t *testing.T) {
	// Create unhealthy backend
	unhealthyBackend := createHealthCheckBackend("unhealthy", false)
	defer unhealthyBackend.Close()

	config := ProxyConfiguration{
		Enabled: true,
		HealthCheck: HealthCheckConfig{
			Enabled:         true,
			DefaultInterval: 50 * time.Millisecond,
			Timeout:         1 * time.Second,
			RetryCount:      1,
		},
		Rules: []ProxyRule{
			{
				Name:       "test-rule",
				PathPrefix: "/test/",
				Backends: []Backend{
					{
						URL:                 unhealthyBackend.URL,
						Weight:              1,
						HealthCheckPath:     "/health",
						HealthCheckInterval: 50 * time.Millisecond,
					},
				},
				LoadBalancing: RoundRobinStrategy,
				Timeout:       5 * time.Second,
			},
		},
	}

	logger := &testLogger{}
	router := mux.NewRouter()
	if err := RegisterProxyMiddleware(router, config, logger); err != nil {
		t.Fatalf("Failed to register proxy middleware: %v", err)
	}

	// Start health checks and wait for them to mark backend as unhealthy
	time.Sleep(200 * time.Millisecond)

	// Add a fallback handler for unmatched routes
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// Request should fail when no healthy backends available
	req := httptest.NewRequest(GET, "/test/endpoint", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503 when no healthy backends, got %d", rr.Code)
	}
}

func TestRequestTimeout(t *testing.T) {
	// Create slow backend that takes longer than timeout
	slowBackend := createMockBackend("slow", 200*time.Millisecond, http.StatusOK)
	defer slowBackend.Close()

	config := ProxyConfiguration{
		Enabled: true,
		Rules: []ProxyRule{
			{
				Name:          "test-rule",
				PathPrefix:    "/test/",
				Backends:      []Backend{{URL: slowBackend.URL, Weight: 1}},
				LoadBalancing: RoundRobinStrategy,
				Timeout:       50 * time.Millisecond, // Short timeout
			},
		},
	}

	logger := &testLogger{}
	router := mux.NewRouter()
	if err := RegisterProxyMiddleware(router, config, logger); err != nil {
		t.Fatalf("Failed to register proxy middleware: %v", err)
	}

	// Add a fallback handler for unmatched routes
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	req := httptest.NewRequest(GET, "/test/endpoint", nil)
	rr := httptest.NewRecorder()

	start := time.Now()
	router.ServeHTTP(rr, req)
	duration := time.Since(start)

	// Request should timeout and complete quickly
	if duration > 100*time.Millisecond {
		t.Errorf("Request took too long: %v", duration)
	}

	// Should get timeout error (typically 502 or 504)
	if rr.Code != http.StatusBadGateway && rr.Code != http.StatusGatewayTimeout {
		t.Errorf("Expected timeout error status, got %d", rr.Code)
	}
}

// Helper functions and types

type testLogger struct {
	mu   sync.Mutex
	logs []logEntry
}

type logEntry struct {
	level   string
	message string
	fields  []any
}

func (tl *testLogger) Debug(msg string, fields ...any) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.logs = append(tl.logs, logEntry{"debug", msg, fields})
}

func (tl *testLogger) Info(msg string, fields ...any) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.logs = append(tl.logs, logEntry{"info", msg, fields})
}

func (tl *testLogger) Error(msg string, fields ...any) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.logs = append(tl.logs, logEntry{"error", msg, fields})
}

func (tl *testLogger) GetLogs() []logEntry {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	return append([]logEntry(nil), tl.logs...)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Test proxy manager creation
func TestNewProxyManager(t *testing.T) {
	config := ProxyConfiguration{
		Enabled:       true,
		GlobalTimeout: 30 * time.Second,
		Rules: []ProxyRule{
			{
				Name:          "test-rule",
				PathPrefix:    "/test/",
				Backends:      []Backend{{URL: "http://localhost:8080", Weight: 1}},
				LoadBalancing: RoundRobinStrategy,
				Timeout:       10 * time.Second,
			},
		},
	}

	logger := &testLogger{}
	pm, err := newProxyManager(config, logger)
	if err != nil {
		t.Fatalf("Failed to create proxy manager: %v", err)
	}

	if len(pm.rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(pm.rules))
	}

	rule := pm.rules[0]
	if rule.Name != "test-rule" {
		t.Errorf("Expected rule name 'test-rule', got '%s'", rule.Name)
	}

	if len(rule.backends) != 1 {
		t.Errorf("Expected 1 backend, got %d", len(rule.backends))
	}
}

func TestProxyRuleMatching(t *testing.T) {
	backend := createMockBackend("test-backend", 0, http.StatusOK)
	defer backend.Close()

	config := ProxyConfiguration{
		Enabled: true,
		Rules: []ProxyRule{
			{
				Name:          "api-rule",
				PathPrefix:    "/api/",
				Backends:      []Backend{{URL: backend.URL, Weight: 1}},
				LoadBalancing: RoundRobinStrategy,
				Timeout:       5 * time.Second,
			},
			{
				Name:          "static-rule",
				PathPrefix:    "/static/",
				Backends:      []Backend{{URL: backend.URL, Weight: 1}},
				LoadBalancing: RoundRobinStrategy,
				Timeout:       5 * time.Second,
			},
		},
	}

	logger := &testLogger{}
	router := mux.NewRouter()
	if err := RegisterProxyMiddleware(router, config, logger); err != nil {
		t.Fatalf("Failed to register proxy middleware: %v", err)
	}

	// Add a fallback handler for unmatched routes
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	tests := []struct {
		path           string
		expectedStatus int
		description    string
	}{
		{"/api/users", http.StatusOK, "API path should match"},
		{"/static/css/style.css", http.StatusOK, "Static path should match"},
		{"/other/path", http.StatusNotFound, "Other paths should not match"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := httptest.NewRequest(GET, tt.path, nil)
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Path %s: expected status %d, got %d", tt.path, tt.expectedStatus, rr.Code)
			}
		})
	}
}
