package servex

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewBuiltinMetrics(t *testing.T) {
	metrics := newBuiltinMetrics()

	if metrics == nil {
		t.Fatal("expected non-nil metrics instance")
	}

	if !metrics.enabled {
		t.Error("metrics should be enabled by default")
	}

	if metrics.statusCodes == nil {
		t.Error("status codes map should be initialized")
	}

	if metrics.pathMetrics == nil {
		t.Error("path metrics map should be initialized")
	}

	if metrics.methodMetrics == nil {
		t.Error("method metrics map should be initialized")
	}
}

func TestBuiltinMetrics_SetEnabled(t *testing.T) {
	metrics := newBuiltinMetrics()

	metrics.setEnabled(false)
	if metrics.enabled {
		t.Error("metrics should be disabled")
	}

	metrics.setEnabled(true)
	if !metrics.enabled {
		t.Error("metrics should be enabled")
	}
}

func TestBuiltinMetrics_HandleRequest(t *testing.T) {
	metrics := newBuiltinMetrics()

	req1 := httptest.NewRequest("GET", "/test", nil)
	req2 := httptest.NewRequest("POST", "/api", nil)

	metrics.HandleRequest(req1)
	metrics.HandleRequest(req2)

	if metrics.requestCount != 2 {
		t.Errorf("expected request count 2, got %d", metrics.requestCount)
	}

	if metrics.methodMetrics["GET"] != 1 {
		t.Errorf("expected GET method count 1, got %d", metrics.methodMetrics["GET"])
	}

	if metrics.methodMetrics["POST"] != 1 {
		t.Errorf("expected POST method count 1, got %d", metrics.methodMetrics["POST"])
	}
}

func TestBuiltinMetrics_HandleRequest_Disabled(t *testing.T) {
	metrics := newBuiltinMetrics()
	metrics.setEnabled(false)

	req := httptest.NewRequest("GET", "/test", nil)
	metrics.HandleRequest(req)

	if metrics.requestCount != 0 {
		t.Errorf("expected request count 0 when disabled, got %d", metrics.requestCount)
	}
}

func TestBuiltinMetrics_RecordResponse(t *testing.T) {
	metrics := newBuiltinMetrics()

	// Record a successful response
	metrics.recordResponse("/api/users", "GET", 200, 100*time.Millisecond, false)

	if metrics.responseCount != 1 {
		t.Errorf("expected response count 1, got %d", metrics.responseCount)
	}

	if metrics.errorCount != 0 {
		t.Errorf("expected error count 0, got %d", metrics.errorCount)
	}

	if metrics.statusCodes[200] != 1 {
		t.Errorf("expected status code 200 count 1, got %d", metrics.statusCodes[200])
	}

	pathMetric := metrics.pathMetrics["/api/users"]
	if pathMetric == nil {
		t.Fatal("expected path metric to be created")
	}

	if pathMetric.Count != 1 {
		t.Errorf("expected path count 1, got %d", pathMetric.Count)
	}

	if pathMetric.ErrorCount != 0 {
		t.Errorf("expected path error count 0, got %d", pathMetric.ErrorCount)
	}

	// Record an error response
	metrics.recordResponse("/api/error", "POST", 500, 50*time.Millisecond, true)

	if metrics.responseCount != 2 {
		t.Errorf("expected response count 2, got %d", metrics.responseCount)
	}

	if metrics.errorCount != 1 {
		t.Errorf("expected error count 1, got %d", metrics.errorCount)
	}

	errorPathMetric := metrics.pathMetrics["/api/error"]
	if errorPathMetric.ErrorCount != 1 {
		t.Errorf("expected path error count 1, got %d", errorPathMetric.ErrorCount)
	}
}

func TestBuiltinMetrics_RecordResponse_Disabled(t *testing.T) {
	metrics := newBuiltinMetrics()
	metrics.setEnabled(false)

	metrics.recordResponse("/api/test", "GET", 200, 100*time.Millisecond, false)

	if metrics.responseCount != 0 {
		t.Errorf("expected response count 0 when disabled, got %d", metrics.responseCount)
	}
}

func TestBuiltinMetrics_GetSnapshot(t *testing.T) {
	metrics := newBuiltinMetrics()

	// Record some test data
	req := httptest.NewRequest("GET", "/api/test", nil)
	metrics.HandleRequest(req)
	metrics.recordResponse("/api/test", "GET", 200, 100*time.Millisecond, false)
	metrics.recordResponse("/api/error", "POST", 500, 50*time.Millisecond, true)

	snapshot := metrics.getSnapshot()

	if snapshot.RequestCount != 1 {
		t.Errorf("expected request count 1, got %d", snapshot.RequestCount)
	}

	if snapshot.ResponseCount != 2 {
		t.Errorf("expected response count 2, got %d", snapshot.ResponseCount)
	}

	if snapshot.ErrorCount != 1 {
		t.Errorf("expected error count 1, got %d", snapshot.ErrorCount)
	}

	if snapshot.ErrorRate != 50.0 {
		t.Errorf("expected error rate 50.0%%, got %.1f%%", snapshot.ErrorRate)
	}

	if snapshot.StatusCodes[200] != 1 {
		t.Errorf("expected status 200 count 1, got %d", snapshot.StatusCodes[200])
	}

	if snapshot.StatusCodes[500] != 1 {
		t.Errorf("expected status 500 count 1, got %d", snapshot.StatusCodes[500])
	}

	if snapshot.Methods["GET"] != 1 {
		t.Errorf("expected GET method count 1, got %d", snapshot.Methods["GET"])
	}

	if len(snapshot.TopPaths) == 0 {
		t.Error("expected top paths to be populated")
	}

	// Check system metrics are populated
	if snapshot.SystemMetrics.GoroutineCount <= 0 {
		t.Error("expected positive goroutine count")
	}
}

func TestBuiltinMetrics_GetTopPaths(t *testing.T) {
	metrics := newBuiltinMetrics()

	// Record data for multiple paths
	paths := []string{"/api/popular", "/api/less-popular", "/api/least-popular"}
	counts := []int{10, 5, 1}

	for i, path := range paths {
		for j := 0; j < counts[i]; j++ {
			metrics.recordResponse(path, "GET", 200, 10*time.Millisecond, false)
		}
	}

	topPaths := metrics.getTopPaths(2)

	if len(topPaths) != 2 {
		t.Errorf("expected 2 top paths, got %d", len(topPaths))
	}

	// Should be sorted by count descending
	if topPaths[0].Path != "/api/popular" {
		t.Errorf("expected first path to be '/api/popular', got '%s'", topPaths[0].Path)
	}

	if topPaths[0].Count != 10 {
		t.Errorf("expected first path count 10, got %d", topPaths[0].Count)
	}

	if topPaths[1].Path != "/api/less-popular" {
		t.Errorf("expected second path to be '/api/less-popular', got '%s'", topPaths[1].Path)
	}
}

func TestBuiltinMetrics_Reset(t *testing.T) {
	metrics := newBuiltinMetrics()

	// Record some data
	req := httptest.NewRequest("GET", "/test", nil)
	metrics.HandleRequest(req)
	metrics.recordResponse("/test", "GET", 200, 100*time.Millisecond, false)

	// Verify data exists
	if metrics.requestCount == 0 {
		t.Error("expected non-zero request count before reset")
	}

	// Reset metrics
	metrics.reset()

	// Verify data is cleared
	if metrics.requestCount != 0 {
		t.Errorf("expected request count 0 after reset, got %d", metrics.requestCount)
	}

	if metrics.responseCount != 0 {
		t.Errorf("expected response count 0 after reset, got %d", metrics.responseCount)
	}

	if metrics.errorCount != 0 {
		t.Errorf("expected error count 0 after reset, got %d", metrics.errorCount)
	}

	if len(metrics.statusCodes) != 0 {
		t.Errorf("expected empty status codes map after reset, got %d entries", len(metrics.statusCodes))
	}

	if len(metrics.pathMetrics) != 0 {
		t.Errorf("expected empty path metrics map after reset, got %d entries", len(metrics.pathMetrics))
	}

	if len(metrics.methodMetrics) != 0 {
		t.Errorf("expected empty method metrics map after reset, got %d entries", len(metrics.methodMetrics))
	}
}

func TestBuiltinMetrics_GetPrometheusMetrics(t *testing.T) {
	metrics := newBuiltinMetrics()

	// Record some test data
	req := httptest.NewRequest("GET", "/api/test", nil)
	metrics.HandleRequest(req)
	metrics.recordResponse("/api/test", "GET", 200, 100*time.Millisecond, false)
	metrics.recordResponse("/api/error", "POST", 500, 50*time.Millisecond, true)

	prometheusOutput := metrics.getPrometheusMetrics()

	// Check for expected Prometheus format elements
	expectedMetrics := []string{
		"servex_build_info",
		"servex_uptime_seconds",
		"servex_requests_total",
		"servex_responses_total",
		"servex_errors_total",
		"servex_error_rate_percent",
		"servex_requests_per_second",
		"servex_response_time_ms_avg",
		"servex_responses_by_status_total",
		"servex_requests_by_method_total",
		"servex_memory_usage_mb",
		"servex_goroutines",
	}

	for _, expectedMetric := range expectedMetrics {
		if !strings.Contains(prometheusOutput, expectedMetric) {
			t.Errorf("expected Prometheus output to contain '%s'", expectedMetric)
		}
	}

	// Check for HELP and TYPE comments
	if !strings.Contains(prometheusOutput, "# HELP") {
		t.Error("expected Prometheus output to contain HELP comments")
	}

	if !strings.Contains(prometheusOutput, "# TYPE") {
		t.Error("expected Prometheus output to contain TYPE comments")
	}

	// Check that it includes method and status code metrics
	if !strings.Contains(prometheusOutput, `method="GET"`) {
		t.Error("expected Prometheus output to contain method labels")
	}

	if !strings.Contains(prometheusOutput, `code="200"`) {
		t.Error("expected Prometheus output to contain status code labels")
	}
}

func TestBuiltinMetrics_RegisterMetricsEndpoint(t *testing.T) {
	metrics := newBuiltinMetrics()
	server, err := NewServer()
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Register metrics endpoint
	metrics.registerMetricsEndpoint(server, "/metrics")

	// Test GET request to metrics endpoint
	req := httptest.NewRequest("GET", "/metrics", nil)
	recorder := httptest.NewRecorder()

	server.Router().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", recorder.Code)
	}

	contentType := recorder.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("expected Content-Type to contain 'text/plain', got '%s'", contentType)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "servex_") {
		t.Error("expected metrics output to contain servex metrics")
	}

	// Test non-GET request (should fail)
	req = httptest.NewRequest("POST", "/metrics", nil)
	recorder = httptest.NewRecorder()

	server.Router().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405 for POST request, got %d", recorder.Code)
	}
}

func TestPrometheusEscape(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`simple`, `simple`},
		{`with"quotes`, `with\"quotes`},
		{`with\backslash`, `with\\backslash`},
		{`with
newline`, `with\nnewline`},
		{`with	tab`, `with\ttab`},
		{`with\r\n`, `with\\r\\n`},
		{`mixed"test\with	special`, `mixed\"test\\with\tspecial`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := prometheusEscape(tt.input)
			if result != tt.expected {
				t.Errorf("prometheusEscape(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestPathMetrics_TimingCalculations(t *testing.T) {
	metrics := newBuiltinMetrics()

	// Record responses with different durations
	durations := []time.Duration{
		10 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
	}

	for _, duration := range durations {
		metrics.recordResponse("/api/test", "GET", 200, duration, false)
	}

	pathMetric := metrics.pathMetrics["/api/test"]
	if pathMetric == nil {
		t.Fatal("expected path metric to exist")
	}

	// Check min time (10ms = 10,000,000 ns)
	if pathMetric.MinTime != 10000000 {
		t.Errorf("expected min time 10000000 ns, got %d", pathMetric.MinTime)
	}

	// Check max time (100ms = 100,000,000 ns)
	if pathMetric.MaxTime != 100000000 {
		t.Errorf("expected max time 100000000 ns, got %d", pathMetric.MaxTime)
	}

	// Check total time (160ms = 160,000,000 ns)
	expectedTotal := int64(160000000)
	if pathMetric.TotalTime != expectedTotal {
		t.Errorf("expected total time %d ns, got %d", expectedTotal, pathMetric.TotalTime)
	}

	// Check count
	if pathMetric.Count != 3 {
		t.Errorf("expected count 3, got %d", pathMetric.Count)
	}
}

func TestSystemMetrics(t *testing.T) {
	sysMetrics := getSystemMetrics()

	if sysMetrics.GoroutineCount <= 0 {
		t.Error("expected positive goroutine count")
	}

	// HeapObjectCount should be positive in most cases
	if sysMetrics.HeapObjectCount == 0 {
		t.Log("warning: heap object count is 0, this might be unusual")
	}
}

func TestBytesToMegabytes(t *testing.T) {
	tests := []struct {
		bytes    uint64
		expected uint64
	}{
		{0, 0},
		{1024, 0},                  // Less than 1 MB
		{1024 * 1024, 1},           // Exactly 1 MB
		{1024 * 1024 * 5, 5},       // 5 MB
		{1024 * 1024 * 1024, 1024}, // 1 GB = 1024 MB
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := bToMb(tt.bytes)
			if result != tt.expected {
				t.Errorf("bToMb(%d) = %d, expected %d", tt.bytes, result, tt.expected)
			}
		})
	}
}

func TestMetricsIntegration(t *testing.T) {
	// Test that metrics integrate properly with the middleware system
	metrics := newBuiltinMetrics()
	server, err := NewServer(WithMetrics(metrics))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	server.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Make a request
	req := httptest.NewRequest("GET", "/test", nil)
	recorder := httptest.NewRecorder()

	server.Router().ServeHTTP(recorder, req)

	// Check that metrics were recorded
	if metrics.requestCount != 1 {
		t.Errorf("expected request count 1, got %d", metrics.requestCount)
	}

	// The response recording happens in the logging middleware
	// so we need to ensure the logging middleware is also working
	snapshot := metrics.getSnapshot()
	if snapshot.RequestCount != 1 {
		t.Errorf("expected snapshot request count 1, got %d", snapshot.RequestCount)
	}
}
