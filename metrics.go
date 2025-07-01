package servex

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics is an interface for collecting metrics on each request.
// [Metrics.HandleRequest] is called on each request.
// [Metrics.HandleResponse] is called on each response.
type Metrics interface {
	// HandleRequest is called on each request to collect metrics.
	HandleRequest(r *http.Request)

	// HandleResponse is called on each response to collect metrics.
	HandleResponse(r *http.Request, w http.ResponseWriter, statusCode int, duration time.Duration)
}

// builtinMetrics provides comprehensive request and system metrics
type builtinMetrics struct {
	mu               sync.RWMutex
	startTime        time.Time
	requestCount     int64
	responseCount    int64
	errorCount       int64
	totalRequestTime int64 // in nanoseconds
	statusCodes      map[int]int64
	pathMetrics      map[string]*pathMetrics
	methodMetrics    map[string]int64
	enabled          bool
}

// pathMetrics tracks metrics for specific paths
type pathMetrics struct {
	Count       int64
	TotalTime   int64 // in nanoseconds
	ErrorCount  int64
	MaxTime     int64
	MinTime     int64
	StatusCodes map[int]int64
}

// metricsSnapshot provides a point-in-time view of metrics
type metricsSnapshot struct {
	Timestamp       time.Time        `json:"timestamp"`
	Uptime          string           `json:"uptime"`
	RequestCount    int64            `json:"request_count"`
	ResponseCount   int64            `json:"response_count"`
	ErrorCount      int64            `json:"error_count"`
	ErrorRate       float64          `json:"error_rate_percent"`
	AvgResponseTime float64          `json:"avg_response_time_ms"`
	RequestsPerSec  float64          `json:"requests_per_second"`
	StatusCodes     map[int]int64    `json:"status_codes"`
	Methods         map[string]int64 `json:"methods"`
	TopPaths        []pathSummary    `json:"top_paths"`
	SystemMetrics   systemMetrics    `json:"system_metrics"`
}

// pathSummary provides summary metrics for a path
type pathSummary struct {
	Path            string  `json:"path"`
	Count           int64   `json:"count"`
	ErrorCount      int64   `json:"error_count"`
	ErrorRate       float64 `json:"error_rate_percent"`
	AvgResponseTime float64 `json:"avg_response_time_ms"`
	MaxResponseTime float64 `json:"max_response_time_ms"`
	MinResponseTime float64 `json:"min_response_time_ms"`
}

// systemMetrics provides system-level metrics
type systemMetrics struct {
	MemoryUsageMB   uint64  `json:"memory_usage_mb"`
	MemoryAllocMB   uint64  `json:"memory_alloc_mb"`
	GoroutineCount  int     `json:"goroutine_count"`
	GCCount         uint32  `json:"gc_count"`
	HeapObjectCount uint64  `json:"heap_objects"`
	CPUUsagePercent float64 `json:"cpu_usage_percent,omitempty"`
}

// newBuiltinMetrics creates a new metrics collector
func newBuiltinMetrics() *builtinMetrics {
	return &builtinMetrics{
		startTime:     time.Now(),
		statusCodes:   make(map[int]int64),
		pathMetrics:   make(map[string]*pathMetrics),
		methodMetrics: make(map[string]int64),
		enabled:       true,
	}
}

// Enable/disable metrics collection
func (m *builtinMetrics) setEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = enabled
}

// HandleRequest implements the Metrics interface
func (m *builtinMetrics) HandleRequest(r *http.Request) {
	if !m.enabled {
		return
	}

	atomic.AddInt64(&m.requestCount, 1)

	// Track method metrics
	m.mu.Lock()
	m.methodMetrics[r.Method]++
	m.mu.Unlock()
}

// HandleResponse implements the Metrics interface
func (m *builtinMetrics) HandleResponse(r *http.Request, w http.ResponseWriter, statusCode int, duration time.Duration) {
	m.recordResponse(r.URL.Path, r.Method, statusCode, duration, statusCode >= 400)
}

// recordResponse records response metrics
func (m *builtinMetrics) recordResponse(path, method string, statusCode int, duration time.Duration, isError bool) {
	if !m.enabled {
		return
	}

	atomic.AddInt64(&m.responseCount, 1)
	atomic.AddInt64(&m.totalRequestTime, duration.Nanoseconds())

	if isError {
		atomic.AddInt64(&m.errorCount, 1)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Track status codes
	m.statusCodes[statusCode]++

	// Track path metrics
	if m.pathMetrics[path] == nil {
		m.pathMetrics[path] = &pathMetrics{
			StatusCodes: make(map[int]int64),
			MinTime:     duration.Nanoseconds(),
			MaxTime:     duration.Nanoseconds(),
		}
	}

	pathMetric := m.pathMetrics[path]
	pathMetric.Count++
	pathMetric.TotalTime += duration.Nanoseconds()
	pathMetric.StatusCodes[statusCode]++

	if isError {
		pathMetric.ErrorCount++
	}

	// Update min/max times
	durationNs := duration.Nanoseconds()
	if durationNs < pathMetric.MinTime {
		pathMetric.MinTime = durationNs
	}
	if durationNs > pathMetric.MaxTime {
		pathMetric.MaxTime = durationNs
	}
}

// getSnapshot returns current metrics snapshot
func (m *builtinMetrics) getSnapshot() metricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	snapshot := metricsSnapshot{
		Timestamp:     time.Now(),
		Uptime:        time.Since(m.startTime).String(),
		RequestCount:  atomic.LoadInt64(&m.requestCount),
		ResponseCount: atomic.LoadInt64(&m.responseCount),
		ErrorCount:    atomic.LoadInt64(&m.errorCount),
		StatusCodes:   make(map[int]int64),
		Methods:       make(map[string]int64),
		SystemMetrics: getSystemMetrics(),
	}

	// Copy status codes
	for code, count := range m.statusCodes {
		snapshot.StatusCodes[code] = count
	}

	// Copy method metrics
	for method, count := range m.methodMetrics {
		snapshot.Methods[method] = count
	}

	// Calculate derived metrics
	if snapshot.ResponseCount > 0 {
		snapshot.ErrorRate = (float64(snapshot.ErrorCount) / float64(snapshot.ResponseCount)) * 100

		totalTime := atomic.LoadInt64(&m.totalRequestTime)
		snapshot.AvgResponseTime = float64(totalTime) / float64(snapshot.ResponseCount) / 1e6 // Convert to milliseconds
	}

	// Calculate requests per second
	uptime := time.Since(m.startTime).Seconds()
	if uptime > 0 {
		snapshot.RequestsPerSec = float64(snapshot.RequestCount) / uptime
	}

	// Generate top paths
	snapshot.TopPaths = m.getTopPaths(10)

	return snapshot
}

// getTopPaths returns the top N paths by request count
func (m *builtinMetrics) getTopPaths(limit int) []pathSummary {
	type pathCount struct {
		path  string
		count int64
	}

	var paths []pathCount
	for path, metric := range m.pathMetrics {
		paths = append(paths, pathCount{path: path, count: metric.Count})
	}

	// Simple selection sort for top N
	for i := 0; i < len(paths) && i < limit; i++ {
		maxIdx := i
		for j := i + 1; j < len(paths); j++ {
			if paths[j].count > paths[maxIdx].count {
				maxIdx = j
			}
		}
		if maxIdx != i {
			paths[i], paths[maxIdx] = paths[maxIdx], paths[i]
		}
	}

	// Convert to summaries
	summaries := make([]pathSummary, 0, limit)
	for i := 0; i < len(paths) && i < limit; i++ {
		path := paths[i].path
		metric := m.pathMetrics[path]

		summary := pathSummary{
			Path:            path,
			Count:           metric.Count,
			ErrorCount:      metric.ErrorCount,
			AvgResponseTime: float64(metric.TotalTime) / float64(metric.Count) / 1e6,
			MaxResponseTime: float64(metric.MaxTime) / 1e6,
			MinResponseTime: float64(metric.MinTime) / 1e6,
		}

		if metric.Count > 0 {
			summary.ErrorRate = (float64(metric.ErrorCount) / float64(metric.Count)) * 100
		}

		summaries = append(summaries, summary)
	}

	return summaries
}

// getSystemMetrics collects system-level metrics
func getSystemMetrics() systemMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return systemMetrics{
		MemoryUsageMB:   bToMb(m.Sys),
		MemoryAllocMB:   bToMb(m.Alloc),
		GoroutineCount:  runtime.NumGoroutine(),
		GCCount:         m.NumGC,
		HeapObjectCount: m.HeapObjects,
	}
}

// bToMb converts bytes to megabytes
func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

// registerMetricsEndpoint registers a metrics endpoint on the given router
func (m *builtinMetrics) registerMetricsEndpoint(server *Server, path string) {
	server.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Set Prometheus-compatible content type
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

		// Get metrics in Prometheus format
		prometheusMetrics := m.getPrometheusMetrics()

		// Write the Prometheus text format directly
		if _, err := w.Write([]byte(prometheusMetrics)); err != nil {
			// If we can't write the response, there's not much we can do
			// The error will be logged by the request logging middleware
			return
		}
	}).Methods("GET")
}

// reset clears all metrics (useful for testing)
func (m *builtinMetrics) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	atomic.StoreInt64(&m.requestCount, 0)
	atomic.StoreInt64(&m.responseCount, 0)
	atomic.StoreInt64(&m.errorCount, 0)
	atomic.StoreInt64(&m.totalRequestTime, 0)

	m.startTime = time.Now()
	m.statusCodes = make(map[int]int64)
	m.pathMetrics = make(map[string]*pathMetrics)
	m.methodMetrics = make(map[string]int64)
}

// getPrometheusMetrics returns metrics in Prometheus text format
func (m *builtinMetrics) getPrometheusMetrics() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	snapshot := m.getSnapshot()
	var result strings.Builder

	// Server info
	result.WriteString("# HELP servex_build_info Server build information\n")
	result.WriteString("# TYPE servex_build_info gauge\n")
	result.WriteString("servex_build_info{version=\"unknown\"} 1\n")
	result.WriteString("\n")

	// Uptime
	result.WriteString("# HELP servex_uptime_seconds Server uptime in seconds\n")
	result.WriteString("# TYPE servex_uptime_seconds gauge\n")
	uptimeSeconds := time.Since(m.startTime).Seconds()
	result.WriteString(fmt.Sprintf("servex_uptime_seconds %.2f\n", uptimeSeconds))
	result.WriteString("\n")

	// Request metrics
	result.WriteString("# HELP servex_requests_total Total number of HTTP requests received\n")
	result.WriteString("# TYPE servex_requests_total counter\n")
	result.WriteString(fmt.Sprintf("servex_requests_total %d\n", snapshot.RequestCount))
	result.WriteString("\n")

	result.WriteString("# HELP servex_responses_total Total number of HTTP responses sent\n")
	result.WriteString("# TYPE servex_responses_total counter\n")
	result.WriteString(fmt.Sprintf("servex_responses_total %d\n", snapshot.ResponseCount))
	result.WriteString("\n")

	result.WriteString("# HELP servex_errors_total Total number of HTTP errors\n")
	result.WriteString("# TYPE servex_errors_total counter\n")
	result.WriteString(fmt.Sprintf("servex_errors_total %d\n", snapshot.ErrorCount))
	result.WriteString("\n")

	// Rate metrics
	result.WriteString("# HELP servex_error_rate_percent Error rate as percentage\n")
	result.WriteString("# TYPE servex_error_rate_percent gauge\n")
	result.WriteString(fmt.Sprintf("servex_error_rate_percent %.2f\n", snapshot.ErrorRate))
	result.WriteString("\n")

	result.WriteString("# HELP servex_requests_per_second Request rate per second\n")
	result.WriteString("# TYPE servex_requests_per_second gauge\n")
	result.WriteString(fmt.Sprintf("servex_requests_per_second %.2f\n", snapshot.RequestsPerSec))
	result.WriteString("\n")

	result.WriteString("# HELP servex_response_time_ms_avg Average response time in milliseconds\n")
	result.WriteString("# TYPE servex_response_time_ms_avg gauge\n")
	result.WriteString(fmt.Sprintf("servex_response_time_ms_avg %.2f\n", snapshot.AvgResponseTime))
	result.WriteString("\n")

	// Status code metrics
	result.WriteString("# HELP servex_responses_by_status_total Total responses by HTTP status code\n")
	result.WriteString("# TYPE servex_responses_by_status_total counter\n")
	for code, count := range snapshot.StatusCodes {
		result.WriteString(fmt.Sprintf("servex_responses_by_status_total{code=\"%d\"} %d\n", code, count))
	}
	result.WriteString("\n")

	// Method metrics
	result.WriteString("# HELP servex_requests_by_method_total Total requests by HTTP method\n")
	result.WriteString("# TYPE servex_requests_by_method_total counter\n")
	for method, count := range snapshot.Methods {
		result.WriteString(fmt.Sprintf("servex_requests_by_method_total{method=\"%s\"} %d\n", method, count))
	}
	result.WriteString("\n")

	// Path metrics
	result.WriteString("# HELP servex_requests_by_path_total Total requests by path\n")
	result.WriteString("# TYPE servex_requests_by_path_total counter\n")
	result.WriteString("# HELP servex_path_response_time_ms_avg Average response time by path in milliseconds\n")
	result.WriteString("# TYPE servex_path_response_time_ms_avg gauge\n")
	result.WriteString("# HELP servex_path_response_time_ms_max Maximum response time by path in milliseconds\n")
	result.WriteString("# TYPE servex_path_response_time_ms_max gauge\n")
	result.WriteString("# HELP servex_path_response_time_ms_min Minimum response time by path in milliseconds\n")
	result.WriteString("# TYPE servex_path_response_time_ms_min gauge\n")
	result.WriteString("# HELP servex_path_errors_total Total errors by path\n")
	result.WriteString("# TYPE servex_path_errors_total counter\n")
	result.WriteString("# HELP servex_path_error_rate_percent Error rate by path as percentage\n")
	result.WriteString("# TYPE servex_path_error_rate_percent gauge\n")

	for _, pathSummary := range snapshot.TopPaths {
		escapedPath := prometheusEscape(pathSummary.Path)
		result.WriteString(fmt.Sprintf("servex_requests_by_path_total{path=\"%s\"} %d\n", escapedPath, pathSummary.Count))
		result.WriteString(fmt.Sprintf("servex_path_response_time_ms_avg{path=\"%s\"} %.2f\n", escapedPath, pathSummary.AvgResponseTime))
		result.WriteString(fmt.Sprintf("servex_path_response_time_ms_max{path=\"%s\"} %.2f\n", escapedPath, pathSummary.MaxResponseTime))
		result.WriteString(fmt.Sprintf("servex_path_response_time_ms_min{path=\"%s\"} %.2f\n", escapedPath, pathSummary.MinResponseTime))
		result.WriteString(fmt.Sprintf("servex_path_errors_total{path=\"%s\"} %d\n", escapedPath, pathSummary.ErrorCount))
		result.WriteString(fmt.Sprintf("servex_path_error_rate_percent{path=\"%s\"} %.2f\n", escapedPath, pathSummary.ErrorRate))
	}
	result.WriteString("\n")

	// System metrics
	result.WriteString("# HELP servex_memory_usage_mb System memory usage in megabytes\n")
	result.WriteString("# TYPE servex_memory_usage_mb gauge\n")
	result.WriteString(fmt.Sprintf("servex_memory_usage_mb %d\n", snapshot.SystemMetrics.MemoryUsageMB))
	result.WriteString("\n")

	result.WriteString("# HELP servex_memory_alloc_mb Allocated memory in megabytes\n")
	result.WriteString("# TYPE servex_memory_alloc_mb gauge\n")
	result.WriteString(fmt.Sprintf("servex_memory_alloc_mb %d\n", snapshot.SystemMetrics.MemoryAllocMB))
	result.WriteString("\n")

	result.WriteString("# HELP servex_goroutines Current number of goroutines\n")
	result.WriteString("# TYPE servex_goroutines gauge\n")
	result.WriteString(fmt.Sprintf("servex_goroutines %d\n", snapshot.SystemMetrics.GoroutineCount))
	result.WriteString("\n")

	result.WriteString("# HELP servex_gc_count_total Total number of garbage collections\n")
	result.WriteString("# TYPE servex_gc_count_total counter\n")
	result.WriteString(fmt.Sprintf("servex_gc_count_total %d\n", snapshot.SystemMetrics.GCCount))
	result.WriteString("\n")

	result.WriteString("# HELP servex_heap_objects Current number of heap objects\n")
	result.WriteString("# TYPE servex_heap_objects gauge\n")
	result.WriteString(fmt.Sprintf("servex_heap_objects %d\n", snapshot.SystemMetrics.HeapObjectCount))
	result.WriteString("\n")

	if snapshot.SystemMetrics.CPUUsagePercent > 0 {
		result.WriteString("# HELP servex_cpu_usage_percent CPU usage percentage\n")
		result.WriteString("# TYPE servex_cpu_usage_percent gauge\n")
		result.WriteString(fmt.Sprintf("servex_cpu_usage_percent %.2f\n", snapshot.SystemMetrics.CPUUsagePercent))
		result.WriteString("\n")
	}

	return result.String()
}

// prometheusEscape escapes special characters in label values for Prometheus format
func prometheusEscape(s string) string {
	// Escape backslashes first to avoid double-escaping
	s = strings.ReplaceAll(s, "\\", "\\\\")
	// Escape quotes
	s = strings.ReplaceAll(s, "\"", "\\\"")
	// Escape newlines (though they shouldn't appear in paths)
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}
