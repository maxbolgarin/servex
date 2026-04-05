package servex

import (
	"fmt"
	"math"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
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

// builtinMetrics provides comprehensive request and system metrics.
// All hot-path recording uses lock-free atomic operations and sync.Map.
type builtinMetrics struct {
	startTimeNano   atomic.Int64 // UnixNano of start time
	requestCount    atomic.Int64
	responseCount    atomic.Int64
	errorCount       atomic.Int64
	totalRequestTime atomic.Int64 // in nanoseconds

	statusCodes   sync.Map // map[int]*atomic.Int64
	pathMetricsM  sync.Map // map[string]*atomicPathMetrics
	methodMetrics sync.Map // map[string]*atomic.Int64

	maxPathMetrics  int          // cardinality cap, default 1000
	pathMetricCount atomic.Int32 // current number of unique paths

	enabled atomic.Bool

	// WebSocket metrics
	wsConnections  atomic.Int64 // current active connections (gauge)
	wsConnTotal    atomic.Int64 // total connections ever opened
	wsDisconnTotal atomic.Int64 // total connections closed
	wsMsgSentTotal atomic.Int64 // total messages sent
	wsMsgRecvTotal atomic.Int64 // total messages received
	wsErrorTotal   atomic.Int64 // total WebSocket errors
}

// atomicPathMetrics tracks metrics for specific paths using lock-free atomics.
type atomicPathMetrics struct {
	Count       atomic.Int64
	TotalTime   atomic.Int64 // in nanoseconds
	ErrorCount  atomic.Int64
	MaxTime     atomic.Int64
	MinTime     atomic.Int64
	StatusCodes sync.Map // map[int]*atomic.Int64
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

// defaultMaxPathMetrics is the default cardinality cap for path metrics.
const defaultMaxPathMetrics = 1000

// newBuiltinMetrics creates a new metrics collector
func newBuiltinMetrics() *builtinMetrics {
	m := &builtinMetrics{
		maxPathMetrics: defaultMaxPathMetrics,
	}
	m.startTimeNano.Store(time.Now().UnixNano())
	m.enabled.Store(true)
	return m
}

// startTime returns the start time reconstructed from the atomic UnixNano field.
func (m *builtinMetrics) startTime() time.Time {
	return time.Unix(0, m.startTimeNano.Load())
}

// Enable/disable metrics collection
func (m *builtinMetrics) setEnabled(enabled bool) {
	m.enabled.Store(enabled)
}

// HandleRequest implements the Metrics interface
func (m *builtinMetrics) HandleRequest(r *http.Request) {
	if !m.enabled.Load() {
		return
	}

	m.requestCount.Add(1)

	// Track method metrics (lock-free)
	method := r.Method
	if v, ok := m.methodMetrics.Load(method); ok {
		v.(*atomic.Int64).Add(1)
	} else {
		counter := &atomic.Int64{}
		counter.Store(1)
		if actual, loaded := m.methodMetrics.LoadOrStore(method, counter); loaded {
			actual.(*atomic.Int64).Add(1)
		}
	}
}

// HandleResponse implements the Metrics interface.
// It uses the gorilla/mux route template as the path label when available,
// falling back to the raw URL path. This prevents cardinality explosion
// from path parameters like /users/123, /users/456 becoming separate entries.
func (m *builtinMetrics) HandleResponse(r *http.Request, w http.ResponseWriter, statusCode int, duration time.Duration) {
	path := r.URL.Path
	if route := mux.CurrentRoute(r); route != nil {
		if tpl, err := route.GetPathTemplate(); err == nil {
			path = tpl
		}
	}
	m.recordResponse(path, r.Method, statusCode, duration, statusCode >= 400)
}

// recordResponse records response metrics using lock-free atomic operations.
func (m *builtinMetrics) recordResponse(path, method string, statusCode int, duration time.Duration, isError bool) {
	if !m.enabled.Load() {
		return
	}

	m.responseCount.Add(1)
	m.totalRequestTime.Add(duration.Nanoseconds())

	if isError {
		m.errorCount.Add(1)
	}

	// Track status codes (lock-free)
	atomicAdd(&m.statusCodes, statusCode)

	// Track path metrics (lock-free) with cardinality protection
	durationNs := duration.Nanoseconds()
	if v, ok := m.pathMetricsM.Load(path); ok {
		v.(*atomicPathMetrics).record(statusCode, durationNs, isError)
	} else {
		// Check cardinality cap before creating new entry
		if m.maxPathMetrics > 0 && int(m.pathMetricCount.Load()) >= m.maxPathMetrics {
			path = "_other"
			if v, ok := m.pathMetricsM.Load(path); ok {
				v.(*atomicPathMetrics).record(statusCode, durationNs, isError)
				return
			}
		}
		pm := newAtomicPathMetrics()
		if actual, loaded := m.pathMetricsM.LoadOrStore(path, pm); loaded {
			actual.(*atomicPathMetrics).record(statusCode, durationNs, isError)
		} else {
			m.pathMetricCount.Add(1)
			pm.record(statusCode, durationNs, isError)
		}
	}
}

// atomicAdd increments a counter in a sync.Map[K]*atomic.Int64, creating it if needed.
func atomicAdd[K comparable](m *sync.Map, key K) {
	if v, ok := m.Load(key); ok {
		v.(*atomic.Int64).Add(1)
		return
	}
	counter := &atomic.Int64{}
	counter.Store(1)
	if actual, loaded := m.LoadOrStore(key, counter); loaded {
		actual.(*atomic.Int64).Add(1)
	}
}

// newAtomicPathMetrics creates a new atomicPathMetrics with initial min/max set.
func newAtomicPathMetrics() *atomicPathMetrics {
	pm := &atomicPathMetrics{}
	pm.MinTime.Store(math.MaxInt64)
	return pm
}

// record atomically records a response into path metrics.
func (pm *atomicPathMetrics) record(statusCode int, durationNs int64, isError bool) {
	pm.Count.Add(1)
	pm.TotalTime.Add(durationNs)

	if isError {
		pm.ErrorCount.Add(1)
	}

	atomicAdd(&pm.StatusCodes, statusCode)

	// Update max time using CAS loop
	for {
		old := pm.MaxTime.Load()
		if durationNs <= old || pm.MaxTime.CompareAndSwap(old, durationNs) {
			break
		}
	}

	// Update min time using CAS loop
	for {
		old := pm.MinTime.Load()
		if durationNs >= old || pm.MinTime.CompareAndSwap(old, durationNs) {
			break
		}
	}
}

// getSnapshot returns current metrics snapshot (eventually consistent, no locks).
func (m *builtinMetrics) getSnapshot() metricsSnapshot {
	snapshot := metricsSnapshot{
		Timestamp:     time.Now(),
		Uptime:        time.Since(m.startTime()).String(),
		RequestCount:  m.requestCount.Load(),
		ResponseCount: m.responseCount.Load(),
		ErrorCount:    m.errorCount.Load(),
		StatusCodes:   make(map[int]int64),
		Methods:       make(map[string]int64),
		SystemMetrics: getSystemMetrics(),
	}

	// Copy status codes from sync.Map
	m.statusCodes.Range(func(key, value any) bool {
		snapshot.StatusCodes[key.(int)] = value.(*atomic.Int64).Load()
		return true
	})

	// Copy method metrics from sync.Map
	m.methodMetrics.Range(func(key, value any) bool {
		snapshot.Methods[key.(string)] = value.(*atomic.Int64).Load()
		return true
	})

	// Calculate derived metrics
	if snapshot.ResponseCount > 0 {
		snapshot.ErrorRate = (float64(snapshot.ErrorCount) / float64(snapshot.ResponseCount)) * 100

		totalTime := m.totalRequestTime.Load()
		snapshot.AvgResponseTime = float64(totalTime) / float64(snapshot.ResponseCount) / 1e6 // Convert to milliseconds
	}

	// Calculate requests per second
	uptime := time.Since(m.startTime()).Seconds()
	if uptime > 0 {
		snapshot.RequestsPerSec = float64(snapshot.RequestCount) / uptime
	}

	// Generate top paths
	snapshot.TopPaths = m.getTopPaths(10)

	return snapshot
}

// getTopPaths returns the top N paths by request count
func (m *builtinMetrics) getTopPaths(limit int) []pathSummary {
	type pathEntry struct {
		path   string
		metric *atomicPathMetrics
		count  int64
	}

	var paths []pathEntry
	m.pathMetricsM.Range(func(key, value any) bool {
		pm := value.(*atomicPathMetrics)
		count := pm.Count.Load()
		paths = append(paths, pathEntry{path: key.(string), metric: pm, count: count})
		return true
	})

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
		pm := paths[i].metric
		count := paths[i].count
		errorCount := pm.ErrorCount.Load()
		minTime := pm.MinTime.Load()
		if minTime == math.MaxInt64 {
			minTime = 0
		}

		summary := pathSummary{
			Path:            paths[i].path,
			Count:           count,
			ErrorCount:      errorCount,
			AvgResponseTime: float64(pm.TotalTime.Load()) / float64(count) / 1e6,
			MaxResponseTime: float64(pm.MaxTime.Load()) / 1e6,
			MinResponseTime: float64(minTime) / 1e6,
		}

		if count > 0 {
			summary.ErrorRate = (float64(errorCount) / float64(count)) * 100
		}

		summaries = append(summaries, summary)
	}

	return summaries
}

// loadStatusCode returns the count for a specific status code.
func (m *builtinMetrics) loadStatusCode(code int) int64 {
	if v, ok := m.statusCodes.Load(code); ok {
		return v.(*atomic.Int64).Load()
	}
	return 0
}

// loadMethodCount returns the count for a specific HTTP method.
func (m *builtinMetrics) loadMethodCount(method string) int64 {
	if v, ok := m.methodMetrics.Load(method); ok {
		return v.(*atomic.Int64).Load()
	}
	return 0
}

// loadPathMetric returns the atomic path metrics for a path, or nil if not found.
func (m *builtinMetrics) loadPathMetric(path string) *atomicPathMetrics {
	if v, ok := m.pathMetricsM.Load(path); ok {
		return v.(*atomicPathMetrics)
	}
	return nil
}

// statusCodesLen returns the number of unique status codes tracked.
func (m *builtinMetrics) statusCodesLen() int {
	n := 0
	m.statusCodes.Range(func(_, _ any) bool { n++; return true })
	return n
}

// pathMetricsLen returns the number of unique paths tracked.
func (m *builtinMetrics) pathMetricsLen() int {
	return int(m.pathMetricCount.Load())
}

// methodMetricsLen returns the number of unique methods tracked.
func (m *builtinMetrics) methodMetricsLen() int {
	n := 0
	m.methodMetrics.Range(func(_, _ any) bool { n++; return true })
	return n
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
	}).Methods(GET)
}

// WebSocket metrics recording methods

func (m *builtinMetrics) wsConnect() {
	m.wsConnections.Add(1)
	m.wsConnTotal.Add(1)
}

func (m *builtinMetrics) wsDisconnect() {
	m.wsConnections.Add(-1)
	m.wsDisconnTotal.Add(1)
}

func (m *builtinMetrics) wsMsgSent() {
	m.wsMsgSentTotal.Add(1)
}

func (m *builtinMetrics) wsMsgRecv() {
	m.wsMsgRecvTotal.Add(1)
}

func (m *builtinMetrics) wsError() {
	m.wsErrorTotal.Add(1)
}

// reset clears all metrics (useful for testing)
func (m *builtinMetrics) reset() {
	m.requestCount.Store(0)
	m.responseCount.Store(0)
	m.errorCount.Store(0)
	m.totalRequestTime.Store(0)

	m.startTimeNano.Store(time.Now().UnixNano())

	// Clear sync.Maps by deleting all entries
	m.statusCodes.Range(func(key, _ any) bool { m.statusCodes.Delete(key); return true })
	m.pathMetricsM.Range(func(key, _ any) bool { m.pathMetricsM.Delete(key); return true })
	m.methodMetrics.Range(func(key, _ any) bool { m.methodMetrics.Delete(key); return true })
	m.pathMetricCount.Store(0)

	m.wsConnections.Store(0)
	m.wsConnTotal.Store(0)
	m.wsDisconnTotal.Store(0)
	m.wsMsgSentTotal.Store(0)
	m.wsMsgRecvTotal.Store(0)
	m.wsErrorTotal.Store(0)
}

// getPrometheusMetrics returns metrics in Prometheus text format
func (m *builtinMetrics) getPrometheusMetrics() string {
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
	uptimeSeconds := time.Since(m.startTime()).Seconds()
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

	// WebSocket metrics
	result.WriteString("# HELP servex_ws_connections_active Current number of active WebSocket connections\n")
	result.WriteString("# TYPE servex_ws_connections_active gauge\n")
	result.WriteString(fmt.Sprintf("servex_ws_connections_active %d\n", m.wsConnections.Load()))
	result.WriteString("\n")

	result.WriteString("# HELP servex_ws_connections_total Total WebSocket connections opened\n")
	result.WriteString("# TYPE servex_ws_connections_total counter\n")
	result.WriteString(fmt.Sprintf("servex_ws_connections_total %d\n", m.wsConnTotal.Load()))
	result.WriteString("\n")

	result.WriteString("# HELP servex_ws_disconnections_total Total WebSocket connections closed\n")
	result.WriteString("# TYPE servex_ws_disconnections_total counter\n")
	result.WriteString(fmt.Sprintf("servex_ws_disconnections_total %d\n", m.wsDisconnTotal.Load()))
	result.WriteString("\n")

	result.WriteString("# HELP servex_ws_messages_sent_total Total WebSocket messages sent\n")
	result.WriteString("# TYPE servex_ws_messages_sent_total counter\n")
	result.WriteString(fmt.Sprintf("servex_ws_messages_sent_total %d\n", m.wsMsgSentTotal.Load()))
	result.WriteString("\n")

	result.WriteString("# HELP servex_ws_messages_received_total Total WebSocket messages received\n")
	result.WriteString("# TYPE servex_ws_messages_received_total counter\n")
	result.WriteString(fmt.Sprintf("servex_ws_messages_received_total %d\n", m.wsMsgRecvTotal.Load()))
	result.WriteString("\n")

	result.WriteString("# HELP servex_ws_errors_total Total WebSocket errors\n")
	result.WriteString("# TYPE servex_ws_errors_total counter\n")
	result.WriteString(fmt.Sprintf("servex_ws_errors_total %d\n", m.wsErrorTotal.Load()))
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

// compositeMetrics combines multiple Metrics implementations, calling each in sequence.
// This allows using both built-in default metrics and custom metrics simultaneously.
//
// Example:
//
//	defaultMetrics := newBuiltinMetrics()
//	customMetrics := &MyPrometheusMetrics{}
//	combined := newCompositeMetrics(defaultMetrics, customMetrics)
type compositeMetrics struct {
	metrics []Metrics
}

// newCompositeMetrics creates a new composite metrics collector that calls multiple metrics implementations.
//
// Parameters:
//   - metrics: Variable number of Metrics implementations to combine
//
// Returns:
//   - *compositeMetrics: A composite metrics collector that forwards calls to all provided implementations
func newCompositeMetrics(metrics ...Metrics) *compositeMetrics {
	return &compositeMetrics{
		metrics: metrics,
	}
}

// HandleRequest implements the Metrics interface by forwarding to all underlying metrics.
func (c *compositeMetrics) HandleRequest(r *http.Request) {
	for _, m := range c.metrics {
		if m != nil {
			m.HandleRequest(r)
		}
	}
}

// HandleResponse implements the Metrics interface by forwarding to all underlying metrics.
func (c *compositeMetrics) HandleResponse(r *http.Request, w http.ResponseWriter, statusCode int, duration time.Duration) {
	for _, m := range c.metrics {
		if m != nil {
			m.HandleResponse(r, w, statusCode, duration)
		}
	}
}

// getBuiltinMetrics returns the first builtinMetrics instance from the composite, or nil if none exists.
// This is used internally to register the metrics endpoint when using WithMetricsAndDefault.
func (c *compositeMetrics) getBuiltinMetrics() *builtinMetrics {
	for _, m := range c.metrics {
		if builtin, ok := m.(*builtinMetrics); ok {
			return builtin
		}
	}
	return nil
}
