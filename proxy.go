package servex

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maxbolgarin/lang"
)

// LoadBalancingStrategy defines the load balancing algorithm
type LoadBalancingStrategy string

const (
	// RoundRobinStrategy cycles through backends in order
	RoundRobinStrategy LoadBalancingStrategy = "round_robin"
	// WeightedRoundRobinStrategy cycles through backends based on weights
	WeightedRoundRobinStrategy LoadBalancingStrategy = "weighted_round_robin"
	// LeastConnectionsStrategy routes to backend with fewest active connections
	LeastConnectionsStrategy LoadBalancingStrategy = "least_connections"
	// RandomStrategy routes to a random backend
	RandomStrategy LoadBalancingStrategy = "random"
	// WeightedRandomStrategy routes to a random backend based on weights
	WeightedRandomStrategy LoadBalancingStrategy = "weighted_random"
	// IPHashStrategy routes based on client IP hash (session affinity)
	IPHashStrategy LoadBalancingStrategy = "ip_hash"
)

// Backend represents a backend server
type Backend struct {
	// URL is the backend server URL
	URL string `yaml:"url" json:"url"`
	// Weight for weighted load balancing (default: 1)
	Weight int `yaml:"weight" json:"weight"`
	// HealthCheckPath for health checking (optional)
	HealthCheckPath string `yaml:"health_check_path" json:"health_check_path"`
	// HealthCheckInterval for health checking (default: 30s)
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
	// MaxConnections limits concurrent connections to this backend (0 = unlimited)
	MaxConnections int `yaml:"max_connections" json:"max_connections"`

	// Internal fields
	url         *url.URL
	healthy     atomic.Bool
	connections atomic.Int64
	proxy       *httputil.ReverseProxy
}

// ProxyRule represents a routing rule for the proxy
type ProxyRule struct {
	// Name is a unique identifier for the rule
	Name string `yaml:"name" json:"name"`
	// PathPrefix matches request paths starting with this prefix
	PathPrefix string `yaml:"path_prefix" json:"path_prefix"`
	// PathRegex matches request paths using regex (alternative to PathPrefix)
	PathRegex string `yaml:"path_regex" json:"path_regex"`
	// Host matches request Host header
	Host string `yaml:"host" json:"host"`
	// Headers matches specific request headers
	Headers map[string]string `yaml:"headers" json:"headers"`
	// Methods restricts rule to specific HTTP methods
	Methods []string `yaml:"methods" json:"methods"`
	// Backends defines the backend servers for this rule
	Backends []Backend `yaml:"backends" json:"backends"`
	// LoadBalancing strategy for this rule
	LoadBalancing LoadBalancingStrategy `yaml:"load_balancing" json:"load_balancing"`
	// StripPrefix removes prefix from path before forwarding
	StripPrefix string `yaml:"strip_prefix" json:"strip_prefix"`
	// AddPrefix adds prefix to path before forwarding
	AddPrefix string `yaml:"add_prefix" json:"add_prefix"`
	// Timeout for backend requests
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
	// EnableTrafficDump enables traffic dumping for this rule
	EnableTrafficDump bool `yaml:"enable_traffic_dump" json:"enable_traffic_dump"`
	// DumpDirectory specifies where to dump traffic (uses global if empty)
	DumpDirectory string `yaml:"dump_directory" json:"dump_directory"`

	// Internal fields
	counter      atomic.Uint64 // for round robin
	backends     []*Backend
	healthyCount atomic.Int32
}

// ProxyConfiguration represents the complete proxy configuration
type ProxyConfiguration struct {
	// Enabled indicates if the proxy is enabled
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Rules defines the routing rules
	Rules []ProxyRule `yaml:"rules" json:"rules"`
	// GlobalTimeout for all proxy requests
	GlobalTimeout time.Duration `yaml:"global_timeout" json:"global_timeout"`
	// MaxIdleConns for connection pooling
	MaxIdleConns int `yaml:"max_idle_conns" json:"max_idle_conns"`
	// MaxIdleConnsPerHost for connection pooling
	MaxIdleConnsPerHost int `yaml:"max_idle_conns_per_host" json:"max_idle_conns_per_host"`
	// IdleConnTimeout for connection pooling
	IdleConnTimeout time.Duration `yaml:"idle_conn_timeout" json:"idle_conn_timeout"`
	// TrafficDump configuration
	TrafficDump TrafficDumpConfig `yaml:"traffic_dump" json:"traffic_dump"`
	// HealthCheck configuration
	HealthCheck HealthCheckConfig `yaml:"health_check" json:"health_check"`
	// InsecureSkipVerify skips certificate verification
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
}

// TrafficDumpConfig configures traffic dumping
type TrafficDumpConfig struct {
	// Enabled indicates if traffic dumping is enabled globally
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Directory where to store traffic dumps
	Directory string `yaml:"directory" json:"directory"`
	// MaxFileSize for rotation (in bytes, default: 100MB)
	MaxFileSize int64 `yaml:"max_file_size" json:"max_file_size"`
	// MaxFiles for retention (default: 10)
	MaxFiles int `yaml:"max_files" json:"max_files"`
	// IncludeBody whether to include request/response bodies
	IncludeBody bool `yaml:"include_body" json:"include_body"`
	// MaxBodySize maximum body size to dump (default: 64KB)
	MaxBodySize int64 `yaml:"max_body_size" json:"max_body_size"`
	// SampleRate for sampling traffic (0.0-1.0, default: 1.0 = all traffic)
	SampleRate float64 `yaml:"sample_rate" json:"sample_rate"`
}

// HealthCheckConfig configures health checking
type HealthCheckConfig struct {
	// Enabled indicates if health checking is enabled
	Enabled bool `yaml:"enabled" json:"enabled"`
	// DefaultInterval for health checks
	DefaultInterval time.Duration `yaml:"default_interval" json:"default_interval"`
	// Timeout for health check requests
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
	// RetryCount before marking backend as unhealthy
	RetryCount int `yaml:"retry_count" json:"retry_count"`
}

// proxyManager manages the reverse proxy functionality
type proxyManager struct {
	config     ProxyConfiguration
	rules      []*ProxyRule
	client     *http.Client
	dumpWriter *trafficDumpWriter
	logger     Logger
	mu         sync.RWMutex
}

// trafficDumpWriter handles writing traffic dumps to files
type trafficDumpWriter struct {
	config    TrafficDumpConfig
	mu        sync.Mutex
	file      *os.File
	size      int64
	fileIndex int
	basePath  string
}

// RegisterProxyMiddleware registers the proxy middleware
//
// Parameters:
//   - router: The router to register the middleware for
//   - config: The proxy configuration to register the middleware for
//   - logger: The logger to register the middleware for (optional)
//
// Example:
//
//	RegisterProxyMiddleware(router, config, logger)
//
// Returns:
//   - *ProxyManager: The proxy manager
func RegisterProxyMiddleware(router MiddlewareRouter, config ProxyConfiguration, logger ...Logger) error {
	if !config.Enabled {
		return nil
	}

	pm, err := newProxyManager(config, lang.First(logger))
	if err != nil {
		return err
	}

	// Register proxy middleware
	router.Use(pm.proxyMiddleware)

	return nil
}

// newProxyManager creates a new proxy manager
func newProxyManager(config ProxyConfiguration, logger Logger) (*proxyManager, error) {
	if !config.Enabled {
		return nil, nil
	}

	// Set defaults
	if config.GlobalTimeout == 0 {
		config.GlobalTimeout = 30 * time.Second
	}
	if config.MaxIdleConns == 0 {
		config.MaxIdleConns = 100
	}
	if config.MaxIdleConnsPerHost == 0 {
		config.MaxIdleConnsPerHost = 10
	}
	if config.IdleConnTimeout == 0 {
		config.IdleConnTimeout = 90 * time.Second
	}
	if config.TrafficDump.MaxFileSize == 0 {
		config.TrafficDump.MaxFileSize = 100 * 1024 * 1024 // 100MB
	}
	if config.TrafficDump.MaxFiles == 0 {
		config.TrafficDump.MaxFiles = 10
	}
	if config.TrafficDump.MaxBodySize == 0 {
		config.TrafficDump.MaxBodySize = 64 * 1024 // 64KB
	}
	if config.TrafficDump.SampleRate == 0 {
		config.TrafficDump.SampleRate = 1.0
	}
	if config.HealthCheck.DefaultInterval == 0 {
		config.HealthCheck.DefaultInterval = 30 * time.Second
	}
	if config.HealthCheck.Timeout == 0 {
		config.HealthCheck.Timeout = 5 * time.Second
	}
	if config.HealthCheck.RetryCount == 0 {
		config.HealthCheck.RetryCount = 3
	}

	// Create HTTP client with connection pooling
	transport := &http.Transport{
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		IdleConnTimeout:     config.IdleConnTimeout,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: config.InsecureSkipVerify},
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: config.GlobalTimeout,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.GlobalTimeout,
	}

	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}

	pm := &proxyManager{
		config: config,
		client: client,
		logger: logger,
	}

	// Initialize traffic dump writer if enabled
	if config.TrafficDump.Enabled && config.TrafficDump.Directory != "" {
		var err error
		pm.dumpWriter, err = newTrafficDumpWriter(config.TrafficDump)
		if err != nil {
			return nil, fmt.Errorf("create traffic dump writer: %w", err)
		}
	}

	// Initialize rules
	pm.rules = make([]*ProxyRule, len(config.Rules))

	for i := range config.Rules {
		rule := &config.Rules[i]
		if err := pm.initializeRule(rule); err != nil {
			return nil, fmt.Errorf("initialize rule %s: %w", rule.Name, err)
		}
		pm.rules[i] = rule
	}

	// Start health checks if enabled
	if config.HealthCheck.Enabled {
		pm.startHealthChecks()
	}

	return pm, nil
}

// initializeRule initializes a proxy rule
func (pm *proxyManager) initializeRule(rule *ProxyRule) error {
	if rule.LoadBalancing == "" {
		rule.LoadBalancing = RoundRobinStrategy
	}
	if rule.Timeout == 0 {
		rule.Timeout = pm.config.GlobalTimeout
	}

	// Initialize backends
	rule.backends = make([]*Backend, len(rule.Backends))
	for i := range rule.Backends {
		backend := &rule.Backends[i]
		if err := pm.initializeBackend(backend); err != nil {
			return fmt.Errorf("initialize backend %s: %w", backend.URL, err)
		}
		rule.backends[i] = backend
		rule.healthyCount.Add(1) // Assume healthy initially
	}

	return nil
}

// initializeBackend initializes a backend
func (pm *proxyManager) initializeBackend(backend *Backend) error {
	var err error
	backend.url, err = url.Parse(backend.URL)
	if err != nil {
		return fmt.Errorf("parse backend URL %s: %w", backend.URL, err)
	}

	if backend.Weight == 0 {
		backend.Weight = 1
	}
	if backend.HealthCheckInterval == 0 {
		backend.HealthCheckInterval = pm.config.HealthCheck.DefaultInterval
	}

	backend.healthy.Store(true) // Assume healthy initially

	// Create reverse proxy for this backend
	backend.proxy = httputil.NewSingleHostReverseProxy(backend.url)
	backend.proxy.Transport = pm.client.Transport
	backend.proxy.ErrorHandler = pm.createErrorHandler(backend)

	return nil
}

// createErrorHandler creates an error handler for a backend
func (pm *proxyManager) createErrorHandler(backend *Backend) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		pm.logger.Error("proxy error", "backend", backend.URL, "error", err, "path", r.URL.Path)
		backend.healthy.Store(false)

		// Decrement connection count
		backend.connections.Add(-1)

		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}
}

// proxyMiddleware is the main proxy middleware
func (pm *proxyManager) proxyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pm.logger.Debug("proxyMiddleware", "path", r.URL.Path)
		// Find matching rule
		rule := pm.findMatchingRule(r)
		if rule == nil {
			// No rule matches, continue to next handler
			next.ServeHTTP(w, r)
			return
		}

		// Handle proxy request
		pm.handleProxyRequestEnhanced(w, r, rule)
	})
}

// findMatchingRule finds the first rule that matches the request
func (pm *proxyManager) findMatchingRule(r *http.Request) *ProxyRule {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, rule := range pm.rules {
		if pm.ruleMatches(rule, r) {
			return rule
		}
	}
	return nil
}

// ruleMatches checks if a rule matches the request
func (pm *proxyManager) ruleMatches(rule *ProxyRule, r *http.Request) bool {
	// Check path prefix
	if rule.PathPrefix != "" && !strings.HasPrefix(r.URL.Path, rule.PathPrefix) {
		return false
	}

	// Check host
	if rule.Host != "" && r.Host != rule.Host {
		return false
	}

	// Check methods
	if len(rule.Methods) > 0 {
		methodMatches := false
		for _, method := range rule.Methods {
			if r.Method == method {
				methodMatches = true
				break
			}
		}
		if !methodMatches {
			return false
		}
	}

	// Check headers
	for key, value := range rule.Headers {
		if r.Header.Get(key) != value {
			return false
		}
	}

	return true
}

// Enhanced handleProxyRequest with better logging and monitoring
func (pm *proxyManager) handleProxyRequestEnhanced(w http.ResponseWriter, r *http.Request, rule *ProxyRule) {
	startTime := time.Now()

	// Create proxy logger if not exists
	proxyLogger := newProxyLogger(pm.logger)

	// Select backend using load balancing strategy
	backend := pm.selectBackend(rule, r)
	if backend == nil {
		proxyLogger.logRequest(rule, nil, r, time.Since(startTime), http.StatusServiceUnavailable, fmt.Errorf("no healthy backends available"))
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	// Check connection limits
	if backend.MaxConnections > 0 && backend.connections.Load() >= int64(backend.MaxConnections) {
		proxyLogger.logRequest(rule, backend, r, time.Since(startTime), http.StatusServiceUnavailable, fmt.Errorf("connection limit exceeded"))
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	// Increment connection count
	backend.connections.Add(1)
	defer backend.connections.Add(-1)

	// Enhanced traffic dumping with RAW HTTP
	if (rule.EnableTrafficDump || pm.config.TrafficDump.Enabled) && pm.shouldSampleRequest() {
		pm.dumpTrafficEnhanced(r, rule, backend)
	}

	// Modify request path if needed
	originalPath := r.URL.Path
	if rule.StripPrefix != "" {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, rule.StripPrefix)
	}
	if rule.AddPrefix != "" {
		r.URL.Path = rule.AddPrefix + r.URL.Path
	}

	// Set timeout for this request
	ctx, cancel := context.WithTimeout(r.Context(), rule.Timeout)
	defer cancel()
	r = r.WithContext(ctx)

	// Create response recorder to capture status code
	recorder := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

	// Proxy the request
	backend.proxy.ServeHTTP(recorder, r)

	// Calculate duration and log request
	duration := time.Since(startTime)
	proxyLogger.logRequest(rule, backend, r, duration, recorder.statusCode, nil)

	// Restore original path
	r.URL.Path = originalPath
}

// responseRecorder captures the response status code
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	rr.ResponseWriter.WriteHeader(code)
}

// selectBackend selects a backend using the configured load balancing strategy
func (pm *proxyManager) selectBackend(rule *ProxyRule, r *http.Request) *Backend {
	healthyBackends := make([]*Backend, 0, len(rule.backends))
	for _, backend := range rule.backends {
		if backend.healthy.Load() {
			healthyBackends = append(healthyBackends, backend)
		}
	}

	if len(healthyBackends) == 0 {
		pm.logger.Error("no healthy backends available", "rule", rule.Name)
		return nil
	}

	switch rule.LoadBalancing {
	case RoundRobinStrategy:
		return pm.selectRoundRobin(rule, healthyBackends)
	case WeightedRoundRobinStrategy:
		return pm.selectWeightedRoundRobin(rule, healthyBackends)
	case LeastConnectionsStrategy:
		return pm.selectLeastConnections(healthyBackends)
	case RandomStrategy:
		return pm.selectRandom(healthyBackends)
	case WeightedRandomStrategy:
		return pm.selectWeightedRandom(healthyBackends)
	case IPHashStrategy:
		return pm.selectIPHash(r, healthyBackends)
	default:
		return pm.selectRoundRobin(rule, healthyBackends)
	}
}

// selectRoundRobin implements round-robin load balancing
func (pm *proxyManager) selectRoundRobin(rule *ProxyRule, backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}
	index := rule.counter.Add(1) - 1
	return backends[index%uint64(len(backends))]
}

// selectWeightedRoundRobin implements weighted round-robin load balancing
func (pm *proxyManager) selectWeightedRoundRobin(rule *ProxyRule, backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	// Calculate total weight
	totalWeight := 0
	for _, backend := range backends {
		totalWeight += backend.Weight
	}

	if totalWeight == 0 {
		return pm.selectRoundRobin(rule, backends)
	}

	// Use counter to determine position in weighted sequence
	position := int(rule.counter.Add(1)-1) % totalWeight
	currentWeight := 0

	for _, backend := range backends {
		currentWeight += backend.Weight
		if position < currentWeight {
			return backend
		}
	}

	return backends[0]
}

// selectLeastConnections implements least connections load balancing
func (pm *proxyManager) selectLeastConnections(backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	minConnections := backends[0].connections.Load()
	selectedBackend := backends[0]

	for _, backend := range backends[1:] {
		connections := backend.connections.Load()
		if connections < minConnections {
			minConnections = connections
			selectedBackend = backend
		}
	}

	return selectedBackend
}

// selectRandom implements random load balancing
func (pm *proxyManager) selectRandom(backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}
	return backends[rand.Intn(len(backends))]
}

// selectWeightedRandom implements weighted random load balancing
func (pm *proxyManager) selectWeightedRandom(backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	// Calculate total weight
	totalWeight := 0
	for _, backend := range backends {
		totalWeight += backend.Weight
	}

	if totalWeight == 0 {
		return pm.selectRandom(backends)
	}

	// Generate random number and select backend
	randomWeight := rand.Intn(totalWeight)
	currentWeight := 0

	for _, backend := range backends {
		currentWeight += backend.Weight
		if randomWeight < currentWeight {
			return backend
		}
	}

	return backends[0]
}

// selectIPHash implements IP hash-based load balancing for session affinity
func (pm *proxyManager) selectIPHash(r *http.Request, backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	// Get client IP
	clientIP := pm.getClientIP(r)

	// Simple hash function
	hash := 0
	for _, b := range []byte(clientIP) {
		hash = hash*31 + int(b)
	}
	if hash < 0 {
		hash = -hash
	}

	return backends[hash%len(backends)]
}

// getClientIP extracts the real client IP from the request
func (pm *proxyManager) getClientIP(r *http.Request) string {
	// Check X-Real-IP header
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Fall back to RemoteAddr
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}

	return r.RemoteAddr
}

// shouldSampleRequest determines if this request should be sampled for traffic dumping
func (pm *proxyManager) shouldSampleRequest() bool {
	if pm.config.TrafficDump.SampleRate >= 1.0 {
		return true
	}
	if pm.config.TrafficDump.SampleRate <= 0.0 {
		return false
	}
	return rand.Float64() < pm.config.TrafficDump.SampleRate
}

// newTrafficDumpWriter creates a new traffic dump writer
func newTrafficDumpWriter(config TrafficDumpConfig) (*trafficDumpWriter, error) {
	if config.Directory == "" {
		return nil, fmt.Errorf("dump directory is required")
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(config.Directory, 0755); err != nil {
		return nil, fmt.Errorf("create dump directory: %w", err)
	}

	basePath := filepath.Join(config.Directory, "traffic_dump")

	tdw := &trafficDumpWriter{
		config:   config,
		basePath: basePath,
	}

	// Create initial file
	if err := tdw.rotateFile(); err != nil {
		return nil, fmt.Errorf("create initial dump file: %w", err)
	}

	return tdw, nil
}

// rotateFile creates a new dump file and closes the old one
func (tdw *trafficDumpWriter) rotateFile() error {
	// Close current file if exists
	if tdw.file != nil {
		tdw.file.Close()
	}

	// Create new file
	filename := fmt.Sprintf("%s_%03d.jsonl", tdw.basePath, tdw.fileIndex)
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	tdw.file = file
	tdw.size = 0
	tdw.fileIndex++

	// Clean up old files if we exceed the limit
	if tdw.config.MaxFiles > 0 && tdw.fileIndex > tdw.config.MaxFiles {
		oldFile := fmt.Sprintf("%s_%03d.jsonl", tdw.basePath, tdw.fileIndex-tdw.config.MaxFiles-1)
		os.Remove(oldFile) // Ignore errors
	}

	return nil
}

// rawHTTPDumpEntry represents a raw HTTP traffic dump entry
type rawHTTPDumpEntry struct {
	Timestamp      time.Time           `json:"timestamp"`
	Rule           string              `json:"rule"`
	Backend        string              `json:"backend"`
	ClientIP       string              `json:"client_ip"`
	RawRequest     string              `json:"raw_request"`
	RequestHeaders map[string][]string `json:"request_headers"`
	StatusCode     int                 `json:"status_code,omitempty"`
}

// Enhanced traffic dumping with RAW HTTP capture
func (pm *proxyManager) dumpTrafficEnhanced(r *http.Request, rule *ProxyRule, backend *Backend) {
	if pm.dumpWriter == nil {
		return
	}

	// Capture raw HTTP request
	var rawRequest strings.Builder
	rawRequest.WriteString(fmt.Sprintf("%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto))
	rawRequest.WriteString(fmt.Sprintf("Host: %s\r\n", r.Host))

	// Add all headers
	for name, values := range r.Header {
		for _, value := range values {
			rawRequest.WriteString(fmt.Sprintf("%s: %s\r\n", name, value))
		}
	}
	rawRequest.WriteString("\r\n")

	// Add body if enabled and not too large
	var bodyData []byte
	if pm.config.TrafficDump.IncludeBody && r.ContentLength > 0 && r.ContentLength <= pm.config.TrafficDump.MaxBodySize {
		bodyData, _ = io.ReadAll(io.LimitReader(r.Body, pm.config.TrafficDump.MaxBodySize))
		if len(bodyData) > 0 {
			rawRequest.Write(bodyData)
			// Restore body for actual proxying
			r.Body = io.NopCloser(bytes.NewReader(bodyData))
		}
	}

	entry := rawHTTPDumpEntry{
		Timestamp:      time.Now(),
		Rule:           rule.Name,
		Backend:        backend.URL,
		ClientIP:       pm.getClientIP(r),
		RawRequest:     rawRequest.String(),
		RequestHeaders: make(map[string][]string),
	}

	// Copy headers
	for name, values := range r.Header {
		entry.RequestHeaders[name] = values
	}

	// Write entry (response will be added later if response capture is implemented)
	pm.dumpWriter.writeRawEntry(entry)
}

// writeRawEntry writes a raw HTTP dump entry to the file
func (tdw *trafficDumpWriter) writeRawEntry(entry rawHTTPDumpEntry) error {
	tdw.mu.Lock()
	defer tdw.mu.Unlock()

	// Check if we need to rotate the file
	if tdw.size >= tdw.config.MaxFileSize {
		if err := tdw.rotateFile(); err != nil {
			return fmt.Errorf("rotate dump file: %w", err)
		}
	}

	// Write entry as JSON line
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}

	line := string(entryJSON) + "\n"
	n, err := tdw.file.WriteString(line)
	if err != nil {
		return fmt.Errorf("write entry: %w", err)
	}

	tdw.size += int64(n)

	// Flush to ensure data is written
	return tdw.file.Sync()
}

// close closes the traffic dump writer
func (tdw *trafficDumpWriter) close() error {
	tdw.mu.Lock()
	defer tdw.mu.Unlock()

	if tdw.file != nil {
		return tdw.file.Close()
	}
	return nil
}

// proxyLogger is a specialized logger for proxy operations
type proxyLogger struct {
	logger Logger
}

// fieldsPool is a pool for reusing log field slices to reduce allocations
var fieldsPool = sync.Pool{
	New: func() any {
		// Pre-allocate with maximum capacity to avoid reallocations
		// Base fields: 24 elements (12 key-value pairs) + potential error: 2 elements = 26 total
		return make([]any, 0, 26)
	},
}

// newProxyLogger creates a new proxy logger
func newProxyLogger(logger Logger) *proxyLogger {
	return &proxyLogger{logger: logger}
}

// LogRequest logs proxy request details
func (pl *proxyLogger) logRequest(rule *ProxyRule, backend *Backend, r *http.Request, duration time.Duration, statusCode int, err error) {
	backendURL := "no backend"
	backendConnections := int64(0)
	backendHealthy := false
	if backend != nil {
		backendURL = backend.URL
		backendConnections = backend.connections.Load()
		backendHealthy = backend.healthy.Load()
	}

	// Get a slice from the pool to avoid allocations
	fields := fieldsPool.Get().([]any)
	defer func() {
		// Reset slice length and return to pool
		fields = fields[:0]
		fieldsPool.Put(fields)
	}()

	// Resize slice to needed length (24 elements for base fields)
	fields = fields[:24]

	// Use indexed assignment to avoid any slice growth
	fields[0] = "rule"
	fields[1] = rule.Name
	fields[2] = "backend"
	fields[3] = backendURL
	fields[4] = "method"
	fields[5] = r.Method
	fields[6] = "path"
	fields[7] = r.URL.Path
	fields[8] = "host"
	fields[9] = r.Host
	fields[10] = "remote_addr"
	fields[11] = r.RemoteAddr
	fields[12] = "user_agent"
	fields[13] = r.Header.Get("User-Agent")
	fields[14] = "duration_ms"
	fields[15] = duration.Milliseconds()
	fields[16] = "status_code"
	fields[17] = statusCode
	fields[18] = "backend_connections"
	fields[19] = backendConnections
	fields[20] = "backend_healthy"
	fields[21] = backendHealthy
	fields[22] = "load_balancing"
	fields[23] = string(rule.LoadBalancing)

	if err != nil {
		// Extend slice to include error fields without reallocation
		fields = fields[:26]
		fields[24] = "error"
		fields[25] = err.Error()
		pl.logger.Error("proxy failed", fields...)
	} else if statusCode >= 400 {
		pl.logger.Error("proxy client error", fields...)
	} else {
		pl.logger.Info("proxy", fields...)
	}
}

// LogBackendHealthChange logs backend health status changes
func (pl *proxyLogger) logBackendHealthChange(backend *Backend, healthy bool, err error) {
	fields := []any{
		"component", "proxy",
		"backend", backend.URL,
		"healthy", healthy,
	}

	if err != nil {
		fields = append(fields, "error", err.Error())
	}

	if healthy {
		pl.logger.Info("backend recovered", fields...)
	} else {
		pl.logger.Error("backend unhealthy", fields...)
	}
}

// Enhanced health check with better lifecycle management
func (pm *proxyManager) startHealthChecks() {
	for _, rule := range pm.rules {
		for _, backend := range rule.backends {
			if backend.HealthCheckPath != "" {
				go pm.healthCheckLoopEnhanced(backend)
			}
		}
	}
}

// healthCheckLoopEnhanced with better lifecycle and logging
func (pm *proxyManager) healthCheckLoopEnhanced(backend *Backend) {
	proxyLogger := newProxyLogger(pm.logger)
	ticker := time.NewTicker(backend.HealthCheckInterval)
	defer ticker.Stop()

	// Create a context for health check lifecycle management
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Log start of health checking
	pm.logger.Info("starting health checks",
		"component", "proxy",
		"backend", backend.URL,
		"interval", backend.HealthCheckInterval,
		"path", backend.HealthCheckPath,
	)

	for {
		select {
		case <-ctx.Done():
			pm.logger.Info("stopping health checks", "component", "proxy", "backend", backend.URL)
			return
		case <-ticker.C:
			pm.performHealthCheckEnhanced(backend, proxyLogger)
		}
	}
}

// performHealthCheckEnhanced with better error handling and logging
func (pm *proxyManager) performHealthCheckEnhanced(backend *Backend, proxyLogger *proxyLogger) {
	healthURL := backend.url.ResolveReference(&url.URL{Path: backend.HealthCheckPath})

	// Create health check client with timeout
	client := &http.Client{
		Timeout: pm.config.HealthCheck.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // For health checks only
			MaxIdleConns:    10,
			IdleConnTimeout: 30 * time.Second,
		},
	}

	retryCount := pm.config.HealthCheck.RetryCount
	healthy := false
	var lastErr error

	for i := 0; i < retryCount; i++ {
		resp, err := client.Get(healthURL.String())
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			healthy = true
			resp.Body.Close()
			break
		}

		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("health check failed with status %d", resp.StatusCode)
			resp.Body.Close()
		}

		// Wait a bit before retry
		if i < retryCount-1 {
			time.Sleep(time.Second)
		}
	}

	wasHealthy := backend.healthy.Load()
	backend.healthy.Store(healthy)

	// Log status changes
	if healthy != wasHealthy {
		proxyLogger.logBackendHealthChange(backend, healthy, lastErr)
	}
}
