package servex

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
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

// ProxyManager manages the reverse proxy functionality
type ProxyManager struct {
	config     ProxyConfiguration
	rules      []*ProxyRule
	client     *http.Client
	dumpWriter *TrafficDumpWriter
	logger     Logger
	mu         sync.RWMutex
}

// TrafficDumpWriter handles writing traffic dumps to files
type TrafficDumpWriter struct {
	config    TrafficDumpConfig
	mu        sync.Mutex
	file      *os.File
	size      int64
	fileIndex int
	basePath  string
}

// NewProxyManager creates a new proxy manager
func NewProxyManager(config ProxyConfiguration, logger Logger) (*ProxyManager, error) {
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
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
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

	pm := &ProxyManager{
		config: config,
		client: client,
		logger: logger,
	}

	// Initialize traffic dump writer if enabled
	if config.TrafficDump.Enabled && config.TrafficDump.Directory != "" {
		var err error
		pm.dumpWriter, err = NewTrafficDumpWriter(config.TrafficDump)
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
func (pm *ProxyManager) initializeRule(rule *ProxyRule) error {
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
func (pm *ProxyManager) initializeBackend(backend *Backend) error {
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
func (pm *ProxyManager) createErrorHandler(backend *Backend) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		pm.logger.Error("proxy error", "backend", backend.URL, "error", err, "path", r.URL.Path)
		backend.healthy.Store(false)

		// Decrement connection count
		backend.connections.Add(-1)

		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}
}

// RegisterProxyMiddleware registers the proxy middleware
func RegisterProxyMiddleware(router MiddlewareRouter, config ProxyConfiguration, logger Logger) (*ProxyManager, error) {
	if !config.Enabled {
		return nil, nil
	}

	pm, err := NewProxyManager(config, logger)
	if err != nil {
		return nil, err
	}

	// Register proxy middleware
	router.Use(pm.ProxyMiddleware)

	return pm, nil
}

// ProxyMiddleware is the main proxy middleware
func (pm *ProxyManager) ProxyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Find matching rule
		rule := pm.findMatchingRule(r)
		if rule == nil {
			// No rule matches, continue to next handler
			next.ServeHTTP(w, r)
			return
		}

		// Handle proxy request
		pm.handleProxyRequest(w, r, rule)
	})
}

// findMatchingRule finds the first rule that matches the request
func (pm *ProxyManager) findMatchingRule(r *http.Request) *ProxyRule {
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
func (pm *ProxyManager) ruleMatches(rule *ProxyRule, r *http.Request) bool {
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

// handleProxyRequest handles a proxy request
func (pm *ProxyManager) handleProxyRequest(w http.ResponseWriter, r *http.Request, rule *ProxyRule) {
	// Select backend using load balancing strategy
	backend := pm.selectBackend(rule, r)
	if backend == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	// Check connection limits
	if backend.MaxConnections > 0 && backend.connections.Load() >= int64(backend.MaxConnections) {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	// Increment connection count
	backend.connections.Add(1)
	defer backend.connections.Add(-1)

	// Dump traffic if enabled
	if (rule.EnableTrafficDump || pm.config.TrafficDump.Enabled) && pm.shouldSampleRequest() {
		pm.dumpTraffic(r, rule, backend)
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

	// Proxy the request
	backend.proxy.ServeHTTP(w, r)

	// Restore original path
	r.URL.Path = originalPath
}

// selectBackend selects a backend using the configured load balancing strategy
func (pm *ProxyManager) selectBackend(rule *ProxyRule, r *http.Request) *Backend {
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
func (pm *ProxyManager) selectRoundRobin(rule *ProxyRule, backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}
	index := rule.counter.Add(1) - 1
	return backends[index%uint64(len(backends))]
}

// selectWeightedRoundRobin implements weighted round-robin load balancing
func (pm *ProxyManager) selectWeightedRoundRobin(rule *ProxyRule, backends []*Backend) *Backend {
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
func (pm *ProxyManager) selectLeastConnections(backends []*Backend) *Backend {
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
func (pm *ProxyManager) selectRandom(backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}
	return backends[rand.Intn(len(backends))]
}

// selectWeightedRandom implements weighted random load balancing
func (pm *ProxyManager) selectWeightedRandom(backends []*Backend) *Backend {
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
func (pm *ProxyManager) selectIPHash(r *http.Request, backends []*Backend) *Backend {
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
func (pm *ProxyManager) getClientIP(r *http.Request) string {
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
func (pm *ProxyManager) shouldSampleRequest() bool {
	if pm.config.TrafficDump.SampleRate >= 1.0 {
		return true
	}
	if pm.config.TrafficDump.SampleRate <= 0.0 {
		return false
	}
	return rand.Float64() < pm.config.TrafficDump.SampleRate
}

// dumpTraffic dumps the traffic for analysis
func (pm *ProxyManager) dumpTraffic(r *http.Request, rule *ProxyRule, backend *Backend) {
	if pm.dumpWriter == nil {
		return
	}

	// Create traffic dump entry
	timestamp := time.Now()
	entry := TrafficDumpEntry{
		Timestamp:   timestamp,
		Rule:        rule.Name,
		Backend:     backend.URL,
		Method:      r.Method,
		URL:         r.URL.String(),
		Host:        r.Host,
		RemoteAddr:  r.RemoteAddr,
		UserAgent:   r.Header.Get("User-Agent"),
		Headers:     make(map[string][]string),
		RequestBody: "",
	}

	// Copy headers
	for name, values := range r.Header {
		entry.Headers[name] = values
	}

	// Read request body if enabled and not too large
	if pm.config.TrafficDump.IncludeBody && r.ContentLength > 0 && r.ContentLength <= pm.config.TrafficDump.MaxBodySize {
		if bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, pm.config.TrafficDump.MaxBodySize)); err == nil {
			entry.RequestBody = string(bodyBytes)
			// Restore body for actual proxying
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	// Write to dump file
	pm.dumpWriter.WriteEntry(entry)
}

// TrafficDumpEntry represents a traffic dump entry
type TrafficDumpEntry struct {
	Timestamp   time.Time           `json:"timestamp"`
	Rule        string              `json:"rule"`
	Backend     string              `json:"backend"`
	Method      string              `json:"method"`
	URL         string              `json:"url"`
	Host        string              `json:"host"`
	RemoteAddr  string              `json:"remote_addr"`
	UserAgent   string              `json:"user_agent"`
	Headers     map[string][]string `json:"headers"`
	RequestBody string              `json:"request_body,omitempty"`
}

// NewTrafficDumpWriter creates a new traffic dump writer
func NewTrafficDumpWriter(config TrafficDumpConfig) (*TrafficDumpWriter, error) {
	if config.Directory == "" {
		return nil, fmt.Errorf("dump directory is required")
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(config.Directory, 0755); err != nil {
		return nil, fmt.Errorf("create dump directory: %w", err)
	}

	basePath := filepath.Join(config.Directory, "traffic_dump")

	tdw := &TrafficDumpWriter{
		config:   config,
		basePath: basePath,
	}

	// Create initial file
	if err := tdw.rotateFile(); err != nil {
		return nil, fmt.Errorf("create initial dump file: %w", err)
	}

	return tdw, nil
}

// WriteEntry writes a traffic dump entry to the file
func (tdw *TrafficDumpWriter) WriteEntry(entry TrafficDumpEntry) error {
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

// rotateFile creates a new dump file and closes the old one
func (tdw *TrafficDumpWriter) rotateFile() error {
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

// Close closes the traffic dump writer
func (tdw *TrafficDumpWriter) Close() error {
	tdw.mu.Lock()
	defer tdw.mu.Unlock()

	if tdw.file != nil {
		return tdw.file.Close()
	}
	return nil
}

// (Replaced by enhanced version below)

// ProxyLogger is a specialized logger for proxy operations
type ProxyLogger struct {
	logger Logger
}

// NewProxyLogger creates a new proxy logger
func NewProxyLogger(logger Logger) *ProxyLogger {
	return &ProxyLogger{logger: logger}
}

// LogRequest logs proxy request details
func (pl *ProxyLogger) LogRequest(rule *ProxyRule, backend *Backend, r *http.Request, duration time.Duration, statusCode int, err error) {
	fields := []any{
		"component", "proxy",
		"rule", rule.Name,
		"backend", backend.URL,
		"method", r.Method,
		"path", r.URL.Path,
		"host", r.Host,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.Header.Get("User-Agent"),
		"duration_ms", duration.Milliseconds(),
		"status_code", statusCode,
		"backend_connections", backend.connections.Load(),
		"backend_healthy", backend.healthy.Load(),
		"load_balancing", string(rule.LoadBalancing),
	}

	if err != nil {
		fields = append(fields, "error", err.Error())
		pl.logger.Error("proxy request failed", fields...)
	} else if statusCode >= 400 {
		pl.logger.Error("proxy request error", fields...)
	} else {
		pl.logger.Info("proxy request", fields...)
	}
}

// LogBackendHealthChange logs backend health status changes
func (pl *ProxyLogger) LogBackendHealthChange(backend *Backend, healthy bool, err error) {
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

// LogRuleSelection logs load balancer rule selection
func (pl *ProxyLogger) LogRuleSelection(rule *ProxyRule, backend *Backend, strategy LoadBalancingStrategy) {
	pl.logger.Debug("backend selected",
		"component", "proxy",
		"rule", rule.Name,
		"backend", backend.URL,
		"strategy", string(strategy),
		"weight", backend.Weight,
		"connections", backend.connections.Load(),
	)
}

// RawHTTPDumpEntry represents a raw HTTP traffic dump entry
type RawHTTPDumpEntry struct {
	Timestamp       time.Time           `json:"timestamp"`
	Rule            string              `json:"rule"`
	Backend         string              `json:"backend"`
	ClientIP        string              `json:"client_ip"`
	RequestID       string              `json:"request_id"`
	RawRequest      string              `json:"raw_request"`
	RawResponse     string              `json:"raw_response,omitempty"`
	RequestHeaders  map[string][]string `json:"request_headers"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	StatusCode      int                 `json:"status_code,omitempty"`
	Duration        time.Duration       `json:"duration"`
	Error           string              `json:"error,omitempty"`
}

// Enhanced traffic dumping with RAW HTTP capture
func (pm *ProxyManager) dumpTrafficEnhanced(r *http.Request, rule *ProxyRule, backend *Backend) {
	if pm.dumpWriter == nil {
		return
	}

	// Generate unique request ID
	requestID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), generateRandomString(8))

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

	entry := RawHTTPDumpEntry{
		Timestamp:      time.Now(),
		Rule:           rule.Name,
		Backend:        backend.URL,
		ClientIP:       pm.getClientIP(r),
		RequestID:      requestID,
		RawRequest:     rawRequest.String(),
		RequestHeaders: make(map[string][]string),
	}

	// Copy headers
	for name, values := range r.Header {
		entry.RequestHeaders[name] = values
	}

	// Store request ID in context for response logging
	r.Header.Set("X-Proxy-Request-ID", requestID)

	// Write entry (response will be added later if response capture is implemented)
	pm.dumpWriter.WriteRawEntry(entry)
}

// generateRandomString generates a random string of given length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

// WriteRawEntry writes a raw HTTP dump entry to the file
func (tdw *TrafficDumpWriter) WriteRawEntry(entry RawHTTPDumpEntry) error {
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

// Enhanced handleProxyRequest with better logging and monitoring
func (pm *ProxyManager) handleProxyRequestEnhanced(w http.ResponseWriter, r *http.Request, rule *ProxyRule) {
	startTime := time.Now()

	// Create proxy logger if not exists
	proxyLogger := NewProxyLogger(pm.logger)

	// Select backend using load balancing strategy
	backend := pm.selectBackend(rule, r)
	if backend == nil {
		proxyLogger.LogRequest(rule, &Backend{URL: "no-backend"}, r, time.Since(startTime), 503, fmt.Errorf("no healthy backends available"))
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	// Log backend selection
	proxyLogger.LogRuleSelection(rule, backend, rule.LoadBalancing)

	// Check connection limits
	if backend.MaxConnections > 0 && backend.connections.Load() >= int64(backend.MaxConnections) {
		proxyLogger.LogRequest(rule, backend, r, time.Since(startTime), 503, fmt.Errorf("connection limit exceeded"))
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
	recorder := &responseRecorder{ResponseWriter: w, statusCode: 200}

	// Proxy the request
	backend.proxy.ServeHTTP(recorder, r)

	// Calculate duration and log request
	duration := time.Since(startTime)
	proxyLogger.LogRequest(rule, backend, r, duration, recorder.statusCode, nil)

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

// Enhanced health check with better lifecycle management
func (pm *ProxyManager) startHealthChecks() {
	for _, rule := range pm.rules {
		for _, backend := range rule.backends {
			if backend.HealthCheckPath != "" {
				go pm.healthCheckLoopEnhanced(backend)
			}
		}
	}
}

// healthCheckLoopEnhanced with better lifecycle and logging
func (pm *ProxyManager) healthCheckLoopEnhanced(backend *Backend) {
	proxyLogger := NewProxyLogger(pm.logger)
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
func (pm *ProxyManager) performHealthCheckEnhanced(backend *Backend, proxyLogger *ProxyLogger) {
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
		proxyLogger.LogBackendHealthChange(backend, healthy, lastErr)
	}
}
