package servex

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	stdjson "encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"math/rand"
	"regexp"
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
	url            *url.URL
	healthy        atomic.Bool
	connections    atomic.Int64
	proxy          *httputil.ReverseProxy
	failureTracker *backendFailureTracker
	cb             *circuitBreaker
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

	// PassiveHealth configures passive health checking based on live traffic responses.
	// When enabled, backends are marked unhealthy immediately when failure threshold is exceeded.
	PassiveHealth PassiveHealthConfig `yaml:"passive_health" json:"passive_health"`

	// ShouldBufferResponse decides whether to buffer the entire backend response before
	// forwarding to the client. This allows inspecting the response status and headers,
	// and replacing error responses with custom error pages.
	// If nil, responses stream directly (default behavior).
	// The function receives the backend's status code and response headers.
	ShouldBufferResponse func(statusCode int, header http.Header) bool `yaml:"-" json:"-"`

	// DynamicUpstream configures DNS-based dynamic backend discovery.
	// When set, backends are resolved from DNS records instead of static configuration.
	DynamicUpstream DynamicUpstreamConfig `yaml:"dynamic_upstream" json:"dynamic_upstream"`

	// Internal fields
	counter      atomic.Uint64 // for round robin
	backends     []*Backend
	healthyCount atomic.Int32
	pathRegex    *regexp.Regexp
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
	// CircuitBreaker configures per-backend circuit breaking.
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`
	// InsecureSkipVerify skips certificate verification
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
	// TrustedProxies is a list of trusted proxy IP addresses or CIDR ranges.
	// When set, proxy headers (X-Forwarded-For, X-Real-IP) are only trusted
	// if the request comes from one of these addresses. When empty, only
	// r.RemoteAddr is used for client IP detection.
	TrustedProxies []string `yaml:"trusted_proxies" json:"trusted_proxies"`
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

// CircuitBreakerConfig configures per-backend circuit breaking.
// When enabled, backends are temporarily removed from the pool after consecutive failures.
type CircuitBreakerConfig struct {
	// Enabled activates circuit breaking for all proxy backends.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Threshold is the number of consecutive failures before opening the circuit.
	// Default: 5.
	Threshold int `yaml:"threshold" json:"threshold"`
	// Timeout is how long to keep the circuit open before allowing a probe request (half-open).
	// Default: 30 seconds.
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
}

// Circuit breaker states.
const (
	cbClosed   int32 = 0
	cbOpen     int32 = 1
	cbHalfOpen int32 = 2
)

// circuitBreaker implements a consecutive-failure circuit breaker per backend.
type circuitBreaker struct {
	state         atomic.Int32
	failures      atomic.Int32
	lastFailure   atomic.Int64 // Unix nanoseconds
	probeInFlight atomic.Bool  // ensures only one probe in half-open state
	threshold     int
	timeout       time.Duration
}

// isOpen returns true if the circuit is open and no request should be sent.
// On timeout expiry it transitions from open to half-open (allows exactly one probe).
func (cb *circuitBreaker) isOpen() bool {
	state := cb.state.Load()
	if state == cbClosed {
		return false
	}
	if state == cbOpen {
		elapsed := time.Since(time.Unix(0, cb.lastFailure.Load()))
		if elapsed >= cb.timeout {
			if cb.state.CompareAndSwap(cbOpen, cbHalfOpen) {
				// Won the CAS — this goroutine may probe
				cb.probeInFlight.Store(true)
				return false
			}
			// Another goroutine won the CAS; fall through to half-open check
			state = cb.state.Load()
			if state != cbHalfOpen {
				return state == cbOpen
			}
		} else {
			return true
		}
	}
	// cbHalfOpen — allow only one concurrent probe request
	if cb.probeInFlight.CompareAndSwap(true, false) {
		return false // this goroutine is the probe
	}
	return true // another probe is already in flight, reject
}

// recordSuccess resets the failure count and closes the circuit.
func (cb *circuitBreaker) recordSuccess() {
	cb.failures.Store(0)
	cb.probeInFlight.Store(false)
	cb.state.Store(cbClosed)
}

// recordFailure increments the failure counter and opens the circuit on threshold breach.
// In half-open state, a single failure immediately re-opens the circuit.
func (cb *circuitBreaker) recordFailure() {
	cb.lastFailure.Store(time.Now().UnixNano())
	state := cb.state.Load()
	if state == cbHalfOpen {
		cb.state.Store(cbOpen)
		return
	}
	if state == cbClosed {
		n := cb.failures.Add(1)
		if n >= int32(cb.threshold) {
			cb.state.CompareAndSwap(cbClosed, cbOpen)
		}
	}
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

// PassiveHealthConfig configures passive health checking.
// Passive checks monitor actual proxy responses and mark backends unhealthy
// when too many failures occur within a time window.
type PassiveHealthConfig struct {
	// FailThreshold is the number of failures within FailWindow before marking unhealthy. Default: 3.
	FailThreshold int `yaml:"fail_threshold" json:"fail_threshold"`
	// FailWindow is the time window for counting failures. Default: 30s.
	FailWindow time.Duration `yaml:"fail_window" json:"fail_window"`
	// RecoveryInterval is how long to wait before re-enabling an unhealthy backend. Default: 30s.
	RecoveryInterval time.Duration `yaml:"recovery_interval" json:"recovery_interval"`
	// UnhealthyStatusCodes are status codes that count as failures. Default: [502, 503, 504].
	UnhealthyStatusCodes []int `yaml:"unhealthy_status_codes" json:"unhealthy_status_codes"`
}

// isActive returns true if passive health checking should be enabled.
func (c PassiveHealthConfig) isActive() bool {
	return c.FailThreshold > 0
}

// backendFailureTracker tracks recent failures for passive health checking.
type backendFailureTracker struct {
	mu        sync.Mutex
	failures  []time.Time
	threshold int
	window    time.Duration
}

func newBackendFailureTracker(threshold int, window time.Duration) *backendFailureTracker {
	return &backendFailureTracker{
		failures:  make([]time.Time, 0, threshold),
		threshold: threshold,
		window:    window,
	}
}

// recordFailure records a failure and returns true if the threshold is exceeded.
func (t *backendFailureTracker) recordFailure() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-t.window)

	// Remove expired failures
	valid := t.failures[:0]
	for _, ts := range t.failures {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	valid = append(valid, now)
	t.failures = valid

	return len(t.failures) >= t.threshold
}

// reset clears the failure history.
func (t *backendFailureTracker) reset() {
	t.mu.Lock()
	t.failures = t.failures[:0]
	t.mu.Unlock()
}

// proxyManager manages the reverse proxy functionality
type proxyManager struct {
	config           ProxyConfiguration
	rules            []*ProxyRule
	client           *http.Client
	healthClient     *http.Client
	dumpWriter       *trafficDumpWriter
	logger           Logger
	mu               sync.RWMutex
	trustedProxyNets []*net.IPNet

	// Lifecycle management
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
	recoveryWg     sync.WaitGroup
	resolvers      []*upstreamResolver
}

// trafficDumpWriter handles writing traffic dumps to files
type trafficDumpWriter struct {
	config       TrafficDumpConfig
	mu           sync.Mutex
	file         *os.File
	size         int64
	fileIndex    int
	basePath     string
	writesCount  int   // Track writes since last sync
	syncInterval int   // Sync every N writes
	lastSync     int64 // Unix timestamp of last sync
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
func RegisterProxyMiddleware(router MiddlewareRouter, config ProxyConfiguration, logger ...Logger) (func(), error) {
	if !config.Enabled {
		return func() {}, nil
	}

	pm, err := newProxyManager(config, lang.First(logger))
	if err != nil {
		return nil, err
	}

	// Register proxy middleware
	router.Use(pm.proxyMiddleware)

	return pm.shutdown, nil
}

// shutdown cancels the shutdown context to stop health check goroutines.
func (pm *proxyManager) shutdown() {
	pm.shutdownCancel()
	pm.recoveryWg.Wait()
	if pm.dumpWriter != nil {
		pm.dumpWriter.Close()
	}
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

	// Create shutdown context for lifecycle management
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())

	// Create a shared HTTP client for health checks (avoids creating new transports per check)
	healthClient := &http.Client{
		Timeout: config.HealthCheck.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: config.InsecureSkipVerify},
			MaxIdleConns:    10,
			IdleConnTimeout: 30 * time.Second,
		},
	}

	// Parse trusted proxy networks once
	var trustedProxyNets []*net.IPNet
	for _, proxy := range config.TrustedProxies {
		if !strings.Contains(proxy, "/") {
			if ip := net.ParseIP(proxy); ip != nil {
				if ip.To4() != nil {
					proxy += "/32"
				} else {
					proxy += "/128"
				}
			}
		}
		if _, network, err := net.ParseCIDR(proxy); err == nil {
			trustedProxyNets = append(trustedProxyNets, network)
		}
	}

	pm := &proxyManager{
		config:           config,
		client:           client,
		healthClient:     healthClient,
		logger:           logger,
		shutdownCtx:      shutdownCtx,
		shutdownCancel:   shutdownCancel,
		trustedProxyNets: trustedProxyNets,
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


	// Start dynamic upstream resolvers
	for _, rule := range pm.rules {
		if rule.DynamicUpstream.isActive() {
			resolver := newUpstreamResolver(rule.DynamicUpstream, rule, pm, pm.logger)
			if err := resolver.start(pm.shutdownCtx); err != nil {
				pm.logger.Error("failed to start dynamic upstream resolver", "rule", rule.Name, "error", err)
			}
			pm.resolvers = append(pm.resolvers, resolver)
		}
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
	if rule.PathRegex != "" {
		var err error
		rule.pathRegex, err = regexp.Compile(rule.PathRegex)
		if err != nil {
			return fmt.Errorf("compile path regex %s: %w", rule.PathRegex, err)
		}
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

	// Initialize passive health check failure trackers if configured
	if rule.PassiveHealth.isActive() {
		cfg := rule.PassiveHealth
		if cfg.FailThreshold == 0 {
			cfg.FailThreshold = 3
		}
		if cfg.FailWindow == 0 {
			cfg.FailWindow = 30 * time.Second
		}
		if cfg.RecoveryInterval == 0 {
			cfg.RecoveryInterval = 30 * time.Second
		}
		if len(cfg.UnhealthyStatusCodes) == 0 {
			cfg.UnhealthyStatusCodes = []int{502, 503, 504}
		}
		for _, backend := range rule.backends {
			backend.failureTracker = newBackendFailureTracker(cfg.FailThreshold, cfg.FailWindow)
		}
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

	// Initialize circuit breaker if configured
	if pm.config.CircuitBreaker.Enabled {
		threshold := pm.config.CircuitBreaker.Threshold
		if threshold <= 0 {
			threshold = 5
		}
		timeout := pm.config.CircuitBreaker.Timeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		backend.cb = &circuitBreaker{
			threshold: threshold,
			timeout:   timeout,
		}
	}

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
		if backend.cb != nil {
			backend.cb.recordFailure()
		}

		// Mark recorder so post-proxy circuit breaker check doesn't double-count.
		if rr, ok := w.(*responseRecorder); ok {
			rr.errorHandlerCalled = true
		}

		// Note: connection count is decremented by the defer in handleProxyRequestEnhanced.
		// Do NOT decrement here — that causes a double-decrement.

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

	// Check path regex
	if rule.pathRegex != nil && !rule.pathRegex.MatchString(r.URL.Path) {
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

	// Clone the URL to avoid mutating the shared request object
	clonedURL := *r.URL
	if rule.StripPrefix != "" {
		clonedURL.Path = strings.TrimPrefix(clonedURL.Path, rule.StripPrefix)
	}
	if rule.AddPrefix != "" {
		clonedURL.Path = rule.AddPrefix + clonedURL.Path
	}

	// Set timeout for this request
	ctx, cancel := context.WithTimeout(r.Context(), rule.Timeout)
	defer cancel()
	r = r.Clone(ctx)
	r.URL = &clonedURL

	// Create response recorder to capture status code
	recorder := &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		shouldBufferFn: rule.ShouldBufferResponse,
	}

	// Proxy the request
	backend.proxy.ServeHTTP(recorder, r)

	// If buffering was active, flush the response to the underlying writer
	if recorder.buffering {
		recorder.flushBuffered()
	}

	// Circuit breaker: record success/failure based on response status.
	// The ErrorHandler already calls recordFailure for transport errors,
	// so we only record here for actual upstream responses (success or 5xx from upstream).
	if backend.cb != nil && !recorder.errorHandlerCalled {
		if recorder.statusCode < 500 {
			backend.cb.recordSuccess()
		} else {
			backend.cb.recordFailure()
		}
	}

	// Passive health check: monitor response status
	if rule.PassiveHealth.isActive() && backend.failureTracker != nil {
		if isUnhealthyStatus(recorder.statusCode, rule.PassiveHealth.UnhealthyStatusCodes) {
			if backend.failureTracker.recordFailure() && backend.healthy.CompareAndSwap(true, false) {
				pm.logger.Info("passive health check: marking backend unhealthy",
					"rule", rule.Name, "backend", backend.URL,
					"status", recorder.statusCode)
				// Start recovery goroutine
				pm.recoveryWg.Add(1)
				go pm.recoverBackend(backend, rule.PassiveHealth.RecoveryInterval)
			}
		}
	}

	// Calculate duration and log request
	duration := time.Since(startTime)
	proxyLogger.logRequest(rule, backend, r, duration, recorder.statusCode, nil)
}

// responseRecorder captures the response status code and optionally buffers the body.
type responseRecorder struct {
	http.ResponseWriter
	statusCode         int
	shouldBufferFn     func(int, http.Header) bool
	buffering          bool // true while actively buffering
	body               bytes.Buffer
	headerWritten      bool
	errorHandlerCalled bool // set by ErrorHandler to avoid double circuit-breaker recording
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	if rr.shouldBufferFn != nil && !rr.headerWritten {
		rr.headerWritten = true
		// Ask callback whether to buffer this response
		if rr.shouldBufferFn(code, rr.Header()) {
			rr.buffering = true
			return // defer forwarding until flush
		}
		// Callback says don't buffer — forward headers immediately
		rr.ResponseWriter.WriteHeader(code)
		return
	}
	if !rr.buffering {
		rr.ResponseWriter.WriteHeader(code)
	}
}

func (rr *responseRecorder) Write(data []byte) (int, error) {
	if rr.buffering {
		return rr.body.Write(data)
	}
	return rr.ResponseWriter.Write(data)
}

// flushBuffered writes the buffered status code, headers, and body to the underlying writer.
func (rr *responseRecorder) flushBuffered() {
	if !rr.headerWritten {
		return
	}
	rr.ResponseWriter.WriteHeader(rr.statusCode)
	if rr.body.Len() > 0 {
		_, _ = rr.ResponseWriter.Write(rr.body.Bytes())
	}
}

// Hijack implements http.Hijacker so WebSocket upgrades work through proxy.
func (rr *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rr.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("upstream ResponseWriter does not implement http.Hijacker")
}

// isUnhealthyStatus checks if the status code is in the list of unhealthy status codes.
func isUnhealthyStatus(code int, unhealthyCodes []int) bool {
	for _, c := range unhealthyCodes {
		if code == c {
			return true
		}
	}
	return false
}

// recoverBackend waits for the recovery interval, then re-enables the backend and resets its failure tracker.
func (pm *proxyManager) recoverBackend(backend *Backend, interval time.Duration) {
	defer pm.recoveryWg.Done()
	select {
	case <-time.After(interval):
		backend.healthy.Store(true)
		if backend.failureTracker != nil {
			backend.failureTracker.reset()
		}
		pm.logger.Info("passive health check: backend recovered", "backend", backend.URL)
	case <-pm.shutdownCtx.Done():
		return
	}
}

// selectBackend selects a backend using the configured load balancing strategy.
// Uses RLock to safely read rule.backends which may be updated by dynamic DNS resolution.
func (pm *proxyManager) selectBackend(rule *ProxyRule, r *http.Request) *Backend {
	pm.mu.RLock()
	backends := rule.backends
	pm.mu.RUnlock()

	healthyBackends := make([]*Backend, 0, len(backends))
	for _, backend := range backends {
		if !backend.healthy.Load() {
			continue
		}
		if backend.cb != nil && backend.cb.isOpen() {
			continue
		}
		healthyBackends = append(healthyBackends, backend)
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
// Uses FNV-1a hash algorithm for better distribution and collision resistance
func (pm *proxyManager) selectIPHash(r *http.Request, backends []*Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	// Get client IP
	clientIP := pm.getClientIP(r)

	// Use FNV-1a hash for better distribution
	h := fnv.New32a()
	h.Write([]byte(clientIP))
	hash := h.Sum32()

	return backends[hash%uint32(len(backends))]
}

// getClientIP extracts the real client IP from the request.
// Proxy headers (X-Real-IP, X-Forwarded-For) are only trusted when the
// request originates from a configured trusted proxy. Otherwise, only
// r.RemoteAddr is used.
func (pm *proxyManager) getClientIP(r *http.Request) string {
	remoteAddr := getRemoteAddr(r)

	// Only trust proxy headers if the request is from a trusted proxy
	if len(pm.trustedProxyNets) > 0 && isFromTrustedProxy(remoteAddr, pm.trustedProxyNets) {
		if ip := extractIPFromHeaders(r); ip != "" && isValidIP(ip) {
			return ip
		}
	}

	return remoteAddr
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
		config:       config,
		basePath:     basePath,
		syncInterval: 100, // Sync every 100 writes instead of every write
		lastSync:     time.Now().Unix(),
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
		if err := tdw.file.Close(); err != nil {
			return fmt.Errorf("close old file: %w", err)
		}
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
		_ = os.Remove(oldFile) // Ignore errors - file might not exist
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
	if err := pm.dumpWriter.writeRawEntry(entry); err != nil {
		pm.logger.Error("failed to write traffic dump entry",
			"component", "proxy",
			"error", err.Error())
	}
}

// writeRawEntry writes a raw HTTP dump entry to the file
// Syncs are performed periodically rather than on every write for better performance
func (tdw *trafficDumpWriter) writeRawEntry(entry rawHTTPDumpEntry) error {
	tdw.mu.Lock()
	defer tdw.mu.Unlock()

	// Check if we need to rotate the file
	if tdw.size >= tdw.config.MaxFileSize {
		// Sync before rotation to ensure data integrity
		if tdw.file != nil {
			_ = tdw.file.Sync()
		}
		if err := tdw.rotateFile(); err != nil {
			return fmt.Errorf("rotate dump file: %w", err)
		}
	}

	// Write entry as JSON line
	entryJSON, err := stdjson.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}

	// Write JSON bytes and newline separately to avoid string allocation
	n, err := tdw.file.Write(entryJSON)
	if err != nil {
		return fmt.Errorf("write entry: %w", err)
	}

	n2, err := tdw.file.WriteString("\n")
	if err != nil {
		return fmt.Errorf("write newline: %w", err)
	}

	tdw.size += int64(n + n2)
	tdw.writesCount++

	// Sync periodically instead of on every write
	shouldSync := tdw.writesCount >= tdw.syncInterval ||
		time.Now().Unix()-tdw.lastSync > 30 // Also sync if 30 seconds have passed

	if shouldSync {
		if err := tdw.file.Sync(); err != nil {
			return fmt.Errorf("sync file: %w", err)
		}
		tdw.writesCount = 0
		tdw.lastSync = time.Now().Unix()
	}

	return nil
}

// Close closes the traffic dump writer and ensures all data is synced to disk.
// This method should be called when shutting down the proxy manager.
func (tdw *trafficDumpWriter) Close() error {
	tdw.mu.Lock()
	defer tdw.mu.Unlock()

	if tdw.file != nil {
		// Ensure final sync before closing
		if err := tdw.file.Sync(); err != nil {
			// Log error but continue with close
			_ = tdw.file.Close()
			return fmt.Errorf("final sync failed: %w", err)
		}
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

	// Log start of health checking
	pm.logger.Info("starting health checks",
		"component", "proxy",
		"backend", backend.URL,
		"interval", backend.HealthCheckInterval,
		"path", backend.HealthCheckPath,
	)

	for {
		select {
		case <-pm.shutdownCtx.Done():
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

	retryCount := pm.config.HealthCheck.RetryCount
	healthy := false
	var lastErr error

	for i := 0; i < retryCount; i++ {
		resp, err := pm.healthClient.Get(healthURL.String())
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			healthy = true
			_ = resp.Body.Close()
			break
		}

		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("health check failed with status %d", resp.StatusCode)
			_ = resp.Body.Close()
		}

		// Wait before retry, but respect shutdown context
		if i < retryCount-1 {
			select {
			case <-time.After(time.Second):
			case <-pm.shutdownCtx.Done():
				return
			}
		}
	}

	wasHealthy := backend.healthy.Load()
	backend.healthy.Store(healthy)

	// Log status changes
	if healthy != wasHealthy {
		proxyLogger.logBackendHealthChange(backend, healthy, lastErr)
	}
}
