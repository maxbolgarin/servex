package servex

import (
	"bytes"
	stdjson "encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maxbolgarin/lang"
	"golang.org/x/time/rate"
)

const (
	// Cleanup intervals - more aggressive cleanup to prevent memory buildup
	cleanupInterval         = 30 * time.Minute // Reduced from 1 hour to 30 minutes
	defaultInterval         = time.Minute
	maxVisitors             = 10000            // Maximum number of concurrent visitors
	cleanupTickInterval     = 5 * time.Minute  // Run cleanup every 5 minutes instead of 10
	emergencyCleanupTicks   = 30 * time.Second // Emergency cleanup when near memory limits
	memoryPressureThreshold = 8000             // Trigger more aggressive cleanup at 80% capacity
)

// LocationRateLimitConfig defines a rate limit configuration for specific locations.
// This allows different rate limits to be applied to different URL paths.
type LocationRateLimitConfig struct {
	// PathPatterns are the URL path patterns this config applies to.
	// Supports wildcards using filepath.Match syntax (e.g., "/api/*", "/admin/*").
	// If multiple patterns are provided, any match will apply this config.
	//
	// Examples:
	//   - ["/api/*"] - All API endpoints
	//   - ["/admin/*", "/dashboard/*"] - Admin and dashboard areas
	//   - ["/auth/login", "/auth/register"] - Specific auth endpoints
	//   - ["/upload/*"] - File upload endpoints
	PathPatterns []string

	// Config is the rate limit configuration to apply for matching paths.
	// This contains all the rate limiting settings like requests per interval,
	// burst size, status codes, etc.
	Config RateLimitConfig
}

// visitor represents a client accessing the server.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen int64 // Use atomic int64 for Unix timestamp to avoid race conditions
}

// Pool for reusing visitor objects to reduce allocations
var visitorPool = sync.Pool{
	New: func() any {
		return &visitor{}
	},
}

// getVisitor retrieves a visitor from the pool
func getVisitor() *visitor {
	return visitorPool.Get().(*visitor)
}

// putVisitor returns a visitor to the pool after resetting it
func putVisitor(v *visitor) {
	// Reset the visitor to prevent memory leaks
	v.limiter = nil
	v.lastSeen = 0
	visitorPool.Put(v)
}

// getLastSeen returns the last seen time safely
func (v *visitor) getLastSeen() time.Time {
	timestamp := atomic.LoadInt64(&v.lastSeen)
	return time.Unix(timestamp, 0)
}

// updateLastSeen updates the last seen time safely
func (v *visitor) updateLastSeen() {
	atomic.StoreInt64(&v.lastSeen, time.Now().Unix())
}

// rateLimiterMiddleware provides rate limiting middleware functionality.
type rateLimiterMiddleware struct {
	cfg             RateLimitConfig
	locationConfigs []LocationRateLimitConfig
	visitors        map[string]*visitor
	mu              sync.RWMutex
	cleanupDone     chan struct{}
	cleanupOnce     sync.Once
	visitorCount    int64 // Atomic counter for visitor count

	// Emergency cleanup control
	emergencyCleanup chan struct{}
	emergencyOnce    sync.Once

	// Goroutine lifecycle management
	shutdownOnce sync.Once
	goroutineWG  sync.WaitGroup
	isShutdown   int32 // atomic flag

	// Audit logging for security events
	auditLogger AuditLogger
}

// RegisterRateLimitMiddleware adds rate limiting middleware to the router.
// If the config is not enabled, no middleware will be registered.
// It returns a function that can be used to stop the cleanup routine.
//
// Parameters:
//   - router: The router to register the middleware for
//   - cfg: The rate limit configuration to register the middleware for
//   - auditLogger: The audit logger to register the middleware for
//
// Returns:
//   - func(): The function to stop the cleanup routine
func RegisterRateLimitMiddleware(router MiddlewareRouter, cfg RateLimitConfig, auditLogger ...AuditLogger) func() {
	if !cfg.Enabled || cfg.RequestsPerInterval <= 0 {
		return func() {} // Return no-op function for consistency
	}
	cfg.BurstSize = lang.Check(cfg.BurstSize, cfg.RequestsPerInterval)
	cfg.Interval = lang.Check(cfg.Interval, defaultInterval)
	cfg.StatusCode = lang.Check(cfg.StatusCode, http.StatusTooManyRequests)
	cfg.Message = lang.Check(cfg.Message, "Rate limit exceeded, try again later.")

	if cfg.KeyFunc == nil {
		cfg.KeyFunc = getUsernameKeyFuncWithProxies(cfg.TrustedProxies)
	}

	// Get audit logger (optional parameter)
	var audit AuditLogger = &NoopAuditLogger{}
	if len(auditLogger) > 0 && auditLogger[0] != nil {
		audit = auditLogger[0]
	}

	m := &rateLimiterMiddleware{
		cfg:              cfg,
		visitors:         make(map[string]*visitor),
		cleanupDone:      make(chan struct{}),
		emergencyCleanup: make(chan struct{}, 1), // Buffered to avoid blocking
		auditLogger:      audit,
	}

	router.Use(m.middleware)

	// Start cleanup goroutines with proper lifecycle management
	m.cleanupOnce.Do(func() {
		m.startBackgroundTasks()
	})

	return func() {
		m.shutdown()
	}
}

// RegisterLocationBasedRateLimitMiddleware adds location-based rate limiting middleware to the router.
// This allows different rate limit configurations for different URL paths.
// If no location configs are provided or none are enabled, no middleware will be registered.
// It returns a function that can be used to stop the cleanup routine.
//
// The middleware will:
// 1. Check each location config in order for path pattern matches
// 2. Use the first matching config's rate limits
// 3. Fall back to no rate limiting if no patterns match
//
// Example usage:
//
//	stop := RegisterLocationBasedRateLimitMiddleware(router, []LocationRateLimitConfig{
//	  {
//	    PathPatterns: []string{"/api/*"},
//	    Config: RateLimitConfig{
//	      Enabled: true,
//	      RequestsPerInterval: 100,
//	      Interval: time.Minute,
//	    },
//	  },
//	  {
//	    PathPatterns: []string{"/auth/login", "/auth/register"},
//	    Config: RateLimitConfig{
//	      Enabled: true,
//	      RequestsPerInterval: 10,
//	      Interval: time.Minute,
//	    },
//	  },
//	})
func RegisterLocationBasedRateLimitMiddleware(router MiddlewareRouter, locationConfigs []LocationRateLimitConfig, auditLogger ...AuditLogger) func() {
	if len(locationConfigs) == 0 {
		return func() {} // Return no-op function for consistency
	}

	// Validate and prepare configs
	var validConfigs []LocationRateLimitConfig
	for _, locCfg := range locationConfigs {
		if !locCfg.Config.Enabled || locCfg.Config.RequestsPerInterval <= 0 || len(locCfg.PathPatterns) == 0 {
			continue
		}

		// Set defaults for this config
		locCfg.Config.BurstSize = lang.Check(locCfg.Config.BurstSize, locCfg.Config.RequestsPerInterval)
		locCfg.Config.Interval = lang.Check(locCfg.Config.Interval, defaultInterval)
		locCfg.Config.StatusCode = lang.Check(locCfg.Config.StatusCode, http.StatusTooManyRequests)
		locCfg.Config.Message = lang.Check(locCfg.Config.Message, "rate limit exceeded, try again later.")

		if locCfg.Config.KeyFunc == nil {
			locCfg.Config.KeyFunc = getUsernameKeyFuncWithProxies(locCfg.Config.TrustedProxies)
		}

		validConfigs = append(validConfigs, locCfg)
	}

	if len(validConfigs) == 0 {
		return func() {} // Return no-op function for consistency
	}

	// Get audit logger (optional parameter)
	var audit AuditLogger = &NoopAuditLogger{}
	if len(auditLogger) > 0 && auditLogger[0] != nil {
		audit = auditLogger[0]
	}

	m := &rateLimiterMiddleware{
		locationConfigs:  validConfigs,
		visitors:         make(map[string]*visitor),
		cleanupDone:      make(chan struct{}),
		emergencyCleanup: make(chan struct{}, 1), // Buffered to avoid blocking
		auditLogger:      audit,
	}

	router.Use(m.middleware)

	// Start cleanup goroutines with proper lifecycle management
	m.cleanupOnce.Do(func() {
		m.startBackgroundTasks()
	})

	return func() {
		m.shutdown()
	}
}

// startCleanupRoutine runs a background cleanup task to remove stale visitors.
func (m *rateLimiterMiddleware) startCleanupRoutine() {
	ticker := time.NewTicker(cleanupTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanup(false) // Regular cleanup
		case <-m.cleanupDone:
			return
		}
	}
}

// startEmergencyCleanupRoutine handles emergency cleanup when memory pressure is high.
func (m *rateLimiterMiddleware) startEmergencyCleanupRoutine() {
	ticker := time.NewTicker(emergencyCleanupTicks)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if we need emergency cleanup
			if atomic.LoadInt64(&m.visitorCount) > memoryPressureThreshold {
				m.cleanup(true) // Aggressive cleanup
			}
		case <-m.emergencyCleanup:
			m.cleanup(true) // Immediate aggressive cleanup
		case <-m.cleanupDone:
			return
		}
	}
}

// cleanup removes stale visitors from the map and implements LRU eviction if needed.
// aggressive parameter controls whether to use more aggressive cleanup thresholds
func (m *rateLimiterMiddleware) cleanup(aggressive bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	keysToDelete := make([]string, 0, len(m.visitors)/4) // Pre-allocate for efficiency

	// Determine cleanup threshold based on mode
	cleanupThreshold := cleanupInterval
	if aggressive {
		cleanupThreshold = cleanupInterval / 2 // More aggressive: cleanup visitors idle for 15 minutes
	}

	// First pass: collect stale visitors
	for key, v := range m.visitors {
		if now.Sub(v.getLastSeen()) > cleanupThreshold {
			keysToDelete = append(keysToDelete, key)
		}
	}

	// Delete stale visitors and return them to pool
	for _, key := range keysToDelete {
		if v, exists := m.visitors[key]; exists {
			putVisitor(v) // Return visitor to pool
			delete(m.visitors, key)
			atomic.AddInt64(&m.visitorCount, -1)
		}
	}

	// Second pass: if still over limit, implement LRU eviction
	evictionTarget := maxVisitors
	if aggressive {
		evictionTarget = memoryPressureThreshold // More aggressive target
	}

	if len(m.visitors) > evictionTarget {
		m.evictLRU(len(m.visitors) - evictionTarget)
	}

	// Sync the atomic counter with actual map size to prevent drift
	atomic.StoreInt64(&m.visitorCount, int64(len(m.visitors)))
}

// startBackgroundTasks starts the cleanup goroutines with proper lifecycle tracking
func (m *rateLimiterMiddleware) startBackgroundTasks() {
	if atomic.LoadInt32(&m.isShutdown) == 1 {
		return // Already shutdown
	}

	m.goroutineWG.Add(2)
	go func() {
		defer m.goroutineWG.Done()
		m.startCleanupRoutine()
	}()
	go func() {
		defer m.goroutineWG.Done()
		m.startEmergencyCleanupRoutine()
	}()
}

// shutdown gracefully stops all background goroutines
func (m *rateLimiterMiddleware) shutdown() {
	m.shutdownOnce.Do(func() {
		atomic.StoreInt32(&m.isShutdown, 1)
		close(m.cleanupDone)
		m.goroutineWG.Wait()
	})
}

// evictLRU removes the least recently used visitors to stay under memory limits.
// Must be called with write lock held.
func (m *rateLimiterMiddleware) evictLRU(numToEvict int) {
	if numToEvict <= 0 || len(m.visitors) == 0 {
		return
	}

	type keyTime struct {
		key      string
		lastSeen time.Time
	}

	// Collect all visitors with their last seen times
	visitors := make([]keyTime, 0, len(m.visitors))
	for key, v := range m.visitors {
		visitors = append(visitors, keyTime{
			key:      key,
			lastSeen: v.getLastSeen(),
		})
	}

	// Sort by last seen time (oldest first) - Use Go's efficient sort
	sort.Slice(visitors, func(i, j int) bool {
		return visitors[i].lastSeen.Before(visitors[j].lastSeen)
	})

	// Remove the oldest entries and return them to pool
	evicted := 0
	for i := 0; i < len(visitors) && evicted < numToEvict; i++ {
		key := visitors[i].key
		if v, exists := m.visitors[key]; exists {
			putVisitor(v) // Return visitor to pool
			delete(m.visitors, key)
			evicted++
		}
	}

	// Update counter
	atomic.AddInt64(&m.visitorCount, int64(-evicted))
}

// middleware is the actual rate limiting middleware function.
func (m *rateLimiterMiddleware) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the appropriate config for this request
		cfg := m.getConfigForPath(r.URL.Path)
		if cfg == nil {
			// No rate limiting config applies to this path
			next.ServeHTTP(w, r)
			return
		}

		// Check if the path should be rate limited according to the config
		if !m.shouldRateLimit(r, *cfg) {
			next.ServeHTTP(w, r)
			return
		}

		// Get the rate limiting key from the request
		key := cfg.KeyFunc(r)
		if key == "" {
			// If we can't determine a key, allow the request
			next.ServeHTTP(w, r)
			return
		}

		// Get or create rate limiter for this visitor using the specific config
		limiter := m.getLimiter(key, *cfg)
		if limiter == nil {
			// Failed to create limiter due to memory constraints
			w.Header().Set("Retry-After", "60")
			C(w, r).Error(fmt.Errorf("rate limit exceeded"), http.StatusServiceUnavailable, "service temporarily unavailable")
			return
		}

		// Check if this request exceeds the rate limit
		if !limiter.Allow() {
			// Rate limit exceeded - log security event
			if m.auditLogger != nil {
				details := map[string]any{
					"rate_limit_key":        key,
					"requests_per_interval": cfg.RequestsPerInterval,
					"interval_seconds":      cfg.Interval.Seconds(),
					"burst_size":            cfg.BurstSize,
				}
				m.auditLogger.LogRateLimitEvent(r, key, details)
			}

			w.Header().Set("Retry-After", "60") // Suggest retry after 1 minute
			C(w, r).Error(fmt.Errorf("rate limit exceeded"), cfg.StatusCode, cfg.Message)
			return
		}

		// Allow the request
		next.ServeHTTP(w, r)
	})
}

// getConfigForPath returns the rate limit config that applies to the given path.
// Returns nil if no config matches the path.
func (m *rateLimiterMiddleware) getConfigForPath(path string) *RateLimitConfig {
	// If using single config mode (backward compatibility)
	if len(m.locationConfigs) == 0 {
		return &m.cfg
	}

	// Check location-based configs in order
	for _, locCfg := range m.locationConfigs {
		for _, pattern := range locCfg.PathPatterns {
			if matchPath(path, []string{}, []string{pattern}, true) {
				return &locCfg.Config
			}
		}
	}

	// No config matches this path
	return nil
}

// shouldRateLimit determines if the request should be rate limited based on the path.
func (m *rateLimiterMiddleware) shouldRateLimit(r *http.Request, cfg RateLimitConfig) bool {
	return matchPath(r.URL.Path, cfg.ExcludePaths, cfg.IncludePaths, false)
}

// getLimiter retrieves or creates a rate limiter for a visitor.
// Returns nil if memory limits are exceeded.
func (m *rateLimiterMiddleware) getLimiter(key string, cfg RateLimitConfig) *rate.Limiter {
	// First try with read lock for better performance
	m.mu.RLock()
	if v, exists := m.visitors[key]; exists {
		// Update lastSeen atomically - no race condition
		v.updateLastSeen()
		limiter := v.limiter
		m.mu.RUnlock()
		return limiter
	}
	m.mu.RUnlock()

	// Check if we're at memory limit before creating new visitor
	currentCount := atomic.LoadInt64(&m.visitorCount)
	if currentCount >= maxVisitors {
		// Trigger emergency cleanup and reject request
		select {
		case m.emergencyCleanup <- struct{}{}:
		default: // Don't block if channel is full
		}
		return nil // Reject request to prevent memory exhaustion
	}

	// If not found, acquire write lock and create new limiter
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check in case another goroutine created it while we were waiting
	if v, exists := m.visitors[key]; exists {
		v.updateLastSeen()
		return v.limiter
	}

	// Final check with actual map size to handle any counter drift
	if len(m.visitors) >= maxVisitors {
		return nil
	}

	// Create new rate limiter with the specific config
	limiter := rate.NewLimiter(
		rate.Limit(float64(cfg.RequestsPerInterval)/cfg.Interval.Seconds()),
		cfg.BurstSize,
	)

	// Get visitor from pool and initialize it
	v := getVisitor()
	v.limiter = limiter
	v.lastSeen = time.Now().Unix()

	// Store the visitor
	m.visitors[key] = v

	// Update atomic counter
	atomic.AddInt64(&m.visitorCount, 1)

	return limiter
}

// getUsernameKeyFuncWithProxies returns a key function that uses the username from the request body
// as the rate limit key for login attempts. Falls back to IP if no username found.
// This function preserves the request body for subsequent handlers.
func getUsernameKeyFuncWithProxies(trustedProxies []string) func(r *http.Request) string {
	ipKeyFunc := getIPKeyFuncWithProxies(trustedProxies)
	return func(r *http.Request) string {
		// Only try to extract username from login/register endpoints
		if r.Method == http.MethodPost && (r.URL.Path == "/login" || r.URL.Path == "/register") {
			// Read body with size limit to prevent DoS attacks
			body, err := io.ReadAll(io.LimitReader(r.Body, defaultMaxUsernameBodySize)) // 1KB limit for username extraction
			if err == nil && len(body) > 0 {
				// Restore the body for subsequent handlers
				r.Body = io.NopCloser(bytes.NewReader(body))

				// Try to parse JSON to extract username
				var req struct {
					Username string `json:"username"`
				}
				if stdjson.Unmarshal(body, &req) == nil && req.Username != "" {
					return "user:" + req.Username // Prefix to distinguish from IP-based keys
				}
			}
		}
		// Fall back to IP-based limiting
		return "ip:" + ipKeyFunc(r) // Prefix to distinguish key types
	}
}

// getIPKeyFuncWithProxies returns a key function that uses the client's IP address as the rate limit key.
// It only trusts proxy headers (X-Forwarded-For, X-Real-IP) when the request comes from a trusted proxy.
func getIPKeyFuncWithProxies(trustedProxies []string) func(r *http.Request) string {
	// Parse trusted proxy networks once for efficiency
	var trustedNets []*net.IPNet
	if len(trustedProxies) > 0 {
		trustedNets = make([]*net.IPNet, 0, len(trustedProxies))
		for _, proxy := range trustedProxies {
			// Handle both single IPs and CIDR ranges
			if !strings.Contains(proxy, "/") {
				// Single IP, convert to /32 or /128
				if ip := net.ParseIP(proxy); ip != nil {
					if ip.To4() != nil {
						proxy += "/32"
					} else {
						proxy += "/128"
					}
				}
			}
			if _, network, err := net.ParseCIDR(proxy); err == nil {
				trustedNets = append(trustedNets, network)
			}
		}
	}

	return func(r *http.Request) string {
		// Get the remote address
		remoteAddr := getRemoteAddr(r)

		// If no trusted proxies configured, always use RemoteAddr for security
		if len(trustedNets) == 0 {
			return remoteAddr
		}

		// Check if the request comes from a trusted proxy
		if !isFromTrustedProxy(remoteAddr, trustedNets) {
			return remoteAddr
		}

		// Try to get real IP from trusted proxy headers
		if ip := extractIPFromHeaders(r); ip != "" && isValidIP(ip) {
			return ip
		}

		// Fall back to RemoteAddr
		return remoteAddr
	}
}

// getRemoteAddr extracts the remote address from the request.
func getRemoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr might not have port (e.g., during testing)
		return r.RemoteAddr
	}
	return host
}

// isFromTrustedProxy checks if the remote address is from a trusted proxy.
func isFromTrustedProxy(remoteAddr string, trustedNets []*net.IPNet) bool {
	ip := net.ParseIP(remoteAddr)
	if ip == nil {
		return false
	}

	for _, network := range trustedNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// extractIPFromHeaders extracts the real client IP from proxy headers.
func extractIPFromHeaders(r *http.Request) string {
	// Check X-Forwarded-For header (can contain multiple IPs)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs separated by commas
		// The first IP is the original client IP
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	return ""
}

// isValidIP validates that the given string is a valid IP address.
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
