package servex

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maxbolgarin/lang"
	"golang.org/x/time/rate"
)

const (
	cleanupInterval = 3 * time.Hour
	defaultInterval = time.Minute
)

// visitor represents a client accessing the server.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen int64 // Use atomic int64 for Unix timestamp to avoid race conditions
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
	cfg         RateLimitConfig
	visitors    map[string]*visitor
	mu          sync.RWMutex
	statusMsg   string
	cleanupDone chan struct{}
	cleanupOnce sync.Once
}

// RegisterRateLimitMiddleware adds rate limiting middleware to the router.
// If the config is not enabled, no middleware will be registered.
// It returns a function that can be used to stop the cleanup routine.
func RegisterRateLimitMiddleware(router MiddlewareRouter, cfg RateLimitConfig) func() {
	if cfg.RequestsPerInterval <= 0 {
		return nil
	}

	cfg.BurstSize = lang.Check(cfg.BurstSize, cfg.RequestsPerInterval)
	cfg.Interval = lang.Check(cfg.Interval, defaultInterval)
	cfg.StatusCode = lang.Check(cfg.StatusCode, http.StatusTooManyRequests)
	cfg.Message = lang.Check(cfg.Message, "rate limit exceeded, try again later.")

	if cfg.KeyFunc == nil {
		cfg.KeyFunc = getUsernameKeyFuncWithProxies(cfg.TrustedProxies)
	}

	m := &rateLimiterMiddleware{
		cfg:         cfg,
		visitors:    make(map[string]*visitor),
		cleanupDone: make(chan struct{}),
	}

	router.Use(m.middleware)

	// Start cleanup goroutine only once
	m.cleanupOnce.Do(func() {
		go m.startCleanupRoutine()
	})

	return func() {
		close(m.cleanupDone)
	}
}

// startCleanupRoutine runs a background cleanup task to remove stale visitors.
func (m *rateLimiterMiddleware) startCleanupRoutine() {
	// Run cleanup every 30 minutes instead of every 18 minutes (cleanupInterval/10)
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanup()
		case <-m.cleanupDone:
			return
		}
	}
}

// cleanup removes stale visitors from the map.
func (m *rateLimiterMiddleware) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for key, v := range m.visitors {
		if now.Sub(v.getLastSeen()) > cleanupInterval {
			delete(m.visitors, key)
		}
	}
}

// middleware is the actual rate limiting middleware function.
func (m *rateLimiterMiddleware) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the path should be rate limited
		if !m.shouldRateLimit(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Get the rate limiting key from the request
		key := m.cfg.KeyFunc(r)

		// Get or create rate limiter for this visitor
		limiter := m.getLimiter(key)

		// Check if this request exceeds the rate limit
		if !limiter.Allow() {
			// Rate limit exceeded
			w.Header().Set("Retry-After", "60") // Suggest retry after 1 minute
			C(w, r).Error(fmt.Errorf("rate limit exceeded"), m.cfg.StatusCode, m.cfg.Message)
			return
		}

		// Allow the request
		next.ServeHTTP(w, r)
	})
}

// shouldRateLimit determines if the request should be rate limited based on the path.
func (m *rateLimiterMiddleware) shouldRateLimit(r *http.Request) bool {
	return matchPath(r.URL.Path, m.cfg.ExcludePaths, m.cfg.IncludePaths, false)
}

// getLimiter retrieves or creates a rate limiter for a visitor.
func (m *rateLimiterMiddleware) getLimiter(key string) *rate.Limiter {
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

	// If not found, acquire write lock and create new limiter
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check in case another goroutine created it while we were waiting
	if v, exists := m.visitors[key]; exists {
		v.updateLastSeen()
		return v.limiter
	}

	limiter := rate.NewLimiter(
		rate.Limit(float64(m.cfg.RequestsPerInterval)/m.cfg.Interval.Seconds()),
		m.cfg.BurstSize,
	)

	m.visitors[key] = &visitor{
		limiter:  limiter,
		lastSeen: time.Now().Unix(),
	}

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
			// Read body and preserve it for the actual handler
			if body, err := io.ReadAll(r.Body); err == nil && len(body) > 0 {
				// Restore the body for subsequent handlers
				r.Body = io.NopCloser(bytes.NewReader(body))

				// Try to parse JSON from body copy using a temporary request
				tempReq := *r
				tempReq.Body = io.NopCloser(bytes.NewReader(body))
				ctx := NewContext(nil, &tempReq)

				var req struct {
					Username string `json:"username"`
				}
				if err := ctx.ReadJSON(&req); err == nil && req.Username != "" {
					return req.Username
				}
			}
		}
		// Fall back to IP-based limiting
		return ipKeyFunc(r)
	}
}

// getIPKeyFuncWithProxies returns a key function that uses the client's IP address as the rate limit key.
// It only trusts proxy headers (X-Forwarded-For, X-Real-IP) when the request comes from a trusted proxy.
func getIPKeyFuncWithProxies(trustedProxies []string) func(r *http.Request) string {
	// Parse trusted proxy networks once
	var trustedNets []*net.IPNet
	if len(trustedProxies) > 0 {
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
