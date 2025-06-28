package servex

import (
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/maxbolgarin/lang"
	"golang.org/x/time/rate"
)

const cleanupInterval = 3 * time.Hour

// visitor represents a client accessing the server.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
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
// RequestsPerInterval must be greater than 0.
func RegisterRateLimitMiddleware(router MiddlewareRouter, cfg RateLimitConfig) func() {
	if cfg.RequestsPerInterval <= 0 {
		return nil
	}

	cfg.BurstSize = lang.Check(cfg.BurstSize, cfg.RequestsPerInterval)
	cfg.Interval = lang.Check(cfg.Interval, time.Minute)
	cfg.StatusCode = lang.Check(cfg.StatusCode, http.StatusTooManyRequests)
	cfg.Message = lang.Check(cfg.Message, "rate limit exceeded, try again later.")

	if cfg.KeyFunc == nil {
		cfg.KeyFunc = getUsernameKeyFunc()
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

	return m.Stop
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
		if now.Sub(v.lastSeen) > cleanupInterval {
			delete(m.visitors, key)
		}
	}
}

// Stop gracefully stops the cleanup routine.
func (m *rateLimiterMiddleware) Stop() {
	close(m.cleanupDone)
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
	// Check if path is in the excluded list
	path := r.URL.Path
	if slices.Contains(m.cfg.ExcludePaths, path) {
		return false
	}

	// If include paths are specified, check if this path is included
	if len(m.cfg.IncludePaths) > 0 {
		return slices.Contains(m.cfg.IncludePaths, path)
	}

	// By default, rate limit all paths not explicitly excluded
	return true
}

// getLimiter retrieves or creates a rate limiter for a visitor.
func (m *rateLimiterMiddleware) getLimiter(key string) *rate.Limiter {
	// First try with read lock for better performance
	m.mu.RLock()
	if v, exists := m.visitors[key]; exists {
		v.lastSeen = time.Now()
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
		v.lastSeen = time.Now()
		return v.limiter
	}

	limiter := rate.NewLimiter(
		rate.Limit(float64(m.cfg.RequestsPerInterval)/m.cfg.Interval.Seconds()),
		m.cfg.BurstSize,
	)

	m.visitors[key] = &visitor{
		limiter:  limiter,
		lastSeen: time.Now(),
	}

	return limiter
}

// UsernameKeyFunc returns a key function that uses the username from the request body
// as the rate limit key for login attempts. Falls backto IP if no username found.
func getUsernameKeyFunc() func(r *http.Request) string {
	ipKeyFunc := getIPKeyFunc()
	return func(r *http.Request) string {
		// Only try to extract username from login/register endpoints
		if r.Method == http.MethodPost && (r.URL.Path == "/login" || r.URL.Path == "/register") {
			// Try to parse JSON from body
			var req struct {
				Username string `json:"username"`
			}
			ctx := NewContext(nil, r)
			if err := ctx.ReadJSON(&req); err == nil && req.Username != "" {
				return "username:" + req.Username
			}
		}
		// Fall back to IP-based limiting
		return ipKeyFunc(r)
	}
}

// IPKeyFunc returns a key function that uses the client's IP address as the rate limit key.
// It tries to get the real IP from common proxy headers if they exist.
func getIPKeyFunc() func(r *http.Request) string {
	return func(r *http.Request) string {
		// Try to get real IP from headers that might be set by proxies
		if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
			return ip
		}
		if ip := r.Header.Get("X-Real-IP"); ip != "" {
			return ip
		}
		// Fall back to RemoteAddr
		return r.RemoteAddr
	}
}
