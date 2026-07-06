package servex

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// RegisterSecurityHeadersMiddleware adds security headers to HTTP responses.
// It implements common security headers to protect against various attacks.
// If the config is empty or disabled, no middleware will be registered.
func RegisterSecurityHeadersMiddleware(router MiddlewareRouter, cfg SecurityConfig) {
	if !cfg.isActive() {
		return
	}

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the path should have security headers applied
			if !shouldApplySecurityHeaders(r, cfg) {
				next.ServeHTTP(w, r)
				return
			}

			// Apply security headers before handler
			applySecurityHeaders(w, cfg)

			// Execute the handler
			next.ServeHTTP(w, r)
		})
	})

	// Register CSRF protection if enabled
	if cfg.CSRFEnabled {
		RegisterCSRFMiddleware(router, cfg)
	}
}

// RegisterCSRFMiddleware adds CSRF (Cross-Site Request Forgery) protection middleware.
// This middleware provides comprehensive CSRF protection for web applications.
func RegisterCSRFMiddleware(router MiddlewareRouter, cfg SecurityConfig) {
	// Set defaults for CSRF configuration
	tokenName := cfg.CSRFTokenName
	if tokenName == "" {
		tokenName = "X-CSRF-Token"
	}

	cookieName := cfg.CSRFCookieName
	if cookieName == "" {
		cookieName = "csrf_token"
	}

	cookiePath := cfg.CSRFCookiePath
	if cookiePath == "" {
		cookiePath = "/"
	}

	// Default SameSite to Lax if not configured
	if cfg.CSRFCookieSameSite == "" {
		cfg.CSRFCookieSameSite = "lax"
	}

	errorMessage := cfg.CSRFErrorMessage
	if errorMessage == "" {
		errorMessage = "CSRF token validation failed"
	}

	safeMethods := cfg.CSRFSafeMethods
	if len(safeMethods) == 0 {
		safeMethods = []string{GET, HEAD, OPTIONS, TRACE}
	}

	// Create safe methods map for faster lookup
	safeMethodsMap := make(map[string]bool)
	for _, method := range safeMethods {
		safeMethodsMap[strings.ToUpper(method)] = true
	}

	// Register CSRF token endpoint if configured
	if cfg.CSRFTokenEndpoint != "" {
		registerCSRFTokenEndpoint(router, cfg.CSRFTokenEndpoint, cookieName, cookiePath, cfg)
	}

	// Register CSRF validation middleware
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CSRF validation for safe methods
			if safeMethodsMap[strings.ToUpper(r.Method)] {
				// Set CSRF cookie for safe methods to establish token
				if _, err := r.Cookie(cookieName); err != nil {
					setCSRFCookie(w, cookieName, cookiePath, cfg)
				}
				next.ServeHTTP(w, r)
				return
			}

			// Skip CSRF validation for token endpoint
			if cfg.CSRFTokenEndpoint != "" && r.URL.Path == cfg.CSRFTokenEndpoint {
				next.ServeHTTP(w, r)
				return
			}

			// Check if the path should have CSRF protection applied
			if !shouldApplySecurityHeaders(r, cfg) {
				next.ServeHTTP(w, r)
				return
			}

			// Validate CSRF token
			if !validateCSRFToken(r, tokenName, cookieName) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(errorMessage))
				return
			}

			// Token is valid, proceed with request
			next.ServeHTTP(w, r)
		})
	})
}

// registerCSRFTokenEndpoint creates an endpoint that returns CSRF tokens for SPAs and AJAX applications.
func registerCSRFTokenEndpoint(router MiddlewareRouter, endpoint, cookieName, cookiePath string, cfg SecurityConfig) {
	if endpoint == "" {
		endpoint = "/csrf-token"
	}
	// We need to add the endpoint to the router if it's a *mux.Router
	if muxRouter, ok := router.(*mux.Router); ok {
		muxRouter.HandleFunc(endpoint, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != GET {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			// Generate and set CSRF token
			token := setCSRFCookie(w, cookieName, cookiePath, cfg)

			// Return token as JSON
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"csrf_token": "%s"}`, token)
		}).Methods(GET)
	}
}

// setCSRFCookie generates a new CSRF token and sets it as a cookie.
func setCSRFCookie(w http.ResponseWriter, cookieName, cookiePath string, cfg SecurityConfig) string {
	// Generate secure random token
	token := generateCSRFToken()

	// Create cookie
	// CSRF cookies are HttpOnly by default to prevent token theft via XSS;
	// clients then use the X-CSRF-Token header (from a /csrf-token endpoint).
	// An explicit CSRFCookieHttpOnly=false makes the cookie readable from
	// JavaScript for the SPA double-submit cookie pattern.
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     cookiePath,
		HttpOnly: cfg.CSRFCookieHttpOnly == nil || *cfg.CSRFCookieHttpOnly,
		Secure:   cfg.CSRFCookieSecure,
		SameSite: parseSameSite(cfg.CSRFCookieSameSite),
	}

	// Set MaxAge if configured
	if cfg.CSRFCookieMaxAge > 0 {
		cookie.MaxAge = cfg.CSRFCookieMaxAge
		cookie.Expires = time.Now().Add(time.Duration(cfg.CSRFCookieMaxAge) * time.Second)
	}

	// Set cookie
	http.SetCookie(w, cookie)

	return token
}

// validateCSRFToken validates the CSRF token from the request.
func validateCSRFToken(r *http.Request, tokenName, cookieName string) bool {
	// Get expected token from cookie
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	expectedToken := cookie.Value

	// Extract token from request (try multiple sources)
	var providedToken string

	// 1. Try header
	providedToken = r.Header.Get(tokenName)

	// 2. Try form field if not found in header
	if providedToken == "" {
		if err := r.ParseForm(); err == nil {
			providedToken = r.FormValue(tokenName)
		}
	}

	// 3. Try multipart form if still not found
	if providedToken == "" && strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err == nil { // 32MB max
			if r.MultipartForm != nil && r.MultipartForm.Value != nil {
				if values := r.MultipartForm.Value[tokenName]; len(values) > 0 {
					providedToken = values[0]
				}
			}
		}
	}

	// Validate token using constant-time comparison
	if providedToken == "" || expectedToken == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(providedToken), []byte(expectedToken)) == 1
}

// generateCSRFToken generates a cryptographically secure random token.
// If crypto/rand is unavailable, this function will panic rather than falling back
// to an insecure random source.
func generateCSRFToken() string {
	// Generate 32 bytes of random data
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// CRITICAL: Do not fallback to insecure random generation
		// If crypto/rand fails, the system is in an insecure state
		panic(fmt.Sprintf("CRITICAL: crypto/rand unavailable for CSRF token generation: %v", err))
	}

	// Encode as base64 URL-safe string
	return base64.URLEncoding.EncodeToString(bytes)
}

// parseSameSite converts string to http.SameSite enum.
func parseSameSite(sameSite string) http.SameSite {
	switch strings.ToLower(sameSite) {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode // Default to Lax for security and usability balance
	}
}

// shouldApplySecurityHeaders determines if security headers should be applied based on the path.
func shouldApplySecurityHeaders(r *http.Request, cfg SecurityConfig) bool {
	return matchPath(r.URL.Path, cfg.ExcludePaths, cfg.IncludePaths, true)
}

// applySecurityHeaders applies the configured security headers to the response.
func applySecurityHeaders(w http.ResponseWriter, cfg SecurityConfig) {
	header := w.Header()

	// Content Security Policy
	if cfg.ContentSecurityPolicy != "" {
		header.Set("Content-Security-Policy", cfg.ContentSecurityPolicy)
	}

	// X-Content-Type-Options
	if cfg.XContentTypeOptions != "" {
		header.Set("X-Content-Type-Options", cfg.XContentTypeOptions)
	}

	// X-Frame-Options
	if cfg.XFrameOptions != "" {
		header.Set("X-Frame-Options", cfg.XFrameOptions)
	}

	// X-XSS-Protection
	if cfg.XXSSProtection != "" {
		header.Set("X-XSS-Protection", cfg.XXSSProtection)
	}

	// Strict-Transport-Security
	if cfg.StrictTransportSecurity != "" {
		header.Set("Strict-Transport-Security", cfg.StrictTransportSecurity)
	}

	// Referrer-Policy
	if cfg.ReferrerPolicy != "" {
		header.Set("Referrer-Policy", cfg.ReferrerPolicy)
	}

	// Permissions-Policy
	if cfg.PermissionsPolicy != "" {
		header.Set("Permissions-Policy", cfg.PermissionsPolicy)
	}

	// X-Permitted-Cross-Domain-Policies
	if cfg.XPermittedCrossDomainPolicies != "" {
		header.Set("X-Permitted-Cross-Domain-Policies", cfg.XPermittedCrossDomainPolicies)
	}

	// Cross-Origin-Embedder-Policy
	if cfg.CrossOriginEmbedderPolicy != "" {
		header.Set("Cross-Origin-Embedder-Policy", cfg.CrossOriginEmbedderPolicy)
	}

	// Cross-Origin-Opener-Policy
	if cfg.CrossOriginOpenerPolicy != "" {
		header.Set("Cross-Origin-Opener-Policy", cfg.CrossOriginOpenerPolicy)
	}

	// Cross-Origin-Resource-Policy
	if cfg.CrossOriginResourcePolicy != "" {
		header.Set("Cross-Origin-Resource-Policy", cfg.CrossOriginResourcePolicy)
	}
}

// RegisterCustomHeadersMiddleware adds custom headers to HTTP responses.
// This is separate from security headers to maintain separation of concerns.
func RegisterCustomHeadersMiddleware(router MiddlewareRouter, customHeaders map[string]string) {
	if len(customHeaders) == 0 {
		return // No custom headers to add
	}

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Apply custom headers before handler
			header := w.Header()
			for name, value := range customHeaders {
				if value != "" {
					header.Set(name, value)
				}
			}

			next.ServeHTTP(w, r)
		})
	})
}

// RegisterHeaderRemovalMiddleware removes specified headers from HTTP responses.
// It wraps the ResponseWriter so that headers are deleted just before they are
// flushed, which is the only reliable way to suppress headers set by handlers.
func RegisterHeaderRemovalMiddleware(router MiddlewareRouter, headersToRemove []string) {
	if len(headersToRemove) == 0 {
		return // No headers to remove
	}

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(&headerRemovalWriter{ResponseWriter: w, headers: headersToRemove}, r)
		})
	})
}

// headerRemovalWriter is a ResponseWriter wrapper that strips configured headers
// just before they are flushed to the client.
type headerRemovalWriter struct {
	http.ResponseWriter
	headers []string
}

func (w *headerRemovalWriter) WriteHeader(code int) {
	for _, h := range w.headers {
		w.ResponseWriter.Header().Del(h)
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *headerRemovalWriter) Write(b []byte) (int, error) {
	// Ensure headers are stripped even when WriteHeader is called implicitly.
	for _, h := range w.headers {
		w.ResponseWriter.Header().Del(h)
	}
	return w.ResponseWriter.Write(b)
}

func (w *headerRemovalWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("upstream ResponseWriter does not implement http.Hijacker")
}

func (w *headerRemovalWriter) Flush() {
	if fl, ok := w.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

// RegisterHTTPSRedirectMiddleware adds HTTP to HTTPS redirection middleware to the router.
// This middleware automatically redirects all HTTP requests to their HTTPS equivalent
// to enforce secure connections across the entire application.
// If the config is disabled, no middleware will be registered.
func RegisterHTTPSRedirectMiddleware(router MiddlewareRouter, cfg HTTPSRedirectConfig) {
	if !cfg.isActive() {
		return
	}

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the path should be redirected to HTTPS
			if !shouldRedirectToHTTPS(r, cfg) {
				next.ServeHTTP(w, r)
				return
			}

			// Check if the request is already HTTPS
			if isHTTPSRequest(r, cfg.TrustedProxies) {
				next.ServeHTTP(w, r)
				return
			}

			// Validate Host header to prevent open redirect via spoofed Host
			host := r.Host
			if len(cfg.AllowedHosts) > 0 {
				// Strip port for comparison
				h := host
				if colonIdx := strings.LastIndex(h, ":"); colonIdx != -1 {
					h = h[:colonIdx]
				}
				allowed := false
				for _, ah := range cfg.AllowedHosts {
					if strings.EqualFold(h, ah) {
						allowed = true
						break
					}
				}
				if !allowed {
					w.WriteHeader(http.StatusMisdirectedRequest)
					return
				}
			}

			// Perform HTTP to HTTPS redirect
			httpsURL := "https://" + host + r.RequestURI

			// Choose redirect status code
			statusCode := http.StatusMovedPermanently // 301
			if !cfg.Permanent {
				statusCode = http.StatusFound // 302
			}

			w.Header().Set("Location", httpsURL)
			w.WriteHeader(statusCode)
		})
	})
}

// shouldRedirectToHTTPS determines if a request path should be redirected to HTTPS
// based on the configuration's include and exclude paths.
func shouldRedirectToHTTPS(r *http.Request, cfg HTTPSRedirectConfig) bool {
	return matchPath(r.URL.Path, cfg.ExcludePaths, cfg.IncludePaths, true)
}

// isHTTPSRequest checks if the current request is already using HTTPS.
// It considers both direct TLS connections and proxy headers for load balancer scenarios.
func isHTTPSRequest(r *http.Request, trustedProxies []string) bool {
	// Direct TLS connection
	if r.TLS != nil {
		return true
	}

	// Check proxy headers only if the request comes from a trusted proxy
	if len(trustedProxies) > 0 {
		remoteAddr := r.RemoteAddr
		if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
			remoteAddr = host
		}

		// Check if request comes from trusted proxy
		if isFromTrustedHTTPSProxy(remoteAddr, trustedProxies) {
			return isHTTPSFromProxyHeaders(r)
		}
	}

	return false
}

// isFromTrustedHTTPSProxy checks if the remote address is from a trusted proxy for HTTPS redirection.
func isFromTrustedHTTPSProxy(remoteAddr string, trustedProxies []string) bool {
	remoteIP := net.ParseIP(remoteAddr)
	if remoteIP == nil {
		return false
	}

	for _, proxy := range trustedProxies {
		// Try parsing as CIDR
		_, network, err := net.ParseCIDR(proxy)
		if err == nil {
			if network.Contains(remoteIP) {
				return true
			}
			continue
		}

		// Try parsing as single IP
		proxyIP := net.ParseIP(proxy)
		if proxyIP != nil && proxyIP.Equal(remoteIP) {
			return true
		}
	}

	return false
}

// isHTTPSFromProxyHeaders checks standard proxy headers to determine if the original request was HTTPS.
func isHTTPSFromProxyHeaders(r *http.Request) bool {
	// Check X-Forwarded-Proto header (most common)
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return strings.ToLower(proto) == "https"
	}

	// Check X-Forwarded-Ssl header (some load balancers)
	if ssl := r.Header.Get("X-Forwarded-Ssl"); ssl != "" {
		return strings.ToLower(ssl) == "on"
	}

	// Check X-Url-Scheme header (some proxies)
	if scheme := r.Header.Get("X-Url-Scheme"); scheme != "" {
		return strings.ToLower(scheme) == "https"
	}

	// Check Front-End-Https header (Microsoft IIS)
	if frontEnd := r.Header.Get("Front-End-Https"); frontEnd != "" {
		return strings.ToLower(frontEnd) == "on"
	}

	// Check X-Forwarded-Port header (if it's the standard HTTPS port)
	if port := r.Header.Get("X-Forwarded-Port"); port == "443" {
		return true
	}

	return false
}
