package servex

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
)

// Filter holds the compiled filtering logic and patterns.
// This struct is responsible for all filtering logic.
type Filter struct {
	config FilterConfig

	// compiled regex patterns and IP networks
	allowedIPNets      []*net.IPNet
	blockedIPNets      []*net.IPNet
	allowedUAExact     map[string]bool
	blockedUAExact     map[string]bool
	allowedUARegex     []*regexp.Regexp
	blockedUARegex     []*regexp.Regexp
	allowedHeaderExact map[string]map[string]bool
	blockedHeaderExact map[string]map[string]bool
	allowedHeaderRegex map[string][]*regexp.Regexp
	blockedHeaderRegex map[string][]*regexp.Regexp
	allowedQueryExact  map[string]map[string]bool
	blockedQueryExact  map[string]map[string]bool
	allowedQueryRegex  map[string][]*regexp.Regexp
	blockedQueryRegex  map[string][]*regexp.Regexp
	trustedProxyNets   []*net.IPNet
}

// RegisterFilterMiddleware adds request filtering middleware to the router.
// If the config has no filters configured, no middleware will be registered.
func RegisterFilterMiddleware(router MiddlewareRouter, cfg FilterConfig) {
	if !cfg.isEnabled() {
		return
	}

	filter, err := newFilter(cfg)
	if err != nil {
		// Log error but don't prevent server startup
		// In production, you might want to fail startup instead
		return
	}

	router.Use(filter.middleware)
}

// isEnabled checks if any filtering rules are configured.
func (cfg *FilterConfig) isEnabled() bool {
	return len(cfg.AllowedIPs) > 0 ||
		len(cfg.BlockedIPs) > 0 ||
		len(cfg.AllowedUserAgents) > 0 ||
		len(cfg.AllowedUserAgentsRegex) > 0 ||
		len(cfg.BlockedUserAgents) > 0 ||
		len(cfg.BlockedUserAgentsRegex) > 0 ||
		len(cfg.AllowedHeaders) > 0 ||
		len(cfg.AllowedHeadersRegex) > 0 ||
		len(cfg.BlockedHeaders) > 0 ||
		len(cfg.BlockedHeadersRegex) > 0 ||
		len(cfg.AllowedQueryParams) > 0 ||
		len(cfg.AllowedQueryParamsRegex) > 0 ||
		len(cfg.BlockedQueryParams) > 0 ||
		len(cfg.BlockedQueryParamsRegex) > 0
}

// newFilter creates a new Filter from the given configuration.
func newFilter(cfg FilterConfig) (*Filter, error) {
	filter := &Filter{
		config: cfg,
	}

	if err := filter.compile(); err != nil {
		return nil, fmt.Errorf("compile filter: %w", err)
	}

	return filter, nil
}

// compile prepares regex patterns and IP networks for efficient matching.
func (f *Filter) compile() error {
	var err error

	// Compile IP networks
	f.allowedIPNets, err = f.compileIPNets(f.config.AllowedIPs)
	if err != nil {
		return fmt.Errorf("compile allowed IPs: %w", err)
	}

	f.blockedIPNets, err = f.compileIPNets(f.config.BlockedIPs)
	if err != nil {
		return fmt.Errorf("compile blocked IPs: %w", err)
	}

	f.trustedProxyNets, err = f.compileIPNets(f.config.TrustedProxies)
	if err != nil {
		return fmt.Errorf("compile trusted proxies: %w", err)
	}

	// Compile User-Agent patterns
	f.allowedUAExact = f.compileExactPatterns(f.config.AllowedUserAgents)
	f.blockedUAExact = f.compileExactPatterns(f.config.BlockedUserAgents)

	f.allowedUARegex, err = f.compileRegexPatterns(f.config.AllowedUserAgentsRegex)
	if err != nil {
		return fmt.Errorf("compile allowed user agent regex: %w", err)
	}

	f.blockedUARegex, err = f.compileRegexPatterns(f.config.BlockedUserAgentsRegex)
	if err != nil {
		return fmt.Errorf("compile blocked user agent regex: %w", err)
	}

	// Compile header patterns
	f.allowedHeaderExact = f.compileExactHeaderPatterns(f.config.AllowedHeaders)
	f.blockedHeaderExact = f.compileExactHeaderPatterns(f.config.BlockedHeaders)

	f.allowedHeaderRegex, err = f.compileRegexHeaderPatterns(f.config.AllowedHeadersRegex)
	if err != nil {
		return fmt.Errorf("compile allowed header regex: %w", err)
	}

	f.blockedHeaderRegex, err = f.compileRegexHeaderPatterns(f.config.BlockedHeadersRegex)
	if err != nil {
		return fmt.Errorf("compile blocked header regex: %w", err)
	}

	// Compile query parameter patterns
	f.allowedQueryExact = f.compileExactHeaderPatterns(f.config.AllowedQueryParams)
	f.blockedQueryExact = f.compileExactHeaderPatterns(f.config.BlockedQueryParams)

	f.allowedQueryRegex, err = f.compileRegexHeaderPatterns(f.config.AllowedQueryParamsRegex)
	if err != nil {
		return fmt.Errorf("compile allowed query regex: %w", err)
	}

	f.blockedQueryRegex, err = f.compileRegexHeaderPatterns(f.config.BlockedQueryParamsRegex)
	if err != nil {
		return fmt.Errorf("compile blocked query regex: %w", err)
	}

	return nil
}

// compileIPNets converts IP strings to IPNet objects.
func (f *Filter) compileIPNets(ips []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, ipStr := range ips {
		// Check if it's a CIDR range
		if strings.Contains(ipStr, "/") {
			_, ipNet, err := net.ParseCIDR(ipStr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %s: %w", ipStr, err)
			}
			nets = append(nets, ipNet)
		} else {
			// Single IP address
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %s", ipStr)
			}
			// Convert to CIDR
			var ipNet *net.IPNet
			if ip.To4() != nil {
				_, ipNet, _ = net.ParseCIDR(ipStr + "/32")
			} else {
				_, ipNet, _ = net.ParseCIDR(ipStr + "/128")
			}
			nets = append(nets, ipNet)
		}
	}
	return nets, nil
}

// compileExactPatterns creates a map for fast exact string lookups.
func (f *Filter) compileExactPatterns(patterns []string) map[string]bool {
	result := make(map[string]bool)
	for _, pattern := range patterns {
		result[pattern] = true
	}
	return result
}

// compileRegexPatterns compiles string patterns to regex.
func (f *Filter) compileRegexPatterns(patterns []string) ([]*regexp.Regexp, error) {
	var regexes []*regexp.Regexp
	for _, pattern := range patterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern %s: %w", pattern, err)
		}
		regexes = append(regexes, regex)
	}
	return regexes, nil
}

// compileExactHeaderPatterns compiles exact header/query parameter patterns.
func (f *Filter) compileExactHeaderPatterns(headers map[string][]string) map[string]map[string]bool {
	result := make(map[string]map[string]bool)
	for header, patterns := range headers {
		headerMap := make(map[string]bool)
		for _, pattern := range patterns {
			headerMap[pattern] = true
		}
		result[strings.ToLower(header)] = headerMap
	}
	return result
}

// compileRegexHeaderPatterns compiles regex header/query parameter patterns.
func (f *Filter) compileRegexHeaderPatterns(headers map[string][]string) (map[string][]*regexp.Regexp, error) {
	result := make(map[string][]*regexp.Regexp)
	for header, patterns := range headers {
		regexes, err := f.compileRegexPatterns(patterns)
		if err != nil {
			return nil, fmt.Errorf("compile patterns for %s: %w", header, err)
		}
		result[strings.ToLower(header)] = regexes
	}
	return result, nil
}

// middleware is the actual filtering middleware function.
func (f *Filter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the path should be filtered
		if !f.shouldFilter(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Check IP filtering
		if !f.checkIP(r) {
			f.blockRequest(w, r, "IP address blocked")
			return
		}

		// Check User-Agent filtering
		if !f.checkUserAgent(r) {
			f.blockRequest(w, r, "User-Agent blocked")
			return
		}

		// Check header filtering
		if !f.checkHeaders(r) {
			f.blockRequest(w, r, "Request headers blocked")
			return
		}

		// Check query parameter filtering
		if !f.checkQueryParams(r) {
			f.blockRequest(w, r, "Query parameters blocked")
			return
		}

		// All checks passed, allow the request
		next.ServeHTTP(w, r)
	})
}

// shouldFilter determines if the request should be filtered based on the path.
func (f *Filter) shouldFilter(r *http.Request) bool {
	return matchPath(r.URL.Path, f.config.ExcludePaths, f.config.IncludePaths, false)
}

// getClientIP extracts the real client IP, considering trusted proxies.
func (f *Filter) getClientIP(r *http.Request) string {
	// Get remote address
	remoteAddr := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteAddr = host
	}

	// Check if request comes from trusted proxy
	if len(f.trustedProxyNets) > 0 {
		remoteIP := net.ParseIP(remoteAddr)
		if remoteIP != nil {
			for _, trustedNet := range f.trustedProxyNets {
				if trustedNet.Contains(remoteIP) {
					// Request comes from trusted proxy, check headers
					if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
						// Use first IP in X-Forwarded-For chain
						if ips := strings.Split(ip, ","); len(ips) > 0 {
							return strings.TrimSpace(ips[0])
						}
					}
					if ip := r.Header.Get("X-Real-IP"); ip != "" {
						return strings.TrimSpace(ip)
					}
					break
				}
			}
		}
	}

	return remoteAddr
}

// checkIP checks if the client IP is allowed.
func (f *Filter) checkIP(r *http.Request) bool {
	clientIP := f.getClientIP(r)
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false // Invalid IP
	}

	// Check blocked IPs first (takes precedence)
	for _, blockedNet := range f.blockedIPNets {
		if blockedNet.Contains(ip) {
			return false
		}
	}

	// If allowed IPs are specified, check if IP is in the list
	if len(f.allowedIPNets) > 0 {
		for _, allowedNet := range f.allowedIPNets {
			if allowedNet.Contains(ip) {
				return true
			}
		}
		return false // IP not in allowed list
	}

	return true // No IP restrictions or IP not blocked
}

// checkUserAgent checks if the User-Agent is allowed.
func (f *Filter) checkUserAgent(r *http.Request) bool {
	userAgent := r.Header.Get("User-Agent")

	// Check blocked User-Agents first (takes precedence)
	if f.blockedUAExact[userAgent] {
		return false
	}

	for _, regex := range f.blockedUARegex {
		if regex.MatchString(userAgent) {
			return false
		}
	}

	// If allowed User-Agents are specified, check if current UA matches
	if len(f.allowedUAExact) > 0 || len(f.allowedUARegex) > 0 {
		// Check exact matches first
		if f.allowedUAExact[userAgent] {
			return true
		}

		// Check regex patterns
		for _, regex := range f.allowedUARegex {
			if regex.MatchString(userAgent) {
				return true
			}
		}
		return false // User-Agent not in allowed list
	}

	return true // No User-Agent restrictions or not blocked
}

// checkHeaders checks if request headers are allowed.
func (f *Filter) checkHeaders(r *http.Request) bool {
	// Check blocked headers first
	for headerName, exactMap := range f.blockedHeaderExact {
		if values, exists := r.Header[http.CanonicalHeaderKey(headerName)]; exists {
			for _, value := range values {
				if exactMap[value] {
					return false
				}
			}
		}
	}

	for headerName, regexes := range f.blockedHeaderRegex {
		if values, exists := r.Header[http.CanonicalHeaderKey(headerName)]; exists {
			for _, value := range values {
				for _, regex := range regexes {
					if regex.MatchString(value) {
						return false
					}
				}
			}
		}
	}

	// Check allowed headers
	for headerName, exactMap := range f.allowedHeaderExact {
		if values, exists := r.Header[http.CanonicalHeaderKey(headerName)]; exists {
			hasMatch := false
			for _, value := range values {
				if exactMap[value] {
					hasMatch = true
					break
				}
			}
			if !hasMatch {
				return false // Header value not in allowed list
			}
		} else if len(exactMap) > 0 {
			return false // Required header missing
		}
	}

	for headerName, regexes := range f.allowedHeaderRegex {
		if values, exists := r.Header[http.CanonicalHeaderKey(headerName)]; exists {
			hasMatch := false
			for _, value := range values {
				for _, regex := range regexes {
					if regex.MatchString(value) {
						hasMatch = true
						break
					}
				}
				if hasMatch {
					break
				}
			}
			if !hasMatch {
				return false // Header value not in allowed list
			}
		} else if len(regexes) > 0 {
			return false // Required header missing
		}
	}

	return true
}

// checkQueryParams checks if query parameters are allowed.
func (f *Filter) checkQueryParams(r *http.Request) bool {
	queryParams := r.URL.Query()

	// Check blocked query parameters first
	for paramName, exactMap := range f.blockedQueryExact {
		if values, exists := queryParams[paramName]; exists {
			for _, value := range values {
				if exactMap[value] {
					return false
				}
			}
		}
	}

	for paramName, regexes := range f.blockedQueryRegex {
		if values, exists := queryParams[paramName]; exists {
			for _, value := range values {
				for _, regex := range regexes {
					if regex.MatchString(value) {
						return false
					}
				}
			}
		}
	}

	// Check allowed query parameters
	for paramName, exactMap := range f.allowedQueryExact {
		if values, exists := queryParams[paramName]; exists {
			hasMatch := false
			for _, value := range values {
				if exactMap[value] {
					hasMatch = true
					break
				}
			}
			if !hasMatch {
				return false // Parameter value not in allowed list
			}
		} else if len(exactMap) > 0 {
			return false // Required parameter missing
		}
	}

	for paramName, regexes := range f.allowedQueryRegex {
		if values, exists := queryParams[paramName]; exists {
			hasMatch := false
			for _, value := range values {
				for _, regex := range regexes {
					if regex.MatchString(value) {
						hasMatch = true
						break
					}
				}
				if hasMatch {
					break
				}
			}
			if !hasMatch {
				return false // Parameter value not in allowed list
			}
		} else if len(regexes) > 0 {
			return false // Required parameter missing
		}
	}

	return true
}

// blockRequest sends a blocked response.
func (f *Filter) blockRequest(w http.ResponseWriter, r *http.Request, reason string) {
	statusCode := f.config.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusForbidden
	}

	message := f.config.Message
	if message == "" {
		message = "Request blocked by security filter"
	}

	C(w, r).Error(fmt.Errorf("request blocked: %s", reason), statusCode, message)
}
