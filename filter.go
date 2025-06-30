package servex

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// LocationFilterConfig defines a filter configuration for specific locations.
// This allows different filter rules to be applied to different URL paths.
type LocationFilterConfig struct {
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

	// Config is the filter configuration to apply for matching paths.
	// This contains all the filtering settings like allowed/blocked IPs,
	// user agents, headers, query parameters, etc.
	Config FilterConfig
}

// Filter holds the compiled filtering logic and patterns.
// This struct is responsible for all filtering logic.
type Filter struct {
	// mu protects all fields in this struct for concurrent access
	mu sync.RWMutex

	config          FilterConfig
	locationConfigs []LocationFilterConfig

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

	// Location-based compiled filters (map from config index to compiled filter)
	locationFilters map[int]*Filter
}

// DynamicFilterMethods provides methods to modify filter rules at runtime.
// These methods are thread-safe and allow dynamic adaptation of filtering rules.
type DynamicFilterMethods interface {
	// IP Management
	AddBlockedIP(ip string) error
	RemoveBlockedIP(ip string) error
	AddAllowedIP(ip string) error
	RemoveAllowedIP(ip string) error
	IsIPBlocked(ip string) bool
	GetBlockedIPs() []string
	GetAllowedIPs() []string

	// User-Agent Management
	AddBlockedUserAgent(userAgent string) error
	RemoveBlockedUserAgent(userAgent string) error
	AddAllowedUserAgent(userAgent string) error
	RemoveAllowedUserAgent(userAgent string) error
	IsUserAgentBlocked(userAgent string) bool
	GetBlockedUserAgents() []string
	GetAllowedUserAgents() []string

	// Clear all rules
	ClearAllBlockedIPs() error
	ClearAllAllowedIPs() error
	ClearAllBlockedUserAgents() error
	ClearAllAllowedUserAgents() error
}

// RegisterFilterMiddleware adds request filtering middleware to the router.
// If the config has no filters configured, no middleware will be registered.
// Returns the created filter instance for dynamic modification, or nil if no filter was created.
func RegisterFilterMiddleware(router MiddlewareRouter, cfg FilterConfig) (*Filter, error) {
	if !cfg.isEnabled() {
		return nil, nil
	}

	filter, err := newFilter(cfg)
	if err != nil {
		return nil, err
	}

	router.Use(filter.middleware)

	return filter, nil
}

// RegisterLocationBasedFilterMiddleware adds location-based filtering middleware to the router.
// This allows different filter configurations for different URL paths.
// If no location configs are provided or none are enabled, no middleware will be registered.
//
// The middleware will:
// 1. Check each location config in order for path pattern matches
// 2. Use the first matching config's filter rules
// 3. Fall back to no filtering if no patterns match
//
// Example usage:
//
//	err := RegisterLocationBasedFilterMiddleware(router, []LocationFilterConfig{
//	  {
//	    PathPatterns: []string{"/api/*"},
//	    Config: FilterConfig{
//	      AllowedIPs: []string{"192.168.1.0/24"},
//	      StatusCode: http.StatusForbidden,
//	      Message:    "API access restricted",
//	    },
//	  },
//	  {
//	    PathPatterns: []string{"/admin/*"},
//	    Config: FilterConfig{
//	      AllowedIPs: []string{"10.0.0.0/8"},
//	      BlockedUserAgents: []string{"Bot", "Crawler"},
//	      StatusCode: http.StatusForbidden,
//	      Message:    "Admin access denied",
//	    },
//	  },
//	})
func RegisterLocationBasedFilterMiddleware(router MiddlewareRouter, locationConfigs []LocationFilterConfig) (*Filter, error) {
	if len(locationConfigs) == 0 {
		return nil, nil
	}

	// Validate and prepare configs
	var validConfigs []LocationFilterConfig
	for _, locCfg := range locationConfigs {
		if !locCfg.Config.isEnabled() || len(locCfg.PathPatterns) == 0 {
			continue
		}

		// Set defaults for this config
		if locCfg.Config.StatusCode == 0 {
			locCfg.Config.StatusCode = http.StatusForbidden
		}
		if locCfg.Config.Message == "" {
			locCfg.Config.Message = "Access denied by filter"
		}

		validConfigs = append(validConfigs, locCfg)
	}

	if len(validConfigs) == 0 {
		return nil, errors.New("no valid location configs")
	}

	filter, err := newLocationBasedFilter(validConfigs)
	if err != nil {
		return nil, err
	}

	router.Use(filter.middleware)

	return filter, nil
}

// newLocationBasedFilter creates a new Filter for location-based filtering.
func newLocationBasedFilter(locationConfigs []LocationFilterConfig) (*Filter, error) {
	filter := &Filter{
		locationConfigs: locationConfigs,
		locationFilters: make(map[int]*Filter),
	}

	// Compile each location-specific filter
	for i, locCfg := range locationConfigs {
		locFilter, err := newFilter(locCfg.Config)
		if err != nil {
			return nil, fmt.Errorf("compile filter for location config %d: %w", i, err)
		}
		filter.locationFilters[i] = locFilter
	}

	return filter, nil
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
		// Get the appropriate filter for this request
		filter := f.getFilterForPath(r.URL.Path)
		if filter == nil {
			// No filter config applies to this path
			next.ServeHTTP(w, r)
			return
		}

		// Check if the path should be filtered according to the filter config
		if !filter.shouldFilter(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Check IP filtering
		if !filter.checkIP(r) {
			filter.blockRequest(w, r, "IP address blocked")
			return
		}

		// Check User-Agent filtering
		if !filter.checkUserAgent(r) {
			filter.blockRequest(w, r, "User-Agent blocked")
			return
		}

		// Check header filtering
		if !filter.checkHeaders(r) {
			filter.blockRequest(w, r, "Request headers blocked")
			return
		}

		// Check query parameter filtering
		if !filter.checkQueryParams(r) {
			filter.blockRequest(w, r, "Query parameters blocked")
			return
		}

		// All checks passed, allow the request
		next.ServeHTTP(w, r)
	})
}

// getFilterForPath returns the filter that applies to the given path.
// Returns nil if no filter matches the path.
func (f *Filter) getFilterForPath(path string) *Filter {
	// If using single config mode (backward compatibility)
	if len(f.locationConfigs) == 0 {
		return f
	}

	// Check location-based configs in order
	for i, locCfg := range f.locationConfigs {
		for _, pattern := range locCfg.PathPatterns {
			if matchPath(path, []string{}, []string{pattern}, true) {
				return f.locationFilters[i]
			}
		}
	}

	// No config matches this path
	return nil
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
	f.mu.RLock()
	defer f.mu.RUnlock()

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
	f.mu.RLock()
	defer f.mu.RUnlock()

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
	f.mu.RLock()
	defer f.mu.RUnlock()
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
	f.mu.RLock()
	defer f.mu.RUnlock()

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

// =============================================================================
// Dynamic Filter Methods - Runtime Filter Modification
// =============================================================================

// AddBlockedIP dynamically adds an IP address or CIDR range to the blocked list.
// This method is thread-safe and takes effect immediately.
//
// Example:
//
//	// Block a specific IP that accessed a honeypot
//	err := filter.AddBlockedIP("192.168.1.100")
//
//	// Block an entire subnet
//	err := filter.AddBlockedIP("10.0.0.0/24")
func (f *Filter) AddBlockedIP(ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Add to config for persistence
	f.config.BlockedIPs = append(f.config.BlockedIPs, ip)

	// Recompile blocked IP networks
	nets, err := f.compileIPNets(f.config.BlockedIPs)
	if err != nil {
		// Remove from config if compilation failed
		f.config.BlockedIPs = f.config.BlockedIPs[:len(f.config.BlockedIPs)-1]
		return fmt.Errorf("add blocked IP %s: %w", ip, err)
	}

	f.blockedIPNets = nets
	return nil
}

// RemoveBlockedIP dynamically removes an IP address or CIDR range from the blocked list.
// This method is thread-safe and takes effect immediately.
func (f *Filter) RemoveBlockedIP(ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Remove from config
	for i, blockedIP := range f.config.BlockedIPs {
		if blockedIP == ip {
			f.config.BlockedIPs = append(f.config.BlockedIPs[:i], f.config.BlockedIPs[i+1:]...)
			break
		}
	}

	// Recompile blocked IP networks
	nets, err := f.compileIPNets(f.config.BlockedIPs)
	if err != nil {
		return fmt.Errorf("recompile blocked IPs after removing %s: %w", ip, err)
	}

	f.blockedIPNets = nets
	return nil
}

// AddAllowedIP dynamically adds an IP address or CIDR range to the allowed list.
// This method is thread-safe and takes effect immediately.
func (f *Filter) AddAllowedIP(ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Add to config for persistence
	f.config.AllowedIPs = append(f.config.AllowedIPs, ip)

	// Recompile allowed IP networks
	nets, err := f.compileIPNets(f.config.AllowedIPs)
	if err != nil {
		// Remove from config if compilation failed
		f.config.AllowedIPs = f.config.AllowedIPs[:len(f.config.AllowedIPs)-1]
		return fmt.Errorf("add allowed IP %s: %w", ip, err)
	}

	f.allowedIPNets = nets
	return nil
}

// RemoveAllowedIP dynamically removes an IP address or CIDR range from the allowed list.
// This method is thread-safe and takes effect immediately.
func (f *Filter) RemoveAllowedIP(ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Remove from config
	for i, allowedIP := range f.config.AllowedIPs {
		if allowedIP == ip {
			f.config.AllowedIPs = append(f.config.AllowedIPs[:i], f.config.AllowedIPs[i+1:]...)
			break
		}
	}

	// Recompile allowed IP networks
	nets, err := f.compileIPNets(f.config.AllowedIPs)
	if err != nil {
		return fmt.Errorf("recompile allowed IPs after removing %s: %w", ip, err)
	}

	f.allowedIPNets = nets
	return nil
}

// IsIPBlocked checks if an IP address is currently blocked.
// This method is thread-safe.
func (f *Filter) IsIPBlocked(ip string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false // Invalid IP
	}

	// Check blocked IPs
	for _, blockedNet := range f.blockedIPNets {
		if blockedNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// GetBlockedIPs returns a copy of the current blocked IP list.
// This method is thread-safe.
func (f *Filter) GetBlockedIPs() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Return a copy to prevent external modification
	blocked := make([]string, len(f.config.BlockedIPs))
	copy(blocked, f.config.BlockedIPs)
	return blocked
}

// GetAllowedIPs returns a copy of the current allowed IP list.
// This method is thread-safe.
func (f *Filter) GetAllowedIPs() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Return a copy to prevent external modification
	allowed := make([]string, len(f.config.AllowedIPs))
	copy(allowed, f.config.AllowedIPs)
	return allowed
}

// AddBlockedUserAgent dynamically adds a User-Agent string to the blocked list.
// This method is thread-safe and takes effect immediately.
//
// Example:
//
//	// Block a specific bot after it accessed a honeypot
//	err := filter.AddBlockedUserAgent("BadBot/1.0")
func (f *Filter) AddBlockedUserAgent(userAgent string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Add to config for persistence
	f.config.BlockedUserAgents = append(f.config.BlockedUserAgents, userAgent)

	// Recompile exact patterns
	f.blockedUAExact = f.compileExactPatterns(f.config.BlockedUserAgents)
	return nil
}

// RemoveBlockedUserAgent dynamically removes a User-Agent string from the blocked list.
// This method is thread-safe and takes effect immediately.
func (f *Filter) RemoveBlockedUserAgent(userAgent string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Remove from config
	for i, blockedUA := range f.config.BlockedUserAgents {
		if blockedUA == userAgent {
			f.config.BlockedUserAgents = append(f.config.BlockedUserAgents[:i], f.config.BlockedUserAgents[i+1:]...)
			break
		}
	}

	// Recompile exact patterns
	f.blockedUAExact = f.compileExactPatterns(f.config.BlockedUserAgents)
	return nil
}

// AddAllowedUserAgent dynamically adds a User-Agent string to the allowed list.
// This method is thread-safe and takes effect immediately.
func (f *Filter) AddAllowedUserAgent(userAgent string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Add to config for persistence
	f.config.AllowedUserAgents = append(f.config.AllowedUserAgents, userAgent)

	// Recompile exact patterns
	f.allowedUAExact = f.compileExactPatterns(f.config.AllowedUserAgents)
	return nil
}

// RemoveAllowedUserAgent dynamically removes a User-Agent string from the allowed list.
// This method is thread-safe and takes effect immediately.
func (f *Filter) RemoveAllowedUserAgent(userAgent string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Remove from config
	for i, allowedUA := range f.config.AllowedUserAgents {
		if allowedUA == userAgent {
			f.config.AllowedUserAgents = append(f.config.AllowedUserAgents[:i], f.config.AllowedUserAgents[i+1:]...)
			break
		}
	}

	// Recompile exact patterns
	f.allowedUAExact = f.compileExactPatterns(f.config.AllowedUserAgents)
	return nil
}

// IsUserAgentBlocked checks if a User-Agent string is currently blocked.
// This method is thread-safe.
func (f *Filter) IsUserAgentBlocked(userAgent string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Check exact matches
	if f.blockedUAExact[userAgent] {
		return true
	}

	// Check regex patterns
	for _, regex := range f.blockedUARegex {
		if regex.MatchString(userAgent) {
			return true
		}
	}

	return false
}

// GetBlockedUserAgents returns a copy of the current blocked User-Agent list.
// This method is thread-safe.
func (f *Filter) GetBlockedUserAgents() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Return a copy to prevent external modification
	blocked := make([]string, len(f.config.BlockedUserAgents))
	copy(blocked, f.config.BlockedUserAgents)
	return blocked
}

// GetAllowedUserAgents returns a copy of the current allowed User-Agent list.
// This method is thread-safe.
func (f *Filter) GetAllowedUserAgents() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Return a copy to prevent external modification
	allowed := make([]string, len(f.config.AllowedUserAgents))
	copy(allowed, f.config.AllowedUserAgents)
	return allowed
}

// ClearAllBlockedIPs removes all blocked IP addresses.
// This method is thread-safe and takes effect immediately.
func (f *Filter) ClearAllBlockedIPs() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.config.BlockedIPs = nil
	f.blockedIPNets = nil
	return nil
}

// ClearAllAllowedIPs removes all allowed IP addresses.
// This method is thread-safe and takes effect immediately.
func (f *Filter) ClearAllAllowedIPs() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.config.AllowedIPs = nil
	f.allowedIPNets = nil
	return nil
}

// ClearAllBlockedUserAgents removes all blocked User-Agent strings.
// This method is thread-safe and takes effect immediately.
func (f *Filter) ClearAllBlockedUserAgents() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.config.BlockedUserAgents = nil
	f.blockedUAExact = make(map[string]bool)
	return nil
}

// ClearAllAllowedUserAgents removes all allowed User-Agent strings.
// This method is thread-safe and takes effect immediately.
func (f *Filter) ClearAllAllowedUserAgents() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.config.AllowedUserAgents = nil
	f.allowedUAExact = make(map[string]bool)
	return nil
}
