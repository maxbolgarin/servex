package servex


// WithFilterConfig sets the complete request filtering configuration at once.
// This allows fine-grained control over all filtering settings for IP addresses,
// User-Agents, headers, and query parameters.
//
// Example:
//
//	filterConfig := servex.FilterConfig{
//		AllowedIPs: []string{"10.0.0.0/8", "192.168.1.100"},
//		BlockedUserAgents: []string{"BadBot", "Scraper"},
//		AllowedHeaders: map[string][]string{
//			"X-API-Version": {"v1", "v2"},
//		},
//		StatusCode: 403,
//		Message: "Access denied by security filter",
//		ExcludePaths: []string{"/health", "/public/*"},
//	}
//
//	server := servex.New(servex.WithFilterConfig(filterConfig))
//
// Use this when you need to configure multiple filtering settings at once
// or when loading configuration from files or environment variables.
func WithFilterConfig(filter FilterConfig) Option {
	return func(op *Options) {
		op.Filter = filter
	}
}

// WithAllowedIPs restricts access to specific IP addresses or CIDR ranges.
// Only requests from these IPs will be allowed. All other IPs are blocked.
//
// Example:
//
//	// Allow specific office IPs
//	server := servex.New(servex.WithAllowedIPs(
//		"192.168.1.0/24",    // Office network
//		"203.0.113.100",     // VPN gateway
//		"10.0.0.0/8",        // Internal network
//	))
//
//	// Allow only localhost
//	server := servex.New(servex.WithAllowedIPs("127.0.0.1", "::1"))
//
// IP formats supported:
//   - Single IP: "192.168.1.100"
//   - CIDR range: "10.0.0.0/8", "192.168.1.0/24"
//   - IPv6: "2001:db8::1", "2001:db8::/32"
//
// Use cases:
//   - Restrict admin interfaces to office IPs
//   - Allow only partner/client IPs
//   - Internal-only APIs
//   - Development/staging environment protection
//
// If empty, all IPs are allowed unless blocked by WithBlockedIPs().
func WithAllowedIPs(ips ...string) Option {
	return func(op *Options) {
		op.Filter.AllowedIPs = append(op.Filter.AllowedIPs, ips...)
	}
}

// WithBlockedIPs blocks access from specific IP addresses or CIDR ranges.
// Requests from these IPs will be denied with a 403 Forbidden response.
//
// Example:
//
//	// Block known malicious IPs
//	server := servex.New(servex.WithBlockedIPs(
//		"203.0.113.0/24",    // Known spam network
//		"198.51.100.50",     // Specific malicious IP
//		"192.0.2.0/24",      // Blocked range
//	))
//
//	// Block competitors from scraping
//	server := servex.New(servex.WithBlockedIPs("competitor-ip-range"))
//
// IP formats supported:
//   - Single IP: "192.168.1.100"
//   - CIDR range: "10.0.0.0/8", "192.168.1.0/24"
//   - IPv6: "2001:db8::1", "2001:db8::/32"
//
// Use cases:
//   - Block known malicious IPs
//   - Prevent competitor scraping
//   - Geographic restrictions
//   - Temporary IP bans
//
// Note: BlockedIPs takes precedence over AllowedIPs.
// If an IP is in both lists, it will be blocked.
func WithBlockedIPs(ips ...string) Option {
	return func(op *Options) {
		op.Filter.BlockedIPs = append(op.Filter.BlockedIPs, ips...)
	}
}

// WithAllowedUserAgents restricts access to specific User-Agent strings.
// Only requests with these exact User-Agent headers will be allowed.
//
// Example:
//
//	// Allow only your mobile app
//	server := servex.New(servex.WithAllowedUserAgents(
//		"MyApp/1.0 (iOS)",
//		"MyApp/1.0 (Android)",
//	))
//
//	// Allow specific browsers
//	server := servex.New(servex.WithAllowedUserAgents(
//		"Mozilla/5.0 Chrome/120.0.0.0",
//		"Mozilla/5.0 Safari/537.36",
//	))
//
// For pattern matching instead of exact strings, use WithAllowedUserAgentsRegex().
//
// Use cases:
//   - Restrict API to your apps only
//   - Block automated scrapers
//   - Allow only supported browsers
//   - Partner API access control
//
// If empty, all User-Agents are allowed unless blocked by WithBlockedUserAgents().
func WithAllowedUserAgents(userAgents ...string) Option {
	return func(op *Options) {
		op.Filter.AllowedUserAgents = append(op.Filter.AllowedUserAgents, userAgents...)
	}
}

// WithAllowedUserAgentsRegex restricts access using User-Agent regex patterns.
// Only requests with User-Agent headers matching these patterns will be allowed.
//
// Example:
//
//	// Allow any Chrome browser
//	server := servex.New(servex.WithAllowedUserAgentsRegex(
//		`Chrome/\d+\.\d+`,
//	))
//
//	// Allow your app with any version
//	server := servex.New(servex.WithAllowedUserAgentsRegex(
//		`^MyApp/\d+\.\d+ \((iOS|Android)\)$`,
//	))
//
//	// Allow major browsers
//	server := servex.New(servex.WithAllowedUserAgentsRegex(
//		`(Chrome|Firefox|Safari|Edge)/\d+`,
//	))
//
// Regex features:
//   - Use standard Go regex syntax
//   - Case-sensitive matching
//   - ^ and $ for exact matching
//   - \d+ for version numbers
//   - | for alternatives
//
// This is more flexible than WithAllowedUserAgents() for version-aware filtering.
func WithAllowedUserAgentsRegex(patterns ...string) Option {
	return func(op *Options) {
		op.Filter.AllowedUserAgentsRegex = append(op.Filter.AllowedUserAgentsRegex, patterns...)
	}
}

// WithBlockedUserAgents blocks access from specific User-Agent strings.
// Requests with these exact User-Agent headers will be denied.
//
// Example:
//
//	// Block common bots
//	server := servex.New(servex.WithBlockedUserAgents(
//		"Googlebot",
//		"Bingbot",
//		"facebookexternalhit",
//		"Twitterbot",
//	))
//
//	// Block scrapers
//	server := servex.New(servex.WithBlockedUserAgents(
//		"curl/7.68.0",
//		"wget",
//		"python-requests",
//		"scrapy",
//	))
//
// For pattern matching instead of exact strings, use WithBlockedUserAgentsRegex().
//
// Use cases:
//   - Block automated scrapers
//   - Prevent bot traffic
//   - Block specific tools
//   - Temporary user-agent bans
//
// Note: BlockedUserAgents takes precedence over AllowedUserAgents.
func WithBlockedUserAgents(userAgents ...string) Option {
	return func(op *Options) {
		op.Filter.BlockedUserAgents = append(op.Filter.BlockedUserAgents, userAgents...)
	}
}

// WithBlockedUserAgentsRegex blocks access using User-Agent regex patterns.
// Requests with User-Agent headers matching these patterns will be denied.
//
// Example:
//
//	// Block all bots and crawlers
//	server := servex.New(servex.WithBlockedUserAgentsRegex(
//		`(?i)(bot|crawler|spider|scraper)`,
//	))
//
//	// Block command line tools
//	server := servex.New(servex.WithBlockedUserAgentsRegex(
//		`^(curl|wget|python-requests)`,
//	))
//
//	// Block old browser versions
//	server := servex.New(servex.WithBlockedUserAgentsRegex(
//		`MSIE [1-9]\.`,  // IE 9 and below
//	))
//
// Regex features:
//   - (?i) for case-insensitive matching
//   - Use standard Go regex syntax
//   - ^ and $ for exact matching
//   - | for alternatives
//
// Note: BlockedUserAgentsRegex takes precedence over AllowedUserAgentsRegex.
func WithBlockedUserAgentsRegex(patterns ...string) Option {
	return func(op *Options) {
		op.Filter.BlockedUserAgentsRegex = append(op.Filter.BlockedUserAgentsRegex, patterns...)
	}
}

// WithAllowedHeaders restricts requests based on header values.
// Only requests with headers matching the specified exact values will be allowed.
//
// Example:
//
//	// Require specific API version
//	server := servex.New(servex.WithAllowedHeaders(map[string][]string{
//		"X-API-Version": {"v1", "v2"},
//		"Content-Type":  {"application/json"},
//	}))
//
//	// Require authentication header
//	server := servex.New(servex.WithAllowedHeaders(map[string][]string{
//		"Authorization": {"Bearer token1", "Bearer token2"},
//	}))
//
// Header matching:
//   - Header names are case-insensitive
//   - Values must match exactly (case-sensitive)
//   - Multiple allowed values per header
//   - All specified headers must be present
//
// Use cases:
//   - API version enforcement
//   - Content-Type validation
//   - Custom authentication schemes
//   - Partner-specific headers
//
// For pattern matching instead of exact values, use WithAllowedHeadersRegex().
func WithAllowedHeaders(headers map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.AllowedHeaders == nil {
			op.Filter.AllowedHeaders = make(map[string][]string)
		}
		for k, v := range headers {
			op.Filter.AllowedHeaders[k] = append(op.Filter.AllowedHeaders[k], v...)
		}
	}
}

// WithAllowedHeadersRegex restricts requests based on header regex patterns.
// Only requests with headers matching the specified patterns will be allowed.
//
// Example:
//
//	// Allow any Bearer token
//	server := servex.New(servex.WithAllowedHeadersRegex(map[string][]string{
//		"Authorization": {`^Bearer [A-Za-z0-9+/=]+$`},
//	}))
//
//	// Allow semantic versioning
//	server := servex.New(servex.WithAllowedHeadersRegex(map[string][]string{
//		"X-API-Version": {`^v\d+\.\d+$`},  // v1.0, v2.1, etc.
//	}))
//
//	// Validate custom headers
//	server := servex.New(servex.WithAllowedHeadersRegex(map[string][]string{
//		"X-Request-ID": {`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`},
//	}))
//
// Regex features:
//   - Header names are case-insensitive
//   - Use standard Go regex syntax
//   - ^ and $ for exact matching
//   - Multiple patterns per header (OR logic)
//
// This is more flexible than WithAllowedHeaders() for pattern-based validation.
func WithAllowedHeadersRegex(headers map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.AllowedHeadersRegex == nil {
			op.Filter.AllowedHeadersRegex = make(map[string][]string)
		}
		for k, v := range headers {
			op.Filter.AllowedHeadersRegex[k] = append(op.Filter.AllowedHeadersRegex[k], v...)
		}
	}
}

// WithBlockedHeaders blocks requests based on header values.
// Requests with headers matching the specified exact values will be denied.
//
// Example:
//
//	// Block suspicious headers
//	server := servex.New(servex.WithBlockedHeaders(map[string][]string{
//		"X-Forwarded-For": {"malicious-proxy-ip"},
//		"User-Agent":      {"BadBot/1.0"},
//	}))
//
//	// Block old API versions
//	server := servex.New(servex.WithBlockedHeaders(map[string][]string{
//		"X-API-Version": {"v0.1", "v0.2"},
//	}))
//
// Header matching:
//   - Header names are case-insensitive
//   - Values must match exactly (case-sensitive)
//   - Multiple blocked values per header
//   - Any matching header causes blocking
//
// Use cases:
//   - Block deprecated API versions
//   - Security header filtering
//   - Malicious request detection
//   - Legacy client blocking
//
// Note: BlockedHeaders takes precedence over AllowedHeaders.
func WithBlockedHeaders(headers map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.BlockedHeaders == nil {
			op.Filter.BlockedHeaders = make(map[string][]string)
		}
		for k, v := range headers {
			op.Filter.BlockedHeaders[k] = append(op.Filter.BlockedHeaders[k], v...)
		}
	}
}

// WithBlockedHeadersRegex blocks requests based on header regex patterns.
// Requests with headers matching the specified patterns will be denied.
//
// Example:
//
//	// Block requests with suspicious X-Forwarded-For
//	server := servex.New(servex.WithBlockedHeadersRegex(map[string][]string{
//		"X-Forwarded-For": {`(10\.0\.0\.|192\.168\.)`},  // Block internal IPs
//	}))
//
//	// Block old user agents
//	server := servex.New(servex.WithBlockedHeadersRegex(map[string][]string{
//		"User-Agent": {`(?i)(bot|crawler|spider)`},
//	}))
//
// Regex features:
//   - Header names are case-insensitive
//   - (?i) for case-insensitive pattern matching
//   - Use standard Go regex syntax
//   - Multiple patterns per header (OR logic)
//
// Note: BlockedHeadersRegex takes precedence over AllowedHeadersRegex.
func WithBlockedHeadersRegex(headers map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.BlockedHeadersRegex == nil {
			op.Filter.BlockedHeadersRegex = make(map[string][]string)
		}
		for k, v := range headers {
			op.Filter.BlockedHeadersRegex[k] = append(op.Filter.BlockedHeadersRegex[k], v...)
		}
	}
}

// WithAllowedQueryParams restricts requests based on query parameter values.
// Only requests with query parameters matching the specified exact values will be allowed.
//
// Example:
//
//	// Require specific API version
//	server := servex.New(servex.WithAllowedQueryParams(map[string][]string{
//		"version": {"v1", "v2"},
//		"format":  {"json", "xml"},
//	}))
//
//	// Require valid sort parameters
//	server := servex.New(servex.WithAllowedQueryParams(map[string][]string{
//		"sort": {"name", "date", "price"},
//		"order": {"asc", "desc"},
//	}))
//
// Parameter matching:
//   - Parameter names are case-sensitive
//   - Values must match exactly (case-sensitive)
//   - Multiple allowed values per parameter
//   - All specified parameters must be present
//
// Use cases:
//   - API parameter validation
//   - Prevent SQL injection via query params
//   - Business logic validation
//   - Feature flag enforcement
//
// For pattern matching instead of exact values, use WithAllowedQueryParamsRegex().
func WithAllowedQueryParams(params map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.AllowedQueryParams == nil {
			op.Filter.AllowedQueryParams = make(map[string][]string)
		}
		for k, v := range params {
			op.Filter.AllowedQueryParams[k] = append(op.Filter.AllowedQueryParams[k], v...)
		}
	}
}

// WithAllowedQueryParamsRegex restricts requests based on query parameter regex patterns.
// Only requests with query parameters matching the specified patterns will be allowed.
//
// Example:
//
//	// Allow numeric IDs only
//	server := servex.New(servex.WithAllowedQueryParamsRegex(map[string][]string{
//		"id": {`^\d+$`},
//		"page": {`^[1-9]\d*$`},  // Positive integers only
//	}))
//
//	// Validate email format
//	server := servex.New(servex.WithAllowedQueryParamsRegex(map[string][]string{
//		"email": {`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`},
//	}))
//
//	// Allow UUID format
//	server := servex.New(servex.WithAllowedQueryParamsRegex(map[string][]string{
//		"uuid": {`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`},
//	}))
//
// Regex features:
//   - Parameter names are case-sensitive
//   - Use standard Go regex syntax
//   - ^ and $ for exact matching
//   - Multiple patterns per parameter (OR logic)
//
// This is more flexible than WithAllowedQueryParams() for format validation.
func WithAllowedQueryParamsRegex(params map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.AllowedQueryParamsRegex == nil {
			op.Filter.AllowedQueryParamsRegex = make(map[string][]string)
		}
		for k, v := range params {
			op.Filter.AllowedQueryParamsRegex[k] = append(op.Filter.AllowedQueryParamsRegex[k], v...)
		}
	}
}

// WithBlockedQueryParams blocks requests based on query parameter values.
// Requests with query parameters matching the specified exact values will be denied.
//
// Example:
//
//	// Block dangerous parameters
//	server := servex.New(servex.WithBlockedQueryParams(map[string][]string{
//		"debug": {"true", "1"},
//		"admin": {"true", "1"},
//	}))
//
//	// Block SQL injection attempts
//	server := servex.New(servex.WithBlockedQueryParams(map[string][]string{
//		"id": {"'; DROP TABLE users; --"},
//	}))
//
// Parameter matching:
//   - Parameter names are case-sensitive
//   - Values must match exactly (case-sensitive)
//   - Multiple blocked values per parameter
//   - Any matching parameter causes blocking
//
// Use cases:
//   - Security parameter filtering
//   - Debug mode blocking in production
//   - Malicious query detection
//   - Legacy parameter deprecation
//
// Note: BlockedQueryParams takes precedence over AllowedQueryParams.
func WithBlockedQueryParams(params map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.BlockedQueryParams == nil {
			op.Filter.BlockedQueryParams = make(map[string][]string)
		}
		for k, v := range params {
			op.Filter.BlockedQueryParams[k] = append(op.Filter.BlockedQueryParams[k], v...)
		}
	}
}

// WithBlockedQueryParamsRegex blocks requests based on query parameter regex patterns.
// Requests with query parameters matching the specified patterns will be denied.
//
// Example:
//
//	// Block SQL injection patterns
//	server := servex.New(servex.WithBlockedQueryParamsRegex(map[string][]string{
//		"search": {`(?i)(union|select|drop|delete|insert|update)`},
//	}))
//
//	// Block script injection
//	server := servex.New(servex.WithBlockedQueryParamsRegex(map[string][]string{
//		"callback": {`(?i)(<script|javascript:|vbscript:)`},
//	}))
//
//	// Block excessive length
//	server := servex.New(servex.WithBlockedQueryParamsRegex(map[string][]string{
//		"query": {`.{1000,}`},  // Block queries longer than 1000 chars
//	}))
//
// Regex features:
//   - Parameter names are case-sensitive
//   - (?i) for case-insensitive pattern matching
//   - Use standard Go regex syntax
//   - Multiple patterns per parameter (OR logic)
//
// Note: BlockedQueryParamsRegex takes precedence over AllowedQueryParamsRegex.
func WithBlockedQueryParamsRegex(params map[string][]string) Option {
	return func(op *Options) {
		if op.Filter.BlockedQueryParamsRegex == nil {
			op.Filter.BlockedQueryParamsRegex = make(map[string][]string)
		}
		for k, v := range params {
			op.Filter.BlockedQueryParamsRegex[k] = append(op.Filter.BlockedQueryParamsRegex[k], v...)
		}
	}
}

// WithFilterExcludePaths excludes specific paths from request filtering.
// Requests to these paths will bypass all filtering rules.
//
// Example:
//
//	// Exclude public endpoints from filtering
//	server := servex.New(
//		servex.WithAllowedIPs("192.168.1.0/24"),
//		servex.WithFilterExcludePaths("/health", "/public/*", "/docs/*"),
//	)
//
//	// Exclude monitoring from strict filtering
//	server := servex.New(
//		servex.WithBlockedUserAgents("curl"),
//		servex.WithFilterExcludePaths("/metrics", "/status", "/ping"),
//	)
//
// Common exclusions:
//   - Health checks: "/health", "/ping"
//   - Public APIs: "/public/*", "/api/public/*"
//   - Documentation: "/docs/*", "/swagger/*"
//   - Static assets: "/static/*", "/assets/*"
//   - Monitoring: "/metrics", "/status"
//
// Path matching supports wildcards (*) for pattern matching.
// Excluded paths bypass ALL filtering rules (IP, User-Agent, headers, query params).
func WithFilterExcludePaths(paths ...string) Option {
	return func(op *Options) {
		op.Filter.ExcludePaths = append(op.Filter.ExcludePaths, paths...)
	}
}

// WithFilterIncludePaths specifies which paths should be filtered.
// If set, only requests to these paths will be subject to filtering rules.
//
// Example:
//
//	// Only filter admin endpoints
//	server := servex.New(
//		servex.WithAllowedIPs("192.168.1.0/24"),
//		servex.WithFilterIncludePaths("/admin/*", "/api/admin/*"),
//	)
//
//	// Filter only sensitive API endpoints
//	server := servex.New(
//		servex.WithBlockedUserAgents("curl", "wget"),
//		servex.WithFilterIncludePaths("/api/sensitive/*", "/api/payment/*"),
//	)
//
// If both IncludePaths and ExcludePaths are set:
//  1. Paths must match IncludePaths to be filtered
//  2. Paths in ExcludePaths are then excluded from filtering
//
// Use cases:
//   - Protect only sensitive endpoints
//   - Apply filtering to specific API versions
//   - Filter only external-facing endpoints
//   - Granular security control
//
// Path matching supports wildcards (*) for pattern matching.
func WithFilterIncludePaths(paths ...string) Option {
	return func(op *Options) {
		op.Filter.IncludePaths = append(op.Filter.IncludePaths, paths...)
	}
}

// WithFilterStatusCode sets the HTTP status code returned when requests are blocked by filters.
// Default is 403 (Forbidden) if not set.
//
// Example:
//
//	// Use standard 403 Forbidden
//	server := servex.New(
//		servex.WithAllowedIPs("192.168.1.0/24"),
//		servex.WithFilterStatusCode(403),
//	)
//
//	// Use 404 to hide the existence of endpoints
//	server := servex.New(
//		servex.WithBlockedUserAgents("BadBot"),
//		servex.WithFilterStatusCode(404),
//	)
//
//	// Use 429 to indicate rate limiting (misleading but sometimes useful)
//	server := servex.New(
//		servex.WithBlockedIPs("malicious-range"),
//		servex.WithFilterStatusCode(429),
//	)
//
// Common status codes:
//   - 403 Forbidden (recommended) - Clear about blocking
//   - 404 Not Found - Hides endpoint existence
//   - 401 Unauthorized - Suggests authentication needed
//   - 429 Too Many Requests - Can mislead attackers
//
// Choose based on your security strategy and user experience needs.
func WithFilterStatusCode(statusCode int) Option {
	return func(op *Options) {
		op.Filter.StatusCode = statusCode
	}
}

// WithFilterMessage sets the response message when requests are blocked by filters.
// Default is "Request blocked by security filter" if not set.
//
// Example:
//
//	// Generic security message
//	server := servex.New(
//		servex.WithAllowedIPs("192.168.1.0/24"),
//		servex.WithFilterMessage("Access denied for security reasons"),
//	)
//
//	// Specific filter message
//	server := servex.New(
//		servex.WithBlockedUserAgents("BadBot"),
//		servex.WithFilterMessage("Your user agent is not allowed"),
//	)
//
//	// Helpful message with contact info
//	server := servex.New(
//		servex.WithAllowedHeaders(map[string][]string{"X-API-Key": {"validkey"}}),
//		servex.WithFilterMessage("Missing or invalid API key. Contact support@example.com for access."),
//	)
//
// Best practices:
//   - Be clear but not too specific about the filter
//   - Include contact information for legitimate users
//   - Avoid revealing security implementation details
//   - Keep messages user-friendly
//
// The message is returned as plain text in the response body.
func WithFilterMessage(message string) Option {
	return func(op *Options) {
		op.Filter.Message = message
	}
}

// WithFilterTrustedProxies sets trusted proxy IP addresses or CIDR ranges
// for accurate client IP detection in filtering.
//
// Example:
//
//	// Trust load balancer IPs for filtering
//	server := servex.New(
//		servex.WithAllowedIPs("192.168.1.0/24"),
//		servex.WithFilterTrustedProxies("10.0.0.0/8", "172.16.0.0/12"),
//	)
//
//	// Trust specific proxy servers
//	server := servex.New(
//		servex.WithBlockedIPs("malicious-range"),
//		servex.WithFilterTrustedProxies("192.168.1.100", "192.168.1.101"),
//	)
//
// How it works:
//   - Without trusted proxies: Uses r.RemoteAddr (proxy IP) for IP filtering
//   - With trusted proxies: Uses X-Forwarded-For or X-Real-IP headers
//
// Common proxy ranges:
//   - AWS ALB: Check AWS documentation for current ranges
//   - Cloudflare: Use Cloudflare's published IP ranges
//   - Internal load balancers: Your internal network ranges
//   - Docker networks: 172.16.0.0/12, 10.0.0.0/8
//
// Security considerations:
//   - Only list IPs you actually trust
//   - Malicious clients can spoof X-Forwarded-For headers
//   - Ensure proxy properly validates and forwards real client IPs
//   - Consider using separate trusted proxy lists for different purposes
func WithFilterTrustedProxies(proxies ...string) Option {
	return func(op *Options) {
		op.Filter.TrustedProxies = append(op.Filter.TrustedProxies, proxies...)
	}
}
