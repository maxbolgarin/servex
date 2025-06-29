package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/maxbolgarin/servex"
)

func main() {
	// Example 1: Basic IP filtering
	basicIPFiltering()

	// Example 2: User-Agent filtering for bot protection
	userAgentFiltering()

	// Example 3: Header-based API key authentication
	headerBasedAuth()

	// Example 4: Comprehensive security filtering
	comprehensiveSecurity()

	// Example 5: Production security filtering
	productionExample()
}

func basicIPFiltering() {
	fmt.Println("=== Basic IP Filtering Example ===")

	server := servex.New(
		// Only allow requests from specific IP ranges
		servex.WithAllowedIPs("192.168.1.0/24", "10.0.0.0/8"),

		// Block specific problematic IPs
		servex.WithBlockedIPs("203.0.113.1", "198.51.100.0/24"),

		// Trust proxy headers for real IP detection
		servex.WithFilterTrustedProxies("172.16.0.0/12"),

		// Custom response for blocked requests
		servex.WithFilterStatusCode(403),
		servex.WithFilterMessage("Access denied: IP not allowed"),
	)

	server.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Access granted to IP: %s", r.RemoteAddr)
	})

	fmt.Println("Server with IP filtering configured")
}

func userAgentFiltering() {
	fmt.Println("\n=== User-Agent Filtering Example ===")

	server := servex.New(
		// Block common bots and scrapers
		servex.WithBlockedUserAgents("BadTool/1.0"), // Specific bad tool
		servex.WithBlockedUserAgentsRegex(
			".*[Bb]ot.*",     // Any bot
			".*[Ss]craper.*", // Any scraper
			".*[Cc]rawler.*", // Any crawler
		),

		// Only allow modern browsers (optional - can be used without blocked list)
		servex.WithAllowedUserAgentsRegex(
			"Mozilla.*Chrome.*",
			"Mozilla.*Firefox.*",
			"Mozilla.*Safari.*",
			"Mozilla.*Edge.*",
		),

		// Exclude health check from filtering
		servex.WithFilterExcludePaths("/health", "/status"),
	)

	server.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")
		fmt.Fprintf(w, "Access granted to User-Agent: %s", userAgent)
	})

	server.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK") // This endpoint bypasses User-Agent filtering
	})

	fmt.Println("Server with User-Agent filtering configured")
}

func headerBasedAuth() {
	fmt.Println("\n=== Header-Based Authentication Example ===")

	server := servex.New(
		// Require specific API key in header
		servex.WithAllowedHeadersRegex(map[string][]string{
			"X-API-Key":        {"^api-key-[0-9a-f]{32}$"},      // Require specific API key format
			"X-Client-Version": {"^v[0-9]+\\.[0-9]+\\.[0-9]+$"}, // Require version header
		}),

		// Block requests with dangerous headers
		servex.WithBlockedHeaders(map[string][]string{
			"X-Debug": {"true", "1"}, // Block debug headers
		}),
		servex.WithBlockedHeadersRegex(map[string][]string{
			"X-Admin": {".*"}, // Block any admin header
		}),

		// Only apply to API endpoints
		servex.WithFilterIncludePaths("/api/v1/secure", "/api/v1/admin"),
	)

	server.HandleFunc("/api/v1/secure", func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		version := r.Header.Get("X-Client-Version")
		fmt.Fprintf(w, "Secure access granted with API key: %s, version: %s", apiKey, version)
	})

	server.HandleFunc("/api/v1/public", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Public endpoint - no header filtering")
	})

	fmt.Println("Server with header-based authentication configured")
}

func comprehensiveSecurity() {
	fmt.Println("\n=== Comprehensive Security Example ===")

	// Create server with multiple security layers
	server := servex.New(
		// Rate limiting
		servex.WithRPS(10), // 10 requests per second

		// IP filtering
		servex.WithAllowedIPs("0.0.0.0/0"), // Allow all IPs (but could be restricted)
		servex.WithBlockedIPs(
			"203.0.113.0/24", // Block example malicious range
			"198.51.100.1",   // Block specific IP
		),

		// User-Agent filtering
		servex.WithBlockedUserAgentsRegex(
			".*[Bb]ot.*",
			".*[Ss]craper.*",
			"curl.*", // Block curl (often used for automation)
		),

		// Header security
		servex.WithBlockedHeadersRegex(map[string][]string{
			"X-Forwarded-For": {".*script.*"},  // Block potential XSS in headers
			"User-Agent":      {".*<script.*"}, // Block XSS attempts in UA
		}),

		// Query parameter security
		servex.WithBlockedQueryParams(map[string][]string{
			"debug": {"true", "1", "on"},
		}),
		servex.WithBlockedQueryParamsRegex(map[string][]string{
			"admin":    {".*"},                   // Block any admin parameter
			"redirect": {"https?://[^/]*[^.].*"}, // Block potential open redirects
		}),

		// Path configuration
		servex.WithFilterExcludePaths("/health", "/metrics", "/favicon.ico"),

		// Custom error response
		servex.WithFilterStatusCode(403),
		servex.WithFilterMessage("Request blocked by security policy"),

		// Proxy configuration for real IP detection
		servex.WithFilterTrustedProxies("172.16.0.0/12", "10.0.0.0/8"),
	)

	// Add routes
	server.HandleFunc("/api/users", handleUsers)
	server.HandleFunc("/api/admin", handleAdmin)
	server.HandleFunc("/health", handleHealth)

	fmt.Println("Server with comprehensive security filtering configured")

	// Example of starting the server
	fmt.Println("Starting server on :8080...")

	// In a real application, you would use StartWithShutdown
	// ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	// defer cancel()
	// err := server.StartWithShutdown(ctx, ":8080", "")
	// if err != nil {
	//     log.Fatal(err)
	// }
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Users API - secure endpoint")
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Admin API - highly secure endpoint")
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Service is healthy") // This bypasses all filtering
}

// Example configuration struct for production use
type SecurityConfig struct {
	AllowedIPs           []string
	BlockedIPs           []string
	TrustedProxies       []string
	BlockedBots          []string
	BlockedBotsRegex     []string
	RequiredHeaders      map[string][]string
	RequiredHeadersRegex map[string][]string
}

func productionExample() {
	config := SecurityConfig{
		AllowedIPs: []string{
			"192.168.0.0/16", // Internal network
			"10.0.0.0/8",     // Private network
		},
		BlockedIPs: []string{
			"203.0.113.0/24", // Known malicious range
		},
		TrustedProxies: []string{
			"172.16.0.0/12", // Load balancer range
		},
		BlockedBots: []string{
			"SomeSpecificBot/1.0",
		},
		BlockedBotsRegex: []string{
			".*[Bb]ot.*",
			".*[Ss]craper.*",
			".*[Cc]rawler.*",
		},
		RequiredHeaders: map[string][]string{
			"X-API-Key": {"some-exact-key"},
		},
		RequiredHeadersRegex: map[string][]string{
			"X-API-Key": {"^[a-zA-Z0-9]{32}$"},
		},
	}

	server := createSecureServer(config)

	// Add your application routes
	server.HandleFunc("/api/v1/data", func(w http.ResponseWriter, r *http.Request) {
		// Your application logic here
		fmt.Fprintf(w, "Secure data access")
	})

	// Start server
	log.Fatal(server.Start(":8080", ""))
}

func createSecureServer(config SecurityConfig) *servex.Server {
	options := []servex.Option{
		// Apply IP filtering if configured
		servex.WithAllowedIPs(config.AllowedIPs...),
		servex.WithBlockedIPs(config.BlockedIPs...),
		servex.WithFilterTrustedProxies(config.TrustedProxies...),

		// Apply bot filtering
		servex.WithBlockedUserAgents(config.BlockedBots...),
		servex.WithBlockedUserAgentsRegex(config.BlockedBotsRegex...),

		// Apply header requirements
		servex.WithAllowedHeaders(config.RequiredHeaders),
		servex.WithAllowedHeadersRegex(config.RequiredHeadersRegex),

		// Standard security settings
		servex.WithFilterExcludePaths("/health", "/metrics"),
		servex.WithFilterStatusCode(403),
		servex.WithFilterMessage("Request blocked by security policy"),

		// Rate limiting
		servex.WithRPS(100),
	}

	return servex.New(options...)
}
