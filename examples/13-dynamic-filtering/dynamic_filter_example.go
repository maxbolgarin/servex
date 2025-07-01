package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex"
)

func dynamicTest() {
	// Example 1: Basic honeypot with dynamic IP blocking
	honeypotExample()

	// Example 2: Advanced security with dynamic blocking
	advancedSecurityExample()

	// Example 3: Temporary blocking with auto-removal
	temporaryBlockingExample()
}

func honeypotExample() {
	fmt.Println("=== Honeypot Example ===")

	// Create server with basic filtering
	server, err := servex.NewServer(
		// Start with some basic blocked IPs
		servex.WithBlockedIPs("10.0.0.1", "192.168.1.1"),

		// Custom error message
		servex.WithFilterStatusCode(404), // Hide endpoint existence
		servex.WithFilterMessage("Not found"),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Get filter instance for dynamic modification
	filter := server.Filter()
	if filter == nil {
		log.Fatal("Filter is not available")
	}

	// Set up honeypot endpoint
	server.HandleFunc("/admin/backup.sql", func(w http.ResponseWriter, r *http.Request) {
		// This is a honeypot - anyone accessing this should be blocked
		clientIP := servex.C(w, r).ClientIP()

		// Dynamically block the IP
		if err := filter.AddBlockedIP(clientIP); err != nil {
			log.Printf("Failed to block IP %s: %v", clientIP, err)
		} else {
			log.Printf("🚨 HONEYPOT: Blocked suspicious IP %s that accessed %s", clientIP, r.URL.Path)
		}

		// Log additional details about the attacker
		log.Printf("🔍 Attack details - IP: %s, User-Agent: %s, Referer: %s",
			clientIP,
			r.Header.Get("User-Agent"),
			r.Header.Get("Referer"),
		)

		// Return fake content to keep attacker engaged
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("-- Fake database dump\nSELECT * FROM users;"))
	})

	// Set up another honeypot for suspicious bots
	server.HandleFunc("/wp-admin/admin-ajax.php", func(w http.ResponseWriter, r *http.Request) {
		clientIP := servex.C(w, r).ClientIP()
		userAgent := r.Header.Get("User-Agent")

		// Block both IP and User-Agent
		filter.AddBlockedIP(clientIP)
		filter.AddBlockedUserAgent(userAgent)

		log.Printf("🚨 WordPress attack detected from IP %s with User-Agent: %s", clientIP, userAgent)

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not found"))
	})

	// Legitimate endpoint
	server.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]string{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	// Status endpoint to view blocked IPs
	server.HandleFunc("/admin/security/blocked", func(w http.ResponseWriter, r *http.Request) {
		blockedIPs := filter.GetBlockedIPs()
		blockedUAs := filter.GetBlockedUserAgents()

		response := map[string]interface{}{
			"blocked_ips":         blockedIPs,
			"blocked_user_agents": blockedUAs,
			"total_blocked_ips":   len(blockedIPs),
			"total_blocked_uas":   len(blockedUAs),
		}

		servex.C(w, r).JSON(response)
	})

	fmt.Println("Honeypot server configured with dynamic blocking")
	fmt.Println("Try accessing /admin/backup.sql to trigger honeypot")
	fmt.Println("Check blocked IPs at /admin/security/blocked")
}

func advancedSecurityExample() {
	fmt.Println("\n=== Advanced Security Example ===")

	// Create server with comprehensive security
	server, err := servex.NewServer(
		// Rate limiting
		servex.WithRPS(100),

		// Initial IP filtering
		servex.WithBlockedIPs("203.0.113.0/24"), // Known bad network

		// User-Agent filtering for known bots
		servex.WithBlockedUserAgents("BadBot/1.0", "Scraper/2.0"),
		servex.WithBlockedUserAgentsRegex(".*[Bb]ot.*", ".*[Ss]craper.*"),

		// Custom error response
		servex.WithFilterStatusCode(403),
		servex.WithFilterMessage("Access denied by security policy"),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	filter := server.Filter()

	// Security monitoring middleware
	server.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Monitor for suspicious patterns
			userAgent := r.Header.Get("User-Agent")
			clientIP := servex.C(w, r).ClientIP()

			// Block empty User-Agents (often automated tools)
			if userAgent == "" {
				filter.AddBlockedIP(clientIP)
				log.Printf("🚨 Blocked IP %s for empty User-Agent", clientIP)
				w.WriteHeader(http.StatusForbidden)
				return
			}

			// Block IPs making too many requests to non-existent paths
			if r.URL.Path == "/favicon.ico" || r.URL.Path == "/robots.txt" {
				// These are normal, skip monitoring
			} else if !isValidEndpoint(r.URL.Path) {
				// Check if this IP has made multiple invalid requests
				// (In a real application, you'd track this in a database or cache)
				filter.AddBlockedIP(clientIP)
				log.Printf("🚨 Blocked IP %s for accessing invalid path: %s", clientIP, r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
				return
			}

			next.ServeHTTP(w, r)
		})
	})

	// API endpoints
	server.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]string{"message": "Users API"})
	})

	server.HandleFunc("/api/products", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]string{"message": "Products API"})
	})

	// Admin endpoint to manually block/unblock IPs
	server.HandleFunc("/admin/security/block", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		ip := r.FormValue("ip")
		if ip == "" {
			servex.C(w, r).Error(fmt.Errorf("IP is required"), 400, "Missing IP parameter")
			return
		}

		if err := filter.AddBlockedIP(ip); err != nil {
			servex.C(w, r).Error(err, 500, "Failed to block IP")
			return
		}

		log.Printf("✅ Manually blocked IP: %s", ip)
		servex.C(w, r).JSON(map[string]string{
			"message": "IP blocked successfully",
			"ip":      ip,
		})
	})

	server.HandleFunc("/admin/security/unblock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		ip := r.FormValue("ip")
		if ip == "" {
			servex.C(w, r).Error(fmt.Errorf("IP is required"), 400, "Missing IP parameter")
			return
		}

		if err := filter.RemoveBlockedIP(ip); err != nil {
			servex.C(w, r).Error(err, 500, "Failed to unblock IP")
			return
		}

		log.Printf("✅ Manually unblocked IP: %s", ip)
		servex.C(w, r).JSON(map[string]string{
			"message": "IP unblocked successfully",
			"ip":      ip,
		})
	})

	fmt.Println("Advanced security server configured")
	fmt.Println("Use POST /admin/security/block with 'ip' parameter to manually block IPs")
	fmt.Println("Use POST /admin/security/unblock with 'ip' parameter to manually unblock IPs")
}

func temporaryBlockingExample() {
	fmt.Println("\n=== Temporary Blocking Example ===")

	server, err := servex.NewServer()
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	filter := server.Filter()
	if filter == nil {
		// If no filter is configured, we need to enable it
		server, err = servex.NewServer(servex.WithBlockedIPs()) // Enable filtering with empty list
		if err != nil {
			log.Fatal("Failed to create server with filtering:", err)
		}
		filter = server.Filter()
	}

	// Map to track temporarily blocked IPs
	tempBlocked := make(map[string]time.Time)

	// Background goroutine to remove temporary blocks
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			now := time.Now()
			for ip, blockedUntil := range tempBlocked {
				if now.After(blockedUntil) {
					// Remove from temporary block list
					delete(tempBlocked, ip)

					// Remove from filter
					if err := filter.RemoveBlockedIP(ip); err != nil {
						log.Printf("Failed to remove temporary block for IP %s: %v", ip, err)
					} else {
						log.Printf("⏰ Removed temporary block for IP: %s", ip)
					}
				}
			}
		}
	}()

	// Rate limiting endpoint - blocks IPs temporarily for rapid requests
	server.HandleFunc("/api/limited", func(w http.ResponseWriter, r *http.Request) {
		clientIP := servex.C(w, r).ClientIP()

		// Simple rate limiting logic (in production, use a proper rate limiter)
		// For demo purposes, block any IP that we see again within a short time
		if _, exists := tempBlocked[clientIP]; exists {
			// Already temporarily blocked, extend the block
			tempBlocked[clientIP] = time.Now().Add(2 * time.Minute)
			log.Printf("🚨 Extended temporary block for IP: %s", clientIP)
		} else {
			// First request or not blocked, add temporary block
			tempBlocked[clientIP] = time.Now().Add(1 * time.Minute)
			filter.AddBlockedIP(clientIP)
			log.Printf("⚠️ Temporarily blocked IP for 1 minute: %s", clientIP)
		}

		servex.C(w, r).JSON(map[string]interface{}{
			"message":       "Request processed",
			"blocked_until": tempBlocked[clientIP].Format(time.RFC3339),
		})
	})

	// Status endpoint
	server.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		blockedIPs := filter.GetBlockedIPs()
		tempCount := len(tempBlocked)

		servex.C(w, r).JSON(map[string]interface{}{
			"blocked_ips":        blockedIPs,
			"temp_blocked_count": tempCount,
			"temp_blocked_ips":   tempBlocked,
		})
	})

	fmt.Println("Temporary blocking server configured")
	fmt.Println("Access /api/limited multiple times to trigger temporary blocking")
	fmt.Println("Check status at /status")
	fmt.Println("Temporary blocks are automatically removed after 1-2 minutes")
}

// Helper function to determine if an endpoint is valid
func isValidEndpoint(path string) bool {
	validPaths := []string{
		"/api/users",
		"/api/products",
		"/api/status",
		"/api/limited",
		"/status",
		"/admin/security/block",
		"/admin/security/unblock",
		"/admin/security/blocked",
		"/favicon.ico",
		"/robots.txt",
	}

	for _, validPath := range validPaths {
		if path == validPath {
			return true
		}
	}
	return false
}

// Production usage example
func productionUsageExample() {
	fmt.Println("\n=== Production Usage Example ===")

	// In a production environment, you might want to integrate with external services
	server, err := servex.NewServer(
		servex.WithBlockedIPs(), // Enable filtering
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	filter := server.Filter()

	// Example: Integration with threat intelligence feeds
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			// Fetch updated threat intelligence
			maliciousIPs, err := fetchThreatIntelligence()
			if err != nil {
				log.Printf("Failed to fetch threat intelligence: %v", err)
				continue
			}

			// Add new malicious IPs to block list
			for _, ip := range maliciousIPs {
				if err := filter.AddBlockedIP(ip); err != nil {
					log.Printf("Failed to block threat intel IP %s: %v", ip, err)
				}
			}

			log.Printf("Updated threat intelligence: added %d IPs", len(maliciousIPs))
		}
	}()

	// Example: Log suspicious activity for further analysis
	server.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Log all requests for security analysis
			clientIP := servex.C(w, r).ClientIP()

			// Check if IP is already blocked
			if filter.IsIPBlocked(clientIP) {
				log.Printf("🛡️  Blocked request from %s to %s", clientIP, r.URL.Path)
				w.WriteHeader(http.StatusForbidden)
				return
			}

			// Pattern detection: Block IPs scanning for vulnerabilities
			suspiciousPaths := []string{
				"/admin", "/wp-admin", "/.env", "/config",
				"/phpMyAdmin", "/mysql", "/database",
			}

			for _, suspiciousPath := range suspiciousPaths {
				if r.URL.Path == suspiciousPath ||
					(len(r.URL.Path) > len(suspiciousPath) &&
						r.URL.Path[:len(suspiciousPath)] == suspiciousPath) {

					filter.AddBlockedIP(clientIP)
					log.Printf("🚨 BLOCKED: IP %s accessed suspicious path %s", clientIP, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
					return
				}
			}

			// Continue with request
			next.ServeHTTP(w, r)
		})
	})

	fmt.Println("Production-ready server with dynamic security configured")
}

// Mock function to simulate fetching threat intelligence
func fetchThreatIntelligence() ([]string, error) {
	// In a real implementation, this would call external APIs like:
	// - VirusTotal
	// - AbuseIPDB
	// - Shodan
	// - Your own threat intelligence feeds

	// For demo purposes, return some example IPs
	return []string{
		"203.0.113.50",  // Example malicious IP
		"198.51.100.25", // Another example
	}, nil
}

// Example of how to use this in a real application
func realWorldExample() {
	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create server
	server, err := servex.NewServer(
		// Enable various security features
		servex.WithRPS(50),                // Rate limiting
		servex.WithBlockedIPs("10.0.0.1"), // Initial blocked IPs
		servex.WithFilterStatusCode(403),
		servex.WithFilterMessage("Access denied"),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Get filter for dynamic management
	filter := server.Filter()

	// Set up your application routes
	server.HandleFunc("/api/v1/users", handleUsers)
	server.HandleFunc("/api/v1/auth", handleAuth)

	// Security honeypots
	server.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		clientIP := servex.C(w, r).ClientIP()
		filter.AddBlockedIP(clientIP)
		log.Printf("🚨 Honeypot triggered by IP: %s", clientIP)
		w.WriteHeader(http.StatusNotFound)
	})

	// Start server with graceful shutdown
	go func() {
		if err := server.StartWithShutdown(ctx, ":8080", ""); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	log.Println("Server started on :8080")
	log.Println("Press Ctrl+C to stop")

	// In a real app, you'd wait for interrupt signals here
	// signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	// <-c
	// cancel() // This triggers graceful shutdown
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	servex.C(w, r).JSON(map[string]string{"message": "Users endpoint"})
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	servex.C(w, r).JSON(map[string]string{"message": "Auth endpoint"})
}
