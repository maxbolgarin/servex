package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

// Global state for demo purposes
var (
	tempBlocked        = make(map[string]time.Time)
	tempBlockedMutex   sync.RWMutex
	honeypotCounter    = 0
	threatIntelCounter = 0
	lastThreatUpdate   time.Time
	securityEventChan  = make(chan string, 100)
)

func main() {
	fmt.Println("🛡️  Tutorial 12: Dynamic Filtering")
	fmt.Println("==================================")
	fmt.Println("Learn how to dynamically update filtering rules at runtime")
	fmt.Println()

	// Create server with initial filtering enabled
	server, err := servex.NewServer(
		// Start with some initial blocked IPs for demo
		servex.WithBlockedIPs("10.0.0.1", "192.168.99.99"),
		servex.WithBlockedUserAgents("BadBot/1.0", "EvilCrawler/2.0"),
		servex.WithFilterStatusCode(http.StatusForbidden),
		servex.WithFilterMessage("Access denied by security policy"),
		servex.WithHealthEndpoint(),
		servex.WithSendErrorToClient(), // For demo purposes only
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Get filter instance for dynamic modification
	filter := server.Filter()
	if filter == nil {
		log.Fatal("Filter is not available - filtering must be enabled")
	}

	// Start background services
	startTemporaryBlockCleanup(filter)
	startThreatIntelligenceUpdater(filter)
	startSecurityEventProcessor()

	// === HONEYPOT ENDPOINTS ===
	setupHoneypots(server, filter)

	// === SECURITY MANAGEMENT ENDPOINTS ===
	setupSecurityManagement(server, filter)

	// === MONITORING ENDPOINTS ===
	setupMonitoring(server, filter)

	// === APPLICATION ENDPOINTS ===
	setupApplicationEndpoints(server, filter)

	// === PATTERN DETECTION MIDDLEWARE ===
	setupPatternDetection(server, filter)

	// Start server with helpful information
	fmt.Println("🌐 Server starting on http://localhost:8080")
	fmt.Println()
	fmt.Println("🛡️  Security Features:")
	fmt.Println("  → Dynamic IP blocking/unblocking")
	fmt.Println("  → Honeypot traps with automatic blocking")
	fmt.Println("  → Temporary blocks with auto-expiration")
	fmt.Println("  → Pattern-based threat detection")
	fmt.Println("  → Real-time security monitoring")
	fmt.Println()
	fmt.Println("🎯 Test Endpoints:")
	fmt.Println("  🍯 Honeypots (⚠️  will block your IP):")
	fmt.Println("     → GET  /admin/backup.sql")
	fmt.Println("     → GET  /wp-admin/admin-ajax.php")
	fmt.Println("     → GET  /.env")
	fmt.Println()
	fmt.Println("  🔧 Security Management:")
	fmt.Println("     → POST /security/block (ip=...)")
	fmt.Println("     → POST /security/unblock (ip=...)")
	fmt.Println("     → GET  /security/blocked")
	fmt.Println("     → GET  /security/dashboard")
	fmt.Println()
	fmt.Println("  📊 Monitoring:")
	fmt.Println("     → GET  /security/metrics")
	fmt.Println("     → GET  /security/threats")
	fmt.Println("     → GET  /security/events/live")
	fmt.Println()
	fmt.Println("  🧪 Test APIs:")
	fmt.Println("     → GET  /api/test")
	fmt.Println("     → GET  /api/rate-limited")
	fmt.Println("     → GET  /api/public/info")
	fmt.Println()
	fmt.Println("⚠️  WARNING: Accessing honeypot endpoints will block your IP!")
	fmt.Println("💡 Use /security/unblock to unblock yourself if needed")
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")

	if err := server.StartWithWaitSignalsHTTP(context.Background(), ":8080"); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

// setupHoneypots creates honeypot endpoints that automatically block attackers
func setupHoneypots(server *servex.Server, filter servex.DynamicFilterMethods) {
	// Honeypot 1: Fake database backup file
	server.HandleFunc("/admin/backup.sql", func(w http.ResponseWriter, r *http.Request) {
		clientIP := servex.C(w, r).ClientIP()
		userAgent := r.Header.Get("User-Agent")

		// Block the IP
		if err := filter.AddBlockedIP(clientIP); err != nil {
			log.Printf("Failed to block IP %s: %v", clientIP, err)
		} else {
			honeypotCounter++
			log.Printf("🚨 HONEYPOT: Blocked IP %s accessing fake backup file", clientIP)

			// Send security event
			event := fmt.Sprintf("honeypot_triggered:backup.sql:ip=%s:ua=%s", clientIP, userAgent)
			select {
			case securityEventChan <- event:
			default:
			}
		}

		// Return fake content to keep attacker engaged
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=backup.sql")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`-- Database Backup (Fake)
-- This is a honeypot trap
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password_hash VARCHAR(255),
    email VARCHAR(100)
);

INSERT INTO users VALUES 
(1, 'admin', 'fake_hash_123', 'admin@example.com'),
(2, 'user', 'fake_hash_456', 'user@example.com');
`))
	})

	// Honeypot 2: WordPress admin endpoint
	server.HandleFunc("/wp-admin/admin-ajax.php", func(w http.ResponseWriter, r *http.Request) {
		clientIP := servex.C(w, r).ClientIP()
		userAgent := r.Header.Get("User-Agent")

		// Block both IP and User-Agent
		filter.AddBlockedIP(clientIP)
		filter.AddBlockedUserAgent(userAgent)

		honeypotCounter++
		log.Printf("🚨 HONEYPOT: WordPress attack from IP %s, User-Agent: %s", clientIP, userAgent)

		event := fmt.Sprintf("honeypot_triggered:wordpress:ip=%s:ua=%s", clientIP, userAgent)
		select {
		case securityEventChan <- event:
		default:
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not found"))
	})

	// Honeypot 3: Environment file access
	server.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		clientIP := servex.C(w, r).ClientIP()

		filter.AddBlockedIP(clientIP)
		honeypotCounter++
		log.Printf("🚨 HONEYPOT: Environment file access from IP %s", clientIP)

		event := fmt.Sprintf("honeypot_triggered:env_file:ip=%s", clientIP)
		select {
		case securityEventChan <- event:
		default:
		}

		// Return fake environment variables
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`# Fake Environment File (Honeypot)
DB_HOST=fake.database.local
DB_USER=fake_user
DB_PASS=fake_password
API_KEY=fake_api_key_12345
SECRET_KEY=fake_secret_key_67890
`))
	})
}

// setupSecurityManagement creates endpoints for manual security management
func setupSecurityManagement(server *servex.Server, filter servex.DynamicFilterMethods) {
	// Block an IP manually
	server.HandleFunc("/security/block", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		ip := r.FormValue("ip")
		reason := r.FormValue("reason")
		if reason == "" {
			reason = "manual_block"
		}

		if ip == "" {
			servex.C(w, r).Error(fmt.Errorf("IP parameter is required"), 400, "Missing IP parameter")
			return
		}

		// Validate IP address
		if net.ParseIP(ip) == nil {
			servex.C(w, r).Error(fmt.Errorf("invalid IP address"), 400, "Invalid IP address format")
			return
		}

		if err := filter.AddBlockedIP(ip); err != nil {
			servex.C(w, r).Error(err, 500, "Failed to block IP")
			return
		}

		log.Printf("✅ Manually blocked IP: %s (reason: %s)", ip, reason)

		event := fmt.Sprintf("manual_block:ip=%s:reason=%s", ip, reason)
		select {
		case securityEventChan <- event:
		default:
		}

		servex.C(w, r).Response(200, map[string]any{
			"message":    "IP blocked successfully",
			"ip":         ip,
			"reason":     reason,
			"blocked_at": time.Now().Format(time.RFC3339),
		})
	})

	// Unblock an IP manually
	server.HandleFunc("/security/unblock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		ip := r.FormValue("ip")
		reason := r.FormValue("reason")
		if reason == "" {
			reason = "manual_unblock"
		}

		if ip == "" {
			servex.C(w, r).Error(fmt.Errorf("IP parameter is required"), 400, "Missing IP parameter")
			return
		}

		if err := filter.RemoveBlockedIP(ip); err != nil {
			servex.C(w, r).Error(err, 500, "Failed to unblock IP")
			return
		}

		// Also remove from temporary blocks
		tempBlockedMutex.Lock()
		delete(tempBlocked, ip)
		tempBlockedMutex.Unlock()

		log.Printf("✅ Manually unblocked IP: %s (reason: %s)", ip, reason)

		event := fmt.Sprintf("manual_unblock:ip=%s:reason=%s", ip, reason)
		select {
		case securityEventChan <- event:
		default:
		}

		servex.C(w, r).Response(200, map[string]any{
			"message":      "IP unblocked successfully",
			"ip":           ip,
			"reason":       reason,
			"unblocked_at": time.Now().Format(time.RFC3339),
		})
	})

	// View all blocked IPs and User-Agents
	server.HandleFunc("/security/blocked", func(w http.ResponseWriter, r *http.Request) {
		blockedIPs := filter.GetBlockedIPs()
		blockedUAs := filter.GetBlockedUserAgents()

		tempBlockedMutex.RLock()
		tempBlockedList := make(map[string]string)
		for ip, expiry := range tempBlocked {
			tempBlockedList[ip] = expiry.Format(time.RFC3339)
		}
		tempBlockedMutex.RUnlock()

		response := map[string]any{
			"blocked_ips":         blockedIPs,
			"blocked_user_agents": blockedUAs,
			"temporary_blocks":    tempBlockedList,
			"total_blocked_ips":   len(blockedIPs),
			"total_blocked_uas":   len(blockedUAs),
			"total_temp_blocks":   len(tempBlockedList),
			"last_updated":        time.Now().Format(time.RFC3339),
		}

		servex.C(w, r).Response(200, response)
	})
}

// setupMonitoring creates monitoring and dashboard endpoints
func setupMonitoring(server *servex.Server, filter servex.DynamicFilterMethods) {
	// Security dashboard
	server.HandleFunc("/security/dashboard", func(w http.ResponseWriter, r *http.Request) {
		blockedIPs := filter.GetBlockedIPs()
		blockedUAs := filter.GetBlockedUserAgents()

		tempBlockedMutex.RLock()
		tempBlockCount := len(tempBlocked)
		tempBlockedMutex.RUnlock()

		dashboard := map[string]any{
			"title":     "Dynamic Filtering Security Dashboard",
			"status":    "operational",
			"timestamp": time.Now().Format(time.RFC3339),
			"security_stats": map[string]any{
				"blocked_ips_count":         len(blockedIPs),
				"blocked_user_agents_count": len(blockedUAs),
				"temporary_blocks_count":    tempBlockCount,
				"honeypot_triggers":         honeypotCounter,
				"threat_intel_updates":      threatIntelCounter,
			},
			"recent_blocks": map[string]any{
				"blocked_ips":         getRecentItems(blockedIPs, 10),
				"blocked_user_agents": getRecentItems(blockedUAs, 5),
			},
			"threat_intelligence": map[string]any{
				"last_update":  lastThreatUpdate.Format(time.RFC3339),
				"update_count": threatIntelCounter,
			},
			"features": []string{
				"Real-time IP blocking",
				"Honeypot detection",
				"Temporary blocking",
				"Pattern-based filtering",
				"Threat intelligence integration",
			},
		}

		servex.C(w, r).Response(200, dashboard)
	})

	// Security metrics
	server.HandleFunc("/security/metrics", func(w http.ResponseWriter, r *http.Request) {
		blockedIPs := filter.GetBlockedIPs()
		blockedUAs := filter.GetBlockedUserAgents()

		tempBlockedMutex.RLock()
		tempBlockCount := len(tempBlocked)
		tempBlockedMutex.RUnlock()

		metrics := map[string]any{
			"blocked_ips_total":         len(blockedIPs),
			"blocked_user_agents_total": len(blockedUAs),
			"temporary_blocks_active":   tempBlockCount,
			"honeypot_triggers_total":   honeypotCounter,
			"threat_intel_hits_total":   threatIntelCounter,
			"last_threat_update":        lastThreatUpdate.Format(time.RFC3339),
			"uptime_seconds":            time.Since(lastThreatUpdate).Seconds(),
		}

		servex.C(w, r).Response(200, metrics)
	})

	// Real-time security events (Server-Sent Events)
	server.HandleFunc("/security/events/live", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// Send initial connection event
		fmt.Fprintf(w, "data: {\"type\":\"connected\",\"timestamp\":\"%s\"}\n\n", time.Now().Format(time.RFC3339))
		w.(http.Flusher).Flush()

		// Stream events
		ctx := r.Context()
		ticker := time.NewTicker(30 * time.Second) // Heartbeat
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case event := <-securityEventChan:
				fmt.Fprintf(w, "data: {\"type\":\"security_event\",\"event\":\"%s\",\"timestamp\":\"%s\"}\n\n",
					event, time.Now().Format(time.RFC3339))
				w.(http.Flusher).Flush()
			case <-ticker.C:
				// Heartbeat
				fmt.Fprintf(w, "data: {\"type\":\"heartbeat\",\"timestamp\":\"%s\"}\n\n", time.Now().Format(time.RFC3339))
				w.(http.Flusher).Flush()
			}
		}
	})

	// Current threats summary
	server.HandleFunc("/security/threats", func(w http.ResponseWriter, r *http.Request) {
		threats := map[string]any{
			"active_threats": map[string]any{
				"blocked_ips":    len(filter.GetBlockedIPs()),
				"blocked_agents": len(filter.GetBlockedUserAgents()),
				"temp_blocks": func() int {
					tempBlockedMutex.RLock()
					defer tempBlockedMutex.RUnlock()
					return len(tempBlocked)
				}(),
			},
			"threat_sources": map[string]any{
				"honeypots":         honeypotCounter,
				"pattern_detection": 0, // Could track this separately
				"threat_intel":      threatIntelCounter,
				"manual_blocks":     0, // Could track this separately
			},
			"last_updated": time.Now().Format(time.RFC3339),
		}

		servex.C(w, r).Response(200, threats)
	})
}

// setupApplicationEndpoints creates normal application endpoints for testing
func setupApplicationEndpoints(server *servex.Server, filter servex.DynamicFilterMethods) {
	// Normal API endpoint
	server.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"message":    "API test endpoint",
			"timestamp":  time.Now().Format(time.RFC3339),
			"client_ip":  r.RemoteAddr,
			"user_agent": r.Header.Get("User-Agent"),
			"note":       "This endpoint is protected by dynamic filtering",
		})
	})

	// Rate-limited endpoint that triggers temporary blocking
	server.HandleFunc("/api/rate-limited", func(w http.ResponseWriter, r *http.Request) {
		clientIP := servex.C(w, r).ClientIP()

		// Simple rate limiting logic - block if already temp blocked
		tempBlockedMutex.RLock()
		_, isBlocked := tempBlocked[clientIP]
		tempBlockedMutex.RUnlock()

		if isBlocked {
			// Extend the block
			tempBlockedMutex.Lock()
			tempBlocked[clientIP] = time.Now().Add(2 * time.Minute)
			tempBlockedMutex.Unlock()

			log.Printf("⚠️  Extended temporary block for IP: %s", clientIP)
		} else {
			// Add temporary block
			tempBlockedMutex.Lock()
			tempBlocked[clientIP] = time.Now().Add(1 * time.Minute)
			tempBlockedMutex.Unlock()

			filter.AddBlockedIP(clientIP)
			log.Printf("⚡ Temporarily blocked IP for 1 minute: %s", clientIP)

			event := fmt.Sprintf("temp_block:ip=%s:duration=1min", clientIP)
			select {
			case securityEventChan <- event:
			default:
			}
		}

		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"message":   "Rate limited endpoint accessed",
			"client_ip": clientIP,
			"blocked_until": func() string {
				tempBlockedMutex.RLock()
				defer tempBlockedMutex.RUnlock()
				if until, exists := tempBlocked[clientIP]; exists {
					return until.Format(time.RFC3339)
				}
				return ""
			}(),
		})
	})

	// Public endpoint
	server.HandleFunc("/api/public/info", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]any{
			"message": "Public information endpoint",
			"info": map[string]any{
				"service":     "Dynamic Filtering Demo",
				"version":     "1.0",
				"environment": "tutorial",
				"features":    []string{"dynamic-filtering", "honeypots", "real-time-monitoring"},
			},
		})
	})
}

// setupPatternDetection adds middleware for detecting suspicious patterns
func setupPatternDetection(server *servex.Server, filter servex.DynamicFilterMethods) {
	server.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := servex.C(w, r).ClientIP()
			userAgent := r.Header.Get("User-Agent")
			path := r.URL.Path

			// Check for suspicious patterns
			suspicious := false
			reason := ""

			// Block empty User-Agents (often automated tools)
			if userAgent == "" {
				suspicious = true
				reason = "empty_user_agent"
			}

			// Check for vulnerability scanning patterns
			vulnerabilityPaths := []string{
				"/admin.php", "/config.php", "/database.sql", "/.git/config",
				"/phpmyadmin", "/mysql", "/adminer", "/wp-config.php",
				"/shell.php", "/cmd.php", "/backdoor.php",
			}

			for _, vulnPath := range vulnerabilityPaths {
				if strings.Contains(path, vulnPath) {
					suspicious = true
					reason = fmt.Sprintf("vulnerability_scan:%s", vulnPath)
					break
				}
			}

			// Check for bot patterns in User-Agent
			if !suspicious {
				botPatterns := []string{"bot", "spider", "crawler", "scraper", "scanner"}
				lowerUA := strings.ToLower(userAgent)
				for _, pattern := range botPatterns {
					if strings.Contains(lowerUA, pattern) && !strings.Contains(lowerUA, "googlebot") { // Allow Googlebot
						suspicious = true
						reason = fmt.Sprintf("bot_pattern:%s", pattern)
						break
					}
				}
			}

			if suspicious {
				filter.AddBlockedIP(clientIP)
				if userAgent != "" {
					filter.AddBlockedUserAgent(userAgent)
				}

				log.Printf("🚨 Pattern detection blocked IP %s (reason: %s, path: %s)", clientIP, reason, path)

				event := fmt.Sprintf("pattern_detection:ip=%s:reason=%s:path=%s", clientIP, reason, path)
				select {
				case securityEventChan <- event:
				default:
				}

				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Access denied by security policy"))
				return
			}

			next.ServeHTTP(w, r)
		})
	})
}

// Background service to clean up temporary blocks
func startTemporaryBlockCleanup(filter servex.DynamicFilterMethods) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			now := time.Now()
			tempBlockedMutex.Lock()

			for ip, blockedUntil := range tempBlocked {
				if now.After(blockedUntil) {
					delete(tempBlocked, ip)

					if err := filter.RemoveBlockedIP(ip); err != nil {
						log.Printf("Failed to remove temporary block for IP %s: %v", ip, err)
					} else {
						log.Printf("⏰ Removed temporary block for IP: %s", ip)

						event := fmt.Sprintf("temp_unblock:ip=%s:auto_expired", ip)
						select {
						case securityEventChan <- event:
						default:
						}
					}
				}
			}
			tempBlockedMutex.Unlock()
		}
	}()
}

// Background service to simulate threat intelligence updates
func startThreatIntelligenceUpdater(filter servex.DynamicFilterMethods) {
	lastThreatUpdate = time.Now()

	go func() {
		ticker := time.NewTicker(5 * time.Minute) // More frequent for demo
		defer ticker.Stop()

		for range ticker.C {
			// Simulate fetching threat intelligence
			maliciousIPs, err := fetchThreatIntelligence()
			if err != nil {
				log.Printf("Failed to fetch threat intelligence: %v", err)
				continue
			}

			// Add new threats to filter
			newThreats := 0
			for _, ip := range maliciousIPs {
				if err := filter.AddBlockedIP(ip); err == nil {
					newThreats++
				}
			}

			if newThreats > 0 {
				threatIntelCounter += newThreats
				lastThreatUpdate = time.Now()
				log.Printf("🛡️  Updated threat intelligence: added %d new threats", newThreats)

				event := fmt.Sprintf("threat_intel_update:new_threats=%d", newThreats)
				select {
				case securityEventChan <- event:
				default:
				}
			}
		}
	}()
}

// Background service to process security events
func startSecurityEventProcessor() {
	go func() {
		for event := range securityEventChan {
			// In a real application, you might:
			// - Send to SIEM system
			// - Store in database
			// - Send alerts
			// - Update dashboards
			log.Printf("📊 Security Event: %s", event)
		}
	}()
}

// Mock function to simulate fetching threat intelligence
func fetchThreatIntelligence() ([]string, error) {
	// In a real implementation, this would call external APIs like:
	// - VirusTotal
	// - AbuseIPDB
	// - Shodan
	// - Your own threat intelligence feeds

	// For demo purposes, return some example malicious IPs
	demoThreats := [][]string{
		{"203.0.113.50", "198.51.100.25"},
		{"192.0.2.100", "203.0.113.75"},
		{"198.51.100.50"},
		{}, // Sometimes no new threats
	}

	// Rotate through different threat sets for demo
	threatSet := demoThreats[threatIntelCounter%len(demoThreats)]
	return threatSet, nil
}

// Helper function to get recent items from a slice
func getRecentItems(items []string, limit int) []string {
	if len(items) <= limit {
		return items
	}
	return items[len(items)-limit:]
}
