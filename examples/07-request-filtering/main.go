package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/maxbolgarin/servex/v2"
)

func main() {
	fmt.Println("🚀 Servex Tutorial - Request Filtering")
	fmt.Println("=======================================")

	// Create server with comprehensive request filtering
	server, err := servex.NewServer(
		// Basic security headers
		servex.WithSecurityHeaders(),

		// Block known bad user agents (bots, scrapers)
		servex.WithBlockedUserAgentsRegex(
			".*[Bb]ot.*",     // Any bot
			".*[Ss]craper.*", // Any scraper
			".*[Cc]rawler.*", // Any crawler
			"curl.*",         // Block curl (for demo purposes)
		),

		// Block requests with suspicious query parameters
		servex.WithBlockedQueryParams(map[string][]string{
			"debug": {"true", "1", "on"}, // Block debug parameters
			"admin": {"true", "1", "on"}, // Block admin parameters
		}),

		// Block specific IP addresses (for demo - normally you'd block real threats)
		servex.WithBlockedIPs("127.0.0.2"), // Block a demo IP

		// Exclude health endpoints from filtering
		servex.WithFilterExcludePaths("/health", "/metrics"),

		// Custom error response
		servex.WithFilterStatusCode(403),
		servex.WithFilterMessage("Request blocked by security policy"),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Demo API endpoint that's protected by filtering
	server.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":    "Request passed all security filters!",
			"user_agent": r.Header.Get("User-Agent"),
			"ip":         r.RemoteAddr,
			"tutorial":   "07-request-filtering",
		})
	})

	// Test endpoint for trying different filters
	server.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)

		// Get query parameters
		debugParam := r.URL.Query().Get("debug")
		adminParam := r.URL.Query().Get("admin")

		ctx.Response(200, map[string]interface{}{
			"message": "Test endpoint - filters working!",
			"query_params": map[string]string{
				"debug": debugParam,
				"admin": adminParam,
			},
			"headers": map[string]string{
				"User-Agent": r.Header.Get("User-Agent"),
				"X-Real-IP":  r.Header.Get("X-Real-IP"),
			},
		})
	})

	// Health endpoint (excluded from filtering)
	server.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"status": "healthy",
			"note":   "This endpoint bypasses all filters",
		})
	})

	// Status endpoint to show filter configuration
	server.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"filters": map[string]interface{}{
				"blocked_user_agents": []string{
					".*[Bb]ot.*", ".*[Ss]craper.*", ".*[Cc]rawler.*", "curl.*",
				},
				"blocked_query_params": map[string][]string{
					"debug": {"true", "1", "on"},
					"admin": {"true", "1", "on"},
				},
				"blocked_ips":    []string{"127.0.0.2"},
				"excluded_paths": []string{"/health", "/metrics"},
			},
			"tutorial": "07-request-filtering",
		})
	})

	// Interactive demo page
	server.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := `
<!DOCTYPE html>
<html>
<head>
    <title>Request Filtering Demo</title>
    <style>
        body { font-family: Arial; max-width: 900px; margin: 0 auto; padding: 20px; }
        .container { background: #f8f9fa; padding: 20px; border-radius: 8px; }
        button { background: #007bff; color: white; border: none; padding: 10px 15px; margin: 5px; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        button.danger { background: #dc3545; }
        button.danger:hover { background: #c82333; }
        .results { background: white; border: 1px solid #ddd; padding: 15px; margin-top: 10px; border-radius: 4px; height: 300px; overflow-y: auto; }
        .success { color: green; }
        .error { color: red; }
        .info { color: blue; }
        .filter-test { background: #fff3cd; padding: 15px; margin: 10px 0; border-radius: 4px; border-left: 4px solid #ffc107; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Servex Request Filtering Tutorial</h1>
        <p>This demo shows request filtering in action. Try the tests below to see how different requests are handled.</p>
        
        <h2>🧪 Filter Tests</h2>
        
        <div class="filter-test">
            <h3>✅ Allowed Requests</h3>
            <button onclick="normalRequest()">Normal Request</button>
            <button onclick="healthRequest()">Health Check (No Filtering)</button>
            <button onclick="statusRequest()">View Filter Status</button>
        </div>
        
        <div class="filter-test">
            <h3>❌ Blocked Requests</h3>
            <button class="danger" onclick="debugRequest()">Debug Parameter (Blocked)</button>
            <button class="danger" onclick="adminRequest()">Admin Parameter (Blocked)</button>
            <button class="danger" onclick="botRequest()">Bot User-Agent (Blocked)</button>
        </div>
        
        <h2>📊 Results</h2>
        <div id="results" class="results">
            <div class="info">Click a test button above to see filtering in action...</div>
        </div>
        
        <h2>🛡️ Active Filters</h2>
        <ul>
            <li><strong>User-Agent Filtering:</strong> Blocks bots, scrapers, crawlers, curl</li>
            <li><strong>Query Parameter Filtering:</strong> Blocks debug=true, admin=true</li>
            <li><strong>IP Filtering:</strong> Blocks 127.0.0.2 (demo IP)</li>
            <li><strong>Path Exclusions:</strong> /health and /metrics bypass filters</li>
        </ul>
        
        <h2>🧪 Manual Testing</h2>
        <pre>
# Normal request (should work)
curl http://localhost:8080/api/test

# Blocked by user-agent
curl -H "User-Agent: BadBot/1.0" http://localhost:8080/api/test

# Blocked by query parameter
curl "http://localhost:8080/api/test?debug=true"

# Health check (bypasses filters)
curl http://localhost:8080/health

# Check filter status
curl http://localhost:8080/api/status
        </pre>
    </div>

    <script>
        function log(message, type = 'info') {
            const results = document.getElementById('results');
            const div = document.createElement('div');
            div.className = type;
            div.textContent = new Date().toLocaleTimeString() + ' - ' + message;
            results.appendChild(div);
            results.scrollTop = results.scrollHeight;
        }

        function normalRequest() {
            log('Making normal request...', 'info');
            fetch('/api/test')
                .then(response => response.json())
                .then(data => {
                    log('✅ Normal request succeeded: ' + data.message, 'success');
                })
                .catch(err => log('❌ Error: ' + err.message, 'error'));
        }

        function healthRequest() {
            log('Testing health endpoint (no filtering)...', 'info');
            fetch('/health')
                .then(response => response.json())
                .then(data => {
                    log('✅ Health check passed: ' + data.status + ' - ' + data.note, 'success');
                })
                .catch(err => log('❌ Error: ' + err.message, 'error'));
        }

        function statusRequest() {
            log('Fetching filter status...', 'info');
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    log('✅ Filter status retrieved - check console for details', 'success');
                    console.log('Filter Configuration:', data.filters);
                })
                .catch(err => log('❌ Error: ' + err.message, 'error'));
        }

        function debugRequest() {
            log('Testing blocked query parameter (debug=true)...', 'info');
            fetch('/api/test?debug=true')
                .then(response => {
                    if (response.status === 403) {
                        log('✅ Request correctly blocked: ' + response.status + ' ' + response.statusText, 'success');
                    } else {
                        log('⚠️ Unexpected response: ' + response.status, 'error');
                    }
                })
                .catch(err => log('❌ Error: ' + err.message, 'error'));
        }

        function adminRequest() {
            log('Testing blocked query parameter (admin=true)...', 'info');
            fetch('/api/test?admin=true')
                .then(response => {
                    if (response.status === 403) {
                        log('✅ Request correctly blocked: ' + response.status + ' ' + response.statusText, 'success');
                    } else {
                        log('⚠️ Unexpected response: ' + response.status, 'error');
                    }
                })
                .catch(err => log('❌ Error: ' + err.message, 'error'));
        }

        function botRequest() {
            log('Testing blocked User-Agent (bot)...', 'info');
            fetch('/api/test', {
                headers: {
                    'User-Agent': 'BadBot/1.0'
                }
            })
            .then(response => {
                if (response.status === 403) {
                    log('✅ Bot request correctly blocked: ' + response.status + ' ' + response.statusText, 'success');
                } else {
                    log('⚠️ Unexpected response: ' + response.status, 'error');
                }
            })
            .catch(err => log('❌ Error: ' + err.message, 'error'));
        }
    </script>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, html)
	})

	fmt.Println("🌐 Server starting on http://localhost:8080")
	fmt.Println("🛡️  Active filters:")
	fmt.Println("    → User-Agent filtering (blocks bots, scrapers)")
	fmt.Println("    → Query parameter filtering (blocks debug, admin)")
	fmt.Println("    → IP filtering (blocks demo IP)")
	fmt.Println("")
	fmt.Println("Try these URLs:")
	fmt.Println("  → http://localhost:8080/ (interactive demo)")
	fmt.Println("  → http://localhost:8080/api/test (test endpoint)")
	fmt.Println("  → http://localhost:8080/api/status (filter status)")
	fmt.Println("")
	fmt.Println("Test filtering:")
	fmt.Println("  curl \"http://localhost:8080/api/test?debug=true\"  # Blocked")
	fmt.Println("  curl -H \"User-Agent: BadBot/1.0\" http://localhost:8080/api/test  # Blocked")
	fmt.Println("  curl http://localhost:8080/health  # Allowed (excluded)")
	fmt.Println("")
	fmt.Println("Press Ctrl+C to stop")

	server.Start(":8080", "")
}
