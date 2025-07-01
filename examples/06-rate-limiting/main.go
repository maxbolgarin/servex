package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

func main() {
	fmt.Println("🚀 Servex Tutorial - Rate Limiting")
	fmt.Println("===================================")

	// Create server with different rate limiting strategies
	server, err := servex.NewServer(
		servex.WithSecurityHeaders(),
		servex.WithRPS(5), // Allow 5 requests per second
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Normal API endpoint with default rate limiting
	server.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":   "This endpoint has 5 RPS rate limiting",
			"timestamp": time.Now().Format(time.RFC3339),
			"tutorial":  "06-rate-limiting",
		})
	})

	// High-frequency endpoint (for testing rate limits)
	server.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"message":   "Test endpoint - hit this rapidly to see rate limiting",
			"timestamp": time.Now().Format(time.RFC3339),
			"tip":       "Try: for i in {1..10}; do curl http://localhost:8080/api/test; done",
		})
	})

	// Health endpoint (usually excluded from rate limiting)
	server.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"status":   "healthy",
			"tutorial": "06-rate-limiting",
		})
	})

	// Status endpoint to show current rate limiting info
	server.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"rate_limit": map[string]interface{}{
				"requests_per_second": 5,
				"strategy":            "Token bucket",
				"scope":               "Per IP address",
			},
			"headers": map[string]string{
				"X-RateLimit-Limit":     "Shows rate limit",
				"X-RateLimit-Remaining": "Shows remaining requests",
				"X-RateLimit-Reset":     "Shows reset time",
			},
			"tutorial": "06-rate-limiting",
		})
	})

	// Demo page with JavaScript to test rate limiting
	server.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := `
<!DOCTYPE html>
<html>
<head>
    <title>Rate Limiting Demo</title>
    <style>
        body { font-family: Arial; max-width: 800px; margin: 0 auto; padding: 20px; }
        .container { background: #f8f9fa; padding: 20px; border-radius: 8px; }
        button { background: #007bff; color: white; border: none; padding: 10px 20px; margin: 5px; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .results { background: white; border: 1px solid #ddd; padding: 15px; margin-top: 10px; border-radius: 4px; height: 300px; overflow-y: auto; }
        .success { color: green; }
        .error { color: red; }
        .info { color: blue; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Servex Rate Limiting Tutorial</h1>
        <p>This demo shows rate limiting in action. The server allows <strong>5 requests per second</strong>.</p>
        
        <h2>🧪 Test Rate Limiting</h2>
        <button onclick="singleRequest()">Single Request</button>
        <button onclick="rapidRequests()">Rapid Requests (10x)</button>
        <button onclick="slowRequests()">Slow Requests (10x, 1s apart)</button>
        <button onclick="clearResults()">Clear Results</button>
        
        <h2>📊 Results</h2>
        <div id="results" class="results">
            <div class="info">Click a button above to test rate limiting...</div>
        </div>
        
        <h2>📋 Rate Limiting Info</h2>
        <ul>
            <li><strong>Limit:</strong> 5 requests per second</li>
            <li><strong>Strategy:</strong> Token bucket algorithm</li>
            <li><strong>Scope:</strong> Per IP address</li>
            <li><strong>Response:</strong> 429 Too Many Requests when exceeded</li>
        </ul>
        
        <h2>🧪 Manual Testing</h2>
        <pre>
# Single request
curl http://localhost:8080/api/test

# Check rate limit headers
curl -I http://localhost:8080/api/test

# Rapid requests (will trigger rate limiting)
for i in {1..10}; do curl http://localhost:8080/api/test; done

# Check status
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

        function singleRequest() {
            log('Making single request...', 'info');
            fetch('/api/test')
                .then(response => {
                    if (response.ok) {
                        log('✅ Success: ' + response.status + ' ' + response.statusText, 'success');
                    } else {
                        log('❌ Rate limited: ' + response.status + ' ' + response.statusText, 'error');
                    }
                })
                .catch(err => log('❌ Error: ' + err.message, 'error'));
        }

        function rapidRequests() {
            log('Making 10 rapid requests...', 'info');
            for (let i = 0; i < 10; i++) {
                setTimeout(() => {
                    fetch('/api/test')
                        .then(response => {
                            if (response.ok) {
                                log('✅ Request ' + (i+1) + ': Success', 'success');
                            } else {
                                log('❌ Request ' + (i+1) + ': Rate limited (' + response.status + ')', 'error');
                            }
                        })
                        .catch(err => log('❌ Request ' + (i+1) + ': Error', 'error'));
                }, i * 50); // 50ms apart = very rapid
            }
        }

        function slowRequests() {
            log('Making 10 slow requests (1 second apart)...', 'info');
            for (let i = 0; i < 10; i++) {
                setTimeout(() => {
                    fetch('/api/test')
                        .then(response => {
                            if (response.ok) {
                                log('✅ Slow request ' + (i+1) + ': Success', 'success');
                            } else {
                                log('❌ Slow request ' + (i+1) + ': Rate limited', 'error');
                            }
                        })
                        .catch(err => log('❌ Slow request ' + (i+1) + ': Error', 'error'));
                }, i * 1000); // 1 second apart
            }
        }

        function clearResults() {
            document.getElementById('results').innerHTML = '<div class="info">Results cleared. Click a button to test...</div>';
        }
    </script>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, html)
	})

	fmt.Println("🌐 Server starting on http://localhost:8080")
	fmt.Println("🛡️  Rate limiting: 5 requests per second")
	fmt.Println("")
	fmt.Println("Try these URLs:")
	fmt.Println("  → http://localhost:8080/ (interactive demo)")
	fmt.Println("  → http://localhost:8080/api/test (test endpoint)")
	fmt.Println("  → http://localhost:8080/api/status (rate limit info)")
	fmt.Println("")
	fmt.Println("Test rate limiting:")
	fmt.Println("  for i in {1..10}; do curl http://localhost:8080/api/test; done")
	fmt.Println("")
	fmt.Println("Press Ctrl+C to stop")

	server.Start(":8080", "")
}
