package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex"
)

func main() {
	fmt.Println("🚀 Servex Tutorial - Advanced Proxy")
	fmt.Println("====================================")
	fmt.Println("This tutorial demonstrates advanced proxy features with multiple load balancing strategies.")
	fmt.Println("")

	// Configure advanced proxy with multiple strategies and routing rules
	proxyConfig := servex.ProxyConfiguration{
		Enabled: true,

		// Global settings for connection management
		GlobalTimeout:       30 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,

		// Advanced traffic dumping for debugging
		TrafficDump: servex.TrafficDumpConfig{
			Enabled:     true,
			Directory:   "./traffic_dumps",
			MaxFileSize: 100 * 1024 * 1024, // 100MB
			MaxFiles:    5,
			IncludeBody: true,
			MaxBodySize: 32 * 1024, // 32KB
			SampleRate:  0.3,       // Sample 30% of traffic
		},

		// Health check configuration for all backends
		HealthCheck: servex.HealthCheckConfig{
			Enabled:         true,
			DefaultInterval: 30 * time.Second,
			Timeout:         5 * time.Second,
			RetryCount:      2,
		},

		Rules: []servex.ProxyRule{
			{
				Name:       "api-weighted-round-robin",
				PathPrefix: "/api/v1/",
				Methods:    []string{"GET", "POST", "PUT", "DELETE"},
				Backends: []servex.Backend{
					{
						URL:                 "http://localhost:8081",
						Weight:              3, // High-capacity server
						HealthCheckPath:     "/health",
						HealthCheckInterval: 30 * time.Second,
						MaxConnections:      50,
					},
					{
						URL:                 "http://localhost:8082",
						Weight:              2, // Medium-capacity server
						HealthCheckPath:     "/health",
						HealthCheckInterval: 30 * time.Second,
						MaxConnections:      30,
					},
					{
						URL:                 "http://localhost:8083",
						Weight:              1, // Lower-capacity server
						HealthCheckPath:     "/health",
						HealthCheckInterval: 30 * time.Second,
						MaxConnections:      20,
					},
				},
				LoadBalancing:     servex.WeightedRoundRobinStrategy,
				StripPrefix:       "/api/v1",
				Timeout:           25 * time.Second,
				EnableTrafficDump: true,
			},
			{
				Name:       "api-least-connections",
				PathPrefix: "/api/v2/",
				Methods:    []string{"GET", "POST"},
				Backends: []servex.Backend{
					{
						URL:                 "http://localhost:8084",
						Weight:              1,
						HealthCheckPath:     "/health",
						HealthCheckInterval: 20 * time.Second,
						MaxConnections:      25,
					},
					{
						URL:                 "http://localhost:8085",
						Weight:              1,
						HealthCheckPath:     "/health",
						HealthCheckInterval: 20 * time.Second,
						MaxConnections:      25,
					},
				},
				LoadBalancing:     servex.LeastConnectionsStrategy,
				StripPrefix:       "/api/v2",
				AddPrefix:         "/v2",
				Timeout:           15 * time.Second,
				EnableTrafficDump: true,
			},
			{
				Name:       "auth-ip-hash",
				PathPrefix: "/auth/",
				Methods:    []string{"POST", "GET"},
				Backends: []servex.Backend{
					{
						URL:                 "http://localhost:8086",
						Weight:              1,
						HealthCheckPath:     "/ping",
						HealthCheckInterval: 15 * time.Second,
						MaxConnections:      30,
					},
					{
						URL:                 "http://localhost:8087",
						Weight:              1,
						HealthCheckPath:     "/ping",
						HealthCheckInterval: 15 * time.Second,
						MaxConnections:      30,
					},
				},
				LoadBalancing: servex.IPHashStrategy, // Session affinity
				StripPrefix:   "/auth",
				Timeout:       10 * time.Second,
			},
			{
				Name:       "static-random",
				PathPrefix: "/static/",
				Methods:    []string{"GET", "HEAD"},
				Backends: []servex.Backend{
					{
						URL:            "http://localhost:8088",
						Weight:         1,
						MaxConnections: 50,
					},
					{
						URL:            "http://localhost:8089",
						Weight:         1,
						MaxConnections: 50,
					},
					{
						URL:            "http://localhost:8090",
						Weight:         1,
						MaxConnections: 50,
					},
				},
				LoadBalancing: servex.RandomStrategy,
				StripPrefix:   "/static",
				Timeout:       10 * time.Second,
			},
		},
	}

	// Create server with advanced proxy configuration
	server, err := servex.NewServer(
		servex.WithProxyConfig(proxyConfig),
		servex.WithSecurityHeaders(),
		servex.WithRPM(500), // 500 requests per minute
		servex.WithHealthEndpoint(),
		servex.WithDefaultMetrics(),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Add status endpoint to show proxy configuration
	server.GET("/proxy-status", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"proxy_enabled": true,
			"rules_count":   len(proxyConfig.Rules),
			"strategies": map[string]string{
				"api_v1": "Weighted Round Robin (3:2:1)",
				"api_v2": "Least Connections",
				"auth":   "IP Hash (Session Affinity)",
				"static": "Random",
			},
			"features": map[string]interface{}{
				"traffic_dump": proxyConfig.TrafficDump.Enabled,
				"health_check": proxyConfig.HealthCheck.Enabled,
				"sample_rate":  proxyConfig.TrafficDump.SampleRate,
			},
			"tutorial": "10-advanced-proxy",
		})
	})

	// Information endpoint about load balancing strategies
	server.GET("/strategies", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]interface{}{
			"load_balancing_strategies": map[string]interface{}{
				"weighted_round_robin": map[string]interface{}{
					"endpoint":    "/api/v1/*",
					"description": "Distributes requests based on backend weights (3:2:1)",
					"use_case":    "When backends have different capacities",
					"backends":    []string{"localhost:8081 (weight 3)", "localhost:8082 (weight 2)", "localhost:8083 (weight 1)"},
				},
				"least_connections": map[string]interface{}{
					"endpoint":    "/api/v2/*",
					"description": "Routes to backend with fewest active connections",
					"use_case":    "For long-running requests or variable request processing time",
					"backends":    []string{"localhost:8084", "localhost:8085"},
				},
				"ip_hash": map[string]interface{}{
					"endpoint":    "/auth/*",
					"description": "Routes based on client IP for session affinity",
					"use_case":    "For stateful applications requiring sticky sessions",
					"backends":    []string{"localhost:8086", "localhost:8087"},
				},
				"random": map[string]interface{}{
					"endpoint":    "/static/*",
					"description": "Random backend selection",
					"use_case":    "For stateless content serving with similar backends",
					"backends":    []string{"localhost:8088", "localhost:8089", "localhost:8090"},
				},
			},
			"tutorial": "10-advanced-proxy",
		})
	})

	// Interactive demo page
	server.GET("/", func(w http.ResponseWriter, r *http.Request) {
		html := `
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Proxy Demo</title>
    <style>
        body { font-family: Arial; max-width: 1000px; margin: 0 auto; padding: 20px; }
        .container { background: #f8f9fa; padding: 20px; border-radius: 8px; }
        .strategy-card { background: white; border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }
        button { background: #007bff; color: white; border: none; padding: 8px 12px; margin: 3px; border-radius: 4px; cursor: pointer; font-size: 12px; }
        button:hover { background: #0056b3; }
        .results { background: white; border: 1px solid #ddd; padding: 15px; margin-top: 10px; border-radius: 4px; height: 350px; overflow-y: auto; }
        .success { color: green; }
        .error { color: red; }
        .info { color: blue; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 11px; }
        .strategy-title { color: #495057; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Servex Advanced Proxy Tutorial</h1>
        <p>This demo showcases different load balancing strategies and advanced proxy routing.</p>
        
        <h2>🎯 Load Balancing Strategies</h2>
        
        <div class="strategy-card">
            <div class="strategy-title">1. Weighted Round Robin - /api/v1/*</div>
            <p>Distributes requests with weights 3:2:1 (High:Medium:Low capacity servers)</p>
            <button onclick="testWeightedRR()">Test Single Request</button>
            <button onclick="testWeightedRRMultiple()">Test 6 Requests</button>
        </div>
        
        <div class="strategy-card">
            <div class="strategy-title">2. Least Connections - /api/v2/*</div>
            <p>Routes to backend with fewest active connections</p>
            <button onclick="testLeastConn()">Test Single Request</button>
            <button onclick="testLeastConnMultiple()">Test Multiple Requests</button>
        </div>
        
        <div class="strategy-card">
            <div class="strategy-title">3. IP Hash (Session Affinity) - /auth/*</div>
            <p>Same client IP always goes to same backend</p>
            <button onclick="testIPHash()">Test Single Request</button>
            <button onclick="testIPHashMultiple()">Test 5 Requests (Same Client)</button>
        </div>
        
        <div class="strategy-card">
            <div class="strategy-title">4. Random - /static/*</div>
            <p>Random backend selection for stateless content</p>
            <button onclick="testRandom()">Test Single Request</button>
            <button onclick="testRandomMultiple()">Test 5 Requests</button>
        </div>
        
        <h2>📊 Test Results</h2>
        <button onclick="checkProxyStatus()">Check Proxy Status</button>
        <button onclick="checkStrategies()">View All Strategies</button>
        <button onclick="clearResults()">Clear Results</button>
        
        <div id="results" class="results">
            <div class="info">Click test buttons above to see different load balancing strategies in action...</div>
            <div class="info">⚠️ Note: Backend services must be running on ports 8081-8090 for full demo.</div>
        </div>
        
        <h2>🧪 Manual Testing</h2>
        <pre>
# Test weighted round robin (should follow 3:2:1 pattern)
for i in {1..6}; do curl http://localhost:8080/api/v1/test; done

# Test least connections
curl http://localhost:8080/api/v2/users

# Test session affinity (same client → same backend)
curl http://localhost:8080/auth/login
curl http://localhost:8080/auth/validate

# Test random selection
curl http://localhost:8080/static/image.jpg

# Check proxy configuration
curl http://localhost:8080/proxy-status
curl http://localhost:8080/strategies
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

        function testWeightedRR() {
            log('Testing Weighted Round Robin (single request)...', 'info');
            fetch('/api/v1/test')
                .then(response => {
                    if (response.ok) {
                        log('✅ Weighted RR: Request successful', 'success');
                    } else {
                        throw new Error('HTTP ' + response.status);
                    }
                })
                .catch(err => log('❌ Request failed: ' + err.message, 'error'));
        }

        function testWeightedRRMultiple() {
            log('Testing Weighted Round Robin (6 requests to see 3:2:1 pattern)...', 'info');
            for (let i = 1; i <= 6; i++) {
                setTimeout(() => {
                    fetch('/api/v1/test' + i)
                        .then(response => {
                            if (response.ok) {
                                log('✅ WRR Request ' + i + ': Success (pattern: 3:2:1)', 'success');
                            } else {
                                throw new Error('HTTP ' + response.status);
                            }
                        })
                        .catch(err => log('❌ WRR Request ' + i + ': ' + err.message, 'error'));
                }, i * 300);
            }
        }

        function testLeastConn() {
            log('Testing Least Connections...', 'info');
            fetch('/api/v2/users')
                .then(response => {
                    if (response.ok) {
                        log('✅ Least Connections: Request successful', 'success');
                    } else {
                        throw new Error('HTTP ' + response.status);
                    }
                })
                .catch(err => log('❌ Request failed: ' + err.message, 'error'));
        }

        function testLeastConnMultiple() {
            log('Testing Least Connections (multiple requests)...', 'info');
            for (let i = 1; i <= 4; i++) {
                setTimeout(() => {
                    fetch('/api/v2/data' + i)
                        .then(response => {
                            if (response.ok) {
                                log('✅ LC Request ' + i + ': Success (routes to least busy)', 'success');
                            } else {
                                throw new Error('HTTP ' + response.status);
                            }
                        })
                        .catch(err => log('❌ LC Request ' + i + ': ' + err.message, 'error'));
                }, i * 200);
            }
        }

        function testIPHash() {
            log('Testing IP Hash (session affinity)...', 'info');
            fetch('/auth/login')
                .then(response => {
                    if (response.ok) {
                        log('✅ IP Hash: Request successful (client → same backend)', 'success');
                    } else {
                        throw new Error('HTTP ' + response.status);
                    }
                })
                .catch(err => log('❌ Request failed: ' + err.message, 'error'));
        }

        function testIPHashMultiple() {
            log('Testing IP Hash (5 requests from same client)...', 'info');
            for (let i = 1; i <= 5; i++) {
                setTimeout(() => {
                    fetch('/auth/session' + i)
                        .then(response => {
                            if (response.ok) {
                                log('✅ IP Hash ' + i + ': Same backend (sticky session)', 'success');
                            } else {
                                throw new Error('HTTP ' + response.status);
                            }
                        })
                        .catch(err => log('❌ IP Hash ' + i + ': ' + err.message, 'error'));
                }, i * 400);
            }
        }

        function testRandom() {
            log('Testing Random selection...', 'info');
            fetch('/static/image.jpg')
                .then(response => {
                    if (response.ok) {
                        log('✅ Random: Request successful', 'success');
                    } else {
                        throw new Error('HTTP ' + response.status);
                    }
                })
                .catch(err => log('❌ Request failed: ' + err.message, 'error'));
        }

        function testRandomMultiple() {
            log('Testing Random selection (5 requests)...', 'info');
            for (let i = 1; i <= 5; i++) {
                setTimeout(() => {
                    fetch('/static/file' + i + '.css')
                        .then(response => {
                            if (response.ok) {
                                log('✅ Random ' + i + ': Success (random backend)', 'success');
                            } else {
                                throw new Error('HTTP ' + response.status);
                            }
                        })
                        .catch(err => log('❌ Random ' + i + ': ' + err.message, 'error'));
                }, i * 200);
            }
        }

        function checkProxyStatus() {
            log('Checking proxy status...', 'info');
            fetch('/proxy-status')
                .then(response => response.json())
                .then(data => {
                    log('✅ Proxy Status: ' + data.rules_count + ' rules configured', 'success');
                    console.log('Proxy Details:', data);
                })
                .catch(err => log('❌ Status check failed: ' + err.message, 'error'));
        }

        function checkStrategies() {
            log('Fetching strategy details...', 'info');
            fetch('/strategies')
                .then(response => response.json())
                .then(data => {
                    log('✅ Strategy details retrieved - check console', 'success');
                    console.log('Load Balancing Strategies:', data.load_balancing_strategies);
                })
                .catch(err => log('❌ Strategy fetch failed: ' + err.message, 'error'));
        }

        function clearResults() {
            document.getElementById('results').innerHTML = '<div class="info">Results cleared. Click test buttons to continue...</div>';
        }
    </script>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, html)
	})

	fmt.Println("🌐 Server starting on http://localhost:8080")
	fmt.Println("🔀 Advanced proxy with 4 load balancing strategies:")
	fmt.Println("    → /api/v1/* → Weighted Round Robin (3:2:1)")
	fmt.Println("    → /api/v2/* → Least Connections")
	fmt.Println("    → /auth/* → IP Hash (Session Affinity)")
	fmt.Println("    → /static/* → Random")
	fmt.Println("")
	fmt.Println("🛠️  Advanced features:")
	fmt.Println("    → Health checking (automatic failover)")
	fmt.Println("    → Traffic dumping (30% sampling → ./traffic_dumps/)")
	fmt.Println("    → Connection limits per backend")
	fmt.Println("    → Per-rule timeouts and path manipulation")
	fmt.Println("")
	fmt.Println("Try these URLs:")
	fmt.Println("  → http://localhost:8080/ (interactive demo)")
	fmt.Println("  → http://localhost:8080/proxy-status (configuration)")
	fmt.Println("  → http://localhost:8080/strategies (strategy details)")
	fmt.Println("")
	fmt.Println("⚠️  Backend services needed (ports 8081-8090):")
	fmt.Println("  Use: for i in {8081..8090}; do python3 -m http.server $i &; done")
	fmt.Println("")
	fmt.Println("Press Ctrl+C to stop")

	// Start server with graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server.StartWithShutdown(ctx, ":8080", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
