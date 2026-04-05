package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

func main() {
	log.Println("Servex Tutorial - Simple Proxy")
	log.Println("==============================")

	// Simple proxy configuration with two rules
	proxyConfig := servex.ProxyConfiguration{
		Enabled:         true,
		GlobalTimeout:   30 * time.Second,
		MaxIdleConns:    50,
		IdleConnTimeout: 90 * time.Second,

		// Enable traffic dumping
		TrafficDump: servex.TrafficDumpConfig{
			Enabled:     true,
			Directory:   "./traffic_logs",
			IncludeBody: true,
			MaxBodySize: 32 * 1024, // 32KB
			SampleRate:  0.5,       // Sample 50% of traffic
		},

		// Enable health checking
		HealthCheck: servex.HealthCheckConfig{
			Enabled:         true,
			DefaultInterval: 30 * time.Second,
			Timeout:         5 * time.Second,
			RetryCount:      2,
		},

		Rules: []servex.ProxyRule{
			{
				Name:       "api-service",
				PathPrefix: "/api/",
				Backends: []servex.Backend{
					{
						URL:                 "http://localhost:8081",
						Weight:              2,
						HealthCheckInterval: 30 * time.Second,
					},
					{
						URL:                 "http://localhost:8082",
						Weight:              1,
						HealthCheckInterval: 30 * time.Second,
					},
				},
				LoadBalancing:     servex.WeightedRoundRobinStrategy,
				StripPrefix:       "/api",
				Timeout:           20 * time.Second,
				EnableTrafficDump: true,
			},
			{
				Name:       "auth-service",
				PathPrefix: "/auth/",
				Backends: []servex.Backend{
					{
						URL:    "http://localhost:8083",
						Weight: 1,
					},
				},
				LoadBalancing: servex.RoundRobinStrategy,
				StripPrefix:   "/auth",
				Timeout:       15 * time.Second,
			},
		},
	}

	// Create server with proxy
	server, err := servex.NewServer(
		servex.WithProxyConfig(proxyConfig),
		servex.WithHealthEndpoint(),
		servex.WithDefaultMetrics(),
		servex.WithRPM(100), // Rate limit: 100 requests per minute
	)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	server.GET("/api", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]any{
			"proxy_enabled": true,
			"rules":         len(proxyConfig.Rules),
			"timestamp":     time.Now().Format(time.RFC3339),
			"message":       "Proxy server is running",
		})
	})

	// Add a status endpoint
	server.GET("/status", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]any{
			"proxy_enabled": true,
			"rules":         len(proxyConfig.Rules),
			"timestamp":     time.Now().Format(time.RFC3339),
			"message":       "Proxy server is running",
		})
	})

	// Add a simple info endpoint with interactive demo
	server.GET("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.SetHeader("Content-Type", "text/html")
		html := `
<!DOCTYPE html>
<html>
<head>
    <title>Simple Proxy Demo</title>
    <style>
        body { font-family: Arial; max-width: 900px; margin: 0 auto; padding: 20px; }
        .container { background: #f8f9fa; padding: 20px; border-radius: 8px; }
        button { background: #007bff; color: white; border: none; padding: 10px 15px; margin: 5px; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .backend-status { background: white; border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .results { background: white; border: 1px solid #ddd; padding: 15px; margin-top: 10px; border-radius: 4px; height: 300px; overflow-y: auto; }
        .success { color: green; }
        .error { color: red; }
        .info { color: blue; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Servex Simple Proxy Tutorial</h1>
        <p>This demo shows reverse proxy with load balancing between multiple backend services.</p>
        
        <h2>🏗️ Proxy Configuration</h2>
        <div class="backend-status">
            <strong>API Service</strong> (Weighted Round Robin)
            <ul>
                <li>Backend 1: localhost:8081 (weight 2) - gets 66% of traffic</li>
                <li>Backend 2: localhost:8082 (weight 1) - gets 33% of traffic</li>
            </ul>
        </div>
        
        <div class="backend-status">
            <strong>Auth Service</strong> (Round Robin)
            <ul>
                <li>Backend: localhost:8083 (single service)</li>
            </ul>
        </div>
        
        <h2>🧪 Test Proxy</h2>
        <button onclick="testAPI()">Test API Service (Load Balanced)</button>
        <button onclick="testAuth()">Test Auth Service</button>
        <button onclick="testMultipleAPI()">Test API 5x (See Load Balancing)</button>
        <button onclick="checkStatus()">Check Proxy Status</button>
        <button onclick="checkHealth()">Check Health</button>
        
        <div id="results" class="results">
            <div class="info">Click a test button above to see proxy in action...</div>
            <div class="info">⚠️ Note: Backend services on ports 8081, 8082, 8083 must be running for proxy to work.</div>
        </div>
        
        <h2>🛠️ Features Demonstrated</h2>
        <ul>
            <li>✅ <strong>Load Balancing:</strong> Weighted round-robin between backends</li>
            <li>✅ <strong>Health Checking:</strong> Automatic backend health monitoring</li>
            <li>✅ <strong>Traffic Dumping:</strong> Request/response logging (50% sampling)</li>
            <li>✅ <strong>Rate Limiting:</strong> 100 requests per minute</li>
            <li>✅ <strong>Metrics:</strong> Built-in Prometheus metrics</li>
        </ul>
        
        <h2>🧪 Manual Testing</h2>
        <pre>
# Test API load balancing (alternates between 8081/8082)
curl http://localhost:8080/api/users
curl http://localhost:8080/api/data

# Test auth service
curl http://localhost:8080/auth/login

# Check proxy status
curl http://localhost:8080/status

# Check health
curl http://localhost:8080/health

# Check metrics
curl http://localhost:8080/metrics
        </pre>
        
        <h2>🏃‍♂️ Start Backend Services</h2>
        <p>Use these commands to start test backends:</p>
        <pre>
# Backend 1 (port 8081)
python3 -m http.server 8081 &

# Backend 2 (port 8082) 
python3 -m http.server 8082 &

# Backend 3 (port 8083)
python3 -m http.server 8083 &
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

        function testAPI() {
            log('Testing API service (load balanced)...', 'info');
            fetch('/api/test')
                .then(response => {
                    if (response.ok) {
                        return response.text();
                    } else {
                        throw new Error('HTTP ' + response.status);
                    }
                })
                .then(data => {
                    log('✅ API request successful - check which backend responded', 'success');
                })
                .catch(err => {
                    log('❌ API request failed: ' + err.message + ' (backends may not be running)', 'error');
                });
        }

        function testAuth() {
            log('Testing auth service...', 'info');
            fetch('/auth/login')
                .then(response => {
                    if (response.ok) {
                        return response.text();
                    } else {
                        throw new Error('HTTP ' + response.status);
                    }
                })
                .then(data => {
                    log('✅ Auth request successful', 'success');
                })
                .catch(err => {
                    log('❌ Auth request failed: ' + err.message + ' (backend may not be running)', 'error');
                });
        }

        function testMultipleAPI() {
            log('Testing API 5 times to see load balancing...', 'info');
            for (let i = 1; i <= 5; i++) {
                setTimeout(() => {
                    fetch('/api/test' + i)
                        .then(response => {
                            if (response.ok) {
                                log('✅ API request ' + i + ': Success (should see 2:1 ratio)', 'success');
                            } else {
                                throw new Error('HTTP ' + response.status);
                            }
                        })
                        .catch(err => {
                            log('❌ API request ' + i + ': Failed - ' + err.message, 'error');
                        });
                }, i * 500); // 500ms apart
            }
        }

        function checkStatus() {
            log('Checking proxy status...', 'info');
            fetch('/status')
                .then(response => response.json())
                .then(data => {
                    log('✅ Proxy status: ' + data.rules + ' rules configured', 'success');
                    console.log('Proxy details:', data);
                })
                .catch(err => log('❌ Status check failed: ' + err.message, 'error'));
        }

        function checkHealth() {
            log('Checking proxy health...', 'info');
            fetch('/health')
                .then(response => response.json())
                .then(data => {
                    log('✅ Proxy health check passed', 'success');
                    console.log('Health details:', data);
                })
                .catch(err => log('❌ Health check failed: ' + err.message, 'error'));
        }
    </script>
</body>
</html>`
		ctx.Response(200, html)
	})

	// Start the proxy server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Println("Server: http://localhost:8080")
	log.Println("Proxy: /api/* -> localhost:8081,8082 | /auth/* -> localhost:8083")
	log.Println("Try: curl http://localhost:8080/status")
	log.Println("Press Ctrl+C to stop")

	if err := server.StartWithWaitSignalsHTTP(ctx, ":8080"); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

/*
To test this example, you can create simple backend servers:

# Backend 1 (port 8081) - Simple Go server
echo 'package main
import ("fmt"; "net/http")
func main() {
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"status": "ok", "service": "backend-1"}`)
    })
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"message": "Hello from backend 1", "port": 8081}`)
    })
    fmt.Println("Backend 1 starting on :8081")
    http.ListenAndServe(":8081", nil)
}' > backend1.go && go run backend1.go &

# Backend 2 (port 8082) - Simple Go server
echo 'package main
import ("fmt"; "net/http")
func main() {
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"status": "ok", "service": "backend-2"}`)
    })
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"message": "Hello from backend 2", "port": 8082}`)
    })
    fmt.Println("Backend 2 starting on :8082")
    http.ListenAndServe(":8082", nil)
}' > backend2.go && go run backend2.go &

# Auth service (port 8083) - Simple Go server
echo 'package main
import ("fmt"; "net/http")
func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, `{"message": "Auth service", "endpoint": "%s"}`, r.URL.Path)
    })
    fmt.Println("Auth service starting on :8083")
    http.ListenAndServe(":8083", nil)
}' > auth.go && go run auth.go &

Then test the proxy:
curl http://localhost:8080/api/users      # -> goes to 8081 or 8082 (weighted)
curl http://localhost:8080/auth/login     # -> goes to 8083
curl http://localhost:8080/status         # -> proxy status
curl http://localhost:8080/health         # -> health check
curl http://localhost:8080/metrics        # -> metrics

Check traffic dumps in ./traffic_logs/ directory.
*/
