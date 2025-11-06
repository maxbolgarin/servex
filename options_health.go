package servex


// WithHealthEndpoint enables an automatic health check endpoint that returns server status.
// This creates a simple endpoint that responds with "OK" and HTTP 200 status.
//
// Note: The health endpoint is enabled by default. You only need to use this function
// if you want to explicitly enable it after disabling it, or to ensure it's enabled
// for clarity in your code.
//
// Example:
//
//	// Health endpoint is already enabled by default
//	server := servex.New()
//	// Available at: GET /health
//
//	// Explicitly enable (redundant but clear)
//	server := servex.New(servex.WithHealthEndpoint())
//	// Available at: GET /health
//
//	// Custom health path
//	server := servex.New(
//		servex.WithHealthEndpoint(),
//		servex.WithHealthPath("/status"),
//	)
//	// Available at: GET /status
//
// The health endpoint:
//   - Returns 200 OK with "OK" body when server is running
//   - Bypasses authentication and filtering
//   - Suitable for load balancer health checks
//   - Kubernetes liveness/readiness probes
//   - Monitoring systems
//
// Use cases:
//   - Load balancer health checks
//   - Kubernetes probes
//   - Monitoring and alerting
//   - Service discovery
//   - Uptime monitoring
//
// To disable the health endpoint, use WithDisableHealthEndpoint().
// For custom health logic, implement your own endpoint instead of using this option.
func WithHealthEndpoint() Option {
	return func(op *Options) {
		op.EnableHealthEndpoint = true
		if op.HealthPath == "" {
			op.HealthPath = "/health"
		}
	}
}

// WithDisableHealthEndpoint disables the automatic health check endpoint.
//
// The health endpoint is enabled by default for production readiness.
// Use this function to explicitly disable it if you:
//   - Don't need health checks
//   - Have your own custom health check endpoint
//   - Want to minimize exposed endpoints
//   - Are running in an environment without load balancers
//
// Example:
//
//	// Disable the default health endpoint
//	server := servex.New(servex.WithDisableHealthEndpoint())
//
//	// Disable and implement custom health logic
//	server := servex.New(servex.WithDisableHealthEndpoint())
//	server.Get("/custom-health", func(w http.ResponseWriter, r *http.Request) {
//		// Custom health check logic
//		servex.C(w, r).Response(200, map[string]string{"status": "healthy"})
//	})
//
// Note: Most production applications should keep the health endpoint enabled
// for proper monitoring and orchestration.
func WithDisableHealthEndpoint() Option {
	return func(op *Options) {
		op.EnableHealthEndpoint = false
	}
}

// WithHealthPath sets a custom path for the health check endpoint.
// This only works when WithHealthEndpoint() is also used.
//
// Example:
//
//	// Custom health check path
//	server := servex.New(
//		servex.WithHealthEndpoint(),
//		servex.WithHealthPath("/ping"),
//	)
//	// Available at: GET /ping
//
//	// Health check for specific service
//	server := servex.New(
//		servex.WithHealthEndpoint(),
//		servex.WithHealthPath("/api/v1/health"),
//	)
//	// Available at: GET /api/v1/health
//
// Common health check paths:
//   - "/health" (default)
//   - "/ping"
//   - "/status"
//   - "/healthz" (Kubernetes style)
//   - "/alive"
//   - "/ready"
//
// Default is "/health" if not specified.
// The path should start with "/" and be unique to avoid conflicts.
func WithHealthPath(path string) Option {
	return func(op *Options) {
		op.HealthPath = path
		// Enable health endpoint if path is set
		if path != "" {
			op.EnableHealthEndpoint = true
		}
	}
}

// WithMetrics sets a custom metrics collector that will be called on each HTTP request and response.
//
// The Metrics interface requires two methods:
//   - HandleRequest(r *http.Request) - Called when a request arrives
//   - HandleResponse(r *http.Request, w http.ResponseWriter, statusCode int, duration time.Duration) - Called when response is sent
//
// This allows you to collect detailed metrics about your application's HTTP traffic.
// When using a custom metrics implementation, the default metrics endpoint is automatically disabled.
//
// Example - Basic Request Counter:
//
//	type MyMetrics struct {
//		requestCount int64
//	}
//
//	func (m *MyMetrics) HandleRequest(r *http.Request) {
//		atomic.AddInt64(&m.requestCount, 1)
//	}
//
//	func (m *MyMetrics) HandleResponse(r *http.Request, w http.ResponseWriter, statusCode int, duration time.Duration) {
//		// Track response metrics, status codes, response times, etc.
//	}
//
//	metrics := &MyMetrics{}
//	server := servex.New(servex.WithMetrics(metrics))
//
// Example - Prometheus Integration:
//
//	type PrometheusMetrics struct {
//		requestsTotal   *prometheus.CounterVec
//		requestDuration *prometheus.HistogramVec
//	}
//
//	func (m *PrometheusMetrics) HandleRequest(r *http.Request) {
//		// Increment request counter
//		m.requestsTotal.WithLabelValues(r.Method, r.URL.Path).Inc()
//	}
//
//	func (m *PrometheusMetrics) HandleResponse(r *http.Request, w http.ResponseWriter, statusCode int, duration time.Duration) {
//		// Record response time and status
//		m.requestDuration.WithLabelValues(r.Method, r.URL.Path, fmt.Sprint(statusCode)).Observe(duration.Seconds())
//	}
//
// Use cases:
//   - Prometheus metrics collection with custom labels and buckets
//   - StatsD or DataDog integration
//   - Custom analytics and monitoring systems
//   - Application Performance Monitoring (APM) integration
//   - Request/response tracking for debugging
//   - Business metrics (e.g., tracking API usage per customer)
//
// Performance considerations:
//   - The metrics methods are called for EVERY request, ensure they are fast and non-blocking
//   - Avoid expensive operations like database writes or external API calls
//   - Use atomic operations for counters to avoid mutex contention
//   - Consider using buffering or background workers for complex metric processing
//
// Note: Using WithMetrics disables the default metrics endpoint. If you need both built-in
// and custom metrics, consider wrapping or composing metrics implementations, or use
// WithDefaultMetrics() instead for the built-in Prometheus-compatible metrics endpoint.
func WithMetrics(m Metrics) Option {
	return func(op *Options) {
		op.Metrics = m
		op.EnableDefaultMetrics = false
		op.MetricsPath = ""
	}
}

// WithDefaultMetrics enables the default built-in metrics endpoint with Prometheus-compatible output.
//
// This creates a comprehensive metrics endpoint that tracks:
//   - Total requests, responses, and errors
//   - Error rate percentage
//   - Average response time in milliseconds
//   - Requests per second
//   - Response status code distribution (2xx, 3xx, 4xx, 5xx)
//   - HTTP method distribution (GET, POST, PUT, DELETE, etc.)
//   - Per-path request counts and timing statistics
//   - System metrics (memory usage, goroutine count, GC stats)
//
// The metrics endpoint outputs in Prometheus text format (version 0.0.4) and can be
// scraped by Prometheus, Grafana, or other monitoring tools.
//
// Example:
//
//	// Enable default metrics at /metrics
//	server := servex.New(servex.WithDefaultMetrics())
//
//	// Custom metrics path
//	server := servex.New(servex.WithDefaultMetrics("/stats"))
//
//	// Combined with other monitoring features
//	server := servex.New(
//		servex.WithDefaultMetrics("/metrics"),
//		servex.WithHealthEndpoint(),
//		servex.WithRequestLogger(myLogger),
//	)
//
// Available metrics include:
//   - servex_requests_total - Total number of HTTP requests
//   - servex_responses_total - Total number of HTTP responses
//   - servex_errors_total - Total number of errors (4xx and 5xx)
//   - servex_error_rate_percent - Percentage of requests that resulted in errors
//   - servex_requests_per_second - Current request rate
//   - servex_response_time_ms_avg - Average response time in milliseconds
//   - servex_responses_by_status_total{status="200"} - Responses by status code
//   - servex_requests_by_method_total{method="GET"} - Requests by HTTP method
//   - servex_requests_by_path_total{path="/api/users"} - Requests by path
//   - servex_memory_usage_bytes - Current memory usage
//   - servex_goroutines - Number of active goroutines
//   - servex_gc_count - Total garbage collection count
//
// Default path: "/metrics" if not specified.
//
// Use this when:
//   - You want quick observability without writing custom metrics
//   - You need Prometheus-compatible metrics
//   - You want built-in system and HTTP metrics
//   - You're building a production service and need monitoring
//
// Note: This automatically creates and registers a metrics endpoint.
// For custom metrics, use WithMetrics() instead.
func WithDefaultMetrics(path ...string) Option {
	return func(op *Options) {
		op.EnableDefaultMetrics = true
		op.Metrics = newBuiltinMetrics()
		if len(path) > 0 {
			op.MetricsPath = path[0]
		}
	}
}

// WithMetricsDefault is an alias for WithDefaultMetrics.
// It enables the default built-in metrics endpoint with Prometheus-compatible output.
//
// This function provides an alternative naming convention that some developers may find
// more intuitive (WithMetricsDefault vs WithDefaultMetrics).
//
// Example:
//
//	// These are equivalent:
//	server := servex.New(servex.WithDefaultMetrics())
//	server := servex.New(servex.WithMetricsDefault())
//
//	// Both enable the /metrics endpoint
//	server := servex.New(servex.WithMetricsDefault("/stats"))
//
// See WithDefaultMetrics() for full documentation and available metrics.
func WithMetricsDefault(path ...string) Option {
	return WithDefaultMetrics(path...)
}

// WithMetricsAndDefault enables both custom metrics and the default built-in metrics simultaneously.
//
// This function combines your custom Metrics implementation with the built-in default metrics,
// calling both on each request. This is useful when you want to:
//   - Send metrics to your own monitoring system (e.g., custom Prometheus metrics)
//   - Keep the built-in /metrics endpoint for quick observability
//   - Have both detailed custom metrics and standard HTTP metrics
//
// Both metrics implementations will receive HandleRequest and HandleResponse calls for every request.
// The default metrics endpoint will still be available at the specified path (default: "/metrics").
//
// Example:
//
//	// Your custom Prometheus metrics
//	customMetrics := &MyPrometheusMetrics{
//		requestsTotal: prometheus.NewCounterVec(...),
//		// ... other custom metrics
//	}
//
//	// Enable both custom and default metrics
//	server := servex.New(
//		servex.WithMetricsAndDefault(customMetrics),
//	)
//	// Now both your custom metrics AND built-in metrics are active
//	// The /metrics endpoint shows the built-in metrics
//
//	// Custom path for built-in metrics
//	server := servex.New(
//		servex.WithMetricsAndDefault(customMetrics, "/stats"),
//	)
//
// Use cases:
//   - Gradual migration from built-in to custom metrics
//   - Running both systems in parallel for comparison
//   - Custom business metrics alongside standard HTTP metrics
//   - Different metrics for different monitoring systems
//
// Performance note: Both metrics implementations will be called on every request.
// Ensure both are optimized for high-frequency calls.
func WithMetricsAndDefault(customMetrics Metrics, path ...string) Option {
	return func(op *Options) {
		// Create built-in metrics
		defaultMetrics := newBuiltinMetrics()

		// Combine both metrics implementations
		op.Metrics = newCompositeMetrics(defaultMetrics, customMetrics)

		// Enable default metrics endpoint
		op.EnableDefaultMetrics = true
		if len(path) > 0 {
			op.MetricsPath = path[0]
		}
	}
}

// WithSecurityConfig sets the complete security headers configuration at once.
// This allows fine-grained control over all security headers applied to responses.
//
// Example:
//
//	securityConfig := servex.SecurityConfig{
//		Enabled: true,
//		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'",
//		XContentTypeOptions: "nosniff",
//		XFrameOptions: "DENY",
//		XXSSProtection: "1; mode=block",
//		StrictTransportSecurity: "max-age=31536000; includeSubDomains",
//	}
//
//	server := servex.New(servex.WithSecurityConfig(securityConfig))
//
// Use this when you need to configure multiple security headers at once
// or when loading configuration from files or environment variables.
