package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/maxbolgarin/servex"
)

// Static File Serving Example
//
// This example demonstrates how to serve static files using servex.
// Static file serving is essential for web applications that need to serve
// HTML, CSS, JavaScript, images, and other assets to browsers.
//
// Key concepts covered:
// - Basic static file serving
// - SPA (Single Page Application) mode
// - Combining static files with API routes
// - Cache control for performance optimization
// - Security considerations and best practices
// - URL prefix handling
// - Path exclusions for API routes

// To run this example:
// 1. Uncomment one of the example calls in runExample()
// 2. Run: go run static_example.go
// 3. Open your browser to the displayed URL
// 4. Press Ctrl+C to stop the server

// Main entry point - change this to main() when running as standalone
func runExample() {
	// Create a temporary directory structure to demonstrate file serving
	// In production, this would be your actual static assets directory
	tempDir, err := os.MkdirTemp("", "servex-static-demo")
	if err != nil {
		log.Fatal("Failed to create temp directory:", err)
	}
	defer os.RemoveAll(tempDir) // Cleanup after demo

	// Create a realistic directory structure with various file types
	setupDemoFiles(tempDir)

	// Run different examples to showcase various static file configurations
	// Uncomment the example you want to run:

	// Example 1: Basic static file serving (recommended starting point)
	basicStaticExample(tempDir)

	// Example 2: SPA mode for client-side routing applications
	// spaExample(tempDir)

	// Example 3: Static files combined with API endpoints
	// staticWithAPIExample(tempDir)

	// Example 4: Performance optimization with caching
	// staticWithCachingExample(tempDir)

	// Example 5: Advanced configuration with URL prefixes and exclusions
	// advancedStaticExample(tempDir)

	// Example 6: Security-focused configuration
	// secureStaticExample(tempDir)
}

// Example 1: Basic Static File Serving
//
// This is the simplest way to serve static files. All files in the directory
// will be served at their relative paths. For example:
// - /index.html serves tempDir/index.html
// - /css/style.css serves tempDir/css/style.css
// - /js/app.js serves tempDir/js/app.js
func basicStaticExample(dir string) {
	// Create server with basic static file configuration
	// WithStaticFiles(dir, prefix) enables static file serving
	// - dir: the directory containing your static files
	// - prefix: URL prefix (empty string serves from root)
	server, err := servex.New(
		servex.WithStaticFiles(dir, ""), // Serve from root path with no URL prefix
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// The server will now automatically serve any file found in the directory
	// Requests are handled with proper MIME type detection:
	// - .html files: text/html; charset=utf-8
	// - .css files: text/css; charset=utf-8
	// - .js files: application/javascript
	// - .json files: application/json
	// - .png/.jpg/.gif: appropriate image MIME types
	// - And many more...

	// Security features are built-in:
	// - Directory traversal protection (blocks ../ patterns)
	// - URL encoding attack prevention
	// - Files are only served from within the configured directory

	log.Printf("Basic static server running on http://localhost:8080")
	log.Printf("Available files:")
	log.Printf("  http://localhost:8080/index.html - Main page")
	log.Printf("  http://localhost:8080/css/style.css - Stylesheet")
	log.Printf("  http://localhost:8080/js/app.js - JavaScript")
	log.Printf("  http://localhost:8080/images/logo.png - Image")
	log.Printf("  http://localhost:8080/assets/data.json - JSON data")

	if err := server.Start(":8080", ""); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 2: SPA (Single Page Application) Mode
//
// SPA mode is designed for modern web applications that use client-side routing.
// When enabled, any request for a non-existent file will serve the index.html
// instead of returning 404. This allows client-side routers (React Router,
// Vue Router, etc.) to handle navigation.
func spaExample(dir string) {
	// Create server with SPA mode enabled
	// WithSPAMode(dir, indexFile) configures both static serving and SPA behavior
	// - dir: directory containing static files
	// - indexFile: the file to serve for non-existent routes (usually index.html)
	server, err := servex.New(
		servex.WithSPAMode(dir, "index.html"), // Enable SPA fallback to index.html
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// How SPA mode works:
	// 1. If the requested file exists (e.g., /js/app.js), serve it directly
	// 2. If the file doesn't exist but looks like an API route (/api/*), return 404
	// 3. For all other non-existent routes, serve the index.html file
	//
	// This allows your JavaScript application to handle routes like:
	// - /dashboard → serves index.html, client router handles /dashboard
	// - /user/profile → serves index.html, client router handles /user/profile
	// - /about → serves index.html, client router handles /about
	//
	// While still serving actual files:
	// - /js/app.js → serves the actual app.js file
	// - /css/style.css → serves the actual style.css file

	log.Printf("SPA server running on http://localhost:8081")
	log.Printf("Routes that serve index.html (for client-side routing):")
	log.Printf("  http://localhost:8081/ - Root page")
	log.Printf("  http://localhost:8081/dashboard - Client route")
	log.Printf("  http://localhost:8081/user/profile - Client route")
	log.Printf("  http://localhost:8081/about - Client route")
	log.Printf("Routes that serve actual files:")
	log.Printf("  http://localhost:8081/js/app.js - JavaScript file")
	log.Printf("  http://localhost:8081/css/style.css - CSS file")

	if err := server.Start(":8081", ""); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 3: Static Files with API Routes
//
// This example shows how to combine static file serving with API endpoints.
// API routes are automatically excluded from static file serving, ensuring
// that your API responses aren't overridden by static files.
func staticWithAPIExample(dir string) {
	// Create server with SPA mode for the frontend
	server, err := servex.New(
		servex.WithSPAMode(dir, "index.html"), // Frontend served via SPA mode
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Add API routes - these will be prioritized over static files
	// The static middleware automatically excludes common API patterns:
	// - /api/* - API endpoints
	// - /auth/* - Authentication endpoints
	// - /admin/* - Admin endpoints
	// - /ws/* - WebSocket endpoints

	// RESTful API endpoint for users
	server.GET("/api/users", func(w http.ResponseWriter, r *http.Request) {
		// Use servex context for convenient JSON responses
		servex.C(w, r).JSON(map[string]interface{}{
			"users": []map[string]string{
				{"id": "1", "name": "Alice", "email": "alice@example.com"},
				{"id": "2", "name": "Bob", "email": "bob@example.com"},
				{"id": "3", "name": "Charlie", "email": "charlie@example.com"},
			},
			"total": 3,
		})
	})

	// Health check endpoint for monitoring
	server.GET("/api/health", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]string{
			"status":    "healthy",
			"service":   "static-demo",
			"version":   "1.0.0",
			"timestamp": "2024-01-01T00:00:00Z",
		})
	})

	// Authentication endpoint example
	server.POST("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		// In a real application, you'd validate credentials here
		servex.C(w, r).JSON(map[string]interface{}{
			"token":   "demo-jwt-token",
			"expires": "2024-01-02T00:00:00Z",
			"user": map[string]string{
				"id":   "1",
				"name": "Demo User",
			},
		})
	})

	// How request routing works:
	// 1. API routes (/api/*, /auth/*) are handled by the defined handlers
	// 2. Static files (*.js, *.css, etc.) are served directly
	// 3. Other routes fall back to index.html for SPA handling
	//
	// This creates a seamless full-stack application where:
	// - Your frontend can make API calls to /api/* endpoints
	// - Static assets are served efficiently
	// - Client-side routing works for all other paths

	log.Printf("Full-stack server running on http://localhost:8082")
	log.Printf("API endpoints:")
	log.Printf("  GET http://localhost:8082/api/users - User list")
	log.Printf("  GET http://localhost:8082/api/health - Health check")
	log.Printf("  POST http://localhost:8082/auth/login - Login")
	log.Printf("Frontend routes (serve index.html):")
	log.Printf("  http://localhost:8082/ - Home page")
	log.Printf("  http://localhost:8082/dashboard - Dashboard")
	log.Printf("Static assets:")
	log.Printf("  http://localhost:8082/js/app.js - Application code")
	log.Printf("  http://localhost:8082/css/style.css - Styles")

	if err := server.Start(":8082", ""); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 4: Performance Optimization with Caching
//
// Proper caching is crucial for web application performance. This example
// shows how to configure cache headers for different file types to optimize
// loading times and reduce server load.
func staticWithCachingExample(dir string) {
	// Create server with comprehensive caching configuration
	server, err := servex.New(
		servex.WithStaticFiles(dir, ""), // Basic static file serving
		servex.WithStaticFileCache(
			3600, // Default cache duration: 1 hour (3600 seconds)
			map[string]int{
				// Long-term caching for assets that rarely change
				// These should have versioned filenames in production (e.g., app.v1.2.3.js)
				".js":    31536000, // JavaScript: 1 year (365 * 24 * 60 * 60)
				".css":   31536000, // CSS: 1 year
				".woff":  31536000, // Web fonts: 1 year
				".woff2": 31536000,

				// Medium-term caching for images
				".png":  2592000, // Images: 30 days (30 * 24 * 60 * 60)
				".jpg":  2592000,
				".jpeg": 2592000,
				".gif":  2592000,
				".svg":  2592000,
				".ico":  2592000, // Favicon

				// Short-term caching for content that might change
				".html": 300,  // HTML: 5 minutes (5 * 60)
				".json": 60,   // JSON data: 1 minute
				".xml":  300,  // XML: 5 minutes
				".txt":  1800, // Text files: 30 minutes

				// No caching for specific files
				"/api/*":             0, // API responses shouldn't be cached by default
				"/health":            0, // Health checks need real-time data
				"/service-worker.js": 0, // Service workers need immediate updates
			},
		),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Cache headers automatically added:
	// - Cache-Control: public, max-age=<seconds>
	// - Expires: <calculated future date>
	// - ETag: <file identifier for conditional requests>
	//
	// Benefits of proper caching:
	// - Reduced server load (fewer requests for cached files)
	// - Faster page loads for users (files served from browser cache)
	// - Lower bandwidth usage
	// - Better user experience, especially on slower connections
	//
	// Best practices implemented:
	// - Long cache for versioned assets (JS/CSS with version in filename)
	// - Short cache for HTML (allows quick updates to reference new asset versions)
	// - Medium cache for images (good balance of performance and freshness)
	// - No cache for dynamic content and APIs

	log.Printf("Cached static server running on http://localhost:8083")
	log.Printf("Files served with optimized cache headers:")
	log.Printf("  http://localhost:8083/index.html - 5 minute cache")
	log.Printf("  http://localhost:8083/js/app.js - 1 year cache")
	log.Printf("  http://localhost:8083/css/style.css - 1 year cache")
	log.Printf("  http://localhost:8083/images/logo.png - 30 day cache")
	log.Printf("  http://localhost:8083/assets/data.json - 1 minute cache")
	log.Printf("Check browser dev tools Network tab to see cache headers")

	if err := server.Start(":8083", ""); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 5: Advanced Configuration with URL Prefixes and Exclusions
//
// This example demonstrates advanced static file serving features including
// URL prefixes and custom path exclusions for complex application architectures.
func advancedStaticExample(dir string) {
	// Create server with advanced static file configuration
	server, err := servex.New(
		// Serve static files under the /static URL prefix
		// This means files will be available at /static/* instead of /*
		servex.WithStaticFileConfig(servex.StaticFileConfig{
			Enabled:   true,
			Dir:       dir,          // Source directory
			URLPrefix: "/static",    // URL prefix for all static files
			SPAMode:   false,        // Disable SPA mode for this example
			IndexFile: "index.html", // Default index file
			ExcludePaths: []string{ // Paths to exclude from static serving
				"/api/*",      // API endpoints
				"/admin/*",    // Admin interface
				"/auth/*",     // Authentication
				"/webhook/*",  // Webhook endpoints
				"/internal/*", // Internal services
			},
			CacheMaxAge: 7200, // 2 hours default cache
			CacheRules: map[string]int{
				".js":  86400, // JavaScript: 1 day
				".css": 86400, // CSS: 1 day
			},
		}),
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Add routes that demonstrate the exclusion system
	server.GET("/api/config", func(w http.ResponseWriter, r *http.Request) {
		servex.C(w, r).JSON(map[string]string{
			"api_version": "v1",
			"environment": "development",
		})
	})

	server.GET("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Admin Dashboard - Not served by static middleware"))
	})

	// How URL prefixes work:
	// - Files are served under the specified prefix: /static/
	// - Original file: tempDir/index.html → URL: /static/index.html
	// - Original file: tempDir/js/app.js → URL: /static/js/app.js
	//
	// Benefits of URL prefixes:
	// - Clear separation between static assets and application routes
	// - Easier to configure CDN or reverse proxy rules
	// - Better organization in complex applications
	// - Allows serving multiple static directories with different prefixes

	log.Printf("Advanced static server running on http://localhost:8084")
	log.Printf("Static files served under /static prefix:")
	log.Printf("  http://localhost:8084/static/index.html")
	log.Printf("  http://localhost:8084/static/js/app.js")
	log.Printf("  http://localhost:8084/static/css/style.css")
	log.Printf("Application routes (excluded from static serving):")
	log.Printf("  http://localhost:8084/api/config")
	log.Printf("  http://localhost:8084/admin/dashboard")

	if err := server.Start(":8084", ""); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Example 6: Security-Focused Configuration
//
// This example emphasizes security best practices for static file serving,
// including proper headers and additional protections.
func secureStaticExample(dir string) {
	// Create server with security-focused configuration
	server, err := servex.New(
		servex.WithStaticFiles(dir, ""),

		// Add security middleware (if available in your servex version)
		// servex.WithSecurity(...), // Security headers, CSRF protection, etc.
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Add security headers middleware manually for this example
	server.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Security headers for static content
			w.Header().Set("X-Content-Type-Options", "nosniff") // Prevent MIME sniffing
			w.Header().Set("X-Frame-Options", "DENY")           // Prevent clickjacking
			w.Header().Set("X-XSS-Protection", "1; mode=block") // XSS protection
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			// Content Security Policy for static HTML files
			if r.URL.Path == "/" || r.URL.Path == "/index.html" {
				w.Header().Set("Content-Security-Policy",
					"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';")
			}

			next.ServeHTTP(w, r)
		})
	})

	// Security features built into servex static middleware:
	// 1. Directory traversal protection - blocks ../ patterns and variants
	// 2. Path validation - ensures files are within the configured directory
	// 3. URL encoding attack prevention - handles various encoding schemes
	// 4. File type restrictions - only serves files, not directories
	// 5. Safe MIME type detection - prevents malicious content-type issues
	//
	// Additional security considerations:
	// - Use HTTPS in production
	// - Implement proper authentication for sensitive areas
	// - Regular security audits of served content
	// - Monitor for suspicious access patterns
	// - Consider implementing rate limiting for static assets

	log.Printf("Secure static server running on http://localhost:8085")
	log.Printf("Security features enabled:")
	log.Printf("  - Directory traversal protection")
	log.Printf("  - Security headers (X-Content-Type-Options, X-Frame-Options, etc.)")
	log.Printf("  - Content Security Policy for HTML files")
	log.Printf("  - MIME type validation")
	log.Printf("Test security with these URLs:")
	log.Printf("  http://localhost:8085/index.html - Legitimate file")
	log.Printf("  http://localhost:8085/../../../etc/passwd - Blocked (directory traversal)")
	log.Printf("  http://localhost:8085/%2E%2E/secret.txt - Blocked (encoded traversal)")

	if err := server.Start(":8085", ""); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// setupDemoFiles creates a realistic directory structure with various file types
// This simulates a typical web application's static asset organization
func setupDemoFiles(baseDir string) {
	// Create directory structure
	dirs := []string{
		"css",
		"js",
		"images",
		"assets",
		"fonts",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(baseDir, dir), 0755); err != nil {
			log.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	// Create realistic file content
	files := map[string]string{
		"index.html": `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Servex Static File Demo</title>
    <link rel="stylesheet" href="/css/style.css">
    <link rel="icon" href="/images/favicon.ico">
</head>
<body>
    <header>
        <h1>Welcome to Servex Static File Demo</h1>
        <nav>
            <a href="/">Home</a>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
        </nav>
    </header>
    <main>
        <h2>Features Demonstrated:</h2>
        <ul>
            <li>Static file serving with proper MIME types</li>
            <li>SPA mode for client-side routing</li>
            <li>API integration</li>
            <li>Caching strategies</li>
            <li>Security best practices</li>
        </ul>
    </main>
    <script src="/js/app.js"></script>
</body>
</html>`,

		"css/style.css": `/* Modern CSS for the demo application */
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.6;
    color: #333;
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 2rem;
    border-radius: 8px;
    margin-bottom: 2rem;
}

nav a {
    color: white;
    text-decoration: none;
    margin-right: 1rem;
    padding: 0.5rem 1rem;
    border-radius: 4px;
    transition: background-color 0.3s;
}

nav a:hover {
    background-color: rgba(255, 255, 255, 0.2);
}

main {
    background: white;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}`,

		"js/app.js": `// Demo JavaScript application
console.log('Servex static file demo loaded successfully!');

// Simulate a modern JavaScript application
class DemoApp {
    constructor() {
        this.init();
    }

    init() {
        console.log('Demo app initialized');
        this.setupEventListeners();
        this.loadData();
    }

    setupEventListeners() {
        document.addEventListener('DOMContentLoaded', () => {
            console.log('DOM ready');
            this.highlightCurrentPage();
        });
    }

    async loadData() {
        try {
            // Example API call (if API routes are available)
            const response = await fetch('/api/users');
            if (response.ok) {
                const data = await response.json();
                console.log('Loaded user data:', data);
            }
        } catch (error) {
            console.log('API not available or error:', error.message);
        }
    }

    highlightCurrentPage() {
        const currentPath = window.location.pathname;
        const navLinks = document.querySelectorAll('nav a');
        
        navLinks.forEach(link => {
            if (link.getAttribute('href') === currentPath) {
                link.style.backgroundColor = 'rgba(255, 255, 255, 0.3)';
            }
        });
    }
}

// Initialize the app
new DemoApp();`,

		"assets/data.json": `{
    "application": {
        "name": "Servex Static Demo",
        "version": "1.0.0",
        "description": "Demonstration of static file serving capabilities"
    },
    "features": [
        "Static file serving",
        "SPA mode support", 
        "Cache optimization",
        "Security protection",
        "API integration"
    ],
    "configuration": {
        "caching_enabled": true,
        "spa_mode": true,
        "security_headers": true
    }
}`,

		"images/favicon.ico": "fake-favicon-data", // In reality, this would be binary data
		"images/logo.png":    "fake-png-data",     // In reality, this would be binary data
		"fonts/demo.woff2":   "fake-font-data",    // In reality, this would be binary data
	}

	// Write all demo files
	for filename, content := range files {
		path := filepath.Join(baseDir, filename)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			log.Fatalf("Failed to create file %s: %v", path, err)
		}
	}

	log.Printf("Demo files created in: %s", baseDir)
}
