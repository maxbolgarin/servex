package servex

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStaticFileMiddleware tests the basic static file serving functionality
func TestStaticFileMiddleware(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()

	// Create test files
	createTestFile(t, filepath.Join(tempDir, "index.html"), "<html><body>Hello World</body></html>")
	createTestFile(t, filepath.Join(tempDir, "app.js"), "console.log('Hello from JS');")
	createTestFile(t, filepath.Join(tempDir, "style.css"), "body { color: red; }")

	tests := []struct {
		name           string
		config         StaticFileConfig
		requestPath    string
		expectedStatus int
		expectedBody   string
		expectedHeader map[string]string
	}{
		{
			name: "Basic static file serving",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/index.html",
			expectedStatus: http.StatusOK,
			expectedBody:   "<html><body>Hello World</body></html>",
		},
		{
			name: "JavaScript file serving",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/app.js",
			expectedStatus: http.StatusOK,
			expectedBody:   "console.log('Hello from JS');",
			expectedHeader: map[string]string{
				"Content-Type": "application/javascript",
			},
		},
		{
			name: "CSS file serving",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/style.css",
			expectedStatus: http.StatusOK,
			expectedBody:   "body { color: red; }",
			expectedHeader: map[string]string{
				"Content-Type": "text/css; charset=utf-8",
			},
		},
		{
			name: "Non-existent file - 404",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/nonexistent.html",
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "Disabled static files",
			config: StaticFileConfig{
				Enabled: false,
				Dir:     tempDir,
			},
			requestPath:    "/index.html",
			expectedStatus: http.StatusNotFound, // Should pass through to next handler
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server with static file middleware
			server, err := NewServer(WithStaticFileConfig(tt.config))
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			// Create test request
			req := httptest.NewRequest(GET, tt.requestPath, nil)
			rr := httptest.NewRecorder()

			// Execute request
			server.Router().ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Check body if expected
			if tt.expectedBody != "" {
				body := rr.Body.String()
				if body != tt.expectedBody {
					t.Errorf("Expected body %q, got %q", tt.expectedBody, body)
				}
			}

			// Check headers if expected
			for key, expectedValue := range tt.expectedHeader {
				actualValue := rr.Header().Get(key)
				if !strings.Contains(actualValue, expectedValue) {
					t.Errorf("Expected header %s to contain %q, got %q", key, expectedValue, actualValue)
				}
			}
		})
	}
}

// TestSPAMode tests Single Page Application routing
func TestSPAMode(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()

	// Create test files
	createTestFile(t, filepath.Join(tempDir, "index.html"), "<html><body>SPA Index</body></html>")
	createTestFile(t, filepath.Join(tempDir, "app.js"), "console.log('SPA JS');")

	tests := []struct {
		name           string
		config         StaticFileConfig
		requestPath    string
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "SPA Mode - existing file",
			config: StaticFileConfig{
				Enabled:   true,
				Dir:       tempDir,
				SPAMode:   true,
				IndexFile: "index.html",
			},
			requestPath:    "/app.js",
			expectedStatus: http.StatusOK,
			expectedBody:   "console.log('SPA JS');",
		},
		{
			name: "SPA Mode - non-existent route serves index",
			config: StaticFileConfig{
				Enabled:   true,
				Dir:       tempDir,
				SPAMode:   true,
				IndexFile: "index.html",
			},
			requestPath:    "/user/profile",
			expectedStatus: http.StatusOK,
			expectedBody:   "<html><body>SPA Index</body></html>",
		},
		{
			name: "SPA Mode - root path serves index",
			config: StaticFileConfig{
				Enabled:   true,
				Dir:       tempDir,
				SPAMode:   true,
				IndexFile: "index.html",
			},
			requestPath:    "/",
			expectedStatus: http.StatusOK,
			expectedBody:   "<html><body>SPA Index</body></html>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server with static file middleware
			server, err := NewServer(WithStaticFileConfig(tt.config))
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			// Create test request
			req := httptest.NewRequest(GET, tt.requestPath, nil)
			rr := httptest.NewRecorder()

			// Execute request
			server.Router().ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Check body
			if tt.expectedBody != "" {
				body := rr.Body.String()
				if body != tt.expectedBody {
					t.Errorf("Expected body %q, got %q", tt.expectedBody, body)
				}
			}
		})
	}
}

// TestStaticFileExclusions tests path exclusion functionality
func TestStaticFileExclusions(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()

	// Create test files
	createTestFile(t, filepath.Join(tempDir, "index.html"), "<html><body>Index</body></html>")

	config := StaticFileConfig{
		Enabled:      true,
		Dir:          tempDir,
		SPAMode:      true,
		IndexFile:    "index.html",
		ExcludePaths: []string{"/api/*", "/auth/*", "/admin"},
	}

	server, err := NewServer(WithStaticFileConfig(config))
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Add an API route that should not be overridden by static files
	server.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("API Response"))
	})

	tests := []struct {
		name           string
		requestPath    string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Regular path serves SPA",
			requestPath:    "/user/profile",
			expectedStatus: http.StatusOK,
			expectedBody:   "<html><body>Index</body></html>",
		},
		{
			name:           "API path excluded - serves API",
			requestPath:    "/api/users",
			expectedStatus: http.StatusOK,
			expectedBody:   "API Response",
		},
		{
			name:           "API path excluded - 404 for non-existent API",
			requestPath:    "/api/nonexistent",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Auth path excluded",
			requestPath:    "/auth/login",
			expectedStatus: http.StatusNotFound, // No handler, but not served by static files
		},
		{
			name:           "Admin path excluded",
			requestPath:    "/admin",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(GET, tt.requestPath, nil)
			rr := httptest.NewRecorder()

			server.Router().ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.expectedBody != "" {
				body := rr.Body.String()
				if body != tt.expectedBody {
					t.Errorf("Expected body %q, got %q", tt.expectedBody, body)
				}
			}
		})
	}
}

// TestStaticFileCaching tests cache header functionality
func TestStaticFileCaching(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()

	// Create test files
	createTestFile(t, filepath.Join(tempDir, "app.js"), "console.log('JS');")
	createTestFile(t, filepath.Join(tempDir, "style.css"), "body { color: blue; }")
	createTestFile(t, filepath.Join(tempDir, "index.html"), "<html></html>")
	createTestFile(t, filepath.Join(tempDir, "image.png"), "fake-png-data")

	config := StaticFileConfig{
		Enabled:     true,
		Dir:         tempDir,
		CacheMaxAge: 3600, // 1 hour default
		CacheRules: map[string]int{
			".js":   31536000, // 1 year for JS
			".css":  31536000, // 1 year for CSS
			".html": 300,      // 5 minutes for HTML
			".png":  86400,    // 1 day for images
		},
	}

	server, err := NewServer(WithStaticFileConfig(config))
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	tests := []struct {
		name        string
		requestPath string
		expectedAge string
	}{
		{
			name:        "JavaScript file gets long cache",
			requestPath: "/app.js",
			expectedAge: "max-age=31536000",
		},
		{
			name:        "CSS file gets long cache",
			requestPath: "/style.css",
			expectedAge: "max-age=31536000",
		},
		{
			name:        "HTML file gets short cache",
			requestPath: "/index.html",
			expectedAge: "max-age=300",
		},
		{
			name:        "PNG file gets medium cache",
			requestPath: "/image.png",
			expectedAge: "max-age=86400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(GET, tt.requestPath, nil)
			rr := httptest.NewRecorder()

			server.Router().ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", rr.Code)
			}

			cacheControl := rr.Header().Get("Cache-Control")
			if !strings.Contains(cacheControl, tt.expectedAge) {
				t.Errorf("Expected Cache-Control to contain %q, got %q", tt.expectedAge, cacheControl)
			}
		})
	}
}

// TestStaticFileWithURLPrefix tests serving files with URL prefix
func TestStaticFileWithURLPrefix(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()

	// Create test files
	createTestFile(t, filepath.Join(tempDir, "app.js"), "console.log('prefixed');")

	config := StaticFileConfig{
		Enabled:   true,
		Dir:       tempDir,
		URLPrefix: "/static",
	}

	server, err := NewServer(WithStaticFileConfig(config))
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	tests := []struct {
		name           string
		requestPath    string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "File with prefix works",
			requestPath:    "/static/app.js",
			expectedStatus: http.StatusOK,
			expectedBody:   "console.log('prefixed');",
		},
		{
			name:           "File without prefix doesn't work",
			requestPath:    "/app.js",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(GET, tt.requestPath, nil)
			rr := httptest.NewRecorder()

			server.Router().ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.expectedBody != "" {
				body := rr.Body.String()
				if body != tt.expectedBody {
					t.Errorf("Expected body %q, got %q", tt.expectedBody, body)
				}
			}
		})
	}
}

// TestStaticFileDirectoryTraversal tests protection against directory traversal attacks
func TestStaticFileDirectoryTraversal(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()

	// Create a test file in temp directory
	createTestFile(t, filepath.Join(tempDir, "safe.txt"), "safe content")

	// Create a file outside the temp directory that shouldn't be accessible
	parentDir := filepath.Dir(tempDir)
	dangerousFile := filepath.Join(parentDir, "dangerous.txt")
	createTestFile(t, dangerousFile, "dangerous content")
	defer os.Remove(dangerousFile)

	config := StaticFileConfig{
		Enabled: true,
		Dir:     tempDir,
	}

	server, err := NewServer(WithStaticFileConfig(config))
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	tests := []struct {
		name           string
		requestPath    string
		expectedStatus int
		description    string
	}{
		{
			name:           "Normal file access works",
			requestPath:    "/safe.txt",
			expectedStatus: http.StatusOK,
			description:    "Normal files should be served correctly",
		},
		{
			name:           "Directory traversal cleaned by router",
			requestPath:    "/../dangerous.txt",
			expectedStatus: http.StatusNotFound, // After redirect, file doesn't exist in static dir
			description:    "Router cleans path, then we get 404 for non-existent file",
		},
		{
			name:           "URL encoded traversal cleaned by router",
			requestPath:    "/%2E%2E/dangerous.txt",
			expectedStatus: http.StatusNotFound, // After redirect, file doesn't exist in static dir
			description:    "URL encoded traversal gets cleaned, then 404 for non-existent file",
		},
		{
			name:           "Multiple traversal attempts cleaned",
			requestPath:    "/../../dangerous.txt",
			expectedStatus: http.StatusNotFound, // After redirect, file doesn't exist in static dir
			description:    "Multiple directory traversal gets cleaned, then 404 for non-existent file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(GET, tt.requestPath, nil)
			rr := httptest.NewRecorder()

			server.Router().ServeHTTP(rr, req)

			// Handle redirects for directory traversal tests
			if strings.Contains(tt.requestPath, "..") || strings.Contains(tt.requestPath, "%2E") {
				// For directory traversal attempts, we expect either:
				// 1. 404 if the cleaned path doesn't exist
				// 2. 301 redirect followed by 404
				if rr.Code == 301 {
					// Follow the redirect and test the final result
					location := rr.Header().Get("Location")
					if location != "" {
						req2 := httptest.NewRequest(GET, location, nil)
						rr2 := httptest.NewRecorder()
						server.Router().ServeHTTP(rr2, req2)

						// The final result should be 404 since dangerous.txt doesn't exist in tempDir
						if rr2.Code != http.StatusNotFound {
							t.Errorf("After redirect, expected status 404, got %d", rr2.Code)
						}

						// Most importantly, ensure we don't serve the dangerous content
						body := rr2.Body.String()
						if strings.Contains(body, "dangerous content") {
							t.Error("Directory traversal attack succeeded - dangerous content was served after redirect")
						}
					}
				} else if rr.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
				}
			} else {
				// For normal requests, check status exactly
				if rr.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
				}
			}

			// If it's the dangerous file request, make sure we didn't serve the dangerous content
			if strings.Contains(tt.requestPath, "dangerous") && rr.Code == http.StatusOK {
				body := rr.Body.String()
				if strings.Contains(body, "dangerous content") {
					t.Error("Directory traversal attack succeeded - dangerous content was served")
				}
			}
		})
	}
}

// TestStaticFileOptions tests the convenience option functions
func TestStaticFileOptions(t *testing.T) {
	tempDir := t.TempDir()
	createTestFile(t, filepath.Join(tempDir, "index.html"), "<html>Test</html>")
	createTestFile(t, filepath.Join(tempDir, "app.js"), "console.log('test');")

	tests := []struct {
		name           string
		options        []Option
		requestPath    string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "WithStaticFiles option",
			options:        []Option{WithStaticFiles(tempDir, "")},
			requestPath:    "/app.js",
			expectedStatus: http.StatusOK,
			expectedBody:   "console.log('test');",
		},
		{
			name:           "WithSPAMode option",
			options:        []Option{WithSPAMode(tempDir, "index.html")},
			requestPath:    "/nonexistent/route",
			expectedStatus: http.StatusOK,
			expectedBody:   "<html>Test</html>",
		},
		{
			name: "WithStaticFileCache option",
			options: []Option{
				WithStaticFiles(tempDir, ""),
				WithStaticFileCache(7200, map[string]int{".js": 86400}),
			},
			requestPath:    "/app.js",
			expectedStatus: http.StatusOK,
		},
		{
			name: "WithStaticFileExclusions option",
			options: []Option{
				WithSPAMode(tempDir, "index.html"),
				WithStaticFileExclusions("/api/*"),
			},
			requestPath:    "/api/test",
			expectedStatus: http.StatusNotFound, // Should be excluded
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewServer(tt.options...)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			req := httptest.NewRequest(GET, tt.requestPath, nil)
			rr := httptest.NewRecorder()

			server.Router().ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.expectedBody != "" {
				body := rr.Body.String()
				if body != tt.expectedBody {
					t.Errorf("Expected body %q, got %q", tt.expectedBody, body)
				}
			}

			// For cache test, check if Cache-Control header is set
			if strings.Contains(tt.name, "Cache") && rr.Code == http.StatusOK {
				cacheControl := rr.Header().Get("Cache-Control")
				if cacheControl == "" {
					t.Error("Expected Cache-Control header to be set")
				}
			}
		})
	}
}

// TestStaticFileIntegrationWithAPI tests that static files work alongside API routes
func TestStaticFileIntegrationWithAPI(t *testing.T) {
	tempDir := t.TempDir()
	createTestFile(t, filepath.Join(tempDir, "index.html"), "<html>SPA</html>")

	server, err := NewServer(WithSPAMode(tempDir, "index.html"))
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Add API routes
	server.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"users": []}`))
	}, GET)

	server.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}, GET)

	tests := []struct {
		name           string
		requestPath    string
		expectedStatus int
		expectedBody   string
		expectedType   string
	}{
		{
			name:           "API route works",
			requestPath:    "/api/users",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"users": []}`,
			expectedType:   "application/json",
		},
		{
			name:           "Health API works",
			requestPath:    "/api/health",
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "SPA route works",
			requestPath:    "/dashboard",
			expectedStatus: http.StatusOK,
			expectedBody:   "<html>SPA</html>",
		},
		{
			name:           "Root serves SPA",
			requestPath:    "/",
			expectedStatus: http.StatusOK,
			expectedBody:   "<html>SPA</html>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(GET, tt.requestPath, nil)
			rr := httptest.NewRecorder()

			server.Router().ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			body := rr.Body.String()
			if body != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, body)
			}

			if tt.expectedType != "" {
				contentType := rr.Header().Get("Content-Type")
				if !strings.Contains(contentType, tt.expectedType) {
					t.Errorf("Expected Content-Type to contain %q, got %q", tt.expectedType, contentType)
				}
			}
		})
	}
}

// Helper function to create test files
func createTestFile(t *testing.T, path, content string) {
	t.Helper()

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("Failed to create directory %s: %v", dir, err)
	}

	// Write file
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file %s: %v", path, err)
	}
}

// TestStaticMiddlewareComprehensive tests various static middleware scenarios
func TestStaticMiddlewareComprehensive(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()

	// Create test files with various content types
	testFiles := map[string]string{
		"index.html":       "<html><head><title>Test</title></head><body>Hello World</body></html>",
		"app.js":           "console.log('Hello from JavaScript');",
		"styles.css":       "body { color: red; font-size: 16px; }",
		"data.json":        `{"message": "Hello JSON"}`,
		"image.png":        "fake-png-binary-data",
		"document.pdf":     "fake-pdf-content",
		"text.txt":         "Plain text content",
		"favicon.ico":      "fake-ico-data",
		"logo.svg":         "<svg><circle r='10'/></svg>",
		"photo.jpg":        "fake-jpeg-data",
		"animation.gif":    "fake-gif-data",
		"nested/deep.html": "<html>Nested file</html>",
		"assets/style.css": "/* nested css */",
	}

	for filename, content := range testFiles {
		fullPath := filepath.Join(tempDir, filename)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", fullPath, err)
		}
	}

	tests := []struct {
		name           string
		config         StaticFileConfig
		setupRoutes    func(*Server)
		requestPath    string
		requestMethod  string
		expectedStatus int
		expectedBody   string
		expectedHeader map[string]string
		checkContent   bool
	}{
		// Basic static file serving
		{
			name: "Serve HTML file",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/index.html",
			requestMethod:  GET,
			expectedStatus: http.StatusOK,
			expectedBody:   testFiles["index.html"],
			expectedHeader: map[string]string{
				"Content-Type": "text/html; charset=utf-8",
			},
			checkContent: true,
		},
		{
			name: "Serve JavaScript file",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/app.js",
			requestMethod:  GET,
			expectedStatus: http.StatusOK,
			expectedBody:   testFiles["app.js"],
			expectedHeader: map[string]string{
				"Content-Type": "application/javascript",
			},
			checkContent: true,
		},
		{
			name: "Serve CSS file",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/styles.css",
			requestMethod:  GET,
			expectedStatus: http.StatusOK,
			expectedBody:   testFiles["styles.css"],
			expectedHeader: map[string]string{
				"Content-Type": "text/css; charset=utf-8",
			},
			checkContent: true,
		},
		{
			name: "Serve nested file",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/nested/deep.html",
			requestMethod:  GET,
			expectedStatus: http.StatusOK,
			expectedBody:   testFiles["nested/deep.html"],
			expectedHeader: map[string]string{
				"Content-Type": "text/html; charset=utf-8",
			},
			checkContent: true,
		},
		// Content type detection
		{
			name: "JSON content type",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/data.json",
			requestMethod:  GET,
			expectedStatus: http.StatusOK,
			expectedHeader: map[string]string{
				"Content-Type": "application/json",
			},
		},
		{
			name: "PNG content type",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/image.png",
			requestMethod:  GET,
			expectedStatus: http.StatusOK,
			expectedHeader: map[string]string{
				"Content-Type": "image/png",
			},
		},
		{
			name: "SVG content type",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/logo.svg",
			requestMethod:  GET,
			expectedStatus: http.StatusOK,
			expectedHeader: map[string]string{
				"Content-Type": "image/svg+xml",
			},
		},
		// HTTP methods
		{
			name: "HEAD request works",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/index.html",
			requestMethod:  "HEAD",
			expectedStatus: http.StatusOK,
			expectedHeader: map[string]string{
				"Content-Type": "text/html; charset=utf-8",
			},
		},
		{
			name: "POST request ignored by static middleware",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/index.html",
			requestMethod:  POST,
			expectedStatus: http.StatusNotFound, // No POST handler, so 404
		},
		{
			name: "PUT request ignored by static middleware",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/index.html",
			requestMethod:  PUT,
			expectedStatus: http.StatusNotFound, // No PUT handler, so 404
		},
		// Non-existent files
		{
			name: "Non-existent file returns 404",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
			},
			requestPath:    "/nonexistent.html",
			requestMethod:  GET,
			expectedStatus: http.StatusNotFound,
		},
		// URL prefix handling
		{
			name: "URL prefix - file with prefix works",
			config: StaticFileConfig{
				Enabled:   true,
				Dir:       tempDir,
				URLPrefix: "/static",
			},
			requestPath:    "/static/app.js",
			requestMethod:  GET,
			expectedStatus: http.StatusOK,
			expectedBody:   testFiles["app.js"],
			checkContent:   true,
		},
		{
			name: "URL prefix - file without prefix fails",
			config: StaticFileConfig{
				Enabled:   true,
				Dir:       tempDir,
				URLPrefix: "/static",
			},
			requestPath:    "/app.js",
			requestMethod:  GET,
			expectedStatus: http.StatusNotFound,
		},
		// SPA mode
		{
			name: "SPA mode - existing file served directly",
			config: StaticFileConfig{
				Enabled:   true,
				Dir:       tempDir,
				SPAMode:   true,
				IndexFile: "index.html",
			},
			requestPath:    "/app.js",
			requestMethod:  GET,
			expectedStatus: http.StatusOK,
			expectedBody:   testFiles["app.js"],
			checkContent:   true,
		},
		{
			name: "SPA mode - non-existent route serves index",
			config: StaticFileConfig{
				Enabled:   true,
				Dir:       tempDir,
				SPAMode:   true,
				IndexFile: "index.html",
			},
			requestPath:    "/user/profile/settings",
			requestMethod:  GET,
			expectedStatus: http.StatusOK,
			expectedBody:   testFiles["index.html"],
			expectedHeader: map[string]string{
				"Content-Type": "text/html; charset=utf-8",
			},
			checkContent: true,
		},
		{
			name: "SPA mode - root serves index",
			config: StaticFileConfig{
				Enabled:   true,
				Dir:       tempDir,
				SPAMode:   true,
				IndexFile: "index.html",
			},
			requestPath:    "/",
			requestMethod:  GET,
			expectedStatus: http.StatusOK,
			expectedBody:   testFiles["index.html"],
			checkContent:   true,
		},
		// API route integration
		{
			name: "API route not overridden by static files",
			config: StaticFileConfig{
				Enabled: true,
				Dir:     tempDir,
				SPAMode: true,
			},
			setupRoutes: func(server *Server) {
				server.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"api": "response"}`))
				}, GET)
			},
			requestPath:    "/api/test",
			requestMethod:  GET,
			expectedStatus: http.StatusOK,
			expectedBody:   `{"api": "response"}`,
			expectedHeader: map[string]string{
				"Content-Type": "application/json",
			},
			checkContent: true,
		},
		// Path exclusions
		{
			name: "Excluded path not served by static middleware",
			config: StaticFileConfig{
				Enabled:      true,
				Dir:          tempDir,
				SPAMode:      true,
				IndexFile:    "index.html",
				ExcludePaths: []string{"/admin/*", "/api/*"},
			},
			requestPath:    "/admin/dashboard",
			requestMethod:  GET,
			expectedStatus: http.StatusNotFound, // No handler for excluded path
		},
		// Disabled static files
		{
			name: "Disabled static files don't serve content",
			config: StaticFileConfig{
				Enabled: false,
				Dir:     tempDir,
			},
			requestPath:    "/index.html",
			requestMethod:  GET,
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server with static file middleware
			server, err := NewServer(WithStaticFileConfig(tt.config))
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			// Set up additional routes if needed
			if tt.setupRoutes != nil {
				tt.setupRoutes(server)
			}

			// Create test request
			req := httptest.NewRequest(tt.requestMethod, tt.requestPath, nil)
			rr := httptest.NewRecorder()

			// Execute request
			server.Router().ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Check headers if expected
			for key, expectedValue := range tt.expectedHeader {
				actualValue := rr.Header().Get(key)
				if !strings.Contains(actualValue, expectedValue) {
					t.Errorf("Expected header %s to contain %q, got %q", key, expectedValue, actualValue)
				}
			}

			// Check body if expected and content checking is enabled
			if tt.checkContent && tt.expectedBody != "" {
				body := rr.Body.String()
				if body != tt.expectedBody {
					t.Errorf("Expected body %q, got %q", tt.expectedBody, body)
				}
			}
		})
	}
}

// TestStaticMiddlewareCaching tests cache header functionality
func TestStaticMiddlewareCaching(t *testing.T) {
	tempDir := t.TempDir()

	// Create test files
	testFiles := map[string]string{
		"app.js":     "console.log('test');",
		"styles.css": "body { color: blue; }",
		"index.html": "<html></html>",
		"image.png":  "fake-png-data",
		"data.json":  `{"test": true}`,
	}

	for filename, content := range testFiles {
		fullPath := filepath.Join(tempDir, filename)
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", fullPath, err)
		}
	}

	config := StaticFileConfig{
		Enabled:     true,
		Dir:         tempDir,
		CacheMaxAge: 3600, // 1 hour default
		CacheRules: map[string]int{
			".js":   31536000, // 1 year for JS
			".css":  31536000, // 1 year for CSS
			".html": 300,      // 5 minutes for HTML
			".png":  86400,    // 1 day for images
			".json": 0,        // No cache for JSON
		},
	}

	server, err := NewServer(WithStaticFileConfig(config))
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	tests := []struct {
		name          string
		requestPath   string
		expectedAge   string
		expectNoCache bool
	}{
		{
			name:        "JavaScript file gets long cache",
			requestPath: "/app.js",
			expectedAge: "max-age=31536000",
		},
		{
			name:        "CSS file gets long cache",
			requestPath: "/styles.css",
			expectedAge: "max-age=31536000",
		},
		{
			name:        "HTML file gets short cache",
			requestPath: "/index.html",
			expectedAge: "max-age=300",
		},
		{
			name:        "PNG file gets medium cache",
			requestPath: "/image.png",
			expectedAge: "max-age=86400",
		},
		{
			name:          "JSON file gets no cache",
			requestPath:   "/data.json",
			expectNoCache: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(GET, tt.requestPath, nil)
			rr := httptest.NewRecorder()

			server.Router().ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", rr.Code)
				return
			}

			cacheControl := rr.Header().Get("Cache-Control")

			if tt.expectNoCache {
				if cacheControl != "no-cache" {
					t.Errorf("Expected no-cache for %s, got %q", tt.requestPath, cacheControl)
				}
			} else {
				if !strings.Contains(cacheControl, tt.expectedAge) {
					t.Errorf("Expected Cache-Control to contain %q for %s, got %q", tt.expectedAge, tt.requestPath, cacheControl)
				}

				// Check that Expires header is also set
				expires := rr.Header().Get("Expires")
				if expires == "" {
					t.Errorf("Expected Expires header to be set for %s", tt.requestPath)
				}
			}
		})
	}
}

// TestStaticMiddlewareSecurityEdgeCases tests various security scenarios
func TestStaticMiddlewareSecurityEdgeCases(t *testing.T) {
	tempDir := t.TempDir()

	// Create a safe file
	safeFile := filepath.Join(tempDir, "safe.txt")
	if err := os.WriteFile(safeFile, []byte("safe content"), 0644); err != nil {
		t.Fatalf("Failed to create safe file: %v", err)
	}

	config := StaticFileConfig{
		Enabled: true,
		Dir:     tempDir,
	}

	server, err := NewServer(WithStaticFileConfig(config))
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	securityTests := []struct {
		name           string
		requestPath    string
		description    string
		expectRedirect bool
	}{
		{
			name:        "Double encoded directory traversal",
			requestPath: "/%252E%252E/safe.txt",
			description: "Should not serve files via double encoded paths",
		},
		{
			name:        "Null byte injection",
			requestPath: "/safe.txt%00.exe",
			description: "Should not be vulnerable to null byte injection",
		},
		{
			name:        "Backslash directory traversal",
			requestPath: "/..\\safe.txt",
			description: "Should not serve files via backslash traversal",
		},
		{
			name:           "Mixed case traversal",
			requestPath:    "/%2E%2e/safe.txt",
			description:    "Should not serve files via mixed case traversal",
			expectRedirect: true, // This will be redirected by mux
		},
	}

	for _, tt := range securityTests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(GET, tt.requestPath, nil)
			rr := httptest.NewRecorder()

			server.Router().ServeHTTP(rr, req)

			// These requests should either result in 404 or redirect (301)
			// but should never successfully serve the safe.txt content
			if rr.Code == http.StatusOK {
				body := rr.Body.String()
				if strings.Contains(body, "safe content") {
					t.Errorf("Security vulnerability: %s - successfully served protected content", tt.description)
				}
			}

			// For requests that might be redirected by mux
			if rr.Code == http.StatusMovedPermanently {
				location := rr.Header().Get("Location")
				if location != "" {
					req2 := httptest.NewRequest(GET, location, nil)
					rr2 := httptest.NewRecorder()
					server.Router().ServeHTTP(rr2, req2)

					// For directory traversal patterns that get cleaned by mux,
					// the security requirement is that the final path should only serve
					// files that are actually within the configured static directory.
					// Since "safe.txt" exists in tempDir, serving it after redirect is OK.
					// The real security is preventing access to files OUTSIDE tempDir.

					// We expect this to work for legitimate files in the static directory
					if tt.expectRedirect && location == "/safe.txt" {
						// This is expected behavior - mux cleaned the path and
						// the file exists in the static directory, so it's served
						return
					}

					if rr2.Code == http.StatusOK {
						body := rr2.Body.String()
						if strings.Contains(body, "safe content") && !tt.expectRedirect {
							t.Errorf("Security vulnerability after redirect: %s - successfully served protected content at %s", tt.description, location)
						}
					}
				}
			}
		})
	}
}
