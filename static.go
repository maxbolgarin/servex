package servex

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// isDirectoryTraversalAttempt checks if a path contains directory traversal patterns
func isDirectoryTraversalAttempt(path string) bool {
	if path == "" {
		return false
	}

	// Check for common directory traversal patterns
	patterns := []string{
		"..",
		"%2e%2e",
		"%2E%2E",
		"%2e%2E", // Mixed case
		"%2E%2e", // Mixed case
		"%2e.",
		"%2E.",
		".%2e",
		".%2E",
		"..%2f",
		"..%2F",
		"%2e%2e%2f",
		"%2E%2E%2F",
		"%2e%2E%2f", // Mixed case
		"%2E%2e%2F", // Mixed case
		"..\\",
		"%2e%2e%5c",
		"%2E%2E%5C",
		"%2e%2E%5c", // Mixed case
		"%2E%2e%5C", // Mixed case
	}

	for _, pattern := range patterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}

	return false
}

// RegisterStaticFileMiddleware sets up static file serving middleware based on the configuration.
// This should be called after all API routes are registered but before starting the server.
// It returns a cleanup function that should be called when shutting down.
func RegisterStaticFileMiddleware(router MiddlewareRouter, cfg StaticFileConfig) {
	if !cfg.Enabled || cfg.Dir == "" {
		return
	}

	// Create the static file handler
	staticHandler := createStaticFileHandler(cfg)

	// For gorilla/mux, we need to use middleware that only handles 404s
	// This ensures API routes are handled first
	if muxRouter, ok := router.(*mux.Router); ok {

		// Use middleware that captures 404s and serves static files
		router.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Only handle GET and HEAD requests for static files
				if r.Method != http.MethodGet && r.Method != http.MethodHead {
					next.ServeHTTP(w, r)
					return
				}

				// Check if this path should be excluded from static file serving
				if shouldExcludeFromStatic(r.URL.Path, cfg.ExcludePaths) {
					next.ServeHTTP(w, r)
					return
				}

				// Create a response writer that captures the status code
				captureWriter := &staticResponseWriter{ResponseWriter: w}

				// Let other handlers try first
				next.ServeHTTP(captureWriter, r)

				// If we got a 404, try to serve static files
				if captureWriter.statusCode == 404 || captureWriter.statusCode == 0 {
					// Reset the response writer for static file serving
					// Create a new response writer that doesn't interfere with the original
					if captureWriter.bytesWritten == 0 {
						// Only serve static files if nothing was written yet
						if cfg.SPAMode {
							staticHandler.serveSPA(w, r, http.NotFoundHandler())
						} else {
							staticHandler.serveStatic(w, r, http.NotFoundHandler())
						}
					}
				}
			})
		})

		// Also set a custom NotFoundHandler as fallback
		originalNotFound := muxRouter.NotFoundHandler
		muxRouter.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only handle GET and HEAD requests for static files
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				if originalNotFound != nil {
					originalNotFound.ServeHTTP(w, r)
				} else {
					http.NotFound(w, r)
				}
				return
			}

			// Check if this path should be excluded from static file serving
			if shouldExcludeFromStatic(r.URL.Path, cfg.ExcludePaths) {
				if originalNotFound != nil {
					originalNotFound.ServeHTTP(w, r)
				} else {
					http.NotFound(w, r)
				}
				return
			}

			// Try to serve static file
			if cfg.SPAMode {
				staticHandler.serveSPA(w, r, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if originalNotFound != nil {
						originalNotFound.ServeHTTP(w, r)
					} else {
						http.NotFound(w, r)
					}
				}))
			} else {
				staticHandler.serveStatic(w, r, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if originalNotFound != nil {
						originalNotFound.ServeHTTP(w, r)
					} else {
						http.NotFound(w, r)
					}
				}))
			}
		})
		return
	}

	// For other router types, use middleware
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only handle GET and HEAD requests for static files
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}

			// Check if this path should be excluded from static file serving
			if shouldExcludeFromStatic(r.URL.Path, cfg.ExcludePaths) {
				next.ServeHTTP(w, r)
				return
			}

			// Try to serve static file
			if cfg.SPAMode {
				staticHandler.serveSPA(w, r, next)
			} else {
				staticHandler.serveStatic(w, r, next)
			}
		})
	})
}

// staticFileHandler handles static file serving with optional SPA support
type staticFileHandler struct {
	config     StaticFileConfig
	fileServer http.Handler
	indexPath  string
}

// createStaticFileHandler creates a new static file handler based on configuration
func createStaticFileHandler(cfg StaticFileConfig) *staticFileHandler {
	// Resolve absolute directory path
	absDir, err := filepath.Abs(cfg.Dir)
	if err != nil {
		absDir = cfg.Dir
	}

	// Create the basic file server
	fileSystem := http.Dir(absDir)
	var fileServer http.Handler

	if cfg.URLPrefix != "" && cfg.StripPrefix != "" {
		// Use StripPrefix to handle URL prefix removal
		fileServer = http.StripPrefix(cfg.StripPrefix, http.FileServer(fileSystem))
	} else if cfg.URLPrefix != "" {
		// Simple prefix handling
		fileServer = http.StripPrefix(cfg.URLPrefix, http.FileServer(fileSystem))
	} else {
		// No prefix, serve from root
		fileServer = http.FileServer(fileSystem)
	}

	// Set default index file for SPA mode
	indexFile := cfg.IndexFile
	if cfg.SPAMode && indexFile == "" {
		indexFile = "index.html"
	}

	var indexPath string
	if indexFile != "" {
		indexPath = filepath.Join(absDir, indexFile)
	}

	return &staticFileHandler{
		config:     cfg,
		fileServer: fileServer,
		indexPath:  indexPath,
	}
}

// serveStatic serves static files without SPA fallback
func (h *staticFileHandler) serveStatic(w http.ResponseWriter, r *http.Request, next http.Handler) {
	requestPath := r.URL.Path

	// Check URL prefix matching
	if h.config.URLPrefix != "" {
		if !strings.HasPrefix(requestPath, h.config.URLPrefix) {
			next.ServeHTTP(w, r)
			return
		}
	}

	// Try to serve the file
	h.serveStaticFile(w, r, next)
}

// serveStaticFile handles the actual file serving with security checks
func (h *staticFileHandler) serveStaticFile(w http.ResponseWriter, r *http.Request, next http.Handler) {
	requestPath := r.URL.Path

	// Convert URL path to file system path with security checks
	cleanPath := path.Clean(requestPath)
	if isDirectoryTraversalAttempt(cleanPath) {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Remove URL prefix if configured
	if h.config.URLPrefix != "" {
		cleanPath = strings.TrimPrefix(cleanPath, h.config.URLPrefix)
	}

	// Build file system path
	fsPath := filepath.Join(h.config.Dir, filepath.FromSlash(cleanPath))

	// Additional security check - ensure the resolved path is still within the configured directory
	absConfigDir, err := filepath.Abs(h.config.Dir)
	if err != nil {
		next.ServeHTTP(w, r)
		return
	}

	absFilePath, err := filepath.Abs(fsPath)
	if err != nil {
		next.ServeHTTP(w, r)
		return
	}

	if !strings.HasPrefix(absFilePath, absConfigDir) {
		next.ServeHTTP(w, r)
		return
	}

	// Check if file exists
	stat, err := os.Stat(fsPath)
	if err != nil {
		next.ServeHTTP(w, r)
		return
	}

	if stat.IsDir() {
		next.ServeHTTP(w, r)
		return
	}

	// Apply caching headers before serving
	h.applyCacheHeaders(w, r)

	// Serve the file directly
	file, err := os.Open(fsPath)
	if err != nil {
		next.ServeHTTP(w, r)
		return
	}
	defer file.Close()

	// Set appropriate content type
	ext := strings.ToLower(filepath.Ext(fsPath))
	contentType := getContentType(ext)
	w.Header().Set("Content-Type", contentType)

	// Serve the file content
	http.ServeContent(w, r, filepath.Base(fsPath), stat.ModTime(), file)
}

// getContentType returns the MIME type for common file extensions
func getContentType(ext string) string {
	switch strings.ToLower(ext) {
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	case ".pdf":
		return "application/pdf"
	case ".txt":
		return "text/plain; charset=utf-8"
	default:
		return ""
	}
}

// serveSPA serves static files with SPA fallback support
func (h *staticFileHandler) serveSPA(w http.ResponseWriter, r *http.Request, next http.Handler) {
	requestPath := r.URL.Path

	// Check URL prefix matching first
	if h.config.URLPrefix != "" {
		if !strings.HasPrefix(requestPath, h.config.URLPrefix) {
			next.ServeHTTP(w, r)
			return
		}
	}

	// For SPA mode, we need to check if the requested file exists
	if h.fileExists(requestPath) {
		// File exists, serve it directly with our custom handler
		h.serveStaticFile(w, r, next)
		return
	}

	// Check if this looks like an API route or should be handled by other handlers
	if h.shouldPassToNextHandler(requestPath) {
		next.ServeHTTP(w, r)
		return
	}

	// File doesn't exist and it's not an API route - serve index file for SPA routing
	if h.indexPath != "" {
		h.serveIndexFile(w, r)
	} else {
		next.ServeHTTP(w, r)
	}
}

// fileExists checks if a file exists at the given request path
func (h *staticFileHandler) fileExists(requestPath string) bool {
	// Convert URL path to file system path
	cleanPath := path.Clean(requestPath)
	if isDirectoryTraversalAttempt(cleanPath) {
		return false // Security: prevent directory traversal
	}

	// Remove URL prefix if configured
	if h.config.URLPrefix != "" {
		if !strings.HasPrefix(cleanPath, h.config.URLPrefix) {
			return false
		}
		cleanPath = strings.TrimPrefix(cleanPath, h.config.URLPrefix)
	}

	// Build file system path
	fsPath := filepath.Join(h.config.Dir, filepath.FromSlash(cleanPath))

	// Check if file exists and is not a directory
	info, err := os.Stat(fsPath)
	return err == nil && !info.IsDir()
}

// shouldPassToNextHandler determines if a request should be handled by other handlers
func (h *staticFileHandler) shouldPassToNextHandler(requestPath string) bool {
	// If it looks like an API endpoint, let other handlers process it
	// This is a simple heuristic - you might want to customize this
	if strings.HasPrefix(requestPath, "/api/") {
		return true
	}
	if strings.HasPrefix(requestPath, "/auth/") {
		return true
	}
	if strings.HasPrefix(requestPath, "/admin/") {
		return true
	}
	if strings.HasPrefix(requestPath, "/ws/") {
		return true
	}

	// Check configured exclude paths
	return shouldExcludeFromStatic(requestPath, h.config.ExcludePaths)
}

// serveIndexFile serves the index.html file for SPA routing
func (h *staticFileHandler) serveIndexFile(w http.ResponseWriter, r *http.Request) {
	// Read the index file
	content, err := os.ReadFile(h.indexPath)
	if err != nil {
		http.Error(w, "Index file not found", http.StatusNotFound)
		return
	}

	// Apply appropriate headers for HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Apply cache headers (typically short cache for HTML in SPA)
	if h.config.CacheMaxAge > 0 {
		// For HTML in SPA mode, use short cache or no-cache
		htmlCacheAge := h.getCacheAge(".html", r.URL.Path)
		if htmlCacheAge > 0 {
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", htmlCacheAge))
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
	}

	// Serve the content
	w.WriteHeader(http.StatusOK)
	w.Write(content)
}

// applyCacheHeaders applies caching headers based on configuration
func (h *staticFileHandler) applyCacheHeaders(w http.ResponseWriter, r *http.Request) {
	if h.config.CacheMaxAge <= 0 && len(h.config.CacheRules) == 0 {
		return // No caching configured
	}

	requestPath := r.URL.Path
	cacheAge := h.getCacheAge(path.Ext(requestPath), requestPath)

	if cacheAge > 0 {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", cacheAge))

		// Set Expires header for older clients
		expires := time.Now().Add(time.Duration(cacheAge) * time.Second)
		w.Header().Set("Expires", expires.Format(http.TimeFormat))

		// Add ETag if not already set by other middleware
		if w.Header().Get("ETag") == "" {
			// Simple ETag based on file path (you might want to improve this)
			etag := fmt.Sprintf(`"%x"`, time.Now().Unix()) // Simplified ETag
			w.Header().Set("ETag", etag)
		}
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
}

// getCacheAge returns the cache age for a given file extension and path
func (h *staticFileHandler) getCacheAge(ext, path string) int {
	// Check specific cache rules first
	if h.config.CacheRules != nil {
		// Check for exact path match first
		if age, ok := h.config.CacheRules[path]; ok {
			return age
		}

		// Check for pattern matches (simplified - only supports trailing *)
		for pattern, age := range h.config.CacheRules {
			if strings.HasSuffix(pattern, "*") {
				prefix := strings.TrimSuffix(pattern, "*")
				if strings.HasPrefix(path, prefix) {
					return age
				}
			}
		}

		// Check for file extension match
		if age, ok := h.config.CacheRules[ext]; ok {
			return age
		}
	}

	// Fall back to default max age
	return h.config.CacheMaxAge
}

// shouldExcludeFromStatic checks if a path should be excluded from static file serving
func shouldExcludeFromStatic(requestPath string, excludePaths []string) bool {
	// matchPath returns true if the path should be processed, false if excluded
	// We want the opposite - return true if excluded
	return !matchPath(requestPath, excludePaths, nil, true)
}

// staticResponseWriter wraps http.ResponseWriter to capture status codes
type staticResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (w *staticResponseWriter) WriteHeader(code int) {
	if w.statusCode == 0 {
		w.statusCode = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *staticResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += n
	return n, err
}

// AddStaticFileRoutes is a convenience method to add static file serving to a router.
// This can be used as an alternative to middleware if you prefer explicit routing.
func (s *Server) AddStaticFileRoutes(cfg StaticFileConfig) error {
	if !cfg.Enabled || cfg.Dir == "" {
		return nil
	}

	handler := createStaticFileHandler(cfg)

	// Determine the route pattern
	pattern := cfg.URLPrefix
	if pattern == "" {
		pattern = "/"
	}
	if !strings.HasSuffix(pattern, "/") {
		pattern += "/"
	}
	pattern += "{file:.*}"

	// Register the route
	s.router.PathPrefix(pattern).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.SPAMode {
			handler.serveSPA(w, r, http.NotFoundHandler())
		} else {
			handler.serveStatic(w, r, http.NotFoundHandler())
		}
	})

	return nil
}
