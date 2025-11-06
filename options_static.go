package servex


// WithStaticFileConfig sets the static file serving configuration.
// This provides full control over all static file serving options.
// Use this when you need granular control over file serving behavior.
//
// For simpler setups, consider using WithStaticFiles() or WithSPAMode() instead.
//
// Example:
//
//	cfg := servex.StaticFileConfig{
//		Enabled:      true,
//		Dir:          "build",
//		SPAMode:      true,
//		IndexFile:    "index.html",
//		CacheMaxAge:  3600,
//		ExcludePaths: []string{"/api/*"},
//		CacheRules: map[string]int{
//			".js":  31536000, // 1 year
//			".css": 31536000, // 1 year
//			".html": 3600,    // 1 hour
//		},
//	}
//	server, _ := servex.New(servex.WithStaticFileConfig(cfg))
func WithStaticFileConfig(config StaticFileConfig) Option {
	return func(o *Options) {
		o.StaticFiles = config
	}
}

// WithStaticFiles enables static file serving from the specified directory.
// This is a simple way to serve static files from a directory.
//
// Parameters:
//   - dir: Directory containing static files to serve
//   - urlPrefix: URL path prefix (empty for root, e.g., "/static")
//
// For SPA support with client-side routing, use WithSPAMode() instead.
//
// Examples:
//
//	// Serve files from "public/" at root path
//	servex.WithStaticFiles("public", "")
//
//	// Serve files from "assets/" under "/static" path
//	servex.WithStaticFiles("assets", "/static")
//
//	// Complete example
//	server, _ := servex.New(servex.WithStaticFiles("build", ""))
func WithStaticFiles(dir, urlPrefix string) Option {
	return func(o *Options) {
		o.StaticFiles = StaticFileConfig{
			Enabled:   true,
			Dir:       dir,
			URLPrefix: urlPrefix,
			SPAMode:   false,
		}
	}
}

// WithSPAMode enables Single Page Application (SPA) mode for serving React, Vue, Angular apps.
// This serves static files from the directory and provides fallback routing for client-side navigation.
//
// In SPA mode:
//   - Static files are served normally (JS, CSS, images, etc.)
//   - API routes continue to work (register them before calling this)
//   - All other routes serve the index file for client-side routing
//
// Parameters:
//   - dir: Directory containing SPA build files (e.g., "build", "dist")
//   - indexFile: Fallback file for client-side routing (typically "index.html")
//
// Usage pattern:
//  1. Register your API routes first
//  2. Enable SPA mode last
//
// Examples:
//
//	// React app setup
//	server, _ := servex.New(servex.WithSPAMode("build", "index.html"))
//	server.GET("/api/users", handleUsers)      // API routes work
//	server.GET("/about", handleUsers)          // Serves index.html for client routing
//
//	// Vue app setup
//	server, _ := servex.New(servex.WithSPAMode("dist", "index.html"))
func WithSPAMode(dir, indexFile string) Option {
	return func(o *Options) {
		if indexFile == "" {
			indexFile = "index.html"
		}
		o.StaticFiles = StaticFileConfig{
			Enabled:   true,
			Dir:       dir,
			SPAMode:   true,
			IndexFile: indexFile,
		}
	}
}

// WithStaticFileCache sets cache policies for static files.
// This controls how long browsers and proxies cache static files.
//
// Parameters:
//   - maxAge: Default cache duration in seconds
//   - rules: File extension or path-specific cache rules
//
// The rules map allows different cache durations for different file types:
//   - Key: File extension (e.g., ".js", ".css") or path pattern (e.g., "/images/*")
//   - Value: Cache duration in seconds
//
// Example:
//
//	// Basic cache setup
//	servex.WithStaticFileCache(3600, nil) // 1 hour for all files
//
//	// Advanced cache setup with rules
//	rules := map[string]int{
//		".js":        31536000, // 1 year for JS files
//		".css":       31536000, // 1 year for CSS files
//		".html":      3600,     // 1 hour for HTML files
//		"/images/*":  2592000,  // 30 days for images
//	}
//	servex.WithStaticFileCache(86400, rules) // 1 day default, custom rules
func WithStaticFileCache(maxAge int, rules ...map[string]int) Option {
	return func(o *Options) {
		if !o.StaticFiles.Enabled {
			return // Only apply if static files are enabled
		}
		o.StaticFiles.CacheMaxAge = maxAge
		if len(rules) > 0 {
			o.StaticFiles.CacheRules = rules[0]
		}
	}
}

// WithStaticFileExclusions sets paths that should not be served as static files.
// These paths will be skipped by the static file handler, allowing API routes to handle them.
//
// This is useful when you want to exclude certain paths from static file serving,
// such as API endpoints that should be handled by custom handlers.
//
// Parameters:
//   - paths: List of path patterns to exclude (supports wildcards with *)
//
// Common exclusions:
//   - "/api/*": All API endpoints
//   - "/auth/*": Authentication endpoints
//   - "/admin/*": Admin interfaces
//   - "/ws/*": WebSocket endpoints
//
// Note: API routes registered before static files are automatically excluded.
//
// Example:
//
//	server, _ := servex.New(
//		servex.WithSPAMode("build", "index.html"),
//		servex.WithStaticFileExclusions("/api/*", "/auth/*"),
//	)
func WithStaticFileExclusions(paths ...string) Option {
	return func(opts *Options) {
		opts.StaticFiles.ExcludePaths = append(opts.StaticFiles.ExcludePaths, paths...)
	}
}
