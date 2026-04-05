package servex

import "strings"

// WithCompressionConfig sets the complete compression configuration.
// This provides full control over all compression settings.
//
// Example:
//
//	compressionConfig := servex.CompressionConfig{
//		Enabled: true,
//		Level: 6,
//		MinSize: 1024,
//		Types: []string{"text/html", "application/json", "text/css"},
//		ExcludePaths: []string{"/api/binary/*"},
//	}
//	server, _ := servex.New(servex.WithCompressionConfig(compressionConfig))
//
// For simpler setups, consider using WithCompression() instead.
func WithCompressionConfig(compression CompressionConfig) Option {
	return func(opts *Options) {
		opts.Compression = compression
	}
}

// WithCompression enables HTTP response compression with sensible defaults.
// This automatically compresses text-based responses using gzip encoding.
//
// Default configuration:
//   - Compression level: 6 (balanced speed/compression)
//   - Minimum size: 1KB
//   - Types: HTML, CSS, JS, JSON, XML, plain text, SVG
//   - All paths included unless specifically excluded
//
// Example:
//
//	// Enable compression with defaults
//	server, _ := servex.New(servex.WithCompression())
//
//	// Enable compression with custom minimum size
//	server, _ := servex.New(
//		servex.WithCompression(),
//		servex.WithCompressionMinSize(512),
//	)
//
// Benefits:
//   - Reduces bandwidth usage by 60-80% for text content
//   - Improves page load times
//   - Lower hosting costs
//   - Better user experience
func WithCompression() Option {
	return func(opts *Options) {
		opts.Compression = CompressionConfig{
			Enabled: true,
			Level:   6,    // Balanced compression
			MinSize: 1024, // 1KB minimum
			Types: []string{
				"text/html",
				"text/css",
				"text/plain",
				"text/xml",
				"application/json",
				"application/javascript",
				"application/xml",
				"image/svg+xml",
			},
		}
	}
}

// WithCompressionLevel sets the compression level for gzip encoding.
// Higher levels provide better compression but use more CPU.
//
// Valid range: 1-9
//   - 1: Fastest compression, lower CPU usage
//   - 6: Default balance (recommended)
//   - 9: Best compression, higher CPU usage
//
// Example:
//
//	// Fast compression for high-traffic servers
//	server, _ := servex.New(
//		servex.WithCompression(),
//		servex.WithCompressionLevel(1),
//	)
//
//	// Maximum compression for bandwidth-constrained environments
//	server, _ := servex.New(
//		servex.WithCompression(),
//		servex.WithCompressionLevel(9),
//	)
func WithCompressionLevel(level int) Option {
	return func(opts *Options) {
		if level < 1 {
			level = 1
		} else if level > 9 {
			level = 9
		}
		opts.Compression.Enabled = true
		opts.Compression.Level = level
	}
}

// WithCompressionMinSize sets the minimum response size to trigger compression.
// Responses smaller than this size will not be compressed.
//
// Parameters:
//   - size: Minimum size in bytes (0 to compress all responses)
//
// Example:
//
//	// Only compress responses larger than 2KB
//	server, _ := servex.New(
//		servex.WithCompression(),
//		servex.WithCompressionMinSize(2048),
//	)
//
//	// Compress all responses regardless of size
//	server, _ := servex.New(
//		servex.WithCompression(),
//		servex.WithCompressionMinSize(0),
//	)
//
// Considerations:
//   - Small responses may not benefit from compression
//   - Compression adds CPU overhead
//   - Network overhead for small responses may negate benefits
func WithCompressionMinSize(size int) Option {
	return func(opts *Options) {
		if size < 0 {
			size = 0
		}
		opts.Compression.Enabled = true
		opts.Compression.MinSize = size
	}
}

// WithCompressionTypes sets the MIME types that should be compressed.
// Only responses with these content types will be compressed.
//
// Parameters:
//   - types: List of MIME types to compress
//
// Common types:
//   - "text/html": HTML pages
//   - "text/css": CSS stylesheets
//   - "application/javascript": JavaScript files
//   - "application/json": JSON API responses
//   - "text/xml": XML responses
//   - "text/plain": Plain text files
//   - "image/svg+xml": SVG images
//
// Example:
//
//	// Compress only JSON and HTML
//	server, _ := servex.New(
//		servex.WithCompression(),
//		servex.WithCompressionTypes("application/json", "text/html"),
//	)
//
//	// Add additional types to defaults
//	server, _ := servex.New(
//		servex.WithCompression(),
//		servex.WithCompressionTypes("application/pdf", "text/csv"),
//	)
func WithCompressionTypes(types ...string) Option {
	return func(opts *Options) {
		opts.Compression.Enabled = true
		opts.Compression.Types = append(opts.Compression.Types, types...)
	}
}

// WithCompressionExcludePaths sets paths that should be excluded from compression.
// Responses for these paths will not be compressed regardless of other settings.
//
// Parameters:
//   - paths: List of path patterns to exclude (supports wildcards with *)
//
// Common exclusions:
//   - "/api/binary/*": Binary API endpoints
//   - "/downloads/*": File download endpoints
//   - "/images/*": Image files (already compressed)
//   - "/videos/*": Video files (already compressed)
//
// Example:
//
//	// Exclude binary and media endpoints
//	server, _ := servex.New(
//		servex.WithCompression(),
//		servex.WithCompressionExcludePaths("/api/binary/*", "/downloads/*", "/media/*"),
//	)
//
// Path matching supports wildcards (*) for pattern matching.
func WithCompressionExcludePaths(paths ...string) Option {
	return func(opts *Options) {
		opts.Compression.ExcludePaths = append(opts.Compression.ExcludePaths, paths...)
	}
}

// WithCompressionIncludePaths sets paths that should have compression applied.
// If set, only responses for these paths will be compressed.
//
// Parameters:
//   - paths: List of path patterns to include (supports wildcards with *)
//
// If both IncludePaths and ExcludePaths are set:
//  1. Paths must match IncludePaths to be considered for compression
//  2. Paths in ExcludePaths are then excluded from compression
//
// Example:
//
//	// Compress only API and static assets
//	server, _ := servex.New(
//		servex.WithCompression(),
//		servex.WithCompressionIncludePaths("/api/*", "/static/*"),
//	)
//
//	// Compress specific content areas
//	server, _ := servex.New(
//		servex.WithCompression(),
//		servex.WithCompressionIncludePaths("/docs/*", "/help/*", "/blog/*"),
//	)
//
// Path matching supports wildcards (*) for pattern matching.
// Leave empty to apply compression to all paths (default behavior).
func WithCompressionIncludePaths(paths ...string) Option {
	return func(opts *Options) {
		opts.Compression.IncludePaths = append(opts.Compression.IncludePaths, paths...)
	}
}

// WithBrotliCompression enables Brotli compression support.
// Brotli typically provides 15-25% better compression ratios than gzip at similar speed,
// and is supported by all modern browsers.
//
// When called alone, only Brotli will be offered. Combine with other encoding options
// or use WithCompression() (which enables all encodings) for broader client support.
//
// Example:
//
//	// Enable Brotli and gzip for broad compatibility
//	server, _ := servex.New(
//		servex.WithCompression(),
//		servex.WithBrotliCompression(),
//		servex.WithGzipCompression(),
//	)
func WithBrotliCompression() Option {
	return func(opts *Options) {
		opts.Compression.Enabled = true
		if !containsEncodingStr(opts.Compression.EnabledEncodings, "br") {
			opts.Compression.EnabledEncodings = append(opts.Compression.EnabledEncodings, "br")
		}
	}
}

// WithZstdCompression enables Zstd compression support.
// Zstd is typically faster than gzip with similar or better compression ratios,
// and is supported by modern browsers and HTTP clients.
//
// When called alone, only Zstd will be offered. Combine with other encoding options
// or use WithCompression() (which enables all encodings) for broader client support.
//
// Example:
//
//	// Enable Zstd with gzip fallback
//	server, _ := servex.New(
//		servex.WithCompression(),
//		servex.WithZstdCompression(),
//		servex.WithGzipCompression(),
//	)
func WithZstdCompression() Option {
	return func(opts *Options) {
		opts.Compression.Enabled = true
		if !containsEncodingStr(opts.Compression.EnabledEncodings, "zstd") {
			opts.Compression.EnabledEncodings = append(opts.Compression.EnabledEncodings, "zstd")
		}
	}
}

// WithGzipCompression enables Gzip compression support.
// Gzip has universal browser support and is a safe fallback for all clients.
//
// Example:
//
//	server, _ := servex.New(servex.WithGzipCompression())
func WithGzipCompression() Option {
	return func(opts *Options) {
		opts.Compression.Enabled = true
		if !containsEncodingStr(opts.Compression.EnabledEncodings, "gzip") {
			opts.Compression.EnabledEncodings = append(opts.Compression.EnabledEncodings, "gzip")
		}
	}
}

// WithDeflateCompression enables Deflate compression support.
//
// Example:
//
//	server, _ := servex.New(servex.WithDeflateCompression())
func WithDeflateCompression() Option {
	return func(opts *Options) {
		opts.Compression.Enabled = true
		if !containsEncodingStr(opts.Compression.EnabledEncodings, "deflate") {
			opts.Compression.EnabledEncodings = append(opts.Compression.EnabledEncodings, "deflate")
		}
	}
}

// containsEncodingStr is a helper that checks if a string slice contains a value (case-insensitive).
func containsEncodingStr(slice []string, s string) bool {
	s = strings.ToLower(s)
	for _, v := range slice {
		if strings.ToLower(v) == s {
			return true
		}
	}
	return false
}
