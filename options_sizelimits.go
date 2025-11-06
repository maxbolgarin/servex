package servex


// WithMaxRequestBodySize sets the maximum allowed request body size in bytes.
// This applies to all request bodies including JSON, form data, and file uploads.
// Use 0 to disable global request size limits.
//
// Common configurations:
//   - API servers: WithMaxRequestBodySize(10 << 20) // 10 MB
//   - Web applications: WithMaxRequestBodySize(50 << 20) // 50 MB
//   - File upload services: WithMaxRequestBodySize(1 << 30) // 1 GB
//   - Microservices: WithMaxRequestBodySize(5 << 20) // 5 MB
//
// This is a global limit applied via middleware. Individual endpoints
// can use smaller limits via context methods like ReadJSONWithLimit().
func WithMaxRequestBodySize(size int64) Option {
	return func(opts *Options) {
		opts.MaxRequestBodySize = size
		opts.EnableRequestSizeLimits = true
	}
}

// WithMaxJSONBodySize sets the maximum allowed JSON request body size in bytes.
// This specifically applies to JSON payloads and takes precedence over MaxRequestBodySize for JSON.
//
// Recommended values:
//   - API servers: WithMaxJSONBodySize(5 << 20) // 5 MB
//   - Configuration APIs: WithMaxJSONBodySize(1 << 20) // 1 MB
//   - Data import APIs: WithMaxJSONBodySize(50 << 20) // 50 MB
//   - Real-time APIs: WithMaxJSONBodySize(1 << 20) // 1 MB
//
// Smaller JSON limits help prevent JSON parsing attacks and reduce memory usage.
func WithMaxJSONBodySize(size int64) Option {
	return func(opts *Options) {
		opts.MaxJSONBodySize = size
		opts.EnableRequestSizeLimits = true
	}
}

// WithMaxFileUploadSize sets the maximum allowed file upload size in bytes.
// This applies to multipart form uploads and file uploads.
//
// Common configurations:
//   - Profile images: WithMaxFileUploadSize(10 << 20) // 10 MB
//   - Document uploads: WithMaxFileUploadSize(200 << 20) // 200 MB
//   - Media files: WithMaxFileUploadSize(2 << 30) // 2 GB
//   - Data imports: WithMaxFileUploadSize(1 << 30) // 1 GB
//
// Consider your server's available memory and disk space when setting this limit.
func WithMaxFileUploadSize(size int64) Option {
	return func(opts *Options) {
		opts.MaxFileUploadSize = size
		opts.EnableRequestSizeLimits = true
	}
}

// WithMaxMultipartMemory sets the maximum memory used for multipart form parsing in bytes.
// Files larger than this are stored in temporary files on disk.
//
// Balance considerations:
//   - Higher values: Faster processing, more memory usage
//   - Lower values: Slower processing, less memory usage, more disk I/O
//
// Recommended: 10-50 MB for most applications
// Example: WithMaxMultipartMemory(32 << 20) // 32 MB
func WithMaxMultipartMemory(size int64) Option {
	return func(opts *Options) {
		opts.MaxMultipartMemory = size
	}
}

// WithEnableRequestSizeLimits enables global request size limit middleware.
// When enabled, all requests are checked against the configured size limits.
// Individual endpoints can still use smaller limits via context methods.
//
// Use cases for disabling:
//   - Fine-grained control per endpoint
//   - Custom size limit middleware
//   - Performance-critical applications
//   - Legacy compatibility
func WithEnableRequestSizeLimits(enable bool) Option {
	return func(opts *Options) {
		opts.EnableRequestSizeLimits = enable
	}
}

// WithRequestSizeLimits configures comprehensive request size limits with commonly used defaults.
// This is a convenience function that sets up reasonable defaults for most applications.
//
// Default limits set:
//   - MaxRequestBodySize: 100 MB
//   - MaxJSONBodySize: 1 MB
//   - MaxFileUploadSize: 100 MB
//   - MaxMultipartMemory: 10 MB
//   - EnableRequestSizeLimits: true
//
// Use individual WithMax* functions for custom limits.
func WithRequestSizeLimits() Option {
	return func(opts *Options) {
		opts.MaxRequestBodySize = 100 << 20 // 100 MB
		opts.MaxJSONBodySize = 1 << 20      // 1 MB
		opts.MaxFileUploadSize = 100 << 20  // 100 MB (same as MaxRequestBodySize)
		opts.MaxMultipartMemory = 10 << 20  // 10 MB
		opts.EnableRequestSizeLimits = true
	}
}

// WithStrictRequestSizeLimits enables request size limits with strict, secure default values.
// This configuration prioritizes security over convenience with smaller size limits.
// Use for applications where security is more important than convenience.
func WithStrictRequestSizeLimits() Option {
	return func(opts *Options) {
		opts.MaxRequestBodySize = 10 << 20 // 10 MB
		opts.MaxJSONBodySize = 512 << 10   // 512 KB
		opts.MaxFileUploadSize = 10 << 20  // 10 MB (same as MaxRequestBodySize)
		opts.MaxMultipartMemory = 5 << 20  // 5 MB
		opts.EnableRequestSizeLimits = true
	}
}
