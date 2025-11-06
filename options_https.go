package servex

import (
	"crypto/tls"
)

// WithCertificate sets the TLS certificate for the server from a pre-loaded tls.Certificate.
// This enables HTTPS support on the server. You must start the server with an HTTPS address
// for the certificate to be used.
//
// Example:
//
//	cert, _ := tls.LoadX509KeyPair("server.crt", "server.key")
//	options.Certificate = &cert
//	server := servex.New(servex.WithCertificate(cert))
//	server.Start("", ":8443") // HTTPS only
//
// Use this when you have already loaded the certificate in memory, perhaps for
// certificate rotation or when loading from embedded files.
func WithCertificate(cert tls.Certificate) Option {
	return func(op *Options) {
		op.Certificate = &cert
	}
}

// WithCertificatePtr sets the TLS certificate for the server from a pointer to tls.Certificate.
// This enables HTTPS support on the server. You must start the server with an HTTPS address
// for the certificate to be used.
//
// Example:
//
//	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
//	if err != nil {
//		log.Fatal(err)
//	}
//	server := servex.New(servex.WithCertificatePtr(&cert))
//	server.Start("", ":8443") // HTTPS only
//
// Use this when you need to pass a certificate pointer, useful when sharing
// certificate instances or when the certificate is managed externally.
func WithCertificatePtr(cert *tls.Certificate) Option {
	return func(op *Options) {
		op.Certificate = cert
	}
}

// WithCertificateFromFile configures the server to load TLS certificate from files.
// This enables HTTPS support on the server. The certificate files will be loaded
// when the server starts. You must start the server with an HTTPS address for
// the certificate to be used.
//
// Parameters:
//   - certFilePath: Path to the PEM-encoded certificate file
//   - keyFilePath: Path to the PEM-encoded private key file
//
// Example:
//
//	// Load certificate from files
//	server := servex.New(servex.WithCertificateFromFile("server.crt", "server.key"))
//	server.Start(":8080", ":8443") // Both HTTP and HTTPS
//
//	// HTTPS only server
//	server := servex.New(servex.WithCertificateFromFile("cert.pem", "key.pem"))
//	server.Start("", ":8443") // HTTPS only
//
// This is the most common way to configure TLS certificates. Ensure the files
// are readable by the application and contain valid PEM-encoded data.
func WithCertificateFromFile(certFilePath, keyFilePath string) Option {
	return func(op *Options) {
		op.CertFilePath = certFilePath
		op.KeyFilePath = keyFilePath
	}
}

// WithHTTPSRedirect configures the server to automatically redirect HTTP requests to HTTPS.
// This is a convenience method for the most common HTTPS redirect scenario.
func WithHTTPSRedirect() Option {
	return func(op *Options) {
		op.HTTPSRedirect.Enabled = true
		op.HTTPSRedirect.Permanent = true
	}
}

// WithHTTPSRedirectTemporary enables automatic HTTP to HTTPS redirection using temporary redirects (302).
// This is useful during development and testing when you don't want browsers to cache the redirects.
//
// Example:
//
//	// Enable temporary HTTPS redirection for development
//	server := servex.New(servex.WithHTTPSRedirectTemporary())
//
// For production use, prefer WithHTTPSRedirect() which uses permanent redirects (301)
// for better SEO and performance.
func WithHTTPSRedirectTemporary() Option {
	return func(op *Options) {
		op.HTTPSRedirect.Enabled = true
		op.HTTPSRedirect.Permanent = false
	}
}

// WithHTTPSRedirectConfig sets the complete HTTPS redirection configuration.
// This allows fine-grained control over all HTTPS redirect settings.
//
// Example:
//
//	httpsConfig := servex.HTTPSRedirectConfig{
//		Enabled: true,
//		Permanent: true,
//		TrustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12"},
//		ExcludePaths: []string{"/health", "/.well-known/*"},
//	}
//
//	server := servex.New(servex.WithHTTPSRedirectConfig(httpsConfig))
//
// Use this when you need to configure multiple HTTPS redirect settings at once
// or when loading configuration from files or environment variables.
func WithHTTPSRedirectConfig(config HTTPSRedirectConfig) Option {
	return func(op *Options) {
		op.HTTPSRedirect = config
	}
}

// WithHTTPSRedirectTrustedProxies sets the trusted proxy IP addresses or CIDR ranges
// for accurate HTTP/HTTPS detection when behind load balancers or proxies.
//
// When behind proxies, the server cannot detect HTTPS from r.TLS alone.
// This setting allows checking X-Forwarded-Proto and similar headers
// only when the request comes from trusted proxy IPs.
//
// Example:
//
//	// Trust common internal networks
//	server := servex.New(
//		servex.WithHTTPSRedirect(),
//		servex.WithHTTPSRedirectTrustedProxies("10.0.0.0/8", "172.16.0.0/12"),
//	)
//
//	// Trust specific load balancer IPs
//	server := servex.New(
//		servex.WithHTTPSRedirect(),
//		servex.WithHTTPSRedirectTrustedProxies("192.168.1.100", "192.168.1.101"),
//	)
//
// Security note: Only list IPs you actually trust. Malicious clients
// can spoof X-Forwarded-Proto headers if the proxy IP is trusted.
func WithHTTPSRedirectTrustedProxies(proxies ...string) Option {
	return func(op *Options) {
		op.HTTPSRedirect.TrustedProxies = proxies
	}
}

// WithHTTPSRedirectExcludePaths sets paths that should be excluded from HTTPS redirection.
// Requests to these paths will not be redirected to HTTPS.
//
// Common exclusions:
//   - Health checks: "/health", "/ping" (for load balancers that use HTTP)
//   - Let's Encrypt challenges: "/.well-known/acme-challenge/*"
//   - Development endpoints: "/debug/*"
//   - Legacy integrations that require HTTP: "/legacy/*"
//
// Example:
//
//	// Exclude health checks and Let's Encrypt challenges
//	server := servex.New(
//		servex.WithHTTPSRedirect(),
//		servex.WithHTTPSRedirectExcludePaths("/health", "/.well-known/*"),
//	)
//
// Path matching supports wildcards (*) for pattern matching.
// Use sparingly - most paths should use HTTPS for security.
func WithHTTPSRedirectExcludePaths(paths ...string) Option {
	return func(op *Options) {
		op.HTTPSRedirect.ExcludePaths = paths
	}
}

// WithHTTPSRedirectIncludePaths sets paths that should be included in HTTPS redirection.
// If set, only requests to these paths will be redirected to HTTPS.
//
// If both IncludePaths and ExcludePaths are set:
//  1. Paths must match IncludePaths to be considered for redirection
//  2. Paths in ExcludePaths are then excluded from redirection
//
// Example:
//
//	// Only redirect specific sensitive areas
//	server := servex.New(
//		servex.WithHTTPSRedirect(),
//		servex.WithHTTPSRedirectIncludePaths("/admin/*", "/user/*", "/api/private/*"),
//	)
//
//	// Gradual HTTPS migration
//	server := servex.New(
//		servex.WithHTTPSRedirect(),
//		servex.WithHTTPSRedirectIncludePaths("/secure/*"),
//	)
//
// Use cases:
//   - Gradual HTTPS migration: Start with specific paths
//   - Mixed HTTP/HTTPS applications: Only secure sensitive areas
//   - Testing HTTPS setup: Limit scope during testing
//
// Path matching supports wildcards (*) for pattern matching.
// Leave empty to redirect all paths (recommended for production).
func WithHTTPSRedirectIncludePaths(paths ...string) Option {
	return func(op *Options) {
		op.HTTPSRedirect.IncludePaths = paths
	}
}

