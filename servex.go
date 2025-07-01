// Package servex provides a basic HTTP(S) server based on a [net/http] and [gorilla/mux].
package servex

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/maxbolgarin/lang"
)

// Server represents a high-performance HTTP/HTTPS server with built-in middleware support.
//
// The Server provides comprehensive features including:
//   - Authentication and authorization with JWT tokens
//   - Rate limiting with multiple strategies
//   - Request filtering (IP, User-Agent, headers, query params)
//   - Security headers and CSRF protection
//   - Static file serving with SPA support
//   - Proxy/gateway functionality with load balancing
//   - Request logging and metrics collection
//   - Cache control headers
//   - Graceful shutdown support
//
// Server instances are created using New() or NewWithOptions() and configured
// through the Options pattern using With* functions.
//
// Example usage:
//
//	server, err := servex.New(
//		servex.WithAuthToken("secret-token"),
//		servex.WithRateLimitRPM(60),
//		servex.WithSecurityHeaders(),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	server.HandleFunc("/api/hello", func(w http.ResponseWriter, r *http.Request) {
//		servex.C(w, r).Response(200, map[string]string{"message": "Hello, World!"})
//	})
//
//	log.Fatal(server.Start(":8080", ""))
type Server struct {
	http   *http.Server
	https  *http.Server
	router *mux.Router
	auth   *AuthManager
	filter *Filter
	opts   Options

	basePath string
	cleanups []func()
}

// NewServer creates a new Server instance with the specified options.
//
// The server is configured using the Options pattern with With* functions.
// A server without a TLS certificate can only serve plain HTTP traffic.
//
// Available configuration options include:
//   - Authentication: WithAuth(), WithAuthToken(), WithAuthMemoryDatabase()
//   - Rate limiting: WithRPM(), WithRPS(), WithRateLimitConfig()
//   - Security: WithSecurityHeaders(), WithCSRFProtection(), WithStrictSecurityHeaders()
//   - Filtering: WithAllowedIPs(), WithBlockedUserAgents(), WithFilterConfig()
//   - Static files: WithStaticFiles(), WithSPAMode()
//   - Logging: WithLogger(), WithRequestLogger(), WithAuditLogger()
//   - TLS: WithCertificate(), WithCertificateFromFile()
//   - And many more...
//
// Example:
//
//	server, err := servex.NewServer(
//		servex.WithAuthToken("my-secret-token"),
//		servex.WithRateLimitRPM(100),
//		servex.WithSecurityHeaders(),
//		servex.WithStaticFiles("./public"),
//	)
//	if err != nil {
//		return fmt.Errorf("create server: %w", err)
//	}
//
// The server must have routes registered using the router methods
// (HandleFunc, GET, POST, etc.) before starting.
func NewServer(ops ...Option) (*Server, error) {
	return NewServerWithOptions(parseOptions(ops))
}

// NewServerWithOptions creates a new Server instance with the provided Options struct.
//
// This function is useful when you have already constructed an Options struct,
// either programmatically or from configuration files. For most use cases,
// New() with With* functions is more convenient.
//
// The function validates the configuration and returns an error if any
// invalid settings are detected.
//
// Example:
//
//	opts := servex.Options{
//		AuthToken: "my-secret-token",
//		RateLimit: servex.RateLimitConfig{
//			Enabled: true,
//			RequestsPerInterval: 100,
//			Interval: time.Minute,
//		},
//		Security: servex.SecurityConfig{
//			Enabled: true,
//			XContentTypeOptions: "nosniff",
//		},
//	}
//
//	server, err := servex.NewServerWithOptions(opts)
//	if err != nil {
//		return fmt.Errorf("create server: %w", err)
//	}
func NewServerWithOptions(opts Options) (*Server, error) {
	// Validate configuration before proceeding
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}
	if opts.RequestLogger == nil && !opts.DisableRequestLogging {
		opts.RequestLogger = &BaseRequestLogger{
			Logger:          opts.Logger,
			FieldsToInclude: opts.LogFields,
		}
	}
	if opts.DisableRequestLogging {
		opts.RequestLogger = &noopRequestLogger{}
	}

	// Initialize audit logger if not set but default audit logging was requested
	if opts.AuditLogger == nil {
		if opts.EnableDefaultAuditLogger {
			// Default audit logging was requested, create it now with the available logger
			opts.AuditLogger = NewDefaultAuditLogger(opts.Logger)
		} else {
			// No audit logging requested, use no-op logger
			opts.AuditLogger = &NoopAuditLogger{}
		}
	} else if dal, ok := opts.AuditLogger.(*DefaultAuditLogger); ok && dal.Logger == nil {
		// Complete initialization of DefaultAuditLogger with the logger
		// This handles cases where WithAuditLogHeaders was called before the logger was available
		dal.Logger = opts.Logger
		dal.SensitiveHeaders = []string{"Authorization", "Cookie", "X-API-Key", "X-Auth-Token"}
		dal.MaxDetailSize = 1024
		dal.EnableGeoLocation = false
	}

	if opts.Certificate == nil && opts.CertFilePath != "" && opts.KeyFilePath != "" {
		cert, err := ReadCertificateFromFile(opts.CertFilePath, opts.KeyFilePath)
		if err != nil {
			return nil, fmt.Errorf("read certificate from file cert=%s, key=%s: %w", opts.CertFilePath, opts.KeyFilePath, err)
		}
		opts.Certificate = &cert
	}

	s := &Server{
		router: mux.NewRouter(),
		opts:   opts,
	}

	rateLimitCleanup := RegisterRateLimitMiddleware(s.router, opts.RateLimit, opts.AuditLogger)
	s.cleanups = append(s.cleanups, rateLimitCleanup)
	RegisterRequestSizeLimitMiddleware(s.router, opts)

	filter, err := RegisterFilterMiddleware(s.router, opts.Filter, opts.AuditLogger)
	if err != nil {
		return nil, err
	}
	s.filter = filter

	if opts.HTTPSRedirect.Enabled {
		RegisterHTTPSRedirectMiddleware(s.router, opts.HTTPSRedirect)
	}

	RegisterSecurityHeadersMiddleware(s.router, opts.Security)
	RegisterCacheControlMiddleware(s.router, opts.Cache)
	if len(opts.CustomHeaders) > 0 {
		RegisterCustomHeadersMiddleware(s.router, opts.CustomHeaders)
	}
	if len(opts.HeadersToRemove) > 0 {
		RegisterHeaderRemovalMiddleware(s.router, opts.HeadersToRemove)
	}
	RegisterLoggingMiddleware(s.router, opts.RequestLogger, opts.Metrics)
	RegisterRecoverMiddleware(s.router, opts.Logger)
	RegisterSimpleAuthMiddleware(s.router, opts.AuthToken, opts)
	registerOptsMiddleware(s.router, opts)

	// Register proxy middleware before auth but after security/filtering
	if err := RegisterProxyMiddleware(s.router, opts.Proxy, opts.Logger); err != nil {
		return nil, fmt.Errorf("register proxy middleware: %w", err)
	}

	if s.opts.Auth.Enabled {
		if s.opts.Auth.Database == nil {
			return nil, errors.New("auth database is required")
		}
		authManager, err := NewAuthManager(s.opts.Auth, opts.AuditLogger)
		if err != nil {
			return nil, fmt.Errorf("cannot create auth manager: %w", err)
		}
		s.auth = authManager

		s.auth.RegisterRoutes(s.router)

		for _, user := range s.opts.Auth.InitialUsers {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			err := s.auth.CreateUser(ctx, user.Username, user.Password, user.Roles...)
			if err != nil {
				return nil, fmt.Errorf("cannot create initial user with name=%s: %w", user.Username, err)
			}
		}
	}

	// Register health
	s.registerBuiltinEndpoints()

	// Register static file middleware - should be registered after all other middleware
	RegisterStaticFileMiddleware(s.router, opts.StaticFiles)

	return s, nil
}

// StartServer starts the server with the provided [BaseConfig] and [Option]s.
// It returns an error if there was an error starting either of the servers.
// You should provide a function that sets the handlers for the server to the router.
// It returns shutdown function so you should shutdown the server manually.
//
// Example:
//
//	cfg := servex.BaseConfig{
//		HTTPS: ":8443",
//		CertFile: "cert.pem",
//		KeyFile:  "key.pem",
//	}
//
//	shutdown, err := servex.StartServer(cfg, func(r *mux.Router) {
//		r.HandleFunc("/api/users", handleUsers)
//		r.HandleFunc("/api/health", handleHealth)
//	}, servex.WithAuthToken("secret-token"))
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer shutdown(context.Background())
func StartServer(cfg BaseConfig, handlerSetter func(*mux.Router), opts ...Option) (shutdown func(context.Context) error, err error) {
	s, err := prepareServer(cfg, handlerSetter, opts...)
	if err != nil {
		return nil, err
	}
	if err := s.Start(cfg.HTTP, cfg.HTTPS); err != nil {
		return nil, err
	}
	return s.Shutdown, nil
}

// Start starts the server with the provided [BaseConfig] and [Option]s.
// It returns an error if there was an error starting either of the servers.
// You should provide a function that sets the handlers for the server to the router.
// It shutdowns the server when the context is closed (it starts a goroutine to check [Context.Done]).
//
// Example:
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	cfg := servex.BaseConfig{
//		HTTPS: ":8443",
//		CertFile: "cert.pem",
//		KeyFile:  "key.pem",
//	}
//
//	err := servex.StartServerWithShutdown(ctx, cfg, func(r *mux.Router) {
//		r.HandleFunc("/api/users", handleUsers)
//		r.HandleFunc("/api/health", handleHealth)
//	}, servex.WithAuthToken("secret-token"))
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Server will automatically shutdown when ctx is cancelled
//	// or when the context deadline is reached
func StartServerWithShutdown(ctx context.Context, cfg BaseConfig, handlerSetter func(*mux.Router), opts ...Option) error {
	s, err := prepareServer(cfg, handlerSetter, opts...)
	if err != nil {
		return err
	}
	return s.StartWithShutdown(ctx, cfg.HTTP, cfg.HTTPS)
}

// Start starts both HTTP and HTTPS servers on the specified addresses.
//
// Parameters:
//   - httpAddr: Address for HTTP server (e.g., ":8080", "localhost:8080"). Empty string disables HTTP.
//   - httpsAddr: Address for HTTPS server (e.g., ":8443", "localhost:8443"). Empty string disables HTTPS.
//
// At least one address must be provided. The HTTPS server requires a TLS certificate
// to be configured through WithCertificate() or WithCertificateFromFile() options.
//
// This method starts the servers asynchronously and returns immediately after
// successful startup. Use StartWithShutdown() if you need automatic cleanup
// when a context is cancelled.
//
// Example:
//
//	// Start both HTTP and HTTPS
//	err := server.Start(":8080", ":8443")
//
//	// Start only HTTP
//	err := server.Start(":8080", "")
//
//	// Start only HTTPS
//	err := server.Start("", ":8443")
func (s *Server) Start(httpAddr, httpsAddr string) error {
	if httpAddr == "" && httpsAddr == "" {
		return errors.New("no address provided")
	}
	if httpAddr != "" {
		if err := s.StartHTTP(httpAddr); err != nil {
			return fmt.Errorf("start HTTP server: %w", err)
		}
	}
	if httpsAddr != "" {
		if err := s.StartHTTPS(httpsAddr); err != nil {
			return fmt.Errorf("start HTTPS server: %w", err)
		}
	}
	return nil
}

// StartHTTP starts only the HTTP server on the specified address.
//
// This method is useful when you only need HTTP traffic or want to start
// HTTP and HTTPS servers separately with different timing.
//
// Parameters:
//   - address: The address to bind the HTTP server to (e.g., ":8080", "localhost:8080")
//
// The server starts asynchronously in a goroutine and this method returns
// immediately after successful startup. Use the returned error to check
// for startup failures.
//
// Example:
//
//	if err := server.StartHTTP(":8080"); err != nil {
//		log.Fatalf("Failed to start HTTP server: %v", err)
//	}
//	log.Println("HTTP server started on :8080")
func (s *Server) StartHTTP(address string) error {
	// Reset the ready channel for fresh startup
	httpReady := make(chan error, 1)

	s.http = &http.Server{
		Addr:              address,
		Handler:           s.router,
		ReadHeaderTimeout: lang.Check(s.opts.ReadHeaderTimeout, defaultReadTimeout),
		ReadTimeout:       lang.Check(s.opts.ReadTimeout, defaultReadTimeout),
		IdleTimeout:       lang.Check(s.opts.IdleTimeout, defaultIdleTimeout),
	}
	if err := s.start(address, s.http.Serve, net.Listen, httpReady); err != nil {
		s.http = nil
		return err
	}

	// Wait for server to be ready
	if err := <-httpReady; err != nil {
		s.http = nil
		return fmt.Errorf("HTTP server failed to start: %w", err)
	}

	s.opts.Logger.Info("http server started", "address", address)

	return nil
}

// StartHTTPS starts only the HTTPS server on the specified address.
//
// This method requires a TLS certificate to be configured through
// WithCertificate() or WithCertificateFromFile() options.
//
// Parameters:
//   - address: The address to bind the HTTPS server to (e.g., ":8443", "localhost:8443")
//
// The server starts asynchronously in a goroutine and this method returns
// immediately after successful startup. The method will return an error if
// no TLS certificate is configured.
//
// Example:
//
//	server, err := servex.New(
//		servex.WithCertificateFromFile("cert.pem", "key.pem"),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	if err := server.StartHTTPS(":8443"); err != nil {
//		log.Fatalf("Failed to start HTTPS server: %v", err)
//	}
//	log.Println("HTTPS server started on :8443")
func (s *Server) StartHTTPS(address string) error {
	if s.opts.Certificate == nil {
		return errors.New("TLS certificate is required for HTTPS server")
	}

	// Reset the ready channel for fresh startup
	httpsReady := make(chan error, 1)

	s.https = &http.Server{
		Addr:              address,
		Handler:           s.router,
		ReadHeaderTimeout: lang.Check(s.opts.ReadHeaderTimeout, defaultReadTimeout),
		ReadTimeout:       lang.Check(s.opts.ReadTimeout, defaultReadTimeout),
		IdleTimeout:       lang.Check(s.opts.IdleTimeout, defaultIdleTimeout),
		TLSConfig:         GetTLSConfig(s.opts.Certificate),
	}

	if err := s.start(address, s.https.Serve, func(netType, addr string) (net.Listener, error) {
		return tls.Listen(netType, addr, s.https.TLSConfig)
	}, httpsReady); err != nil {
		s.https = nil
		return err
	}

	// Wait for server to be ready
	if err := <-httpsReady; err != nil {
		s.https = nil
		return fmt.Errorf("HTTPS server failed to start: %w", err)
	}

	s.opts.Logger.Info("https server started", "address", address)

	return nil
}

// StartWithShutdown starts HTTP and HTTPS servers with automatic graceful shutdown.
//
// This method starts the servers and monitors the provided context. When the
// context is cancelled or times out, it automatically initiates a graceful
// shutdown with a 30-second timeout.
//
// Parameters:
//   - ctx: Context for controlling server lifecycle. When cancelled, triggers shutdown.
//   - httpAddr: Address for HTTP server (empty string disables HTTP)
//   - httpsAddr: Address for HTTPS server (empty string disables HTTPS)
//
// This is the recommended way to start servers in production as it handles
// cleanup automatically and supports graceful shutdown for zero-downtime deployments.
//
// Example:
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	// Start server with automatic shutdown
//	err := server.StartWithShutdown(ctx, ":8080", ":8443")
//	if err != nil {
//		log.Fatalf("Server failed: %v", err)
//	}
//
//	// Server will shutdown gracefully when ctx is cancelled
//	// or when the program receives a signal
func (s *Server) StartWithShutdown(ctx context.Context, httpAddr, httpsAddr string) error {
	err := s.Start(httpAddr, httpsAddr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.Shutdown(shutdownCtx); err != nil {
			s.opts.Logger.Error("cannot shutdown", "error", err)
		}
	}()
	return nil
}

// StartWithShutdownHTTP starts only the HTTP server with automatic graceful shutdown.
//
// This is a convenience method that starts only the HTTP server and automatically
// shuts it down when the context is cancelled. Equivalent to calling
// StartWithShutdown(ctx, address, "").
//
// Parameters:
//   - ctx: Context for controlling server lifecycle
//   - address: Address for the HTTP server (e.g., ":8080")
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//
//	err := server.StartWithShutdownHTTP(ctx, ":8080")
func (s *Server) StartWithShutdownHTTP(ctx context.Context, address string) error {
	return s.StartWithShutdown(ctx, address, "")
}

// StartWithShutdownHTTPS starts only the HTTPS server with automatic graceful shutdown.
//
// This is a convenience method that starts only the HTTPS server and automatically
// shuts it down when the context is cancelled. Equivalent to calling
// StartWithShutdown(ctx, "", address).
//
// Requires a TLS certificate to be configured through WithCertificate() or
// WithCertificateFromFile() options.
//
// Parameters:
//   - ctx: Context for controlling server lifecycle
//   - address: Address for the HTTPS server (e.g., ":8443")
//
// Example:
//
//	server, err := servex.New(
//		servex.WithCertificateFromFile("cert.pem", "key.pem"),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	err = server.StartWithShutdownHTTPS(ctx, ":8443")
func (s *Server) StartWithShutdownHTTPS(ctx context.Context, address string) error {
	return s.StartWithShutdown(ctx, "", address)
}

// StartWithWaitSignals starts the server with automatic graceful shutdown when the provided signals are received.
//
// This method starts the servers and waits (blocks) until the provided signals are received.
// When the signals are received, it automatically initiates a graceful shutdown with a 30-second timeout.
//
// Parameters:
//   - ctx: Context for controlling server lifecycle
//   - httpAddr: Address for HTTP server (empty string disables HTTP)
//   - httpsAddr: Address for HTTPS server (empty string disables HTTPS)
//   - signals: Signals to listen for (default: [os.Interrupt, syscall.SIGTERM])
//
// Example:
//
//	server, err := servex.New(
//		servex.WithCertificateFromFile("cert.pem", "key.pem"),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	err = server.StartWithWaitSignals(ctx, ":8080", ":8443", os.Interrupt, syscall.SIGTERM)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Server will shutdown gracefully when ctx is cancelled
//	// or when the program receives a signal
func (s *Server) StartWithWaitSignals(ctx context.Context, httpAddr, httpsAddr string, signals ...os.Signal) error {
	if len(signals) == 0 {
		signals = []os.Signal{os.Interrupt, syscall.SIGTERM}
	}
	ctx, cancel := signal.NotifyContext(ctx, signals...)
	defer cancel()

	if err := s.Start(httpAddr, httpsAddr); err != nil {
		return err
	}

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Shutdown(shutdownCtx); err != nil {
		s.opts.Logger.Error("cannot shutdown", "error", err)
	}

	return nil
}

// StartWithWaitSignalsHTTP starts the HTTP server with automatic graceful shutdown when the provided signals are received.
//
// This method starts the HTTP server and waits (blocks) until the provided signals are received.
// When the signals are received, it automatically initiates a graceful shutdown with a 30-second timeout.
//
// Parameters:
//   - ctx: Context for controlling server lifecycle
//   - httpAddr: Address for HTTP server (empty string disables HTTP)
//   - httpsAddr: Address for HTTPS server (empty string disables HTTPS)
//   - signals: Signals to listen for (default: [os.Interrupt, syscall.SIGTERM])
//
// Example:
//
//	server, err := servex.New(
//		servex.WithCertificateFromFile("cert.pem", "key.pem"),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	err = server.StartWithWaitSignalsHTTP(ctx, ":8080", os.Interrupt, syscall.SIGTERM)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Server will shutdown gracefully when ctx is cancelled
//	// or when the program receives a signal
func (s *Server) StartWithWaitSignalsHTTP(ctx context.Context, address string, signals ...os.Signal) error {
	return s.StartWithWaitSignals(ctx, address, "", signals...)
}

// StartWithWaitSignalsHTTPS starts the HTTPS server with automatic graceful shutdown when the provided signals are received.
//
// This method starts the HTTPS server and waits (blocks) until the provided signals are received.
// When the signals are received, it automatically initiates a graceful shutdown with a 30-second timeout.
//
// Parameters:
//   - ctx: Context for controlling server lifecycle
//   - httpAddr: Address for HTTP server (empty string disables HTTP)
//   - httpsAddr: Address for HTTPS server (empty string disables HTTPS)
//   - signals: Signals to listen for (default: [os.Interrupt, syscall.SIGTERM])
//
// Example:
//
//	server, err := servex.New(
//		servex.WithCertificateFromFile("cert.pem", "key.pem"),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	err = server.StartWithWaitSignalsHTTPS(ctx, ":8443", os.Interrupt, syscall.SIGTERM)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Server will shutdown gracefully when ctx is cancelled
//	// or when the program receives a signal
func (s *Server) StartWithWaitSignalsHTTPS(ctx context.Context, address string, signals ...os.Signal) error {
	return s.StartWithWaitSignals(ctx, "", address, signals...)
}

// Shutdown gracefully shuts down both HTTP and HTTPS servers.
//
// This method attempts to gracefully shut down all running servers by:
//  1. Stopping acceptance of new connections
//  2. Allowing existing connections to complete their requests
//  3. Running all registered cleanup functions
//  4. Returning when all operations complete or the context times out
//
// The context controls the shutdown timeout. It's recommended to use a
// timeout context (e.g., 30 seconds) to prevent hanging on long-running requests.
//
// Parameters:
//   - ctx: Context with timeout for the shutdown operation
//
// Returns an error if any server fails to shut down properly. Multiple
// errors are joined using errors.Join().
//
// Example:
//
//	// Graceful shutdown with 30-second timeout
//	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//
//	if err := server.Shutdown(shutdownCtx); err != nil {
//		log.Printf("Server shutdown error: %v", err)
//	}
func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error
	if s.http != nil {
		if err := s.http.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown HTTP: %w", err))
		}
	}
	if s.https != nil {
		if err := s.https.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown HTTPS: %w", err))
		}
	}
	// Run all cleanup functions
	for _, cleanup := range s.cleanups {
		if cleanup != nil {
			cleanup()
		}
	}
	return errors.Join(errs...)
}

// HTTPAddress returns the address the HTTP server is listening on.
// Returns an empty string if the HTTP server is not running or not configured.
func (s *Server) HTTPAddress() string {
	if s.http == nil {
		return ""
	}
	return s.http.Addr
}

// HTTPSAddress returns the address the HTTPS server is listening on.
// Returns an empty string if the HTTPS server is not running or not configured.
func (s *Server) HTTPSAddress() string {
	if s.https == nil {
		return ""
	}
	return s.https.Addr
}

// AuthManager returns the server's authentication manager for manual auth operations.
//
// This provides access to the underlying AuthManager for advanced authentication
// use cases such as:
//   - Creating users programmatically
//   - Validating tokens manually
//   - Custom authentication flows
//   - User management operations
//
// Returns nil if authentication is not enabled (no database configured).
//
// Example:
//
//	if authMgr := server.AuthManager(); authMgr != nil {
//		ctx := context.Background()
//		err := authMgr.CreateUser(ctx, "admin", "secure-password", "admin", "user")
//		if err != nil {
//			log.Printf("Failed to create user: %v", err)
//		}
//	}
func (s *Server) AuthManager() *AuthManager {
	if !s.opts.Auth.Enabled {
		s.opts.Logger.Error("auth is not enabled, cannot return auth manager")
		return nil
	}
	return s.auth
}

// Filter returns the active filter instance for dynamic modification.
// Returns nil if no filter is configured or enabled.
//
// Example:
//
//	// Block an IP that accessed a honeypot
//	if filter := server.Filter(); filter != nil {
//	    err := filter.AddBlockedIP("192.168.1.100")
//	    if err != nil {
//	        log.Printf("Failed to block IP: %v", err)
//	    }
//	}
//
//	// Check if a User-Agent is blocked
//	if filter := server.Filter(); filter != nil {
//	    if filter.IsUserAgentBlocked("BadBot/1.0") {
//	        log.Println("User-Agent is blocked")
//	    }
//	}
func (s *Server) Filter() DynamicFilterMethods {
	return s.filter
}

// IsAuthEnabled returns true if authentication is enabled on this server.
//
// Authentication is enabled when a database is configured through
// WithAuth() or WithAuthMemoryDatabase() options.
func (s *Server) IsAuthEnabled() bool {
	return s.opts.Auth.Enabled
}

// IsTLS returns true if the HTTPS server is running.
//
// This indicates that the server has a TLS certificate configured
// and the HTTPS server has been started successfully.
func (s *Server) IsTLS() bool {
	return s.https != nil && s.https.Addr != ""
}

// IsHTTP returns true if the HTTP server is running.
//
// This indicates that the HTTP server has been started successfully
// and is accepting connections.
func (s *Server) IsHTTP() bool {
	return s.http != nil && s.http.Addr != ""
}

// registerBuiltinEndpoints registers health and metrics endpoints if enabled in options.
func (s *Server) registerBuiltinEndpoints() {
	// Register health endpoint if enabled
	if s.opts.EnableHealthEndpoint {
		healthPath := s.opts.HealthPath
		if healthPath == "" {
			healthPath = "/health"
		}
		s.router.HandleFunc(healthPath, s.healthHandler).Methods("GET")
	}

	// Register metrics endpoint if enabled
	if s.opts.EnableDefaultMetrics {
		metricsPath := s.opts.MetricsPath
		if metricsPath == "" {
			metricsPath = "/metrics"
		}
		// Register metrics endpoint using the built-in metrics
		if builtinMetrics, ok := s.opts.Metrics.(*builtinMetrics); ok {
			builtinMetrics.registerMetricsEndpoint(s, metricsPath)
		} else {
			s.opts.Logger.Error("cannot register metrics endpoint, metrics is not a BuiltinMetrics")
		}
	}
}

// healthHandler provides a simple health check endpoint.
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]any{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
	}
	C(w, r).Response(http.StatusOK, response)
}

func (s *Server) start(address string, serve func(net.Listener) error, getListener func(string, string) (net.Listener, error), readyChan chan error) error {
	if address == "" {
		return errors.New("address is required")
	}

	l, err := getListener("tcp", address)
	if err != nil {
		// Signal startup failure
		select {
		case readyChan <- err:
		default:
		}
		return err
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.opts.Logger.Error(string(debug.Stack()), "error", fmt.Errorf("%s", r))
				// Signal startup failure on panic
				select {
				case readyChan <- fmt.Errorf("server panic: %v", r):
				default:
				}
			}
		}()

		// Signal that server is ready to accept connections
		select {
		case readyChan <- nil:
		default:
		}

		if err := serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.opts.Logger.Error("cannot serve", "error", err, "address", address)
		}
	}()

	return nil
}

func prepareServer(cfg BaseConfig, handlerSetter func(*mux.Router), opts ...Option) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := ReadCertificateFromFile(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read certificate: %w", err)
		}
		opts = append(opts, WithCertificate(cert))
	}
	if cfg.AuthToken != "" {
		opts = append(opts, WithAuthToken(cfg.AuthToken))
	}

	s, err := NewServer(opts...)
	if err != nil {
		return nil, err
	}
	handlerSetter(s.router)

	return s, nil
}
