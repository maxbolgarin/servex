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
	"runtime/debug"
	"time"

	"github.com/gorilla/mux"
	"github.com/maxbolgarin/lang"
)

// Server represents an HTTP server.
type Server struct {
	http   *http.Server
	https  *http.Server
	router *mux.Router
	auth   *AuthManager
	opts   Options

	basePath string
	cleanup  func()
}

// New creates a new instance of the [Server]. You can provide a list of options using With* methods.
// Server without Certificate can serve only plain HTTP.
func New(ops ...Option) *Server {
	return NewWithOptions(parseOptions(ops))
}

// NewWithOptions creates a new instance of the [Server] with the provided [Options].
func NewWithOptions(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}
	if opts.RequestLogger == nil && !opts.DisableRequestLogging {
		opts.RequestLogger = &BaseRequestLogger{opts.Logger}
	}
	if opts.DisableRequestLogging {
		opts.RequestLogger = &noopRequestLogger{}
	}
	opts.Auth.enabled = opts.Auth.Database != nil

	s := &Server{
		router: mux.NewRouter(),
		opts:   opts,
	}

	if opts.RateLimit.RequestsPerInterval <= 0 && !opts.RateLimit.NoRateInAuthRoutes {
		opts.RateLimit.RequestsPerInterval = 5
		opts.RateLimit.Interval = time.Minute
		opts.RateLimit.IncludePaths = []string{opts.Auth.AuthBasePath}
	}
	if opts.RateLimit.RequestsPerInterval > 0 && !opts.RateLimit.NoRateInAuthRoutes {
		if opts.RateLimit.IncludePaths != nil {
			opts.RateLimit.IncludePaths = append(opts.RateLimit.IncludePaths, opts.Auth.AuthBasePath)
		}
		// If rate limit is enabled without include routes -> it will be applied to all routes
		// So we dont need to include auth routes in the include list
	}

	s.cleanup = RegisterRateLimitMiddleware(s.router, opts.RateLimit)
	RegisterFilterMiddleware(s.router, opts.Filter)
	RegisterSecurityHeadersMiddleware(s.router, opts.Security)
	if len(opts.CustomHeaders) > 0 {
		RegisterCustomHeadersMiddleware(s.router, opts.CustomHeaders)
	}
	if len(opts.HeadersToRemove) > 0 {
		RegisterHeaderRemovalMiddleware(s.router, opts.HeadersToRemove)
	}
	RegisterLoggingMiddleware(s.router, opts.RequestLogger, opts.Metrics)
	RegisterRecoverMiddleware(s.router, opts.Logger)
	RegisterSimpleAuthMiddleware(s.router, opts.AuthToken)
	registerOptsMiddleware(s.router, opts)

	// Register health and metrics endpoints if enabled
	s.registerBuiltinEndpoints()

	return s
}

// Start starts the server with the provided [BaseConfig] and [Option]s.
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
//	shutdown, err := servex.Start(cfg, func(r *mux.Router) {
//		r.HandleFunc("/api/users", handleUsers)
//		r.HandleFunc("/api/health", handleHealth)
//	}, servex.WithAuthToken("secret-token"))
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer shutdown(context.Background())
func Start(cfg BaseConfig, handlerSetter func(*mux.Router), opts ...Option) (shutdown func(context.Context) error, err error) {
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
//	err := servex.StartWithShutdown(ctx, cfg, func(r *mux.Router) {
//		r.HandleFunc("/api/users", handleUsers)
//		r.HandleFunc("/api/health", handleHealth)
//	}, servex.WithAuthToken("secret-token"))
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Server will automatically shutdown when ctx is cancelled
//	// or when the context deadline is reached
func StartWithShutdown(ctx context.Context, cfg BaseConfig, handlerSetter func(*mux.Router), opts ...Option) error {
	s, err := prepareServer(cfg, handlerSetter, opts...)
	if err != nil {
		return err
	}
	return s.StartWithShutdown(ctx, cfg.HTTP, cfg.HTTPS)
}

// Start starts the server. It takes two parameters: httpAddr and httpsAddr - addresses to listen for HTTP and HTTPS.
// It returns an error if there was an error starting either of the servers.
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

// StartHTTP starts an HTTP server on the provided address.
// It returns an error if the server cannot be started or address is invalid.
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

// StartHTTPS starts an HTTPS server on the provided address.
// It returns an error if the server cannot be started, address is invalid or no certificate is provided in config.
func (s *Server) StartHTTPS(address string) error {
	// Reset the ready channel for fresh startup
	httpsReady := make(chan error, 1)

	if s.opts.Certificate == nil {
		if s.opts.CertFilePath == "" || s.opts.KeyFilePath == "" {
			return errors.New("TLS certificate is required for HTTPS server")
		}
		cert, err := ReadCertificateFromFile(s.opts.CertFilePath, s.opts.KeyFilePath)
		if err != nil {
			return fmt.Errorf("read certificate from file cert=%s, key=%s: %w", s.opts.CertFilePath, s.opts.KeyFilePath, err)
		}
		s.opts.Certificate = &cert
	}

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

// StartWithShutdown starts HTTP and HTTPS servers and shutdowns its when the context is closed.
func (s *Server) StartWithShutdown(ctx context.Context, httpAddr, httpsAddr string) error {
	err := s.Start(httpAddr, httpsAddr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			s.opts.Logger.Error("cannot shutdown", "error", err)
		}
	}()
	return nil
}

// StartWithShutdownHTTP starts the HTTP server and shutdowns it when the context is closed.
func (s *Server) StartWithShutdownHTTP(ctx context.Context, address string) error {
	return s.StartWithShutdown(ctx, address, "")
}

// StartWithShutdownHTTPS starts the HTTPS server and shutdowns it when the context is closed.
func (s *Server) StartWithShutdownHTTPS(ctx context.Context, address string) error {
	return s.StartWithShutdown(ctx, "", address)
}

// Shutdown gracefully shutdowns HTTP and HTTPS servers.
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
	if s.cleanup != nil {
		s.cleanup()
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

// Router returns [mux.Router], it may be useful if you want to work with router manually.
// It accepts a path to set as a base path for the router.
func (s *Server) Router(path ...string) *mux.Router {
	if len(path) == 0 {
		return s.router
	}
	return s.router.PathPrefix(path[0]).Subrouter()
}

// R is a shortcut for [Server.Router].
func (s *Server) R(path ...string) *mux.Router {
	return s.Router(path...)
}

// WithBasePath sets the base path for the server's router.
// It returns the server itself to allow method chaining.
func (s *Server) WithBasePath(path string) *Server {
	if len(path) == 0 {
		return s
	}
	s.basePath = path
	return s
}

// AuthManager returns [AuthManager], it may be useful if you want to work with auth manually.
// It returns nil if auth is not enabled (database is not set).
func (s *Server) AuthManager() *AuthManager {
	if !s.opts.Auth.enabled {
		s.opts.Logger.Error("auth is not enabled, cannot return auth manager")
		return nil
	}
	return s.auth
}

// IsAuthEnabled returns true if auth is enabled.
func (s *Server) IsAuthEnabled() bool {
	return s.opts.Auth.enabled
}

// IsTLS returns true if TLS is enabled.
func (s *Server) IsTLS() bool {
	return s.https != nil && s.https.Addr != ""
}

// IsHTTP returns true if HTTP is enabled.
func (s *Server) IsHTTP() bool {
	return s.http != nil && s.http.Addr != ""
}

// AddMiddleware adds one or more [mux.MiddlewareFunc] to the router.
func (s *Server) AddMiddleware(middleware ...func(http.Handler) http.Handler) {
	for _, m := range middleware {
		if m == nil {
			continue
		}
		s.router.Use(m)
	}
}

// Handle registers a new route with the provided path, [http.Handler] and methods.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) Handle(path string, h http.Handler, methods ...string) *mux.Route {
	r := s.router.PathPrefix(s.basePath).Subrouter().Handle(path, h)
	if len(methods) == 0 {
		return r
	}
	return r.Methods(methods...)
}

// H is a shortcut for [Server.Handle].
func (s *Server) H(path string, h http.Handler, methods ...string) *mux.Route {
	return s.Handle(path, h, methods...)
}

// HandleFunc registers a new route with the provided path, [http.HandlerFunc] and methods.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) HandleFunc(path string, f http.HandlerFunc, methods ...string) *mux.Route {
	r := s.router.PathPrefix(s.basePath).Subrouter().HandleFunc(path, f)
	if len(methods) == 0 {
		return r
	}
	return r.Methods(methods...)
}

// HF is a shortcut for [Server.HandleFunc].
func (s *Server) HF(path string, f http.HandlerFunc, methods ...string) *mux.Route {
	return s.HandleFunc(path, f, methods...)
}

// WithAuth adds auth middleware to the router with the provided roles.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) WithAuth(next http.HandlerFunc, roles ...UserRole) http.HandlerFunc {
	if !s.opts.Auth.enabled {
		s.opts.Logger.Error("auth is not enabled, skipping auth middleware")
		return next
	}
	return s.auth.WithAuth(next, roles...)
}

// HandleWithAuth registers a new route with the provided path, [http.Handler] and methods.
// It adds auth middleware to the route with the provided roles.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) HandleWithAuth(path string, h http.Handler, roles ...UserRole) *mux.Route {
	return s.router.PathPrefix(s.basePath).Subrouter().Handle(path, s.WithAuth(h.ServeHTTP, roles...))
}

// HA is a shortcut for [Server.HandleWithAuth].
func (s *Server) HA(path string, f http.HandlerFunc, roles ...UserRole) *mux.Route {
	return s.HandleWithAuth(path, f, roles...)
}

// HandleFuncWithAuth registers a new route with the provided path, [http.HandlerFunc] and methods.
// It adds auth middleware to the route with the provided roles.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) HandleFuncWithAuth(path string, f http.HandlerFunc, roles ...UserRole) *mux.Route {
	return s.router.PathPrefix(s.basePath).Subrouter().HandleFunc(path, s.WithAuth(f, roles...))
}

// HFA is a shortcut for [Server.HandleFuncWithAuth].
func (s *Server) HFA(path string, f http.HandlerFunc, roles ...UserRole) *mux.Route {
	return s.HandleFuncWithAuth(path, f, roles...)
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

	if s.opts.Auth.enabled && !s.opts.Auth.isInitialized {
		if s.opts.Auth.Database == nil {
			return errors.New("auth database is required")
		}
		authManager, err := NewAuthManager(s.opts.Auth)
		if err != nil {
			return fmt.Errorf("cannot create auth manager: %w", err)
		}
		s.auth = authManager

		s.auth.RegisterRoutes(s.router)

		for _, user := range s.opts.Auth.InitialUsers {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			err := s.auth.CreateUser(ctx, user.Username, user.Password, user.Roles...)
			if err != nil {
				return fmt.Errorf("cannot create initial user with name=%s: %w", user.Username, err)
			}
		}
		s.opts.Auth.isInitialized = true
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

	s := New(opts...)
	handlerSetter(s.router)

	return s, nil
}
