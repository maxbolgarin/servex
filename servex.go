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
	opts   Options
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
	if opts.RequestLogger == nil {
		opts.RequestLogger = &BaseRequestLogger{opts.Logger}
	}

	s := &Server{
		router: mux.NewRouter(),
		opts:   opts,
	}

	RegisterLoggingMiddleware(s.router, opts.RequestLogger, opts.Metrics)
	RegisterRecoverMiddleware(s.router, opts.Logger)
	RegisterSimpleAuthMiddleware(s.router, opts.AuthToken)

	return s
}

// Start starts the server with the provided [BaseConfig] and [Option]s.
// It returns an error if there was an error starting either of the servers.
// You should provide a function that sets the handlers for the server to the router.
// It returns shutdown function so you should shutdown the server manually.
func Start(cfg BaseConfig, handlerSetter func(*mux.Router), opts ...Option) (shutdown func(context.Context) error, err error) {
	s, err := prepareServer(cfg, handlerSetter, opts...)
	if err != nil {
		return nil, err
	}
	s.Start(cfg.HTTP, cfg.HTTPS)
	return s.Shutdown, nil
}

// Start starts the server with the provided [BaseConfig] and [Option]s.
// It returns an error if there was an error starting either of the servers.
// You should provide a function that sets the handlers for the server to the router.
// It shutdowns the server when the context is closed (it starts a goroutine to check [Context.Done]).
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
	s.http = &http.Server{
		Addr:              address,
		Handler:           s.router,
		ReadHeaderTimeout: lang.Check(s.opts.ReadHeaderTimeout, defaultReadTimeout),
		ReadTimeout:       lang.Check(s.opts.ReadTimeout, defaultReadTimeout),
		IdleTimeout:       lang.Check(s.opts.IdleTimeout, defaultIdleTimeout),
	}
	if err := s.start(address, s.http.Serve, net.Listen); err != nil {
		return err
	}
	s.opts.Logger.Info("http server started", "address", address)

	return nil
}

// StartHTTPS starts an HTTPS server on the provided address.
// It returns an error if the server cannot be started, address is invalid or no certificate is provided in config.
func (s *Server) StartHTTPS(address string) error {
	if s.opts.Certificate == nil {
		return errors.New("TLS certificate is required for HTTPS server")
	}
	s.https = &http.Server{
		Addr:              address,
		Handler:           s.router,
		ReadHeaderTimeout: lang.Check(s.opts.ReadHeaderTimeout, defaultReadTimeout),
		ReadTimeout:       lang.Check(s.opts.ReadTimeout, defaultReadTimeout),
		IdleTimeout:       lang.Check(s.opts.IdleTimeout, defaultIdleTimeout),
		TLSConfig:         GetTLSConfig(s.opts.Certificate),
	}
	if err := s.start(address, s.https.Serve, func(net, addr string) (net.Listener, error) {
		return tls.Listen(net, addr, s.https.TLSConfig)
	}); err != nil {
		return err
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
	return errors.Join(errs...)
}

// HTTPAddress returns the address that HTTP server is listening.
// It returns an empty string if server is not started.
func (s *Server) HTTPAddress() string {
	return s.http.Addr
}

// HTTPSAddress returns the address that HTTPS server is listening.
// It returns an empty string if server is not started.
func (s *Server) HTTPSAddress() string {
	return s.https.Addr
}

// Router returns [mux.Router], it may be useful if you want to work with router manually.
func (s *Server) Router() *mux.Router {
	return s.router
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
	r := s.router.Handle(path, h)
	if len(methods) == 0 {
		return r
	}
	return r.Methods(methods...)
}

// Handle registers a new route with the provided path, [http.HandlerFunc] and methods.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) HandleFunc(path string, f http.HandlerFunc, methods ...string) *mux.Route {
	r := s.router.HandleFunc(path, f)
	if len(methods) == 0 {
		return r
	}
	return r.Methods(methods...)
}

func (s *Server) start(address string, serve func(net.Listener) error, getListener func(string, string) (net.Listener, error)) error {
	if address == "" {
		return errors.New("address is required")
	}

	l, err := getListener("tcp", address)
	if err != nil {
		return err
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.opts.Logger.Error(string(debug.Stack()), "error", fmt.Errorf("%s", r))
			}
		}()
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
