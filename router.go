package servex

import (
	"net/http"

	"github.com/gorilla/mux"
)

// WithBasePath sets the base path for the server's router.
// It returns the server itself to allow method chaining.
//
// NOTE: basePath is not safe for concurrent use. Call WithBasePath (and RemoveBasePath)
// only during route registration, before calling [Server.Start].
//
// Parameters:
//   - path: The base path to set for the router
//
// Example:
//
//	server.WithBasePath("/api")
//	server.Get("/users", ...)
//
//	Result: /api/users
//
// Returns:
//   - *Server: The server itself to allow method chaining
func (s *Server) WithBasePath(path string) *Server {
	if len(path) == 0 {
		return s
	}
	s.basePath = path
	return s
}

// RemoveBasePath clears the base path for the server's router.
// It returns the server itself to allow method chaining.
//
// Example:
//
//	server.WithBasePath("/api")
//	server.Get("/users", ...)      // Results in /api/users
//	server.RemoveBasePath()
//	server.Get("/health", ...)     // Results in /health
//
// Returns:
//   - *Server: The server itself to allow method chaining
func (s *Server) RemoveBasePath() *Server {
	s.basePath = ""
	return s
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

// AddMiddlewares adds one or more [mux.MiddlewareFunc] to the router.
func (s *Server) AddMiddlewares(middleware ...func(http.Handler) http.Handler) {
	for _, m := range middleware {
		if m == nil {
			continue
		}
		s.router.Use(m)
	}
}

// Use adds one or more [mux.MiddlewareFunc] to the router.
func (s *Server) Use(middleware ...func(http.Handler) http.Handler) {
	s.AddMiddlewares(middleware...)
}

// Handle registers a new route with the provided path, [http.Handler] and methods.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
//
// Parameters:
//   - path: The path to register the route for
//   - h: The handler to register the route for
//   - methods: The methods to register the route for
//
// Returns:
//   - *mux.Route: The created route to set additional settings to the route
func (s *Server) Handle(path string, h http.Handler, methods ...string) *mux.Route {
	r := s.router.PathPrefix(s.basePath).Subrouter().Handle(path, h)
	if len(methods) == 0 {
		return r
	}
	return r.Methods(methods...)
}

// H is a shortcut for [Server.Handle].
//
// Parameters:
//   - path: The path to register the route for
//   - h: The handler to register the route for
//   - methods: The methods to register the route for
//
// Returns:
//   - *mux.Route: The created route to set additional settings to the route
func (s *Server) H(path string, h http.Handler, methods ...string) *mux.Route {
	return s.Handle(path, h, methods...)
}

// HandleFunc registers a new route with the provided path, [http.HandlerFunc] and methods.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
//
// Parameters:
//   - path: The path to register the route for
//   - f: The handler to register the route for
//   - methods: The methods to register the route for
//
// Example:
//
//	server.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
//		w.Write([]byte("Hello, World!"))
//	}, GET, POST)
//
// Returns:
//   - *mux.Route: The created route to set additional settings to the route
func (s *Server) HandleFunc(path string, f http.HandlerFunc, methods ...string) *mux.Route {
	r := s.router.PathPrefix(s.basePath).Subrouter().HandleFunc(path, f)
	if len(methods) == 0 {
		return r
	}
	return r.Methods(methods...)
}

// HF is a shortcut for [Server.HandleFunc].
//
// Parameters:
//   - path: The path to register the route for
//   - f: The handler to register the route for
//   - methods: The methods to register the route for
//
// Example:
//
//	server.HF("/users", func(w http.ResponseWriter, r *http.Request) {
//		w.Write([]byte("Hello, World!"))
//	}, GET, POST)
//
// Returns:
//   - *mux.Route: The created route to set additional settings to the route
func (s *Server) HF(path string, f http.HandlerFunc, methods ...string) *mux.Route {
	return s.HandleFunc(path, f, methods...)
}

// WithAuth adds auth middleware to the router with the provided roles.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
//
// Parameters:
//   - next: The next handler to register the route for
//   - roles: The roles to register the route for
//
// Returns:
//   - http.HandlerFunc: The created handler to register the route for
func (s *Server) WithAuth(next http.HandlerFunc, roles ...UserRole) http.HandlerFunc {
	if s.auth == nil {
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

// Get registers a new GET route with the provided path and [http.HandlerFunc].
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) Get(path string, h http.HandlerFunc) *mux.Route {
	return s.HandleFunc(path, h, GET)
}

// GET is an alias for [Server.Get].
func (s *Server) GET(path string, h http.HandlerFunc) *mux.Route {
	return s.Get(path, h)
}

// GetWithAuth registers a new GET route with the provided path and [http.HandlerFunc].
// It adds auth middleware to the route with the provided roles.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) GetWithAuth(path string, h http.HandlerFunc, roles ...UserRole) *mux.Route {
	return s.Get(path, s.WithAuth(h, roles...))
}

// Post registers a new POST route with the provided path and [http.HandlerFunc].
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) Post(path string, h http.HandlerFunc) *mux.Route {
	return s.HandleFunc(path, h, POST)
}

// POST is an alias for [Server.Post].
func (s *Server) POST(path string, h http.HandlerFunc) *mux.Route {
	return s.Post(path, h)
}

// PostWithAuth registers a new POST route with the provided path and [http.HandlerFunc].
// It adds auth middleware to the route with the provided roles.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) PostWithAuth(path string, h http.HandlerFunc, roles ...UserRole) *mux.Route {
	return s.Post(path, s.WithAuth(h, roles...))
}

// Put registers a new PUT route with the provided path and [http.HandlerFunc].
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) Put(path string, h http.HandlerFunc) *mux.Route {
	return s.HandleFunc(path, h, PUT)
}

// PUT is an alias for [Server.Put].
func (s *Server) PUT(path string, h http.HandlerFunc) *mux.Route {
	return s.Put(path, h)
}

// PutWithAuth registers a new PUT route with the provided path and [http.HandlerFunc].
// It adds auth middleware to the route with the provided roles.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) PutWithAuth(path string, h http.HandlerFunc, roles ...UserRole) *mux.Route {
	return s.Put(path, s.WithAuth(h, roles...))
}

// Patch registers a new PATCH route with the provided path and [http.HandlerFunc].
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) Patch(path string, h http.HandlerFunc) *mux.Route {
	return s.HandleFunc(path, h, PATCH)
}

// PATCH is an alias for [Server.Patch].
func (s *Server) PATCH(path string, h http.HandlerFunc) *mux.Route {
	return s.Patch(path, h)
}

// PatchWithAuth registers a new PATCH route with the provided path and [http.HandlerFunc].
// It adds auth middleware to the route with the provided roles.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) PatchWithAuth(path string, h http.HandlerFunc, roles ...UserRole) *mux.Route {
	return s.Patch(path, s.WithAuth(h, roles...))
}

// Delete registers a new DELETE route with the provided path and [http.HandlerFunc].
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) Delete(path string, h http.HandlerFunc) *mux.Route {
	return s.HandleFunc(path, h, DELETE)
}

// DELETE is an alias for [Server.Delete].
func (s *Server) DELETE(path string, h http.HandlerFunc) *mux.Route {
	return s.Delete(path, h)
}

// DeleteWithAuth registers a new DELETE route with the provided path and [http.HandlerFunc].
// It adds auth middleware to the route with the provided roles.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) DeleteWithAuth(path string, h http.HandlerFunc, roles ...UserRole) *mux.Route {
	return s.Delete(path, s.WithAuth(h, roles...))
}

// Options registers a new OPTIONS route with the provided path and [http.HandlerFunc].
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) Options(path string, h http.HandlerFunc) *mux.Route {
	return s.HandleFunc(path, h, OPTIONS)
}

// OPTIONS is an alias for [Server.Options].
func (s *Server) OPTIONS(path string, h http.HandlerFunc) *mux.Route {
	return s.Options(path, h)
}

// OptionsWithAuth registers a new OPTIONS route with the provided path and [http.HandlerFunc].
// It adds auth middleware to the route with the provided roles.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) OptionsWithAuth(path string, h http.HandlerFunc, roles ...UserRole) *mux.Route {
	return s.Options(path, s.WithAuth(h, roles...))
}

// Head registers a new HEAD route with the provided path and [http.HandlerFunc].
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) Head(path string, h http.HandlerFunc) *mux.Route {
	return s.HandleFunc(path, h, HEAD)
}

// HEAD is an alias for [Server.Head].
func (s *Server) HEAD(path string, h http.HandlerFunc) *mux.Route {
	return s.Head(path, h)
}

// HeadWithAuth registers a new HEAD route with the provided path and [http.HandlerFunc].
// It adds auth middleware to the route with the provided roles.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) HeadWithAuth(path string, h http.HandlerFunc, roles ...UserRole) *mux.Route {
	return s.Head(path, s.WithAuth(h, roles...))
}

// Trace registers a new TRACE route with the provided path and [http.HandlerFunc].
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) Trace(path string, h http.HandlerFunc) *mux.Route {
	return s.HandleFunc(path, h, TRACE)
}

// TRACE is an alias for [Server.Trace].
func (s *Server) TRACE(path string, h http.HandlerFunc) *mux.Route {
	return s.Trace(path, h)
}

// TraceWithAuth registers a new TRACE route with the provided path and [http.HandlerFunc].
// It adds auth middleware to the route with the provided roles.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) TraceWithAuth(path string, h http.HandlerFunc, roles ...UserRole) *mux.Route {
	return s.Trace(path, s.WithAuth(h, roles...))
}

// Connect registers a new CONNECT route with the provided path and [http.HandlerFunc].
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) Connect(path string, h http.HandlerFunc) *mux.Route {
	return s.HandleFunc(path, h, CONNECT)
}

// CONNECT is an alias for [Server.Connect].
func (s *Server) CONNECT(path string, h http.HandlerFunc) *mux.Route {
	return s.Connect(path, h)
}

// ConnectWithAuth registers a new CONNECT route with the provided path and [http.HandlerFunc].
// It adds auth middleware to the route with the provided roles.
// It returns a pointer to the created [mux.Route] to set additional settings to the route.
func (s *Server) ConnectWithAuth(path string, h http.HandlerFunc, roles ...UserRole) *mux.Route {
	return s.Connect(path, s.WithAuth(h, roles...))
}

// Group creates a route group with the given path prefix.
// Routes registered on the group inherit the prefix and any middleware added via [Group.Use].
// Global middleware (rate limiting, security, logging, etc.) still applies to grouped routes.
//
// Example:
//
//	api := server.Group("/api/v1")
//	api.Use(rateLimitMiddleware)
//	api.Get("/users", listUsers)     // matches /api/v1/users
//	api.Post("/users", createUser)   // matches /api/v1/users
//
//	admin := server.Group("/admin")
//	admin.Get("/stats", statsHandler) // matches /admin/stats
func (s *Server) Group(prefix string) *Group {
	return &Group{
		subrouter: s.router.PathPrefix(prefix).Subrouter(),
		auth:      s.auth,
		opts:      &s.opts,
	}
}

// Group represents a route group with a shared path prefix and middleware.
// Create groups using [Server.Group]. Routes registered on a group inherit
// the prefix and all middleware added via [Group.Use].
type Group struct {
	subrouter    *mux.Router
	activeRouter *mux.Router // cached subrouter with basePath applied
	auth         *AuthManager
	opts         *Options
	basePath     string
}

// Group creates a sub-group with an additional path prefix.
// Middleware from the parent group applies to the sub-group.
func (g *Group) Group(prefix string) *Group {
	return &Group{
		subrouter: g.getRouter().PathPrefix(prefix).Subrouter(),
		auth:      g.auth,
		opts:      g.opts,
	}
}

// WithBasePath sets the base path for routes registered on this group.
func (g *Group) WithBasePath(path string) *Group {
	if len(path) == 0 {
		return g
	}
	g.basePath = path
	g.activeRouter = g.subrouter.PathPrefix(path).Subrouter()
	return g
}

// RemoveBasePath clears the base path for routes registered on this group.
func (g *Group) RemoveBasePath() *Group {
	g.basePath = ""
	g.activeRouter = nil
	return g
}

// Use adds middleware that runs only for routes registered on this group.
func (g *Group) Use(middleware ...func(http.Handler) http.Handler) {
	for _, m := range middleware {
		if m == nil {
			continue
		}
		g.subrouter.Use(m)
	}
}

// Router returns the underlying [mux.Router] for this group.
func (g *Group) Router() *mux.Router {
	return g.subrouter
}

func (g *Group) getRouter() *mux.Router {
	if g.activeRouter != nil {
		return g.activeRouter
	}
	return g.subrouter
}

// Handle registers a new route with the provided path and [http.Handler].
func (g *Group) Handle(path string, h http.Handler, methods ...string) *mux.Route {
	r := g.getRouter().Handle(path, h)
	if len(methods) == 0 {
		return r
	}
	return r.Methods(methods...)
}

// HandleFunc registers a new route with the provided path and [http.HandlerFunc].
func (g *Group) HandleFunc(path string, f http.HandlerFunc, methods ...string) *mux.Route {
	r := g.getRouter().HandleFunc(path, f)
	if len(methods) == 0 {
		return r
	}
	return r.Methods(methods...)
}

// WithAuth wraps a handler with auth middleware.
func (g *Group) WithAuth(next http.HandlerFunc, roles ...UserRole) http.HandlerFunc {
	if g.auth == nil {
		if g.opts != nil && g.opts.Logger != nil {
			g.opts.Logger.Error("auth is not enabled, skipping auth middleware")
		}
		return next
	}
	return g.auth.WithAuth(next, roles...)
}

// HandleWithAuth registers a route with auth middleware.
func (g *Group) HandleWithAuth(path string, h http.Handler, roles ...UserRole) *mux.Route {
	return g.getRouter().Handle(path, g.WithAuth(h.ServeHTTP, roles...))
}

// HandleFuncWithAuth registers a route with auth middleware.
func (g *Group) HandleFuncWithAuth(path string, f http.HandlerFunc, roles ...UserRole) *mux.Route {
	return g.getRouter().HandleFunc(path, g.WithAuth(f, roles...))
}

// Get registers a new GET route.
func (g *Group) Get(path string, h http.HandlerFunc) *mux.Route {
	return g.HandleFunc(path, h, GET)
}

// GET is an alias for [Group.Get].
func (g *Group) GET(path string, h http.HandlerFunc) *mux.Route {
	return g.Get(path, h)
}

// GetWithAuth registers a new GET route with auth middleware.
func (g *Group) GetWithAuth(path string, h http.HandlerFunc, roles ...UserRole) *mux.Route {
	return g.Get(path, g.WithAuth(h, roles...))
}

// Post registers a new POST route.
func (g *Group) Post(path string, h http.HandlerFunc) *mux.Route {
	return g.HandleFunc(path, h, POST)
}

// POST is an alias for [Group.Post].
func (g *Group) POST(path string, h http.HandlerFunc) *mux.Route {
	return g.Post(path, h)
}

// PostWithAuth registers a new POST route with auth middleware.
func (g *Group) PostWithAuth(path string, h http.HandlerFunc, roles ...UserRole) *mux.Route {
	return g.Post(path, g.WithAuth(h, roles...))
}

// Put registers a new PUT route.
func (g *Group) Put(path string, h http.HandlerFunc) *mux.Route {
	return g.HandleFunc(path, h, PUT)
}

// PUT is an alias for [Group.Put].
func (g *Group) PUT(path string, h http.HandlerFunc) *mux.Route {
	return g.Put(path, h)
}

// PutWithAuth registers a new PUT route with auth middleware.
func (g *Group) PutWithAuth(path string, h http.HandlerFunc, roles ...UserRole) *mux.Route {
	return g.Put(path, g.WithAuth(h, roles...))
}

// Patch registers a new PATCH route.
func (g *Group) Patch(path string, h http.HandlerFunc) *mux.Route {
	return g.HandleFunc(path, h, PATCH)
}

// PATCH is an alias for [Group.Patch].
func (g *Group) PATCH(path string, h http.HandlerFunc) *mux.Route {
	return g.Patch(path, h)
}

// PatchWithAuth registers a new PATCH route with auth middleware.
func (g *Group) PatchWithAuth(path string, h http.HandlerFunc, roles ...UserRole) *mux.Route {
	return g.Patch(path, g.WithAuth(h, roles...))
}

// Delete registers a new DELETE route.
func (g *Group) Delete(path string, h http.HandlerFunc) *mux.Route {
	return g.HandleFunc(path, h, DELETE)
}

// DELETE is an alias for [Group.Delete].
func (g *Group) DELETE(path string, h http.HandlerFunc) *mux.Route {
	return g.Delete(path, h)
}

// DeleteWithAuth registers a new DELETE route with auth middleware.
func (g *Group) DeleteWithAuth(path string, h http.HandlerFunc, roles ...UserRole) *mux.Route {
	return g.Delete(path, g.WithAuth(h, roles...))
}

// Options registers a new OPTIONS route.
func (g *Group) Options(path string, h http.HandlerFunc) *mux.Route {
	return g.HandleFunc(path, h, OPTIONS)
}

// OPTIONS is an alias for [Group.Options].
func (g *Group) OPTIONS(path string, h http.HandlerFunc) *mux.Route {
	return g.Options(path, h)
}

// Head registers a new HEAD route.
func (g *Group) Head(path string, h http.HandlerFunc) *mux.Route {
	return g.HandleFunc(path, h, HEAD)
}

// HEAD is an alias for [Group.Head].
func (g *Group) HEAD(path string, h http.HandlerFunc) *mux.Route {
	return g.Head(path, h)
}

// --- Per-route middleware chain ---

// Middleware is a function that wraps an http.Handler.
type Middleware = func(http.Handler) http.Handler

// MiddlewareChain allows attaching middleware to individual route registrations.
// Create via [Server.With] or [Group.With].
//
// Example:
//
//	server.With(auditLog, adminOnly).Post("/admin/action", handler)
type MiddlewareChain struct {
	middlewares []Middleware
	server      *Server // non-nil when created from Server
	group       *Group  // non-nil when created from Group
}

// With creates a MiddlewareChain for per-route middleware.
// Middleware is applied in order: the first middleware is the outermost wrapper.
//
// Example:
//
//	server.With(rateLimiter, auditLog).Get("/secure", handler)
func (s *Server) With(middleware ...Middleware) *MiddlewareChain {
	return &MiddlewareChain{middlewares: middleware, server: s}
}

// With creates a MiddlewareChain for per-route middleware on a Group.
func (g *Group) With(middleware ...Middleware) *MiddlewareChain {
	return &MiddlewareChain{middlewares: middleware, group: g}
}

// applyChain wraps handler with all middleware in order.
func (mc *MiddlewareChain) applyChain(h http.HandlerFunc) http.HandlerFunc {
	if len(mc.middlewares) == 0 {
		return h
	}
	var handler http.Handler = h
	for i := len(mc.middlewares) - 1; i >= 0; i-- {
		handler = mc.middlewares[i](handler)
	}
	return handler.ServeHTTP
}

func (mc *MiddlewareChain) handleFunc(path string, h http.HandlerFunc, methods ...string) *mux.Route {
	wrapped := mc.applyChain(h)
	if mc.server != nil {
		return mc.server.HandleFunc(path, wrapped, methods...)
	}
	if mc.group != nil {
		return mc.group.HandleFunc(path, wrapped, methods...)
	}
	panic("servex: MiddlewareChain has neither server nor group set")
}

// Handle registers a route with an http.Handler with the middleware chain applied.
func (mc *MiddlewareChain) Handle(path string, h http.Handler, methods ...string) *mux.Route {
	return mc.handleFunc(path, h.ServeHTTP, methods...)
}

// HandleFunc registers a route with an http.HandlerFunc with the middleware chain applied.
func (mc *MiddlewareChain) HandleFunc(path string, h http.HandlerFunc, methods ...string) *mux.Route {
	return mc.handleFunc(path, h, methods...)
}

// Get registers a GET route with the middleware chain applied.
func (mc *MiddlewareChain) Get(path string, h http.HandlerFunc) *mux.Route {
	return mc.handleFunc(path, h, GET)
}

// GET is an alias for [MiddlewareChain.Get].
func (mc *MiddlewareChain) GET(path string, h http.HandlerFunc) *mux.Route {
	return mc.Get(path, h)
}

// Post registers a POST route with the middleware chain applied.
func (mc *MiddlewareChain) Post(path string, h http.HandlerFunc) *mux.Route {
	return mc.handleFunc(path, h, POST)
}

// POST is an alias for [MiddlewareChain.Post].
func (mc *MiddlewareChain) POST(path string, h http.HandlerFunc) *mux.Route {
	return mc.Post(path, h)
}

// Put registers a PUT route with the middleware chain applied.
func (mc *MiddlewareChain) Put(path string, h http.HandlerFunc) *mux.Route {
	return mc.handleFunc(path, h, PUT)
}

// PUT is an alias for [MiddlewareChain.Put].
func (mc *MiddlewareChain) PUT(path string, h http.HandlerFunc) *mux.Route {
	return mc.Put(path, h)
}

// Patch registers a PATCH route with the middleware chain applied.
func (mc *MiddlewareChain) Patch(path string, h http.HandlerFunc) *mux.Route {
	return mc.handleFunc(path, h, PATCH)
}

// PATCH is an alias for [MiddlewareChain.Patch].
func (mc *MiddlewareChain) PATCH(path string, h http.HandlerFunc) *mux.Route {
	return mc.Patch(path, h)
}

// Delete registers a DELETE route with the middleware chain applied.
func (mc *MiddlewareChain) Delete(path string, h http.HandlerFunc) *mux.Route {
	return mc.handleFunc(path, h, DELETE)
}

// DELETE is an alias for [MiddlewareChain.Delete].
func (mc *MiddlewareChain) DELETE(path string, h http.HandlerFunc) *mux.Route {
	return mc.Delete(path, h)
}

// Options registers an OPTIONS route with the middleware chain applied.
func (mc *MiddlewareChain) Options(path string, h http.HandlerFunc) *mux.Route {
	return mc.handleFunc(path, h, OPTIONS)
}

// OPTIONS is an alias for [MiddlewareChain.Options].
func (mc *MiddlewareChain) OPTIONS(path string, h http.HandlerFunc) *mux.Route {
	return mc.Options(path, h)
}

// Head registers a HEAD route with the middleware chain applied.
func (mc *MiddlewareChain) Head(path string, h http.HandlerFunc) *mux.Route {
	return mc.handleFunc(path, h, HEAD)
}

// HEAD is an alias for [MiddlewareChain.Head].
func (mc *MiddlewareChain) HEAD(path string, h http.HandlerFunc) *mux.Route {
	return mc.Head(path, h)
}
