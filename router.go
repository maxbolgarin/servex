package servex

import (
	"net/http"

	"github.com/gorilla/mux"
)

// WithBasePath sets the base path for the server's router.
// It returns the server itself to allow method chaining.
func (s *Server) WithBasePath(path string) *Server {
	if len(path) == 0 {
		return s
	}
	s.basePath = path
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
	if !s.opts.Auth.Enabled {
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
