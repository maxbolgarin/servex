# Servex - Lightweight HTTP(S) Server Package

[![Go Version][version-img]][doc] [![GoDoc][doc-img]][doc] [![Build][ci-img]][ci] [![GoReport][report-img]][report]

**Servex** is a lightweight HTTP(S) server package built using Go's [net/http](https://pkg.go.dev/net/http) and [gorilla/mux](https://github.com/gorilla/mux). This package is designed to easy integrate into existing `net/http` servers. By using `gorilla/mux`, it offers flexible routing capabilities with the integrated middleware for logging, authentication and panic recovery.


## Table of Contents
- [Why Servex](#why-servex)
- [Installation](#installation)
- [Usage](#usage)
  - [Starting a Server](#starting-a-server)
  - [Using Context in Handlers](#using-context-in-handlers)
  - [Authentication](#authentication)
  - [Rate Limiter](#rate-limiter)
- [Configuration Options](#configuration-options)
- [Key Features](#key-features)
- [Pros and Cons](#pros-and-cons)
- [Contributing](#contributing)
- [License](#license)


## Why Servex

Image you have a web appiction with vanila `net/http` handler:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    bodyBytes, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "cannot read request body", http.StatusBadRequest)
        return
    }

    var request Request
    if err := json.Unmarshal(bodyBytes, &request); err != nil {
        http.Error(w, "invalid request body", http.StatusBadRequest)
        return
    }

    // ... do something with request

    respBytes, err := json.Marshal(resp)
    if err != nil {
        http.Error(w, "cannot marshal response", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Content-Length", strconv.Itoa(len(respBytes)))

    if _, err := w.Write(respBytes); err != nil {
        http.Error(w, "cannot write response", http.StatusInternalServerError)
        return
    }
}
```

With **Servex** you can write your handler like this:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)

    request, err := servex.ReadJSON[Request](r)
    if err != nil {
        ctx.BadRequest(err, "invalid request body")
        return
    }

    // ... do something with request

    ctx.Response(http.StatusOK, resp)
}
```

Less code, more focus on business logic. Implement in your handler just by calling `servex.C(w, r)`. Look at the usage examples below to see options for starting a server with **Servex** in easy way.


## Installation

To install the package, use the following `go get` command:

```shell
go get -u github.com/maxbolgarin/servex
```


## Usage

### Starting a Server

There are multiple ways to set up a Servex server:

#### 1. Quick Start with Configuration

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// Configure the server
config := servex.BaseConfig{
    HTTP: ":8080", // HTTP address
    HTTPS: ":8443", // HTTPS address
    CertFile: "cert.pem", // TLS certificate file
    KeyFile: "key.pem", // TLS key file
}

// Set up routes
routes := func(r *mux.Router) {
    r.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Hello, world!")
    }).Methods(http.MethodGet)
}

// Initialize and start the server
err := servex.StartWithShutdown(ctx, config, routes, servex.WithLogger(slog.Default()))
if err != nil {
    log.Fatalf("failed to start servers: %v", err)
}

// ... some code ...

cancel() // Shutdown the server
```

#### 2. Using the Server Object

```go
// Initialize and start the server
srv := servex.New(
    servex.WithReadTimeout(10*time.Second),
    servex.WithLogger(slog.Default()), 
    servex.WithCertificate(cert),
)

srv.HandleFunc("/hello", helloHandler)
srv.HandleFunc("/world", worldHandler)

if err := srv.Start(":8080", ":8443"); err != nil {
    log.Fatalf("failed to start servers: %v", err)
}

// ... some code ...

srv.Shutdown(ctx)
```

#### 3. Server with Graceful Shutdown

```go
srv := servex.New(servex.WithLogger(slog.Default()))

// Register routes
srv.R().HandleFunc("/api/v1/health", healthHandler).Methods(http.MethodGet)
srv.R("/api/v1").HandleFunc("/users", usersHandler).Methods(http.MethodGet)

// Start with automatic shutdown on context cancellation
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

if err := srv.StartWithShutdown(ctx, ":8080", ""); err != nil {
    log.Fatalf("failed to start server: %v", err)
}

// Server will shut down automatically when context is canceled
```

### Using Context in Handlers

Servex can be integrated into existing `net/http` servers - you can create `servex.Context` based on the `http.Request` and `http.ResponseWriter` objects and use it in your handlers.

```go
func (app *App) CreateUserHandler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)

    userRequest, err := servex.ReadJSON[User](r)
    if err != nil {
        ctx.BadRequest(err, "invalid user")
        return
    }

    userIDResponse, err := app.CreateUser(ctx, userRequest);
    if err != nil {
        ctx.InternalServerError(err, "cannot create user")
        return
    }

    ctx.Response(http.StatusCreated, userIDResponse)
}
```

With `servex.Context` you can get the experience of working in an HTTP framework like [echo](https://github.com/labstack/echo) inside plain `net/http` servers.

#### Context Helpers

Servex's Context provides many helper methods:

```go
func exampleHandler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    
    // Get request information
    requestID := ctx.RequestID()
    apiVersion := ctx.APIVersion() // Extracts 'v1' from paths like /api/v1/...
    userID := ctx.Path("id")       // Path parameters from URL
    sort := ctx.Query("sort")      // Query parameters ?sort=asc
    
    // Read and validate request bodies
    user, err := servex.ReadJSON[User](r)
    // OR with validation if User implements Validate() method
    user, err := servex.ReadAndValidate[User](r)
    
    // Handle cookies
    cookie, _ := ctx.Cookie("session")
    ctx.SetCookie("session", "token123", 3600, true, true)
    
    // Send responses with proper headers
    ctx.Response(http.StatusOK, map[string]string{"status": "success"})
    
    // Or handle errors with consistent formatting
    ctx.BadRequest(err, "invalid input: %s", err.Error())
    ctx.NotFound(err, "user not found")
    ctx.InternalServerError(err, "database error")
}
```

### Authentication

Servex includes a built-in JWT-based authentication system:

#### 1. Setting Up Authentication

```go
// Create an in-memory auth database
memoryDB := servex.NewMemoryAuthDatabase()

// Configure the server with authentication
srv := servex.New(
    servex.WithAuth(servex.AuthConfig{
        Database: memoryDB,
        RolesOnRegister: []servex.UserRole{"user"}, // Default roles for new users
        AccessTokenDuration: 15 * time.Minute,
        RefreshTokenDuration: 7 * 24 * time.Hour,
        InitialUsers: []servex.InitialUser{
            {Username: "admin", Password: "admin123", Roles: []servex.UserRole{"admin", "user"}},
        },
    }),
)

// Authentication routes are automatically registered under /auth/...
// - POST /auth/register - Register new user
// - POST /auth/login - Login and get tokens
// - POST /auth/refresh - Refresh access token
// - POST /auth/logout - Logout (invalidate refresh token)
// - GET /auth/me - Get current user info (requires authentication)

// Create protected routes
srv.HandleFuncWithAuth("/admin", adminHandler, "admin") // Only users with "admin" role can access
srv.HFA("/protected", protectedHandler, "user")         // Short form for HandleFuncWithAuth
```

#### 2. Authentication in Existing Handlers

```go
func (app *App) AdminOnlyHandler(w http.ResponseWriter, r *http.Request) {
    ctx := servex.C(w, r)
    
    // Get user ID from context (set by auth middleware)
    userID, ok := r.Context().Value(servex.UserContextKey{}).(string)
    if !ok {
        ctx.Unauthorized(errors.New("not authenticated"), "authentication required")
        return
    }
    
    // Get user roles 
    roles, _ := r.Context().Value(servex.RoleContextKey{}).([]servex.UserRole)
    
    // ... handle the request
    
    ctx.Response(http.StatusOK, result)
}
```

#### 3. Login Flow Example

```go
// Client sends login request
// POST /auth/login
// {"username": "user1", "password": "pass123"}

// Server responds with:
// 200 OK
// {
//   "id": "user-id-123",
//   "username": "user1",
//   "roles": ["user"],
//   "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
// }
// Set-Cookie: refresh_token=token123; HttpOnly; Secure; SameSite=Strict

// Client uses accessToken in Authorization header
// GET /api/protected
// Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

// When access token expires, client sends refresh request
// POST /auth/refresh
// (refresh_token cookie is sent automatically)
```

### Rate Limiter

Servex includes a built-in rate limiting middleware:

```go
// Configure and start server with rate limiting
srv := servex.New(
    servex.WithRPS(100), // 100 requests per second
    servex.WithRateLimitExcludePaths("/health", "/docs")
)


// Rate limiting by username for login attempts
customKeyFunc := func(r *http.Request) string {
    // Extract username from request for more accurate rate limiting
    // on login endpoints
    if r.URL.Path == "/login" {
        username := r.FormValue("username")
        if username != "" {
            return "user:" + username
        }
    }
    // Fall back to IP-based limiting
    return r.RemoteAddr
}

srv := servex.New(
    servex.WithRateLimitConfig(servex.RateLimitConfig{
        RequestsPerInterval: 5,
        Interval:            time.Minute,
        KeyFunc:             customKeyFunc,
    }),
)
```

## Configuration Options

Servex allows customization through options passed during server instantiation. Here's how you can configure it:

- **WithCertificate**: Set TLS certificate for HTTPS.
- **WithReadTimeout**: Customize read timeout duration.
- **WithIdleTimeout**: Customize idle timeout duration.
- **WithAuthToken**: Set an authorization token for middleware-based authentication.
- **WithMetrics**: Attach a metrics handler to track requests.
- **WithLogger**: Specify a custom logging mechanism.
- **WithRequestLogger**: Customizes request logging separately from server logging.
- **WithAuth**: Configure JWT-based authentication with roles.
- **WithRateLimitConfig**: Configure rate limiting with custom options.
- **WithRPM**: Set rate limit to requests per minute.
- **WithRPS**: Set rate limit to requests per second.

Example:

```go
options := []servex.Option{
    servex.WithReadTimeout(30 * time.Second),
    servex.WithIdleTimeout(120 * time.Second),
    servex.WithAuthToken("s3cret"),
    servex.WithRPS(10), // Limit to 10 requests per second
}

// Create server with options
server := servex.NewWithOptions(servex.Options{
    ReadTimeout:   30 * time.Second,
    IdleTimeout:   120 * time.Second,
    AuthToken:     "s3cret",
    RateLimit: servex.RateLimitConfig{
        RequestsPerInterval: 10,
        Interval:            time.Second,
        BurstSize:           20, // Allow bursts of up to 20 requests
        ExcludePaths:        []string{"/health", "/metrics"},
    },
})
```

## Key Features

- **Simplified HTTP Handling**: Context-based request/response handling with type safety
- **Flexible Routing**: Powered by gorilla/mux with subrouters, path variables, etc.
- **Built-in Authentication**: JWT-based authentication with refresh tokens and role-based access
- **Rate Limiting**: Built-in middleware for restricting request frequency with customizable options
- **Structured Error Responses**: Consistent error formatting across all endpoints
- **Graceful Shutdown**: Clean shutdown capabilities for both HTTP and HTTPS servers
- **TLS Support**: Easy HTTPS configuration with certificate management
- **Integrated Middleware**: Logging, authentication, panic recovery out of the box
- **Type-Safe JSON Handling**: Generic functions for reading and validating JSON requests

## Pros and Cons

### Pros
- **Lightweight**: Minimal overhead, quick to integrate.
- **Flexible Routing**: Powered by `gorilla/mux`, allowing for precise routing and path handling.
- **Built-in Middleware**: Includes logging, authentication, and panic recovery.
- **Context-based Request Handling**: No more boilerplate for reading requests and sending responses.
- **Type Safety**: Generics support for JSON handling with less boilerplate.
- **Roles-Based Auth**: Built-in JWT authentication with refresh tokens and role-based access control.

### Cons
- **Basic Documentation**: Might require understanding of underlying `gorilla/mux` for advanced use cases.
- **Lack of Features**: It is not a framework for complex server architectures.
- **Limited Database Options**: Currently supports only in-memory database for auth out of the box. You should implement it's own database it you want to use auth.

## Contributing

If you'd like to contribute to **servex**, submit a pull request or open an issue.

## License

Servex is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

[version-img]: https://img.shields.io/badge/Go-%3E%3D%201.24-%23007d9c
[doc-img]: https://pkg.go.dev/badge/github.com/maxbolgarin/servex
[doc]: https://pkg.go.dev/github.com/maxbolgarin/servex
[ci-img]: https://github.com/maxbolgarin/servex/actions/workflows/go.yml/badge.svg
[ci]: https://github.com/maxbolgarin/servex/actions
[report-img]: https://goreportcard.com/badge/github.com/maxbolgarin/servex
[report]: https://goreportcard.com/report/github.com/maxbolgarin/servex
