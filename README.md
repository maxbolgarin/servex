# Servex - Lightweight HTTP(S) Server Package

[![Go Version][version-img]][doc] [![GoDoc][doc-img]][doc] [![Build][ci-img]][ci] [![GoReport][report-img]][report]

**Servex** is a lightweight HTTP(S) server package built using Go's [net/http](https://pkg.go.dev/net/http) and [gorilla/mux](https://github.com/gorilla/mux). This package is designed to easy integrate into existing `net/http` servers. By using `gorilla/mux`, it offers flexible routing capabilities with the integrated middleware for logging, authentication and panic recovery.


## Table of Contents
- [Why Servex](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration Options](#configuration-options)
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

To start using **Servex** in your project, there are two ways:


### Start with config

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


### Start with server object

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


### Context in handlers

Thats why Servex can be integrated into existing `net/http` servers — you can create `servex.Context` based of the `http.Request` and `http.ResponseWriter` objects and use it in your handlers.

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

With `servex.Context` you can get experience of working in HTTP framework like [echo](https://github.com/labstack/echo) inside plain `net/http` servers.


### Configuration Options

Servex allows customization through options passed during server instantiation. Here's how you can configure it:

- **WithCertificate**: Set TLS certificate for HTTPS.
- **WithReadTimeout**: Customize read timeout duration.
- **WithIdleTimeout**: Customize idle timeout duration.
- **WithAuthToken**: Set an authorization token for middleware-based authentication.
- **WithMetrics**: Attach a metrics handler to track requests.
- **WithLogger**: Specify a custom logging mechanism.
- **WithRequestLogger**: Customizes request logging separately from server logging.

Example:

```go
options := []servex.Option{
    servex.WithReadTimeout(30 * time.Second),
    servex.WithIdleTimeout(120 * time.Second),
    servex.WithAuthToken("s3cret"),
}

// Create server with options
server := servex.NewWithOptions(servex.Options{
    ReadTimeout:   30 * time.Second,
    IdleTimeout:   120 * time.Second,
    AuthToken:     "s3cret",
})
```


## Pros and Cons

### Pros
- **Lightweight**: Minimal overhead, quick to integrate.
- **Flexible Routing**: Powered by `gorilla/mux`, allowing for precise routing and path handling.
- **Built-in Middleware**: Includes logging, authentication, and panic recovery.
- **Context-based Request Handling**: No more boilerplate for reading requests and sending responses.

### Cons
- **Basic Documentation**: Might require understanding of underlying `gorilla/mux` for advanced use cases.
- **Lack of Features**: It is not a framework for complex server architectures.

## Contributing

If you'd like to contribute to **servex**, submit a pull request or open an issue.

## License

Servex is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

[version-img]: https://img.shields.io/badge/Go-%3E%3D%201.19-%23007d9c
[doc-img]: https://pkg.go.dev/badge/github.com/maxbolgarin/servex
[doc]: https://pkg.go.dev/github.com/maxbolgarin/servex
[ci-img]: https://github.com/maxbolgarin/servex/actions/workflows/go.yml/badge.svg
[ci]: https://github.com/maxbolgarin/servex/actions
[report-img]: https://goreportcard.com/badge/github.com/maxbolgarin/servex
[report]: https://goreportcard.com/report/github.com/maxbolgarin/servex
