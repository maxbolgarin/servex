# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
make build          # Build binary to bin/servex
make test           # Run tests with race detection, coverage, and tparse formatting
make deps           # Download and verify Go module dependencies
make mod-tidy       # Tidy go modules
make mod-update     # Update all dependencies
make clean          # Remove build artifacts
make docker-build   # Build Docker image
make run-dev        # Build and run development server
```

Run a single test:
```bash
go test -v -run TestFunctionName .
```

CI runs tests against Go 1.23, 1.24, 1.25 with race detection:
```bash
go test -v -race -coverprofile=coverage.txt .
```

## Architecture

Servex is a production-ready HTTP(S) server library built on `net/http` and `gorilla/mux`. All library code lives in the root package (`servex`); there are no internal packages.

### Key Source Files

| Area | Files |
|------|-------|
| Server lifecycle | `servex.go` |
| Router (method shortcuts, base path) | `router.go` |
| Configuration loading (YAML + env vars) | `config.go` |
| Options (100+ `With*` builder functions) | `options_core.go`, `options_*.go` |
| Context helpers (`C(w,r)`) | `context_core.go`, `context_request.go`, `context_response.go`, `context_validation.go` |
| JWT authentication | `auth.go`, `middleware_auth.go` |
| Rate limiting | `ratelimit.go` |
| Request filtering (IP/UA/header/query) | `filter.go` |
| Reverse proxy with load balancing | `proxy.go` |
| Security headers, CSRF | `middleware_security.go` |
| Static files & SPA | `static.go` |
| Metrics & audit logging | `metrics.go`, `audit.go`, `logging.go` |
| Presets (Development, Production, etc.) | `presets.go` |
| CLI entry point | `cmd/servex/main.go` |

### Core Design Patterns

- **Options pattern**: Configuration via `With*()` functions passed to `NewServer()`. Options are split across `options_*.go` files by domain.
- **Middleware chain**: Registered in a fixed order in `servex.go` — rate limiting → size limits → filtering → security → CORS → cache → compression → logging → recovery → auth → proxy → static.
- **Context helpers**: `servex.C(w, r)` wraps the standard `http.ResponseWriter` and `*http.Request` to provide convenient JSON reading/writing, parameter extraction, and error responses.
- **Interface-based extensibility**: Provide custom implementations of `Logger`, `RequestLogger`, `AuditLogger`, `Metrics`, and `AuthDatabase` interfaces.

### Key Interfaces

- `AuthDatabase` — user storage backend (see `auth.go`)
- `Metrics` — custom metrics collection (see `metrics.go`)
- `Logger` / `RequestLogger` / `AuditLogger` — logging backends (see `logging.go`, `audit.go`)

## Testing Conventions

- All tests use the standard `testing` package — no external assertion libraries.
- Table-driven tests (`tests := []struct{...}`) are the dominant pattern.
- Tests use `httptest.NewRequest` and `httptest.NewRecorder` for HTTP testing.
- Mock implementations (MockLogger, MockAuthDatabase, MockAuditLogger) are defined in the corresponding `_test.go` files.
- Tests run in the same package (not `_test` suffix packages), so they can access unexported symbols.

## Release

Releases use semantic-release with conventional commits (`.releaserc.json`). Commit prefixes: `feat:` (minor), `fix:` / `perf:` / `docs:` / `refactor:` (patch), `breaking:` (major).
