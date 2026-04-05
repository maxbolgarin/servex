package servex

import (
	"fmt"
	"html"
	"net/http"
	"strings"
)

// SwaggerOption configures the Swagger UI handler.
type SwaggerOption func(*swaggerConfig)

// swaggerConfig holds internal configuration for the Swagger UI handler.
type swaggerConfig struct {
	title    string
	specData []byte
}

// WithSwaggerTitle sets the HTML page title for the Swagger UI.
func WithSwaggerTitle(title string) SwaggerOption {
	return func(cfg *swaggerConfig) {
		cfg.title = title
	}
}

// SwaggerHandler returns an http.Handler that serves Swagger UI and the OpenAPI spec.
//
// The handler serves the following paths (relative to where it is mounted):
//   - GET /           - HTML page with Swagger UI (loaded from CDN)
//   - GET /spec       - the OpenAPI spec file
//   - GET /spec.json  - the OpenAPI spec file (alias)
//   - GET /spec.yaml  - the OpenAPI spec file (alias)
//
// specData is the raw OpenAPI specification content in JSON or YAML format.
// The Content-Type is auto-detected based on the content.
//
// Use http.StripPrefix when mounting on a path prefix:
//
//	http.Handle("/docs/", http.StripPrefix("/docs", servex.SwaggerHandler(spec)))
//
// Or use the servex router directly:
//
//	server.Handle("/docs/", http.StripPrefix("/docs", servex.SwaggerHandler(spec)))
//
// For automatic registration, use WithSwaggerUI or WithSwaggerUIFile options instead.
func SwaggerHandler(specData []byte, opts ...SwaggerOption) http.Handler {
	cfg := &swaggerConfig{
		title:    "API Documentation",
		specData: specData,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	m := http.NewServeMux()
	m.HandleFunc("/", cfg.handleUI)
	m.HandleFunc("/spec", cfg.handleSpec)
	m.HandleFunc("/spec.json", cfg.handleSpec)
	m.HandleFunc("/spec.yaml", cfg.handleSpec)
	return m
}

// handleUI serves the Swagger UI HTML page.
func (cfg *swaggerConfig) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Only serve the UI page at the root path
	if r.URL.Path != "/" && r.URL.Path != "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, swaggerUIHTML(cfg.title))
}

// handleSpec serves the OpenAPI spec file.
func (cfg *swaggerConfig) handleSpec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	contentType := detectSpecContentType(cfg.specData)
	w.Header().Set("Content-Type", contentType)
	w.Write(cfg.specData)
}

// detectSpecContentType returns the Content-Type for the spec data.
// It checks if the content looks like JSON, otherwise assumes YAML.
func detectSpecContentType(data []byte) string {
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return "application/json; charset=utf-8"
	}
	return "application/yaml; charset=utf-8"
}

// registerSwaggerEndpoints registers the Swagger UI handler on the server router.
func registerSwaggerEndpoints(s *Server) {
	path := s.opts.Swagger.Path
	if path == "" {
		path = "/swagger"
	}
	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	handler := SwaggerHandler(s.opts.Swagger.SpecData, s.opts.Swagger.Options...)
	s.router.PathPrefix(path).Handler(http.StripPrefix(path, handler))
}

// swaggerUIHTML returns the HTML page that loads Swagger UI from a CDN.
func swaggerUIHTML(title string) string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>` + html.EscapeString(title) + `</title>
    <!-- TODO: Add integrity="sha384-..." SRI hashes when pinning a specific swagger-ui-dist version -->
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.18.2/swagger-ui.css" crossorigin="anonymous" referrerpolicy="no-referrer">
    <style>
        html { box-sizing: border-box; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin: 0; background: #fafafa; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <!-- TODO: Add integrity="sha384-..." SRI hash when pinning a specific swagger-ui-dist version -->
    <script src="https://unpkg.com/swagger-ui-dist@5.18.2/swagger-ui-bundle.js" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script>
        SwaggerUIBundle({
            url: "./spec",
            dom_id: '#swagger-ui',
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIBundle.SwaggerUIStandalonePreset
            ],
            layout: "BaseLayout",
            deepLinking: true,
        });
    </script>
</body>
</html>`
}
