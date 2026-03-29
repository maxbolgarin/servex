package servex

import "os"

// SwaggerAutoConfig holds configuration for automatic Swagger UI registration via server options.
type SwaggerAutoConfig struct {
	// Enabled determines whether Swagger UI is automatically registered.
	Enabled bool

	// Path is the URL path where Swagger UI will be served.
	// Default: "/swagger"
	Path string

	// SpecData is the raw OpenAPI specification content (JSON or YAML).
	// Either SpecData or SpecFile must be provided when Enabled is true.
	SpecData []byte

	// SpecFile is the path to an OpenAPI specification file on disk.
	// The file is read at server startup. Either SpecData or SpecFile must be provided.
	SpecFile string

	// Options are additional SwaggerOption functions applied to the handler.
	Options []SwaggerOption
}

// WithSwaggerUI enables Swagger UI with the given spec data.
// The spec is served at "/swagger" by default (change with WithSwaggerUIPath).
//
// Example:
//
//	spec, _ := os.ReadFile("openapi.yaml")
//	server, _ := servex.NewServer(
//	    servex.WithSwaggerUI(spec),
//	)
func WithSwaggerUI(specData []byte, opts ...SwaggerOption) Option {
	return func(o *Options) {
		o.Swagger.Enabled = true
		o.Swagger.SpecData = specData
		o.Swagger.Options = append(o.Swagger.Options, opts...)
	}
}

// WithSwaggerUIFile enables Swagger UI, loading the OpenAPI spec from a file at server startup.
// The file is read once when the server is created.
//
// Example:
//
//	server, _ := servex.NewServer(
//	    servex.WithSwaggerUIFile("./openapi.yaml"),
//	)
func WithSwaggerUIFile(filePath string, opts ...SwaggerOption) Option {
	return func(o *Options) {
		o.Swagger.Enabled = true
		o.Swagger.SpecFile = filePath
		o.Swagger.Options = append(o.Swagger.Options, opts...)
	}
}

// WithSwaggerUIPath sets the URL path for the auto-registered Swagger UI.
// Default: "/swagger"
//
// Example:
//
//	server, _ := servex.NewServer(
//	    servex.WithSwaggerUI(spec),
//	    servex.WithSwaggerUIPath("/api-docs"),
//	)
func WithSwaggerUIPath(path string) Option {
	return func(o *Options) {
		o.Swagger.Path = path
	}
}

// WithSwaggerUIConfig sets the full Swagger UI configuration.
func WithSwaggerUIConfig(cfg SwaggerAutoConfig) Option {
	return func(o *Options) {
		o.Swagger = cfg
	}
}

// loadSwaggerSpec reads the spec file into SpecData if SpecFile is set.
func (cfg *SwaggerAutoConfig) loadSwaggerSpec() error {
	if cfg.SpecFile != "" && len(cfg.SpecData) == 0 {
		data, err := os.ReadFile(cfg.SpecFile)
		if err != nil {
			return err
		}
		cfg.SpecData = data
	}
	return nil
}
