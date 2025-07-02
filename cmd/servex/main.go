package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

// Version information (set during build)
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// CLI configuration
type cliConfig struct {
	configFile     string
	envFile        string
	logLevel       string
	logFormat      string
	port           string
	httpsPort      string
	showVersion    bool
	validate       bool
	generateConfig bool
	configType     string
	dryRun         bool
	help           bool
	verbose        bool
	healthCheck    bool
	daemon         bool
}

func main() {
	// Setup graceful shutdown context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals early
	go handleShutdownSignals(cancel)

	// Parse command line arguments
	config := parseFlags()

	// Handle special commands
	if config.help {
		showHelp()
		return
	}

	if config.showVersion {
		showVersion()
		return
	}

	if config.healthCheck {
		os.Exit(performHealthCheck())
	}

	if config.generateConfig {
		generateSampleConfig(config.configType)
		return
	}

	// Setup logging
	setupLogging(config.logLevel, config.logFormat)

	// Load and validate configuration
	serverConfig, err := loadConfiguration(config)
	if err != nil {
		logFatal("Configuration error: %v", err)
	}

	// Validate configuration if requested
	if config.validate {
		if err := validateConfiguration(serverConfig); err != nil {
			logFatal("Configuration validation failed: %v", err)
		}
		logInfo("✅ Configuration file '%s' is valid", config.configFile)
		return
	}

	// Override with CLI flags
	applyCliOverrides(serverConfig, config)

	// Dry run mode
	if config.dryRun {
		showDryRunInfo(serverConfig, config)
		return
	}

	// Create and start server
	if err := runServer(ctx, serverConfig, config); err != nil {
		logFatal("Server error: %v", err)
	}

	logInfo("👋 Server shutdown completed gracefully")
}

// parseFlags parses command line flags
func parseFlags() *cliConfig {
	config := &cliConfig{}

	flag.StringVar(&config.configFile, "config", getDefaultConfigFile(), "Path to configuration file")
	flag.StringVar(&config.configFile, "c", getDefaultConfigFile(), "Path to configuration file (short)")
	flag.StringVar(&config.envFile, "env-file", "", "Path to environment file (.env)")
	flag.StringVar(&config.logLevel, "log-level", "", "Log level (debug, info, warn, error)")
	flag.StringVar(&config.logFormat, "log-format", "", "Log format (json, text)")
	flag.StringVar(&config.port, "port", "", "HTTP port override")
	flag.StringVar(&config.port, "p", "", "HTTP port override (short)")
	flag.StringVar(&config.httpsPort, "https-port", "", "HTTPS port override")
	flag.StringVar(&config.configType, "type", "yaml", "Configuration type for generation (yaml, env)")

	flag.BoolVar(&config.showVersion, "version", false, "Show version information")
	flag.BoolVar(&config.showVersion, "v", false, "Show version information (short)")
	flag.BoolVar(&config.validate, "validate", false, "Validate configuration and exit")
	flag.BoolVar(&config.generateConfig, "generate", false, "Generate sample configuration")
	flag.BoolVar(&config.generateConfig, "g", false, "Generate sample configuration (short)")
	flag.BoolVar(&config.dryRun, "dry-run", false, "Show what would be done without starting server")
	flag.BoolVar(&config.help, "help", false, "Show help")
	flag.BoolVar(&config.help, "h", false, "Show help (short)")
	flag.BoolVar(&config.verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&config.healthCheck, "health-check", false, "Perform health check and exit")
	flag.BoolVar(&config.daemon, "daemon", false, "Run as daemon (disable interactive features)")

	flag.Parse()
	return config
}

// loadConfiguration loads configuration from multiple sources
func loadConfiguration(config *cliConfig) (*servex.Config, error) {
	// Load environment file if specified
	if config.envFile != "" {
		if err := loadEnvFile(config.envFile); err != nil {
			return nil, fmt.Errorf("load env file: %w", err)
		}
		logInfo("📄 Loaded environment file: %s", config.envFile)
	}

	// Check if config file exists
	if _, err := os.Stat(config.configFile); os.IsNotExist(err) {
		logWarn("⚠️  Configuration file '%s' not found", config.configFile)

		// Try to load from environment variables only
		serverConfig, err := servex.LoadConfigFromEnv()
		if err != nil {
			return nil, fmt.Errorf("load config from environment: %w", err)
		}

		logInfo("🔧 Using configuration from environment variables only")
		return serverConfig, nil
	}

	// Load from file with environment overrides
	serverConfig, err := servex.LoadConfig(config.configFile)
	if err != nil {
		return nil, fmt.Errorf("load config from file '%s': %w", config.configFile, err)
	}

	logInfo("✅ Loaded configuration from '%s'", config.configFile)
	return serverConfig, nil
}

// validateConfiguration performs comprehensive validation
func validateConfiguration(config *servex.Config) error {
	var errors []string

	// Validate server configuration
	if config.Server.HTTP == "" && config.Server.HTTPS == "" {
		errors = append(errors, "at least one of HTTP or HTTPS must be configured")
	}

	// Validate HTTPS configuration
	if config.Server.HTTPS != "" {
		if config.Server.CertFile == "" || config.Server.KeyFile == "" {
			errors = append(errors, "HTTPS requires both cert_file and key_file")
		} else {
			if _, err := os.Stat(config.Server.CertFile); os.IsNotExist(err) {
				errors = append(errors, fmt.Sprintf("certificate file not found: %s", config.Server.CertFile))
			}
			if _, err := os.Stat(config.Server.KeyFile); os.IsNotExist(err) {
				errors = append(errors, fmt.Sprintf("key file not found: %s", config.Server.KeyFile))
			}
		}
	}

	// Validate proxy configuration
	if config.Proxy.Enabled {
		for i := range config.Proxy.Rules {
			rule := &config.Proxy.Rules[i]
			if rule.PathPrefix == "" && rule.Host == "" {
				errors = append(errors, fmt.Sprintf("proxy rule %d must have either path_prefix or host", i))
			}
			if len(rule.Backends) == 0 {
				errors = append(errors, fmt.Sprintf("proxy rule %d must have at least one backend", i))
			}
		}
	}

	// Validate static files configuration
	if config.StaticFiles.Enabled {
		if config.StaticFiles.Dir == "" {
			errors = append(errors, "static files enabled but directory not specified")
		} else if _, err := os.Stat(config.StaticFiles.Dir); os.IsNotExist(err) {
			errors = append(errors, fmt.Sprintf("static files directory not found: %s", config.StaticFiles.Dir))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("validation errors:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

// applyCliOverrides applies command line overrides to configuration
func applyCliOverrides(config *servex.Config, cli *cliConfig) {
	if cli.port != "" {
		if !strings.HasPrefix(cli.port, ":") {
			cli.port = ":" + cli.port
		}
		config.Server.HTTP = cli.port
		logInfo("🔧 HTTP port overridden: %s", cli.port)
	}

	if cli.httpsPort != "" {
		if !strings.HasPrefix(cli.httpsPort, ":") {
			cli.httpsPort = ":" + cli.httpsPort
		}
		config.Server.HTTPS = cli.httpsPort
		logInfo("🔧 HTTPS port overridden: %s", cli.httpsPort)
	}
}

// runServer creates and runs the server
func runServer(ctx context.Context, config *servex.Config, cli *cliConfig) error {
	// Create server from configuration
	server, err := servex.NewServerFromConfig(config)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	// Show startup information
	showStartupInfo(config, cli)

	// Validate addresses before starting
	if err := validateAddresses(config); err != nil {
		return fmt.Errorf("address validation: %w", err)
	}

	// Start server with graceful shutdown
	errCh := make(chan error, 1)
	closedCh := make(chan struct{}, 1)
	go func() {
		err := server.StartWithShutdown(ctx, config.Server.HTTP, config.Server.HTTPS)
		if err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
		close(closedCh)
	}()

	// Wait for either error or shutdown signal
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logInfo("📴 Shutdown signal received, stopping server...")

		// Give the server a moment to shut down gracefully
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		select {
		case <-closedCh:
		case <-shutdownCtx.Done():
		}
		return nil
	}
}

// validateAddresses checks if the configured addresses are available
func validateAddresses(config *servex.Config) error {
	// This is a basic validation - in production you might want to actually try binding
	if config.Server.HTTP != "" {
		logInfo("🌐 HTTP server will listen on: %s", config.Server.HTTP)
	}
	if config.Server.HTTPS != "" {
		logInfo("🔒 HTTPS server will listen on: %s", config.Server.HTTPS)
	}
	return nil
}

// showStartupInfo displays startup information
func showStartupInfo(config *servex.Config, cli *cliConfig) {
	logInfo("🚀 Starting Servex Server v%s", Version)
	logInfo("📊 Build: %s (commit: %s)", BuildTime, GitCommit)
	logInfo("🏗️  Go: %s", runtime.Version())

	if cli.verbose {
		logInfo("📁 Working directory: %s", getWorkingDir())
		logInfo("👤 Running as: %s", getUser())
		logInfo("🖥️  Platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Show enabled features
	var features []string
	if config.Server.EnableHealthEndpoint {
		features = append(features, fmt.Sprintf("health:%s", config.Server.HealthPath))
	}
	if config.Server.EnableDefaultMetrics {
		features = append(features, fmt.Sprintf("metrics:%s", config.Server.MetricsPath))
	}
	if config.RateLimit.Enabled {
		features = append(features, "rate-limiting")
	}
	if config.Security.Enabled {
		features = append(features, "security-headers")
	}
	if config.CORS.Enabled {
		features = append(features, "cors")
	}
	if config.Proxy.Enabled {
		features = append(features, fmt.Sprintf("proxy(%d-rules)", len(config.Proxy.Rules)))
	}
	if config.StaticFiles.Enabled {
		features = append(features, "static-files")
	}

	if len(features) > 0 {
		logInfo("🔧 Features: %s", strings.Join(features, ", "))
	}

	fmt.Println() // Empty line for readability
}

// showDryRunInfo shows what would happen in a dry run
func showDryRunInfo(config *servex.Config, cli *cliConfig) {
	fmt.Printf("🔍 DRY RUN MODE - Showing configuration without starting server\n\n")

	fmt.Printf("📋 Configuration Summary:\n")
	fmt.Printf("  Config file: %s\n", cli.configFile)
	if cli.envFile != "" {
		fmt.Printf("  Env file: %s\n", cli.envFile)
	}

	if config.Server.HTTP != "" {
		fmt.Printf("  HTTP: %s\n", config.Server.HTTP)
	}
	if config.Server.HTTPS != "" {
		fmt.Printf("  HTTPS: %s\n", config.Server.HTTPS)
		fmt.Printf("    Cert: %s\n", config.Server.CertFile)
		fmt.Printf("    Key: %s\n", config.Server.KeyFile)
	}

	fmt.Printf("\n🔧 Enabled Features:\n")
	if config.RateLimit.Enabled {
		fmt.Printf("  ⏱️  Rate Limiting: %d req/%s (burst: %d)\n",
			config.RateLimit.RequestsPerInterval,
			config.RateLimit.Interval,
			config.RateLimit.BurstSize)
	}

	if config.Security.Enabled {
		fmt.Printf("  🛡️  Security Headers: enabled\n")
		if config.Security.CSRFEnabled {
			fmt.Printf("    🔐 CSRF Protection: enabled\n")
		}
	}

	if config.Proxy.Enabled {
		fmt.Printf("  🔀 Reverse Proxy: %d rules\n", len(config.Proxy.Rules))
		for i := range config.Proxy.Rules {
			rule := &config.Proxy.Rules[i]
			fmt.Printf("    %d. %s -> %d backends\n", i+1,
				getRouteDescription(rule), len(rule.Backends))
		}
	}

	if config.StaticFiles.Enabled {
		fmt.Printf("  📁 Static Files: %s -> %s\n", config.StaticFiles.URLPrefix, config.StaticFiles.Dir)
	}
}

// performHealthCheck performs a health check
func performHealthCheck() int {
	// This would typically make an HTTP request to the health endpoint
	// For now, we'll just check if we can load the configuration

	config := &cliConfig{
		configFile: getDefaultConfigFile(),
		logLevel:   "error", // Quiet for health checks
	}

	_, err := loadConfiguration(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Health check failed: %v\n", err)
		return 1
	}

	fmt.Println("✅ Health check passed")
	return 0
}

// generateSampleConfig generates a sample configuration file
func generateSampleConfig(configType string) {
	switch configType {
	case "yaml", "yml":
		generateYAMLConfig()
	case "env":
		generateEnvConfig()
	default:
		logFatal("Unknown config type: %s (supported: yaml, env)", configType)
	}
}

// generateYAMLConfig generates a sample YAML configuration
func generateYAMLConfig() {
	content := `# Servex Server Configuration
# Complete example with all available options

server:
  # Network configuration
  http: ":8080"
  # https: ":8443"
  # cert_file: "/etc/ssl/certs/server.crt"
  # key_file: "/etc/ssl/private/server.key"
  
  # Timeouts
  read_timeout: "30s"
  read_header_timeout: "10s"
  idle_timeout: "120s"
  
  # Authentication
  # auth_token: "your-secret-api-key"
  
  # Built-in endpoints
  enable_health_endpoint: true
  health_path: "/health"
  enable_default_metrics: true
  metrics_path: "/metrics"
  
  # Request limits
  enable_request_size_limits: true
  max_request_body_size: 33554432    # 32MB
  max_json_body_size: 1048576        # 1MB
  max_file_upload_size: 10485760     # 10MB

# Rate limiting
rate_limit:
  enabled: true
  requests_per_interval: 100
  interval: "1m"
  burst_size: 20
  exclude_paths:
    - "/health"
    - "/metrics"

# Security headers
security:
  enabled: true
  content_security_policy: "default-src 'self'"
  x_frame_options: "DENY"
  x_content_type_options: "nosniff"
  strict_transport_security: "max-age=31536000"

# Response compression
compression:
  enabled: true
  level: 6
  min_size: 1024
  types:
    - "text/html"
    - "text/css"
    - "application/javascript"
    - "application/json"

# CORS
cors:
  enabled: false
  # allow_origins: ["*"]
  # allow_methods: ["GET", "POST", "PUT", "DELETE"]
  # allow_headers: ["Content-Type", "Authorization"]

# Static files
static_files:
  enabled: false
  # dir: "./public"
  # url_prefix: "/static/"
  # spa_mode: true

# Reverse proxy
proxy:
  enabled: false
  # global_timeout: "30s"
  # rules:
  #   - name: "api"
  #     path_prefix: "/api/"
  #     backends:
  #       - url: "http://localhost:3000"
  #     load_balancing: "round_robin"
`

	filename := "servex.yaml"
	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		logFatal("Failed to write config file: %v", err)
	}

	logInfo("✅ Generated sample configuration: %s", filename)
}

// generateEnvConfig generates a sample environment configuration
func generateEnvConfig() {
	content := `# Servex Environment Configuration
# Set these environment variables to configure servex

# Server configuration
SERVEX_SERVER_HTTP=:8080
# SERVEX_SERVER_HTTPS=:8443
# SERVEX_SERVER_CERT_FILE=/etc/ssl/certs/server.crt
# SERVEX_SERVER_KEY_FILE=/etc/ssl/private/server.key

# Authentication
# SERVEX_SERVER_AUTH_TOKEN=your-secret-api-key

# Health and metrics
SERVEX_SERVER_ENABLE_HEALTH_ENDPOINT=true
SERVEX_SERVER_HEALTH_PATH=/health
SERVEX_SERVER_ENABLE_DEFAULT_METRICS=true
SERVEX_SERVER_METRICS_PATH=/metrics

# Rate limiting
SERVEX_RATE_LIMIT_ENABLED=true
SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL=100
SERVEX_RATE_LIMIT_INTERVAL=1m
SERVEX_RATE_LIMIT_BURST_SIZE=20

# Security
SERVEX_SECURITY_ENABLED=true
SERVEX_SECURITY_CONTENT_SECURITY_POLICY="default-src 'self'"
SERVEX_SECURITY_X_FRAME_OPTIONS=DENY

# Compression
SERVEX_COMPRESSION_ENABLED=true
SERVEX_COMPRESSION_LEVEL=6
SERVEX_COMPRESSION_MIN_SIZE=1024
`

	filename := ".env.example"
	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		logFatal("Failed to write env file: %v", err)
	}

	logInfo("✅ Generated sample environment file: %s", filename)
}

// handleShutdownSignals handles graceful shutdown
func handleShutdownSignals(cancel context.CancelFunc) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)

	sig := <-signals
	logInfo("🛑 Received signal: %s", sig)
	cancel()
}

// showVersion displays comprehensive version information
func showVersion() {
	fmt.Printf("Servex HTTP Server v%s\n", Version)
	fmt.Printf("  Build time: %s\n", BuildTime)
	fmt.Printf("  Git commit: %s\n", GitCommit)
	fmt.Printf("  Go version: %s\n", runtime.Version())
	fmt.Printf("  Platform:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

// showHelp displays comprehensive usage information
func showHelp() {
	fmt.Printf(`Servex - High-Performance HTTP Server & Reverse Proxy

USAGE:
  servex [OPTIONS]

OPTIONS:
  -c, -config FILE      Configuration file (default: %s)
      -env-file FILE    Environment file to load (.env)
  -p, -port PORT        HTTP port override
      -https-port PORT  HTTPS port override
      -log-level LEVEL  Log level (debug, info, warn, error)
      -log-format FMT   Log format (json, text)

COMMANDS:
  -v, -version          Show version information
  -h, -help             Show this help
      -validate         Validate configuration and exit
  -g, -generate         Generate sample configuration
      -type TYPE        Config type for generation (yaml, env)
      -dry-run          Show configuration without starting
      -health-check     Perform health check and exit
      -verbose          Enable verbose output
      -daemon           Run as daemon (disable interactive features)

EXAMPLES:
  # Start with default config
  servex

  # Start with custom config
  servex -config production.yaml

  # Override port via CLI
  servex -port 3000

  # Validate configuration
  servex -validate -config prod.yaml

  # Generate sample configurations
  servex -generate -type yaml
  servex -generate -type env

  # Docker-friendly with environment
  servex -env-file /etc/servex/.env -daemon

  # Development with verbose logging
  servex -verbose -log-level debug

CONFIGURATION:
  Servex supports configuration via:
  1. YAML configuration files
  2. Environment variables (SERVEX_* prefix)
  3. Command-line flag overrides
  4. .env files

  Configuration precedence (highest to lowest):
  CLI flags → Environment variables → Config file → Defaults

ENVIRONMENT:
  All configuration options have corresponding environment variables.
  Format: SERVEX_SECTION_OPTION (e.g., SERVEX_SERVER_HTTP=:8080)

DOCKER:
  servex is designed to work well in containers:
  - Uses proper signal handling for graceful shutdown
  - Supports configuration via environment variables
  - Provides health check endpoints
  - Logs to stdout/stderr in structured format

For more information and examples:
  https://github.com/maxbolgarin/servex/v2
`, getDefaultConfigFile())
}

// Utility functions

func getDefaultConfigFile() string {
	candidates := []string{
		"servex.yaml",
		"servex.yml",
		"server.yaml",
		"server.yml",
		"config.yaml",
		"config.yml",
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	return "servex.yaml" // Default fallback
}

func getWorkingDir() string {
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "unknown"
}

func getUser() string {
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	if user := os.Getenv("USERNAME"); user != "" {
		return user
	}
	return "unknown"
}

func getRouteDescription(rule *servex.ProxyRule) string {
	if rule.Host != "" {
		return fmt.Sprintf("host:%s", rule.Host)
	}
	if rule.PathPrefix != "" {
		return fmt.Sprintf("path:%s", rule.PathPrefix)
	}
	return "unknown"
}

// loadEnvFile loads environment variables from a .env file
func loadEnvFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// Remove quotes if present
			if len(value) >= 2 &&
				((strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
					(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'"))) {
				value = value[1 : len(value)-1]
			}
			os.Setenv(key, value)
		}
	}

	return nil
}

// Logging functions

func setupLogging(level, format string) {
	// Set up basic logging - in a real implementation you might want to use
	// a proper logging library like logrus or zap
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func logInfo(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

func logWarn(format string, args ...interface{}) {
	log.Printf("[WARN] "+format, args...)
}

func logFatal(format string, args ...interface{}) {
	log.Printf("[FATAL] "+format, args...)
	os.Exit(1)
}
