package servex

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
)

// Config represents a comprehensive configuration structure that can be loaded from
// YAML files and environment variables. It includes all major servex options.
//
// Example YAML configuration:
//
//	# server.yaml
//	server:
//	  http: ":8080"
//	  https: ":8443"
//	  cert_file: "/path/to/cert.pem"
//	  key_file: "/path/to/key.pem"
//	  read_timeout: "30s"
//	  idle_timeout: "120s"
//	  auth_token: "secret-api-key"
//	  enable_health_endpoint: true
//	  health_path: "/health"
//
//	auth:
//	  enabled: true
//	  issuer: "my-app"
//	  access_token_duration: "15m"
//	  refresh_token_duration: "7d"
//	  base_path: "/api/v1/auth"
//	  initial_roles: ["user"]
//
//	rate_limit:
//	  enabled: true
//	  requests_per_interval: 100
//	  interval: "1m"
//	  burst_size: 20
//	  status_code: 429
//	  message: "Rate limit exceeded"
//
//	security:
//	  enabled: true
//	  content_security_policy: "default-src 'self'"
//	  x_frame_options: "DENY"
//	  strict_transport_security: "max-age=31536000"
//
//	Example environment variables:
//
//	export SERVEX_SERVER_HTTP=":8080"
//	export SERVEX_SERVER_HTTPS=":8443"
//	export SERVEX_SERVER_AUTH_TOKEN="secret-key"
//	export SERVEX_AUTH_ENABLED="true"
//	export SERVEX_RATE_LIMIT_ENABLED="true"
//	export SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL="100"
type Config struct {
	// Server contains basic server configuration
	Server ServerConfig `yaml:"server" json:"server"`

	// Auth contains authentication configuration
	Auth AuthConfiguration `yaml:"auth" json:"auth"`

	// RateLimit contains rate limiting configuration
	RateLimit RateLimitConfiguration `yaml:"rate_limit" json:"rate_limit"`

	// Filter contains request filtering configuration
	Filter FilterConfiguration `yaml:"filter" json:"filter"`

	// Security contains security headers configuration
	Security SecurityConfiguration `yaml:"security" json:"security"`

	// Cache contains cache control configuration
	Cache CacheConfiguration `yaml:"cache" json:"cache"`

	// Logging contains logging configuration
	Logging LoggingConfiguration `yaml:"logging" json:"logging"`

	// StaticFiles contains static file serving configuration
	StaticFiles StaticFilesConfiguration `yaml:"static_files" json:"static_files"`

	// Proxy contains reverse proxy configuration
	Proxy ProxyConfiguration `yaml:"proxy" json:"proxy"`
}

// ServerConfig represents basic server configuration
type ServerConfig struct {
	HTTP                    string        `yaml:"http" json:"http" env:"SERVEX_SERVER_HTTP"`
	HTTPS                   string        `yaml:"https" json:"https" env:"SERVEX_SERVER_HTTPS"`
	CertFile                string        `yaml:"cert_file" json:"cert_file" env:"SERVEX_SERVER_CERT_FILE"`
	KeyFile                 string        `yaml:"key_file" json:"key_file" env:"SERVEX_SERVER_KEY_FILE"`
	ReadTimeout             time.Duration `yaml:"read_timeout" json:"read_timeout" env:"SERVEX_SERVER_READ_TIMEOUT"`
	ReadHeaderTimeout       time.Duration `yaml:"read_header_timeout" json:"read_header_timeout" env:"SERVEX_SERVER_READ_HEADER_TIMEOUT"`
	IdleTimeout             time.Duration `yaml:"idle_timeout" json:"idle_timeout" env:"SERVEX_SERVER_IDLE_TIMEOUT"`
	AuthToken               string        `yaml:"auth_token" json:"auth_token" env:"SERVEX_SERVER_AUTH_TOKEN"`
	EnableHealthEndpoint    bool          `yaml:"enable_health_endpoint" json:"enable_health_endpoint" env:"SERVEX_SERVER_ENABLE_HEALTH_ENDPOINT"`
	HealthPath              string        `yaml:"health_path" json:"health_path" env:"SERVEX_SERVER_HEALTH_PATH"`
	MetricsPath             string        `yaml:"metrics_path" json:"metrics_path" env:"SERVEX_SERVER_METRICS_PATH"`
	EnableDefaultMetrics    bool          `yaml:"enable_default_metrics" json:"enable_default_metrics" env:"SERVEX_SERVER_ENABLE_DEFAULT_METRICS"`
	MaxRequestBodySize      int64         `yaml:"max_request_body_size" json:"max_request_body_size" env:"SERVEX_SERVER_MAX_REQUEST_BODY_SIZE"`
	MaxJSONBodySize         int64         `yaml:"max_json_body_size" json:"max_json_body_size" env:"SERVEX_SERVER_MAX_JSON_BODY_SIZE"`
	MaxFileUploadSize       int64         `yaml:"max_file_upload_size" json:"max_file_upload_size" env:"SERVEX_SERVER_MAX_FILE_UPLOAD_SIZE"`
	MaxMultipartMemory      int64         `yaml:"max_multipart_memory" json:"max_multipart_memory" env:"SERVEX_SERVER_MAX_MULTIPART_MEMORY"`
	EnableRequestSizeLimits bool          `yaml:"enable_request_size_limits" json:"enable_request_size_limits" env:"SERVEX_SERVER_ENABLE_REQUEST_SIZE_LIMITS"`
	SendErrorToClient       bool          `yaml:"send_error_to_client" json:"send_error_to_client" env:"SERVEX_SERVER_SEND_ERROR_TO_CLIENT"`
}

// AuthConfiguration represents authentication configuration
type AuthConfiguration struct {
	Enabled                bool          `yaml:"enabled" json:"enabled" env:"SERVEX_AUTH_ENABLED"`
	JWTAccessSecret        string        `yaml:"jwt_access_secret" json:"jwt_access_secret" env:"SERVEX_AUTH_JWT_ACCESS_SECRET"`
	JWTRefreshSecret       string        `yaml:"jwt_refresh_secret" json:"jwt_refresh_secret" env:"SERVEX_AUTH_JWT_REFRESH_SECRET"`
	AccessTokenDuration    time.Duration `yaml:"access_token_duration" json:"access_token_duration" env:"SERVEX_AUTH_ACCESS_TOKEN_DURATION"`
	RefreshTokenDuration   time.Duration `yaml:"refresh_token_duration" json:"refresh_token_duration" env:"SERVEX_AUTH_REFRESH_TOKEN_DURATION"`
	Issuer                 string        `yaml:"issuer" json:"issuer" env:"SERVEX_AUTH_ISSUER"`
	RefreshTokenCookieName string        `yaml:"refresh_token_cookie_name" json:"refresh_token_cookie_name" env:"SERVEX_AUTH_REFRESH_TOKEN_COOKIE_NAME"`
	BasePath               string        `yaml:"base_path" json:"base_path" env:"SERVEX_AUTH_BASE_PATH"`
	InitialRoles           []string      `yaml:"initial_roles" json:"initial_roles" env:"SERVEX_AUTH_INITIAL_ROLES"`
	NotRegisterRoutes      bool          `yaml:"not_register_routes" json:"not_register_routes" env:"SERVEX_AUTH_NOT_REGISTER_ROUTES"`
	UseMemoryDatabase      bool          `yaml:"use_memory_database" json:"use_memory_database" env:"SERVEX_AUTH_USE_MEMORY_DATABASE"`
}

// RateLimitConfiguration represents rate limiting configuration
type RateLimitConfiguration struct {
	Enabled             bool          `yaml:"enabled" json:"enabled" env:"SERVEX_RATE_LIMIT_ENABLED"`
	RequestsPerInterval int           `yaml:"requests_per_interval" json:"requests_per_interval" env:"SERVEX_RATE_LIMIT_REQUESTS_PER_INTERVAL"`
	Interval            time.Duration `yaml:"interval" json:"interval" env:"SERVEX_RATE_LIMIT_INTERVAL"`
	BurstSize           int           `yaml:"burst_size" json:"burst_size" env:"SERVEX_RATE_LIMIT_BURST_SIZE"`
	StatusCode          int           `yaml:"status_code" json:"status_code" env:"SERVEX_RATE_LIMIT_STATUS_CODE"`
	Message             string        `yaml:"message" json:"message" env:"SERVEX_RATE_LIMIT_MESSAGE"`
	ExcludePaths        []string      `yaml:"exclude_paths" json:"exclude_paths" env:"SERVEX_RATE_LIMIT_EXCLUDE_PATHS"`
	IncludePaths        []string      `yaml:"include_paths" json:"include_paths" env:"SERVEX_RATE_LIMIT_INCLUDE_PATHS"`
	TrustedProxies      []string      `yaml:"trusted_proxies" json:"trusted_proxies" env:"SERVEX_RATE_LIMIT_TRUSTED_PROXIES"`
}

// FilterConfiguration represents request filtering configuration
type FilterConfiguration struct {
	AllowedIPs              []string            `yaml:"allowed_ips" json:"allowed_ips" env:"SERVEX_FILTER_ALLOWED_IPS"`
	BlockedIPs              []string            `yaml:"blocked_ips" json:"blocked_ips" env:"SERVEX_FILTER_BLOCKED_IPS"`
	AllowedUserAgents       []string            `yaml:"allowed_user_agents" json:"allowed_user_agents" env:"SERVEX_FILTER_ALLOWED_USER_AGENTS"`
	AllowedUserAgentsRegex  []string            `yaml:"allowed_user_agents_regex" json:"allowed_user_agents_regex" env:"SERVEX_FILTER_ALLOWED_USER_AGENTS_REGEX"`
	BlockedUserAgents       []string            `yaml:"blocked_user_agents" json:"blocked_user_agents" env:"SERVEX_FILTER_BLOCKED_USER_AGENTS"`
	BlockedUserAgentsRegex  []string            `yaml:"blocked_user_agents_regex" json:"blocked_user_agents_regex" env:"SERVEX_FILTER_BLOCKED_USER_AGENTS_REGEX"`
	AllowedHeaders          map[string][]string `yaml:"allowed_headers" json:"allowed_headers"`
	AllowedHeadersRegex     map[string][]string `yaml:"allowed_headers_regex" json:"allowed_headers_regex"`
	BlockedHeaders          map[string][]string `yaml:"blocked_headers" json:"blocked_headers"`
	BlockedHeadersRegex     map[string][]string `yaml:"blocked_headers_regex" json:"blocked_headers_regex"`
	AllowedQueryParams      map[string][]string `yaml:"allowed_query_params" json:"allowed_query_params"`
	AllowedQueryParamsRegex map[string][]string `yaml:"allowed_query_params_regex" json:"allowed_query_params_regex"`
	BlockedQueryParams      map[string][]string `yaml:"blocked_query_params" json:"blocked_query_params"`
	BlockedQueryParamsRegex map[string][]string `yaml:"blocked_query_params_regex" json:"blocked_query_params_regex"`
	ExcludePaths            []string            `yaml:"exclude_paths" json:"exclude_paths" env:"SERVEX_FILTER_EXCLUDE_PATHS"`
	IncludePaths            []string            `yaml:"include_paths" json:"include_paths" env:"SERVEX_FILTER_INCLUDE_PATHS"`
	StatusCode              int                 `yaml:"status_code" json:"status_code" env:"SERVEX_FILTER_STATUS_CODE"`
	Message                 string              `yaml:"message" json:"message" env:"SERVEX_FILTER_MESSAGE"`
	TrustedProxies          []string            `yaml:"trusted_proxies" json:"trusted_proxies" env:"SERVEX_FILTER_TRUSTED_PROXIES"`
}

// SecurityConfiguration represents security headers configuration
type SecurityConfiguration struct {
	Enabled bool `yaml:"enabled" json:"enabled" env:"SERVEX_SECURITY_ENABLED"`

	// CSRF Protection Configuration
	CSRFEnabled        bool     `yaml:"csrf_enabled" json:"csrf_enabled" env:"SERVEX_SECURITY_CSRF_ENABLED"`
	CSRFTokenName      string   `yaml:"csrf_token_name" json:"csrf_token_name" env:"SERVEX_SECURITY_CSRF_TOKEN_NAME"`
	CSRFCookieName     string   `yaml:"csrf_cookie_name" json:"csrf_cookie_name" env:"SERVEX_SECURITY_CSRF_COOKIE_NAME"`
	CSRFCookieHttpOnly bool     `yaml:"csrf_cookie_http_only" json:"csrf_cookie_http_only" env:"SERVEX_SECURITY_CSRF_COOKIE_HTTP_ONLY"`
	CSRFCookieSameSite string   `yaml:"csrf_cookie_same_site" json:"csrf_cookie_same_site" env:"SERVEX_SECURITY_CSRF_COOKIE_SAME_SITE"`
	CSRFCookieSecure   bool     `yaml:"csrf_cookie_secure" json:"csrf_cookie_secure" env:"SERVEX_SECURITY_CSRF_COOKIE_SECURE"`
	CSRFCookiePath     string   `yaml:"csrf_cookie_path" json:"csrf_cookie_path" env:"SERVEX_SECURITY_CSRF_COOKIE_PATH"`
	CSRFCookieMaxAge   int      `yaml:"csrf_cookie_max_age" json:"csrf_cookie_max_age" env:"SERVEX_SECURITY_CSRF_COOKIE_MAX_AGE"`
	CSRFTokenEndpoint  string   `yaml:"csrf_token_endpoint" json:"csrf_token_endpoint" env:"SERVEX_SECURITY_CSRF_TOKEN_ENDPOINT"`
	CSRFErrorMessage   string   `yaml:"csrf_error_message" json:"csrf_error_message" env:"SERVEX_SECURITY_CSRF_ERROR_MESSAGE"`
	CSRFSafeMethods    []string `yaml:"csrf_safe_methods" json:"csrf_safe_methods" env:"SERVEX_SECURITY_CSRF_SAFE_METHODS"`

	// Security Headers Configuration
	ContentSecurityPolicy         string   `yaml:"content_security_policy" json:"content_security_policy" env:"SERVEX_SECURITY_CONTENT_SECURITY_POLICY"`
	XContentTypeOptions           string   `yaml:"x_content_type_options" json:"x_content_type_options" env:"SERVEX_SECURITY_X_CONTENT_TYPE_OPTIONS"`
	XFrameOptions                 string   `yaml:"x_frame_options" json:"x_frame_options" env:"SERVEX_SECURITY_X_FRAME_OPTIONS"`
	XXSSProtection                string   `yaml:"x_xss_protection" json:"x_xss_protection" env:"SERVEX_SECURITY_X_XSS_PROTECTION"`
	StrictTransportSecurity       string   `yaml:"strict_transport_security" json:"strict_transport_security" env:"SERVEX_SECURITY_STRICT_TRANSPORT_SECURITY"`
	ReferrerPolicy                string   `yaml:"referrer_policy" json:"referrer_policy" env:"SERVEX_SECURITY_REFERRER_POLICY"`
	PermissionsPolicy             string   `yaml:"permissions_policy" json:"permissions_policy" env:"SERVEX_SECURITY_PERMISSIONS_POLICY"`
	XPermittedCrossDomainPolicies string   `yaml:"x_permitted_cross_domain_policies" json:"x_permitted_cross_domain_policies" env:"SERVEX_SECURITY_X_PERMITTED_CROSS_DOMAIN_POLICIES"`
	CrossOriginEmbedderPolicy     string   `yaml:"cross_origin_embedder_policy" json:"cross_origin_embedder_policy" env:"SERVEX_SECURITY_CROSS_ORIGIN_EMBEDDER_POLICY"`
	CrossOriginOpenerPolicy       string   `yaml:"cross_origin_opener_policy" json:"cross_origin_opener_policy" env:"SERVEX_SECURITY_CROSS_ORIGIN_OPENER_POLICY"`
	CrossOriginResourcePolicy     string   `yaml:"cross_origin_resource_policy" json:"cross_origin_resource_policy" env:"SERVEX_SECURITY_CROSS_ORIGIN_RESOURCE_POLICY"`
	ExcludePaths                  []string `yaml:"exclude_paths" json:"exclude_paths" env:"SERVEX_SECURITY_EXCLUDE_PATHS"`
	IncludePaths                  []string `yaml:"include_paths" json:"include_paths" env:"SERVEX_SECURITY_INCLUDE_PATHS"`
}

// CacheConfiguration represents cache control configuration
type CacheConfiguration struct {
	Enabled      bool     `yaml:"enabled" json:"enabled" env:"SERVEX_CACHE_ENABLED"`
	CacheControl string   `yaml:"cache_control" json:"cache_control" env:"SERVEX_CACHE_CONTROL"`
	Expires      string   `yaml:"expires" json:"expires" env:"SERVEX_CACHE_EXPIRES"`
	ETag         string   `yaml:"etag" json:"etag" env:"SERVEX_CACHE_ETAG"`
	LastModified string   `yaml:"last_modified" json:"last_modified" env:"SERVEX_CACHE_LAST_MODIFIED"`
	Vary         string   `yaml:"vary" json:"vary" env:"SERVEX_CACHE_VARY"`
	ExcludePaths []string `yaml:"exclude_paths" json:"exclude_paths" env:"SERVEX_CACHE_EXCLUDE_PATHS"`
	IncludePaths []string `yaml:"include_paths" json:"include_paths" env:"SERVEX_CACHE_INCLUDE_PATHS"`
}

// LoggingConfiguration represents logging configuration
type LoggingConfiguration struct {
	DisableRequestLogging bool     `yaml:"disable_request_logging" json:"disable_request_logging" env:"SERVEX_LOGGING_DISABLE_REQUEST_LOGGING"`
	NoLogClientErrors     bool     `yaml:"no_log_client_errors" json:"no_log_client_errors" env:"SERVEX_LOGGING_NO_LOG_CLIENT_ERRORS"`
	LogFields             []string `yaml:"log_fields" json:"log_fields" env:"SERVEX_LOGGING_LOG_FIELDS"`
}

// StaticFilesConfiguration represents static file serving configuration
type StaticFilesConfiguration struct {
	Enabled      bool           `yaml:"enabled" json:"enabled" env:"SERVEX_STATIC_FILES_ENABLED"`
	Dir          string         `yaml:"dir" json:"dir" env:"SERVEX_STATIC_FILES_DIR"`
	URLPrefix    string         `yaml:"url_prefix" json:"url_prefix" env:"SERVEX_STATIC_FILES_URL_PREFIX"`
	SPAMode      bool           `yaml:"spa_mode" json:"spa_mode" env:"SERVEX_STATIC_FILES_SPA_MODE"`
	IndexFile    string         `yaml:"index_file" json:"index_file" env:"SERVEX_STATIC_FILES_INDEX_FILE"`
	StripPrefix  string         `yaml:"strip_prefix" json:"strip_prefix" env:"SERVEX_STATIC_FILES_STRIP_PREFIX"`
	ExcludePaths []string       `yaml:"exclude_paths" json:"exclude_paths" env:"SERVEX_STATIC_FILES_EXCLUDE_PATHS"`
	CacheMaxAge  int            `yaml:"cache_max_age" json:"cache_max_age" env:"SERVEX_STATIC_FILES_CACHE_MAX_AGE"`
	CacheRules   map[string]int `yaml:"cache_rules" json:"cache_rules"`
}

// LoadConfigFromFile loads configuration from a YAML file
func LoadConfigFromFile(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", filename, err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config file %s: %w", filename, err)
	}

	return &config, nil
}

// LoadConfigFromEnv loads configuration from environment variables
func LoadConfigFromEnv() (*Config, error) {
	var config Config
	if err := loadEnvToStruct(&config); err != nil {
		return nil, fmt.Errorf("load environment variables: %w", err)
	}
	return &config, nil
}

// LoadConfig loads configuration from a YAML file and then overlays environment variables
func LoadConfig(filename string) (*Config, error) {
	// Start with file-based config
	config, err := LoadConfigFromFile(filename)
	if err != nil {
		return nil, err
	}

	// Overlay with environment variables
	if err := loadEnvToStruct(config); err != nil {
		return nil, fmt.Errorf("overlay environment variables: %w", err)
	}

	return config, nil
}

// ToOptions converts the Config to servex Options
func (c *Config) ToOptions() ([]Option, error) {
	var opts []Option

	// Server configuration
	if c.Server.ReadTimeout > 0 {
		opts = append(opts, WithReadTimeout(c.Server.ReadTimeout))
	}
	if c.Server.ReadHeaderTimeout > 0 {
		opts = append(opts, WithReadHeaderTimeout(c.Server.ReadHeaderTimeout))
	}
	if c.Server.IdleTimeout > 0 {
		opts = append(opts, WithIdleTimeout(c.Server.IdleTimeout))
	}
	if c.Server.AuthToken != "" {
		opts = append(opts, WithAuthToken(c.Server.AuthToken))
	}
	if c.Server.CertFile != "" && c.Server.KeyFile != "" {
		opts = append(opts, WithCertificateFromFile(c.Server.CertFile, c.Server.KeyFile))
	}
	if c.Server.EnableHealthEndpoint {
		opts = append(opts, WithHealthEndpoint())
		if c.Server.HealthPath != "" {
			opts = append(opts, WithHealthPath(c.Server.HealthPath))
		}
	}
	if c.Server.EnableDefaultMetrics {
		opts = append(opts, WithDefaultMetrics(c.Server.MetricsPath))
	}
	if c.Server.MaxRequestBodySize > 0 {
		opts = append(opts, WithMaxRequestBodySize(c.Server.MaxRequestBodySize))
	}
	if c.Server.MaxJSONBodySize > 0 {
		opts = append(opts, WithMaxJSONBodySize(c.Server.MaxJSONBodySize))
	}
	if c.Server.MaxFileUploadSize > 0 {
		opts = append(opts, WithMaxFileUploadSize(c.Server.MaxFileUploadSize))
	}
	if c.Server.MaxMultipartMemory > 0 {
		opts = append(opts, WithMaxMultipartMemory(c.Server.MaxMultipartMemory))
	}
	if c.Server.EnableRequestSizeLimits {
		opts = append(opts, WithEnableRequestSizeLimits(true))
	}
	if c.Server.SendErrorToClient {
		opts = append(opts, WithSendErrorToClient())
	}

	// Authentication configuration
	if c.Auth.Enabled {
		if c.Auth.UseMemoryDatabase {
			opts = append(opts, WithAuthMemoryDatabase())
		}

		if c.Auth.JWTAccessSecret != "" && c.Auth.JWTRefreshSecret != "" {
			opts = append(opts, WithAuthKey(c.Auth.JWTAccessSecret, c.Auth.JWTRefreshSecret))
		}
		if c.Auth.AccessTokenDuration > 0 && c.Auth.RefreshTokenDuration > 0 {
			opts = append(opts, WithAuthTokensDuration(c.Auth.AccessTokenDuration, c.Auth.RefreshTokenDuration))
		}
		if c.Auth.Issuer != "" {
			opts = append(opts, WithAuthIssuer(c.Auth.Issuer))
		}
		if c.Auth.RefreshTokenCookieName != "" {
			opts = append(opts, WithAuthRefreshTokenCookieName(c.Auth.RefreshTokenCookieName))
		}
		if c.Auth.BasePath != "" {
			opts = append(opts, WithAuthBasePath(c.Auth.BasePath))
		}
		if len(c.Auth.InitialRoles) > 0 {
			roles := make([]UserRole, len(c.Auth.InitialRoles))
			for i, role := range c.Auth.InitialRoles {
				roles[i] = UserRole(role)
			}
			opts = append(opts, WithAuthInitialRoles(roles...))
		}
		if c.Auth.NotRegisterRoutes {
			opts = append(opts, WithAuthNotRegisterRoutes(true))
		}
	}

	// Rate limiting configuration
	if c.RateLimit.Enabled {
		rateLimitConfig := RateLimitConfig{
			Enabled:             true,
			RequestsPerInterval: c.RateLimit.RequestsPerInterval,
			Interval:            c.RateLimit.Interval,
			BurstSize:           c.RateLimit.BurstSize,
			StatusCode:          c.RateLimit.StatusCode,
			Message:             c.RateLimit.Message,
			ExcludePaths:        c.RateLimit.ExcludePaths,
			IncludePaths:        c.RateLimit.IncludePaths,
			TrustedProxies:      c.RateLimit.TrustedProxies,
		}
		opts = append(opts, WithRateLimitConfig(rateLimitConfig))
	}

	// Filter configuration
	filterConfig := FilterConfig{
		AllowedIPs:              c.Filter.AllowedIPs,
		BlockedIPs:              c.Filter.BlockedIPs,
		AllowedUserAgents:       c.Filter.AllowedUserAgents,
		AllowedUserAgentsRegex:  c.Filter.AllowedUserAgentsRegex,
		BlockedUserAgents:       c.Filter.BlockedUserAgents,
		BlockedUserAgentsRegex:  c.Filter.BlockedUserAgentsRegex,
		AllowedHeaders:          c.Filter.AllowedHeaders,
		AllowedHeadersRegex:     c.Filter.AllowedHeadersRegex,
		BlockedHeaders:          c.Filter.BlockedHeaders,
		BlockedHeadersRegex:     c.Filter.BlockedHeadersRegex,
		AllowedQueryParams:      c.Filter.AllowedQueryParams,
		AllowedQueryParamsRegex: c.Filter.AllowedQueryParamsRegex,
		BlockedQueryParams:      c.Filter.BlockedQueryParams,
		BlockedQueryParamsRegex: c.Filter.BlockedQueryParamsRegex,
		ExcludePaths:            c.Filter.ExcludePaths,
		IncludePaths:            c.Filter.IncludePaths,
		StatusCode:              c.Filter.StatusCode,
		Message:                 c.Filter.Message,
		TrustedProxies:          c.Filter.TrustedProxies,
	}
	if len(c.Filter.AllowedIPs) > 0 || len(c.Filter.BlockedIPs) > 0 || len(c.Filter.AllowedUserAgents) > 0 ||
		len(c.Filter.BlockedUserAgents) > 0 || len(c.Filter.AllowedUserAgentsRegex) > 0 ||
		len(c.Filter.BlockedUserAgentsRegex) > 0 || len(c.Filter.AllowedHeaders) > 0 ||
		len(c.Filter.BlockedHeaders) > 0 {
		opts = append(opts, WithFilterConfig(filterConfig))
	}

	// Security configuration
	if c.Security.Enabled {
		securityConfig := SecurityConfig{
			Enabled: true,

			// CSRF Protection Configuration
			CSRFEnabled:        c.Security.CSRFEnabled,
			CSRFTokenName:      c.Security.CSRFTokenName,
			CSRFCookieName:     c.Security.CSRFCookieName,
			CSRFCookieHttpOnly: c.Security.CSRFCookieHttpOnly,
			CSRFCookieSameSite: c.Security.CSRFCookieSameSite,
			CSRFCookieSecure:   c.Security.CSRFCookieSecure,
			CSRFCookiePath:     c.Security.CSRFCookiePath,
			CSRFCookieMaxAge:   c.Security.CSRFCookieMaxAge,
			CSRFTokenEndpoint:  c.Security.CSRFTokenEndpoint,
			CSRFErrorMessage:   c.Security.CSRFErrorMessage,
			CSRFSafeMethods:    c.Security.CSRFSafeMethods,

			// Security Headers Configuration
			ContentSecurityPolicy:         c.Security.ContentSecurityPolicy,
			XContentTypeOptions:           c.Security.XContentTypeOptions,
			XFrameOptions:                 c.Security.XFrameOptions,
			XXSSProtection:                c.Security.XXSSProtection,
			StrictTransportSecurity:       c.Security.StrictTransportSecurity,
			ReferrerPolicy:                c.Security.ReferrerPolicy,
			PermissionsPolicy:             c.Security.PermissionsPolicy,
			XPermittedCrossDomainPolicies: c.Security.XPermittedCrossDomainPolicies,
			CrossOriginEmbedderPolicy:     c.Security.CrossOriginEmbedderPolicy,
			CrossOriginOpenerPolicy:       c.Security.CrossOriginOpenerPolicy,
			CrossOriginResourcePolicy:     c.Security.CrossOriginResourcePolicy,
			ExcludePaths:                  c.Security.ExcludePaths,
			IncludePaths:                  c.Security.IncludePaths,
		}
		opts = append(opts, WithSecurityConfig(securityConfig))
	}

	// Cache configuration
	if c.Cache.Enabled {
		cacheConfig := CacheConfig{
			Enabled:      true,
			CacheControl: c.Cache.CacheControl,
			Expires:      c.Cache.Expires,
			ETag:         c.Cache.ETag,
			LastModified: c.Cache.LastModified,
			Vary:         c.Cache.Vary,
			ExcludePaths: c.Cache.ExcludePaths,
			IncludePaths: c.Cache.IncludePaths,
		}
		opts = append(opts, WithCacheConfig(cacheConfig))
	}

	// Logging configuration
	if c.Logging.DisableRequestLogging {
		opts = append(opts, WithDisableRequestLogging())
	}
	if c.Logging.NoLogClientErrors {
		opts = append(opts, WithNoLogClientErrors())
	}
	if len(c.Logging.LogFields) > 0 {
		opts = append(opts, WithLogFields(c.Logging.LogFields...))
	}

	// Static files configuration
	if c.StaticFiles.Enabled {
		staticFileConfig := StaticFileConfig{
			Enabled:      true,
			Dir:          c.StaticFiles.Dir,
			URLPrefix:    c.StaticFiles.URLPrefix,
			SPAMode:      c.StaticFiles.SPAMode,
			IndexFile:    c.StaticFiles.IndexFile,
			StripPrefix:  c.StaticFiles.StripPrefix,
			ExcludePaths: c.StaticFiles.ExcludePaths,
			CacheMaxAge:  c.StaticFiles.CacheMaxAge,
			CacheRules:   c.StaticFiles.CacheRules,
		}
		opts = append(opts, WithStaticFileConfig(staticFileConfig))
	}

	// Proxy configuration
	if c.Proxy.Enabled {
		opts = append(opts, WithProxyConfig(c.Proxy))
	}

	return opts, nil
}

// ToBaseConfig converts the Config to BaseConfig for simple server configuration
func (c *Config) ToBaseConfig() BaseConfig {
	return BaseConfig{
		HTTP:      c.Server.HTTP,
		HTTPS:     c.Server.HTTPS,
		CertFile:  c.Server.CertFile,
		KeyFile:   c.Server.KeyFile,
		AuthToken: c.Server.AuthToken,
	}
}

// NewFromConfig creates a new Server instance from a Config struct
func NewFromConfig(config *Config) (*Server, error) {
	opts, err := config.ToOptions()
	if err != nil {
		return nil, fmt.Errorf("convert config to options: %w", err)
	}
	return NewWithOptions(parseOptions(opts))
}

// StartFromConfig starts a server using configuration from a YAML file
func StartFromConfig(configFile string, handlerSetter func(*mux.Router)) (shutdown func() error, err error) {
	config, err := LoadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	server, err := NewFromConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create server: %w", err)
	}

	server.router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerSetter(server.router)
	}).Methods("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD")

	baseConfig := config.ToBaseConfig()
	if err := server.Start(baseConfig.HTTP, baseConfig.HTTPS); err != nil {
		return nil, fmt.Errorf("start server: %w", err)
	}

	return func() error {
		return server.Shutdown(context.Background())
	}, nil
}

// loadEnvToStruct loads environment variables into a struct using reflection
func loadEnvToStruct(v interface{}) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return errors.New("v must be a non-nil pointer to a struct")
	}

	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		return errors.New("v must be a pointer to a struct")
	}

	return loadEnvToValue(rv, reflect.TypeOf(v).Elem())
}

// loadEnvToValue recursively loads environment variables into struct fields
func loadEnvToValue(rv reflect.Value, rt reflect.Type) error {
	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		fieldType := rt.Field(i)

		if !field.CanSet() {
			continue
		}

		// Handle nested structs
		if field.Kind() == reflect.Struct {
			if err := loadEnvToValue(field, fieldType.Type); err != nil {
				return err
			}
			continue
		}

		// Get environment variable name from tag
		envTag := fieldType.Tag.Get("env")
		if envTag == "" {
			continue
		}

		envValue := os.Getenv(envTag)
		if envValue == "" {
			continue
		}

		// Set the field value based on its type
		if err := setFieldValue(field, envValue); err != nil {
			return fmt.Errorf("set field %s from env %s: %w", fieldType.Name, envTag, err)
		}
	}

	return nil
}

// setFieldValue sets a reflect.Value based on the environment variable string value
func setFieldValue(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)

	case reflect.Bool:
		boolVal, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("parse bool: %w", err)
		}
		field.SetBool(boolVal)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Type() == reflect.TypeOf(time.Duration(0)) {
			// Handle time.Duration specially
			duration, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("parse duration: %w", err)
			}
			field.SetInt(int64(duration))
		} else {
			intVal, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return fmt.Errorf("parse int: %w", err)
			}
			field.SetInt(intVal)
		}

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		uintVal, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return fmt.Errorf("parse uint: %w", err)
		}
		field.SetUint(uintVal)

	case reflect.Float32, reflect.Float64:
		floatVal, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("parse float: %w", err)
		}
		field.SetFloat(floatVal)

	case reflect.Slice:
		// Handle string slices (comma-separated values)
		if field.Type().Elem().Kind() == reflect.String {
			var values []string
			if value != "" {
				values = strings.Split(value, ",")
				// Trim whitespace from each value
				for i, v := range values {
					values[i] = strings.TrimSpace(v)
				}
			}
			field.Set(reflect.ValueOf(values))
		} else {
			return fmt.Errorf("unsupported slice type: %s", field.Type())
		}

	default:
		return fmt.Errorf("unsupported field type: %s", field.Kind())
	}

	return nil
}
