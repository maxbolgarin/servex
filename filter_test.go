package servex

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func TestFilterConfig_isEnabled(t *testing.T) {
	tests := []struct {
		name   string
		config FilterConfig
		want   bool
	}{
		{
			name:   "empty config",
			config: FilterConfig{},
			want:   false,
		},
		{
			name: "with allowed IPs",
			config: FilterConfig{
				AllowedIPs: []string{"192.168.1.1"},
			},
			want: true,
		},
		{
			name: "with blocked IPs",
			config: FilterConfig{
				BlockedIPs: []string{"10.0.0.1"},
			},
			want: true,
		},
		{
			name: "with user agents",
			config: FilterConfig{
				AllowedUserAgents: []string{"Mozilla/5.0"},
			},
			want: true,
		},
		{
			name: "with user agents regex",
			config: FilterConfig{
				AllowedUserAgentsRegex: []string{"Mozilla.*"},
			},
			want: true,
		},
		{
			name: "with headers",
			config: FilterConfig{
				AllowedHeaders: map[string][]string{
					"Authorization": {"Bearer token"},
				},
			},
			want: true,
		},
		{
			name: "with query params",
			config: FilterConfig{
				AllowedQueryParams: map[string][]string{
					"api_key": {"secret"},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.isEnabled(); got != tt.want {
				t.Errorf("FilterConfig.isEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilter_compileIPNets(t *testing.T) {
	filter := &Filter{}

	tests := []struct {
		name    string
		ips     []string
		wantErr bool
		wantLen int
	}{
		{
			name:    "valid single IP",
			ips:     []string{"192.168.1.1"},
			wantErr: false,
			wantLen: 1,
		},
		{
			name:    "valid CIDR",
			ips:     []string{"192.168.1.0/24"},
			wantErr: false,
			wantLen: 1,
		},
		{
			name:    "mixed valid IPs and CIDRs",
			ips:     []string{"192.168.1.1", "10.0.0.0/8", "::1"},
			wantErr: false,
			wantLen: 3,
		},
		{
			name:    "invalid IP",
			ips:     []string{"invalid-ip"},
			wantErr: true,
		},
		{
			name:    "invalid CIDR",
			ips:     []string{"192.168.1.0/99"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets, err := filter.compileIPNets(tt.ips)
			if (err != nil) != tt.wantErr {
				t.Errorf("Filter.compileIPNets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(nets) != tt.wantLen {
				t.Errorf("Filter.compileIPNets() len = %d, want %d", len(nets), tt.wantLen)
			}
		})
	}
}

func TestFilter_compileRegexPatterns(t *testing.T) {
	filter := &Filter{}

	tests := []struct {
		name     string
		patterns []string
		wantErr  bool
		wantLen  int
	}{
		{
			name:     "valid regex patterns",
			patterns: []string{"Mozilla.*", ".*Chrome.*"},
			wantErr:  false,
			wantLen:  2,
		},
		{
			name:     "complex regex patterns",
			patterns: []string{"^Mozilla.*", "test.*$"},
			wantErr:  false,
			wantLen:  2,
		},
		{
			name:     "invalid regex",
			patterns: []string{"[invalid"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regexes, err := filter.compileRegexPatterns(tt.patterns)
			if (err != nil) != tt.wantErr {
				t.Errorf("Filter.compileRegexPatterns() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(regexes) != tt.wantLen {
				t.Errorf("Filter.compileRegexPatterns() len = %d, want %d", len(regexes), tt.wantLen)
			}
		})
	}
}

func TestFilterMiddleware_IPFiltering(t *testing.T) {
	tests := []struct {
		name       string
		config     FilterConfig
		remoteAddr string
		headers    map[string]string
		wantStatus int
	}{
		{
			name: "allowed IP - single",
			config: FilterConfig{
				AllowedIPs: []string{"192.168.1.1"},
			},
			remoteAddr: "192.168.1.1:12345",
			wantStatus: http.StatusOK,
		},
		{
			name: "allowed IP - CIDR",
			config: FilterConfig{
				AllowedIPs: []string{"192.168.1.0/24"},
			},
			remoteAddr: "192.168.1.100:12345",
			wantStatus: http.StatusOK,
		},
		{
			name: "blocked IP - not in allowed list",
			config: FilterConfig{
				AllowedIPs: []string{"192.168.1.1"},
			},
			remoteAddr: "10.0.0.1:12345",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "blocked IP - in blocked list",
			config: FilterConfig{
				BlockedIPs: []string{"10.0.0.1"},
			},
			remoteAddr: "10.0.0.1:12345",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "blocked takes precedence over allowed",
			config: FilterConfig{
				AllowedIPs: []string{"192.168.1.0/24"},
				BlockedIPs: []string{"192.168.1.1"},
			},
			remoteAddr: "192.168.1.1:12345",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "trusted proxy - X-Forwarded-For",
			config: FilterConfig{
				AllowedIPs:     []string{"192.168.1.1"},
				TrustedProxies: []string{"10.0.0.1"},
			},
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.1",
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "trusted proxy - X-Real-IP",
			config: FilterConfig{
				AllowedIPs:     []string{"192.168.1.1"},
				TrustedProxies: []string{"10.0.0.1"},
			},
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Real-IP": "192.168.1.1",
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup router and middleware
			router := mux.NewRouter()
			RegisterFilterMiddleware(router, tt.config)

			// Add test handler
			router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			// Add headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Record response
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestFilterMiddleware_UserAgentFiltering(t *testing.T) {
	tests := []struct {
		name       string
		config     FilterConfig
		userAgent  string
		wantStatus int
	}{
		{
			name: "allowed user agent - exact match",
			config: FilterConfig{
				AllowedUserAgents: []string{"Mozilla/5.0"},
			},
			userAgent:  "Mozilla/5.0",
			wantStatus: http.StatusOK,
		},
		{
			name: "allowed user agent - regex match",
			config: FilterConfig{
				AllowedUserAgentsRegex: []string{"Mozilla.*"},
			},
			userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			wantStatus: http.StatusOK,
		},
		{
			name: "blocked user agent - not in allowed list",
			config: FilterConfig{
				AllowedUserAgents: []string{"Mozilla/5.0"},
			},
			userAgent:  "BadBot/1.0",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "blocked user agent - in blocked list",
			config: FilterConfig{
				BlockedUserAgents: []string{"BadBot/1.0"},
			},
			userAgent:  "BadBot/1.0",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "blocked user agent - regex",
			config: FilterConfig{
				BlockedUserAgentsRegex: []string{".*Bot.*"},
			},
			userAgent:  "SomeBot/2.0",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "blocked takes precedence over allowed",
			config: FilterConfig{
				AllowedUserAgentsRegex: []string{".*"},
				BlockedUserAgents:      []string{"BadBot/1.0"},
			},
			userAgent:  "BadBot/1.0",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup router and middleware
			router := mux.NewRouter()
			RegisterFilterMiddleware(router, tt.config)

			// Add test handler
			router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("User-Agent", tt.userAgent)

			// Record response
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestFilterMiddleware_HeaderFiltering(t *testing.T) {
	tests := []struct {
		name       string
		config     FilterConfig
		headers    map[string]string
		wantStatus int
	}{
		{
			name: "allowed header - exact match",
			config: FilterConfig{
				AllowedHeaders: map[string][]string{
					"Authorization": {"Bearer token123"},
				},
			},
			headers: map[string]string{
				"Authorization": "Bearer token123",
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "allowed header - regex match",
			config: FilterConfig{
				AllowedHeadersRegex: map[string][]string{
					"Authorization": {"Bearer .*"},
				},
			},
			headers: map[string]string{
				"Authorization": "Bearer sometoken",
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "blocked header - not in allowed list",
			config: FilterConfig{
				AllowedHeaders: map[string][]string{
					"Authorization": {"Bearer validtoken"},
				},
			},
			headers: map[string]string{
				"Authorization": "Bearer invalidtoken",
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "blocked header - in blocked list",
			config: FilterConfig{
				BlockedHeaders: map[string][]string{
					"X-Attack": {"malicious"},
				},
			},
			headers: map[string]string{
				"X-Attack": "malicious",
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "blocked takes precedence over allowed",
			config: FilterConfig{
				AllowedHeadersRegex: map[string][]string{
					"Authorization": {".*"},
				},
				BlockedHeaders: map[string][]string{
					"Authorization": {"Bearer badtoken"},
				},
			},
			headers: map[string]string{
				"Authorization": "Bearer badtoken",
			},
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup router and middleware
			router := mux.NewRouter()
			RegisterFilterMiddleware(router, tt.config)

			// Add test handler
			router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)

			// Add headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Record response
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestFilterMiddleware_QueryParamFiltering(t *testing.T) {
	tests := []struct {
		name       string
		config     FilterConfig
		url        string
		wantStatus int
	}{
		{
			name: "allowed query param - exact match",
			config: FilterConfig{
				AllowedQueryParams: map[string][]string{
					"api_key": {"secret123"},
				},
			},
			url:        "/test?api_key=secret123",
			wantStatus: http.StatusOK,
		},
		{
			name: "allowed query param - regex match",
			config: FilterConfig{
				AllowedQueryParamsRegex: map[string][]string{
					"api_key": {"secret.*"},
				},
			},
			url:        "/test?api_key=secret456",
			wantStatus: http.StatusOK,
		},
		{
			name: "blocked query param - not in allowed list",
			config: FilterConfig{
				AllowedQueryParams: map[string][]string{
					"api_key": {"validkey"},
				},
			},
			url:        "/test?api_key=invalidkey",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "blocked query param - in blocked list",
			config: FilterConfig{
				BlockedQueryParams: map[string][]string{
					"debug": {"true"},
				},
			},
			url:        "/test?debug=true",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "blocked takes precedence over allowed",
			config: FilterConfig{
				AllowedQueryParamsRegex: map[string][]string{
					"param": {".*"},
				},
				BlockedQueryParams: map[string][]string{
					"param": {"badvalue"},
				},
			},
			url:        "/test?param=badvalue",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup router and middleware
			router := mux.NewRouter()
			RegisterFilterMiddleware(router, tt.config)

			// Add test handler
			router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})

			// Create test request
			req := httptest.NewRequest("GET", tt.url, nil)

			// Record response
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestFilterMiddleware_PathFiltering(t *testing.T) {
	config := FilterConfig{
		BlockedIPs:   []string{"10.0.0.1"},
		ExcludePaths: []string{"/health"},
		IncludePaths: []string{"/api/v1/users"},
	}

	tests := []struct {
		name       string
		path       string
		remoteAddr string
		wantStatus int
	}{
		{
			name:       "excluded path - should not be filtered",
			path:       "/health",
			remoteAddr: "10.0.0.1:12345", // This IP is blocked
			wantStatus: http.StatusOK,    // But should pass because path is excluded
		},
		{
			name:       "included path - should be filtered",
			path:       "/api/v1/users",
			remoteAddr: "10.0.0.1:12345", // This IP is blocked
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "other path - should not be filtered when include paths are specified",
			path:       "/api/v1/posts",
			remoteAddr: "10.0.0.1:12345", // This IP is blocked
			wantStatus: http.StatusOK,    // But should pass because path is not in include list
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup router and middleware
			router := mux.NewRouter()
			RegisterFilterMiddleware(router, config)

			// Add test handlers
			router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})
			router.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})
			router.HandleFunc("/api/v1/posts", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})

			// Create test request
			req := httptest.NewRequest("GET", tt.path, nil)
			req.RemoteAddr = tt.remoteAddr

			// Record response
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestFilterMiddleware_CustomStatusAndMessage(t *testing.T) {
	config := FilterConfig{
		BlockedIPs: []string{"10.0.0.1"},
		StatusCode: http.StatusTeapot,
		Message:    "Custom blocked message",
	}

	router := mux.NewRouter()
	RegisterFilterMiddleware(router, config)

	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusTeapot {
		t.Errorf("Expected status %d, got %d", http.StatusTeapot, rr.Code)
	}

	if !strings.Contains(rr.Body.String(), "Custom blocked message") {
		t.Errorf("Expected custom message in response, got: %s", rr.Body.String())
	}
}

func TestFilterMiddleware_NoFilteringWhenDisabled(t *testing.T) {
	// Empty config should not register any middleware
	config := FilterConfig{}

	router := mux.NewRouter()
	RegisterFilterMiddleware(router, config)

	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"          // Any IP should work
	req.Header.Set("User-Agent", "BadBot/1.0") // Any user agent should work

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func ExampleRegisterFilterMiddleware() {
	// Create a new router
	router := mux.NewRouter()

	// Configure filtering
	filterConfig := FilterConfig{
		// Only allow requests from specific IP ranges
		AllowedIPs: []string{"192.168.1.0/24", "10.0.0.1"},

		// Block known bad bots
		BlockedUserAgents: []string{
			"BadCrawler/1.0",
		},
		BlockedUserAgentsRegex: []string{
			".*[Bb]ot.*",
			".*[Ss]pider.*",
		},

		// Require API key in specific header
		AllowedHeadersRegex: map[string][]string{
			"X-API-Key": {"key-.*"},
		},

		// Block requests with debug parameter
		BlockedQueryParams: map[string][]string{
			"debug": {"true", "1"},
		},

		// Don't filter health check endpoint
		ExcludePaths: []string{"/health"},

		// Custom response for blocked requests
		StatusCode: http.StatusUnauthorized,
		Message:    "Access denied by security policy",
	}

	// Register the filter middleware
	RegisterFilterMiddleware(router, filterConfig)

	// Add your routes
	router.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Users API")
	})

	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	})
}

func TestLocationBasedFilterMiddleware(t *testing.T) {
	// Set up location-based filter configs
	locationConfigs := []LocationFilterConfig{
		{
			PathPatterns: []string{"/auth/*"},
			Config: FilterConfig{
				BlockedIPs:        []string{"10.0.0.1"},
				AllowedUserAgents: []string{"AuthClient/1.0"},
			},
		},
		{
			PathPatterns: []string{"/api/*"},
			Config: FilterConfig{
				AllowedIPs: []string{"192.168.1.0/24"},
			},
		},
		{
			PathPatterns: []string{"/admin/*"},
			Config: FilterConfig{
				AllowedHeaders: map[string][]string{
					"Admin-Token": {"secret123"},
				},
			},
		},
		{
			PathPatterns: []string{"/upload/*"},
			Config: FilterConfig{
				BlockedUserAgents: []string{"BadBot/1.0"},
				AllowedQueryParams: map[string][]string{
					"api_key": {"valid_key"},
				},
			},
		},
	}

	tests := []struct {
		name        string
		path        string
		remoteAddr  string
		userAgent   string
		headers     map[string]string
		queryParams map[string]string
		wantStatus  int
	}{
		// Auth endpoint tests
		{
			name:       "auth endpoint - blocked IP",
			path:       "/auth/login",
			remoteAddr: "10.0.0.1:12345",
			userAgent:  "AuthClient/1.0",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "auth endpoint - allowed IP and user agent",
			path:       "/auth/login",
			remoteAddr: "192.168.1.100:12345",
			userAgent:  "AuthClient/1.0",
			wantStatus: http.StatusOK,
		},
		{
			name:       "auth endpoint - allowed IP but wrong user agent",
			path:       "/auth/login",
			remoteAddr: "192.168.1.100:12345",
			userAgent:  "WrongClient/1.0",
			wantStatus: http.StatusForbidden,
		},

		// API endpoint tests
		{
			name:       "api endpoint - allowed IP",
			path:       "/api/users",
			remoteAddr: "192.168.1.50:12345",
			wantStatus: http.StatusOK,
		},
		{
			name:       "api endpoint - blocked IP",
			path:       "/api/users",
			remoteAddr: "10.0.0.1:12345",
			wantStatus: http.StatusForbidden,
		},

		// Admin endpoint tests
		{
			name:       "admin endpoint - with valid token",
			path:       "/admin/dashboard",
			remoteAddr: "192.168.1.1:12345",
			headers:    map[string]string{"Admin-Token": "secret123"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "admin endpoint - without token",
			path:       "/admin/dashboard",
			remoteAddr: "192.168.1.1:12345",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "admin endpoint - wrong token",
			path:       "/admin/dashboard",
			remoteAddr: "192.168.1.1:12345",
			headers:    map[string]string{"Admin-Token": "wrong_token"},
			wantStatus: http.StatusForbidden,
		},

		// Upload endpoint tests
		{
			name:        "upload endpoint - with valid API key",
			path:        "/upload/file",
			remoteAddr:  "192.168.1.1:12345",
			userAgent:   "GoodClient/1.0",
			queryParams: map[string]string{"api_key": "valid_key"},
			wantStatus:  http.StatusOK,
		},
		{
			name:        "upload endpoint - blocked user agent",
			path:        "/upload/file",
			remoteAddr:  "192.168.1.1:12345",
			userAgent:   "BadBot/1.0",
			queryParams: map[string]string{"api_key": "valid_key"},
			wantStatus:  http.StatusForbidden,
		},
		{
			name:       "upload endpoint - missing API key",
			path:       "/upload/file",
			remoteAddr: "192.168.1.1:12345",
			userAgent:  "GoodClient/1.0",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup router and middleware
			router := mux.NewRouter()
			RegisterLocationBasedFilterMiddleware(router, locationConfigs)

			// Add test handlers for different paths
			router.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Login OK"))
			})
			router.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Users API"))
			})
			router.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Admin Dashboard"))
			})
			router.HandleFunc("/upload/file", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Upload OK"))
			})

			// Create test request URL with query params
			url := tt.path
			if len(tt.queryParams) > 0 {
				url += "?"
				params := []string{}
				for k, v := range tt.queryParams {
					params = append(params, fmt.Sprintf("%s=%s", k, v))
				}
				url += strings.Join(params, "&")
			}

			req := httptest.NewRequest("POST", url, nil)
			req.RemoteAddr = tt.remoteAddr

			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			// Record response
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d for path %s", tt.wantStatus, rr.Code, tt.path)
			}
		})
	}
}

func TestLocationBasedFilterMiddleware_NoMatchingConfig(t *testing.T) {
	// Set up location-based filter configs that don't match all paths
	locationConfigs := []LocationFilterConfig{
		{
			PathPatterns: []string{"/api/*"},
			Config: FilterConfig{
				BlockedIPs: []string{"10.0.0.1"},
			},
		},
	}

	tests := []struct {
		name       string
		path       string
		remoteAddr string
		wantStatus int
	}{
		{
			name:       "matching path - should be filtered",
			path:       "/api/users",
			remoteAddr: "10.0.0.1:12345",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "non-matching path - should not be filtered",
			path:       "/public/info",
			remoteAddr: "10.0.0.1:12345", // Same blocked IP
			wantStatus: http.StatusOK,    // But should pass because no config matches
		},
		{
			name:       "root path - should not be filtered",
			path:       "/",
			remoteAddr: "10.0.0.1:12345", // Same blocked IP
			wantStatus: http.StatusOK,    // But should pass because no config matches
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup router and middleware
			router := mux.NewRouter()
			RegisterLocationBasedFilterMiddleware(router, locationConfigs)

			// Add test handlers
			router.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("API Response"))
			})
			router.HandleFunc("/public/info", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Public Info"))
			})
			router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Home"))
			})

			req := httptest.NewRequest("GET", tt.path, nil)
			req.RemoteAddr = tt.remoteAddr

			// Record response
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d for path %s", tt.wantStatus, rr.Code, tt.path)
			}
		})
	}
}

func TestLocationBasedFilterMiddleware_EmptyConfigs(t *testing.T) {
	// Test with empty location configs
	router := mux.NewRouter()
	RegisterLocationBasedFilterMiddleware(router, []LocationFilterConfig{})

	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestLocationBasedFilterMiddleware_OverlappingPatterns(t *testing.T) {
	// Test with properly overlapping patterns - first match should win
	// Both patterns can match the same path, demonstrating precedence
	locationConfigs := []LocationFilterConfig{
		{
			PathPatterns: []string{"/api/data"}, // Exact match
			Config: FilterConfig{
				BlockedIPs: []string{"10.0.0.1"},
			},
		},
		{
			PathPatterns: []string{"/api/*"}, // Wildcard that would also match /api/data
			Config: FilterConfig{
				AllowedIPs: []string{"10.0.0.1"}, // This would allow the IP that was blocked above
			},
		},
	}

	router := mux.NewRouter()
	RegisterLocationBasedFilterMiddleware(router, locationConfigs)

	router.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("API Data"))
	})

	// Test with a path that matches both patterns
	req := httptest.NewRequest("GET", "/api/data", nil)
	req.RemoteAddr = "10.0.0.1:12345"

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Should use the first matching config (blocking the IP) because it's checked first
	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d - first matching config should be used", http.StatusForbidden, rr.Code)
	}
}

func TestLocationBasedFilterMiddleware_MultiplePatterns(t *testing.T) {
	// Test config with multiple patterns
	locationConfigs := []LocationFilterConfig{
		{
			PathPatterns: []string{"/auth/*", "/secure/*", "/admin/*"},
			Config: FilterConfig{
				AllowedIPs: []string{"192.168.1.0/24"},
			},
		},
	}

	tests := []struct {
		name       string
		path       string
		remoteAddr string
		wantStatus int
	}{
		{
			name:       "first pattern match - allowed IP",
			path:       "/auth/login",
			remoteAddr: "192.168.1.100:12345",
			wantStatus: http.StatusOK,
		},
		{
			name:       "second pattern match - blocked IP",
			path:       "/secure/data",
			remoteAddr: "10.0.0.1:12345",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "third pattern match - allowed IP",
			path:       "/admin/dashboard",
			remoteAddr: "192.168.1.50:12345",
			wantStatus: http.StatusOK,
		},
		{
			name:       "no pattern match - should pass",
			path:       "/public/info",
			remoteAddr: "10.0.0.1:12345",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := mux.NewRouter()
			RegisterLocationBasedFilterMiddleware(router, locationConfigs)

			// Add handlers for all test paths
			router.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Auth"))
			})
			router.HandleFunc("/secure/data", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Secure"))
			})
			router.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Admin"))
			})
			router.HandleFunc("/public/info", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Public"))
			})

			req := httptest.NewRequest("GET", tt.path, nil)
			req.RemoteAddr = tt.remoteAddr

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d for path %s", tt.wantStatus, rr.Code, tt.path)
			}
		})
	}
}
