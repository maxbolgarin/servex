package servex_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/maxbolgarin/servex/v2"
)

// TestCacheControlPathMatching tests the path matching logic for cache headers through the middleware.
func TestCacheControlPathMatching(t *testing.T) {
	tests := []struct {
		name        string
		config      servex.CacheConfig
		path        string
		shouldApply bool
	}{
		{
			name: "no path restrictions",
			config: servex.CacheConfig{
				Enabled:      true,
				CacheControl: "public, max-age=3600",
			},
			path:        "/any/path",
			shouldApply: true,
		},
		{
			name: "include paths match",
			config: servex.CacheConfig{
				Enabled:      true,
				CacheControl: "public, max-age=3600",
				IncludePaths: []string{"/static/*", "/assets/*"},
			},
			path:        "/static/style.css",
			shouldApply: true,
		},
		{
			name: "include paths no match",
			config: servex.CacheConfig{
				Enabled:      true,
				CacheControl: "public, max-age=3600",
				IncludePaths: []string{"/static/*", "/assets/*"},
			},
			path:        "/api/data",
			shouldApply: false,
		},
		{
			name: "exclude paths match",
			config: servex.CacheConfig{
				Enabled:      true,
				CacheControl: "public, max-age=3600",
				ExcludePaths: []string{"/api/*", "/admin/*"},
			},
			path:        "/api/users",
			shouldApply: false,
		},
		{
			name: "exclude paths no match",
			config: servex.CacheConfig{
				Enabled:      true,
				CacheControl: "public, max-age=3600",
				ExcludePaths: []string{"/api/*", "/admin/*"},
			},
			path:        "/static/app.js",
			shouldApply: true,
		},
		{
			name: "include and exclude - include wins",
			config: servex.CacheConfig{
				Enabled:      true,
				CacheControl: "public, max-age=3600",
				IncludePaths: []string{"/static/*"},
				ExcludePaths: []string{"/static/admin/*"},
			},
			path:        "/static/style.css",
			shouldApply: true,
		},
		{
			name: "include and exclude - exclude wins",
			config: servex.CacheConfig{
				Enabled:      true,
				CacheControl: "public, max-age=3600",
				IncludePaths: []string{"/static/*"},
				ExcludePaths: []string{"/static/admin/*"},
			},
			path:        "/static/admin/secret.css",
			shouldApply: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test router and register cache middleware
			router := mux.NewRouter()
			servex.RegisterCacheControlMiddleware(router, tt.config)

			// Add a test handler
			router.HandleFunc("/{rest:.*}", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("test response"))
			})

			// Create request and response recorder
			req := httptest.NewRequest(servex.GET, tt.path, nil)
			w := httptest.NewRecorder()

			// Execute request
			router.ServeHTTP(w, req)

			// Check if cache control headers are present
			hasCacheControl := w.Header().Get("Cache-Control") != ""

			if hasCacheControl != tt.shouldApply {
				t.Errorf("expected cache headers to be applied: %v for path %q, got headers applied: %v", tt.shouldApply, tt.path, hasCacheControl)
			}
		})
	}
}

// TestCacheControlMiddleware tests the cache control middleware application.
func TestCacheControlMiddleware(t *testing.T) {
	tests := []struct {
		name              string
		config            servex.CacheConfig
		path              string
		expectedHeaders   map[string]string
		shouldHaveHeaders bool
	}{
		{
			name: "basic cache control",
			config: servex.CacheConfig{
				Enabled:      true,
				CacheControl: "public, max-age=3600",
			},
			path: "/test",
			expectedHeaders: map[string]string{
				"Cache-Control": "public, max-age=3600",
			},
			shouldHaveHeaders: true,
		},
		{
			name: "all cache headers",
			config: servex.CacheConfig{
				Enabled:      true,
				CacheControl: "public, max-age=3600",
				ETag:         `"v1.2.3"`,
				LastModified: "Wed, 21 Oct 2015 07:28:00 GMT",
				Expires:      "Thu, 22 Oct 2015 07:28:00 GMT",
				Vary:         "Accept-Encoding",
			},
			path: "/test",
			expectedHeaders: map[string]string{
				"Cache-Control": "public, max-age=3600",
				"ETag":          `"v1.2.3"`,
				"Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT",
				"Expires":       "Thu, 22 Oct 2015 07:28:00 GMT",
				"Vary":          "Accept-Encoding",
			},
			shouldHaveHeaders: true,
		},
		{
			name: "excluded path",
			config: servex.CacheConfig{
				Enabled:      true,
				CacheControl: "public, max-age=3600",
				ExcludePaths: []string{"/api/*"},
			},
			path: "/api/users",
			expectedHeaders: map[string]string{
				"Cache-Control": "public, max-age=3600",
			},
			shouldHaveHeaders: false,
		},
		{
			name: "dynamic etag function",
			config: servex.CacheConfig{
				Enabled:      true,
				CacheControl: "public, max-age=3600",
				ETag:         `"static-etag"`,
				ETagFunc: func(r *http.Request) string {
					return `"dynamic-etag"`
				},
			},
			path: "/test",
			expectedHeaders: map[string]string{
				"Cache-Control": "public, max-age=3600",
				"ETag":          `"dynamic-etag"`, // Dynamic should override static
			},
			shouldHaveHeaders: true,
		},
		{
			name: "dynamic last modified function",
			config: servex.CacheConfig{
				Enabled:      true,
				CacheControl: "public, max-age=3600",
				LastModified: "Wed, 21 Oct 2015 07:28:00 GMT",
				LastModifiedFunc: func(r *http.Request) time.Time {
					return time.Date(2023, 5, 15, 12, 30, 0, 0, time.UTC)
				},
			},
			path: "/test",
			expectedHeaders: map[string]string{
				"Cache-Control": "public, max-age=3600",
				"Last-Modified": "Mon, 15 May 2023 12:30:00 GMT", // Dynamic should override static
			},
			shouldHaveHeaders: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("test response"))
			})

			// Create a test router and register cache middleware
			router := mux.NewRouter()
			servex.RegisterCacheControlMiddleware(router, tt.config)

			// Add the test handler
			router.HandleFunc("/{rest:.*}", handler)

			// Create request and response recorder
			req := httptest.NewRequest(servex.GET, tt.path, nil)
			w := httptest.NewRecorder()

			// Execute request
			router.ServeHTTP(w, req)

			// Check headers
			for key, expectedValue := range tt.expectedHeaders {
				actualValue := w.Header().Get(key)

				if tt.shouldHaveHeaders {
					if actualValue != expectedValue {
						t.Errorf("expected header %q to be %q, got %q", key, expectedValue, actualValue)
					}
				} else {
					if actualValue != "" {
						t.Errorf("expected header %q to be empty, got %q", key, actualValue)
					}
				}
			}

			// Verify response body is unchanged
			if w.Body.String() != "test response" {
				t.Errorf("expected response body to be unchanged, got %q", w.Body.String())
			}
		})
	}
}

// TestCacheControlMiddlewareWithETagValidation tests ETag-based conditional requests.
func TestCacheControlMiddlewareWithETagValidation(t *testing.T) {
	config := servex.CacheConfig{
		Enabled:      true,
		CacheControl: "public, max-age=3600",
		ETag:         `"v1.2.3"`,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Create a test router and register cache middleware
	router := mux.NewRouter()
	servex.RegisterCacheControlMiddleware(router, config)

	// Add the test handler
	router.HandleFunc("/{rest:.*}", handler)

	tests := []struct {
		name               string
		ifNoneMatchHeader  string
		expectedStatusCode int
		expectedBody       string
	}{
		{
			name:               "no conditional header",
			ifNoneMatchHeader:  "",
			expectedStatusCode: http.StatusOK,
			expectedBody:       "test response",
		},
		{
			name:               "matching etag",
			ifNoneMatchHeader:  `"v1.2.3"`,
			expectedStatusCode: http.StatusNotModified,
			expectedBody:       "",
		},
		{
			name:               "non-matching etag",
			ifNoneMatchHeader:  `"v1.2.4"`,
			expectedStatusCode: http.StatusOK,
			expectedBody:       "test response",
		},
		{
			name:               "wildcard etag",
			ifNoneMatchHeader:  "*",
			expectedStatusCode: http.StatusNotModified,
			expectedBody:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(servex.GET, "/test", nil)
			if tt.ifNoneMatchHeader != "" {
				req.Header.Set("If-None-Match", tt.ifNoneMatchHeader)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatusCode {
				t.Errorf("expected status code %d, got %d", tt.expectedStatusCode, w.Code)
			}

			if w.Body.String() != tt.expectedBody {
				t.Errorf("expected body %q, got %q", tt.expectedBody, w.Body.String())
			}

			// ETag header should always be present
			if w.Header().Get("ETag") != `"v1.2.3"` {
				t.Errorf("expected ETag header to be %q, got %q", `"v1.2.3"`, w.Header().Get("ETag"))
			}
		})
	}
}

// TestCacheControlMiddlewareWithLastModifiedValidation tests Last-Modified-based conditional requests.
func TestCacheControlMiddlewareWithLastModifiedValidation(t *testing.T) {
	lastModTime := time.Date(2015, 10, 21, 7, 28, 0, 0, time.UTC)
	config := servex.CacheConfig{
		Enabled:      true,
		CacheControl: "public, max-age=3600",
		LastModified: lastModTime.Format(http.TimeFormat),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Create a test router and register cache middleware
	router := mux.NewRouter()
	servex.RegisterCacheControlMiddleware(router, config)

	// Add the test handler
	router.HandleFunc("/{rest:.*}", handler)

	tests := []struct {
		name                  string
		ifModifiedSinceHeader string
		expectedStatusCode    int
		expectedBody          string
	}{
		{
			name:                  "no conditional header",
			ifModifiedSinceHeader: "",
			expectedStatusCode:    http.StatusOK,
			expectedBody:          "test response",
		},
		{
			name:                  "not modified since",
			ifModifiedSinceHeader: lastModTime.Format(http.TimeFormat),
			expectedStatusCode:    http.StatusNotModified,
			expectedBody:          "",
		},
		{
			name:                  "modified since",
			ifModifiedSinceHeader: lastModTime.Add(-time.Hour).Format(http.TimeFormat),
			expectedStatusCode:    http.StatusOK,
			expectedBody:          "test response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(servex.GET, "/test", nil)
			if tt.ifModifiedSinceHeader != "" {
				req.Header.Set("If-Modified-Since", tt.ifModifiedSinceHeader)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatusCode {
				t.Errorf("expected status code %d, got %d", tt.expectedStatusCode, w.Code)
			}

			if w.Body.String() != tt.expectedBody {
				t.Errorf("expected body %q, got %q", tt.expectedBody, w.Body.String())
			}

			// Last-Modified header should always be present
			expectedLastMod := lastModTime.Format(http.TimeFormat)
			if w.Header().Get("Last-Modified") != expectedLastMod {
				t.Errorf("expected Last-Modified header to be %q, got %q", expectedLastMod, w.Header().Get("Last-Modified"))
			}
		})
	}
}

// TestCacheControlDisabled tests that no headers are applied when caching is disabled.
func TestCacheControlDisabled(t *testing.T) {
	config := servex.CacheConfig{
		Enabled:      false,
		CacheControl: "public, max-age=3600",
		ETag:         `"v1.2.3"`,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Create a test router and register cache middleware
	router := mux.NewRouter()
	servex.RegisterCacheControlMiddleware(router, config)

	// Add the test handler
	router.HandleFunc("/{rest:.*}", handler)

	req := httptest.NewRequest(servex.GET, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// No cache headers should be set
	cacheHeaders := []string{"Cache-Control", "ETag", "Last-Modified", "Expires", "Vary"}
	for _, header := range cacheHeaders {
		if w.Header().Get(header) != "" {
			t.Errorf("expected header %q to be empty when caching is disabled, got %q", header, w.Header().Get(header))
		}
	}

	// Response should be normal
	if w.Code != http.StatusOK {
		t.Errorf("expected status code 200, got %d", w.Code)
	}
	if w.Body.String() != "test response" {
		t.Errorf("expected response body to be unchanged, got %q", w.Body.String())
	}
}
