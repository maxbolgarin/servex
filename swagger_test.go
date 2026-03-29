package servex

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSwaggerHandler(t *testing.T) {
	spec := []byte(`openapi: "3.0.3"
info:
  title: Test API
  version: "1.0"
paths: {}`)

	handler := SwaggerHandler(spec)

	t.Run("serves HTML UI at root", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		ct := w.Header().Get("Content-Type")
		if !strings.Contains(ct, "text/html") {
			t.Fatalf("expected text/html content type, got %s", ct)
		}
		body := w.Body.String()
		if !strings.Contains(body, "swagger-ui") {
			t.Fatal("expected swagger-ui in HTML body")
		}
		if !strings.Contains(body, "API Documentation") {
			t.Fatal("expected default title in HTML")
		}
	})

	t.Run("serves spec at /spec", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/spec", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if w.Body.String() != string(spec) {
			t.Fatal("spec content mismatch")
		}
	})

	t.Run("serves spec at /spec.json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/spec.json", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("serves spec at /spec.yaml", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/spec.yaml", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("returns 404 for unknown paths", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})

	t.Run("returns 405 for non-GET on UI", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", w.Code)
		}
	})

	t.Run("returns 405 for non-GET on spec", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/spec", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", w.Code)
		}
	})
}

func TestSwaggerHandler_ContentType(t *testing.T) {
	t.Run("YAML spec", func(t *testing.T) {
		spec := []byte("openapi: '3.0.3'\ninfo:\n  title: Test\n  version: '1.0'\npaths: {}")
		handler := SwaggerHandler(spec)

		req := httptest.NewRequest(http.MethodGet, "/spec", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		ct := w.Header().Get("Content-Type")
		if !strings.Contains(ct, "application/yaml") {
			t.Fatalf("expected application/yaml, got %s", ct)
		}
	})

	t.Run("JSON spec", func(t *testing.T) {
		spec := []byte(`{"openapi": "3.0.3", "info": {"title": "Test", "version": "1.0"}, "paths": {}}`)
		handler := SwaggerHandler(spec)

		req := httptest.NewRequest(http.MethodGet, "/spec", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		ct := w.Header().Get("Content-Type")
		if !strings.Contains(ct, "application/json") {
			t.Fatalf("expected application/json, got %s", ct)
		}
	})
}

func TestWithSwaggerTitle(t *testing.T) {
	spec := []byte("openapi: '3.0.3'")
	handler := SwaggerHandler(spec, WithSwaggerTitle("My Custom Docs"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !strings.Contains(w.Body.String(), "My Custom Docs") {
		t.Fatal("expected custom title in HTML body")
	}
}

func TestSwaggerAutoConfig_LoadSpec(t *testing.T) {
	t.Run("loads from file", func(t *testing.T) {
		dir := t.TempDir()
		specPath := filepath.Join(dir, "openapi.yaml")
		specContent := []byte("openapi: '3.0.3'\ninfo:\n  title: File Test\n  version: '1.0'")
		if err := os.WriteFile(specPath, specContent, 0644); err != nil {
			t.Fatal(err)
		}

		cfg := &SwaggerAutoConfig{
			Enabled:  true,
			SpecFile: specPath,
		}
		if err := cfg.loadSwaggerSpec(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(cfg.SpecData) != string(specContent) {
			t.Fatal("spec data mismatch")
		}
	})

	t.Run("error on missing file", func(t *testing.T) {
		cfg := &SwaggerAutoConfig{
			Enabled:  true,
			SpecFile: "/nonexistent/path/openapi.yaml",
		}
		if err := cfg.loadSwaggerSpec(); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("skips file load when SpecData already set", func(t *testing.T) {
		existing := []byte("existing spec data")
		cfg := &SwaggerAutoConfig{
			Enabled:  true,
			SpecFile: "/some/file.yaml",
			SpecData: existing,
		}
		if err := cfg.loadSwaggerSpec(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(cfg.SpecData) != string(existing) {
			t.Fatal("should not have overwritten existing SpecData")
		}
	})
}

func TestWithSwaggerUI(t *testing.T) {
	spec := []byte("openapi: '3.0.3'")
	opt := WithSwaggerUI(spec)

	var opts Options
	opt(&opts)

	if !opts.Swagger.Enabled {
		t.Fatal("expected swagger to be enabled")
	}
	if string(opts.Swagger.SpecData) != string(spec) {
		t.Fatal("spec data mismatch")
	}
}

func TestWithSwaggerUIFile(t *testing.T) {
	opt := WithSwaggerUIFile("./test.yaml")

	var opts Options
	opt(&opts)

	if !opts.Swagger.Enabled {
		t.Fatal("expected swagger to be enabled")
	}
	if opts.Swagger.SpecFile != "./test.yaml" {
		t.Fatalf("expected spec file ./test.yaml, got %s", opts.Swagger.SpecFile)
	}
}

func TestWithSwaggerUIPath(t *testing.T) {
	opt := WithSwaggerUIPath("/api-docs")

	var opts Options
	opt(&opts)

	if opts.Swagger.Path != "/api-docs" {
		t.Fatalf("expected path /api-docs, got %s", opts.Swagger.Path)
	}
}

func TestNewServer_SwaggerValidation(t *testing.T) {
	t.Run("error when enabled but no spec", func(t *testing.T) {
		_, err := NewServerWithOptions(Options{
			Swagger: SwaggerAutoConfig{
				Enabled: true,
			},
		})
		if err == nil {
			t.Fatal("expected error when swagger enabled without spec")
		}
		if !strings.Contains(err.Error(), "no spec data") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("error when spec file not found", func(t *testing.T) {
		_, err := NewServerWithOptions(Options{
			Swagger: SwaggerAutoConfig{
				Enabled:  true,
				SpecFile: "/nonexistent/openapi.yaml",
			},
		})
		if err == nil {
			t.Fatal("expected error when spec file not found")
		}
		if !strings.Contains(err.Error(), "load swagger spec file") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("success with spec data", func(t *testing.T) {
		server, err := NewServerWithOptions(Options{
			Swagger: SwaggerAutoConfig{
				Enabled:  true,
				SpecData: []byte("openapi: '3.0.3'"),
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if server == nil {
			t.Fatal("expected server to be created")
		}
	})

	t.Run("success with spec file", func(t *testing.T) {
		dir := t.TempDir()
		specPath := filepath.Join(dir, "openapi.yaml")
		if err := os.WriteFile(specPath, []byte("openapi: '3.0.3'"), 0644); err != nil {
			t.Fatal(err)
		}

		server, err := NewServerWithOptions(Options{
			Swagger: SwaggerAutoConfig{
				Enabled:  true,
				SpecFile: specPath,
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if server == nil {
			t.Fatal("expected server to be created")
		}
	})
}

func TestDetectSpecContentType(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{"JSON object", []byte(`{"openapi": "3.0"}`), "application/json; charset=utf-8"},
		{"JSON with whitespace", []byte(`  {"openapi": "3.0"}`), "application/json; charset=utf-8"},
		{"YAML", []byte("openapi: '3.0'"), "application/yaml; charset=utf-8"},
		{"empty", []byte(""), "application/yaml; charset=utf-8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectSpecContentType(tt.data)
			if got != tt.expected {
				t.Fatalf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}
