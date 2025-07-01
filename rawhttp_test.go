package servex_test

import (
	"net/http"
	"testing"

	"github.com/maxbolgarin/servex/v2"
)

func TestMakeRawRequest(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		host     string
		headers  map[string]string
		body     []string
		expected string
	}{
		{
			name:    "simple GET request",
			path:    "/test",
			host:    "example.com",
			headers: map[string]string{"Authorization": "Bearer token"},
			body:    nil,
			expected: "GET /test HTTP/1.1\n" +
				"Host: example.com\n" +
				"Authorization: Bearer token\n\n",
		},
		{
			name:    "GET request with body",
			path:    "/submit",
			host:    "example.com",
			headers: nil,
			body:    []string{"data=example"},
			expected: "GET /submit HTTP/1.1\n" +
				"Host: example.com\n" +
				"Content-Length: 12\n\n" +
				"data=example",
		},
		{
			name:    "GET request with Content-Length",
			path:    "/data",
			host:    "example.com",
			headers: map[string]string{"Content-Length": "10"},
			body:    []string{"somebody"},
			expected: "GET /data HTTP/1.1\n" +
				"Host: example.com\n" +
				"Content-Length: 10\n\n" +
				"somebody",
		},
	}

	for _, tt := range tests {
		tt := tt // capture loop variable
		t.Run(tt.name, func(t *testing.T) {
			rawRequest := servex.MakeRawRequest(tt.path, tt.host, tt.headers, tt.body...)
			if got, want := string(rawRequest), tt.expected; got != want {
				t.Errorf("MakeRawRequest(%q, %q, %v, %v) = %q, want %q", tt.path, tt.host, tt.headers, tt.body, got, want)
			}
		})
	}
}

func TestMakeRawResponse(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		headers  map[string]string
		body     []string
		expected string
	}{
		{
			name:    "simple 200 response",
			code:    http.StatusOK,
			headers: map[string]string{"Content-Type": "application/json"},
			body:    nil,
			expected: "HTTP/1.1 200 OK\n" +
				"Content-Type: application/json\n\n",
		},
		{
			name:    "200 response with body",
			code:    http.StatusOK,
			headers: map[string]string{"Content-Type": "text/plain"},
			body:    []string{"Hello World"},
			expected: "HTTP/1.1 200 OK\n" +
				"Content-Type: text/plain\n" +
				"Content-Length: 11\n\n" +
				"Hello World",
		},
		{
			name:    "404 response",
			code:    404,
			headers: nil,
			body:    []string{"Not Found"},
			expected: "HTTP/1.1 404 Not Found\n" +
				"Content-Length: 9\n\n" +
				"Not Found",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			rawResponse := servex.MakeRawResponse(tt.code, tt.headers, tt.body...)
			if got, want := string(rawResponse), tt.expected; got != want {
				t.Errorf("MakeRawResponse() = %q, want %q", got, want)
			}
		})
	}
}
