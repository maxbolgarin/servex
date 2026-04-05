package servex

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestServer wraps an [httptest.Server] with a configured servex [Server] for testing.
// It provides a convenient API for making HTTP requests and testing WebSocket connections.
//
// Example:
//
//	func TestMyHandler(t *testing.T) {
//	    ts := servex.NewTestServer(t,
//	        servex.WithHealthEndpoint(),
//	    )
//	    defer ts.Close()
//
//	    resp := ts.Request("GET", "/health").Do()
//	    if resp.Code != 200 {
//	        t.Fatal("unexpected status")
//	    }
//	}
type TestServer struct {
	// Server is the underlying servex server.
	Server *Server
	// HTTP is the httptest server for making requests.
	HTTP *httptest.Server
	// URL is the base URL of the test server.
	URL string
	t   testing.TB
}

// NewTestServer creates a test server with the given options.
// It automatically calls [testing.TB.Cleanup] to close the server when the test finishes.
func NewTestServer(t testing.TB, opts ...Option) *TestServer {
	t.Helper()
	srv, err := NewServer(opts...)
	if err != nil {
		t.Fatalf("servex.NewTestServer: %v", err)
	}

	httpSrv := httptest.NewServer(srv.router)
	t.Cleanup(httpSrv.Close)

	return &TestServer{
		Server: srv,
		HTTP:   httpSrv,
		URL:    httpSrv.URL,
		t:      t,
	}
}

// Close shuts down the test server.
func (ts *TestServer) Close() {
	ts.HTTP.Close()
}

// Request creates a new [TestRequest] for the given method and path.
func (ts *TestServer) Request(method, path string) *TestRequest {
	return &TestRequest{
		ts:     ts,
		method: method,
		path:   path,
		header: make(http.Header),
	}
}

// Get creates a GET [TestRequest].
func (ts *TestServer) Get(path string) *TestRequest {
	return ts.Request("GET", path)
}

// Post creates a POST [TestRequest].
func (ts *TestServer) Post(path string) *TestRequest {
	return ts.Request("POST", path)
}

// Put creates a PUT [TestRequest].
func (ts *TestServer) Put(path string) *TestRequest {
	return ts.Request("PUT", path)
}

// Patch creates a PATCH [TestRequest].
func (ts *TestServer) Patch(path string) *TestRequest {
	return ts.Request("PATCH", path)
}

// Delete creates a DELETE [TestRequest].
func (ts *TestServer) Delete(path string) *TestRequest {
	return ts.Request("DELETE", path)
}

// TestRequest builds an HTTP request for use with [TestServer].
type TestRequest struct {
	ts     *TestServer
	method string
	path   string
	body   io.Reader
	header http.Header
}

// WithBody sets the request body.
func (tr *TestRequest) WithBody(body io.Reader) *TestRequest {
	tr.body = body
	return tr
}

// WithJSON sets the request body as JSON and sets the Content-Type header.
func (tr *TestRequest) WithJSON(v any) *TestRequest {
	data, err := json.Marshal(v)
	if err != nil {
		tr.ts.t.Fatalf("servex.TestRequest.WithJSON: %v", err)
	}
	tr.body = bytes.NewReader(data)
	tr.header.Set("Content-Type", MIMETypeJSON)
	return tr
}

// WithHeader sets a request header.
func (tr *TestRequest) WithHeader(key, value string) *TestRequest {
	tr.header.Set(key, value)
	return tr
}

// WithAuth sets the Authorization header with a Bearer token.
func (tr *TestRequest) WithAuth(token string) *TestRequest {
	tr.header.Set("Authorization", "Bearer "+token)
	return tr
}

// WithCookie adds a cookie to the request.
func (tr *TestRequest) WithCookie(name, value string) *TestRequest {
	tr.header.Add("Cookie", name+"="+value)
	return tr
}

// Do sends the request and returns the recorded response.
func (tr *TestRequest) Do() *TestResponse {
	tr.ts.t.Helper()
	req, err := http.NewRequest(tr.method, tr.ts.URL+tr.path, tr.body)
	if err != nil {
		tr.ts.t.Fatalf("servex.TestRequest.Do: %v", err)
	}
	for key, values := range tr.header {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	resp, err := tr.ts.HTTP.Client().Do(req)
	if err != nil {
		tr.ts.t.Fatalf("servex.TestRequest.Do: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tr.ts.t.Fatalf("servex.TestRequest.Do: read body: %v", err)
	}

	return &TestResponse{
		Code:   resp.StatusCode,
		Header: resp.Header,
		Body:   body,
	}
}

// TestResponse holds a captured HTTP response for assertions.
type TestResponse struct {
	// Code is the HTTP status code.
	Code int
	// Header contains the response headers.
	Header http.Header
	// Body is the raw response body.
	Body []byte
}

// JSON unmarshals the response body into v.
func (tr *TestResponse) JSON(v any) error {
	return json.Unmarshal(tr.Body, v)
}

// BodyString returns the response body as a string.
func (tr *TestResponse) BodyString() string {
	return string(tr.Body)
}
