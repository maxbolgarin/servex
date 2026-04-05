package servex

import (
	"bytes"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// xmlTestStruct is used for XML marshaling tests.
type xmlTestStruct struct {
	XMLName xml.Name `xml:"item"`
	Name    string   `xml:"name"`
	Value   int      `xml:"value"`
}

func TestXML(t *testing.T) {
	tests := []struct {
		name            string
		code            int
		body            any
		wantStatus      int
		wantContentType string
		wantBody        string
	}{
		{
			name:            "marshal struct",
			code:            http.StatusOK,
			body:            xmlTestStruct{Name: "foo", Value: 42},
			wantStatus:      http.StatusOK,
			wantContentType: "application/xml; charset=utf-8",
			wantBody:        "<item><name>foo</name><value>42</value></item>",
		},
		{
			name:            "201 created",
			code:            http.StatusCreated,
			body:            xmlTestStruct{Name: "bar", Value: 1},
			wantStatus:      http.StatusCreated,
			wantContentType: "application/xml; charset=utf-8",
			wantBody:        "<item><name>bar</name><value>1</value></item>",
		},
		{
			name:       "marshal error (channel)",
			code:       http.StatusOK,
			body:       make(chan int),
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			ctx := C(w, r)
			ctx.XML(tt.code, tt.body)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.wantContentType != "" {
				got := w.Header().Get("Content-Type")
				if got != tt.wantContentType {
					t.Errorf("Content-Type = %q, want %q", got, tt.wantContentType)
				}
			}
			if tt.wantBody != "" {
				body := w.Body.String()
				if !strings.Contains(body, tt.wantBody) {
					t.Errorf("body = %q, want to contain %q", body, tt.wantBody)
				}
			}
		})
	}
}

func TestXMLIndent(t *testing.T) {
	tests := []struct {
		name       string
		indent     string
		body       any
		wantIndent bool
		wantStatus int
	}{
		{
			name:       "tab indent",
			indent:     "\t",
			body:       xmlTestStruct{Name: "hello", Value: 7},
			wantIndent: true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "space indent",
			indent:     "  ",
			body:       xmlTestStruct{Name: "hello", Value: 7},
			wantIndent: true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "marshal error (channel)",
			indent:     "  ",
			body:       make(chan int),
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			ctx := C(w, r)
			ctx.XMLIndent(http.StatusOK, tt.body, tt.indent)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusOK {
				ct := w.Header().Get("Content-Type")
				if ct != "application/xml; charset=utf-8" {
					t.Errorf("Content-Type = %q, want application/xml; charset=utf-8", ct)
				}
				body := w.Body.String()
				// Indented output should contain newlines
				if tt.wantIndent && !strings.Contains(body, "\n") {
					t.Errorf("expected indented XML (with newlines), got: %q", body)
				}
				if !strings.Contains(body, "hello") || !strings.Contains(body, "7") {
					t.Errorf("body missing expected content: %q", body)
				}
			}
		})
	}
}

// flusherRecorder wraps httptest.ResponseRecorder and tracks Flush calls.
type flusherRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (f *flusherRecorder) Flush() {
	f.flushed = true
	f.ResponseRecorder.Flush()
}

func TestStream(t *testing.T) {
	tests := []struct {
		name        string
		code        int
		contentType string
		data        string
	}{
		{
			name:        "stream text",
			code:        http.StatusOK,
			contentType: "text/plain",
			data:        "hello streaming world",
		},
		{
			name:        "stream binary-like",
			code:        http.StatusPartialContent,
			contentType: "application/octet-stream",
			data:        "binary\x00data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &flusherRecorder{ResponseRecorder: httptest.NewRecorder()}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			ctx := &Context{
				w: rec,
				r: r,
			}
			ctx.Stream(tt.code, tt.contentType, strings.NewReader(tt.data))

			if rec.Code != tt.code {
				t.Errorf("status = %d, want %d", rec.Code, tt.code)
			}
			got := rec.Header().Get("Content-Type")
			if got != tt.contentType {
				t.Errorf("Content-Type = %q, want %q", got, tt.contentType)
			}
			body := rec.Body.String()
			if body != tt.data {
				t.Errorf("body = %q, want %q", body, tt.data)
			}
			if !rec.flushed {
				t.Error("expected Flush() to be called")
			}
		})
	}

	t.Run("non-flusher writer", func(t *testing.T) {
		// httptest.ResponseRecorder without our wrapper — no Flush method visible through http.Flusher
		// We verify it doesn't panic and response is correct.
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		ctx := C(w, r)
		ctx.Stream(http.StatusOK, "text/plain", strings.NewReader("data"))
		if w.Body.String() != "data" {
			t.Errorf("body = %q, want %q", w.Body.String(), "data")
		}
	})
}

func TestStreamReaderError(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := C(w, r)
	// errReader always returns an error on Read
	ctx.Stream(http.StatusOK, "text/plain", &errReader{})
	// Status is already written; we just check no panic and error is set
	errCode := getValueFromContext[int](ctx.r, codeKey{})
	if errCode != http.StatusInternalServerError {
		t.Errorf("expected error to be set, errCode = %d", errCode)
	}
}

type errReader struct{}

func (e *errReader) Read(p []byte) (int, error) {
	return 0, bytes.ErrTooLarge
}

func TestNegotiate(t *testing.T) {
	type item struct {
		XMLName xml.Name `xml:"item"`
		Msg     string   `xml:"msg"`
	}

	v := item{Msg: "hello"}

	tests := []struct {
		name       string
		accept     string
		wantStatus int
		wantCT     string
		wantBody   string
	}{
		{
			name:       "no accept header defaults to JSON",
			accept:     "",
			wantStatus: http.StatusOK,
			wantCT:     MIMETypeJSON,
			wantBody:   `"hello"`,
		},
		{
			name:       "wildcard defaults to JSON",
			accept:     "*/*",
			wantStatus: http.StatusOK,
			wantCT:     MIMETypeJSON,
		},
		{
			name:       "explicit JSON",
			accept:     "application/json",
			wantStatus: http.StatusOK,
			wantCT:     MIMETypeJSON,
			wantBody:   `"hello"`,
		},
		{
			name:       "explicit XML",
			accept:     "application/xml",
			wantStatus: http.StatusOK,
			wantCT:     "application/xml; charset=utf-8",
			wantBody:   "<msg>hello</msg>",
		},
		{
			name:       "plain text",
			accept:     "text/plain",
			wantStatus: http.StatusOK,
			wantCT:     MIMETypePlain,
			wantBody:   "hello",
		},
		{
			name:       "XML preferred over JSON via q-value",
			accept:     "application/json;q=0.5, application/xml;q=0.9",
			wantStatus: http.StatusOK,
			wantCT:     "application/xml; charset=utf-8",
		},
		{
			name:       "406 when all supported types q=0",
			accept:     "application/json;q=0, application/xml;q=0, text/plain;q=0",
			wantStatus: http.StatusNotAcceptable,
		},
		{
			name:       "unsupported type falls back to wildcard JSON",
			accept:     "text/html, */*;q=0.8",
			wantStatus: http.StatusOK,
			wantCT:     MIMETypeJSON,
		},
		{
			name:       "unsupported type only returns 406",
			accept:     "text/html",
			wantStatus: http.StatusNotAcceptable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.accept != "" {
				r.Header.Set("Accept", tt.accept)
			}
			ctx := C(w, r)
			ctx.Negotiate(http.StatusOK, v)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.wantCT != "" {
				got := w.Header().Get("Content-Type")
				if !strings.HasPrefix(got, tt.wantCT) {
					t.Errorf("Content-Type = %q, want prefix %q", got, tt.wantCT)
				}
			}
			if tt.wantBody != "" {
				body := w.Body.String()
				if !strings.Contains(body, tt.wantBody) {
					t.Errorf("body = %q, want to contain %q", body, tt.wantBody)
				}
			}
		})
	}
}

func TestParseAcceptHeader(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   []acceptEntry
	}{
		{
			name:  "empty",
			input: "",
			want:  nil,
		},
		{
			name:  "single type",
			input: "application/json",
			want:  []acceptEntry{{mediaType: "application/json", quality: 1.0}},
		},
		{
			name:  "with q-value",
			input: "application/json;q=0.9",
			want:  []acceptEntry{{mediaType: "application/json", quality: 0.9}},
		},
		{
			name:  "multiple types with quality",
			input: "text/html, application/json;q=0.9, */*;q=0.8",
			want: []acceptEntry{
				{mediaType: "text/html", quality: 1.0},
				{mediaType: "application/json", quality: 0.9},
				{mediaType: "*/*", quality: 0.8},
			},
		},
		{
			name:  "zero quality",
			input: "application/xml;q=0",
			want:  []acceptEntry{{mediaType: "application/xml", quality: 0.0}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAcceptHeader(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d; got %+v", len(got), len(tt.want), got)
			}
			for i, e := range tt.want {
				if got[i].mediaType != e.mediaType {
					t.Errorf("[%d] mediaType = %q, want %q", i, got[i].mediaType, e.mediaType)
				}
				if got[i].quality != e.quality {
					t.Errorf("[%d] quality = %f, want %f", i, got[i].quality, e.quality)
				}
			}
		})
	}
}
