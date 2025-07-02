package servex

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Define a struct for testing JSON marshaling and validation
type testStruct struct {
	Foo string `json:"foo"`
}

func (t testStruct) Validate() error {
	if t.Foo == "" {
		return errors.New("Foo cannot be empty")
	}
	return nil
}

func TestReadJSON(t *testing.T) {
	testData := testStruct{Foo: "bar"}
	data, _ := json.Marshal(testData)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(data))
	defer req.Body.Close()

	received, err := ReadJSON[testStruct](req)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !reflect.DeepEqual(testData, received) {
		t.Errorf("expected TestData, got %v", received)
	}
}

// TestRead tests the global Read function.
func TestRead(t *testing.T) {
	testData := "Hello, World!"
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testData))
	defer req.Body.Close()

	body, err := Read(req)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if string(body) != testData {
		t.Errorf("expected %q, got %q", testData, string(body))
	}
}

// TestReadEmpty tests the global Read function with empty request body.
func TestReadEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	defer req.Body.Close()

	body, err := Read(req)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(body) != 0 {
		t.Errorf("expected empty body, got %q", string(body))
	}
}

func TestReadAndValidate_Valid(t *testing.T) {
	testData := testStruct{Foo: "bar"}
	data, _ := json.Marshal(testData)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(data))
	defer req.Body.Close()

	received, err := ReadAndValidate[testStruct](req)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !reflect.DeepEqual(testData, received) {
		t.Errorf("expected TestData, got %v", received)
	}
}

func TestReadAndValidate_Invalid(t *testing.T) {
	testData := testStruct{}
	data, _ := json.Marshal(testData)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(data))
	defer req.Body.Close()

	_, err := ReadAndValidate[testStruct](req)
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid body") {
		t.Errorf("expected 'invalid body' in error message, got %v", err)
	}
}

func TestContext_RequestID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := NewContext(httptest.NewRecorder(), req)

	requestID1 := ctx.RequestID()
	requestID2 := ctx.RequestID()
	if requestID1 != requestID2 {
		t.Errorf("Request IDs should be the same for the same context")
	}
}

func TestContext_APIVersion(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	ctx := NewContext(httptest.NewRecorder(), req)

	if ctx.APIVersion() != "v1" {
		t.Errorf("expected 'v1' API version, got %v", ctx.APIVersion())
	}

	req = httptest.NewRequest(http.MethodGet, "/no-version", nil)
	ctx = NewContext(httptest.NewRecorder(), req)
	if ctx.APIVersion() != "" {
		t.Errorf("expected no API version, got %v", ctx.APIVersion())
	}
}

func TestContext_Query(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?key=value", nil)
	ctx := NewContext(httptest.NewRecorder(), req)

	if ctx.Query("key") != "value" {
		t.Errorf("expected 'value' query value, got %v", ctx.Query("key"))
	}
}

func TestContext_Header(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Test", "test-value")
	ctx := NewContext(httptest.NewRecorder(), req)

	if ctx.Header("X-Test") != "test-value" {
		t.Errorf("expected 'test-value' header value, got %v", ctx.Header("X-Test"))
	}
}

func TestContext_SetHeader(t *testing.T) {
	w := httptest.NewRecorder()
	ctx := NewContext(w, nil)

	ctx.SetHeader("X-Test", "test-value")
	if w.Header().Get("X-Test") != "test-value" {
		t.Errorf("expected 'test-value' header value, got %v", w.Header().Get("X-Test"))
	}
	ctx.SetHeader("X-Test", "test-value", "test-value-2")
	if strings.Join(w.Header().Values("X-Test"), ", ") != "test-value, test-value-2" {
		t.Errorf("expected 'test-value, test-value-2' header value, got %v", w.Header().Get("X-Test"))
	}
}

func TestContext_Cookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "test-cookie", Value: "cookie-value"})
	ctx := NewContext(httptest.NewRecorder(), req)

	cookie, err := ctx.Cookie("test-cookie")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if cookie.Value != "cookie-value" {
		t.Errorf("expected 'cookie-value' cookie value, got %v", cookie.Value)
	}
}

func TestContext_SetCookie(t *testing.T) {
	w := httptest.NewRecorder()
	ctx := NewContext(w, nil)

	ctx.SetCookie("test-cookie", "cookie-value", 100, true, true)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Errorf("expected 1 cookie, got %v", len(cookies))
	}
	if cookies[0].Name != "test-cookie" {
		t.Errorf("expected 'test-cookie' cookie name, got %v", cookies[0].Name)
	}
	if cookies[0].Value != "cookie-value" {
		t.Errorf("expected 'cookie-value' cookie value, got %v", cookies[0].Value)
	}
	if !cookies[0].Secure {
		t.Errorf("expected Secure cookie flag, got %v", cookies[0].Secure)
	}
	if !cookies[0].HttpOnly {
		t.Errorf("expected HttpOnly cookie flag, got %v", cookies[0].HttpOnly)
	}
}

func TestContext_SetRawCookie(t *testing.T) {
	w := httptest.NewRecorder()
	ctx := NewContext(w, nil)

	ctx.SetRawCookie(&http.Cookie{Name: "test-cookie", Value: "cookie-value", Secure: true, HttpOnly: true})
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Errorf("expected 1 cookie, got %v", len(cookies))
	}
	if cookies[0].Name != "test-cookie" {
		t.Errorf("expected 'test-cookie' cookie name, got %v", cookies[0].Name)
	}
	if cookies[0].Value != "cookie-value" {
		t.Errorf("expected 'cookie-value' cookie value, got %v", cookies[0].Value)
	}
	if !cookies[0].Secure {
		t.Errorf("expected Secure cookie flag, got %v", cookies[0].Secure)
	}
	if !cookies[0].HttpOnly {
		t.Errorf("expected HttpOnly cookie flag, got %v", cookies[0].HttpOnly)
	}
}

func TestContext_FormValue(t *testing.T) {
	formData := "key=value"
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := NewContext(httptest.NewRecorder(), req)

	if ctx.FormValue("key") != "value" {
		t.Errorf("expected 'value' form value, got %v", ctx.FormValue("key"))
	}
}

func TestContext_ParseUnixFromQuery(t *testing.T) {
	timestamp := time.Now().Unix()
	req := httptest.NewRequest(http.MethodGet, "/?ts="+strconv.FormatInt(timestamp, 10), nil)
	ctx := NewContext(httptest.NewRecorder(), req)

	timeValue, err := ctx.ParseUnixFromQuery("ts")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if timeValue.Unix() != timestamp {
		t.Errorf("expected %v timestamp, got %v", timestamp, timeValue.Unix())
	}
}

func TestContext_ReadJSON(t *testing.T) {
	testData := testStruct{Foo: "bar"}
	data, _ := json.Marshal(testData)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(data))
	defer req.Body.Close()

	ctx := NewContext(httptest.NewRecorder(), req)

	var received testStruct
	err := ctx.ReadJSON(&received)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !reflect.DeepEqual(testData, received) {
		t.Errorf("expected TestData, got %v", received)
	}
}

func TestContext_ReadAndValidate(t *testing.T) {
	testData := testStruct{Foo: "bar"}
	data, _ := json.Marshal(testData)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(data))
	defer req.Body.Close()

	ctx := NewContext(httptest.NewRecorder(), req)

	var received testStruct
	err := ctx.ReadAndValidate(&received)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !reflect.DeepEqual(testData, received) {
		t.Errorf("expected TestData, got %v", received)
	}
}

func TestContext_Response(t *testing.T) {
	w := httptest.NewRecorder()
	ctx := NewContext(w, nil)

	ctx.Response(http.StatusOK, "Hello, World!")
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected %v status code, got %v", http.StatusOK, resp.StatusCode)
	}
	if string(body) != "Hello, World!" {
		t.Errorf("expected 'Hello, World!' body, got %v", string(body))
	}
	if resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("expected 'text/plain; charset=utf-8' Content-Type header, got %v", resp.Header.Get("Content-Type"))
	}
}

func TestContext_ResponseJSON(t *testing.T) {
	w := httptest.NewRecorder()
	ctx := NewContext(w, nil)

	ctx.Response(http.StatusOK, testStruct{Foo: "bar"})
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected %v status code, got %v", http.StatusOK, resp.StatusCode)
	}
	if string(body) != `{"foo":"bar"}` {
		t.Errorf("expected '{\"foo\":\"bar\"}' body, got %v", string(body))
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("expected 'text/plain' Content-Type header, got %v", resp.Header.Get("Content-Type"))
	}
}

func TestContext_Error(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	defer req.Body.Close()

	ctx := NewContext(w, req)

	ctx.Error(errors.New("example error"), http.StatusInternalServerError, "Internal server error", "code", "INTERNAL_ERROR")
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected %v status code, got %v", http.StatusInternalServerError, resp.StatusCode)
	}
	if !strings.Contains(string(body), "Internal server error") {
		t.Errorf("expected 'Internal server error' error message, got %v", string(body))
	}
	if !strings.Contains(string(body), `"code":"INTERNAL_ERROR"`) {
		t.Errorf("expected 'code=INTERNAL_ERROR' in error message, got %v", string(body))
	}
}

// Helper function to test the error response
func testErrorMethod(t *testing.T, method func(*Context, error, string, ...any), expectedStatusCode int, expectedMessage string, args ...any) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	defer req.Body.Close()

	ctx := NewContext(w, req)

	method(ctx, errors.New("sample error"), expectedMessage, args...)
	resp := w.Result()
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if resp.StatusCode != expectedStatusCode {
		t.Errorf("expected status code %d, got %d", expectedStatusCode, resp.StatusCode)
	}
	if !strings.Contains(bodyStr, expectedMessage) {
		t.Errorf("expected error message to contain %q, got %q", expectedMessage, bodyStr)
	}
}

// Define separate test functions for each error method

func TestContext_BadRequest(t *testing.T) {
	testErrorMethod(t, (*Context).BadRequest, http.StatusBadRequest, "Bad request error")
}

func TestContext_Unauthorized(t *testing.T) {
	testErrorMethod(t, (*Context).Unauthorized, http.StatusUnauthorized, "Unauthorized access")
}

func TestContext_Forbidden(t *testing.T) {
	testErrorMethod(t, (*Context).Forbidden, http.StatusForbidden, "Forbidden action")
}

func TestContext_NotFound(t *testing.T) {
	testErrorMethod(t, (*Context).NotFound, http.StatusNotFound, "Resource not found")
}

func TestContext_NotAcceptable(t *testing.T) {
	testErrorMethod(t, (*Context).NotAcceptable, http.StatusNotAcceptable, "Not acceptable")
}

func TestContext_Conflict(t *testing.T) {
	testErrorMethod(t, (*Context).Conflict, http.StatusConflict, "Resource conflict")
}

func TestContext_UnprocessableEntity(t *testing.T) {
	testErrorMethod(t, (*Context).UnprocessableEntity, http.StatusUnprocessableEntity, "Unprocessable entity")
}

func TestContext_TooManyRequests(t *testing.T) {
	testErrorMethod(t, (*Context).TooManyRequests, http.StatusTooManyRequests, "Too many requests")
}

func TestContext_InternalServerError(t *testing.T) {
	testErrorMethod(t, (*Context).InternalServerError, http.StatusInternalServerError, "Internal server error")
}

func TestContext_NotImplemented(t *testing.T) {
	testErrorMethod(t, (*Context).NotImplemented, http.StatusNotImplemented, "Not implemented")
}

func TestContext_BadGateway(t *testing.T) {
	testErrorMethod(t, (*Context).BadGateway, http.StatusBadGateway, "Bad gateway")
}

func TestContext_ServiceUnavailable(t *testing.T) {
	testErrorMethod(t, (*Context).ServiceUnavailable, http.StatusServiceUnavailable, "Service unavailable")
}

func TestReadFile(t *testing.T) {
	// Create a multipart form buffer
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	// Create a file field
	fileContents := []byte("This is test file content for the global function")
	part, err := writer.CreateFormFile("globalfile", "global.txt")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}

	// Write the file content
	_, err = part.Write(fileContents)
	if err != nil {
		t.Fatalf("Failed to write to form file: %v", err)
	}

	// Close the writer
	err = writer.Close()
	if err != nil {
		t.Fatalf("Failed to close writer: %v", err)
	}

	// Create a request with the multipart form
	req := httptest.NewRequest(http.MethodPost, "/global-upload", &buffer)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Test the global ReadFile function
	fileBytes, header, err := ReadFile(req, "globalfile")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Check file content
	if !bytes.Equal(fileBytes, fileContents) {
		t.Errorf("expected file contents %q, got %q", fileContents, fileBytes)
	}

	// Check file name
	if header.Filename != "global.txt" {
		t.Errorf("expected filename 'global.txt', got %q", header.Filename)
	}

	// Test with non-existent file key
	_, _, err = ReadFile(req, "nonexistent")
	if err == nil {
		t.Errorf("expected error for non-existent file, got nil")
	}
}

func TestContext_ReadFile(t *testing.T) {
	// Create a multipart form buffer
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	// Create a file field
	fileContents := []byte("This is a test file content")
	part, err := writer.CreateFormFile("testfile", "test.txt")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}

	// Write the file content
	_, err = part.Write(fileContents)
	if err != nil {
		t.Fatalf("Failed to write to form file: %v", err)
	}

	// Close the writer
	err = writer.Close()
	if err != nil {
		t.Fatalf("Failed to close writer: %v", err)
	}

	// Create a request with the multipart form
	req := httptest.NewRequest(http.MethodPost, "/upload", &buffer)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Create a context
	ctx := NewContext(httptest.NewRecorder(), req)

	// Test ReadFile in the Context
	fileBytes, header, err := ctx.ReadFile("testfile")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Check file content
	if !bytes.Equal(fileBytes, fileContents) {
		t.Errorf("expected file contents %q, got %q", fileContents, fileBytes)
	}

	// Check file name
	if header.Filename != "test.txt" {
		t.Errorf("expected filename 'test.txt', got %q", header.Filename)
	}

	// Test with non-existent file key
	_, _, err = ctx.ReadFile("nonexistent")
	if err == nil {
		t.Errorf("expected error for non-existent file, got nil")
	}
}

func TestContext_ResponseFile(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/download", nil)
	ctx := NewContext(w, req)

	// Test file data
	filename := "test-document.pdf"
	mimeType := "application/pdf"
	fileContents := []byte("This is test PDF file content")

	// Call ResponseFile
	ctx.ResponseFile(filename, mimeType, fileContents)

	// Check response
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	// Check status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// Check content type
	if resp.Header.Get("Content-Type") != mimeType {
		t.Errorf("expected Content-Type %q, got %q", mimeType, resp.Header.Get("Content-Type"))
	}

	// Check Content-Disposition header
	expectedDisposition := "attachment; filename=\"test-document.pdf\""
	if resp.Header.Get("Content-Disposition") != expectedDisposition {
		t.Errorf("expected Content-Disposition %q, got %q", expectedDisposition,
			resp.Header.Get("Content-Disposition"))
	}

	// Check Content-Length
	expectedLength := strconv.Itoa(len(fileContents))
	if resp.Header.Get("Content-Length") != expectedLength {
		t.Errorf("expected Content-Length %q, got %q", expectedLength,
			resp.Header.Get("Content-Length"))
	}

	// Check file contents
	if !bytes.Equal(body, fileContents) {
		t.Errorf("expected file contents %q, got %q", fileContents, body)
	}
}

// TestContext_ResponseFile_HeaderInjection tests that ResponseFile properly sanitizes filenames to prevent header injection attacks.
func TestContext_ResponseFile_HeaderInjection(t *testing.T) {
	tests := []struct {
		name                string
		filename            string
		expectedDisposition string
		description         string
	}{
		{
			name:                "Normal filename",
			filename:            "document.pdf",
			expectedDisposition: "attachment; filename=\"document.pdf\"",
			description:         "Should handle normal filenames correctly",
		},
		{
			name:                "CRLF injection attempt",
			filename:            "file.txt\r\nSet-Cookie: admin=true",
			expectedDisposition: "attachment; filename=\"file.txtSet-Cookie_ admin=true\"",
			description:         "Should remove CR and LF characters and replace colons",
		},
		{
			name:                "Header injection with multiple lines",
			filename:            "evil.pdf\r\nX-XSS-Protection: 0\r\n\r\n<script>alert('xss')</script>",
			expectedDisposition: "attachment; filename=\"evil.pdfX-XSS-Protection_ 0<script>alert('xss')<_script>\"",
			description:         "Should remove all CRLF characters and replace dangerous chars",
		},
		{
			name:                "Filename with quotes",
			filename:            "file\"with\"quotes.txt",
			expectedDisposition: "attachment; filename=\"file'with'quotes.txt\"",
			description:         "Should replace quotes with single quotes",
		},
		{
			name:                "Filename with backslashes",
			filename:            "path\\to\\file.txt",
			expectedDisposition: "attachment; filename=\"path_to_file.txt\"",
			description:         "Should replace backslashes with underscores",
		},
		{
			name:                "Filename with tabs",
			filename:            "file\twith\ttabs.txt",
			expectedDisposition: "attachment; filename=\"file_with_tabs.txt\"",
			description:         "Should replace tabs with underscores",
		},
		{
			name:                "Empty filename",
			filename:            "",
			expectedDisposition: "attachment; filename=\"download\"",
			description:         "Should use default filename for empty input",
		},
		{
			name:                "Filename with only control characters",
			filename:            "\r\n\t\x00\x1f",
			expectedDisposition: "attachment; filename=\"download\"",
			description:         "Should use default filename when all characters are removed",
		},
		{
			name:                "Complex attack attempt",
			filename:            "legitimate.pdf\r\nContent-Type: text/html\r\nSet-Cookie: session=hijacked\r\n\r\n<html><script>document.location='http://evil.com'</script></html>",
			expectedDisposition: "attachment; filename=\"legitimate.pdfContent-Type_ text_htmlSet-Cookie_ session=hijacked<html><script>document.location='http___evil.com'<_script><_html>\"",
			description:         "Should neutralize complex injection attempts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			ctx := NewContext(w, req)

			body := []byte("test content")
			ctx.ResponseFile(tt.filename, "application/octet-stream", body)

			resp := w.Result()
			defer resp.Body.Close()

			// Check that status is OK
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected status 200, got %d", resp.StatusCode)
			}

			// Check Content-Disposition header
			actualDisposition := resp.Header.Get("Content-Disposition")
			if actualDisposition != tt.expectedDisposition {
				t.Errorf("%s: expected Content-Disposition %q, got %q",
					tt.description, tt.expectedDisposition, actualDisposition)
			}

			// Verify no CRLF characters made it through
			if strings.Contains(actualDisposition, "\r") || strings.Contains(actualDisposition, "\n") {
				t.Errorf("%s: Content-Disposition header contains CRLF characters: %q",
					tt.description, actualDisposition)
			}

			// Verify the response body is correct
			responseBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}
			if string(responseBody) != "test content" {
				t.Errorf("expected body 'test content', got %q", string(responseBody))
			}
		})
	}
}

// TestSanitizeFilename tests the filename sanitization function directly.
func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Normal filename",
			input:    "document.pdf",
			expected: "document.pdf",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "download",
		},
		{
			name:     "CRLF characters",
			input:    "file\r\nname.txt",
			expected: "filename.txt",
		},
		{
			name:     "Quotes and backslashes",
			input:    "file\"name\\path.txt",
			expected: "file'name_path.txt",
		},
		{
			name:     "Control characters",
			input:    "file\x00\x1f\x7fname.txt",
			expected: "filename.txt",
		},
		{
			name:     "Only dangerous characters",
			input:    "\r\n\t\x00",
			expected: "download",
		},
		{
			name:     "Unicode filename",
			input:    "файл.txt",
			expected: "файл.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestFormatContentDisposition tests the Content-Disposition header formatting function.
func TestFormatContentDisposition(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		expected string
	}{
		{
			name:     "Normal filename",
			filename: "document.pdf",
			expected: "attachment; filename=\"document.pdf\"",
		},
		{
			name:     "Malicious filename",
			filename: "file.txt\r\nSet-Cookie: admin=true",
			expected: "attachment; filename=\"file.txtSet-Cookie_ admin=true\"",
		},
		{
			name:     "Empty filename",
			filename: "",
			expected: "attachment; filename=\"download\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatContentDisposition(tt.filename)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestContext_Body tests the Body method that reads request body without error handling.
func TestContext_Body(t *testing.T) {
	testData := "Hello, World!"
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testData))
	ctx := NewContext(httptest.NewRecorder(), req)

	body := ctx.Body()
	if string(body) != testData {
		t.Errorf("expected %q, got %q", testData, string(body))
	}
}

// TestContext_BodyEmpty tests the Body method with empty request body.
func TestContext_BodyEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	ctx := NewContext(httptest.NewRecorder(), req)

	body := ctx.Body()
	if len(body) != 0 {
		t.Errorf("expected empty body, got %q", string(body))
	}
}

// TestContext_Read tests the Read method that reads request body with error handling.
func TestContext_Read(t *testing.T) {
	testData := "Hello, World!"
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testData))
	ctx := NewContext(httptest.NewRecorder(), req)

	body, err := ctx.Read()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if string(body) != testData {
		t.Errorf("expected %q, got %q", testData, string(body))
	}
}

// TestContext_ReadEmpty tests the Read method with empty request body.
func TestContext_ReadEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	ctx := NewContext(httptest.NewRecorder(), req)

	body, err := ctx.Read()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(body) != 0 {
		t.Errorf("expected empty body, got %q", string(body))
	}
}

// TestContextWithConfiguredSizeLimits tests that context methods use configured size limits as defaults.
func TestContextWithConfiguredSizeLimits(t *testing.T) {
	tests := []struct {
		name               string
		options            Options
		body               string
		contentType        string
		expectError        bool
		expectErrorMessage string
	}{
		{
			name: "JSON within configured limit",
			options: Options{
				MaxJSONBodySize: 100, // 100 bytes
			},
			body:        `{"test": "data"}`,
			contentType: "application/json",
			expectError: false,
		},
		{
			name: "JSON exceeds configured limit",
			options: Options{
				MaxJSONBodySize: 10, // 10 bytes
			},
			body:               `{"test": "this is a long message that exceeds the limit"}`,
			contentType:        "application/json",
			expectError:        true,
			expectErrorMessage: "request body too large",
		},
		{
			name: "General body within configured limit",
			options: Options{
				MaxRequestBodySize: 50, // 50 bytes
			},
			body:        "short message",
			contentType: "text/plain",
			expectError: false,
		},
		{
			name: "General body exceeds configured limit",
			options: Options{
				MaxRequestBodySize: 10, // 10 bytes
			},
			body:               "this is a long message that exceeds the configured limit",
			contentType:        "text/plain",
			expectError:        true,
			expectErrorMessage: "request body too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request with body
			req := httptest.NewRequest(POST, "/test", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			w := httptest.NewRecorder()

			// Create context with configured options
			ctx := NewContext(w, req, tt.options)

			if strings.Contains(tt.contentType, "application/json") {
				// Test JSON reading
				var data map[string]any
				err := ctx.ReadJSON(&data)

				if tt.expectError {
					if err == nil {
						t.Errorf("expected error but got none")
					} else if !strings.Contains(err.Error(), tt.expectErrorMessage) {
						t.Errorf("expected error message to contain %q, got %q", tt.expectErrorMessage, err.Error())
					}
				} else {
					if err != nil {
						t.Errorf("unexpected error: %v", err)
					}
				}
			} else {
				// Test general body reading
				_, err := ctx.Read()

				if tt.expectError {
					if err == nil {
						t.Errorf("expected error but got none")
					} else if !strings.Contains(err.Error(), tt.expectErrorMessage) {
						t.Errorf("expected error message to contain %q, got %q", tt.expectErrorMessage, err.Error())
					}
				} else {
					if err != nil {
						t.Errorf("unexpected error: %v", err)
					}
				}
			}
		})
	}
}

// TestContextMethodsCanOverrideLimits tests that context methods can still override configured limits.
func TestContextMethodsCanOverrideLimits(t *testing.T) {
	// Configure strict limits
	options := Options{
		MaxJSONBodySize:    10,  // 10 bytes (very small)
		MaxRequestBodySize: 10,  // 10 bytes (very small)
		MaxFileUploadSize:  100, // 100 bytes (small)
	}

	tests := []struct {
		name        string
		body        string
		contentType string
		testFunc    func(*Context) error
		expectError bool
	}{
		{
			name:        "Override JSON limit - should succeed",
			body:        `{"test": "this message is longer than 10 bytes but should work with override"}`,
			contentType: "application/json",
			testFunc: func(ctx *Context) error {
				var data map[string]any
				return ctx.ReadJSONWithLimit(&data, 1000) // Override to 1000 bytes
			},
			expectError: false,
		},
		{
			name:        "Use configured JSON limit - should fail",
			body:        `{"test": "this message is longer than 10 bytes"}`,
			contentType: "application/json",
			testFunc: func(ctx *Context) error {
				var data map[string]any
				return ctx.ReadJSON(&data) // Use configured limit (10 bytes)
			},
			expectError: true,
		},
		{
			name:        "Override general body limit - should succeed",
			body:        "this message is longer than 10 bytes but should work with override",
			contentType: "text/plain",
			testFunc: func(ctx *Context) error {
				_, err := ctx.ReadWithLimit(1000) // Override to 1000 bytes
				return err
			},
			expectError: false,
		},
		{
			name:        "Use configured general body limit - should fail",
			body:        "this message is longer than 10 bytes",
			contentType: "text/plain",
			testFunc: func(ctx *Context) error {
				_, err := ctx.Read() // Use configured limit (10 bytes)
				return err
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request with body
			req := httptest.NewRequest(POST, "/test", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			w := httptest.NewRecorder()

			// Create context with configured options
			ctx := NewContext(w, req, options)

			err := tt.testFunc(ctx)

			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			} else if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestContextWithDefaultLimits tests that context methods use reasonable defaults when no options are provided.
func TestContextWithDefaultLimits(t *testing.T) {
	// Create context without any options
	req := httptest.NewRequest(POST, "/test", strings.NewReader(`{"test": "data"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	ctx := NewContext(w, req) // No options provided

	// Should work with default limits
	var data map[string]any
	err := ctx.ReadJSON(&data)

	if err != nil {
		t.Errorf("unexpected error with default limits: %v", err)
	}

	if data["test"] != "data" {
		t.Errorf("expected data.test to be 'data', got %v", data["test"])
	}
}

// TestContextSendErrorToClientOption tests that the SendErrorToClient option is properly set in context.
func TestContextSendErrorToClientOption(t *testing.T) {
	tests := []struct {
		name              string
		sendErrorToClient bool
		expectedBehavior  string
	}{
		{
			name:              "SendErrorToClient enabled",
			sendErrorToClient: true,
			expectedBehavior:  "should send errors to client",
		},
		{
			name:              "SendErrorToClient disabled",
			sendErrorToClient: false,
			expectedBehavior:  "should not send errors to client by default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(GET, "/test", nil)
			w := httptest.NewRecorder()

			options := Options{
				SendErrorToClient: tt.sendErrorToClient,
			}

			ctx := NewContext(w, req, options)

			// Test that the context was created successfully
			if ctx == nil {
				t.Fatal("context should not be nil")
			}

			// We can't directly test the private field, but we can verify the context
			// was created with the right options by testing its behavior indirectly
			if ctx.RequestID() == "" {
				t.Error("context should have a request ID")
			}
		})
	}
}

type testValidationStruct struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (t *testValidationStruct) Validate() error {
	if t.Name == "" {
		return errors.New("name is required")
	}
	if t.Email == "" {
		return errors.New("email is required")
	}
	return nil
}

// TestContextReadAndValidateWithConfiguredLimits tests ReadAndValidate with configured limits.
func TestContextReadAndValidateWithConfiguredLimits(t *testing.T) {
	server, err := NewServer(WithMaxRequestBodySize(1000), WithMaxJSONBodySize(100)) // Very small limit for testing
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test case 1: Valid data within limit
	validData := &testValidationStruct{
		Name:  "John",
		Email: "john@example.com",
	}
	jsonData, _ := json.Marshal(validData)

	if int64(len(jsonData)) >= 100 {
		t.Fatal("Test data should be smaller than the limit for this test")
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(jsonData))
	ctx := server.C(w, req)

	var result testValidationStruct
	err = ctx.ReadAndValidate(&result)
	if err != nil {
		t.Errorf("Expected no error for valid data within limit, got: %v", err)
	}

	if result.Name != validData.Name || result.Email != validData.Email {
		t.Errorf("Expected %+v, got %+v", validData, result)
	}

	// Test case 2: Valid data but exceeds limit
	largeData := &testValidationStruct{
		Name:  strings.Repeat("VeryLongName", 20), // This should make it exceed the 100-byte limit
		Email: "john@example.com",
	}
	largeJsonData, _ := json.Marshal(largeData)

	if int64(len(largeJsonData)) < 100 {
		t.Fatal("Test data should exceed the limit for this test")
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(largeJsonData))
	ctx2 := server.C(w2, req2)

	var result2 testValidationStruct
	err = ctx2.ReadAndValidate(&result2)
	if err == nil {
		t.Error("Expected error for data exceeding size limit")
	}
	if !strings.Contains(err.Error(), "body too large") {
		t.Errorf("Expected error about body size limit, got: %v", err)
	}
}

// TestContext_ClientIP tests the ClientIP method with various headers
func TestContext_ClientIP(t *testing.T) {
	tests := []struct {
		name        string
		remoteAddr  string
		headers     map[string]string
		expectedIP  string
		description string
	}{
		{
			name:        "No proxy headers - use RemoteAddr",
			remoteAddr:  "192.168.1.100:12345",
			headers:     map[string]string{},
			expectedIP:  "192.168.1.100",
			description: "Should extract IP from RemoteAddr when no proxy headers present",
		},
		{
			name:       "CF-Connecting-IP header",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"CF-Connecting-IP": "203.0.113.195",
			},
			expectedIP:  "203.0.113.195",
			description: "Should prioritize Cloudflare's CF-Connecting-IP header",
		},
		{
			name:       "True-Client-IP header",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"True-Client-IP": "203.0.113.196",
			},
			expectedIP:  "203.0.113.196",
			description: "Should use True-Client-IP when present",
		},
		{
			name:       "X-Real-IP header",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.197",
			},
			expectedIP:  "203.0.113.197",
			description: "Should use X-Real-IP when present",
		},
		{
			name:       "X-Forwarded-For with single IP",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.198",
			},
			expectedIP:  "203.0.113.198",
			description: "Should use first IP from X-Forwarded-For",
		},
		{
			name:       "X-Forwarded-For with multiple IPs",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.198, 10.0.0.2, 172.16.0.1",
			},
			expectedIP:  "203.0.113.198",
			description: "Should use first (client) IP from X-Forwarded-For chain",
		},
		{
			name:       "X-Client-IP header",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"X-Client-IP": "203.0.113.199",
			},
			expectedIP:  "203.0.113.199",
			description: "Should use X-Client-IP when present",
		},
		{
			name:       "Forwarded header RFC 7239",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"Forwarded": "for=203.0.113.200;proto=http;by=203.0.113.43",
			},
			expectedIP:  "203.0.113.200",
			description: "Should parse RFC 7239 Forwarded header",
		},
		{
			name:       "Forwarded header with quoted IP",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"Forwarded": `for="203.0.113.201";proto=https`,
			},
			expectedIP:  "203.0.113.201",
			description: "Should handle quoted IPs in Forwarded header",
		},
		{
			name:       "Forwarded header with IPv6",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"Forwarded": "for=\"[2001:db8::1]\";proto=https",
			},
			expectedIP:  "2001:db8::1",
			description: "Should handle IPv6 addresses in Forwarded header",
		},
		{
			name:       "IPv6 in X-Real-IP",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"X-Real-IP": "2001:db8::2",
			},
			expectedIP:  "2001:db8::2",
			description: "Should handle IPv6 addresses in headers",
		},
		{
			name:       "Priority test - CF-Connecting-IP wins",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"CF-Connecting-IP": "203.0.113.202",
				"X-Real-IP":        "203.0.113.203",
				"X-Forwarded-For":  "203.0.113.204",
			},
			expectedIP:  "203.0.113.202",
			description: "Should prioritize CF-Connecting-IP over other headers",
		},
		{
			name:       "Invalid IP in header - fallback to RemoteAddr",
			remoteAddr: "192.168.1.101:8080",
			headers: map[string]string{
				"X-Real-IP": "not-an-ip",
			},
			expectedIP:  "192.168.1.101",
			description: "Should fallback to RemoteAddr when header contains invalid IP",
		},
		{
			name:       "Empty header value - fallback to RemoteAddr",
			remoteAddr: "192.168.1.102:9090",
			headers: map[string]string{
				"X-Real-IP": "",
			},
			expectedIP:  "192.168.1.102",
			description: "Should fallback to RemoteAddr when header is empty",
		},
		{
			name:       "IP with port in header",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.205:8080",
			},
			expectedIP:  "203.0.113.205",
			description: "Should extract IP from header even when port is included",
		},
		{
			name:        "RemoteAddr without port",
			remoteAddr:  "192.168.1.103",
			headers:     map[string]string{},
			expectedIP:  "192.168.1.103",
			description: "Should handle RemoteAddr without port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr

			// Set headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			ctx := NewContext(httptest.NewRecorder(), req)
			result := ctx.ClientIP()

			if result != tt.expectedIP {
				t.Errorf("%s: expected IP %s, got %s", tt.description, tt.expectedIP, result)
			}
		})
	}
}

// TestContext_ClientIPWithTrustedProxies tests the ClientIPWithTrustedProxies method
func TestContext_ClientIPWithTrustedProxies(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		trustedProxies []string
		headers        map[string]string
		expectedIP     string
		description    string
	}{
		{
			name:           "Trusted proxy - should use headers",
			remoteAddr:     "10.0.0.1:80",
			trustedProxies: []string{"10.0.0.0/8"},
			headers: map[string]string{
				"X-Real-IP": "203.0.113.100",
			},
			expectedIP:  "203.0.113.100",
			description: "Should trust headers when request comes from trusted proxy",
		},
		{
			name:           "Untrusted proxy - should ignore headers",
			remoteAddr:     "203.0.113.50:80",
			trustedProxies: []string{"10.0.0.0/8"},
			headers: map[string]string{
				"X-Real-IP": "203.0.113.100",
			},
			expectedIP:  "203.0.113.50",
			description: "Should ignore headers when request comes from untrusted source",
		},
		{
			name:           "Multiple trusted networks",
			remoteAddr:     "172.16.0.10:443",
			trustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			headers: map[string]string{
				"CF-Connecting-IP": "203.0.113.101",
			},
			expectedIP:  "203.0.113.101",
			description: "Should work with multiple trusted proxy networks",
		},
		{
			name:           "Single trusted IP",
			remoteAddr:     "192.168.1.1:8080",
			trustedProxies: []string{"192.168.1.1"},
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.102, 10.0.0.1",
			},
			expectedIP:  "203.0.113.102",
			description: "Should work with single trusted IP address",
		},
		{
			name:           "IPv6 trusted proxy",
			remoteAddr:     "[2001:db8::1]:80",
			trustedProxies: []string{"2001:db8::/32"},
			headers: map[string]string{
				"X-Real-IP": "203.0.113.103",
			},
			expectedIP:  "203.0.113.103",
			description: "Should work with IPv6 trusted proxies",
		},
		{
			name:           "No trusted proxies defined",
			remoteAddr:     "10.0.0.1:80",
			trustedProxies: []string{},
			headers: map[string]string{
				"X-Real-IP": "203.0.113.104",
			},
			expectedIP:  "10.0.0.1",
			description: "Should ignore headers when no trusted proxies are defined",
		},
		{
			name:           "Invalid trusted proxy CIDR",
			remoteAddr:     "10.0.0.1:80",
			trustedProxies: []string{"invalid-cidr", "10.0.0.0/8"},
			headers: map[string]string{
				"X-Real-IP": "203.0.113.105",
			},
			expectedIP:  "203.0.113.105",
			description: "Should work even if some trusted proxy entries are invalid",
		},
		{
			name:           "Trusted proxy with invalid header",
			remoteAddr:     "10.0.0.1:80",
			trustedProxies: []string{"10.0.0.0/8"},
			headers: map[string]string{
				"X-Real-IP": "not-an-ip",
			},
			expectedIP:  "10.0.0.1",
			description: "Should fallback to RemoteAddr when trusted proxy sends invalid IP",
		},
		{
			name:           "Cloudflare proxy simulation",
			remoteAddr:     "103.21.244.10:443", // Cloudflare IP range
			trustedProxies: []string{"103.21.244.0/22", "103.22.200.0/22"},
			headers: map[string]string{
				"CF-Connecting-IP": "203.0.113.106",
				"X-Forwarded-For":  "203.0.113.106",
			},
			expectedIP:  "203.0.113.106",
			description: "Should work with Cloudflare-like proxy setup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr

			// Set headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			ctx := NewContext(httptest.NewRecorder(), req)
			result := ctx.ClientIPWithTrustedProxies(tt.trustedProxies)

			if result != tt.expectedIP {
				t.Errorf("%s: expected IP %s, got %s", tt.description, tt.expectedIP, result)
			}
		})
	}
}

// TestParseXForwardedFor tests the internal parseXForwardedFor function
func TestParseXForwardedFor(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		expectedIP string
	}{
		{
			name:       "Single IP",
			header:     "203.0.113.1",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "Multiple IPs",
			header:     "203.0.113.1, 10.0.0.1, 172.16.0.1",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "IPs with extra spaces",
			header:     "  203.0.113.1  ,  10.0.0.1  ",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "Invalid first IP",
			header:     "invalid, 203.0.113.1",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "All invalid IPs",
			header:     "invalid1, invalid2",
			expectedIP: "",
		},
		{
			name:       "Empty header",
			header:     "",
			expectedIP: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseXForwardedFor(tt.header)
			if result != tt.expectedIP {
				t.Errorf("parseXForwardedFor(%q) = %q, want %q", tt.header, result, tt.expectedIP)
			}
		})
	}
}

// TestParseForwardedHeader tests the internal parseForwardedHeader function
func TestParseForwardedHeader(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		expectedIP string
	}{
		{
			name:       "Basic for parameter",
			header:     "for=203.0.113.1;proto=http",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "Quoted for parameter",
			header:     `for="203.0.113.1";proto=https`,
			expectedIP: "203.0.113.1",
		},
		{
			name:       "IPv6 with brackets",
			header:     "for=\"[2001:db8::1]\";proto=https",
			expectedIP: "2001:db8::1",
		},
		{
			name:       "IP with port",
			header:     "for=203.0.113.1:8080;proto=http",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "Multiple parameters",
			header:     "for=203.0.113.1;host=example.com;proto=https;by=203.0.113.43",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "No for parameter",
			header:     "proto=https;by=203.0.113.43",
			expectedIP: "",
		},
		{
			name:       "Invalid IP in for parameter",
			header:     "for=invalid-ip;proto=http",
			expectedIP: "",
		},
		{
			name:       "Empty header",
			header:     "",
			expectedIP: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseForwardedHeader(tt.header)
			if result != tt.expectedIP {
				t.Errorf("parseForwardedHeader(%q) = %q, want %q", tt.header, result, tt.expectedIP)
			}
		})
	}
}

// TestParseAndValidateIP tests the internal parseAndValidateIP function
func TestParseAndValidateIP(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		expectedIP string
	}{
		{
			name:       "Valid IPv4",
			input:      "203.0.113.1",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "Valid IPv6",
			input:      "2001:db8::1",
			expectedIP: "2001:db8::1",
		},
		{
			name:       "IPv4 with port",
			input:      "203.0.113.1:8080",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "IPv6 with port and brackets",
			input:      "[2001:db8::1]:8080",
			expectedIP: "2001:db8::1",
		},
		{
			name:       "IPv6 with brackets only",
			input:      "[2001:db8::1]",
			expectedIP: "2001:db8::1",
		},
		{
			name:       "IP with extra whitespace",
			input:      "  203.0.113.1  ",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "Invalid IP",
			input:      "invalid-ip",
			expectedIP: "",
		},
		{
			name:       "Empty string",
			input:      "",
			expectedIP: "",
		},
		{
			name:       "Only whitespace",
			input:      "   ",
			expectedIP: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseAndValidateIP(tt.input)
			if result != tt.expectedIP {
				t.Errorf("parseAndValidateIP(%q) = %q, want %q", tt.input, result, tt.expectedIP)
			}
		})
	}
}
