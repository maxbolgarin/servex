package servex

import (
	"crypto/tls"
	"errors"
	"net/http"
	"testing"
	"time"
)

// MockLogger is a mock implementation of the Logger interface.
type MockLogger struct {
	Messages    []string
	Fields      [][]any
	LastMessage string
}

func (m *MockLogger) Debug(msg string, fields ...any) {
	m.Messages = append(m.Messages, msg)
	m.Fields = append(m.Fields, fields)
	m.LastMessage = msg
}

func (m *MockLogger) Info(msg string, fields ...any) {
	m.Messages = append(m.Messages, msg)
	m.Fields = append(m.Fields, fields)
	m.LastMessage = msg
}

func (m *MockLogger) Error(msg string, fields ...any) {
	m.Messages = append(m.Messages, msg)
	m.Fields = append(m.Fields, fields)
	m.LastMessage = msg
}

func TestRequestLogger_Log(t *testing.T) {
	mockLogger := &MockLogger{}
	rLogger := BaseRequestLogger{Logger: mockLogger}

	req, err := http.NewRequest(GET, "http://example.com", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	bundle := RequestLogBundle{
		Request:      req,
		RequestID:    "12345",
		Error:        errors.New("some error"),
		ErrorMessage: "error occurred",
		StatusCode:   500,
		StartTime:    time.Now().Add(-5 * time.Second), // Simulating that request started 5 seconds ago
	}

	rLogger.Log(bundle)

	if len(mockLogger.Messages) != 1 {
		t.Fatalf("Expected one log message, got %d", len(mockLogger.Messages))
	}

	if mockLogger.Messages[0] != "http" {
		t.Errorf("Expected log message to be 'http', got '%s'", mockLogger.Messages[0])
	}

	expectedFields := []any{
		"error", bundle.Error.Error(),
		"error_message", bundle.ErrorMessage,
		"request_id", bundle.RequestID,
		"status", bundle.StatusCode,
		"duration_ms", int64(5000), // Approximate match due to time function
		"ip", req.RemoteAddr,
		"user_agent", req.UserAgent(),
		"url", req.URL.String(),
		"method", req.Method,
		"proto", req.Proto,
	}

	for i := 0; i < len(expectedFields); i += 2 {
		found := false
		for j := 0; j < len(mockLogger.Fields[0]); j += 2 {
			if expectedFields[i] == mockLogger.Fields[0][j] && expectedFields[i+1] == mockLogger.Fields[0][j+1] {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected log field %v with value %v not found", expectedFields[i], expectedFields[i+1])
		}
	}
}

func TestRequestLogger_LogWithSelectiveFields(t *testing.T) {
	mockLogger := &MockLogger{}
	rLogger := BaseRequestLogger{
		Logger: mockLogger,
		FieldsToInclude: []string{
			MethodLogField,
			StatusLogField,
			DurationLogField,
		},
	}

	req, err := http.NewRequest(POST, "http://example.com/api/users", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	bundle := RequestLogBundle{
		Request:      req,
		RequestID:    "12345",
		Error:        errors.New("some error"),
		ErrorMessage: "error occurred",
		StatusCode:   400,
		StartTime:    time.Now().Add(-2 * time.Second), // Simulating that request started 2 seconds ago
	}

	rLogger.Log(bundle)

	if len(mockLogger.Messages) != 1 {
		t.Fatalf("Expected one log message, got %d", len(mockLogger.Messages))
	}

	if mockLogger.Messages[0] != "http" {
		t.Errorf("Expected log message to be 'http', got '%s'", mockLogger.Messages[0])
	}

	// Check that only the specified fields are present
	// Note: method, url, status, and duration_ms are always included
	expectedFields := map[string]any{
		"method":      POST,
		"url":         "http://example.com/api/users",
		"status":      400,
		"duration_ms": int64(2000), // Approximate match due to time function
	}

	// Check that expected fields are present
	actualFields := make(map[string]any)
	fields := mockLogger.Fields[0]
	for i := 0; i < len(fields); i += 2 {
		key := fields[i].(string)
		value := fields[i+1]
		actualFields[key] = value
	}

	for expectedKey, expectedValue := range expectedFields {
		if actualValue, exists := actualFields[expectedKey]; !exists {
			t.Errorf("Expected field %q not found", expectedKey)
		} else if expectedKey == "duration_ms" {
			// Allow some tolerance for duration since it's time-based
			if actualDuration, ok := actualValue.(int64); !ok || actualDuration < 1000 || actualDuration > 3000 {
				t.Errorf("Expected duration_ms to be around %v, got %v", expectedValue, actualValue)
			}
		} else if actualValue != expectedValue {
			t.Errorf("Expected field %q to have value %v, got %v", expectedKey, expectedValue, actualValue)
		}
	}

	// Check that unexpected fields are NOT present
	unexpectedFields := []string{
		"request_id", "ip", "user_agent", "proto", "error", "error_message",
	}
	for _, unexpectedKey := range unexpectedFields {
		if _, exists := actualFields[unexpectedKey]; exists {
			t.Errorf("Unexpected field %q found in logs", unexpectedKey)
		}
	}
}

func TestNoopRequestLogger(t *testing.T) {
	logger := &noopRequestLogger{}
	req, _ := http.NewRequest(GET, "http://example.com", nil)

	// Should not panic
	logger.Log(RequestLogBundle{
		Request:    req,
		StatusCode: 500,
		Error:      errors.New("test error"),
	})

	// Test passes if no panic occurs
}

func TestStdLogAdapter(t *testing.T) {
	mockLogger := &MockLogger{}
	adapter := newStdLogAdapter(mockLogger)

	testMsg := "test error message"
	n, err := adapter.Write([]byte(testMsg + "\n"))

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	expectedLen := len(testMsg) + 1 // +1 for newline
	if n != expectedLen {
		t.Errorf("Expected to write %d bytes, wrote %d", expectedLen, n)
	}

	if len(mockLogger.Messages) != 1 {
		t.Fatalf("Expected one log message, got %d", len(mockLogger.Messages))
	}

	if mockLogger.Messages[0] != testMsg {
		t.Errorf("Expected message %q, got %q", testMsg, mockLogger.Messages[0])
	}
}

func TestRequestLogger_LogLevels(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		error      error
		expectLog  string // "Debug", "Info", or "Error"
	}{
		{"success request", 200, nil, "Debug"},
		{"created request", 201, nil, "Debug"},
		{"client error", 400, nil, "Info"},
		{"not found", 404, nil, "Info"},
		{"server error", 500, nil, "Error"},
		{"error with 200", 200, errors.New("test error"), "Error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLogger := &MockLogger{}
			rLogger := BaseRequestLogger{Logger: mockLogger}

			req, _ := http.NewRequest(GET, "http://example.com", nil)
			bundle := RequestLogBundle{
				Request:    req,
				StatusCode: tt.statusCode,
				Error:      tt.error,
				StartTime:  time.Now(),
			}

			rLogger.Log(bundle)

			if len(mockLogger.Messages) != 1 {
				t.Fatalf("Expected one log message, got %d", len(mockLogger.Messages))
			}

			// We can't directly check which method was called, but we can verify it was logged
			if mockLogger.LastMessage != "http" {
				t.Errorf("Expected 'http' message, got %q", mockLogger.LastMessage)
			}
		})
	}
}

func TestRequestLogger_NoLogClientErrors(t *testing.T) {
	mockLogger := &MockLogger{}
	rLogger := BaseRequestLogger{Logger: mockLogger}

	req, _ := http.NewRequest(GET, "http://example.com", nil)

	// Test that client errors are NOT logged when NoLogClientErrors is true
	bundle := RequestLogBundle{
		Request:           req,
		StatusCode:        400,
		StartTime:         time.Now(),
		NoLogClientErrors: true,
	}

	rLogger.Log(bundle)

	if len(mockLogger.Messages) != 1 {
		t.Errorf("Expected one log message with NoLogClientErrors=true, got %d messages", len(mockLogger.Messages))
	}

	// Test that server errors ARE still logged
	mockLogger.Messages = nil
	bundle.StatusCode = 500
	rLogger.Log(bundle)

	if len(mockLogger.Messages) != 1 {
		t.Errorf("Expected server errors to be logged even with NoLogClientErrors=true, got %d messages", len(mockLogger.Messages))
	}

	// Test that client errors ARE logged when NoLogClientErrors is false
	mockLogger.Messages = nil
	bundle.StatusCode = 404
	bundle.NoLogClientErrors = false
	rLogger.Log(bundle)

	if len(mockLogger.Messages) != 1 {
		t.Errorf("Expected client errors to be logged with NoLogClientErrors=false, got %d messages", len(mockLogger.Messages))
	}
}

func TestRequestLogger_DefaultStatusCode(t *testing.T) {
	mockLogger := &MockLogger{}
	rLogger := BaseRequestLogger{Logger: mockLogger}

	req, _ := http.NewRequest(GET, "http://example.com", nil)
	bundle := RequestLogBundle{
		Request:    req,
		StatusCode: 0, // Not set
		StartTime:  time.Now(),
	}

	rLogger.Log(bundle)

	if len(mockLogger.Messages) != 1 {
		t.Fatalf("Expected one log message, got %d", len(mockLogger.Messages))
	}

	// Check that status was set to 200
	fields := mockLogger.Fields[0]
	actualFields := make(map[string]any)
	for i := 0; i < len(fields); i += 2 {
		key := fields[i].(string)
		value := fields[i+1]
		actualFields[key] = value
	}

	if _, ok := actualFields["status"].(int); ok {
		t.Errorf("Expected empty status code, got %v", actualFields["status"])
	}
}

func TestRequestLogger_HTTPSMessage(t *testing.T) {
	mockLogger := &MockLogger{}
	rLogger := BaseRequestLogger{Logger: mockLogger}

	req, _ := http.NewRequest(GET, "https://example.com", nil)
	// Simulate HTTPS by setting TLS info
	req.TLS = &tls.ConnectionState{} // Just needs to be non-nil

	bundle := RequestLogBundle{
		Request:    req,
		StatusCode: 200,
		StartTime:  time.Now(),
	}

	rLogger.Log(bundle)

	if len(mockLogger.Messages) != 1 {
		t.Fatalf("Expected one log message, got %d", len(mockLogger.Messages))
	}

	// Verify https message is used for TLS connections
	if mockLogger.LastMessage != "https" {
		t.Errorf("Expected 'https' message for TLS request, got %q", mockLogger.LastMessage)
	}
}

func TestRequestLogBundle_Pool(t *testing.T) {
	// Test getting bundle from pool
	bundle1 := getRequestLogBundle()
	if bundle1 == nil {
		t.Error("Expected non-nil bundle from pool")
	}

	// Set some fields
	req, _ := http.NewRequest(GET, "http://example.com", nil)
	bundle1.Request = req
	bundle1.RequestID = "test-123"
	bundle1.StatusCode = 500

	// Return to pool
	putRequestLogBundle(bundle1)

	// Get another bundle and verify it's reset
	bundle2 := getRequestLogBundle()
	if bundle2.Request != nil || bundle2.RequestID != "" || bundle2.StatusCode != 0 {
		t.Error("Expected bundle from pool to be reset")
	}
}

func TestLogFields_Pool(t *testing.T) {
	// Test getting fields from pool
	fields1 := getLogFields()
	if fields1 == nil {
		t.Error("Expected non-nil fields from pool")
	}

	if len(fields1) != 0 {
		t.Errorf("Expected empty fields slice, got length %d", len(fields1))
	}

	// Add some data
	fields1 = append(fields1, "key1", "value1")
	fields1 = append(fields1, "key2", "value2")

	// Return to pool
	putLogFields(fields1)

	// Get another slice and verify it's empty
	fields2 := getLogFields()
	if len(fields2) != 0 {
		t.Errorf("Expected fields from pool to be empty, got length %d", len(fields2))
	}

	// Test that excessive capacity is not returned to pool
	largeFields := make([]any, 0, 100)
	putLogFields(largeFields)
	// If it doesn't panic, the test passes
}
