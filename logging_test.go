package servex

import (
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

func TestLogFields(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	ctx := C(nil, req)
	fields := ctx.LogFields(UserAgentLogField, URLLogField, MethodLogField, ProtoLogField)

	expectedFields := []any{
		"user_agent", "",
		"url", "http://example.com",
		"method", "GET",
		"proto", "HTTP/1.1",
	}

	// Check if all expected fields are present in the result
	for i := 0; i < len(expectedFields); i += 2 {
		found := false
		for j := 0; j < len(fields); j += 2 {
			if expectedFields[i] == fields[j] && expectedFields[i+1] == fields[j+1] {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected field %v with value %v not found", expectedFields[i], expectedFields[i+1])
		}
	}

	fields = ctx.LogFields()

	expectedFields = []any{
		"request_id", fields[1], // This is rand request id so we cant prepare it
		"ip", fields[3], // This is rand ip so we cant prepare it
		"user_agent", "",
		"url", "http://example.com",
		"method", "GET",
		"proto", "HTTP/1.1",
	}

	// Check if all expected fields are present in the result
	for i := 0; i < len(expectedFields); i += 2 {
		found := false
		for j := 0; j < len(fields); j += 2 {
			if expectedFields[i] == fields[j] && expectedFields[i+1] == fields[j+1] {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected field %v with value %v not found", expectedFields[i], expectedFields[i+1])
		}
	}
}

func TestRequestLogger_Log(t *testing.T) {
	mockLogger := &MockLogger{}
	rLogger := BaseRequestLogger{Logger: mockLogger}

	req, err := http.NewRequest("GET", "http://example.com", nil)
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
		"error", bundle.Error,
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
