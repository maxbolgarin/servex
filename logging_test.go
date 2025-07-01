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

	req, err := http.NewRequest("POST", "http://example.com/api/users", nil)
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
		"method":      "POST",
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
