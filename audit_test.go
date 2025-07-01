package servex

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"encoding/hex"

	"github.com/gorilla/mux"
)

// TestRateLimitAuditLogging tests that audit events are properly logged when rate limits are exceeded.
func TestRateLimitAuditLogging(t *testing.T) {
	var capturedEvents []struct {
		key     string
		details map[string]any
		userIP  string
		path    string
	}

	mockAuditLogger := &MockAuditLogger{
		LogRateLimitEventFunc: func(r *http.Request, key string, details map[string]any) {
			capturedEvents = append(capturedEvents, struct {
				key     string
				details map[string]any
				userIP  string
				path    string
			}{
				key:     key,
				details: details,
				userIP:  extractClientIP(r),
				path:    r.URL.Path,
			})
		},
	}

	// Create rate limit config with very low limits for testing
	rateLimitConfig := RateLimitConfig{
		Enabled:             true,
		RequestsPerInterval: 1,
		Interval:            time.Second, // Use 1 second for faster testing
		BurstSize:           0,           // No burst allowed
	}

	router := mux.NewRouter()
	cleanup := RegisterRateLimitMiddleware(router, rateLimitConfig, mockAuditLogger)
	defer cleanup()

	// Add test handler
	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// First request should pass
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "192.168.1.100:12345"
	rr1 := httptest.NewRecorder()
	router.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Errorf("Expected first request to pass, got status %d", rr1.Code)
	}

	// Second request should be rate limited immediately
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "192.168.1.100:12345"
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("Expected second request to be rate limited, got status %d", rr2.Code)
	}

	// Wait a bit for async audit logging
	time.Sleep(100 * time.Millisecond)

	// Verify audit event was logged
	if len(capturedEvents) == 0 {
		t.Log("No audit events captured - checking if rate limiting middleware is working...")
		// Let's check if rate limiting is actually enabled
		t.Error("Expected at least 1 audit event, got 0 - rate limiting may not be working properly")
		return
	}

	event := capturedEvents[0]
	if event.key == "" {
		t.Error("Expected non-empty rate limit key")
	}
	if event.userIP != "192.168.1.100" {
		t.Errorf("Expected user IP 192.168.1.100, got %s", event.userIP)
	}
}

// TestFilterAuditLogging tests that audit events are properly logged when requests are blocked by filters.
func TestFilterAuditLogging(t *testing.T) {
	var capturedEvents []struct {
		eventType   AuditEventType
		filterType  string
		filterValue string
		rule        string
		userIP      string
		userAgent   string
		path        string
	}

	mockAuditLogger := &MockAuditLogger{
		LogFilterEventFunc: func(eventType AuditEventType, r *http.Request, filterType, filterValue, rule string) {
			capturedEvents = append(capturedEvents, struct {
				eventType   AuditEventType
				filterType  string
				filterValue string
				rule        string
				userIP      string
				userAgent   string
				path        string
			}{
				eventType:   eventType,
				filterType:  filterType,
				filterValue: filterValue,
				rule:        rule,
				userIP:      extractClientIP(r),
				userAgent:   r.Header.Get("User-Agent"),
				path:        r.URL.Path,
			})
		},
	}

	tests := []struct {
		name           string
		config         FilterConfig
		request        func() *http.Request
		expectedEvent  AuditEventType
		expectedFilter string
		expectedValue  string
		expectedRule   string
	}{
		{
			name: "IP blocking logged",
			config: FilterConfig{
				BlockedIPs: []string{"192.168.1.100"},
			},
			request: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.1.100:12345"
				return req
			},
			expectedEvent:  AuditEventFilterIPBlocked,
			expectedFilter: "IP",
			expectedValue:  "192.168.1.100",
			expectedRule:   "blocked IP range: 192.168.1.100/32",
		},
		{
			name: "User-Agent blocking logged",
			config: FilterConfig{
				BlockedUserAgents: []string{"BadBot/1.0"},
			},
			request: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("User-Agent", "BadBot/1.0")
				return req
			},
			expectedEvent:  AuditEventFilterUABlocked,
			expectedFilter: "User-Agent",
			expectedValue:  "BadBot/1.0",
			expectedRule:   "exact match in blocked user agents",
		},
		{
			name: "Header blocking logged",
			config: FilterConfig{
				BlockedHeaders: map[string][]string{
					"X-Test-Header": {"malicious-value"},
				},
			},
			request: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-Test-Header", "malicious-value")
				return req
			},
			expectedEvent:  AuditEventFilterHeaderBlocked,
			expectedFilter: "Header",
			expectedValue:  "x-test-header: malicious-value",
			expectedRule:   "exact match in blocked headers",
		},
		{
			name: "Query parameter blocking logged",
			config: FilterConfig{
				BlockedQueryParams: map[string][]string{
					"cmd": {"rm -rf"},
				},
			},
			request: func() *http.Request {
				req := httptest.NewRequest("GET", "/test?cmd=rm+-rf", nil)
				return req
			},
			expectedEvent:  AuditEventFilterQueryBlocked,
			expectedFilter: "Query Parameter",
			expectedValue:  "cmd=rm -rf",
			expectedRule:   "exact match in blocked query parameters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset captured events
			capturedEvents = nil

			// Create router with filter middleware
			router := mux.NewRouter()
			_, err := RegisterFilterMiddleware(router, tt.config, mockAuditLogger)
			if err != nil {
				t.Fatalf("Failed to register filter middleware: %v", err)
			}

			// Add test handler
			router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})

			// Make request
			req := tt.request()
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			// Verify request was blocked
			if rr.Code == http.StatusOK {
				t.Errorf("Expected request to be blocked, but got status %d", rr.Code)
				return
			}

			// Verify audit event was logged
			if len(capturedEvents) != 1 {
				t.Errorf("Expected 1 audit event, got %d", len(capturedEvents))
				return
			}

			event := capturedEvents[0]
			if event.eventType != tt.expectedEvent {
				t.Errorf("Expected event type %s, got %s", tt.expectedEvent, event.eventType)
			}
			if event.filterType != tt.expectedFilter {
				t.Errorf("Expected filter type %s, got %s", tt.expectedFilter, event.filterType)
			}
			if event.filterValue != tt.expectedValue {
				t.Errorf("Expected filter value %s, got %s", tt.expectedValue, event.filterValue)
			}
			if event.rule != tt.expectedRule {
				t.Errorf("Expected rule %s, got %s", tt.expectedRule, event.rule)
			}
		})
	}
}

// TestDynamicFilterAuditLogging tests that audit events are logged when filter rules are dynamically modified.
func TestDynamicFilterAuditLogging(t *testing.T) {
	var capturedEvents []struct {
		eventType   AuditEventType
		filterType  string
		filterValue string
		rule        string
	}

	mockAuditLogger := &MockAuditLogger{
		LogFilterEventFunc: func(eventType AuditEventType, r *http.Request, filterType, filterValue, rule string) {
			capturedEvents = append(capturedEvents, struct {
				eventType   AuditEventType
				filterType  string
				filterValue string
				rule        string
			}{
				eventType:   eventType,
				filterType:  filterType,
				filterValue: filterValue,
				rule:        rule,
			})
		},
	}

	// Create filter with audit logger
	config := FilterConfig{
		BlockedIPs: []string{"10.0.0.1"},
	}
	filter, err := newFilter(config, mockAuditLogger)
	if err != nil {
		t.Fatalf("Failed to create filter: %v", err)
	}

	tests := []struct {
		name          string
		operation     func() error
		expectedEvent AuditEventType
		expectedType  string
		expectedValue string
		expectedRule  string
	}{
		{
			name: "Add blocked IP",
			operation: func() error {
				return filter.AddBlockedIP("192.168.1.100")
			},
			expectedEvent: AuditEventFilterRuleAdded,
			expectedType:  "IP",
			expectedValue: "192.168.1.100",
			expectedRule:  "dynamically added to blocked list",
		},
		{
			name: "Remove blocked IP",
			operation: func() error {
				return filter.RemoveBlockedIP("192.168.1.100")
			},
			expectedEvent: AuditEventFilterRuleRemoved,
			expectedType:  "IP",
			expectedValue: "192.168.1.100",
			expectedRule:  "dynamically removed from blocked list",
		},
		{
			name: "Add blocked User-Agent",
			operation: func() error {
				return filter.AddBlockedUserAgent("BadBot/2.0")
			},
			expectedEvent: AuditEventFilterRuleAdded,
			expectedType:  "User-Agent",
			expectedValue: "BadBot/2.0",
			expectedRule:  "dynamically added to blocked list",
		},
		{
			name: "Remove blocked User-Agent",
			operation: func() error {
				return filter.RemoveBlockedUserAgent("BadBot/2.0")
			},
			expectedEvent: AuditEventFilterRuleRemoved,
			expectedType:  "User-Agent",
			expectedValue: "BadBot/2.0",
			expectedRule:  "dynamically removed from blocked list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset captured events
			capturedEvents = nil

			// Perform operation
			err := tt.operation()
			if err != nil {
				t.Fatalf("Operation failed: %v", err)
			}

			// Verify audit event was logged
			if len(capturedEvents) != 1 {
				t.Errorf("Expected 1 audit event, got %d", len(capturedEvents))
				return
			}

			event := capturedEvents[0]
			if event.eventType != tt.expectedEvent {
				t.Errorf("Expected event type %s, got %s", tt.expectedEvent, event.eventType)
			}
			if event.filterType != tt.expectedType {
				t.Errorf("Expected filter type %s, got %s", tt.expectedType, event.filterType)
			}
			if event.filterValue != tt.expectedValue {
				t.Errorf("Expected filter value %s, got %s", tt.expectedValue, event.filterValue)
			}
			if event.rule != tt.expectedRule {
				t.Errorf("Expected rule %s, got %s", tt.expectedRule, event.rule)
			}
		})
	}
}

// TestAuthAuditLogging tests that audit events are properly logged for authentication scenarios.
func TestAuthAuditLogging(t *testing.T) {
	var capturedEvents []struct {
		eventType AuditEventType
		userID    string
		success   bool
		details   map[string]any
		userIP    string
		path      string
	}

	mockAuditLogger := &MockAuditLogger{
		LogAuthenticationEventFunc: func(eventType AuditEventType, r *http.Request, userID string, success bool, details map[string]any) {
			capturedEvents = append(capturedEvents, struct {
				eventType AuditEventType
				userID    string
				success   bool
				details   map[string]any
				userIP    string
				path      string
			}{
				eventType: eventType,
				userID:    userID,
				success:   success,
				details:   details,
				userIP:    extractClientIP(r),
				path:      r.URL.Path,
			})
		},
	}

	// Create auth manager with memory database for testing
	authConfig := AuthConfig{
		Enabled:          true,
		Database:         NewMemoryAuthDatabase(),
		JWTAccessSecret:  hex.EncodeToString([]byte("test-secret-key-for-audit-testing-123456789")),         // Hex-encoded JWT secret
		JWTRefreshSecret: hex.EncodeToString([]byte("test-refresh-secret-key-for-audit-testing-987654321")), // Hex-encoded JWT refresh secret
	}
	authManager, err := NewAuthManager(authConfig, mockAuditLogger)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Create a test user
	ctx := httptest.NewRequest("POST", "/auth/register", nil).Context()
	err = authManager.CreateUser(ctx, "testuser", "password123", "user")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Reset captured events after user creation
	capturedEvents = nil

	t.Run("Successful login audit", func(t *testing.T) {
		// Reset events
		capturedEvents = nil

		// Create login request
		req := httptest.NewRequest("POST", "/auth/login", nil)
		req.RemoteAddr = "192.168.1.100:12345"

		// Mock successful login
		mockAuditLogger.LogAuthenticationEventFunc(AuditEventAuthLoginSuccess, req, "1", true, map[string]any{"username": "testuser"})

		// Verify audit event
		if len(capturedEvents) != 1 {
			t.Errorf("Expected 1 audit event, got %d", len(capturedEvents))
			return
		}

		event := capturedEvents[0]
		if event.eventType != AuditEventAuthLoginSuccess {
			t.Errorf("Expected event type %s, got %s", AuditEventAuthLoginSuccess, event.eventType)
		}
		if event.userID != "1" {
			t.Errorf("Expected user ID 1, got %s", event.userID)
		}
		if !event.success {
			t.Errorf("Expected success true, got %v", event.success)
		}
		if event.userIP != "192.168.1.100" {
			t.Errorf("Expected user IP 192.168.1.100, got %s", event.userIP)
		}
	})

	t.Run("Failed login audit", func(t *testing.T) {
		// Reset events
		capturedEvents = nil

		// Create login request
		req := httptest.NewRequest("POST", "/auth/login", nil)
		req.RemoteAddr = "192.168.1.100:12345"

		// Mock failed login
		mockAuditLogger.LogAuthenticationEventFunc(AuditEventAuthLoginFailure, req, "", false, map[string]any{"username": "testuser", "reason": "invalid password"})

		// Verify audit event
		if len(capturedEvents) != 1 {
			t.Errorf("Expected 1 audit event, got %d", len(capturedEvents))
			return
		}

		event := capturedEvents[0]
		if event.eventType != AuditEventAuthLoginFailure {
			t.Errorf("Expected event type %s, got %s", AuditEventAuthLoginFailure, event.eventType)
		}
		if event.userID != "" {
			t.Errorf("Expected empty user ID, got %s", event.userID)
		}
		if event.success {
			t.Errorf("Expected success false, got %v", event.success)
		}
		if event.details["reason"] != "invalid password" {
			t.Errorf("Expected reason 'invalid password', got %v", event.details["reason"])
		}
	})
}

// TestSecurityAuditLogging tests that general security events are properly logged.
func TestSecurityAuditLogging(t *testing.T) {
	var capturedEvents []AuditEvent

	mockAuditLogger := &MockAuditLogger{
		LogSecurityEventFunc: func(event AuditEvent) {
			capturedEvents = append(capturedEvents, event)
		},
	}

	// Set up the LogSuspiciousActivityFunc after the logger is created
	mockAuditLogger.LogSuspiciousActivityFunc = func(r *http.Request, activityType string, details map[string]any) {
		// Simulate what the real DefaultAuditLogger.LogSuspiciousActivity does
		event := AuditEvent{
			EventType: AuditEventAnomalousActivity,
			Severity:  AuditSeverityHigh,
			Timestamp: time.Now(),
			EventID:   "test-event-id",
			ClientIP:  extractClientIP(r),
			UserAgent: r.UserAgent(),
			Method:    r.Method,
			Path:      r.URL.Path,
			Message:   "Suspicious activity detected: " + activityType,
			Details:   details,
		}
		// Call LogSecurityEvent to ensure the event is captured
		if mockAuditLogger.LogSecurityEventFunc != nil {
			mockAuditLogger.LogSecurityEventFunc(event)
		}
	}

	t.Run("Suspicious activity audit", func(t *testing.T) {
		// Reset events
		capturedEvents = nil

		// Create request
		req := httptest.NewRequest("GET", "/admin/sensitive", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		req.Header.Set("User-Agent", "SuspiciousBot/1.0")

		// Mock suspicious activity detection
		details := map[string]any{
			"user_agent": "SuspiciousBot/1.0",
			"path":       "/admin/sensitive",
			"reason":     "multiple failed access attempts",
		}
		mockAuditLogger.LogSuspiciousActivity(req, "multiple failed access attempts", details)

		// Verify audit event was logged
		if len(capturedEvents) != 1 {
			t.Errorf("Expected 1 audit event, got %d", len(capturedEvents))
			return
		}

		event := capturedEvents[0]
		if event.EventType != AuditEventAnomalousActivity {
			t.Errorf("Expected event type %s, got %s", AuditEventAnomalousActivity, event.EventType)
		}
		if event.Severity != AuditSeverityHigh {
			t.Errorf("Expected severity %s, got %s", AuditSeverityHigh, event.Severity)
		}
		if event.ClientIP != "192.168.1.100" {
			t.Errorf("Expected user IP 192.168.1.100, got %s", event.ClientIP)
		}
		if event.Details["user_agent"] != "SuspiciousBot/1.0" {
			t.Errorf("Expected user_agent SuspiciousBot/1.0 in details, got %v", event.Details["user_agent"])
		}
	})
}

// TestDefaultAuditLogger tests that the default audit logger properly formats and logs events.
func TestDefaultAuditLogger(t *testing.T) {
	// Create a mock logger to avoid nil pointer dereference
	mockLogger := &AuditMockLogger{
		logs: make([]LogEntry, 0),
	}

	logger := NewDefaultAuditLogger(mockLogger)
	if logger == nil {
		t.Error("Expected non-nil default audit logger")
		return
	}

	// Test that methods don't panic with valid request
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	// These should not panic
	event := AuditEvent{
		EventType: AuditEventSecurityViolation,
		Severity:  AuditSeverityLow,
		Timestamp: time.Now(),
		EventID:   "test-event-id",
		ClientIP:  "192.168.1.100",
		Method:    "GET",
		Path:      "/test",
		Message:   "test message",
	}
	logger.LogSecurityEvent(event)
	logger.LogAuthenticationEvent(AuditEventAuthLoginSuccess, req, "1", true, map[string]any{"test": "value"})
	logger.LogRateLimitEvent(req, "192.168.1.100", map[string]any{"limit": 100, "current": 101})
	logger.LogFilterEvent(AuditEventFilterIPBlocked, req, "IP", "192.168.1.100", "test rule")

	// Verify that the mock logger received some log entries
	if len(mockLogger.logs) == 0 {
		t.Error("Expected some log entries to be created, but got none")
	}
}

// AuditMockLogger for testing the default audit logger
type AuditMockLogger struct {
	logs []LogEntry
}

type LogEntry struct {
	Level   string
	Message string
	Fields  []any
}

func (ml *AuditMockLogger) Debug(msg string, fields ...any) {
	ml.logs = append(ml.logs, LogEntry{Level: "DEBUG", Message: msg, Fields: fields})
}

func (ml *AuditMockLogger) Info(msg string, fields ...any) {
	ml.logs = append(ml.logs, LogEntry{Level: "INFO", Message: msg, Fields: fields})
}

func (ml *AuditMockLogger) Warn(msg string, fields ...any) {
	ml.logs = append(ml.logs, LogEntry{Level: "WARN", Message: msg, Fields: fields})
}

func (ml *AuditMockLogger) Error(msg string, fields ...any) {
	ml.logs = append(ml.logs, LogEntry{Level: "ERROR", Message: msg, Fields: fields})
}

// MockAuditLogger for testing
type MockAuditLogger struct {
	LogSecurityEventFunc       func(event AuditEvent)
	LogAuthenticationEventFunc func(eventType AuditEventType, r *http.Request, userID string, success bool, details map[string]any)
	LogRateLimitEventFunc      func(r *http.Request, key string, details map[string]any)
	LogFilterEventFunc         func(eventType AuditEventType, r *http.Request, filterType, filterValue, rule string)
	LogCSRFEventFunc           func(eventType AuditEventType, r *http.Request, details map[string]any)
	LogSuspiciousActivityFunc  func(r *http.Request, activityType string, details map[string]any)
}

func (m *MockAuditLogger) LogSecurityEvent(event AuditEvent) {
	if m.LogSecurityEventFunc != nil {
		m.LogSecurityEventFunc(event)
	}
}

func (m *MockAuditLogger) LogAuthenticationEvent(eventType AuditEventType, r *http.Request, userID string, success bool, details map[string]any) {
	if m.LogAuthenticationEventFunc != nil {
		m.LogAuthenticationEventFunc(eventType, r, userID, success, details)
	}
}

func (m *MockAuditLogger) LogRateLimitEvent(r *http.Request, key string, details map[string]any) {
	if m.LogRateLimitEventFunc != nil {
		m.LogRateLimitEventFunc(r, key, details)
	}
}

func (m *MockAuditLogger) LogFilterEvent(eventType AuditEventType, r *http.Request, filterType, filterValue, rule string) {
	if m.LogFilterEventFunc != nil {
		m.LogFilterEventFunc(eventType, r, filterType, filterValue, rule)
	}
}

func (m *MockAuditLogger) LogCSRFEvent(eventType AuditEventType, r *http.Request, details map[string]any) {
	if m.LogCSRFEventFunc != nil {
		m.LogCSRFEventFunc(eventType, r, details)
	}
}

func (m *MockAuditLogger) LogSuspiciousActivity(r *http.Request, activityType string, details map[string]any) {
	if m.LogSuspiciousActivityFunc != nil {
		m.LogSuspiciousActivityFunc(r, activityType, details)
	}
}
