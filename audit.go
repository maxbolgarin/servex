package servex

import (
	"net/http"
	"time"
)

// AuditEventType represents the type of security event being logged
type AuditEventType string

const (
	// Authentication Events
	AuditEventAuthLoginSuccess AuditEventType = "auth.login.success"
	AuditEventAuthLoginFailure AuditEventType = "auth.login.failure"
	AuditEventAuthLogout       AuditEventType = "auth.logout"
	AuditEventAuthTokenRefresh AuditEventType = "auth.token.refresh"
	AuditEventAuthTokenInvalid AuditEventType = "auth.token.invalid"
	AuditEventAuthUnauthorized AuditEventType = "auth.unauthorized"
	AuditEventAuthForbidden    AuditEventType = "auth.forbidden"

	// Rate Limiting Events
	AuditEventRateLimitExceeded AuditEventType = "ratelimit.exceeded"
	AuditEventRateLimitBlocked  AuditEventType = "ratelimit.blocked"

	// Filtering Events
	AuditEventFilterIPBlocked     AuditEventType = "filter.ip.blocked"
	AuditEventFilterUABlocked     AuditEventType = "filter.useragent.blocked"
	AuditEventFilterHeaderBlocked AuditEventType = "filter.header.blocked"
	AuditEventFilterQueryBlocked  AuditEventType = "filter.query.blocked"

	// CSRF Events
	AuditEventCSRFTokenMissing   AuditEventType = "csrf.token.missing"
	AuditEventCSRFTokenInvalid   AuditEventType = "csrf.token.invalid"
	AuditEventCSRFAttackDetected AuditEventType = "csrf.attack.detected"

	// Request Security Events
	AuditEventSuspiciousPath   AuditEventType = "request.suspicious.path"
	AuditEventRequestTooLarge  AuditEventType = "request.too.large"
	AuditEventMaliciousPayload AuditEventType = "request.malicious.payload"

	// Admin Events
	AuditEventAdminAccess       AuditEventType = "admin.access"
	AuditEventConfigChange      AuditEventType = "config.change"
	AuditEventFilterRuleAdded   AuditEventType = "filter.rule.added"
	AuditEventFilterRuleRemoved AuditEventType = "filter.rule.removed"

	// System Events
	AuditEventSecurityViolation AuditEventType = "security.violation"
	AuditEventAnomalousActivity AuditEventType = "security.anomaly"
)

// AuditSeverity represents the severity level of an audit event
type AuditSeverity string

const (
	AuditSeverityLow      AuditSeverity = "low"
	AuditSeverityMedium   AuditSeverity = "medium"
	AuditSeverityHigh     AuditSeverity = "high"
	AuditSeverityCritical AuditSeverity = "critical"
)

// AuditEvent represents a security event that should be logged for audit purposes
type AuditEvent struct {
	// Core event information
	EventType AuditEventType `json:"event_type"`
	Severity  AuditSeverity  `json:"severity"`
	Timestamp time.Time      `json:"timestamp"`
	EventID   string         `json:"event_id"`

	// Request context
	RequestID string `json:"request_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	ClientIP  string `json:"client_ip"`
	UserAgent string `json:"user_agent,omitempty"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Query     string `json:"query,omitempty"`
	Referer   string `json:"referer,omitempty"`

	// Security context
	BlockedRule  string            `json:"blocked_rule,omitempty"`
	RateLimitKey string            `json:"ratelimit_key,omitempty"`
	FilterType   string            `json:"filter_type,omitempty"`
	FilterValue  string            `json:"filter_value,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`

	// Event details
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
	Error   string         `json:"error,omitempty"`

	// Response information
	StatusCode   int   `json:"status_code,omitempty"`
	ResponseTime int64 `json:"response_time_ms,omitempty"`

	// Geographical information (if available)
	Country string `json:"country,omitempty"`
	Region  string `json:"region,omitempty"`
	City    string `json:"city,omitempty"`

	// Threat intelligence
	ThreatLevel  string `json:"threat_level,omitempty"`
	ThreatSource string `json:"threat_source,omitempty"`

	// Compliance tags
	ComplianceTags []string `json:"compliance_tags,omitempty"`
}

// AuditLogger interface for security audit logging
type AuditLogger interface {
	// LogSecurityEvent logs a security-related event
	LogSecurityEvent(event AuditEvent)

	// LogAuthenticationEvent logs authentication-related events
	LogAuthenticationEvent(eventType AuditEventType, r *http.Request, userID string, success bool, details map[string]any)

	// LogRateLimitEvent logs rate limiting events
	LogRateLimitEvent(r *http.Request, key string, details map[string]any)

	// LogFilterEvent logs request filtering events
	LogFilterEvent(eventType AuditEventType, r *http.Request, filterType, filterValue, rule string)

	// LogCSRFEvent logs CSRF protection events
	LogCSRFEvent(eventType AuditEventType, r *http.Request, details map[string]any)

	// LogSuspiciousActivity logs suspicious or anomalous activity
	LogSuspiciousActivity(r *http.Request, activityType string, details map[string]any)
}

// DefaultAuditLogger implements AuditLogger using the standard logger interface
type DefaultAuditLogger struct {
	Logger Logger

	// Configuration for audit logging
	IncludeHeaders    bool
	SensitiveHeaders  []string // Headers to exclude from logging for privacy
	MaxDetailSize     int      // Maximum size of detail fields
	EnableGeoLocation bool     // Enable geographical context (requires external service)
}

// NewDefaultAuditLogger creates a new default audit logger
func NewDefaultAuditLogger(logger Logger) *DefaultAuditLogger {
	return &DefaultAuditLogger{
		Logger:            logger,
		IncludeHeaders:    false, // Default to false for privacy
		SensitiveHeaders:  []string{"Authorization", "Cookie", "X-API-Key", "X-Auth-Token"},
		MaxDetailSize:     1024, // 1KB max for detail fields
		EnableGeoLocation: false,
	}
}

// LogSecurityEvent logs a structured security event
func (al *DefaultAuditLogger) LogSecurityEvent(event AuditEvent) {
	// Use log fields pool for efficient logging
	fields := getLogFields()
	defer putLogFields(fields)

	// Add structured fields for security events
	fields = append(fields,
		"audit_event_type", event.EventType,
		"audit_severity", event.Severity,
		"audit_timestamp", event.Timestamp.Format(time.RFC3339),
		"audit_event_id", event.EventID,
		"client_ip", event.ClientIP,
		"method", event.Method,
		"path", event.Path,
		"message", event.Message,
	)

	// Add optional fields
	if event.RequestID != "" {
		fields = append(fields, "request_id", event.RequestID)
	}
	if event.UserID != "" {
		fields = append(fields, "user_id", event.UserID)
	}
	if event.SessionID != "" {
		fields = append(fields, "session_id", event.SessionID)
	}
	if event.UserAgent != "" {
		fields = append(fields, "user_agent", event.UserAgent)
	}
	if event.Query != "" {
		fields = append(fields, "query", event.Query)
	}
	if event.StatusCode > 0 {
		fields = append(fields, "status_code", event.StatusCode)
	}
	if event.ResponseTime > 0 {
		fields = append(fields, "response_time_ms", event.ResponseTime)
	}
	if event.BlockedRule != "" {
		fields = append(fields, "blocked_rule", event.BlockedRule)
	}
	if event.FilterType != "" {
		fields = append(fields, "filter_type", event.FilterType)
	}
	if event.FilterValue != "" {
		fields = append(fields, "filter_value", event.FilterValue)
	}
	if event.Error != "" {
		fields = append(fields, "error", event.Error)
	}

	// Add compliance tags if present
	if len(event.ComplianceTags) > 0 {
		fields = append(fields, "compliance_tags", event.ComplianceTags)
	}

	// Log at appropriate level based on severity
	switch event.Severity {
	case AuditSeverityCritical, AuditSeverityHigh:
		al.Logger.Error("SECURITY_AUDIT", fields...)
	case AuditSeverityMedium:
		al.Logger.Info("SECURITY_AUDIT", fields...)
	default:
		al.Logger.Debug("SECURITY_AUDIT", fields...)
	}
}

// LogAuthenticationEvent logs authentication-related events
func (al *DefaultAuditLogger) LogAuthenticationEvent(eventType AuditEventType, r *http.Request, userID string, success bool, details map[string]any) {
	severity := AuditSeverityMedium
	if !success {
		severity = AuditSeverityHigh
	}

	event := AuditEvent{
		EventType: eventType,
		Severity:  severity,
		Timestamp: time.Now(),
		EventID:   generateEventID(),
		RequestID: getOrSetRequestID(r),
		UserID:    userID,
		ClientIP:  extractClientIP(r),
		UserAgent: r.UserAgent(),
		Method:    r.Method,
		Path:      r.URL.Path,
		Query:     r.URL.RawQuery,
		Referer:   r.Header.Get("Referer"),
		Message:   al.formatAuthMessage(eventType, success),
		Details:   details,
	}

	// Add sensitive headers if configured
	if al.IncludeHeaders {
		event.Headers = al.sanitizeHeaders(r.Header)
	}

	al.LogSecurityEvent(event)
}

// LogRateLimitEvent logs rate limiting events
func (al *DefaultAuditLogger) LogRateLimitEvent(r *http.Request, key string, details map[string]any) {
	event := AuditEvent{
		EventType:    AuditEventRateLimitExceeded,
		Severity:     AuditSeverityMedium,
		Timestamp:    time.Now(),
		EventID:      generateEventID(),
		RequestID:    getOrSetRequestID(r),
		ClientIP:     extractClientIP(r),
		UserAgent:    r.UserAgent(),
		Method:       r.Method,
		Path:         r.URL.Path,
		Query:        r.URL.RawQuery,
		RateLimitKey: key,
		Message:      "Rate limit exceeded",
		Details:      details,
		StatusCode:   http.StatusTooManyRequests,
	}

	al.LogSecurityEvent(event)
}

// LogFilterEvent logs request filtering events
func (al *DefaultAuditLogger) LogFilterEvent(eventType AuditEventType, r *http.Request, filterType, filterValue, rule string) {
	event := AuditEvent{
		EventType:   eventType,
		Severity:    AuditSeverityHigh,
		Timestamp:   time.Now(),
		EventID:     generateEventID(),
		RequestID:   getOrSetRequestID(r),
		ClientIP:    extractClientIP(r),
		UserAgent:   r.UserAgent(),
		Method:      r.Method,
		Path:        r.URL.Path,
		Query:       r.URL.RawQuery,
		Referer:     r.Header.Get("Referer"),
		BlockedRule: rule,
		FilterType:  filterType,
		FilterValue: filterValue,
		Message:     al.formatFilterMessage(eventType, filterType),
		StatusCode:  http.StatusForbidden,
	}

	al.LogSecurityEvent(event)
}

// LogCSRFEvent logs CSRF protection events
func (al *DefaultAuditLogger) LogCSRFEvent(eventType AuditEventType, r *http.Request, details map[string]any) {
	event := AuditEvent{
		EventType:  eventType,
		Severity:   AuditSeverityHigh,
		Timestamp:  time.Now(),
		EventID:    generateEventID(),
		RequestID:  getOrSetRequestID(r),
		ClientIP:   extractClientIP(r),
		UserAgent:  r.UserAgent(),
		Method:     r.Method,
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		Referer:    r.Header.Get("Referer"),
		Message:    al.formatCSRFMessage(eventType),
		Details:    details,
		StatusCode: http.StatusForbidden,
	}

	al.LogSecurityEvent(event)
}

// LogSuspiciousActivity logs suspicious or anomalous activity
func (al *DefaultAuditLogger) LogSuspiciousActivity(r *http.Request, activityType string, details map[string]any) {
	event := AuditEvent{
		EventType: AuditEventAnomalousActivity,
		Severity:  AuditSeverityHigh,
		Timestamp: time.Now(),
		EventID:   generateEventID(),
		RequestID: getOrSetRequestID(r),
		ClientIP:  extractClientIP(r),
		UserAgent: r.UserAgent(),
		Method:    r.Method,
		Path:      r.URL.Path,
		Query:     r.URL.RawQuery,
		Referer:   r.Header.Get("Referer"),
		Message:   "Suspicious activity detected: " + activityType,
		Details:   details,
	}

	al.LogSecurityEvent(event)
}

// Helper methods for formatting messages
func (al *DefaultAuditLogger) formatAuthMessage(eventType AuditEventType, success bool) string {
	switch eventType {
	case AuditEventAuthLoginSuccess:
		return "User login successful"
	case AuditEventAuthLoginFailure:
		return "User login failed"
	case AuditEventAuthLogout:
		return "User logout"
	case AuditEventAuthTokenRefresh:
		return "Authentication token refreshed"
	case AuditEventAuthTokenInvalid:
		return "Invalid authentication token"
	case AuditEventAuthUnauthorized:
		return "Unauthorized access attempt"
	case AuditEventAuthForbidden:
		return "Forbidden access attempt"
	default:
		return "Authentication event"
	}
}

func (al *DefaultAuditLogger) formatFilterMessage(eventType AuditEventType, filterType string) string {
	switch eventType {
	case AuditEventFilterIPBlocked:
		return "Request blocked by IP filter"
	case AuditEventFilterUABlocked:
		return "Request blocked by User-Agent filter"
	case AuditEventFilterHeaderBlocked:
		return "Request blocked by header filter"
	case AuditEventFilterQueryBlocked:
		return "Request blocked by query parameter filter"
	default:
		return "Request blocked by " + filterType + " filter"
	}
}

func (al *DefaultAuditLogger) formatCSRFMessage(eventType AuditEventType) string {
	switch eventType {
	case AuditEventCSRFTokenMissing:
		return "CSRF token missing"
	case AuditEventCSRFTokenInvalid:
		return "CSRF token invalid"
	case AuditEventCSRFAttackDetected:
		return "Potential CSRF attack detected"
	default:
		return "CSRF protection event"
	}
}

// sanitizeHeaders removes sensitive headers for logging
func (al *DefaultAuditLogger) sanitizeHeaders(headers http.Header) map[string]string {
	sanitized := make(map[string]string)

	for name, values := range headers {
		// Check if this is a sensitive header
		isSensitive := false
		for _, sensitive := range al.SensitiveHeaders {
			if name == sensitive {
				isSensitive = true
				break
			}
		}

		if !isSensitive && len(values) > 0 {
			// Truncate long header values
			value := values[0]
			if len(value) > al.MaxDetailSize {
				value = value[:al.MaxDetailSize] + "..."
			}
			sanitized[name] = value
		}
	}

	return sanitized
}

// generateEventID generates a unique event ID for audit logging
func generateEventID() string {
	return string(getRandomBytes(16))
}

// NoopAuditLogger is a no-op implementation of AuditLogger
type NoopAuditLogger struct{}

func (nal *NoopAuditLogger) LogSecurityEvent(event AuditEvent) {}
func (nal *NoopAuditLogger) LogAuthenticationEvent(eventType AuditEventType, r *http.Request, userID string, success bool, details map[string]any) {
}
func (nal *NoopAuditLogger) LogRateLimitEvent(r *http.Request, key string, details map[string]any) {}
func (nal *NoopAuditLogger) LogFilterEvent(eventType AuditEventType, r *http.Request, filterType, filterValue, rule string) {
}
func (nal *NoopAuditLogger) LogCSRFEvent(eventType AuditEventType, r *http.Request, details map[string]any) {
}
func (nal *NoopAuditLogger) LogSuspiciousActivity(r *http.Request, activityType string, details map[string]any) {
}
