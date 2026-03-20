package servex

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/maxbolgarin/lang"
)

// SetHeader sets the value of the response header with the given name.
// If multiple values are provided, they are added to the header.
func (ctx *Context) SetHeader(key string, value ...string) {
	if len(value) == 0 {
		return
	}
	ctx.w.Header().Set(key, value[0])
	if len(value) > 1 {
		for _, v := range value[1:] {
			ctx.w.Header().Add(key, v)
		}
	}
}

// SetContentType sets the Content-Type header.
func (ctx *Context) SetContentType(mimeType string, charset ...string) {
	if ctx.isSetContentType {
		return
	}
	if len(charset) > 0 {
		ctx.w.Header().Set("Content-Type", mimeType+"; charset="+charset[0])
	} else {
		ctx.w.Header().Set("Content-Type", mimeType)
	}
	ctx.isSetContentType = true
}

// SetCookie sets the cookie with the given name, value, maxAge, secure and httpOnly.
// maxAge is the time in seconds until the cookie expires. If maxAge < 0, the cookie is deleted.
// secure specifies if the cookie should only be transmitted over HTTPS.
// httpOnly prevents the cookie from being accessed through JavaScript, enhancing security against XSS attacks.
func (ctx *Context) SetCookie(name, value string, maxAge int, secure, httpOnly bool) {
	http.SetCookie(ctx.w, &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   maxAge,
		Secure:   secure,
		HttpOnly: httpOnly,
	})
}

// SetRawCookie sets the cookie with the given [http.Cookie].
func (ctx *Context) SetRawCookie(c *http.Cookie) {
	http.SetCookie(ctx.w, c)
}

// SetDeleteCookie sets the cookie with the given name to be deleted.
func (ctx *Context) SetDeleteCookie(name string) {
	http.SetCookie(ctx.w, &http.Cookie{
		Name:   name,
		Value:  "",
		MaxAge: -1,
	})
}

// Response writes an HTTP response with the specified status code and optional body.
//
// This is the primary method for sending responses. It automatically handles
// content type detection, header setting, and proper HTTP response formatting.
//
// Supported body types:
//   - []byte: Written directly with detected content type
//   - string: Written as text/plain with UTF-8 charset
//   - any other type: Marshaled to JSON with application/json content type
//   - nil: Sends only status code with no body
//
// Features:
//   - Automatic Content-Type header setting
//   - Content-Length header calculation
//   - JSON marshaling with error handling
//   - Memory-efficient for large responses
//
// Parameters:
//   - code: HTTP status code (e.g., 200, 404, 500)
//   - bodyRaw: Optional response body (supports multiple types)
//
// Example:
//
//	// JSON response
//	ctx.Response(200, map[string]string{"message": "success"})
//
//	// String response
//	ctx.Response(200, "Hello, World!")
//
//	// Byte response (e.g., file content)
//	ctx.Response(200, fileBytes)
//
//	// Status-only response
//	ctx.Response(204)
//
// Note: Do not modify the ResponseWriter after calling this method.
// This method should typically be the last operation in your handler.
func (ctx *Context) Response(code int, bodyRaw ...any) {
	body := lang.First(bodyRaw)
	if body == nil {
		ctx.w.WriteHeader(code)
		return
	}

	var toWrite []byte
	switch b := body.(type) {
	case []byte:
		toWrite = b
		ctx.SetContentType(http.DetectContentType(toWrite))

	case string:
		toWrite = []byte(b)
		ctx.SetContentType(http.DetectContentType(toWrite))

	default:
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			// Log the marshalling error if possible (though Context doesn't have logger)
			// For now, write a plain 500 response directly, avoiding recursive ctx.Error call.
			// Note: This error hides the original intended response code.
			msg := `{"message":"Internal Server Error: Failed to marshal response JSON"}`
			http.Error(ctx.w, msg, http.StatusInternalServerError)
			// Set error context for logging middleware, even though we short-circuited
			ctx.setError(fmt.Errorf("marshal response: %w", err), http.StatusInternalServerError, msg)
			return
		}
		toWrite = jsonBytes

		ctx.SetContentType(MIMETypeJSON)
	}

	ctx.SetHeader("Content-Length", strconv.Itoa(len(toWrite)))
	ctx.w.WriteHeader(code)

	_, err := ctx.w.Write(toWrite)
	if err != nil {
		// Log the write error if possible (though Context doesn't have logger)
		// Cannot call ctx.Error as headers are already written.
		// We can potentially set the error in context for logging, though the request is mostly finished.
		ctx.setError(fmt.Errorf("write response: %w", err), http.StatusInternalServerError, "failed to write response body")
		// No return here, let the handler finish, but the response is likely broken.
	}
}

// ResponseFile writes the file to the [http.ResponseWriter].
// It sets the Content-Type header to the provided mime type.
// It sets the Content-Disposition header to "attachment; filename=" + filename (safely sanitized).
// It sets the Content-Length header to the length of the body.
// Parameters:
//   - filename: The name of the file
//   - mimeType: The mime type of the file
//   - body: The body of the file
//
// Example:
//
//	// Request: GET /api/users/123/avatar.png
//	// Response: 200 OK
//	// Content-Type: image/png
//	// Content-Disposition: attachment; filename="avatar.png"
//	// Content-Length: 12345
//	// Body: file content
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//		ctx.ResponseFile("avatar.png", "image/png", fileBytes)
//	}
func (ctx *Context) ResponseFile(filename string, mimeType string, body []byte) {
	ctx.SetContentType(mimeType)
	ctx.SetHeader("Content-Disposition", formatContentDisposition(filename))
	ctx.SetHeader("Content-Length", strconv.Itoa(len(body)))
	ctx.w.WriteHeader(http.StatusOK)
	_, err := ctx.w.Write(body)
	if err != nil {
		// Log the write error if possible (though Context doesn't have logger)
		// Cannot call ctx.Error as headers are already written.
		// We can potentially set the error in context for logging, though the request is mostly finished.
		ctx.setError(fmt.Errorf("write response: %w", err), http.StatusInternalServerError, "failed to write response body")
		// No return here, let the handler finish, but the response is likely broken.
	}
}

// JSON is an alias for [Context.Response] with 200 code.
func (ctx *Context) JSON(bodyRaw any) {
	ctx.Response(http.StatusOK, bodyRaw)
}

// BadRequest handles an error by returning an HTTP error response with status code 400.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) BadRequest(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusBadRequest, msg, fields...)
}

// Unauthorized handles an error by returning an HTTP error response with status code 401.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) Unauthorized(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusUnauthorized, msg, fields...)
}

// Forbidden handles an error by returning an HTTP error response with status code 403.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) Forbidden(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusForbidden, msg, fields...)
}

// NotFound handles an error by returning an HTTP error response with status code 404.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) NotFound(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusNotFound, msg, fields...)
}

// MethodNotAllowed handles an error by returning an HTTP error response with status code 405.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// It sends a 'Method not allowed' error response.
//
// It is a shortcut for [Context.Error].
func (ctx *Context) MethodNotAllowed(fields ...any) {
	ctx.Error(nil, http.StatusMethodNotAllowed, "Method not allowed", fields...)
}

// NotAcceptable handles an error by returning an HTTP error response with status code 406.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) NotAcceptable(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusNotAcceptable, msg, fields...)
}

// Conflict handles an error by returning an HTTP error response with status code 409.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) Conflict(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusConflict, msg, fields...)
}

// MethodConflict handles an error by returning an HTTP error response with status code 409.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) PreconditionFailed(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusPreconditionFailed, msg, fields...)
}

// RequestEntityTooLarge handles an error by returning an HTTP error response with status code 413.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) RequestEntityTooLarge(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusRequestEntityTooLarge, msg, fields...)
}

// UnsupportedMediaType handles an error by returning an HTTP error response with status code 415.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) UnsupportedMediaType(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusUnsupportedMediaType, msg, fields...)
}

// StatusUnprocessableEntity handles an error by returning an HTTP error response with status code 422.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) UnprocessableEntity(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusUnprocessableEntity, msg, fields...)
}

// TooManyRequests handles an error by returning an HTTP error response with status code 429.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) TooManyRequests(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusTooManyRequests, msg, fields...)
}

// InternalServerError handles an error by returning an HTTP error response with status code 500.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) InternalServerError(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusInternalServerError, msg, fields...)
}

// NotImplemented handles an error by returning an HTTP error response with status code 501.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) NotImplemented(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusNotImplemented, msg, fields...)
}

// BadGateway handles an error by returning an HTTP error response with status code 502.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) BadGateway(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusBadGateway, msg, fields...)
}

// ServiceUnavailable handles an error by returning an HTTP error response with status code 503.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - err: The error to log and send to the client
//   - msg: The error message to send to the client
//   - fields: Optional fields for the error message
//
// It is a shortcut for [Context.Error].
func (ctx *Context) ServiceUnavailable(err error, msg string, fields ...any) {
	ctx.Error(err, http.StatusServiceUnavailable, msg, fields...)
}

// Redirect performs an HTTP redirect to the specified URL with the given status code.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - url: The URL to redirect to
//   - code: HTTP status code (301, 302, 303, 307, 308)
//
// Example:
//
//	// Temporary redirect
//	ctx.Redirect("/login", 302)
//
//	// Permanent redirect
//	ctx.Redirect("https://example.com/new-path", 301)
func (ctx *Context) Redirect(url string, code int) {
	ctx.SetHeader("Location", url)
	ctx.w.WriteHeader(code)
}

// RedirectPermanent performs a permanent redirect (HTTP 301) to the specified URL.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - url: The URL to redirect to
//
// Example:
//
//	ctx.RedirectPermanent("https://example.com/new-path")
func (ctx *Context) RedirectPermanent(url string) {
	ctx.Redirect(url, http.StatusMovedPermanently)
}

// RedirectTemporary performs a temporary redirect (HTTP 302) to the specified URL.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - url: The URL to redirect to
//
// Example:
//
//	ctx.RedirectTemporary("/login")
func (ctx *Context) RedirectTemporary(url string) {
	ctx.Redirect(url, http.StatusFound)
}

// RedirectSeeOther performs a "See Other" redirect (HTTP 303) to the specified URL.
// This is typically used after a POST request to redirect to a GET endpoint.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - url: The URL to redirect to
//
// Example:
//
//	// After processing a form submission
//	ctx.RedirectSeeOther("/success")
func (ctx *Context) RedirectSeeOther(url string) {
	ctx.Redirect(url, http.StatusSeeOther)
}

// RedirectNotModified performs a "Not Modified" redirect (HTTP 304) to indicate
// that the resource has not been modified since the last request.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// This is typically used with conditional requests (If-Modified-Since, If-None-Match).
//
// Example:
//
//	if !isModified {
//		ctx.RedirectNotModified()
//		return
//	}
func (ctx *Context) RedirectNotModified() {
	ctx.w.WriteHeader(http.StatusNotModified)
}

// RedirectTemporaryPreserveMethod performs a temporary redirect (HTTP 307) to the specified URL.
// Unlike 302, this guarantees that the request method and body will be preserved.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - url: The URL to redirect to
//
// Example:
//
//	ctx.RedirectTemporaryPreserveMethod("/api/v2/users")
func (ctx *Context) RedirectTemporaryPreserveMethod(url string) {
	ctx.Redirect(url, http.StatusTemporaryRedirect)
}

// RedirectPermanentPreserveMethod performs a permanent redirect (HTTP 308) to the specified URL.
// Unlike 301, this guarantees that the request method and body will be preserved.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - url: The URL to redirect to
//
// Example:
//
//	ctx.RedirectPermanentPreserveMethod("https://example.com/api/v2/users")
func (ctx *Context) RedirectPermanentPreserveMethod(url string) {
	ctx.Redirect(url, http.StatusPermanentRedirect)
}

// RedirectToHTTPS redirects the current HTTP request to its HTTPS equivalent.
// This method preserves the host, path, and query parameters while changing the scheme to HTTPS.
// It uses a permanent redirect (HTTP 301) by default to encourage browsers and search engines
// to update their links to use HTTPS.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Parameters:
//   - permanent: If true, uses HTTP 301 (permanent redirect). If false, uses HTTP 302 (temporary redirect)
//
// Example:
//
//	// In a middleware or handler
//	if ctx.r.TLS == nil && ctx.r.Header.Get("X-Forwarded-Proto") != "https" {
//		ctx.RedirectToHTTPS(true) // Permanent redirect
//		return
//	}
//
//	// Temporary redirect (useful during testing)
//	ctx.RedirectToHTTPS(false)
func (ctx *Context) RedirectToHTTPS(permanent ...bool) {
	isPermanent := len(permanent) == 0 || permanent[0] // Default to permanent redirect

	// Build HTTPS URL from current request
	httpsURL := "https://" + ctx.r.Host + ctx.r.RequestURI

	// Choose redirect status code
	statusCode := http.StatusMovedPermanently // 301
	if !isPermanent {
		statusCode = http.StatusFound // 302
	}

	ctx.Redirect(httpsURL, statusCode)
}

// RedirectToHTTPSPermanent redirects the current HTTP request to its HTTPS equivalent
// using a permanent redirect (HTTP 301). This is a convenience method for the most
// common HTTPS redirect scenario.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Example:
//
//	// In a middleware
//	if ctx.r.TLS == nil {
//		ctx.RedirectToHTTPSPermanent()
//		return
//	}
func (ctx *Context) RedirectToHTTPSPermanent() {
	ctx.RedirectToHTTPS(true)
}

// RedirectToHTTPSTemporary redirects the current HTTP request to its HTTPS equivalent
// using a temporary redirect (HTTP 302). This is useful during development or testing
// when you don't want browsers to cache the redirect.
// You should not modify the [http.ResponseWriter] after calling this method.
// You will probably want to return from your handler after calling this method.
//
// Example:
//
//	// During development/testing
//	if ctx.r.TLS == nil {
//		ctx.RedirectToHTTPSTemporary()
//		return
//	}
func (ctx *Context) RedirectToHTTPSTemporary() {
	ctx.RedirectToHTTPS(false)
}

// Error handles errors by sending standardized HTTP error responses.
//
// This method provides consistent error handling across your application
// with proper logging integration and optional client error exposure.
// It formats error messages and manages error context for middleware.
//
// Features:
//   - Consistent error response format
//   - Integration with logging middleware
//   - Configurable error exposure to clients
//   - Support for formatted error messages
//   - Automatic HTTP status code handling
//
// Parameters:
//   - err: The underlying error (logged but not always exposed to client)
//   - code: HTTP status code (400, 401, 404, 500, etc.)
//   - msg: User-friendly error message (can include format verbs)
//   - fields: Optional key-value pairs for additional error context
//
// The response format is JSON: {"message": "error description", "field1": "value1", "field2": "value2"}
//
// Example:
//
//	// Simple error
//	ctx.Error(err, 400, "Invalid request")
//
//	// Formatted error message
//	ctx.Error(err, 404, "User not found", "user_id", userID) -> {"message": "User not found", "user_id": "123"}
//
//	// Use helper methods for common cases
//	ctx.BadRequest(err, "Invalid JSON payload")
//	ctx.NotFound(err, "Resource not found")
//	ctx.InternalServerError(err, "Database connection failed", "database_name", "users") -> {"message": "Database connection failed", "database_name": "users"}
//
// Note: Do not modify the ResponseWriter after calling this method.
// This method should typically be followed by a return statement.
func (ctx *Context) Error(err error, code int, msg string, fields ...any) {
	if err != nil {
		ctx.setError(err, code, msg)

		isSendErrorToClient := getValueFromContext[bool](ctx.r, sendErrorToClientKey{})
		if isSendErrorToClient || ctx.isSendErrorToClient {
			msg = fmt.Sprintf("%s: %s", msg, err.Error())
		}
	}

	body := map[string]any{
		"message": msg,
	}
	for i := 0; i < len(fields); i += 2 {
		if i+1 >= len(fields) {
			break
		}
		if key, ok := fields[i].(string); ok {
			body[key] = fields[i+1]
		}
	}

	jsonBytes, marshalErr := json.Marshal(body)
	if marshalErr != nil {
		jsonBytes = []byte(`{"message":"failed to marshal error response"}`)
	}

	ctx.SetHeader("Content-Length", strconv.Itoa(len(jsonBytes)))
	ctx.SetContentType(MIMETypeJSON)
	ctx.w.WriteHeader(code)

	if _, writeErr := ctx.w.Write(jsonBytes); writeErr != nil {
		origErr := ""
		if err != nil {
			origErr = err.Error()
		}
		ctx.setError(fmt.Errorf("write error response: %w", writeErr), code,
			"failed to write error response body, original error: "+origErr)
	}
}

// sanitizeFilename sanitizes a filename for use in HTTP headers to prevent header injection attacks.
// It removes or replaces characters that could be used for CRLF injection and other attacks.
func sanitizeFilename(filename string) string {
	if filename == "" {
		return "download"
	}

	// Remove or replace dangerous characters that could lead to header injection
	// Replace CRLF characters and other control characters
	replacer := strings.NewReplacer(
		"\r", "",
		"\n", "",
		"\t", "_",
		"\"", "'", // Replace quotes to avoid breaking quoted strings
		"\\", "_", // Replace backslashes
		":", "_", // Replace colons to prevent URLs in attacks
		"/", "_", // Replace slashes to prevent paths in attacks
	)

	sanitized := replacer.Replace(filename)

	// Remove any remaining control characters (ASCII 0-31 and 127)
	var cleaned strings.Builder
	for _, r := range sanitized {
		if r >= 32 && r != 127 {
			cleaned.WriteRune(r)
		}
	}

	result := cleaned.String()

	// If result is empty or contains only underscores/whitespace, use default
	if result == "" || strings.Trim(result, "_ \t") == "" {
		return "download"
	}

	return result
}

// formatContentDisposition safely formats a Content-Disposition header value with the given filename.
// This follows RFC 6266 recommendations and prevents header injection attacks.
func formatContentDisposition(filename string) string {
	sanitized := sanitizeFilename(filename)

	// Use simple filename format for ASCII filenames
	// For more complex cases, RFC 6266 suggests using filename* parameter with encoding,
	// but for this security fix, we'll use the simpler approach
	return fmt.Sprintf("attachment; filename=\"%s\"", sanitized)
}
