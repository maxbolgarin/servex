package servex_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/maxbolgarin/servex"
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

	received, err := servex.ReadJSON[testStruct](req)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !reflect.DeepEqual(testData, received) {
		t.Errorf("expected TestData, got %v", received)
	}
}

func TestReadAndValidate_Valid(t *testing.T) {
	testData := testStruct{Foo: "bar"}
	data, _ := json.Marshal(testData)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(data))
	defer req.Body.Close()

	received, err := servex.ReadAndValidate[testStruct](req)
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

	_, err := servex.ReadAndValidate[testStruct](req)
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid body") {
		t.Errorf("expected 'invalid body' in error message, got %v", err)
	}
}

func TestContext_RequestID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := servex.NewContext(httptest.NewRecorder(), req)

	requestID1 := ctx.RequestID()
	requestID2 := ctx.RequestID()
	if requestID1 != requestID2 {
		t.Errorf("Request IDs should be the same for the same context")
	}
}

func TestContext_APIVersion(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	ctx := servex.NewContext(httptest.NewRecorder(), req)

	if ctx.APIVersion() != "v1" {
		t.Errorf("expected 'v1' API version, got %v", ctx.APIVersion())
	}

	req = httptest.NewRequest(http.MethodGet, "/no-version", nil)
	ctx = servex.NewContext(httptest.NewRecorder(), req)
	if ctx.APIVersion() != "" {
		t.Errorf("expected no API version, got %v", ctx.APIVersion())
	}
}

func TestContext_Query(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?key=value", nil)
	ctx := servex.NewContext(httptest.NewRecorder(), req)

	if ctx.Query("key") != "value" {
		t.Errorf("expected 'value' query value, got %v", ctx.Query("key"))
	}
}

func TestContext_Header(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Test", "test-value")
	ctx := servex.NewContext(httptest.NewRecorder(), req)

	if ctx.Header("X-Test") != "test-value" {
		t.Errorf("expected 'test-value' header value, got %v", ctx.Header("X-Test"))
	}
}

func TestContext_SetHeader(t *testing.T) {
	w := httptest.NewRecorder()
	ctx := servex.NewContext(w, nil)

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
	ctx := servex.NewContext(httptest.NewRecorder(), req)

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
	ctx := servex.NewContext(w, nil)

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
	ctx := servex.NewContext(w, nil)

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
	ctx := servex.NewContext(httptest.NewRecorder(), req)

	if ctx.FormValue("key") != "value" {
		t.Errorf("expected 'value' form value, got %v", ctx.FormValue("key"))
	}
}

func TestContext_ParseUnixFromQuery(t *testing.T) {
	timestamp := time.Now().Unix()
	req := httptest.NewRequest(http.MethodGet, "/?ts="+strconv.FormatInt(timestamp, 10), nil)
	ctx := servex.NewContext(httptest.NewRecorder(), req)

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

	ctx := servex.NewContext(httptest.NewRecorder(), req)

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

	ctx := servex.NewContext(httptest.NewRecorder(), req)

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
	ctx := servex.NewContext(w, nil)

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
	ctx := servex.NewContext(w, nil)

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

	ctx := servex.NewContext(w, req)

	ctx.Error(errors.New("example error"), http.StatusInternalServerError, "Internal server error")
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected %v status code, got %v", http.StatusInternalServerError, resp.StatusCode)
	}
	if !strings.Contains(string(body), "Internal server error") {
		t.Errorf("expected 'Internal server error' error message, got %v", string(body))
	}
}

// Helper function to test the error response
func testErrorMethod(t *testing.T, method func(*servex.Context, error, string, ...any), expectedStatusCode int, expectedMessage string, args ...any) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	defer req.Body.Close()

	ctx := servex.NewContext(w, req)

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
	testErrorMethod(t, (*servex.Context).BadRequest, http.StatusBadRequest, "Bad request error")
}

func TestContext_Unauthorized(t *testing.T) {
	testErrorMethod(t, (*servex.Context).Unauthorized, http.StatusUnauthorized, "Unauthorized access")
}

func TestContext_Forbidden(t *testing.T) {
	testErrorMethod(t, (*servex.Context).Forbidden, http.StatusForbidden, "Forbidden action")
}

func TestContext_NotFound(t *testing.T) {
	testErrorMethod(t, (*servex.Context).NotFound, http.StatusNotFound, "Resource not found")
}

func TestContext_NotAcceptable(t *testing.T) {
	testErrorMethod(t, (*servex.Context).NotAcceptable, http.StatusNotAcceptable, "Not acceptable")
}

func TestContext_Conflict(t *testing.T) {
	testErrorMethod(t, (*servex.Context).Conflict, http.StatusConflict, "Resource conflict")
}

func TestContext_UnprocessableEntity(t *testing.T) {
	testErrorMethod(t, (*servex.Context).UnprocessableEntity, http.StatusUnprocessableEntity, "Unprocessable entity")
}

func TestContext_TooManyRequests(t *testing.T) {
	testErrorMethod(t, (*servex.Context).TooManyRequests, http.StatusTooManyRequests, "Too many requests")
}

func TestContext_InternalServerError(t *testing.T) {
	testErrorMethod(t, (*servex.Context).InternalServerError, http.StatusInternalServerError, "Internal server error")
}

func TestContext_NotImplemented(t *testing.T) {
	testErrorMethod(t, (*servex.Context).NotImplemented, http.StatusNotImplemented, "Not implemented")
}

func TestContext_BadGateway(t *testing.T) {
	testErrorMethod(t, (*servex.Context).BadGateway, http.StatusBadGateway, "Bad gateway")
}

func TestContext_ServiceUnavailable(t *testing.T) {
	testErrorMethod(t, (*servex.Context).ServiceUnavailable, http.StatusServiceUnavailable, "Service unavailable")
}
