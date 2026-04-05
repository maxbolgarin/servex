package servex

import (
	"fmt"
	"io"
	"net/http"
)

// ReadAndValidate reads a JSON from the request body to a variable of the provided type and validates it with size limits.
func ReadAndValidate[T interface{ Validate() error }](r *http.Request) (T, error) {
	return ReadAndValidateWithLimit[T](r, defaultMaxJSONBodySize)
}

// ReadAndValidateWithLimit reads and validates a JSON from the request body with a specific size limit.
func ReadAndValidateWithLimit[T interface{ Validate() error }](r *http.Request, maxSize int64) (T, error) {
	var req T
	if maxSize <= 0 {
		maxSize = defaultMaxJSONBodySize
	}

	bytes, err := io.ReadAll(io.LimitReader(r.Body, maxSize+1))
	if err != nil {
		return req, fmt.Errorf("read: %w", err)
	}

	// Check if we hit the size limit
	if int64(len(bytes)) > maxSize {
		return req, fmt.Errorf("request body too large (max: %d bytes)", maxSize)
	}

	if err := json.Unmarshal(bytes, &req); err != nil {
		return req, fmt.Errorf("unmarshal: %w", err)
	}
	if err := req.Validate(); err != nil {
		return req, fmt.Errorf("invalid body: %w", err)
	}
	return req, nil
}

// ReadAndValidate reads a JSON from the request body to the provided variable and validates it with size limits.
// You should provide a pointer to the variable.
// Example:
//
//	type User struct {
//		Name  string `json:"name"`
//		Email string `json:"email"`
//	}
//
//	func (u *User) Validate() error {
//		if u.Name == "" {
//			return errors.New("name is required")
//		}
//		return nil
//	}
//
//	func createUser(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//
//		var user User
//		if err := ctx.ReadAndValidate(&user); err != nil {
//			ctx.BadRequest(err, "Invalid JSON payload")
//			return
//		}
//
//		// Process user...
//		ctx.JSON(map[string]string{"status": "created"})
//	}
func (ctx *Context) ReadAndValidate(body interface{ Validate() error }) error {
	return ctx.ReadAndValidateWithLimit(body, ctx.maxJSONBodySize)
}

// ReadAndValidateWithLimit reads a JSON from the request body to the provided variable and validates it with size limits.
// You should provide a pointer to the variable.
// Example:
//
//	type User struct {
//		Name  string `json:"name"`
//		Email string `json:"email"`
//	}
//
//	func (u *User) Validate() error {
//		if u.Name == "" {
//			return errors.New("name is required")
//		}
//		return nil
//	}
//
//	func createUser(w http.ResponseWriter, r *http.Request) {
//		ctx := servex.C(w, r)
//
//		var user User
//		if err := ctx.ReadAndValidateWithLimit(&user, 1024); err != nil {
//			ctx.BadRequest(err, "Invalid JSON payload")
//			return
//		}
//
//		// Process user...
//		ctx.JSON(map[string]string{"status": "created"})
//	}
func (ctx *Context) ReadAndValidateWithLimit(body interface{ Validate() error }, maxSize int64) error {
	if err := ctx.ReadJSONWithLimit(body, maxSize); err != nil {
		return err
	}
	if err := body.Validate(); err != nil {
		return fmt.Errorf("invalid body: %w", err)
	}
	return nil
}
