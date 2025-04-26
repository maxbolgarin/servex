package servex

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/maxbolgarin/lang"
	"golang.org/x/crypto/bcrypt"
)

// AuthDatabase defines the interface for interacting with the user database.
type AuthDatabase interface {
	// NewUser creates a new user in the database.
	NewUser(ctx context.Context, username string, passwordHash string, roles ...UserRole) (string, error)

	// FindByID finds a user by their ID.
	FindByID(ctx context.Context, id string) (user User, exists bool, err error)
	// FindByUsername finds a user by their username.
	FindByUsername(ctx context.Context, username string) (user User, exists bool, err error)
	// FindAll retrieves all users from the database.
	FindAll(ctx context.Context) ([]User, error)

	// UpdateUser updates a user's information in the database.
	// Fields are updated only if the corresponding pointers are not nil.
	UpdateUser(ctx context.Context, id string, diff *UserDiff) error
}

// UserRole represents a role assigned to a user.
// It's defined as a string type for easy JSON marshaling/unmarshaling.
type UserRole string

// User represents a user entity in the system.
type User struct {
	ID                    string     `json:"id" bson:"_id" db:"id"`
	Username              string     `json:"username" bson:"username" db:"username"`
	Roles                 []UserRole `json:"roles" bson:"roles" db:"roles"`
	PasswordHash          string     `json:"password_hash" bson:"password_hash" db:"password_hash"`
	RefreshTokenHash      string     `json:"refresh_token_hash" bson:"refresh_token_hash" db:"refresh_token_hash"`
	RefreshTokenExpiresAt time.Time  `json:"refresh_token_expires_at" bson:"refresh_token_expires_at" db:"refresh_token_expires_at"`
}

type UserDiff struct {
	Username              *string     `json:"username,omitempty" bson:"username,omitempty" db:"username,omitempty"`
	Roles                 *[]UserRole `json:"roles,omitempty" bson:"roles,omitempty" db:"roles,omitempty"`
	PasswordHash          *string     `json:"password_hash,omitempty" bson:"password_hash,omitempty" db:"password_hash,omitempty"`
	RefreshTokenHash      *string     `json:"refresh_token_hash,omitempty" bson:"refresh_token_hash,omitempty" db:"refresh_token_hash,omitempty"`
	RefreshTokenExpiresAt *time.Time  `json:"refresh_token_expires_at,omitempty" bson:"refresh_token_expires_at,omitempty" db:"refresh_token_expires_at,omitempty"`
}

const (
	IDDBField                    = "id"
	IDDBBsonField                = "_id"
	UsernameDBField              = "username"
	RolesDBField                 = "roles"
	PasswordHashDBField          = "password_hash"
	RefreshTokenHashDBField      = "refresh_token_hash"
	RefreshTokenExpiresAtDBField = "refresh_token_expires_at"
)

// UserLoginRequest represents the request body for user login and registration.
type UserLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UserUpdateRequest represents the request body for updating user information.
type UserUpdateRequest struct {
	ID       string      `json:"id"`
	Username *string     `json:"username,omitempty"`
	Roles    *[]UserRole `json:"roles,omitempty"`
	Password *string     `json:"password,omitempty"`
}

// UserLoginResponse represents the response body for successful user login or registration.
type UserLoginResponse struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Roles       []UserRole `json:"roles"`
	AccessToken string     `json:"accessToken,omitempty"`
}

// AuthManager handles authentication and authorization logic.
type AuthManager struct {
	service *service
}

type (
	UserContextKey struct{}
	RoleContextKey struct{}
)

// NewAuthManager creates a new AuthManager with the provided configuration.
// It initializes default values for configuration fields if they are not provided
// and generates random secrets if JWT secrets are empty.
func NewAuthManager(cfg AuthConfig) *AuthManager {
	cfg.RefreshTokenCookieName = lang.Check(cfg.RefreshTokenCookieName, refreshTokenCookieName)
	cfg.AuthBasePath = lang.Check(cfg.AuthBasePath, authBasePath)
	cfg.AccessTokenDuration = lang.Check(cfg.AccessTokenDuration, accessTokenDuration)
	cfg.RefreshTokenDuration = lang.Check(cfg.RefreshTokenDuration, refreshTokenDuration)
	cfg.IssuerNameInJWT = lang.Check(cfg.IssuerNameInJWT, "testing")

	if cfg.JWTAccessSecret == "" {
		cfg.JWTAccessSecret = hex.EncodeToString(getRandomBytes(32))
	}

	if cfg.JWTRefreshSecret == "" {
		cfg.JWTRefreshSecret = hex.EncodeToString(getRandomBytes(32))
	}

	cfg.accessSecret, _ = hex.DecodeString(cfg.JWTAccessSecret)
	cfg.refreshSecret, _ = hex.DecodeString(cfg.JWTRefreshSecret)

	return &AuthManager{
		service: newService(cfg),
	}
}

// RegisterRoutes registers the authentication-related HTTP routes on the provided router.
func (h *AuthManager) RegisterRoutes(r *mux.Router) {
	rr := r.PathPrefix(h.service.cfg.AuthBasePath).Subrouter()
	{
		// Public routes
		rr.HandleFunc("/register", h.RegisterHandler).Methods(http.MethodPost)
		rr.HandleFunc("/login", h.LoginHandler).Methods(http.MethodPost)
		rr.HandleFunc("/refresh", h.RefreshHandler).Methods(http.MethodPost)
		rr.HandleFunc("/logout", h.LogoutHandler).Methods(http.MethodPost)
		rr.HandleFunc("/me", h.WithAuth(h.GetCurrentUserHandler)).Methods(http.MethodGet)

		// This roles should be set with custom roles by library user
		// rr.HandleFunc("/users", h.WithAuth(h.GetAllUsers)).Methods(http.MethodGet)
		// rr.HandleFunc("/users/role", h.WithAuth(h.UpdateUserRole)).Methods(http.MethodPut)
	}
}

// WithAuth is an HTTP middleware that enforces authentication and authorization.
// It checks for a valid JWT access token in the Authorization header.
// If roles are provided, it verifies that the authenticated user has at least one of the required roles.
// The user ID and roles are added to the request context.
func (m *AuthManager) WithAuth(next http.HandlerFunc, roles ...UserRole) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := NewContext(w, r)

		// Extract token from Authorization header
		tokenString := extractToken(r)
		if tokenString == "" {
			ctx.Unauthorized(errUnauthorized, "missing or invalid authorization token")
			return
		}

		claims, err := m.service.validateAccessToken(tokenString)
		if err != nil {
			ctx.Unauthorized(err, "invalid token")
			return
		}

		if !hasPermission(claims.Roles, roles) {
			ctx.Forbidden(errInsufficientPermissions, "insufficient permissions")
			return
		}

		reqWithContext := r.WithContext(context.WithValue(r.Context(), UserContextKey{}, claims.UserID))
		reqWithContext = reqWithContext.WithContext(context.WithValue(reqWithContext.Context(), RoleContextKey{}, claims.Roles))

		next(w, reqWithContext)
	}
}

// RegisterHandler handles the HTTP request for user registration.
func (h *AuthManager) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	var req UserLoginRequest
	if err := ctx.ReadAndValidate(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	// Register user
	result, err := h.service.register(r.Context(), req)
	if err != nil {
		switch err {
		case errUsernameAlreadyExists:
			ctx.Conflict(err, err.Error())
		default:
			ctx.InternalServerError(err, "failed to register user")
		}
		return
	}

	h.setAuthCookie(ctx, result.RefreshToken, result.RefreshTokenExpiresAt)

	ctx.Response(http.StatusCreated, result.UserLoginResponse)
}

// LoginHandler handles the HTTP request for user login.
func (h *AuthManager) LoginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	var req UserLoginRequest
	if err := ctx.ReadAndValidate(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	result, err := h.service.login(r.Context(), req)
	if err != nil {
		switch err {
		case errInvalidCredentials:
			ctx.Unauthorized(err, "invalid email or password")
		default:
			ctx.InternalServerError(err, "failed to login user")
		}
		return
	}

	h.setAuthCookie(ctx, result.RefreshToken, result.RefreshTokenExpiresAt)

	ctx.Response(http.StatusOK, result.UserLoginResponse)
}

// RefreshHandler handles the HTTP request for refreshing access tokens using a refresh token cookie.
func (h *AuthManager) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	refreshToken, err := ctx.Cookie(h.service.cfg.RefreshTokenCookieName)
	if err != nil {
		ctx.Unauthorized(err, "missing or invalid refresh token")
		return
	}

	result, err := h.service.refreshToken(ctx, refreshToken.Value)
	if err != nil {
		ctx.Unauthorized(err, "failed to refresh token")
		return
	}

	h.setAuthCookie(ctx, result.RefreshToken, result.RefreshTokenExpiresAt)

	ctx.Response(http.StatusOK, result.UserLoginResponse)
}

// LogoutHandler handles the HTTP request for user logout.
// It invalidates the refresh token associated with the current session.
func (h *AuthManager) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	refreshToken, _ := ctx.Cookie(h.service.cfg.RefreshTokenCookieName)
	h.service.logout(ctx, lang.Deref(refreshToken).Value)

	h.setLogoutCookie(ctx)

	ctx.Response(http.StatusNoContent)
}

// GetCurrentUserHandler handles the HTTP request to retrieve the details of the currently authenticated user.
func (h *AuthManager) GetCurrentUserHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	userID, ok := r.Context().Value(UserContextKey{}).(string)
	if !ok {
		fmt.Println("GetCurrentUser: not authenticated")
		ctx.Unauthorized(errUnauthorized, "not authenticated")
		return
	}

	user, err := h.service.getUserByID(r.Context(), userID)
	if err != nil {
		ctx.InternalServerError(err, "failed to get user")
		return
	}

	ctx.Response(http.StatusOK, UserLoginResponse{
		ID:       user.ID,
		Username: user.Username,
		Roles:    user.Roles,
	})
}

// GetAllUsersHandler handles the HTTP request to retrieve all users.
// Note: This handler is intended for administrative purposes and might require specific roles.
// The corresponding route registration is commented out by default.
func (h *AuthManager) GetAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	// Get all users
	users, err := h.service.getAllUsers(r.Context())
	if err != nil {
		ctx.InternalServerError(err, "failed to get users")
		return
	}

	// Convert to UserBasic to avoid sending password hashes
	resp := make([]UserLoginResponse, len(users))
	for i, user := range users {
		resp[i] = UserLoginResponse{
			ID:       user.ID,
			Username: user.Username,
			Roles:    user.Roles,
		}
	}

	ctx.Response(http.StatusOK, resp)
}

// UpdateUserRoleHandler handles the HTTP request to update a user's roles.
// Note: This handler is intended for administrative purposes and might require specific roles.
// The corresponding route registration is commented out by default.
func (h *AuthManager) UpdateUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(w, r)

	// Parse request body
	var req UserUpdateRequest
	if err := ctx.ReadAndValidate(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	// Update user role
	if err := h.service.updateUserRole(r.Context(), req.ID, lang.Deref(req.Roles)); err != nil {
		ctx.InternalServerError(err, "failed to update user role")
		return
	}

	ctx.Response(http.StatusOK, map[string]string{"message": "user role updated successfully"})
}

// CreateUser provides a programmatic way to create or update a user.
// If the user already exists (based on username), it updates their password and roles.
// If the user does not exist, it creates a new user with the provided details.
func (h *AuthManager) CreateUser(ctx context.Context, username, password string, roles ...UserRole) error {
	user, exists, err := h.service.db.FindByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("find user: %w", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if exists {
		err = h.service.db.UpdateUser(ctx, user.ID, &UserDiff{
			Roles:        &roles,
			PasswordHash: lang.Ptr(string(hashedPassword)),
		})
		if err != nil {
			return fmt.Errorf("update password: %w", err)
		}
		return nil
	}

	_, err = h.service.db.NewUser(ctx, username, string(hashedPassword), roles...)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	return nil
}

func (h *AuthManager) setAuthCookie(ctx *Context, token string, expiresAt time.Time) {
	ctx.SetRawCookie(&http.Cookie{
		Name:     h.service.cfg.RefreshTokenCookieName,
		Value:    token,
		Path:     authBasePath,
		HttpOnly: true,
		Secure:   (ctx.Header("X-Forwarded-Proto") == "https") || ctx.r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(expiresAt.Sub(time.Now()).Seconds()),
	})
}

func (h *AuthManager) setLogoutCookie(ctx *Context) {
	ctx.SetRawCookie(&http.Cookie{
		Name:     h.service.cfg.RefreshTokenCookieName,
		Value:    "",
		Path:     authBasePath,
		HttpOnly: true,
		Secure:   (ctx.Header("X-Forwarded-Proto") == "https") || ctx.r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Delete cookie
		Expires:  time.Now().Add(-1 * time.Hour),
	})
}

type jwtClaims struct {
	UserID    string     `json:"user_id"`
	Roles     []UserRole `json:"roles"`
	IsRefresh bool       `json:"is_refresh"`
	jwt.RegisteredClaims
}

type loginResult struct {
	UserLoginResponse
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
}

// service provides auth operations
type service struct {
	db  AuthDatabase
	cfg AuthConfig
}

// newService creates a new auth service
func newService(cfg AuthConfig) *service {
	return &service{
		cfg: cfg,
		db:  cfg.Database,
	}
}

func (s *service) register(ctx context.Context, req UserLoginRequest) (loginResult, error) {
	_, exists, err := s.db.FindByUsername(ctx, req.Username)
	if err != nil {
		return loginResult{}, fmt.Errorf("FindByUsername: %w", err)
	}

	if exists {
		return loginResult{}, errUsernameAlreadyExists
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return loginResult{}, fmt.Errorf("hashing password: %w", err)
	}

	id, err := s.db.NewUser(ctx, req.Username, string(hashedPassword), s.cfg.RolesOnRegister...)
	if err != nil {
		return loginResult{}, fmt.Errorf("NewUser: %w", err)
	}

	accessToken, refreshToken, refreshTokenExpiresAt, err := s.generateTokens(ctx, User{
		ID:           id,
		Username:     req.Username,
		Roles:        s.cfg.RolesOnRegister,
		PasswordHash: string(hashedPassword),
	})
	if err != nil {
		return loginResult{}, fmt.Errorf("generateTokens: %w", err)
	}

	result := loginResult{
		UserLoginResponse: UserLoginResponse{
			AccessToken: accessToken,
			ID:          id,
			Username:    req.Username,
			Roles:       s.cfg.RolesOnRegister,
		},
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
	}

	return result, nil
}

func (s *service) login(ctx context.Context, req UserLoginRequest) (loginResult, error) {
	user, exists, err := s.db.FindByUsername(ctx, req.Username)
	if err != nil {
		return loginResult{}, fmt.Errorf("FindByUsername: %w", err)
	}

	if !exists {
		return loginResult{}, errInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return loginResult{}, errInvalidCredentials
	}

	accessToken, refreshToken, refreshTokenExpiresAt, err := s.generateTokens(ctx, user)
	if err != nil {
		return loginResult{}, fmt.Errorf("generateTokens: %w", err)
	}

	out := loginResult{
		UserLoginResponse: UserLoginResponse{
			AccessToken: accessToken,
			ID:          user.ID,
			Username:    user.Username,
			Roles:       user.Roles,
		},
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
	}

	return out, nil
}

func (s *service) refreshToken(ctx context.Context, refreshToken string) (loginResult, error) {
	user, err := s.validateRefreshToken(ctx, refreshToken)
	if err != nil {
		return loginResult{}, fmt.Errorf("validateRefreshToken: %w", err)
	}

	accessToken, refreshToken, refreshTokenExpiresAt, err := s.generateTokens(ctx, user)
	if err != nil {
		return loginResult{}, fmt.Errorf("generateTokens: %w", err)
	}

	out := loginResult{
		UserLoginResponse: UserLoginResponse{
			AccessToken: accessToken,
			ID:          user.ID,
			Username:    user.Username,
			Roles:       user.Roles,
		},
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
	}

	return out, nil
}

func (s *service) logout(ctx context.Context, refreshToken string) {
	user, _ := s.validateRefreshToken(ctx, refreshToken)
	if user.ID == "" {
		return
	}
	_ = s.db.UpdateUser(ctx, user.ID, &UserDiff{
		RefreshTokenHash:      lang.Ptr(""),
		RefreshTokenExpiresAt: lang.Ptr(time.Time{}),
	})
}

func (s *service) getUserByID(ctx context.Context, id string) (User, error) {
	user, _, err := s.db.FindByID(ctx, id)
	if err != nil {
		return User{}, fmt.Errorf("FindByID: %w", err)
	}
	return user, nil
}

func (s *service) getAllUsers(ctx context.Context) ([]User, error) {
	users, err := s.db.FindAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("FindAll: %w", err)
	}
	return users, nil
}

func (s *service) updateUserRole(ctx context.Context, id string, roles []UserRole) error {
	return s.db.UpdateUser(ctx, id, &UserDiff{
		Roles: &roles,
	})
}

func (s *service) validateAccessToken(tokenString string) (claims *jwtClaims, err error) {
	claims, err = s.parseToken(tokenString, s.cfg.accessSecret)
	if err != nil {
		return nil, fmt.Errorf("parseToken: %w", err)
	}

	if claims.IsRefresh {
		return nil, fmt.Errorf("unexpected refresh token")
	}

	if claims.Issuer != s.cfg.IssuerNameInJWT {
		return nil, fmt.Errorf("invalid issuer")
	}

	if claims.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("expired token")
	}

	return claims, nil
}

func (s *service) validateRefreshToken(ctx context.Context, tokenString string) (user User, err error) {
	claims, err := s.parseToken(tokenString, s.cfg.refreshSecret)
	if err != nil {
		return User{}, fmt.Errorf("parseToken: %w", err)
	}

	user, exists, err := s.db.FindByID(ctx, claims.UserID)
	if err != nil {
		return User{}, fmt.Errorf("FindByID: %w", err)
	}

	if !exists {
		return User{}, fmt.Errorf("user not found")
	}

	if !claims.IsRefresh {
		return user, fmt.Errorf("unexpected access token")
	}

	if claims.ExpiresAt.Before(time.Now()) {
		return user, fmt.Errorf("expired token")
	}

	tokenString = tokenString[:72]
	if err := bcrypt.CompareHashAndPassword([]byte(user.RefreshTokenHash), []byte(tokenString)); err != nil {
		return user, fmt.Errorf("refresh token mismatch")
	}

	if user.RefreshTokenExpiresAt.Before(time.Now()) {
		return user, fmt.Errorf("refresh token expired")
	}

	return user, nil
}

func (s *service) parseToken(tokenString string, key []byte) (*jwtClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwtClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token format")
	}

	claims, ok := token.Claims.(*jwtClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid claims")
	}

	return claims, nil
}

func (s *service) generateTokens(ctx context.Context, user User) (string, string, time.Time, error) {
	accessToken, _, err := s.generateAccessToken(user)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("generating access token: %w", err)
	}

	refreshToken, refreshTokenExpiresAt, err := s.generateAndSaveRefreshToken(ctx, user)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("generating refresh token: %w", err)
	}

	return accessToken, refreshToken, refreshTokenExpiresAt, nil
}

func (s *service) generateAccessToken(user User) (string, time.Time, error) {
	return s.generateToken(user.ID, user.Roles, false)
}

func (s *service) generateAndSaveRefreshToken(ctx context.Context, user User) (string, time.Time, error) {
	token, expiresAt, err := s.generateToken(user.ID, user.Roles, true)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("generating refresh token: %w", err)
	}

	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(token[:72]), bcrypt.DefaultCost)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("hashing refresh token: %w", err)
	}

	if err := s.db.UpdateUser(ctx, user.ID, &UserDiff{
		RefreshTokenHash:      lang.Ptr(string(refreshTokenHash)),
		RefreshTokenExpiresAt: lang.Ptr(expiresAt),
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("updating refresh token: %w", err)
	}

	return token, expiresAt, nil
}

func (s *service) generateToken(userID string, userRoles []UserRole, isRefresh bool) (string, time.Time, error) {
	expiresAt := time.Now().Add(s.cfg.AccessTokenDuration)
	secret := s.cfg.accessSecret
	if isRefresh {
		expiresAt = time.Now().Add(s.cfg.RefreshTokenDuration)
		secret = s.cfg.refreshSecret
	}

	claims := jwtClaims{
		UserID:    userID,
		Roles:     userRoles,
		IsRefresh: isRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Make refresh lighter
	if !isRefresh {
		claims.Roles = userRoles
		claims.Issuer = s.cfg.IssuerNameInJWT
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get complete token string
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signing token: %w", err)
	}

	return tokenString, expiresAt, nil
}

var (
	errInvalidCredentials      = errors.New("invalid username or password")
	errUnauthorized            = errors.New("unauthorized")
	errInsufficientPermissions = errors.New("insufficient permissions")
	errInvalidToken            = errors.New("invalid token")
	errUnknownRefreshToken     = errors.New("unknown refresh token")
	errUsernameAlreadyExists   = errors.New("username already exists")
)

// Validate checks if the UserLoginRequest is valid.
func (req UserLoginRequest) Validate() error {
	if req.Username == "" {
		return errors.New("username is required")
	}
	if req.Password == "" {
		return errors.New("password is required")
	}
	return nil
}

// Validate checks if the UserUpdateRequest is valid.
func (req UserUpdateRequest) Validate() error {
	if req.ID == "" {
		return errors.New("id is required")
	}
	if req.Roles == nil && req.Username == nil && req.Password == nil {
		return errors.New("at least one field must be provided")
	}
	return nil
}

// extractToken extracts the JWT token from the Authorization header
func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if bearerToken == "" {
		return ""
	}

	// Format: "Bearer {token}"
	parts := strings.Split(bearerToken, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

// hasPermission checks if the given user roles contain at least one of the required roles.
// If requiredRoles is empty, it grants permission (returns true).
func hasPermission(userRoles []UserRole, requiredRoles []UserRole) bool {
	// If no specific roles are required, access is granted.
	if len(requiredRoles) == 0 {
		return true
	}
	// Check if the user has at least one of the required roles.
	for _, requiredRole := range requiredRoles {
		if slices.Contains(userRoles, requiredRole) {
			return true // Found a matching role
		}
	}
	// No matching required role found in the user's roles.
	return false
}

const (
	refreshTokenCookieName = "_servexrt"
	authBasePath           = "/api/v1/auth"

	accessTokenDuration  = 5 * time.Minute
	refreshTokenDuration = 7 * 24 * time.Hour
)

// MockAuthDatabase provides a mock implementation of the AuthDatabase interface for testing.
type MemoryAuthDatabase struct {
	mu            sync.RWMutex
	users         map[string]User // Map username to User
	usersByID     map[string]User // Map ID to User
	userIDCounter int
}

func NewMemoryAuthDatabase() *MemoryAuthDatabase {
	return &MemoryAuthDatabase{
		users:     make(map[string]User),
		usersByID: make(map[string]User),
	}
}

func (db *MemoryAuthDatabase) NewUser(ctx context.Context, username string, passwordHash string, roles ...UserRole) (string, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.users[username]; exists {
		return "", fmt.Errorf("username %q already exists", username)
	}

	db.userIDCounter++
	id := fmt.Sprintf("user-%d", db.userIDCounter)
	user := User{
		ID:           id,
		Username:     username,
		PasswordHash: passwordHash,
		Roles:        roles,
	}
	db.users[username] = user
	db.usersByID[id] = user
	return id, nil
}

func (db *MemoryAuthDatabase) FindByID(ctx context.Context, id string) (User, bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	user, exists := db.usersByID[id]
	return user, exists, nil
}

func (db *MemoryAuthDatabase) FindByUsername(ctx context.Context, username string) (User, bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	user, exists := db.users[username]
	return user, exists, nil
}

func (db *MemoryAuthDatabase) FindAll(ctx context.Context) ([]User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	users := make([]User, 0, len(db.usersByID))
	for _, user := range db.usersByID {
		users = append(users, user)
	}
	return users, nil
}

func (db *MemoryAuthDatabase) UpdateUser(ctx context.Context, id string, diff *UserDiff) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	user, exists := db.usersByID[id]
	if !exists {
		return fmt.Errorf("user with id %s not found", id)
	}

	// Remove old username mapping if username is changing
	if diff.Username != nil && *diff.Username != user.Username {
		if _, exists := db.users[*diff.Username]; exists {
			return fmt.Errorf("new username %q already exists", *diff.Username)
		}
		delete(db.users, user.Username)
		user.Username = *diff.Username
	}

	if diff.Roles != nil {
		user.Roles = *diff.Roles
	}
	if diff.PasswordHash != nil {
		user.PasswordHash = *diff.PasswordHash
	}
	if diff.RefreshTokenHash != nil {
		user.RefreshTokenHash = *diff.RefreshTokenHash
	}

	// Update maps
	db.users[user.Username] = user
	db.usersByID[id] = user

	return nil
}
