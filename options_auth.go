package servex

import (
	"database/sql"
	"time"
)

// WithAuthToken enables simple token-based authentication using the Authorization header.
// When set, the server will check for "Authorization: Bearer <token>" headers on
// protected routes and compare against this token.
//
// Example:
//
//	// Enable simple token auth
//	server := servex.New(servex.WithAuthToken("my-secret-api-key"))
//
//	// Client usage:
//	// curl -H "Authorization: Bearer my-secret-api-key" http://localhost:8080/api/protected
//
// Use this for:
//   - Simple API authentication
//   - Service-to-service communication
//   - Development and testing
//
// For more advanced authentication with user management, JWT tokens, and roles,
// use WithAuth() or WithAuthMemoryDatabase() instead.
//
// Note: This is a simple string comparison. For production use with multiple
// users or complex authorization, consider using the full JWT authentication system.
func WithAuthToken(t string) Option {
	return func(op *Options) {
		op.AuthToken = t
	}
}

// WithAuth enables JWT-based authentication with a custom database implementation.
// This activates the full authentication system with user management, roles, and JWT tokens.
//
// The database must implement the AuthDatabase interface for user persistence.
//
// Example:
//
//	// Custom database implementation
//	type MyAuthDB struct {
//		users map[string]*User
//	}
//
//	func (db *MyAuthDB) CreateUser(ctx context.Context, user User) error {
//		// Implementation
//	}
//	// ... implement other AuthDatabase methods
//
//	server := servex.New(servex.WithAuth(&MyAuthDB{}))
//
// This automatically registers these endpoints:
//   - POST /api/v1/auth/register - User registration
//   - POST /api/v1/auth/login - User login
//   - POST /api/v1/auth/refresh - Token refresh
//   - POST /api/v1/auth/logout - User logout
//   - GET /api/v1/auth/me - Current user info
//
// Use this for:
//   - Multi-user applications
//   - Role-based access control
//   - Persistent user data
//   - Production authentication systems
func WithAuth(db AuthDatabase) Option {
	return func(op *Options) {
		op.Auth.Enabled = true
		op.Auth.Database = db
	}
}

// WithAuthMemoryDatabase enables JWT authentication with an in-memory user database.
// This is convenient for development, testing, and applications that don't need
// persistent user data.
//
// WARNING: All users and sessions will be lost when the application restarts.
// NOT RECOMMENDED FOR PRODUCTION USE.
//
// Example:
//
//	// Development server with auth
//	server := servex.New(
//		servex.WithAuthMemoryDatabase(),
//		servex.WithAuthInitialUsers(servex.InitialUser{
//			Username: "admin",
//			Password: "admin123",
//			Roles:    []servex.UserRole{"admin"},
//		}),
//	)
//
// This automatically registers the same endpoints as WithAuth().
//
// Use this for:
//   - Development and testing
//   - Prototypes and demos
//   - Applications with temporary users
//   - Learning and experimentation
//
// For production, implement a persistent database and use WithAuth() instead.
func WithAuthMemoryDatabase() Option {
	return func(op *Options) {
		op.Auth.Enabled = true
		op.Auth.Database = NewMemoryAuthDatabase()
	}
}

// WithAuthConfig sets the complete authentication configuration at once.
// This allows fine-grained control over all authentication settings.
//
// Example:
//
//	authConfig := servex.AuthConfig{
//		Enabled:                 true,
//		Database:                myDB,
//		AccessTokenDuration:     15 * time.Minute,
//		RefreshTokenDuration:    7 * 24 * time.Hour,
//		AuthBasePath:           "/auth",
//		IssuerNameInJWT:        "my-app",
//		RefreshTokenCookieName: "_refresh",
//		RolesOnRegister:        []servex.UserRole{"user"},
//		InitialUsers: []servex.InitialUser{
//			{Username: "admin", Password: "secure-password", Roles: []servex.UserRole{"admin"}},
//		},
//	}
//
//	server := servex.New(servex.WithAuthConfig(authConfig))
//
// Use this when you need to configure multiple authentication settings at once
// or when loading configuration from files or environment variables.
func WithAuthConfig(auth AuthConfig) Option {
	return func(op *Options) {
		op.Auth = auth
	}
}

// WithAuthKey sets the JWT signing keys for access and refresh tokens.
// Keys should be hex-encoded strings. If empty, random keys will be generated.
//
// Example:
//
//	// Use specific keys (recommended for production)
//	accessKey := "your-32-byte-hex-encoded-access-key"
//	refreshKey := "your-32-byte-hex-encoded-refresh-key"
//	server := servex.New(servex.WithAuthKey(accessKey, refreshKey))
//
//	// Generate random keys (development only)
//	server := servex.New(servex.WithAuthKey("", ""))
//
// Key requirements:
//   - Use strong, randomly generated keys
//   - Access and refresh keys should be different
//   - Store keys securely (environment variables, key management systems)
//   - Rotate keys periodically in production
//
// Security considerations:
//   - Never hardcode keys in source code
//   - Use environment variables or secure configuration
//   - Different keys for different environments
//   - Consider key rotation strategies
func WithAuthKey(accessKey, refreshKey string) Option {
	return func(op *Options) {
		op.Auth.JWTAccessSecret = accessKey
		op.Auth.JWTRefreshSecret = refreshKey
	}
}

// WithAuthIssuer sets the issuer name included in JWT token claims.
// This helps identify which service issued the token and can be used for validation.
//
// Example:
//
//	// Set application name as issuer
//	server := servex.New(servex.WithAuthIssuer("my-api-service"))
//
//	// Environment-specific issuer
//	issuer := fmt.Sprintf("my-app-%s", os.Getenv("ENVIRONMENT"))
//	server := servex.New(servex.WithAuthIssuer(issuer))
//
// The issuer appears in the JWT "iss" claim and can be verified by clients.
// Default is "testing" if not set.
//
// Use descriptive names like:
//   - Application name: "user-service", "payment-api"
//   - Environment-specific: "my-app-prod", "my-app-staging"
//   - Domain-based: "api.mycompany.com"
func WithAuthIssuer(issuer string) Option {
	return func(op *Options) {
		op.Auth.IssuerNameInJWT = issuer
	}
}

// WithAuthBasePath sets the base path for authentication API endpoints.
// All auth routes will be registered under this path.
//
// Example:
//
//	// Custom auth path
//	server := servex.New(servex.WithAuthBasePath("/auth"))
//	// Endpoints: /auth/login, /auth/register, etc.
//
//	// API versioned path
//	server := servex.New(servex.WithAuthBasePath("/api/v2/auth"))
//	// Endpoints: /api/v2/auth/login, /api/v2/auth/register, etc.
//
// Default is "/api/v1/auth" if not set.
//
// Registered endpoints under the base path:
//   - POST {basePath}/register
//   - POST {basePath}/login
//   - POST {basePath}/refresh
//   - POST {basePath}/logout
//   - GET {basePath}/me
func WithAuthBasePath(path string) Option {
	return func(op *Options) {
		op.Auth.AuthBasePath = path
	}
}

// WithAuthInitialRoles sets the default roles assigned to newly registered users.
// These roles are automatically assigned when users register through the /register endpoint.
//
// Example:
//
//	// All new users get "user" role
//	server := servex.New(servex.WithAuthInitialRoles(servex.UserRole("user")))
//
//	// Multiple default roles
//	server := servex.New(servex.WithAuthInitialRoles(
//		servex.UserRole("user"),
//		servex.UserRole("customer"),
//	))
//
// Common role patterns:
//   - Basic: "user"
//   - Hierarchical: "user", "member", "premium"
//   - Functional: "reader", "writer", "admin"
//
// Users can have multiple roles. Additional roles can be assigned later
// through user management endpoints or database operations.
func WithAuthInitialRoles(roles ...UserRole) Option {
	return func(op *Options) {
		op.Auth.RolesOnRegister = roles
	}
}

// WithAuthRefreshTokenCookieName sets the name of the HTTP cookie used to store refresh tokens.
// The refresh token cookie is httpOnly and secure, providing protection against XSS attacks.
//
// Example:
//
//	// Custom cookie name
//	server := servex.New(servex.WithAuthRefreshTokenCookieName("_my_refresh_token"))
//
//	// Short name for bandwidth
//	server := servex.New(servex.WithAuthRefreshTokenCookieName("_rt"))
//
// Default is "_servexrt" if not set.
//
// Cookie characteristics:
//   - HttpOnly: Cannot be accessed by JavaScript
//   - Secure: Only sent over HTTPS (in production)
//   - SameSite: Protection against CSRF attacks
//   - Expires: Set to refresh token duration
//
// Choose names that don't conflict with your application's other cookies.
func WithAuthRefreshTokenCookieName(name string) Option {
	return func(op *Options) {
		op.Auth.RefreshTokenCookieName = name
	}
}

// WithAuthTokensDuration sets the validity duration for access and refresh tokens.
// Access tokens should be short-lived for security, while refresh tokens can be longer.
//
// Example:
//
//	// Typical web application
//	server := servex.New(servex.WithAuthTokensDuration(
//		15*time.Minute,  // Access token: 15 minutes
//		7*24*time.Hour,  // Refresh token: 7 days
//	))
//
//	// High-security application
//	server := servex.New(servex.WithAuthTokensDuration(
//		5*time.Minute,   // Access token: 5 minutes
//		24*time.Hour,    // Refresh token: 1 day
//	))
//
//	// Development environment
//	server := servex.New(servex.WithAuthTokensDuration(
//		1*time.Hour,     // Access token: 1 hour
//		30*24*time.Hour, // Refresh token: 30 days
//	))
//
// Recommended patterns:
//   - Web apps: 15-60 min access, 7-30 days refresh
//   - APIs: 5-30 min access, 1-7 days refresh
//   - Mobile apps: 30-60 min access, 30-90 days refresh
//   - High security: 5-15 min access, 1-3 days refresh
//
// Shorter access tokens improve security but require more refresh operations.
func WithAuthTokensDuration(accessDuration, refreshDuration time.Duration) Option {
	return func(op *Options) {
		op.Auth.AccessTokenDuration = accessDuration
		op.Auth.RefreshTokenDuration = refreshDuration
	}
}

// WithAuthNotRegisterRoutes prevents automatic registration of default authentication routes.
// Use this when you want to implement custom authentication endpoints or integrate
// with existing authentication systems.
//
// It suppresses ALL auto-registered endpoints under the auth base path: the core routes
// (/register, /login, /refresh, /logout, /me), email verification and password reset routes,
// OAuth routes, 2FA routes, and the API key management routes (/api-keys).
//
// Example:
//
//	// Disable default auth routes
//	server := servex.New(
//		servex.WithAuthMemoryDatabase(),
//		servex.WithAuthNotRegisterRoutes(true),
//	)
//
//	// Register custom auth routes
//	server.HandleFunc("/custom/login", myCustomLoginHandler)
//	server.HandleFunc("/custom/register", myCustomRegisterHandler)
//
// When enabled, you must implement your own:
//   - User registration endpoint
//   - Login endpoint
//   - Token refresh endpoint
//   - Logout endpoint
//   - User profile endpoint
//
// You can still use the AuthManager methods for token generation and validation,
// and call AuthManager.RegisterRoutes on a router of your choice to mount the default
// handlers manually. This gives you full control over request/response formats and
// business logic.
func WithAuthNotRegisterRoutes(notRegisterRoutes bool) Option {
	return func(op *Options) {
		op.Auth.NotRegisterRoutes = notRegisterRoutes
	}
}

// WithAuthInitialUsers creates initial users in the database when the server starts.
// This is useful for creating admin accounts or seeding the database with test users.
//
// Example:
//
//	// Create admin user on startup
//	server := servex.New(
//		servex.WithAuthMemoryDatabase(),
//		servex.WithAuthInitialUsers(servex.InitialUser{
//			Username: "admin",
//			Password: "secure-admin-password",
//			Roles:    []servex.UserRole{"admin", "user"},
//		}),
//	)
//
//	// Multiple initial users
//	server := servex.New(
//		servex.WithAuthMemoryDatabase(),
//		servex.WithAuthInitialUsers(
//			servex.InitialUser{
//				Username: "admin",
//				Password: "admin-pass",
//				Roles:    []servex.UserRole{"admin"},
//			},
//			servex.InitialUser{
//				Username: "testuser",
//				Password: "test-pass",
//				Roles:    []servex.UserRole{"user"},
//			},
//		),
//	)
//
// Security considerations:
//   - Use strong passwords
//   - Consider loading from environment variables
//   - Remove or change default passwords in production
//   - Limit to essential accounts only
//
// The users are created if they don't already exist in the database.
func WithAuthInitialUsers(users ...InitialUser) Option {
	return func(op *Options) {
		op.Auth.InitialUsers = users
	}
}

// WithAuthMinPasswordLength sets the minimum required password length for registration.
// Default is 8 characters. Set to 0 to disable the password length check.
func WithAuthMinPasswordLength(n int) Option {
	return func(op *Options) {
		op.Auth.MinPasswordLength = n
	}
}

// WithAuthSQL enables JWT-based authentication with a SQL database.
// The driver parameter selects the SQL dialect: "postgres", "mysql", or "sqlite".
// The caller must import the appropriate database driver (e.g. _ "github.com/jackc/pgx/v5/stdlib").
//
// Servex does not take ownership of the provided *sql.DB; the caller is responsible for closing it.
// Tables are auto-created by default. Disable with SQLAutoMigrate(false).
//
// Example:
//
//	import _ "github.com/jackc/pgx/v5/stdlib"
//
//	db, _ := sql.Open("pgx", "postgres://user:pass@localhost/mydb")
//	server, _ := servex.NewServer(
//	    servex.WithAuthSQL(db, "postgres"),
//	    servex.WithAuthKey(accessKey, refreshKey),
//	)
func WithAuthSQL(db *sql.DB, driver string, opts ...SQLOption) Option {
	return func(op *Options) {
		op.Auth.Enabled = true
		op.Auth.sqlDB = db
		op.Auth.sqlDriver = driver
		op.Auth.sqlOptions = opts
	}
}

// WithAuthSQLDSN enables JWT-based authentication by opening a SQL connection from a DSN.
// Servex owns the connection and closes it on shutdown.
//
// Example:
//
//	server, _ := servex.NewServer(
//	    servex.WithAuthSQLDSN("postgres", "postgres://user:pass@localhost/mydb"),
//	    servex.WithAuthKey(accessKey, refreshKey),
//	)
func WithAuthSQLDSN(driver, dsn string, opts ...SQLOption) Option {
	return func(op *Options) {
		op.Auth.Enabled = true
		op.Auth.sqlDSN = dsn
		op.Auth.sqlDriver = driver
		op.Auth.sqlOptions = opts
	}
}
