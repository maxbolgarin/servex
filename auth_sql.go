package servex

import (
	"context"
	"database/sql"
	stdjson "encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SQLOption configures the SQL auth database.
type SQLOption func(*sqlOptions)

type sqlOptions struct {
	tablePrefix string
	autoMigrate bool
}

// SQLTablePrefix sets the table name prefix for all tables created by the SQL auth database.
func SQLTablePrefix(prefix string) SQLOption {
	return func(o *sqlOptions) {
		o.tablePrefix = prefix
	}
}

// SQLAutoMigrate controls whether tables are automatically created on initialization.
// Defaults to true.
func SQLAutoMigrate(enabled bool) SQLOption {
	return func(o *sqlOptions) {
		o.autoMigrate = enabled
	}
}

// SQLAuthDatabase implements AuthDatabase, EmailAuthDatabase, and OAuthAuthDatabase
// using database/sql for PostgreSQL, MySQL, and SQLite.
type SQLAuthDatabase struct {
	db      *sql.DB
	dialect string // "postgres", "mysql", "sqlite"
	prefix  string
	ownedDB bool // true if we opened it via DSN
}

// NewSQLAuthDatabase creates a SQL auth database from an existing *sql.DB.
// driver is used for dialect detection: "postgres"/"pgx"/"postgresql" → postgres,
// "mysql" → mysql, "sqlite3"/"sqlite" → sqlite.
// Auto-migrates tables by default (disable with SQLAutoMigrate(false)).
func NewSQLAuthDatabase(db *sql.DB, driver string, opts ...SQLOption) (*SQLAuthDatabase, error) {
	dialect, err := normalizeDialect(driver)
	if err != nil {
		return nil, err
	}

	o := &sqlOptions{autoMigrate: true}
	for _, opt := range opts {
		opt(o)
	}

	if err := validateTablePrefix(o.tablePrefix); err != nil {
		return nil, err
	}

	s := &SQLAuthDatabase{
		db:      db,
		dialect: dialect,
		prefix:  o.tablePrefix,
	}

	if o.autoMigrate {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.createTables(ctx); err != nil {
			return nil, fmt.Errorf("sql auth: auto-migrate: %w", err)
		}
	}

	return s, nil
}

// newSQLAuthDatabaseFromDSN opens a connection and creates the database.
// Internal — called by WithAuthSQLDSN option.
func newSQLAuthDatabaseFromDSN(driver, dsn string, opts ...SQLOption) (*SQLAuthDatabase, error) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("sql auth: open: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("sql auth: ping: %w", err)
	}

	s, err := NewSQLAuthDatabase(db, driver, opts...)
	if err != nil {
		db.Close()
		return nil, err
	}
	s.ownedDB = true
	return s, nil
}

func validateTablePrefix(prefix string) error {
	for _, r := range prefix {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_') {
			return fmt.Errorf("sql auth: invalid table prefix %q: only [a-zA-Z0-9_] allowed", prefix)
		}
	}
	return nil
}

func normalizeDialect(driver string) (string, error) {
	switch strings.ToLower(driver) {
	case "postgres", "pgx", "postgresql", "pgx/v5":
		return "postgres", nil
	case "mysql":
		return "mysql", nil
	case "sqlite3", "sqlite", "mattn/go-sqlite3":
		return "sqlite", nil
	default:
		return "", fmt.Errorf("unsupported SQL driver: %q (supported: postgres, mysql, sqlite)", driver)
	}
}

func (s *SQLAuthDatabase) placeholder(n int) string {
	if s.dialect == "postgres" {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func (s *SQLAuthDatabase) placeholders(start, count int) string {
	parts := make([]string, count)
	for i := 0; i < count; i++ {
		parts[i] = s.placeholder(start + i)
	}
	return strings.Join(parts, ", ")
}

func (s *SQLAuthDatabase) tableName(base string) string {
	return s.prefix + base
}

func (s *SQLAuthDatabase) createTables(ctx context.Context) error {
	usersTable := s.tableName("users")
	oauthTable := s.tableName("user_oauth_providers")

	var usersSQL, oauthSQL string

	switch s.dialect {
	case "postgres":
		usersSQL = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id BIGSERIAL PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password_hash TEXT NOT NULL DEFAULT '',
			roles JSONB NOT NULL DEFAULT '[]',
			email VARCHAR(255) NOT NULL DEFAULT '',
			email_verified BOOLEAN NOT NULL DEFAULT FALSE,
			refresh_token_hash TEXT NOT NULL DEFAULT '',
			refresh_token_expires_at TIMESTAMP NULL DEFAULT NULL,
			email_verify_token_hash TEXT NOT NULL DEFAULT '',
			email_verify_token_expires_at TIMESTAMP NULL DEFAULT NULL,
			email_verify_last_sent_at TIMESTAMP NULL DEFAULT NULL,
			password_reset_token_hash TEXT NOT NULL DEFAULT '',
			password_reset_token_expires_at TIMESTAMP NULL DEFAULT NULL,
			two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE,
			two_factor_secret TEXT NOT NULL DEFAULT '',
			two_factor_backup_codes JSONB NOT NULL DEFAULT '[]',
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`, usersTable)

		oauthSQL = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id BIGSERIAL PRIMARY KEY,
			user_id BIGINT NOT NULL REFERENCES %s(id) ON DELETE CASCADE,
			provider VARCHAR(100) NOT NULL,
			provider_id VARCHAR(255) NOT NULL,
			email VARCHAR(255) NOT NULL DEFAULT ''
		)`, oauthTable, usersTable)

	case "mysql":
		usersSQL = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password_hash TEXT NOT NULL DEFAULT '',
			roles JSON NOT NULL,
			email VARCHAR(255) NOT NULL DEFAULT '',
			email_verified BOOLEAN NOT NULL DEFAULT FALSE,
			refresh_token_hash TEXT NOT NULL DEFAULT '',
			refresh_token_expires_at DATETIME NULL DEFAULT NULL,
			email_verify_token_hash TEXT NOT NULL DEFAULT '',
			email_verify_token_expires_at DATETIME NULL DEFAULT NULL,
			email_verify_last_sent_at DATETIME NULL DEFAULT NULL,
			password_reset_token_hash TEXT NOT NULL DEFAULT '',
			password_reset_token_expires_at DATETIME NULL DEFAULT NULL,
			two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE,
			two_factor_secret TEXT NOT NULL DEFAULT '',
			two_factor_backup_codes JSON NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`, usersTable)

		oauthSQL = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			user_id BIGINT NOT NULL,
			provider VARCHAR(100) NOT NULL,
			provider_id VARCHAR(255) NOT NULL,
			email VARCHAR(255) NOT NULL DEFAULT '',
			FOREIGN KEY (user_id) REFERENCES %s(id) ON DELETE CASCADE
		)`, oauthTable, usersTable)

	case "sqlite":
		usersSQL = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL DEFAULT '',
			roles TEXT NOT NULL DEFAULT '[]',
			email TEXT NOT NULL DEFAULT '',
			email_verified INTEGER NOT NULL DEFAULT 0,
			refresh_token_hash TEXT NOT NULL DEFAULT '',
			refresh_token_expires_at DATETIME NULL DEFAULT NULL,
			email_verify_token_hash TEXT NOT NULL DEFAULT '',
			email_verify_token_expires_at DATETIME NULL DEFAULT NULL,
			email_verify_last_sent_at DATETIME NULL DEFAULT NULL,
			password_reset_token_hash TEXT NOT NULL DEFAULT '',
			password_reset_token_expires_at DATETIME NULL DEFAULT NULL,
			two_factor_enabled INTEGER NOT NULL DEFAULT 0,
			two_factor_secret TEXT NOT NULL DEFAULT '',
			two_factor_backup_codes TEXT NOT NULL DEFAULT '[]',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`, usersTable)

		oauthSQL = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES %s(id) ON DELETE CASCADE,
			provider TEXT NOT NULL,
			provider_id TEXT NOT NULL,
			email TEXT NOT NULL DEFAULT ''
		)`, oauthTable, usersTable)
	}

	if _, err := s.db.ExecContext(ctx, usersSQL); err != nil {
		return fmt.Errorf("create users table: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, oauthSQL); err != nil {
		return fmt.Errorf("create oauth table: %w", err)
	}

	return s.createIndexes(ctx)
}

func (s *SQLAuthDatabase) createIndexes(ctx context.Context) error {
	oauthTable := s.tableName("user_oauth_providers")
	usersTable := s.tableName("users")
	p := s.prefix

	if s.dialect == "mysql" {
		return s.createIndexesMySQL(ctx, usersTable, oauthTable, p)
	}

	indexes := []string{
		fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS idx_%soauth_provider_id ON %s (provider, provider_id)`, p, oauthTable),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_%soauth_user_id ON %s (user_id)`, p, oauthTable),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_%susers_email ON %s (email)`, p, usersTable),
	}
	for _, idx := range indexes {
		if _, err := s.db.ExecContext(ctx, idx); err != nil {
			return fmt.Errorf("sql auth: create index: %w", err)
		}
	}
	return nil
}

func (s *SQLAuthDatabase) createIndexesMySQL(ctx context.Context, usersTable, oauthTable, p string) error {
	type indexDef struct {
		table   string
		name    string
		columns string
		unique  bool
	}
	defs := []indexDef{
		{oauthTable, fmt.Sprintf("idx_%soauth_provider_id", p), "provider, provider_id", true},
		{oauthTable, fmt.Sprintf("idx_%soauth_user_id", p), "user_id", false},
		{usersTable, fmt.Sprintf("idx_%susers_email", p), "email", false},
	}

	for _, d := range defs {
		var count int
		checkSQL := `SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`
		if err := s.db.QueryRowContext(ctx, checkSQL, d.table, d.name).Scan(&count); err != nil {
			return fmt.Errorf("sql auth: check index %s: %w", d.name, err)
		}
		if count > 0 {
			continue
		}
		keyword := "INDEX"
		if d.unique {
			keyword = "UNIQUE INDEX"
		}
		createSQL := fmt.Sprintf("CREATE %s %s ON %s (%s)", keyword, d.name, d.table, d.columns)
		if _, err := s.db.ExecContext(ctx, createSQL); err != nil {
			return fmt.Errorf("sql auth: create index %s: %w", d.name, err)
		}
	}
	return nil
}

const sqlUserColumns = "id, username, password_hash, roles, email, email_verified, refresh_token_hash, refresh_token_expires_at, email_verify_token_hash, email_verify_token_expires_at, email_verify_last_sent_at, password_reset_token_hash, password_reset_token_expires_at, two_factor_enabled, two_factor_secret, two_factor_backup_codes, created_at"

// scannable is satisfied by *sql.Row and *sql.Rows.
type scannable interface {
	Scan(dest ...any) error
}

func (s *SQLAuthDatabase) scanUser(row scannable) (User, error) {
	var (
		id                          int64
		rolesJSON                   []byte
		backupCodesJSON             []byte
		emailVerified               int64
		twoFactorEnabled            int64
		refreshTokenExpiresAt       sql.NullTime
		emailVerifyTokenExpiresAt   sql.NullTime
		emailVerifyLastSentAt       sql.NullTime
		passwordResetTokenExpiresAt sql.NullTime
		createdAt                   time.Time
		u                           User
	)

	err := row.Scan(
		&id,
		&u.Username,
		&u.PasswordHash,
		&rolesJSON,
		&u.Email,
		&emailVerified,
		&u.RefreshTokenHash,
		&refreshTokenExpiresAt,
		&u.EmailVerifyTokenHash,
		&emailVerifyTokenExpiresAt,
		&emailVerifyLastSentAt,
		&u.PasswordResetTokenHash,
		&passwordResetTokenExpiresAt,
		&twoFactorEnabled,
		&u.TwoFactorSecret,
		&backupCodesJSON,
		&createdAt,
	)
	if err != nil {
		return User{}, err
	}

	u.ID = strconv.FormatInt(id, 10)
	u.EmailVerified = emailVerified != 0
	u.TwoFactorEnabled = twoFactorEnabled != 0

	if err := stdjson.Unmarshal(rolesJSON, &u.Roles); err != nil {
		return User{}, fmt.Errorf("sql auth: unmarshal roles for user %d: %w", id, err)
	}
	if u.Roles == nil {
		u.Roles = []UserRole{}
	}

	if len(backupCodesJSON) > 0 {
		if err := stdjson.Unmarshal(backupCodesJSON, &u.TwoFactorBackupCodes); err != nil {
			return User{}, fmt.Errorf("sql auth: unmarshal backup codes for user %d: %w", id, err)
		}
	}

	if refreshTokenExpiresAt.Valid {
		u.RefreshTokenExpiresAt = refreshTokenExpiresAt.Time
	}
	if emailVerifyTokenExpiresAt.Valid {
		u.EmailVerifyTokenExpiresAt = emailVerifyTokenExpiresAt.Time
	}
	if emailVerifyLastSentAt.Valid {
		u.EmailVerifyLastSentAt = emailVerifyLastSentAt.Time
	}
	if passwordResetTokenExpiresAt.Valid {
		u.PasswordResetTokenExpiresAt = passwordResetTokenExpiresAt.Time
	}

	_ = createdAt
	return u, nil
}

func (s *SQLAuthDatabase) loadOAuthProviders(ctx context.Context, userIDs ...int64) (map[int64][]OAuthLink, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}

	placeholders := s.placeholders(1, len(userIDs))
	query := fmt.Sprintf(
		"SELECT user_id, provider, provider_id, email FROM %s WHERE user_id IN (%s)",
		s.tableName("user_oauth_providers"),
		placeholders,
	)

	args := make([]any, len(userIDs))
	for i, id := range userIDs {
		args[i] = id
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sql auth: load oauth providers: %w", err)
	}
	defer rows.Close()

	result := make(map[int64][]OAuthLink)
	for rows.Next() {
		var userID int64
		var link OAuthLink
		if err := rows.Scan(&userID, &link.Provider, &link.ProviderID, &link.Email); err != nil {
			return nil, fmt.Errorf("sql auth: scan oauth provider: %w", err)
		}
		result[userID] = append(result[userID], link)
	}
	return result, rows.Err()
}

func (s *SQLAuthDatabase) attachOAuthProviders(ctx context.Context, u *User) error {
	id, err := strconv.ParseInt(u.ID, 10, 64)
	if err != nil {
		return fmt.Errorf("sql auth: parse user id: %w", err)
	}
	providerMap, err := s.loadOAuthProviders(ctx, id)
	if err != nil {
		return err
	}
	u.OAuthProviders = providerMap[id]
	return nil
}

// NewUser creates a new user in the database.
func (s *SQLAuthDatabase) NewUser(ctx context.Context, username string, passwordHash string, roles ...UserRole) (string, error) {
	if len(roles) == 0 {
		roles = []UserRole{}
	}
	rolesJSON, err := stdjson.Marshal(roles)
	if err != nil {
		return "", fmt.Errorf("sql auth: marshal roles: %w", err)
	}

	usersTable := s.tableName("users")

	var id int64
	switch s.dialect {
	case "postgres":
		query := fmt.Sprintf(
			"INSERT INTO %s (username, password_hash, roles) VALUES ($1, $2, $3) RETURNING id",
			usersTable,
		)
		if err := s.db.QueryRowContext(ctx, query, username, passwordHash, string(rolesJSON)).Scan(&id); err != nil {
			return "", fmt.Errorf("sql auth: insert user: %w", err)
		}
	default:
		query := fmt.Sprintf(
			"INSERT INTO %s (username, password_hash, roles) VALUES (?, ?, ?)",
			usersTable,
		)
		result, err := s.db.ExecContext(ctx, query, username, passwordHash, string(rolesJSON))
		if err != nil {
			return "", fmt.Errorf("sql auth: insert user: %w", err)
		}
		id, err = result.LastInsertId()
		if err != nil {
			return "", fmt.Errorf("sql auth: last insert id: %w", err)
		}
	}

	return strconv.FormatInt(id, 10), nil
}

// FindByID finds a user by their ID.
func (s *SQLAuthDatabase) FindByID(ctx context.Context, id string) (User, bool, error) {
	numID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return User{}, false, fmt.Errorf("invalid user id %q: %w", id, err)
	}

	query := fmt.Sprintf(
		"SELECT %s FROM %s WHERE id = %s",
		sqlUserColumns, s.tableName("users"), s.placeholder(1),
	)

	u, err := s.scanUser(s.db.QueryRowContext(ctx, query, numID))
	if err == sql.ErrNoRows {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, fmt.Errorf("sql auth: find by id: %w", err)
	}

	if err := s.attachOAuthProviders(ctx, &u); err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

// FindByUsername finds a user by their username.
func (s *SQLAuthDatabase) FindByUsername(ctx context.Context, username string) (User, bool, error) {
	query := fmt.Sprintf(
		"SELECT %s FROM %s WHERE username = %s",
		sqlUserColumns, s.tableName("users"), s.placeholder(1),
	)

	u, err := s.scanUser(s.db.QueryRowContext(ctx, query, username))
	if err == sql.ErrNoRows {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, fmt.Errorf("sql auth: find by username: %w", err)
	}

	if err := s.attachOAuthProviders(ctx, &u); err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

// FindAll retrieves all users from the database.
func (s *SQLAuthDatabase) FindAll(ctx context.Context) ([]User, error) {
	query := fmt.Sprintf("SELECT %s FROM %s", sqlUserColumns, s.tableName("users"))

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("sql auth: find all: %w", err)
	}
	defer rows.Close()

	var users []User
	var ids []int64
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("sql auth: scan user: %w", err)
		}
		users = append(users, u)
		id, _ := strconv.ParseInt(u.ID, 10, 64)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sql auth: find all rows: %w", err)
	}
	rows.Close() // close before issuing second query to avoid SQLite single-connection deadlock

	if len(ids) == 0 {
		return users, nil
	}

	providerMap, err := s.loadOAuthProviders(ctx, ids...)
	if err != nil {
		return nil, err
	}
	for i := range users {
		id, _ := strconv.ParseInt(users[i].ID, 10, 64)
		users[i].OAuthProviders = providerMap[id]
	}

	return users, nil
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// sqlCol is a column name / value pair used to build dynamic UPDATE statements.
type sqlCol struct {
	name  string
	value any
}

// UpdateUser updates a user's information in the database.
func (s *SQLAuthDatabase) UpdateUser(ctx context.Context, id string, diff *UserDiff) error {
	if diff == nil {
		return nil
	}

	numID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return fmt.Errorf("sql auth: invalid user id: %w", err)
	}

	var cols []sqlCol

	if diff.Username != nil {
		cols = append(cols, sqlCol{"username", *diff.Username})
	}
	if diff.Roles != nil {
		b, err := stdjson.Marshal(*diff.Roles)
		if err != nil {
			return fmt.Errorf("sql auth: marshal roles: %w", err)
		}
		cols = append(cols, sqlCol{"roles", string(b)})
	}
	if diff.PasswordHash != nil {
		cols = append(cols, sqlCol{"password_hash", *diff.PasswordHash})
	}
	if diff.RefreshTokenHash != nil {
		cols = append(cols, sqlCol{"refresh_token_hash", *diff.RefreshTokenHash})
	}
	if diff.RefreshTokenExpiresAt != nil {
		cols = append(cols, sqlCol{"refresh_token_expires_at", nullableTime(*diff.RefreshTokenExpiresAt)})
	}
	if diff.Email != nil {
		cols = append(cols, sqlCol{"email", *diff.Email})
	}
	if diff.EmailVerified != nil {
		cols = append(cols, sqlCol{"email_verified", *diff.EmailVerified})
	}
	if diff.EmailVerifyTokenHash != nil {
		cols = append(cols, sqlCol{"email_verify_token_hash", *diff.EmailVerifyTokenHash})
	}
	if diff.EmailVerifyTokenExpiresAt != nil {
		cols = append(cols, sqlCol{"email_verify_token_expires_at", nullableTime(*diff.EmailVerifyTokenExpiresAt)})
	}
	if diff.EmailVerifyLastSentAt != nil {
		cols = append(cols, sqlCol{"email_verify_last_sent_at", nullableTime(*diff.EmailVerifyLastSentAt)})
	}
	if diff.PasswordResetTokenHash != nil {
		cols = append(cols, sqlCol{"password_reset_token_hash", *diff.PasswordResetTokenHash})
	}
	if diff.PasswordResetTokenExpiresAt != nil {
		cols = append(cols, sqlCol{"password_reset_token_expires_at", nullableTime(*diff.PasswordResetTokenExpiresAt)})
	}
	if diff.TwoFactorEnabled != nil {
		cols = append(cols, sqlCol{"two_factor_enabled", *diff.TwoFactorEnabled})
	}
	if diff.TwoFactorSecret != nil {
		cols = append(cols, sqlCol{"two_factor_secret", *diff.TwoFactorSecret})
	}
	if diff.TwoFactorBackupCodes != nil {
		b, err := stdjson.Marshal(*diff.TwoFactorBackupCodes)
		if err != nil {
			return fmt.Errorf("sql auth: marshal backup codes: %w", err)
		}
		cols = append(cols, sqlCol{"two_factor_backup_codes", string(b)})
	}

	if len(cols) == 0 && diff.OAuthProviders == nil {
		return nil
	}

	if diff.OAuthProviders == nil {
		return s.execUpdate(ctx, numID, cols)
	}

	return s.execUpdateWithOAuth(ctx, numID, cols, *diff.OAuthProviders)
}

func (s *SQLAuthDatabase) execUpdate(ctx context.Context, numID int64, cols []sqlCol) error {
	if len(cols) == 0 {
		return nil
	}

	setParts := make([]string, len(cols))
	args := make([]any, len(cols))
	for i, c := range cols {
		setParts[i] = fmt.Sprintf("%s = %s", c.name, s.placeholder(i+1))
		args[i] = c.value
	}
	args = append(args, numID)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE id = %s",
		s.tableName("users"),
		strings.Join(setParts, ", "),
		s.placeholder(len(cols)+1),
	)

	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("sql auth: update user: %w", err)
	}
	return nil
}

func (s *SQLAuthDatabase) execUpdateWithOAuth(ctx context.Context, numID int64, cols []sqlCol, providers []OAuthLink) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sql auth: begin tx: %w", err)
	}
	defer tx.Rollback()

	if len(cols) > 0 {
		setParts := make([]string, len(cols))
		args := make([]any, len(cols))
		for i, c := range cols {
			setParts[i] = fmt.Sprintf("%s = %s", c.name, s.placeholder(i+1))
			args[i] = c.value
		}
		args = append(args, numID)

		query := fmt.Sprintf(
			"UPDATE %s SET %s WHERE id = %s",
			s.tableName("users"),
			strings.Join(setParts, ", "),
			s.placeholder(len(cols)+1),
		)

		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("sql auth: update user in tx: %w", err)
		}
	}

	oauthTable := s.tableName("user_oauth_providers")

	deleteQuery := fmt.Sprintf("DELETE FROM %s WHERE user_id = %s", oauthTable, s.placeholder(1))
	if _, err := tx.ExecContext(ctx, deleteQuery, numID); err != nil {
		return fmt.Errorf("sql auth: delete oauth providers: %w", err)
	}

	for _, p := range providers {
		insertQuery := fmt.Sprintf(
			"INSERT INTO %s (user_id, provider, provider_id, email) VALUES (%s)",
			oauthTable,
			s.placeholders(1, 4),
		)
		if _, err := tx.ExecContext(ctx, insertQuery, numID, p.Provider, p.ProviderID, p.Email); err != nil {
			return fmt.Errorf("sql auth: insert oauth provider: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sql auth: commit tx: %w", err)
	}
	return nil
}

// FindByEmail finds a user by their email address. Implements EmailAuthDatabase.
func (s *SQLAuthDatabase) FindByEmail(ctx context.Context, email string) (User, bool, error) {
	if email == "" {
		return User{}, false, nil
	}

	query := fmt.Sprintf(
		"SELECT %s FROM %s WHERE email = %s",
		sqlUserColumns, s.tableName("users"), s.placeholder(1),
	)

	u, err := s.scanUser(s.db.QueryRowContext(ctx, query, email))
	if err == sql.ErrNoRows {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, fmt.Errorf("sql auth: find by email: %w", err)
	}

	if err := s.attachOAuthProviders(ctx, &u); err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

// FindByOAuthProvider finds a user by OAuth provider and provider ID. Implements OAuthAuthDatabase.
func (s *SQLAuthDatabase) FindByOAuthProvider(ctx context.Context, provider string, providerID string) (User, bool, error) {
	usersTable := s.tableName("users")
	oauthTable := s.tableName("user_oauth_providers")

	colParts := strings.Split(sqlUserColumns, ", ")
	aliased := make([]string, len(colParts))
	for i, c := range colParts {
		aliased[i] = "u." + strings.TrimSpace(c)
	}

	query := fmt.Sprintf(
		"SELECT %s FROM %s u JOIN %s p ON u.id = p.user_id WHERE p.provider = %s AND p.provider_id = %s",
		strings.Join(aliased, ", "),
		usersTable,
		oauthTable,
		s.placeholder(1),
		s.placeholder(2),
	)

	u, err := s.scanUser(s.db.QueryRowContext(ctx, query, provider, providerID))
	if err == sql.ErrNoRows {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, fmt.Errorf("sql auth: find by oauth provider: %w", err)
	}

	if err := s.attachOAuthProviders(ctx, &u); err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

// Close closes the underlying database connection if it was opened by servex.
func (s *SQLAuthDatabase) Close() error {
	if s.ownedDB {
		return s.db.Close()
	}
	return nil
}

// DB returns the underlying *sql.DB for direct access.
func (s *SQLAuthDatabase) DB() *sql.DB {
	return s.db
}

// Compile-time interface checks.
var (
	_ AuthDatabase      = (*SQLAuthDatabase)(nil)
	_ EmailAuthDatabase = (*SQLAuthDatabase)(nil)
	_ OAuthAuthDatabase = (*SQLAuthDatabase)(nil)
)
