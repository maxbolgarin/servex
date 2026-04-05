package servex

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestSQLDB(t *testing.T) *SQLAuthDatabase {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	sqlDB, err := NewSQLAuthDatabase(db, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	return sqlDB
}

func ptr[T any](v T) *T { return &v }

// ---------------------------------------------------------------------------
// TestNewSQLAuthDatabase
// ---------------------------------------------------------------------------

func TestNewSQLAuthDatabase(t *testing.T) {
	t.Run("unknown driver returns error", func(t *testing.T) {
		db, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		_, err = NewSQLAuthDatabase(db, "baddriver")
		if err == nil {
			t.Fatal("expected error for unknown driver, got nil")
		}
	})

	t.Run("auto migrate creates tables", func(t *testing.T) {
		sqlDB := newTestSQLDB(t)
		ctx := context.Background()

		// Insert should succeed if table exists.
		_, err := sqlDB.NewUser(ctx, "alice", "hash")
		if err != nil {
			t.Fatalf("insert after auto-migrate failed: %v", err)
		}
	})

	t.Run("SQLAutoMigrate false does not create tables", func(t *testing.T) {
		db, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		sqlDB, err := NewSQLAuthDatabase(db, "sqlite", SQLAutoMigrate(false))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		ctx := context.Background()
		_, err = sqlDB.NewUser(ctx, "alice", "hash")
		if err == nil {
			t.Fatal("expected error when inserting into non-existent table")
		}
	})

	t.Run("SQLTablePrefix creates prefixed tables", func(t *testing.T) {
		db, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		sqlDB, err := NewSQLAuthDatabase(db, "sqlite", SQLTablePrefix("app_"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		ctx := context.Background()
		_, err = sqlDB.NewUser(ctx, "bob", "hash")
		if err != nil {
			t.Fatalf("insert into prefixed table failed: %v", err)
		}

		// Verify the row is in app_users (not users).
		var count int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM app_users").Scan(&count); err != nil {
			t.Fatalf("query app_users: %v", err)
		}
		if count != 1 {
			t.Errorf("expected 1 row in app_users, got %d", count)
		}
	})
}

// ---------------------------------------------------------------------------
// TestSQLNewUserAndFindByID
// ---------------------------------------------------------------------------

func TestSQLNewUserAndFindByID(t *testing.T) {
	ctx := context.Background()
	sqlDB := newTestSQLDB(t)

	id, err := sqlDB.NewUser(ctx, "alice", "hashed", UserRole("admin"), UserRole("user"))
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty ID")
	}

	t.Run("id is numeric string", func(t *testing.T) {
		for _, ch := range id {
			if ch < '0' || ch > '9' {
				t.Errorf("ID %q is not numeric", id)
			}
		}
	})

	t.Run("FindByID returns correct user", func(t *testing.T) {
		u, exists, err := sqlDB.FindByID(ctx, id)
		if err != nil {
			t.Fatalf("FindByID: %v", err)
		}
		if !exists {
			t.Fatal("expected user to exist")
		}
		if u.ID != id {
			t.Errorf("ID: got %q, want %q", u.ID, id)
		}
		if u.Username != "alice" {
			t.Errorf("Username: got %q, want %q", u.Username, "alice")
		}
		if u.PasswordHash != "hashed" {
			t.Errorf("PasswordHash: got %q, want %q", u.PasswordHash, "hashed")
		}
		if len(u.Roles) != 2 {
			t.Errorf("Roles len: got %d, want 2", len(u.Roles))
		}
	})

	t.Run("FindByID non-existent returns false", func(t *testing.T) {
		_, exists, err := sqlDB.FindByID(ctx, "99999")
		if err != nil {
			t.Fatalf("FindByID: %v", err)
		}
		if exists {
			t.Fatal("expected user to not exist")
		}
	})

	t.Run("FindByID non-numeric returns false", func(t *testing.T) {
		_, exists, err := sqlDB.FindByID(ctx, "not-a-number")
		if err != nil {
			t.Fatalf("FindByID: %v", err)
		}
		if exists {
			t.Fatal("expected false for non-numeric ID")
		}
	})

	t.Run("roles preserved on round-trip", func(t *testing.T) {
		u, _, _ := sqlDB.FindByID(ctx, id)
		wantRoles := []UserRole{"admin", "user"}
		if len(u.Roles) != len(wantRoles) {
			t.Fatalf("roles len: got %d, want %d", len(u.Roles), len(wantRoles))
		}
		for i, r := range wantRoles {
			if u.Roles[i] != r {
				t.Errorf("roles[%d]: got %q, want %q", i, u.Roles[i], r)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// TestSQLFindByUsername
// ---------------------------------------------------------------------------

func TestSQLFindByUsername(t *testing.T) {
	ctx := context.Background()
	sqlDB := newTestSQLDB(t)

	_, err := sqlDB.NewUser(ctx, "bob", "hash123")
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}

	t.Run("found", func(t *testing.T) {
		u, exists, err := sqlDB.FindByUsername(ctx, "bob")
		if err != nil {
			t.Fatalf("FindByUsername: %v", err)
		}
		if !exists {
			t.Fatal("expected user to exist")
		}
		if u.Username != "bob" {
			t.Errorf("Username: got %q, want %q", u.Username, "bob")
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, exists, err := sqlDB.FindByUsername(ctx, "nobody")
		if err != nil {
			t.Fatalf("FindByUsername: %v", err)
		}
		if exists {
			t.Fatal("expected user to not exist")
		}
	})
}

// ---------------------------------------------------------------------------
// TestSQLFindAll
// ---------------------------------------------------------------------------

func TestSQLFindAll(t *testing.T) {
	ctx := context.Background()

	t.Run("empty database returns empty slice", func(t *testing.T) {
		sqlDB := newTestSQLDB(t)
		users, err := sqlDB.FindAll(ctx)
		if err != nil {
			t.Fatalf("FindAll: %v", err)
		}
		if len(users) != 0 {
			t.Errorf("expected empty slice, got %d elements", len(users))
		}
	})

	t.Run("returns all users with oauth providers", func(t *testing.T) {
		sqlDB := newTestSQLDB(t)

		ids := make([]string, 3)
		for i := 0; i < 3; i++ {
			id, err := sqlDB.NewUser(ctx, fmt.Sprintf("user%d", i), "hash")
			if err != nil {
				t.Fatalf("NewUser %d: %v", i, err)
			}
			ids[i] = id
		}

		// Add OAuth provider to user 0.
		err := sqlDB.UpdateUser(ctx, ids[0], &UserDiff{
			OAuthProviders: &[]OAuthLink{
				{Provider: "google", ProviderID: "gid1", Email: "u0@g.com"},
			},
		})
		if err != nil {
			t.Fatalf("UpdateUser oauth: %v", err)
		}

		users, err := sqlDB.FindAll(ctx)
		if err != nil {
			t.Fatalf("FindAll: %v", err)
		}
		if len(users) != 3 {
			t.Fatalf("expected 3 users, got %d", len(users))
		}

		var foundWithOAuth bool
		for _, u := range users {
			if u.ID == ids[0] && len(u.OAuthProviders) == 1 {
				foundWithOAuth = true
			}
		}
		if !foundWithOAuth {
			t.Error("expected user 0 to have OAuth provider attached in FindAll")
		}
	})
}

// ---------------------------------------------------------------------------
// TestSQLUpdateUser
// ---------------------------------------------------------------------------

func TestSQLUpdateUser(t *testing.T) {
	ctx := context.Background()

	setup := func(t *testing.T) (*SQLAuthDatabase, string) {
		t.Helper()
		sqlDB := newTestSQLDB(t)
		id, err := sqlDB.NewUser(ctx, "carol", "oldhash", UserRole("user"))
		if err != nil {
			t.Fatalf("NewUser: %v", err)
		}
		return sqlDB, id
	}

	t.Run("nil diff is no-op", func(t *testing.T) {
		sqlDB, id := setup(t)
		if err := sqlDB.UpdateUser(ctx, id, nil); err != nil {
			t.Fatalf("UpdateUser nil: %v", err)
		}
		u, _, _ := sqlDB.FindByID(ctx, id)
		if u.Username != "carol" {
			t.Errorf("Username changed unexpectedly: %q", u.Username)
		}
	})

	t.Run("empty diff is no-op", func(t *testing.T) {
		sqlDB, id := setup(t)
		if err := sqlDB.UpdateUser(ctx, id, &UserDiff{}); err != nil {
			t.Fatalf("UpdateUser empty: %v", err)
		}
		u, _, _ := sqlDB.FindByID(ctx, id)
		if u.Username != "carol" {
			t.Errorf("Username changed unexpectedly: %q", u.Username)
		}
	})

	t.Run("change username", func(t *testing.T) {
		sqlDB, id := setup(t)
		if err := sqlDB.UpdateUser(ctx, id, &UserDiff{Username: ptr("carol2")}); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		u, _, _ := sqlDB.FindByID(ctx, id)
		if u.Username != "carol2" {
			t.Errorf("Username: got %q, want %q", u.Username, "carol2")
		}
	})

	t.Run("change email", func(t *testing.T) {
		sqlDB, id := setup(t)
		if err := sqlDB.UpdateUser(ctx, id, &UserDiff{Email: ptr("carol@example.com")}); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		u, _, _ := sqlDB.FindByID(ctx, id)
		if u.Email != "carol@example.com" {
			t.Errorf("Email: got %q, want %q", u.Email, "carol@example.com")
		}
	})

	t.Run("change roles json round-trip", func(t *testing.T) {
		sqlDB, id := setup(t)
		newRoles := []UserRole{"admin", "moderator"}
		if err := sqlDB.UpdateUser(ctx, id, &UserDiff{Roles: &newRoles}); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		u, _, _ := sqlDB.FindByID(ctx, id)
		if len(u.Roles) != 2 {
			t.Fatalf("Roles len: got %d, want 2", len(u.Roles))
		}
		if u.Roles[0] != "admin" || u.Roles[1] != "moderator" {
			t.Errorf("Roles: got %v, want [admin moderator]", u.Roles)
		}
	})

	t.Run("change password hash", func(t *testing.T) {
		sqlDB, id := setup(t)
		if err := sqlDB.UpdateUser(ctx, id, &UserDiff{PasswordHash: ptr("newhash")}); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		u, _, _ := sqlDB.FindByID(ctx, id)
		if u.PasswordHash != "newhash" {
			t.Errorf("PasswordHash: got %q, want %q", u.PasswordHash, "newhash")
		}
	})

	t.Run("update refresh token fields", func(t *testing.T) {
		sqlDB, id := setup(t)
		expiry := time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second)
		diff := &UserDiff{
			RefreshTokenHash:      ptr("rthash"),
			RefreshTokenExpiresAt: &expiry,
		}
		if err := sqlDB.UpdateUser(ctx, id, diff); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		u, _, _ := sqlDB.FindByID(ctx, id)
		if u.RefreshTokenHash != "rthash" {
			t.Errorf("RefreshTokenHash: got %q, want %q", u.RefreshTokenHash, "rthash")
		}
		if !u.RefreshTokenExpiresAt.Equal(expiry) {
			t.Errorf("RefreshTokenExpiresAt: got %v, want %v", u.RefreshTokenExpiresAt, expiry)
		}
	})

	t.Run("update email verification fields", func(t *testing.T) {
		sqlDB, id := setup(t)
		expiry := time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second)
		sentAt := time.Now().UTC().Truncate(time.Second)
		diff := &UserDiff{
			Email:                     ptr("carol@example.com"),
			EmailVerified:             ptr(true),
			EmailVerifyTokenHash:      ptr("vtkhash"),
			EmailVerifyTokenExpiresAt: &expiry,
			EmailVerifyLastSentAt:     &sentAt,
		}
		if err := sqlDB.UpdateUser(ctx, id, diff); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		u, _, _ := sqlDB.FindByID(ctx, id)
		if u.Email != "carol@example.com" {
			t.Errorf("Email: got %q", u.Email)
		}
		if !u.EmailVerified {
			t.Error("EmailVerified: expected true")
		}
		if u.EmailVerifyTokenHash != "vtkhash" {
			t.Errorf("EmailVerifyTokenHash: got %q", u.EmailVerifyTokenHash)
		}
		if !u.EmailVerifyTokenExpiresAt.Equal(expiry) {
			t.Errorf("EmailVerifyTokenExpiresAt: got %v, want %v", u.EmailVerifyTokenExpiresAt, expiry)
		}
		if !u.EmailVerifyLastSentAt.Equal(sentAt) {
			t.Errorf("EmailVerifyLastSentAt: got %v, want %v", u.EmailVerifyLastSentAt, sentAt)
		}
	})

	t.Run("update password reset fields", func(t *testing.T) {
		sqlDB, id := setup(t)
		expiry := time.Now().Add(1 * time.Hour).UTC().Truncate(time.Second)
		diff := &UserDiff{
			PasswordResetTokenHash:      ptr("prthash"),
			PasswordResetTokenExpiresAt: &expiry,
		}
		if err := sqlDB.UpdateUser(ctx, id, diff); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		u, _, _ := sqlDB.FindByID(ctx, id)
		if u.PasswordResetTokenHash != "prthash" {
			t.Errorf("PasswordResetTokenHash: got %q", u.PasswordResetTokenHash)
		}
		if !u.PasswordResetTokenExpiresAt.Equal(expiry) {
			t.Errorf("PasswordResetTokenExpiresAt: got %v, want %v", u.PasswordResetTokenExpiresAt, expiry)
		}
	})

	t.Run("update 2fa fields", func(t *testing.T) {
		sqlDB, id := setup(t)
		backupCodes := []string{"code1", "code2", "code3"}
		diff := &UserDiff{
			TwoFactorEnabled:     ptr(true),
			TwoFactorSecret:      ptr("totp-secret"),
			TwoFactorBackupCodes: &backupCodes,
		}
		if err := sqlDB.UpdateUser(ctx, id, diff); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		u, _, _ := sqlDB.FindByID(ctx, id)
		if !u.TwoFactorEnabled {
			t.Error("TwoFactorEnabled: expected true")
		}
		if u.TwoFactorSecret != "totp-secret" {
			t.Errorf("TwoFactorSecret: got %q", u.TwoFactorSecret)
		}
		if len(u.TwoFactorBackupCodes) != 3 {
			t.Fatalf("TwoFactorBackupCodes len: got %d, want 3", len(u.TwoFactorBackupCodes))
		}
		for i, c := range backupCodes {
			if u.TwoFactorBackupCodes[i] != c {
				t.Errorf("TwoFactorBackupCodes[%d]: got %q, want %q", i, u.TwoFactorBackupCodes[i], c)
			}
		}
	})

	t.Run("update non-existent user is no-op without error", func(t *testing.T) {
		sqlDB := newTestSQLDB(t)
		err := sqlDB.UpdateUser(ctx, "99999", &UserDiff{Username: ptr("ghost")})
		if err != nil {
			t.Fatalf("UpdateUser on non-existent: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TestSQLUpdateUserOAuth
// ---------------------------------------------------------------------------

func TestSQLUpdateUserOAuth(t *testing.T) {
	ctx := context.Background()

	t.Run("add oauth providers and verify on FindByID", func(t *testing.T) {
		sqlDB := newTestSQLDB(t)
		id, err := sqlDB.NewUser(ctx, "dave", "hash")
		if err != nil {
			t.Fatalf("NewUser: %v", err)
		}

		providers := []OAuthLink{
			{Provider: "google", ProviderID: "gid1", Email: "dave@gmail.com"},
			{Provider: "github", ProviderID: "ghid1", Email: "dave@github.com"},
		}
		if err := sqlDB.UpdateUser(ctx, id, &UserDiff{OAuthProviders: &providers}); err != nil {
			t.Fatalf("UpdateUser oauth: %v", err)
		}

		u, exists, err := sqlDB.FindByID(ctx, id)
		if err != nil || !exists {
			t.Fatalf("FindByID: err=%v, exists=%v", err, exists)
		}
		if len(u.OAuthProviders) != 2 {
			t.Fatalf("OAuthProviders len: got %d, want 2", len(u.OAuthProviders))
		}
	})

	t.Run("update replaces old providers", func(t *testing.T) {
		sqlDB := newTestSQLDB(t)
		id, _ := sqlDB.NewUser(ctx, "eve", "hash")

		first := []OAuthLink{{Provider: "google", ProviderID: "gid1", Email: "eve@g.com"}}
		if err := sqlDB.UpdateUser(ctx, id, &UserDiff{OAuthProviders: &first}); err != nil {
			t.Fatalf("UpdateUser first: %v", err)
		}

		second := []OAuthLink{{Provider: "github", ProviderID: "ghid2", Email: "eve@gh.com"}}
		if err := sqlDB.UpdateUser(ctx, id, &UserDiff{OAuthProviders: &second}); err != nil {
			t.Fatalf("UpdateUser second: %v", err)
		}

		u, _, _ := sqlDB.FindByID(ctx, id)
		if len(u.OAuthProviders) != 1 {
			t.Fatalf("OAuthProviders len: got %d, want 1", len(u.OAuthProviders))
		}
		if u.OAuthProviders[0].Provider != "github" {
			t.Errorf("Provider: got %q, want %q", u.OAuthProviders[0].Provider, "github")
		}
	})

	t.Run("empty providers list deletes all", func(t *testing.T) {
		sqlDB := newTestSQLDB(t)
		id, _ := sqlDB.NewUser(ctx, "frank", "hash")

		providers := []OAuthLink{{Provider: "google", ProviderID: "gid", Email: "f@g.com"}}
		sqlDB.UpdateUser(ctx, id, &UserDiff{OAuthProviders: &providers})

		empty := []OAuthLink{}
		if err := sqlDB.UpdateUser(ctx, id, &UserDiff{OAuthProviders: &empty}); err != nil {
			t.Fatalf("UpdateUser empty: %v", err)
		}

		u, _, _ := sqlDB.FindByID(ctx, id)
		if len(u.OAuthProviders) != 0 {
			t.Errorf("expected 0 providers, got %d", len(u.OAuthProviders))
		}
	})

	t.Run("oauth update combined with other fields", func(t *testing.T) {
		sqlDB := newTestSQLDB(t)
		id, _ := sqlDB.NewUser(ctx, "grace", "hash")

		providers := []OAuthLink{{Provider: "google", ProviderID: "gid", Email: "grace@g.com"}}
		diff := &UserDiff{
			Email:          ptr("grace@example.com"),
			OAuthProviders: &providers,
		}
		if err := sqlDB.UpdateUser(ctx, id, diff); err != nil {
			t.Fatalf("UpdateUser combined: %v", err)
		}

		u, _, _ := sqlDB.FindByID(ctx, id)
		if u.Email != "grace@example.com" {
			t.Errorf("Email: got %q", u.Email)
		}
		if len(u.OAuthProviders) != 1 {
			t.Errorf("OAuthProviders len: got %d, want 1", len(u.OAuthProviders))
		}
	})
}

// ---------------------------------------------------------------------------
// TestSQLFindByEmail
// ---------------------------------------------------------------------------

func TestSQLFindByEmail(t *testing.T) {
	ctx := context.Background()
	sqlDB := newTestSQLDB(t)

	id, _ := sqlDB.NewUser(ctx, "hank", "hash")
	sqlDB.UpdateUser(ctx, id, &UserDiff{Email: ptr("hank@example.com")})

	t.Run("found by email", func(t *testing.T) {
		u, exists, err := sqlDB.FindByEmail(ctx, "hank@example.com")
		if err != nil {
			t.Fatalf("FindByEmail: %v", err)
		}
		if !exists {
			t.Fatal("expected user to exist")
		}
		if u.Username != "hank" {
			t.Errorf("Username: got %q", u.Username)
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, exists, err := sqlDB.FindByEmail(ctx, "nobody@example.com")
		if err != nil {
			t.Fatalf("FindByEmail: %v", err)
		}
		if exists {
			t.Fatal("expected user to not exist")
		}
	})

	t.Run("empty email returns not found", func(t *testing.T) {
		// FindByEmail("") should return false to prevent matching users without email.
		sqlDB2 := newTestSQLDB(t)
		sqlDB2.NewUser(ctx, "noemail", "hash")
		_, exists, err := sqlDB2.FindByEmail(ctx, "")
		if err != nil {
			t.Fatalf("FindByEmail empty: %v", err)
		}
		if exists {
			t.Fatal("expected FindByEmail('') to return not found")
		}
	})
}

// ---------------------------------------------------------------------------
// TestSQLFindByOAuthProvider
// ---------------------------------------------------------------------------

func TestSQLFindByOAuthProvider(t *testing.T) {
	ctx := context.Background()
	sqlDB := newTestSQLDB(t)

	id, _ := sqlDB.NewUser(ctx, "ivan", "hash")
	providers := []OAuthLink{
		{Provider: "google", ProviderID: "ivan-gid", Email: "ivan@g.com"},
	}
	if err := sqlDB.UpdateUser(ctx, id, &UserDiff{OAuthProviders: &providers}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	t.Run("found", func(t *testing.T) {
		u, exists, err := sqlDB.FindByOAuthProvider(ctx, "google", "ivan-gid")
		if err != nil {
			t.Fatalf("FindByOAuthProvider: %v", err)
		}
		if !exists {
			t.Fatal("expected user to exist")
		}
		if u.Username != "ivan" {
			t.Errorf("Username: got %q", u.Username)
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, exists, err := sqlDB.FindByOAuthProvider(ctx, "github", "nonexistent")
		if err != nil {
			t.Fatalf("FindByOAuthProvider: %v", err)
		}
		if exists {
			t.Fatal("expected user to not exist")
		}
	})
}

// ---------------------------------------------------------------------------
// TestSQLCreateTablesIdempotent
// ---------------------------------------------------------------------------

func TestSQLCreateTablesIdempotent(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	sqlDB, err := NewSQLAuthDatabase(db, "sqlite")
	if err != nil {
		t.Fatalf("first NewSQLAuthDatabase: %v", err)
	}

	// Call createTables a second time — should not error.
	if err := sqlDB.createTables(ctx); err != nil {
		t.Fatalf("second createTables: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestSQLTablePrefix
// ---------------------------------------------------------------------------

func TestSQLTablePrefix(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	sqlDB, err := NewSQLAuthDatabase(db, "sqlite", SQLTablePrefix("myapp_"))
	if err != nil {
		t.Fatalf("NewSQLAuthDatabase: %v", err)
	}

	id, err := sqlDB.NewUser(ctx, "judy", "hash")
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}

	t.Run("users in myapp_users", func(t *testing.T) {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM myapp_users").Scan(&count); err != nil {
			t.Fatalf("query myapp_users: %v", err)
		}
		if count != 1 {
			t.Errorf("expected 1 row in myapp_users, got %d", count)
		}
	})

	t.Run("oauth in myapp_user_oauth_providers", func(t *testing.T) {
		providers := []OAuthLink{{Provider: "google", ProviderID: "jgid", Email: "j@g.com"}}
		if err := sqlDB.UpdateUser(ctx, id, &UserDiff{OAuthProviders: &providers}); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}

		var count int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM myapp_user_oauth_providers").Scan(&count); err != nil {
			t.Fatalf("query myapp_user_oauth_providers: %v", err)
		}
		if count != 1 {
			t.Errorf("expected 1 row in myapp_user_oauth_providers, got %d", count)
		}
	})
}

// ---------------------------------------------------------------------------
// TestSQLCloseAndDB
// ---------------------------------------------------------------------------

func TestSQLCloseAndDB(t *testing.T) {
	t.Run("Close on non-owned DB does nothing", func(t *testing.T) {
		db, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}

		sqlDB, err := NewSQLAuthDatabase(db, "sqlite")
		if err != nil {
			t.Fatalf("NewSQLAuthDatabase: %v", err)
		}

		// ownedDB is false — Close should return nil without closing db.
		if err := sqlDB.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		// db should still be usable.
		if err := db.Ping(); err != nil {
			t.Errorf("db.Ping after Close: %v", err)
		}
		db.Close()
	})

	t.Run("DB returns underlying sql.DB", func(t *testing.T) {
		sqlDB := newTestSQLDB(t)
		underlying := sqlDB.DB()
		if underlying == nil {
			t.Fatal("expected non-nil *sql.DB")
		}
		if err := underlying.Ping(); err != nil {
			t.Fatalf("Ping on returned DB: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TestSQLDialectNormalization
// ---------------------------------------------------------------------------

func TestSQLDialectNormalization(t *testing.T) {
	recognized := []string{"sqlite", "sqlite3", "mattn/go-sqlite3", "postgres", "pgx", "postgresql", "pgx/v5", "mysql"}

	for _, driver := range recognized {
		t.Run("recognized_"+driver, func(t *testing.T) {
			_, err := normalizeDialect(driver)
			if err != nil {
				t.Errorf("normalizeDialect(%q): unexpected error: %v", driver, err)
			}
		})
	}

	t.Run("unrecognized returns error", func(t *testing.T) {
		_, err := normalizeDialect("oracle")
		if err == nil {
			t.Error("expected error for unrecognized driver, got nil")
		}
	})
}
