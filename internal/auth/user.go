package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	// ErrUserNotFound is returned when a user is not found.
	ErrUserNotFound = errors.New("user not found")
	// ErrUserExists is returned when trying to create a user that already exists.
	ErrUserExists = errors.New("user already exists")
	// ErrInvalidCredentials is returned when login credentials are invalid.
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// User represents a user in the system.
type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"` // Never expose in JSON
	Email        string    `json:"email,omitempty"`
	IsAdmin      bool      `json:"is_admin"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

// UserService handles user-related database operations.
type UserService struct {
	db *sql.DB
}

// NewUserService creates a new user service with the given database connection.
func NewUserService(db *sql.DB) *UserService {
	return &UserService{db: db}
}

// InitSchema creates the users table if it doesn't exist.
func (s *UserService) InitSchema(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		email TEXT,
		is_admin BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	`
	_, err := s.db.ExecContext(ctx, query)
	return err
}

// CreateUser creates a new user with the given credentials.
func (s *UserService) CreateUser(ctx context.Context, username, password string, isAdmin bool) (*User, error) {
	// Check if user already exists
	existing, _ := s.GetByUsername(ctx, username)
	if existing != nil {
		return nil, ErrUserExists
	}

	// Hash password
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	// Insert user
	query := `
	INSERT INTO users (username, password_hash, is_admin, created_at, updated_at)
	VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`
	result, err := s.db.ExecContext(ctx, query, username, hash, isAdmin)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return s.GetByID(ctx, id)
}

// GetByID retrieves a user by their ID.
func (s *UserService) GetByID(ctx context.Context, id int64) (*User, error) {
	query := `
	SELECT id, username, password_hash, email, is_admin, created_at, updated_at, last_login_at
	FROM users WHERE id = ?
	`
	user := &User{}
	var email sql.NullString
	var lastLogin sql.NullTime

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&email,
		&user.IsAdmin,
		&user.CreatedAt,
		&user.UpdatedAt,
		&lastLogin,
	)
	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	if email.Valid {
		user.Email = email.String
	}
	if lastLogin.Valid {
		user.LastLoginAt = &lastLogin.Time
	}

	return user, nil
}

// GetByUsername retrieves a user by their username.
func (s *UserService) GetByUsername(ctx context.Context, username string) (*User, error) {
	query := `
	SELECT id, username, password_hash, email, is_admin, created_at, updated_at, last_login_at
	FROM users WHERE username = ?
	`
	user := &User{}
	var email sql.NullString
	var lastLogin sql.NullTime

	err := s.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&email,
		&user.IsAdmin,
		&user.CreatedAt,
		&user.UpdatedAt,
		&lastLogin,
	)
	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	if email.Valid {
		user.Email = email.String
	}
	if lastLogin.Valid {
		user.LastLoginAt = &lastLogin.Time
	}

	return user, nil
}

// Authenticate validates user credentials and returns the user if valid.
func (s *UserService) Authenticate(ctx context.Context, username, password string) (*User, error) {
	user, err := s.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if err := CheckPassword(password, user.PasswordHash); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Update last login time
	_, _ = s.db.ExecContext(ctx, "UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", user.ID)

	return user, nil
}

// UpdatePassword changes a user's password.
func (s *UserService) UpdatePassword(ctx context.Context, userID int64, newPassword string) error {
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	query := `UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	result, err := s.db.ExecContext(ctx, query, hash, userID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrUserNotFound
	}

	return nil
}

// UserCount returns the number of users in the database.
func (s *UserService) UserCount(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

// EnsureAdminExists creates the default admin user if no users exist.
func (s *UserService) EnsureAdminExists(ctx context.Context, defaultPassword string) (*User, error) {
	count, err := s.UserCount(ctx)
	if err != nil {
		return nil, err
	}

	if count > 0 {
		// Users exist, return the admin
		return s.GetByUsername(ctx, "admin")
	}

	// No users, create default admin
	return s.CreateUser(ctx, "admin", defaultPassword, true)
}
