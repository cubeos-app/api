// Package database provides SQLite database initialization and management.
package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// Open opens or creates a SQLite database at the given path.
func Open(dbPath string) (*sql.DB, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Open database with WAL mode for better concurrency
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", dbPath)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool (SQLite handles this differently but it's good practice)
	db.SetMaxOpenConns(1) // SQLite only supports one writer at a time
	db.SetMaxIdleConns(1)

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Info().Str("path", dbPath).Msg("Database connection established")
	return db, nil
}

// Close closes the database connection.
func Close(db *sql.DB) error {
	if db == nil {
		return nil
	}
	return db.Close()
}
