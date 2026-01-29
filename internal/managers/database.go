package managers

import (
	"database/sql"
)

// DatabaseManager is a simple wrapper around *sql.DB
type DatabaseManager struct {
	db *sql.DB
}

// NewDatabaseManager creates a new database manager
func NewDatabaseManager(db *sql.DB) *DatabaseManager {
	return &DatabaseManager{db: db}
}

// DB returns the underlying database connection
func (m *DatabaseManager) DB() *sql.DB {
	return m.db
}

// Exec executes a query without returning results
func (m *DatabaseManager) Exec(query string, args ...interface{}) (sql.Result, error) {
	return m.db.Exec(query, args...)
}

// Query executes a query that returns rows
func (m *DatabaseManager) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return m.db.Query(query, args...)
}

// QueryRow executes a query that returns a single row
func (m *DatabaseManager) QueryRow(query string, args ...interface{}) *sql.Row {
	return m.db.QueryRow(query, args...)
}
