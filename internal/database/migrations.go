// Package database provides SQLite database initialization and management.
package database

import (
	"database/sql"
	"fmt"

	"github.com/rs/zerolog/log"
)

// Migration represents a database migration.
type Migration struct {
	Version     int
	Description string
	Up          func(db *sql.DB) error
}

// migrations contains all database migrations in order.
// Add new migrations to the end of this slice.
var migrations = []Migration{
	// Version 1 is the initial schema, created by InitSchema()
	// Future migrations go here:
	// {
	//     Version:     2,
	//     Description: "Add new column to apps table",
	//     Up: func(db *sql.DB) error {
	//         _, err := db.Exec("ALTER TABLE apps ADD COLUMN new_field TEXT DEFAULT ''")
	//         return err
	//     },
	// },
}

// Migrate runs all pending database migrations.
// It's safe to call this multiple times - it only runs migrations
// that haven't been applied yet.
func Migrate(db *sql.DB) error {
	currentVersion, err := GetSchemaVersion(db)
	if err != nil {
		return fmt.Errorf("failed to get schema version: %w", err)
	}

	log.Info().Int("current_version", currentVersion).Int("target_version", CurrentSchemaVersion).Msg("Checking migrations")

	// Run each migration that hasn't been applied
	for _, m := range migrations {
		if m.Version <= currentVersion {
			continue
		}

		log.Info().Int("version", m.Version).Str("description", m.Description).Msg("Running migration")

		if err := m.Up(db); err != nil {
			return fmt.Errorf("migration %d failed: %w", m.Version, err)
		}

		if err := SetSchemaVersion(db, m.Version); err != nil {
			return fmt.Errorf("failed to update schema version after migration %d: %w", m.Version, err)
		}

		log.Info().Int("version", m.Version).Msg("Migration completed")
	}

	return nil
}

// MigrateAndSeed runs migrations and ensures seed data exists.
// This is the main entry point for database initialization on startup.
func MigrateAndSeed(db *sql.DB) error {
	// First, ensure the schema exists
	if err := InitSchema(db); err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	// Then run any pending migrations
	if err := Migrate(db); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

// DropAllTables drops all tables in the database.
// WARNING: This is destructive and should only be used for testing/reset.
func DropAllTables(db *sql.DB) error {
	tables := []string{
		"profile_apps",
		"port_allocations",
		"fqdns",
		"app_health",
		"profiles",
		"apps",
		"system_state",
		"network_config",
		"vpn_configs",
		"mounts",
		"backups",
		"users",
		"preferences",
		"nodes",
	}

	for _, table := range tables {
		if _, err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", table)); err != nil {
			return fmt.Errorf("failed to drop table %s: %w", table, err)
		}
	}

	log.Warn().Msg("All tables dropped")
	return nil
}

// ResetDatabase drops all tables and reinitializes the schema.
// WARNING: This is destructive and should only be used for factory reset.
func ResetDatabase(db *sql.DB) error {
	if err := DropAllTables(db); err != nil {
		return err
	}

	if err := MigrateAndSeed(db); err != nil {
		return err
	}

	log.Info().Msg("Database reset complete")
	return nil
}

// CheckIntegrity runs SQLite integrity check on the database.
func CheckIntegrity(db *sql.DB) error {
	var result string
	err := db.QueryRow("PRAGMA integrity_check").Scan(&result)
	if err != nil {
		return fmt.Errorf("integrity check failed: %w", err)
	}

	if result != "ok" {
		return fmt.Errorf("database integrity check failed: %s", result)
	}

	return nil
}

// Vacuum runs VACUUM on the database to reclaim space.
func Vacuum(db *sql.DB) error {
	_, err := db.Exec("VACUUM")
	return err
}

// TableExists checks if a table exists in the database.
func TableExists(db *sql.DB, tableName string) (bool, error) {
	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&name)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetTableCount returns the number of rows in a table.
func GetTableCount(db *sql.DB, tableName string) (int, error) {
	var count int
	err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)).Scan(&count)
	return count, err
}
