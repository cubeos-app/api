// Package database provides SQLite database initialization and management.
package database

import (
	"database/sql"
	"fmt"
	"strings"

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

	// Version 2: Add missing columns from Sprint 2 unified schema
	{
		Version:     2,
		Description: "Add Sprint 2 unified schema columns to apps table",
		Up: func(db *sql.DB) error {
			// Add columns one by one, ignoring errors if they already exist
			columns := []struct {
				name         string
				definition   string
				defaultValue string
			}{
				{"category", "TEXT", "'other'"},
				{"data_path", "TEXT", "''"},
				{"store_id", "TEXT", "NULL"},
				{"tor_enabled", "BOOLEAN", "FALSE"},
				{"vpn_enabled", "BOOLEAN", "FALSE"},
				{"version", "TEXT", "''"},
				{"homepage", "TEXT", "''"},
				{"deploy_mode", "TEXT", "'stack'"},
			}

			for _, col := range columns {
				query := fmt.Sprintf("ALTER TABLE apps ADD COLUMN %s %s DEFAULT %s",
					col.name, col.definition, col.defaultValue)
				_, err := db.Exec(query)
				if err != nil {
					// Ignore "duplicate column name" errors
					if !isDuplicateColumnError(err) {
						return fmt.Errorf("failed to add column %s: %w", col.name, err)
					}
					log.Debug().Str("column", col.name).Msg("Column already exists, skipping")
				}
			}
			return nil
		},
	},

	// Version 3: Set correct deploy_mode for host-network services
	{
		Version:     3,
		Description: "Set deploy_mode=compose for pihole and npm (host network)",
		Up: func(db *sql.DB) error {
			_, err := db.Exec(`
				UPDATE apps SET deploy_mode = 'compose' 
				WHERE name IN ('pihole', 'npm')
			`)
			return err
		},
	},

	// Version 4: Rename api/dashboard to cubeos-api/cubeos-dashboard
	{
		Version:     4,
		Description: "Rename api/dashboard to match Swarm stack names",
		Up: func(db *sql.DB) error {
			// Update api -> cubeos-api
			_, err := db.Exec(`UPDATE apps SET name = 'cubeos-api' WHERE name = 'api'`)
			if err != nil {
				return err
			}

			// Update dashboard -> cubeos-dashboard
			_, err = db.Exec(`UPDATE apps SET name = 'cubeos-dashboard' WHERE name = 'dashboard'`)
			return err
		},
	},

	// Version 5: Ensure core system apps exist with correct settings
	{
		Version:     5,
		Description: "Seed/update core system apps",
		Up: func(db *sql.DB) error {
			systemApps := []struct {
				name        string
				displayName string
				appType     string
				category    string
				port        int
				deployMode  string
				description string
			}{
				{"pihole", "Pi-hole", "system", "infrastructure", 6001, "compose", "DNS and DHCP server"},
				{"npm", "Nginx Proxy Manager", "system", "infrastructure", 6000, "compose", "Reverse proxy manager"},
				{"registry", "Docker Registry", "system", "infrastructure", 5000, "stack", "Local Docker registry"},
				{"cubeos-api", "CubeOS API", "platform", "core", 6010, "stack", "CubeOS backend API"},
				{"cubeos-dashboard", "CubeOS Dashboard", "platform", "core", 6011, "stack", "CubeOS web interface"},
				{"dozzle", "Dozzle", "platform", "monitoring", 6012, "stack", "Container log viewer"},
				{"ollama", "Ollama", "ai", "ai", 6030, "stack", "Local LLM server"},
				{"chromadb", "ChromaDB", "ai", "ai", 6031, "stack", "Vector database"},
			}

			for _, sa := range systemApps {
				composePath := fmt.Sprintf("/cubeos/coreapps/%s/appconfig/docker-compose.yml", sa.name)
				dataPath := fmt.Sprintf("/cubeos/coreapps/%s/appdata", sa.name)

				// Use INSERT OR REPLACE to handle both new installs and updates
				_, err := db.Exec(`
					INSERT INTO apps (name, display_name, description, type, category, 
						compose_path, data_path, enabled, deploy_mode)
					VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, ?)
					ON CONFLICT(name) DO UPDATE SET
						display_name = excluded.display_name,
						description = excluded.description,
						type = excluded.type,
						category = excluded.category,
						compose_path = excluded.compose_path,
						data_path = excluded.data_path,
						deploy_mode = excluded.deploy_mode,
						updated_at = CURRENT_TIMESTAMP
				`, sa.name, sa.displayName, sa.description, sa.appType, sa.category,
					composePath, dataPath, sa.deployMode)
				if err != nil {
					return fmt.Errorf("failed to upsert %s: %w", sa.name, err)
				}

				// Ensure port allocation exists
				var appID int64
				err = db.QueryRow("SELECT id FROM apps WHERE name = ?", sa.name).Scan(&appID)
				if err != nil {
					continue
				}

				_, err = db.Exec(`
					INSERT INTO port_allocations (app_id, port, protocol, description, is_primary)
					VALUES (?, ?, 'tcp', 'Web UI', TRUE)
					ON CONFLICT DO NOTHING
				`, appID, sa.port)
				if err != nil {
					log.Warn().Str("app", sa.name).Err(err).Msg("Failed to insert port allocation")
				}

				// Ensure FQDN exists
				fqdn := fmt.Sprintf("%s.cubeos.cube", sa.name)
				_, err = db.Exec(`
					INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port)
					VALUES (?, ?, ?, ?)
					ON CONFLICT DO NOTHING
				`, appID, fqdn, sa.name, sa.port)
				if err != nil {
					log.Warn().Str("app", sa.name).Err(err).Msg("Failed to insert FQDN")
				}
			}

			return nil
		},
	},

	// Version 6: Clean up stale/removed apps
	{
		Version:     6,
		Description: "Remove deprecated apps from database",
		Up: func(db *sql.DB) error {
			deprecatedApps := []string{
				"dockge",
				"terminal",
				"watchdog",
				"docs-indexer",
				"homarr",
				"terminal-ro",
				"usb-monitor",
				"logs",
				"api",       // Old name, replaced by cubeos-api
				"dashboard", // Old name, replaced by cubeos-dashboard
			}

			for _, name := range deprecatedApps {
				// Delete related records first (in case cascade isn't working)
				db.Exec("DELETE FROM fqdns WHERE app_id IN (SELECT id FROM apps WHERE name = ?)", name)
				db.Exec("DELETE FROM port_allocations WHERE app_id IN (SELECT id FROM apps WHERE name = ?)", name)
				db.Exec("DELETE FROM profile_apps WHERE app_id IN (SELECT id FROM apps WHERE name = ?)", name)
				db.Exec("DELETE FROM apps WHERE name = ?", name)
			}

			return nil
		},
	},

	// Version 7: Create default profiles if they don't exist
	{
		Version:     7,
		Description: "Ensure default profiles exist",
		Up: func(db *sql.DB) error {
			profiles := []struct {
				name        string
				displayName string
				description string
				isSystem    bool
			}{
				{"full", "Full", "All services enabled", true},
				{"minimal", "Minimal", "Only essential services (Pi-hole, NPM, API, Dashboard)", true},
				{"offline", "Offline", "Optimized for offline/air-gapped operation", true},
			}

			for _, p := range profiles {
				_, err := db.Exec(`
					INSERT INTO profiles (name, display_name, description, is_system, is_active)
					VALUES (?, ?, ?, ?, FALSE)
					ON CONFLICT(name) DO NOTHING
				`, p.name, p.displayName, p.description, p.isSystem)
				if err != nil {
					return fmt.Errorf("failed to insert profile %s: %w", p.name, err)
				}
			}

			// Set 'full' as active if no profile is active
			var activeCount int
			db.QueryRow("SELECT COUNT(*) FROM profiles WHERE is_active = TRUE").Scan(&activeCount)
			if activeCount == 0 {
				db.Exec("UPDATE profiles SET is_active = TRUE WHERE name = 'full'")
			}

			return nil
		},
	},

	// Version 8: Add is_primary column to port_allocations if missing
	// This handles databases created before the column was added to schema.go
	{
		Version:     8,
		Description: "Add is_primary column to port_allocations table",
		Up: func(db *sql.DB) error {
			_, err := db.Exec(`ALTER TABLE port_allocations ADD COLUMN is_primary BOOLEAN DEFAULT FALSE`)
			if err != nil {
				// Ignore if column already exists (manual fix or new install)
				if isDuplicateColumnError(err) {
					log.Debug().Msg("is_primary column already exists, skipping")
					return nil
				}
				return fmt.Errorf("failed to add is_primary column: %w", err)
			}
			log.Info().Msg("Added is_primary column to port_allocations")
			return nil
		},
	},

	// Version 9: Add missing network_config columns + users table columns
	// The NetworkManager queries 12+ columns that weren't in the original schema
	{
		Version:     9,
		Description: "Add missing network_config columns (VPN, DHCP, AP) and users columns (email, last_login)",
		Up: func(db *sql.DB) error {
			// network_config columns needed by NetworkManager
			netColumns := []struct {
				name         string
				definition   string
				defaultValue string
			}{
				{"vpn_mode", "TEXT", "'none'"},
				{"vpn_config_id", "INTEGER", "NULL"},
				{"gateway_ip", "TEXT", "'10.42.24.1'"},
				{"subnet", "TEXT", "'10.42.24.0/24'"},
				{"dhcp_range_start", "TEXT", "'10.42.24.10'"},
				{"dhcp_range_end", "TEXT", "'10.42.24.250'"},
				{"fallback_static_ip", "TEXT", "'192.168.1.242'"},
				{"ap_ssid", "TEXT", "'CubeOS'"},
				{"ap_password", "TEXT", "''"},
				{"ap_channel", "INTEGER", "7"},
				{"ap_hidden", "BOOLEAN", "FALSE"},
				{"server_mode_warning_dismissed", "BOOLEAN", "FALSE"},
			}

			for _, col := range netColumns {
				query := fmt.Sprintf("ALTER TABLE network_config ADD COLUMN %s %s DEFAULT %s",
					col.name, col.definition, col.defaultValue)
				_, err := db.Exec(query)
				if err != nil && !isDuplicateColumnError(err) {
					return fmt.Errorf("failed to add network_config.%s: %w", col.name, err)
				}
			}

			// users table columns needed by setup.go and models.User
			usersColumns := []struct {
				name         string
				definition   string
				defaultValue string
			}{
				{"email", "TEXT", "''"},
				{"last_login", "DATETIME", "NULL"},
			}

			for _, col := range usersColumns {
				query := fmt.Sprintf("ALTER TABLE users ADD COLUMN %s %s DEFAULT %s",
					col.name, col.definition, col.defaultValue)
				_, err := db.Exec(query)
				if err != nil && !isDuplicateColumnError(err) {
					return fmt.Errorf("failed to add users.%s: %w", col.name, err)
				}
			}

			// Ensure all new tables exist (for databases created before schema.go included them)
			newTables := []string{
				`CREATE TABLE IF NOT EXISTS settings (
					key TEXT PRIMARY KEY, value TEXT, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
				`CREATE TABLE IF NOT EXISTS service_states (
					name TEXT PRIMARY KEY, enabled BOOLEAN DEFAULT TRUE, reason TEXT, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
				`CREATE TABLE IF NOT EXISTS app_stores (
					id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL UNIQUE, description TEXT,
					author TEXT, app_count INTEGER DEFAULT 0, last_sync DATETIME, enabled INTEGER DEFAULT 1,
					created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
				`CREATE TABLE IF NOT EXISTS installed_apps (
					id TEXT PRIMARY KEY, store_id TEXT, store_app_id TEXT, name TEXT NOT NULL,
					title TEXT, description TEXT, icon TEXT, category TEXT, version TEXT,
					status TEXT DEFAULT 'stopped', webui TEXT, compose_file TEXT, data_path TEXT,
					npm_proxy_id INTEGER DEFAULT 0, installed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
					updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
				`CREATE INDEX IF NOT EXISTS idx_installed_apps_name ON installed_apps(name)`,
				`CREATE TABLE IF NOT EXISTS setup_status (
					id INTEGER PRIMARY KEY CHECK (id = 1), is_complete INTEGER DEFAULT 0,
					current_step INTEGER DEFAULT 0, started_at DATETIME, completed_at DATETIME, config_json TEXT)`,
				`CREATE TABLE IF NOT EXISTS system_config (
					key TEXT PRIMARY KEY, value TEXT, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
			}

			for _, q := range newTables {
				if _, err := db.Exec(q); err != nil {
					log.Warn().Err(err).Msg("Failed to create table in migration 9")
				}
			}

			// Seed setup_status if empty
			db.Exec(`INSERT OR IGNORE INTO setup_status (id, is_complete, current_step) VALUES (1, 0, 0)`)

			log.Info().Msg("Migration 9: Added missing network_config, users columns, and new tables")
			return nil
		},
	},

	// Version 10: Unify installed_apps into apps table, add app_catalog
	{
		Version:     10,
		Description: "Migrate installed_apps into unified apps table, add app_catalog",
		Up: func(db *sql.DB) error {
			// Step 1: Add store_app_id column to apps if missing
			_, err := db.Exec(`ALTER TABLE apps ADD COLUMN store_app_id TEXT DEFAULT NULL`)
			if err != nil && !isDuplicateColumnError(err) {
				return fmt.Errorf("failed to add apps.store_app_id: %w", err)
			}

			// Step 2: Migrate rows from installed_apps → apps (if installed_apps exists)
			var tableExists int
			err = db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='installed_apps'`).Scan(&tableExists)
			if err != nil {
				return fmt.Errorf("failed to check for installed_apps table: %w", err)
			}

			if tableExists > 0 {
				// Copy installed_apps rows into apps table, mapping columns:
				//   installed_apps.name          → apps.name
				//   installed_apps.title          → apps.display_name
				//   installed_apps.description    → apps.description
				//   installed_apps.icon           → apps.icon_url
				//   installed_apps.category       → apps.category
				//   installed_apps.version        → apps.version
				//   installed_apps.compose_file   → apps.compose_path
				//   installed_apps.data_path      → apps.data_path
				//   installed_apps.store_id       → apps.store_id
				//   installed_apps.store_app_id   → apps.store_app_id
				//   installed_apps.webui          → apps.homepage
				//   installed_apps.deploy_mode    → apps.deploy_mode
				//   installed_apps.installed_at   → apps.created_at
				//   installed_apps.updated_at     → apps.updated_at
				// Fields NOT migrated:
				//   installed_apps.status         → Swarm is truth (runtime only)
				//   installed_apps.npm_proxy_id   → Tracked per-FQDN in fqdns table
				_, err = db.Exec(`
					INSERT OR IGNORE INTO apps (
						name, display_name, description, type, category, source,
						store_id, store_app_id, compose_path, data_path,
						enabled, deploy_mode, icon_url, version, homepage,
						created_at, updated_at
					)
					SELECT
						ia.name,
						COALESCE(ia.title, ia.name),
						COALESCE(ia.description, ''),
						'user',
						COALESCE(ia.category, 'other'),
						'casaos',
						ia.store_id,
						ia.store_app_id,
						COALESCE(ia.compose_file, ''),
						COALESCE(ia.data_path, ''),
						TRUE,
						COALESCE(ia.deploy_mode, 'stack'),
						COALESCE(ia.icon, ''),
						COALESCE(ia.version, ''),
						COALESCE(ia.webui, ''),
						COALESCE(ia.installed_at, CURRENT_TIMESTAMP),
						COALESCE(ia.updated_at, CURRENT_TIMESTAMP)
					FROM installed_apps ia
					WHERE ia.name NOT IN (SELECT name FROM apps)
				`)
				if err != nil {
					log.Warn().Err(err).Msg("Migration 10: Failed to migrate installed_apps rows (non-fatal)")
				}

				// Migrate npm_proxy_id to fqdns table where possible
				rows, err := db.Query(`
					SELECT ia.name, ia.npm_proxy_id 
					FROM installed_apps ia 
					WHERE ia.npm_proxy_id > 0
				`)
				if err == nil {
					defer rows.Close()
					for rows.Next() {
						var name string
						var npmID int
						if rows.Scan(&name, &npmID) == nil {
							db.Exec(`
								UPDATE fqdns SET npm_proxy_id = ? 
								WHERE app_id = (SELECT id FROM apps WHERE name = ?)
								AND npm_proxy_id IS NULL
							`, npmID, name)
						}
					}
				}

				// Step 3: Drop installed_apps table
				_, err = db.Exec(`DROP TABLE IF EXISTS installed_apps`)
				if err != nil {
					log.Warn().Err(err).Msg("Migration 10: Failed to drop installed_apps (non-fatal)")
				}
			}

			// Step 4: Create app_catalog table for store caching
			_, err = db.Exec(`
				CREATE TABLE IF NOT EXISTS app_catalog (
					id              TEXT PRIMARY KEY,
					store_id        TEXT NOT NULL,
					name            TEXT NOT NULL,
					title           TEXT DEFAULT '',
					description     TEXT DEFAULT '',
					icon_url        TEXT DEFAULT '',
					category        TEXT DEFAULT '',
					version         TEXT DEFAULT '',
					architectures   TEXT DEFAULT '[]',
					manifest_path   TEXT DEFAULT '',
					cached_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
					FOREIGN KEY (store_id) REFERENCES app_stores(id) ON DELETE CASCADE
				)
			`)
			if err != nil {
				return fmt.Errorf("failed to create app_catalog table: %w", err)
			}

			_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_app_catalog_store ON app_catalog(store_id)`)
			if err != nil {
				log.Warn().Err(err).Msg("Migration 10: Failed to create app_catalog index")
			}

			log.Info().Msg("Migration 10: Unified installed_apps into apps table, created app_catalog")
			return nil
		},
	},

	// Version 11: Add volume_mappings table for tracking bind mount remappings
	{
		Version:     11,
		Description: "Add volume_mappings table for app volume management",
		Up: func(db *sql.DB) error {
			_, err := db.Exec(`
				CREATE TABLE IF NOT EXISTS volume_mappings (
					id              INTEGER PRIMARY KEY AUTOINCREMENT,
					app_id          INTEGER NOT NULL,
					container_path  TEXT NOT NULL,
					original_host_path TEXT NOT NULL,
					current_host_path TEXT NOT NULL,
					description     TEXT DEFAULT '',
					is_remapped     BOOLEAN DEFAULT FALSE,
					is_config       BOOLEAN DEFAULT FALSE,
					read_only       BOOLEAN DEFAULT FALSE,
					created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
					updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
					FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE,
					UNIQUE(app_id, container_path)
				)
			`)
			if err != nil {
				return fmt.Errorf("failed to create volume_mappings table: %w", err)
			}

			_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_volume_mappings_app ON volume_mappings(app_id)`)
			if err != nil {
				log.Warn().Err(err).Msg("Migration 11: Failed to create volume_mappings index")
			}

			log.Info().Msg("Migration 11: Created volume_mappings table")
			return nil
		},
	},
	{
		Version:     12,
		Description: "Add webui_type column to apps table for UI click behavior",
		Up: func(db *sql.DB) error {
			_, err := db.Exec(`ALTER TABLE apps ADD COLUMN webui_type TEXT DEFAULT 'browser'`)
			if err != nil && !isDuplicateColumnError(err) {
				return fmt.Errorf("failed to add webui_type column: %w", err)
			}
			log.Info().Msg("Migration 12: Added webui_type column to apps table")
			return nil
		},
	},

	// Version 13: Add npm_proxy_id column to fqdns table
	// Fixes silent INSERT failure when install pipeline tried to store npm_proxy_id
	{
		Version:     13,
		Description: "Add npm_proxy_id column to fqdns table",
		Up: func(db *sql.DB) error {
			_, err := db.Exec(`ALTER TABLE fqdns ADD COLUMN npm_proxy_id INTEGER DEFAULT NULL`)
			if err != nil && !isDuplicateColumnError(err) {
				return fmt.Errorf("failed to add npm_proxy_id column: %w", err)
			}
			log.Info().Msg("Migration 13: Added npm_proxy_id column to fqdns table")
			return nil
		},
	},

	// Version 14: Add static IP columns to network_config (Network Modes Batch 3 — T11)
	// Allows per-mode static IP override on the upstream interface instead of DHCP.
	{
		Version:     14,
		Description: "Add static IP columns to network_config for upstream interface override",
		Up: func(db *sql.DB) error {
			columns := []struct {
				name         string
				definition   string
				defaultValue string
			}{
				{"use_static_ip", "BOOLEAN", "FALSE"},
				{"static_ip_address", "TEXT", "''"},
				{"static_ip_netmask", "TEXT", "'255.255.255.0'"},
				{"static_ip_gateway", "TEXT", "''"},
				{"static_dns_primary", "TEXT", "''"},
				{"static_dns_secondary", "TEXT", "''"},
			}

			for _, col := range columns {
				query := fmt.Sprintf("ALTER TABLE network_config ADD COLUMN %s %s DEFAULT %s",
					col.name, col.definition, col.defaultValue)
				_, err := db.Exec(query)
				if err != nil && !isDuplicateColumnError(err) {
					return fmt.Errorf("failed to add network_config.%s: %w", col.name, err)
				}
			}

			log.Info().Msg("Migration 14: Added static IP columns to network_config")
			return nil
		},
	},

	// Version 15: Add schema_migrations table for proper migration tracking (T1.5)
	{
		Version:     15,
		Description: "Add schema_migrations table for migration audit trail",
		Up: func(db *sql.DB) error {
			_, err := db.Exec(`
				CREATE TABLE IF NOT EXISTS schema_migrations (
					version         INTEGER PRIMARY KEY,
					description     TEXT NOT NULL DEFAULT '',
					applied_at      DATETIME DEFAULT CURRENT_TIMESTAMP
				)
			`)
			if err != nil {
				return fmt.Errorf("failed to create schema_migrations table: %w", err)
			}

			// Backfill previously applied migrations (hardcoded to avoid
			// referencing the migrations slice, which causes an init cycle)
			backfill := []struct {
				version int
				desc    string
			}{
				{2, "Add Sprint 2 unified schema columns to apps table"},
				{3, "Set deploy_mode=compose for pihole and npm (host network)"},
				{4, "Rename api/dashboard to match Swarm stack names"},
				{5, "Seed/update core system apps"},
				{6, "Remove deprecated apps from database"},
				{7, "Ensure default profiles exist"},
				{8, "Add is_primary column to port_allocations table"},
				{9, "Add missing network_config columns (VPN, DHCP, AP) and users columns (email, last_login)"},
				{10, "Migrate installed_apps into unified apps table, add app_catalog"},
				{11, "Add volume_mappings table for app volume management"},
				{12, "Add webui_type column to apps table for UI click behavior"},
				{13, "Add npm_proxy_id column to fqdns table"},
				{14, "Add static IP columns to network_config for upstream interface override"},
				{15, "Add schema_migrations table for migration audit trail"},
			}
			for _, b := range backfill {
				db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, description) VALUES (?, ?)`,
					b.version, b.desc)
			}

			log.Info().Msg("Migration 15: Created schema_migrations table with backfill")
			return nil
		},
	},
}

// isDuplicateColumnError checks if an error is a "duplicate column" error
func isDuplicateColumnError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return contains(errStr, "duplicate column") || contains(errStr, "already exists")
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// Migrate runs all pending database migrations.
// It's safe to call this multiple times - it only runs migrations
// that haven't been applied yet.
func Migrate(db *sql.DB) error {
	currentVersion, err := GetSchemaVersion(db)
	if err != nil {
		return fmt.Errorf("failed to get schema version: %w", err)
	}

	targetVersion := CurrentSchemaVersion
	if len(migrations) > 0 && migrations[len(migrations)-1].Version > targetVersion {
		targetVersion = migrations[len(migrations)-1].Version
	}

	log.Info().Int("current_version", currentVersion).Int("target_version", targetVersion).Msg("Checking migrations")

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

		// Record migration in schema_migrations table (T1.5, best-effort)
		db.Exec(`INSERT OR IGNORE INTO schema_migrations (version, description) VALUES (?, ?)`,
			m.Version, m.Description)

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
		"volume_mappings",
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
		"settings",
		"service_states",
		"app_stores",
		"app_catalog",
		"setup_status",
		"system_config",
		"schema_migrations",
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
// tableName is validated against sqlite_master to prevent SQL injection.
func GetTableCount(db *sql.DB, tableName string) (int, error) {
	// Validate table exists (prevents SQL injection via table name)
	exists, err := TableExists(db, tableName)
	if err != nil {
		return 0, fmt.Errorf("failed to validate table %q: %w", tableName, err)
	}
	if !exists {
		return 0, fmt.Errorf("table %q does not exist", tableName)
	}

	var count int
	// Safe: tableName validated against sqlite_master above
	err = db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %q", tableName)).Scan(&count)
	return count, err
}
