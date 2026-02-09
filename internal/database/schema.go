// Package database provides SQLite database initialization and management.
package database

import (
	"database/sql"
	"fmt"

	"github.com/rs/zerolog/log"
)

// CurrentSchemaVersion tracks the database schema version for migrations.
const CurrentSchemaVersion = 12

// Schema defines the unified CubeOS database schema.
// Design Principles:
// 1. Swarm is Truth - Container running state comes from Swarm, not DB
// 2. DB stores Config - Database stores what *should* be running, not what *is* running
// 3. Single App Table - No more apps vs installed_apps confusion
// 4. Referential Integrity - Foreign keys enforced, cascading deletes
// 5. Audit Trail - Created/updated timestamps on all tables
const Schema = `
-- =============================================================================
-- APPS: Unified application registry
-- =============================================================================
CREATE TABLE IF NOT EXISTS apps (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT UNIQUE NOT NULL,           -- Stack name (lowercase, no spaces)
    display_name    TEXT NOT NULL,                  -- Human-readable name
    description     TEXT DEFAULT '',
    
    -- Classification
    type            TEXT NOT NULL DEFAULT 'user',   -- 'system' | 'platform' | 'network' | 'ai' | 'user'
    category        TEXT DEFAULT 'other',           -- 'infrastructure' | 'media' | 'productivity' | etc.
    source          TEXT DEFAULT 'custom',          -- 'cubeos' | 'casaos' | 'custom'
    store_id        TEXT DEFAULT NULL,              -- Reference to app store (if installed from store)
    store_app_id    TEXT DEFAULT NULL,              -- Store catalog app ID (for updates)
    
    -- Paths
    compose_path    TEXT NOT NULL,                  -- /cubeos/{core}apps/{name}/appconfig/docker-compose.yml
    data_path       TEXT DEFAULT '',                -- /cubeos/{core}apps/{name}/appdata
    
    -- State (desired, not actual)
    enabled         BOOLEAN DEFAULT TRUE,           -- Should start on boot
    
    -- Networking
    tor_enabled     BOOLEAN DEFAULT FALSE,          -- Route through Tor
    vpn_enabled     BOOLEAN DEFAULT FALSE,          -- Route through VPN
    
    -- Deployment mode
    deploy_mode     TEXT DEFAULT 'stack',           -- 'stack' (Swarm) or 'compose' (host network)
    
    -- Web UI behavior
    webui_type      TEXT DEFAULT 'browser',         -- 'browser' (open in new tab) or 'api' (show status modal)
    
    -- Metadata
    icon_url        TEXT DEFAULT '',
    version         TEXT DEFAULT '',
    homepage        TEXT DEFAULT '',
    
    -- Timestamps
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_apps_name ON apps(name);
CREATE INDEX IF NOT EXISTS idx_apps_type ON apps(type);
CREATE INDEX IF NOT EXISTS idx_apps_enabled ON apps(enabled);

-- =============================================================================
-- PORT_ALLOCATIONS: Track assigned ports per app
-- Port scheme: 
--   6000-6009: Infrastructure (NPM, Pi-hole)
--   6010-6019: Platform (API, Dashboard, Dozzle)
--   6020-6029: Network (WireGuard, OpenVPN, Tor)
--   6030-6039: AI/ML (Ollama, ChromaDB)
--   6100-6999: User applications
-- =============================================================================
CREATE TABLE IF NOT EXISTS port_allocations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id          INTEGER NOT NULL,
    port            INTEGER NOT NULL,
    protocol        TEXT DEFAULT 'tcp',             -- 'tcp' | 'udp'
    description     TEXT DEFAULT '',                -- 'Web UI' | 'API' | etc.
    is_primary      BOOLEAN DEFAULT FALSE,          -- Main access port for the app
    
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE,
    UNIQUE(port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_ports_app ON port_allocations(app_id);
CREATE INDEX IF NOT EXISTS idx_ports_port ON port_allocations(port);

-- =============================================================================
-- FQDNS: DNS entries and reverse proxy mappings
-- =============================================================================
CREATE TABLE IF NOT EXISTS fqdns (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id          INTEGER NOT NULL,
    fqdn            TEXT UNIQUE NOT NULL,           -- filebrowser.cubeos.cube
    subdomain       TEXT NOT NULL,                  -- filebrowser
    backend_port    INTEGER NOT NULL,               -- Port to proxy to
    ssl_enabled     BOOLEAN DEFAULT FALSE,          -- HTTPS enabled
    npm_proxy_id    INTEGER DEFAULT NULL,           -- NPM proxy host ID
    
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_fqdns_app ON fqdns(app_id);
CREATE INDEX IF NOT EXISTS idx_fqdns_subdomain ON fqdns(subdomain);

-- =============================================================================
-- PROFILES: Service profiles (Full, Minimal, Offline, Custom)
-- =============================================================================
CREATE TABLE IF NOT EXISTS profiles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT UNIQUE NOT NULL,
    display_name    TEXT NOT NULL,
    description     TEXT DEFAULT '',
    is_active       BOOLEAN DEFAULT FALSE,          -- Only one can be active
    is_system       BOOLEAN DEFAULT FALSE,          -- System profiles can't be deleted
    
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- PROFILE_APPS: Which apps are enabled in each profile
-- =============================================================================
CREATE TABLE IF NOT EXISTS profile_apps (
    profile_id      INTEGER NOT NULL,
    app_id          INTEGER NOT NULL,
    enabled         BOOLEAN DEFAULT TRUE,
    
    PRIMARY KEY (profile_id, app_id),
    FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_profile_apps_profile ON profile_apps(profile_id);

-- =============================================================================
-- SYSTEM_STATE: System-wide state and flags
-- =============================================================================
CREATE TABLE IF NOT EXISTS system_state (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- APP_HEALTH: Health check configuration per app
-- =============================================================================
CREATE TABLE IF NOT EXISTS app_health (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id          INTEGER UNIQUE NOT NULL,
    
    -- Health check settings
    check_endpoint  TEXT DEFAULT '',                -- HTTP endpoint to check
    check_interval  INTEGER DEFAULT 30,             -- Seconds between checks
    check_timeout   INTEGER DEFAULT 10,             -- Seconds before timeout
    max_retries     INTEGER DEFAULT 3,              -- Retries before marking unhealthy
    
    -- Alert settings
    alert_after     INTEGER DEFAULT 300,            -- Seconds unhealthy before alert
    
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
);

-- =============================================================================
-- NETWORK_CONFIG: Network mode and WiFi settings
-- =============================================================================
CREATE TABLE IF NOT EXISTS network_config (
    id              INTEGER PRIMARY KEY CHECK (id = 1),  -- Single row
    mode            TEXT DEFAULT 'offline',         -- 'offline' | 'online_eth' | 'online_wifi' | 'server_eth' | 'server_wifi'
    
    -- VPN overlay (V2)
    vpn_mode        TEXT DEFAULT 'none',            -- 'none' | 'wireguard' | 'openvpn' | 'tor'
    vpn_config_id   INTEGER DEFAULT NULL,           -- FK to vpn_configs (nullable)
    
    -- WiFi client credentials (for online_wifi and server_wifi)
    wifi_ssid       TEXT DEFAULT '',                -- Upstream WiFi SSID
    wifi_password   TEXT DEFAULT '',                -- Encrypted or reference to secrets.env
    
    -- Interfaces
    eth_interface   TEXT DEFAULT 'eth0',
    wifi_ap_interface TEXT DEFAULT 'wlan0',
    wifi_client_interface TEXT DEFAULT 'wlan1',     -- USB dongle
    
    -- DHCP server configuration (for AP modes)
    gateway_ip      TEXT DEFAULT '10.42.24.1',
    subnet          TEXT DEFAULT '10.42.24.0/24',
    dhcp_range_start TEXT DEFAULT '10.42.24.10',
    dhcp_range_end  TEXT DEFAULT '10.42.24.250',
    
    -- Server mode fallback
    fallback_static_ip TEXT DEFAULT '192.168.1.242',
    
    -- Access Point configuration
    ap_ssid         TEXT DEFAULT 'CubeOS',
    ap_password     TEXT DEFAULT '',
    ap_channel      INTEGER DEFAULT 7,
    ap_hidden       BOOLEAN DEFAULT FALSE,
    
    -- UX state
    server_mode_warning_dismissed BOOLEAN DEFAULT FALSE,
    
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- VPN_CONFIGS: VPN configuration profiles
-- =============================================================================
CREATE TABLE IF NOT EXISTS vpn_configs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT UNIQUE NOT NULL,
    type            TEXT NOT NULL,                  -- 'wireguard' | 'openvpn'
    config_path     TEXT NOT NULL,                  -- Path to config file
    is_active       BOOLEAN DEFAULT FALSE,          -- Currently connected
    auto_connect    BOOLEAN DEFAULT FALSE,          -- Connect on boot
    
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- MOUNTS: SMB/NFS mount configurations
-- =============================================================================
CREATE TABLE IF NOT EXISTS mounts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT UNIQUE NOT NULL,           -- Mount point name
    type            TEXT NOT NULL,                  -- 'smb' | 'nfs'
    remote_path     TEXT NOT NULL,                  -- //server/share or server:/path
    local_path      TEXT NOT NULL,                  -- /cubeos/mounts/{name}
    username        TEXT DEFAULT '',                -- For SMB
    password        TEXT DEFAULT '',                -- Encrypted or reference
    options         TEXT DEFAULT '',                -- Mount options
    auto_mount      BOOLEAN DEFAULT FALSE,          -- Mount on boot
    is_mounted      BOOLEAN DEFAULT FALSE,          -- Current state
    
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- BACKUPS: Backup job configurations
-- =============================================================================
CREATE TABLE IF NOT EXISTS backups (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT UNIQUE NOT NULL,
    destination     TEXT NOT NULL,                  -- Mount name or path
    include_apps    TEXT DEFAULT '*',               -- JSON array or '*' for all
    schedule        TEXT DEFAULT '',                -- Cron expression
    retention_days  INTEGER DEFAULT 30,
    last_run        DATETIME,
    last_status     TEXT DEFAULT '',
    
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- USERS: Authentication
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    email           TEXT DEFAULT '',                -- Optional email address
    role            TEXT DEFAULT 'admin',           -- 'admin' | 'user' | 'readonly'
    last_login      DATETIME,                      -- Last successful login
    
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- =============================================================================
-- PREFERENCES: User/system preferences
-- =============================================================================
CREATE TABLE IF NOT EXISTS preferences (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- NODES: For future multi-node Swarm support
-- =============================================================================
CREATE TABLE IF NOT EXISTS nodes (
    id              TEXT PRIMARY KEY,               -- Docker node ID
    hostname        TEXT NOT NULL,
    role            TEXT DEFAULT 'worker',          -- 'manager' | 'worker'
    status          TEXT DEFAULT 'unknown',         -- 'ready' | 'down' | 'unknown'
    ip_address      TEXT,
    
    joined_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- SETTINGS: Key-value settings (legacy, used by main.go initDB)
-- =============================================================================
CREATE TABLE IF NOT EXISTS settings (
    key             TEXT PRIMARY KEY,
    value           TEXT,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- SERVICE_STATES: Enabled/disabled state for system services
-- =============================================================================
CREATE TABLE IF NOT EXISTS service_states (
    name            TEXT PRIMARY KEY,
    enabled         BOOLEAN DEFAULT TRUE,
    reason          TEXT,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- APP_STORES: Registered app store sources
-- =============================================================================
CREATE TABLE IF NOT EXISTS app_stores (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    url             TEXT NOT NULL UNIQUE,
    description     TEXT,
    author          TEXT,
    app_count       INTEGER DEFAULT 0,
    last_sync       DATETIME,
    enabled         INTEGER DEFAULT 1,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- APP_CATALOG: Cached app store catalog entries
-- =============================================================================
CREATE TABLE IF NOT EXISTS app_catalog (
    id              TEXT PRIMARY KEY,               -- composite: store_id/app_name
    store_id        TEXT NOT NULL,
    name            TEXT NOT NULL,
    title           TEXT DEFAULT '',
    description     TEXT DEFAULT '',
    icon_url        TEXT DEFAULT '',
    category        TEXT DEFAULT '',
    version         TEXT DEFAULT '',
    architectures   TEXT DEFAULT '[]',              -- JSON array of supported archs
    manifest_path   TEXT DEFAULT '',
    cached_at       DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (store_id) REFERENCES app_stores(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_app_catalog_store ON app_catalog(store_id);

-- =============================================================================
-- VOLUME_MAPPINGS: Track per-app volume mount remappings
-- =============================================================================
CREATE TABLE IF NOT EXISTS volume_mappings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id          INTEGER NOT NULL,
    container_path  TEXT NOT NULL,           -- mount target inside container (e.g., /movies)
    original_host_path TEXT NOT NULL,        -- path from manifest (e.g., /DATA/Media/Movies)
    current_host_path TEXT NOT NULL,         -- actual path on host (e.g., /cubeos/apps/bazarr/appdata/movies)
    description     TEXT DEFAULT '',         -- human-readable label (e.g., "Movies")
    is_remapped     BOOLEAN DEFAULT FALSE,   -- TRUE if we changed it from original
    is_config       BOOLEAN DEFAULT FALSE,   -- TRUE if config-like mount (/config, /data)
    read_only       BOOLEAN DEFAULT FALSE,   -- TRUE if mount is read-only
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE,
    UNIQUE(app_id, container_path)
);

CREATE INDEX IF NOT EXISTS idx_volume_mappings_app ON volume_mappings(app_id);

-- =============================================================================
-- SETUP_STATUS: First-boot setup wizard state
-- =============================================================================
CREATE TABLE IF NOT EXISTS setup_status (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    is_complete     INTEGER DEFAULT 0,
    current_step    INTEGER DEFAULT 0,
    started_at      DATETIME,
    completed_at    DATETIME,
    config_json     TEXT
);

-- =============================================================================
-- SYSTEM_CONFIG: System configuration key-value store (setup manager)
-- =============================================================================
CREATE TABLE IF NOT EXISTS system_config (
    key             TEXT PRIMARY KEY,
    value           TEXT,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);
`

// SeedData contains initial data for the database.
const SeedData = `
-- =============================================================================
-- DEFAULT PROFILES
-- =============================================================================
INSERT OR IGNORE INTO profiles (name, display_name, description, is_system, is_active) VALUES
    ('full', 'Full', 'All services enabled including AI/ML', TRUE, TRUE),
    ('minimal', 'Minimal', 'Only essential infrastructure services', TRUE, FALSE),
    ('offline', 'Offline', 'Optimized for air-gapped operation', TRUE, FALSE);

-- =============================================================================
-- SYSTEM STATE DEFAULTS
-- =============================================================================
INSERT OR IGNORE INTO system_state (key, value) VALUES
    ('setup_complete', 'false'),
    ('swarm_initialized', 'false'),
    ('last_boot', ''),
    ('version', '2.0.0'),
    ('domain', 'cubeos.cube'),
    ('gateway_ip', '10.42.24.1'),
    ('subnet', '10.42.24.0/24'),
    ('schema_version', '10');

-- =============================================================================
-- DEFAULT NETWORK CONFIG
-- =============================================================================
INSERT OR IGNORE INTO network_config (id, mode) VALUES (1, 'offline');

-- =============================================================================
-- SETUP STATUS
-- =============================================================================
INSERT OR IGNORE INTO setup_status (id, is_complete, current_step) VALUES (1, 0, 0);
`

// InitSchema initializes the database schema.
// This is idempotent - safe to call multiple times.
func InitSchema(db *sql.DB) error {
	log.Info().Msg("Initializing database schema...")

	// Execute schema creation
	if _, err := db.Exec(Schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	// Execute seed data
	if _, err := db.Exec(SeedData); err != nil {
		return fmt.Errorf("failed to seed data: %w", err)
	}

	log.Info().Msg("Database schema initialized successfully")
	return nil
}

// GetSchemaVersion returns the current schema version from the database.
func GetSchemaVersion(db *sql.DB) (int, error) {
	var version int
	err := db.QueryRow("SELECT CAST(value AS INTEGER) FROM system_state WHERE key = 'schema_version'").Scan(&version)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	return version, nil
}

// SetSchemaVersion updates the schema version in the database.
func SetSchemaVersion(db *sql.DB, version int) error {
	_, err := db.Exec("INSERT OR REPLACE INTO system_state (key, value, updated_at) VALUES ('schema_version', ?, CURRENT_TIMESTAMP)", version)
	return err
}

// GetSystemState retrieves a system state value by key.
func GetSystemState(db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRow("SELECT value FROM system_state WHERE key = ?", key).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return value, nil
}

// SetSystemState sets a system state value.
func SetSystemState(db *sql.DB, key, value string) error {
	_, err := db.Exec("INSERT OR REPLACE INTO system_state (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)", key, value)
	return err
}
