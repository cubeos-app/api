package managers

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"cubeos-api/internal/models"
	_ "modernc.org/sqlite"
)

// =============================================================================
// PORT MANAGER TESTS
// =============================================================================

// TestPortConstants verifies the port allocation scheme.
func TestPortConstants(t *testing.T) {
	tests := []struct {
		name     string
		got      int
		expected int
	}{
		{"SSH", PortSSH, 22},
		{"DNS", PortDNS, 53},
		{"DHCP", PortDHCP, 67},
		{"HTTP", PortHTTP, 80},
		{"HTTPS", PortHTTPS, 443},
		{"Registry", PortRegistry, 5000},
		{"NPM", PortNPM, 6000},
		{"Pi-hole", PortPihole, 6001},
		{"API", PortAPI, 6010},
		{"Dashboard", PortDashboard, 6011},
		{"Dozzle", PortDozzle, 6012},
		{"WireGuard", PortWireGuard, 6020},
		{"OpenVPN", PortOpenVPN, 6021},
		{"Tor", PortTor, 6022},
		{"Ollama", PortOllama, 6030},
		{"ChromaDB", PortChromaDB, 6031},
		{"UserPortMin", UserPortMin, 6100},
		{"UserPortMax", UserPortMax, 6999},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("expected %s port %d, got %d", tt.name, tt.expected, tt.got)
			}
		})
	}
}

// TestReservedPorts verifies reserved ports are defined.
func TestReservedPorts(t *testing.T) {
	requiredPorts := []int{22, 53, 67, 80, 443, 5000, 6000, 6001, 6010, 6011, 6012, 6020, 6021, 6022, 6030, 6031}

	for _, port := range requiredPorts {
		if _, ok := ReservedSystemPorts[port]; !ok {
			t.Errorf("port %d should be reserved", port)
		}
	}
}

// TestPortManagerWithDB tests PortManager with in-memory database.
func TestPortManagerWithDB(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	// Create minimal schema
	_, err = db.Exec(`
		CREATE TABLE apps (id INTEGER PRIMARY KEY, name TEXT);
		CREATE TABLE port_allocations (
			id INTEGER PRIMARY KEY,
			app_id INTEGER,
			port INTEGER UNIQUE,
			protocol TEXT DEFAULT 'tcp',
			description TEXT,
			is_primary BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	pm := NewPortManager(db)

	// Test first allocation
	port1, err := pm.AllocateUserPort()
	if err != nil {
		t.Fatalf("failed to allocate first port: %v", err)
	}
	if port1 != UserPortMin {
		t.Errorf("expected first port %d, got %d", UserPortMin, port1)
	}

	// Simulate Orchestrator.InstallApp() behavior: insert allocation into database
	// This is what happens in real usage - AllocateUserPort finds the port,
	// then the caller inserts it when creating the app
	_, err = db.Exec(`INSERT INTO port_allocations (app_id, port, protocol, is_primary) VALUES (1, ?, 'tcp', TRUE)`, port1)
	if err != nil {
		t.Fatalf("failed to insert allocation: %v", err)
	}

	// Test second allocation - should return next port
	port2, err := pm.AllocateUserPort()
	if err != nil {
		t.Fatalf("failed to allocate second port: %v", err)
	}
	if port2 != UserPortMin+1 {
		t.Errorf("expected second port %d, got %d", UserPortMin+1, port2)
	}
}

// TestPortManagerExhaustion tests behavior when all ports are allocated.
func TestPortManagerExhaustion(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE port_allocations (
			id INTEGER PRIMARY KEY,
			app_id INTEGER,
			port INTEGER UNIQUE,
			protocol TEXT DEFAULT 'tcp'
		);
	`)
	if err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	// Fill up all user ports
	for port := UserPortMin; port <= UserPortMax; port++ {
		_, err = db.Exec(`INSERT INTO port_allocations (app_id, port) VALUES (?, ?)`, port-UserPortMin+1, port)
		if err != nil {
			t.Fatalf("failed to insert port %d: %v", port, err)
		}
	}

	pm := NewPortManager(db)

	// Should fail - no ports available
	_, err = pm.AllocateUserPort()
	if err == nil {
		t.Error("expected error when all ports exhausted")
	}
}

// TestValidatePortScheme tests port scheme validation.
func TestValidatePortScheme(t *testing.T) {
	tests := []struct {
		port    int
		appType string
		wantErr bool
	}{
		// Valid cases
		{6100, "user", false},
		{6500, "user", false},
		{6999, "user", false},
		{6001, "system", false},
		{6010, "platform", false},
		{6020, "network", false},
		{6030, "ai", false},

		// Invalid cases
		{6001, "user", true},  // System port for user app
		{80, "user", true},    // HTTP port for user app
		{7000, "user", true},  // Outside user range
		{6050, "user", true},  // Reserved range
		{5999, "user", true},  // Below all ranges
		{10000, "user", true}, // Way above range
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			err := ValidatePortScheme(tt.port, tt.appType)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePortScheme(%d, %s) error = %v, wantErr %v", tt.port, tt.appType, err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// DATABASE SCHEMA TESTS
// =============================================================================

// TestSchemaCreation tests that schema can be created and tables exist.
func TestSchemaCreation(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	// Create full schema
	schema := `
		CREATE TABLE IF NOT EXISTS apps (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			description TEXT DEFAULT '',
			type TEXT NOT NULL DEFAULT 'user',
			category TEXT DEFAULT 'other',
			source TEXT DEFAULT 'custom',
			store_id TEXT DEFAULT NULL,
			compose_path TEXT NOT NULL,
			data_path TEXT DEFAULT '',
			enabled BOOLEAN DEFAULT TRUE,
			deploy_mode TEXT DEFAULT 'stack',
			tor_enabled BOOLEAN DEFAULT FALSE,
			vpn_enabled BOOLEAN DEFAULT FALSE,
			icon_url TEXT DEFAULT '',
			version TEXT DEFAULT '',
			homepage TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS port_allocations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			app_id INTEGER NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT DEFAULT 'tcp',
			description TEXT DEFAULT '',
			is_primary BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE,
			UNIQUE(port, protocol)
		);

		CREATE TABLE IF NOT EXISTS fqdns (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			app_id INTEGER NOT NULL,
			fqdn TEXT UNIQUE NOT NULL,
			subdomain TEXT NOT NULL,
			backend_port INTEGER NOT NULL,
			ssl_enabled BOOLEAN DEFAULT FALSE,
			npm_proxy_id INTEGER DEFAULT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS profiles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			description TEXT DEFAULT '',
			is_active BOOLEAN DEFAULT FALSE,
			is_system BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS profile_apps (
			profile_id INTEGER NOT NULL,
			app_id INTEGER NOT NULL,
			enabled BOOLEAN DEFAULT TRUE,
			PRIMARY KEY (profile_id, app_id),
			FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
			FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS system_state (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS network_config (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			mode TEXT DEFAULT 'offline',
			wifi_ssid TEXT DEFAULT '',
			wifi_password TEXT DEFAULT '',
			eth_interface TEXT DEFAULT 'eth0',
			wifi_ap_interface TEXT DEFAULT 'wlan0',
			wifi_client_interface TEXT DEFAULT 'wlan1',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS app_health (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			app_id INTEGER UNIQUE NOT NULL,
			check_endpoint TEXT DEFAULT '',
			check_interval INTEGER DEFAULT 30,
			check_timeout INTEGER DEFAULT 10,
			max_retries INTEGER DEFAULT 3,
			alert_after INTEGER DEFAULT 300,
			FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS vpn_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			type TEXT NOT NULL,
			config_path TEXT NOT NULL,
			is_active BOOLEAN DEFAULT FALSE,
			auto_connect BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS mounts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			type TEXT NOT NULL,
			remote_path TEXT NOT NULL,
			local_path TEXT NOT NULL,
			username TEXT DEFAULT '',
			password TEXT DEFAULT '',
			options TEXT DEFAULT '',
			auto_mount BOOLEAN DEFAULT FALSE,
			is_mounted BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS backups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			destination TEXT NOT NULL,
			include_apps TEXT DEFAULT '*',
			schedule TEXT DEFAULT '',
			retention_days INTEGER DEFAULT 30,
			last_run DATETIME,
			last_status TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			email TEXT DEFAULT '',
			role TEXT DEFAULT 'admin',
			last_login DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS preferences (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS nodes (
			id TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			role TEXT DEFAULT 'worker',
			status TEXT DEFAULT 'unknown',
			ip_address TEXT,
			joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`

	_, err = db.Exec(schema)
	if err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	// Verify tables exist
	tables := []string{"apps", "port_allocations", "fqdns", "profiles", "profile_apps", "system_state", "network_config", "app_health", "vpn_configs", "mounts", "backups", "users", "preferences", "nodes"}
	for _, table := range tables {
		var name string
		err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Errorf("table %s should exist: %v", table, err)
		}
	}
}

// TestAppCRUD tests basic app create, read, update, delete operations.
func TestAppCRUD(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	ctx := context.Background()

	// Create app
	result, err := db.ExecContext(ctx, `
		INSERT INTO apps (name, display_name, type, compose_path)
		VALUES (?, ?, ?, ?)
	`, "test-app", "Test App", "user", "/cubeos/apps/test-app/appconfig/docker-compose.yml")
	if err != nil {
		t.Fatalf("failed to insert app: %v", err)
	}

	appID, _ := result.LastInsertId()

	// Read app
	var app struct {
		ID          int64
		Name        string
		DisplayName string
		Type        string
	}
	err = db.QueryRowContext(ctx, `SELECT id, name, display_name, type FROM apps WHERE id = ?`, appID).
		Scan(&app.ID, &app.Name, &app.DisplayName, &app.Type)
	if err != nil {
		t.Fatalf("failed to read app: %v", err)
	}
	if app.Name != "test-app" {
		t.Errorf("expected name 'test-app', got '%s'", app.Name)
	}

	// Update app
	_, err = db.ExecContext(ctx, `UPDATE apps SET display_name = ? WHERE id = ?`, "Updated Test App", appID)
	if err != nil {
		t.Fatalf("failed to update app: %v", err)
	}

	// Verify update
	var displayName string
	err = db.QueryRowContext(ctx, `SELECT display_name FROM apps WHERE id = ?`, appID).Scan(&displayName)
	if err != nil {
		t.Fatalf("failed to read updated app: %v", err)
	}
	if displayName != "Updated Test App" {
		t.Errorf("expected display_name 'Updated Test App', got '%s'", displayName)
	}

	// Delete app
	_, err = db.ExecContext(ctx, `DELETE FROM apps WHERE id = ?`, appID)
	if err != nil {
		t.Fatalf("failed to delete app: %v", err)
	}

	// Verify deletion
	var count int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM apps WHERE id = ?`, appID).Scan(&count)
	if count != 0 {
		t.Error("app should be deleted")
	}
}

// TestCascadeDelete tests that deleting an app cascades to related tables.
func TestCascadeDelete(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	ctx := context.Background()

	// Create app
	result, _ := db.ExecContext(ctx, `
		INSERT INTO apps (name, display_name, type, compose_path)
		VALUES ('cascade-test', 'Cascade Test', 'user', '/path/compose.yml')
	`)
	appID, _ := result.LastInsertId()

	// Create related records
	db.ExecContext(ctx, `INSERT INTO port_allocations (app_id, port) VALUES (?, 6100)`, appID)
	db.ExecContext(ctx, `INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port) VALUES (?, 'test.cubeos.cube', 'test', 6100)`, appID)

	// Delete app
	db.ExecContext(ctx, `DELETE FROM apps WHERE id = ?`, appID)

	// Verify cascade
	var portCount, fqdnCount int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM port_allocations WHERE app_id = ?`, appID).Scan(&portCount)
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM fqdns WHERE app_id = ?`, appID).Scan(&fqdnCount)

	if portCount != 0 {
		t.Error("port_allocations should cascade delete")
	}
	if fqdnCount != 0 {
		t.Error("fqdns should cascade delete")
	}
}

// =============================================================================
// MODEL TESTS
// =============================================================================

// TestAppTypeConstants tests app type constants.
func TestAppTypeConstants(t *testing.T) {
	tests := []struct {
		appType models.AppType
		str     string
	}{
		{models.AppTypeSystem, "system"},
		{models.AppTypePlatform, "platform"},
		{models.AppTypeNetwork, "network"},
		{models.AppTypeAI, "ai"},
		{models.AppTypeUser, "user"},
	}

	for _, tt := range tests {
		if string(tt.appType) != tt.str {
			t.Errorf("AppType %v should be '%s'", tt.appType, tt.str)
		}
	}
}

// TestDeployModeConstants tests deploy mode constants.
func TestDeployModeConstants(t *testing.T) {
	if string(models.DeployModeStack) != "stack" {
		t.Error("DeployModeStack should be 'stack'")
	}
	if string(models.DeployModeCompose) != "compose" {
		t.Error("DeployModeCompose should be 'compose'")
	}
}

// TestNetworkModeConstants tests network mode constants.
func TestNetworkModeConstants(t *testing.T) {
	tests := []struct {
		mode models.NetworkMode
		str  string
	}{
		{models.NetworkModeOffline, "offline"},
		{models.NetworkModeOnlineETH, "online_eth"},
		{models.NetworkModeOnlineWiFi, "online_wifi"},
	}

	for _, tt := range tests {
		if string(tt.mode) != tt.str {
			t.Errorf("NetworkMode %v should be '%s'", tt.mode, tt.str)
		}
	}
}

// TestAppFilter tests app filter functionality.
func TestAppFilter(t *testing.T) {
	filter := &models.AppFilter{
		Type:    models.AppTypeUser,
		Enabled: boolPtr(true),
	}

	if filter.Type != models.AppTypeUser {
		t.Error("filter type should be user")
	}
	if filter.Enabled == nil || *filter.Enabled != true {
		t.Error("filter enabled should be true")
	}
}

// =============================================================================
// COMPOSE TRANSFORMER TESTS
// =============================================================================

// TestComposeTransformerDetectDeployMode tests deploy mode detection.
func TestComposeTransformerDetectDeployMode(t *testing.T) {
	transformer := NewComposeTransformer("localhost:5000", "cubeos.cube")

	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name: "host network requires compose",
			content: `
services:
  app:
    image: nginx
    network_mode: host
`,
			expected: "compose",
		},
		{
			name: "bridge network uses stack",
			content: `
services:
  app:
    image: nginx
    ports:
      - "8080:80"
`,
			expected: "stack",
		},
		{
			name: "host mode with quotes",
			content: `
services:
  app:
    image: nginx
    network_mode: "host"
`,
			expected: "compose",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode := transformer.DetectDeployMode(tt.content)
			if mode != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, mode)
			}
		})
	}
}

// TestComposeTransformerValidateForSwarm tests Swarm validation.
func TestComposeTransformerValidateForSwarm(t *testing.T) {
	transformer := NewComposeTransformer("localhost:5000", "cubeos.cube")

	tests := []struct {
		name       string
		content    string
		wantIssues int
	}{
		{
			name: "valid compose",
			content: `
services:
  app:
    image: nginx
    ports:
      - "8080:80"
`,
			wantIssues: 0,
		},
		{
			name: "has build directive",
			content: `
services:
  app:
    build: .
    ports:
      - "8080:80"
`,
			wantIssues: 1,
		},
		{
			name: "has links (deprecated)",
			content: `
services:
  app:
    image: nginx
    links:
      - db
`,
			wantIssues: 1,
		},
		{
			name: "multiple issues",
			content: `
services:
  app:
    build: .
    links:
      - db
    network_mode: host
`,
			wantIssues: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := transformer.ValidateForSwarm(tt.content)
			if len(issues) != tt.wantIssues {
				t.Errorf("expected %d issues, got %d: %v", tt.wantIssues, len(issues), issues)
			}
		})
	}
}

// TestComposeTransformerTransform tests full transformation.
func TestComposeTransformerTransform(t *testing.T) {
	transformer := NewComposeTransformer("localhost:5000", "cubeos.cube")

	content := `
services:
  app:
    image: nginx:latest
    restart: always
    ports:
      - "8080:80"
`

	result, err := transformer.TransformForSwarm(content, "test-app")
	if err != nil {
		t.Fatalf("transform failed: %v", err)
	}

	if result.RequiresHost {
		t.Error("should not require host mode")
	}

	if result.DeployMode != "stack" {
		t.Errorf("expected deploy mode 'stack', got '%s'", result.DeployMode)
	}

	// Check ports were extracted
	if len(result.OriginalPorts) != 1 {
		t.Errorf("expected 1 port, got %d", len(result.OriginalPorts))
	}
	if len(result.OriginalPorts) > 0 && result.OriginalPorts[0].HostPort != 8080 {
		t.Errorf("expected host port 8080, got %d", result.OriginalPorts[0].HostPort)
	}
}

// =============================================================================
// APP NAME VALIDATION TESTS
// =============================================================================

// TestAppNameValidation tests app name validation rules.
func TestAppNameValidation(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"valid-app", true},
		{"myapp123", true},
		{"app", true},
		{"a", true},
		{"123app", true},
		{"", false},
		{"Invalid_Name", false},
		{"has space", false},
		{"has.dot", false},
		{"UPPERCASE", false},
		{"-starts-with-dash", false},
		{"ends-with-dash-", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := testIsValidAppName(tt.name)
			if valid != tt.valid {
				t.Errorf("isValidAppName(%q) = %v, want %v", tt.name, valid, tt.valid)
			}
		})
	}
}

// =============================================================================
// PROFILE TESTS
// =============================================================================

// TestProfileCRUD tests profile create, read, update, delete.
func TestProfileCRUD(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	ctx := context.Background()

	// Create profile
	result, err := db.ExecContext(ctx, `
		INSERT INTO profiles (name, display_name, description, is_system)
		VALUES (?, ?, ?, ?)
	`, "test-profile", "Test Profile", "A test profile", false)
	if err != nil {
		t.Fatalf("failed to insert profile: %v", err)
	}

	profileID, _ := result.LastInsertId()

	// Read profile
	var profile struct {
		ID          int64
		Name        string
		DisplayName string
		IsSystem    bool
	}
	err = db.QueryRowContext(ctx, `SELECT id, name, display_name, is_system FROM profiles WHERE id = ?`, profileID).
		Scan(&profile.ID, &profile.Name, &profile.DisplayName, &profile.IsSystem)
	if err != nil {
		t.Fatalf("failed to read profile: %v", err)
	}
	if profile.Name != "test-profile" {
		t.Errorf("expected name 'test-profile', got '%s'", profile.Name)
	}

	// Update profile
	_, err = db.ExecContext(ctx, `UPDATE profiles SET is_active = TRUE WHERE id = ?`, profileID)
	if err != nil {
		t.Fatalf("failed to update profile: %v", err)
	}

	// Delete profile
	_, err = db.ExecContext(ctx, `DELETE FROM profiles WHERE id = ?`, profileID)
	if err != nil {
		t.Fatalf("failed to delete profile: %v", err)
	}
}

// TestSystemState tests system state operations.
func TestSystemState(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	ctx := context.Background()

	// Read existing state
	var version string
	err := db.QueryRowContext(ctx, `SELECT value FROM system_state WHERE key = 'version'`).Scan(&version)
	if err != nil {
		t.Fatalf("failed to read version: %v", err)
	}
	if version != "2.0.0" {
		t.Errorf("expected version '2.0.0', got '%s'", version)
	}

	// Update state
	_, err = db.ExecContext(ctx, `UPDATE system_state SET value = ? WHERE key = 'setup_complete'`, "true")
	if err != nil {
		t.Fatalf("failed to update setup_complete: %v", err)
	}

	// Verify update
	var setupComplete string
	db.QueryRowContext(ctx, `SELECT value FROM system_state WHERE key = 'setup_complete'`).Scan(&setupComplete)
	if setupComplete != "true" {
		t.Errorf("expected setup_complete 'true', got '%s'", setupComplete)
	}
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}

	schema := `
		PRAGMA foreign_keys = ON;

		CREATE TABLE IF NOT EXISTS apps (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			description TEXT DEFAULT '',
			type TEXT NOT NULL DEFAULT 'user',
			category TEXT DEFAULT 'other',
			source TEXT DEFAULT 'custom',
			store_id TEXT DEFAULT NULL,
			compose_path TEXT NOT NULL,
			data_path TEXT DEFAULT '',
			enabled BOOLEAN DEFAULT TRUE,
			deploy_mode TEXT DEFAULT 'stack',
			tor_enabled BOOLEAN DEFAULT FALSE,
			vpn_enabled BOOLEAN DEFAULT FALSE,
			icon_url TEXT DEFAULT '',
			version TEXT DEFAULT '',
			homepage TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS port_allocations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			app_id INTEGER NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT DEFAULT 'tcp',
			description TEXT DEFAULT '',
			is_primary BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE,
			UNIQUE(port, protocol)
		);

		CREATE TABLE IF NOT EXISTS fqdns (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			app_id INTEGER NOT NULL,
			fqdn TEXT UNIQUE NOT NULL,
			subdomain TEXT NOT NULL,
			backend_port INTEGER NOT NULL,
			ssl_enabled BOOLEAN DEFAULT FALSE,
			npm_proxy_id INTEGER DEFAULT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS profiles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			description TEXT DEFAULT '',
			is_active BOOLEAN DEFAULT FALSE,
			is_system BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS profile_apps (
			profile_id INTEGER NOT NULL,
			app_id INTEGER NOT NULL,
			enabled BOOLEAN DEFAULT TRUE,
			PRIMARY KEY (profile_id, app_id),
			FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
			FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS system_state (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS network_config (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			mode TEXT DEFAULT 'offline',
			wifi_ssid TEXT DEFAULT '',
			wifi_password TEXT DEFAULT '',
			eth_interface TEXT DEFAULT 'eth0',
			wifi_ap_interface TEXT DEFAULT 'wlan0',
			wifi_client_interface TEXT DEFAULT 'wlan1',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS app_health (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			app_id INTEGER UNIQUE NOT NULL,
			check_endpoint TEXT DEFAULT '',
			check_interval INTEGER DEFAULT 30,
			check_timeout INTEGER DEFAULT 10,
			max_retries INTEGER DEFAULT 3,
			alert_after INTEGER DEFAULT 300,
			FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS vpn_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			type TEXT NOT NULL,
			config_path TEXT NOT NULL,
			is_active BOOLEAN DEFAULT FALSE,
			auto_connect BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS mounts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			type TEXT NOT NULL,
			remote_path TEXT NOT NULL,
			local_path TEXT NOT NULL,
			username TEXT DEFAULT '',
			password TEXT DEFAULT '',
			options TEXT DEFAULT '',
			auto_mount BOOLEAN DEFAULT FALSE,
			is_mounted BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS backups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			destination TEXT NOT NULL,
			include_apps TEXT DEFAULT '*',
			schedule TEXT DEFAULT '',
			retention_days INTEGER DEFAULT 30,
			last_run DATETIME,
			last_status TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			email TEXT DEFAULT '',
			role TEXT DEFAULT 'admin',
			last_login DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS preferences (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS nodes (
			id TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			role TEXT DEFAULT 'worker',
			status TEXT DEFAULT 'unknown',
			ip_address TEXT,
			joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		-- Seed system state
		INSERT INTO system_state (key, value) VALUES
			('setup_complete', 'false'),
			('version', '2.0.0'),
			('domain', 'cubeos.cube'),
			('gateway_ip', '10.42.24.1'),
			('subnet', '10.42.24.0/24');

		-- Seed network config
		INSERT INTO network_config (id, mode) VALUES (1, 'offline');
	`

	_, err = db.Exec(schema)
	if err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	return db
}

// boolPtr is defined in orchestrator.go, reuse it in tests

// testIsValidAppName is a local copy for testing (the real one is in orchestrator.go)
func testIsValidAppName(name string) bool {
	if name == "" {
		return false
	}

	// Must be lowercase
	if name != strings.ToLower(name) {
		return false
	}

	// Must start and end with alphanumeric
	if !testIsAlphaNumeric(rune(name[0])) || !testIsAlphaNumeric(rune(name[len(name)-1])) {
		return false
	}

	// Only alphanumeric and hyphens
	for _, r := range name {
		if !testIsAlphaNumeric(r) && r != '-' {
			return false
		}
	}

	return true
}

func testIsAlphaNumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}
