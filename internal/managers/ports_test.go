package managers

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// setupPortsTestDB creates an in-memory SQLite database with the required schema.
func setupPortsTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	// Create minimal schema matching production
	schema := `
		CREATE TABLE IF NOT EXISTS apps (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'user',
			source TEXT NOT NULL DEFAULT 'manual',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS port_allocations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			app_id INTEGER NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL DEFAULT 'tcp',
			description TEXT DEFAULT '',
			is_primary BOOLEAN DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
		);

		CREATE UNIQUE INDEX IF NOT EXISTS idx_port_protocol 
			ON port_allocations(port, protocol);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	return db
}

// insertTestApp creates a test app and returns its ID.
func insertTestApp(t *testing.T, db *sql.DB, name, appType string) int64 {
	t.Helper()
	result, err := db.Exec(
		"INSERT INTO apps (name, type, source) VALUES (?, ?, 'manual')",
		name, appType,
	)
	if err != nil {
		t.Fatalf("Failed to insert test app: %v", err)
	}
	id, _ := result.LastInsertId()
	return id
}

// insertTestPortAllocation inserts a port allocation row.
func insertTestPortAllocation(t *testing.T, db *sql.DB, appID int64, port int) {
	t.Helper()
	_, err := db.Exec(
		"INSERT INTO port_allocations (app_id, port, protocol, description, is_primary) VALUES (?, ?, 'tcp', 'test', 1)",
		appID, port,
	)
	if err != nil {
		t.Fatalf("Failed to insert port allocation for port %d: %v", port, err)
	}
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewPortManager_NilDeps(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	// Should not panic with nil swarm and hal
	pm := NewPortManager(db, nil, nil)
	if pm == nil {
		t.Fatal("NewPortManager returned nil")
	}
	if pm.db != db {
		t.Error("NewPortManager db not set")
	}
	if pm.swarm != nil {
		t.Error("NewPortManager swarm should be nil")
	}
	if pm.hal != nil {
		t.Error("NewPortManager hal should be nil")
	}
}

// =============================================================================
// AllocateUserPort — DB-Only Mode (swarm=nil, hal=nil)
// =============================================================================

func TestAllocateUserPort_FirstAllocation(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	pm := NewPortManager(db, nil, nil)

	port, err := pm.AllocateUserPort()
	if err != nil {
		t.Fatalf("AllocateUserPort() error: %v", err)
	}
	if port != UserPortMin {
		t.Errorf("First allocation should be %d, got %d", UserPortMin, port)
	}
}

func TestAllocateUserPort_SkipsAllocatedPorts(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	// Pre-allocate ports 6100, 6101, 6102
	app := insertTestApp(t, db, "test-app", "user")
	insertTestPortAllocation(t, db, app, 6100)
	insertTestPortAllocation(t, db, app, 6101)
	insertTestPortAllocation(t, db, app, 6102)

	pm := NewPortManager(db, nil, nil)

	port, err := pm.AllocateUserPort()
	if err != nil {
		t.Fatalf("AllocateUserPort() error: %v", err)
	}
	if port != 6103 {
		t.Errorf("Expected port 6103 (first gap after 6100-6102), got %d", port)
	}
}

func TestAllocateUserPort_FindsGaps(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	// Allocate 6100 and 6102, leaving 6101 as a gap
	app := insertTestApp(t, db, "test-app", "user")
	insertTestPortAllocation(t, db, app, 6100)
	insertTestPortAllocation(t, db, app, 6102)

	pm := NewPortManager(db, nil, nil)

	port, err := pm.AllocateUserPort()
	if err != nil {
		t.Fatalf("AllocateUserPort() error: %v", err)
	}
	if port != 6101 {
		t.Errorf("Expected port 6101 (gap between 6100 and 6102), got %d", port)
	}
}

func TestAllocateUserPort_ContextVariant(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	pm := NewPortManager(db, nil, nil)

	ctx := context.Background()
	port, err := pm.AllocateUserPortWithContext(ctx)
	if err != nil {
		t.Fatalf("AllocateUserPortWithContext() error: %v", err)
	}
	if port != UserPortMin {
		t.Errorf("Expected port %d, got %d", UserPortMin, port)
	}
}

func TestAllocateUserPort_SuccessiveAllocations(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	pm := NewPortManager(db, nil, nil)

	// Allocate 3 ports successively (simulating install flow)
	// Note: AllocateUserPort only finds available ports — it doesn't write to DB.
	// In production, the caller (AppStoreManager/Orchestrator) writes to DB.
	// So to test successive allocations, we write to DB between calls.
	app := insertTestApp(t, db, "app1", "user")

	port1, err := pm.AllocateUserPort()
	if err != nil {
		t.Fatalf("First allocation error: %v", err)
	}
	if port1 != 6100 {
		t.Errorf("First port should be 6100, got %d", port1)
	}
	insertTestPortAllocation(t, db, app, port1)

	app2 := insertTestApp(t, db, "app2", "user")
	port2, err := pm.AllocateUserPort()
	if err != nil {
		t.Fatalf("Second allocation error: %v", err)
	}
	if port2 != 6101 {
		t.Errorf("Second port should be 6101, got %d", port2)
	}
	insertTestPortAllocation(t, db, app2, port2)

	app3 := insertTestApp(t, db, "app3", "user")
	port3, err := pm.AllocateUserPort()
	if err != nil {
		t.Fatalf("Third allocation error: %v", err)
	}
	if port3 != 6102 {
		t.Errorf("Third port should be 6102, got %d", port3)
	}
	_ = app3
}

func TestAllocateUserPort_ReusesFreedPort(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	// Allocate 6100, 6101, 6102
	app1 := insertTestApp(t, db, "app1", "user")
	app2 := insertTestApp(t, db, "app2", "user")
	app3 := insertTestApp(t, db, "app3", "user")
	insertTestPortAllocation(t, db, app1, 6100)
	insertTestPortAllocation(t, db, app2, 6101)
	insertTestPortAllocation(t, db, app3, 6102)

	// Free port 6101 (simulate uninstall cascade)
	db.Exec("DELETE FROM port_allocations WHERE port = 6101")

	pm := NewPortManager(db, nil, nil)

	port, err := pm.AllocateUserPort()
	if err != nil {
		t.Fatalf("AllocateUserPort() error: %v", err)
	}
	if port != 6101 {
		t.Errorf("Expected reused port 6101, got %d", port)
	}
}

// =============================================================================
// Graceful Degradation Tests
// =============================================================================

func TestAllocateUserPort_NilSwarm_NilHAL(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	// Both nil: should fall back to DB-only, same as pre-Group 2 behavior
	pm := NewPortManager(db, nil, nil)

	port, err := pm.AllocateUserPort()
	if err != nil {
		t.Fatalf("AllocateUserPort() with nil deps error: %v", err)
	}
	if port < UserPortMin || port > UserPortMax {
		t.Errorf("Port %d outside user range [%d, %d]", port, UserPortMin, UserPortMax)
	}
}

func TestGetSwarmPorts_NilSwarm(t *testing.T) {
	pm := &PortManager{swarm: nil}

	ports := pm.getSwarmPorts(context.Background())
	if ports == nil {
		t.Error("getSwarmPorts with nil swarm returned nil, expected empty map")
	}
	if len(ports) != 0 {
		t.Errorf("getSwarmPorts with nil swarm returned %d ports, expected 0", len(ports))
	}
}

func TestGetHostPorts_NilHAL(t *testing.T) {
	pm := &PortManager{hal: nil}

	ports := pm.getHostPorts(context.Background())
	if len(ports) != 0 {
		t.Errorf("getHostPorts with nil hal returned %d ports, expected 0", len(ports))
	}
}

// =============================================================================
// AllocatePort Tests (specific port allocation)
// =============================================================================

func TestAllocatePort_SpecificPort(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	app := insertTestApp(t, db, "test-app", "user")
	pm := NewPortManager(db, nil, nil)

	err := pm.AllocatePort(app, 6150, "tcp", "Web UI", true)
	if err != nil {
		t.Fatalf("AllocatePort() error: %v", err)
	}

	// Verify it was stored
	allocated, err := pm.IsPortAllocated(6150, "tcp")
	if err != nil {
		t.Fatalf("IsPortAllocated() error: %v", err)
	}
	if !allocated {
		t.Error("Port 6150 should be allocated after AllocatePort()")
	}
}

func TestAllocatePort_DuplicateRejected(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	app := insertTestApp(t, db, "test-app", "user")
	pm := NewPortManager(db, nil, nil)

	// First allocation succeeds
	err := pm.AllocatePort(app, 6150, "tcp", "Web UI", true)
	if err != nil {
		t.Fatalf("First AllocatePort() error: %v", err)
	}

	// Second allocation with same port/protocol should fail
	err = pm.AllocatePort(app, 6150, "tcp", "Another UI", false)
	if err == nil {
		t.Error("AllocatePort() should reject duplicate port/protocol")
	}
}

func TestAllocatePort_ReservedPortRejectedForUserApp(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	app := insertTestApp(t, db, "user-app", "user")
	pm := NewPortManager(db, nil, nil)

	// Try to allocate SSH port for a user app
	err := pm.AllocatePort(app, 22, "tcp", "SSH", true)
	if err == nil {
		t.Error("AllocatePort() should reject reserved port for user app")
	}
}

func TestAllocatePort_ReservedPortAllowedForSystemApp(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	app := insertTestApp(t, db, "sshd", "system")
	pm := NewPortManager(db, nil, nil)

	err := pm.AllocatePort(app, 22, "tcp", "SSH", true)
	if err != nil {
		t.Errorf("AllocatePort() should allow reserved port for system app: %v", err)
	}
}

func TestAllocatePort_AutoAllocate(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	app := insertTestApp(t, db, "test-app", "user")
	pm := NewPortManager(db, nil, nil)

	// Port 0 triggers auto-allocation
	err := pm.AllocatePort(app, 0, "tcp", "Auto", true)
	if err != nil {
		t.Fatalf("AllocatePort(0) auto-allocate error: %v", err)
	}

	// Should have allocated UserPortMin
	allocated, err := pm.IsPortAllocated(UserPortMin, "tcp")
	if err != nil {
		t.Fatalf("IsPortAllocated() error: %v", err)
	}
	if !allocated {
		t.Error("Auto-allocated port should be UserPortMin")
	}
}

// =============================================================================
// Deallocate Tests
// =============================================================================

func TestDeallocatePort(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	app := insertTestApp(t, db, "test-app", "user")
	pm := NewPortManager(db, nil, nil)

	pm.AllocatePort(app, 6150, "tcp", "test", true)

	err := pm.DeallocatePort(6150, "tcp")
	if err != nil {
		t.Fatalf("DeallocatePort() error: %v", err)
	}

	allocated, _ := pm.IsPortAllocated(6150, "tcp")
	if allocated {
		t.Error("Port should not be allocated after deallocation")
	}
}

func TestDeallocateAppPorts(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	app := insertTestApp(t, db, "test-app", "user")
	pm := NewPortManager(db, nil, nil)

	pm.AllocatePort(app, 6150, "tcp", "port1", true)
	pm.AllocatePort(app, 6151, "tcp", "port2", false)

	err := pm.DeallocateAppPorts(app)
	if err != nil {
		t.Fatalf("DeallocateAppPorts() error: %v", err)
	}

	ports, _ := pm.GetAppPorts(app)
	if len(ports) != 0 {
		t.Errorf("Expected 0 ports after deallocation, got %d", len(ports))
	}
}

// =============================================================================
// Foreign Key Cascade Test
// =============================================================================

func TestForeignKeyCascade(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	app := insertTestApp(t, db, "cascade-test", "user")
	pm := NewPortManager(db, nil, nil)

	pm.AllocatePort(app, 6200, "tcp", "test", true)

	// Delete the app — should cascade to port_allocations
	_, err := db.Exec("DELETE FROM apps WHERE id = ?", app)
	if err != nil {
		t.Fatalf("DELETE FROM apps error: %v", err)
	}

	allocated, _ := pm.IsPortAllocated(6200, "tcp")
	if allocated {
		t.Error("Port allocation should be cascade-deleted when app is deleted")
	}
}

// =============================================================================
// GetPortOwner / GetAppPorts / GetAllAllocations Tests
// =============================================================================

func TestGetPortOwner(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	app := insertTestApp(t, db, "my-app", "user")
	pm := NewPortManager(db, nil, nil)

	pm.AllocatePort(app, 6150, "tcp", "test", true)

	owner, err := pm.GetPortOwner(6150, "tcp")
	if err != nil {
		t.Fatalf("GetPortOwner() error: %v", err)
	}
	if owner != "my-app" {
		t.Errorf("Expected owner 'my-app', got '%s'", owner)
	}
}

func TestGetPortOwner_Unallocated(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	pm := NewPortManager(db, nil, nil)

	owner, err := pm.GetPortOwner(6999, "tcp")
	if err != nil {
		t.Fatalf("GetPortOwner() error: %v", err)
	}
	if owner != "" {
		t.Errorf("Expected empty owner for unallocated port, got '%s'", owner)
	}
}

func TestGetAppPorts(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	app := insertTestApp(t, db, "multi-port", "user")
	pm := NewPortManager(db, nil, nil)

	pm.AllocatePort(app, 6150, "tcp", "http", true)
	pm.AllocatePort(app, 6151, "tcp", "websocket", false)

	ports, err := pm.GetAppPorts(app)
	if err != nil {
		t.Fatalf("GetAppPorts() error: %v", err)
	}
	if len(ports) != 2 {
		t.Errorf("Expected 2 ports, got %d", len(ports))
	}
}

// =============================================================================
// ValidatePortScheme Tests
// =============================================================================

func TestValidatePortScheme_Ports(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		appType string
		wantErr bool
	}{
		{"user port in range", 6100, "user", false},
		{"user port max", 6999, "user", false},
		{"user port below range", 6099, "user", true},
		{"user port above range", 7000, "user", true},
		{"platform port in range", 6010, "platform", false},
		{"platform port out of range", 6100, "platform", true},
		{"network port in range", 6020, "network", false},
		{"network port out of range", 6010, "network", true},
		{"ai port in range", 6030, "ai", false},
		{"ai port out of range", 6020, "ai", true},
		{"system port 6000", 6000, "system", false}, // 6000 is in 6000-6009 range
		{"system port SSH", 22, "system", false},    // SSH is in ReservedSystemPorts
		{"unknown type", 6100, "unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePortScheme(tt.port, tt.appType)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePortScheme(%d, %q) error = %v, wantErr %v",
					tt.port, tt.appType, err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// IsPortReserved Tests
// =============================================================================

func TestIsPortReserved(t *testing.T) {
	pm := &PortManager{}

	tests := []struct {
		port     int
		expected bool
	}{
		{22, true},
		{53, true},
		{80, true},
		{443, true},
		{6010, true},
		{6100, false},
		{6500, false},
		{8080, false},
	}

	for _, tt := range tests {
		got := pm.IsPortReserved(tt.port)
		if got != tt.expected {
			t.Errorf("IsPortReserved(%d) = %v, want %v", tt.port, got, tt.expected)
		}
	}
}

// =============================================================================
// GetPortStats Tests
// =============================================================================

func TestGetPortStats_Empty(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	pm := NewPortManager(db, nil, nil)

	stats, err := pm.GetPortStats()
	if err != nil {
		t.Fatalf("GetPortStats() error: %v", err)
	}
	if stats.TotalAllocated != 0 {
		t.Errorf("Expected 0 total allocated, got %d", stats.TotalAllocated)
	}
	if stats.UserPortsAvailable != UserPortCount {
		t.Errorf("Expected %d available user ports, got %d", UserPortCount, stats.UserPortsAvailable)
	}
}

func TestGetPortStats_WithAllocations(t *testing.T) {
	db := setupPortsTestDB(t)
	defer db.Close()

	app := insertTestApp(t, db, "test", "user")
	pm := NewPortManager(db, nil, nil)

	pm.AllocatePort(app, 6100, "tcp", "test", true)
	pm.AllocatePort(app, 6101, "tcp", "test2", false)

	stats, err := pm.GetPortStats()
	if err != nil {
		t.Fatalf("GetPortStats() error: %v", err)
	}
	if stats.UserAllocated != 2 {
		t.Errorf("Expected 2 user allocated, got %d", stats.UserAllocated)
	}
	if stats.UserPortsAvailable != UserPortCount-2 {
		t.Errorf("Expected %d available, got %d", UserPortCount-2, stats.UserPortsAvailable)
	}
}
