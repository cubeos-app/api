package managers

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// TestPortConstants verifies the port allocation scheme.
func TestPortConstants(t *testing.T) {
	if PortAPI != 6010 {
		t.Errorf("unexpected API port: %d", PortAPI)
	}
	if PortDashboard != 6011 {
		t.Errorf("unexpected Dashboard port: %d", PortDashboard)
	}
	if UserPortMin != 6100 {
		t.Errorf("unexpected UserPortMin: %d", UserPortMin)
	}
	if UserPortMax != 6999 {
		t.Errorf("unexpected UserPortMax: %d", UserPortMax)
	}
}

// TestReservedPorts verifies reserved ports are defined.
func TestReservedPorts(t *testing.T) {
	if _, ok := ReservedSystemPorts[22]; !ok {
		t.Error("SSH port 22 should be reserved")
	}
	if _, ok := ReservedSystemPorts[53]; !ok {
		t.Error("DNS port 53 should be reserved")
	}
	if _, ok := ReservedSystemPorts[6010]; !ok {
		t.Error("API port 6010 should be reserved")
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

	// Test first allocation (should return 6100 when table is empty)
	port, err := pm.AllocateUserPort()
	if err != nil {
		t.Fatalf("failed to allocate port: %v", err)
	}
	if port != UserPortMin {
		t.Errorf("expected first port %d, got %d", UserPortMin, port)
	}

	// Actually record the allocation in the database
	// This simulates what Orchestrator.InstallApp() would do
	_, err = db.Exec(`INSERT INTO port_allocations (app_id, port, protocol, description, is_primary) 
		VALUES (1, ?, 'tcp', 'Test App', TRUE)`, port)
	if err != nil {
		t.Fatalf("failed to insert port allocation: %v", err)
	}

	// Test second allocation (should return 6101 now that 6100 is allocated)
	port2, err := pm.AllocateUserPort()
	if err != nil {
		t.Fatalf("failed to allocate second port: %v", err)
	}
	if port2 != UserPortMin+1 {
		t.Errorf("expected second port %d, got %d", UserPortMin+1, port2)
	}
}

// TestValidatePortScheme tests port scheme validation.
func TestValidatePortScheme(t *testing.T) {
	// Test valid user app port
	err := ValidatePortScheme(6100, "user")
	if err != nil {
		t.Errorf("port 6100 should be valid for user apps: %v", err)
	}

	// Test valid system port
	err = ValidatePortScheme(6001, "system")
	if err != nil {
		t.Errorf("port 6001 should be valid for system apps: %v", err)
	}

	// Test invalid user port (in system range)
	err = ValidatePortScheme(6001, "user")
	if err == nil {
		t.Error("port 6001 should be invalid for user apps")
	}
}
