package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	_ "modernc.org/sqlite"
)

// setupFQDNTestDB creates an in-memory SQLite with the required tables.
func setupFQDNTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}

	_, err = db.Exec(`
		PRAGMA foreign_keys = ON;

		CREATE TABLE apps (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			description TEXT DEFAULT '',
			type TEXT NOT NULL DEFAULT 'user',
			compose_path TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE fqdns (
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

		-- Seed a test app
		INSERT INTO apps (id, name, display_name, compose_path) VALUES (1, 'filebrowser', 'File Browser', '/cubeos/apps/filebrowser/docker-compose.yml');
		INSERT INTO apps (id, name, display_name, compose_path) VALUES (2, 'gitea', 'Gitea', '/cubeos/apps/gitea/docker-compose.yml');
	`)
	if err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	return db
}

// newFQDNRouter creates a chi router with FQDN routes for testing.
// NPM and Pihole managers are nil (skips external service calls).
func newFQDNRouter(db *sql.DB) http.Handler {
	handler := NewFQDNsHandler(db, nil, nil)
	r := chi.NewRouter()
	r.Route("/api/v1/fqdns", func(r chi.Router) {
		r.Get("/", handler.ListFQDNs)
		r.Post("/", handler.CreateFQDN)
		r.Get("/{fqdn}", handler.GetFQDN)
		r.Put("/{fqdn}", handler.UpdateFQDN)
		r.Delete("/{fqdn}", handler.DeleteFQDN)
	})
	return r
}

// =============================================================================
// CreateFQDN Integration Tests
// =============================================================================

func TestCreateFQDN(t *testing.T) {
	db := setupFQDNTestDB(t)
	defer db.Close()

	router := newFQDNRouter(db)

	body := map[string]interface{}{
		"app_id":       1,
		"subdomain":    "files",
		"backend_port": 6100,
		"ssl_enabled":  false,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/fqdns", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("CreateFQDN status = %d, want %d. Body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var result FQDN
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.FQDN != "files.cubeos.cube" {
		t.Errorf("FQDN = %q, want %q", result.FQDN, "files.cubeos.cube")
	}
	if result.Subdomain != "files" {
		t.Errorf("Subdomain = %q, want %q", result.Subdomain, "files")
	}
	if result.BackendPort != 6100 {
		t.Errorf("BackendPort = %d, want %d", result.BackendPort, 6100)
	}
	if result.AppID != 1 {
		t.Errorf("AppID = %d, want %d", result.AppID, 1)
	}

	// Verify the record exists in the DB
	var count int
	db.QueryRow("SELECT COUNT(*) FROM fqdns WHERE fqdn = 'files.cubeos.cube'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 FQDN record in DB, got %d", count)
	}
}

func TestCreateFQDNDuplicateConflict(t *testing.T) {
	db := setupFQDNTestDB(t)
	defer db.Close()

	router := newFQDNRouter(db)

	body := map[string]interface{}{
		"app_id":       1,
		"subdomain":    "files",
		"backend_port": 6100,
	}
	bodyBytes, _ := json.Marshal(body)

	// First create — should succeed
	req1 := httptest.NewRequest("POST", "/api/v1/fqdns", bytes.NewReader(bodyBytes))
	req1.Header.Set("Content-Type", "application/json")
	rr1 := httptest.NewRecorder()
	router.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusCreated {
		t.Fatalf("first CreateFQDN status = %d, want %d", rr1.Code, http.StatusCreated)
	}

	// Second create with same subdomain — should conflict
	req2 := httptest.NewRequest("POST", "/api/v1/fqdns", bytes.NewReader(bodyBytes))
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusConflict {
		t.Errorf("duplicate CreateFQDN status = %d, want %d", rr2.Code, http.StatusConflict)
	}
}

func TestCreateFQDNValidation(t *testing.T) {
	db := setupFQDNTestDB(t)
	defer db.Close()

	router := newFQDNRouter(db)

	tests := []struct {
		name       string
		body       map[string]interface{}
		wantStatus int
	}{
		{
			name:       "missing subdomain",
			body:       map[string]interface{}{"app_id": 1, "backend_port": 6100},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty subdomain",
			body:       map[string]interface{}{"app_id": 1, "subdomain": "", "backend_port": 6100},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid subdomain chars",
			body:       map[string]interface{}{"app_id": 1, "subdomain": "my_app!", "backend_port": 6100},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid port zero",
			body:       map[string]interface{}{"app_id": 1, "subdomain": "test", "backend_port": 0},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid port too high",
			body:       map[string]interface{}{"app_id": 1, "subdomain": "test", "backend_port": 70000},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing app_id",
			body:       map[string]interface{}{"subdomain": "test", "backend_port": 6100},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "nonexistent app_id",
			body:       map[string]interface{}{"app_id": 999, "subdomain": "test", "backend_port": 6100},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/v1/fqdns", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d. Body: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}
		})
	}
}

// =============================================================================
// ListFQDNs Tests
// =============================================================================

func TestListFQDNsEmpty(t *testing.T) {
	db := setupFQDNTestDB(t)
	defer db.Close()

	router := newFQDNRouter(db)

	req := httptest.NewRequest("GET", "/api/v1/fqdns", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &result)

	fqdns, ok := result["fqdns"].([]interface{})
	if !ok {
		t.Fatal("response missing 'fqdns' array")
	}
	if len(fqdns) != 0 {
		t.Errorf("expected 0 FQDNs, got %d", len(fqdns))
	}
}

func TestListFQDNsWithData(t *testing.T) {
	db := setupFQDNTestDB(t)
	defer db.Close()

	// Pre-populate FQDNs
	db.Exec("INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port, ssl_enabled) VALUES (1, 'files.cubeos.cube', 'files', 6100, FALSE)")
	db.Exec("INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port, ssl_enabled) VALUES (2, 'git.cubeos.cube', 'git', 6101, TRUE)")

	router := newFQDNRouter(db)

	req := httptest.NewRequest("GET", "/api/v1/fqdns", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &result)

	fqdns, ok := result["fqdns"].([]interface{})
	if !ok {
		t.Fatal("response missing 'fqdns' array")
	}
	if len(fqdns) != 2 {
		t.Errorf("expected 2 FQDNs, got %d", len(fqdns))
	}

	// Verify stats
	stats, ok := result["stats"].(map[string]interface{})
	if !ok {
		t.Fatal("response missing 'stats'")
	}
	if total, ok := stats["total"].(float64); !ok || int(total) != 2 {
		t.Errorf("stats.total = %v, want 2", stats["total"])
	}
	if withSSL, ok := stats["with_ssl"].(float64); !ok || int(withSSL) != 1 {
		t.Errorf("stats.with_ssl = %v, want 1", stats["with_ssl"])
	}
}

// =============================================================================
// GetFQDN Tests
// =============================================================================

func TestGetFQDNBySubdomain(t *testing.T) {
	db := setupFQDNTestDB(t)
	defer db.Close()

	db.Exec("INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port) VALUES (1, 'files.cubeos.cube', 'files', 6100)")

	router := newFQDNRouter(db)

	req := httptest.NewRequest("GET", "/api/v1/fqdns/files", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var result FQDN
	json.Unmarshal(rr.Body.Bytes(), &result)

	if result.FQDN != "files.cubeos.cube" {
		t.Errorf("FQDN = %q, want %q", result.FQDN, "files.cubeos.cube")
	}
}

func TestGetFQDNNotFound(t *testing.T) {
	db := setupFQDNTestDB(t)
	defer db.Close()

	router := newFQDNRouter(db)

	req := httptest.NewRequest("GET", "/api/v1/fqdns/nonexistent", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// =============================================================================
// DeleteFQDN Tests
// =============================================================================

func TestDeleteFQDN(t *testing.T) {
	db := setupFQDNTestDB(t)
	defer db.Close()

	db.Exec("INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port) VALUES (1, 'files.cubeos.cube', 'files', 6100)")

	router := newFQDNRouter(db)

	req := httptest.NewRequest("DELETE", "/api/v1/fqdns/files", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify deleted from DB
	var count int
	db.QueryRow("SELECT COUNT(*) FROM fqdns WHERE subdomain = 'files'").Scan(&count)
	if count != 0 {
		t.Errorf("FQDN should be deleted, but %d records remain", count)
	}
}

func TestDeleteFQDNNotFound(t *testing.T) {
	db := setupFQDNTestDB(t)
	defer db.Close()

	router := newFQDNRouter(db)

	req := httptest.NewRequest("DELETE", "/api/v1/fqdns/nonexistent", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// =============================================================================
// Full FQDN Lifecycle: Create → Read → Delete
// =============================================================================

func TestFQDNLifecycle(t *testing.T) {
	db := setupFQDNTestDB(t)
	defer db.Close()

	router := newFQDNRouter(db)

	// Step 1: Create FQDN
	createBody, _ := json.Marshal(map[string]interface{}{
		"app_id":       1,
		"subdomain":    "myapp",
		"backend_port": 6150,
		"ssl_enabled":  true,
	})
	createReq := httptest.NewRequest("POST", "/api/v1/fqdns", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createRR := httptest.NewRecorder()
	router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("Create status = %d, want %d. Body: %s", createRR.Code, http.StatusCreated, createRR.Body.String())
	}

	// Step 2: Read back via GET
	getReq := httptest.NewRequest("GET", "/api/v1/fqdns/myapp", nil)
	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Fatalf("Get status = %d, want %d", getRR.Code, http.StatusOK)
	}

	var fqdn FQDN
	json.Unmarshal(getRR.Body.Bytes(), &fqdn)
	if fqdn.FQDN != "myapp.cubeos.cube" {
		t.Errorf("FQDN = %q, want %q", fqdn.FQDN, "myapp.cubeos.cube")
	}
	if fqdn.BackendPort != 6150 {
		t.Errorf("BackendPort = %d, want %d", fqdn.BackendPort, 6150)
	}

	// Step 3: Verify in list
	listReq := httptest.NewRequest("GET", "/api/v1/fqdns", nil)
	listRR := httptest.NewRecorder()
	router.ServeHTTP(listRR, listReq)

	var listResult map[string]interface{}
	json.Unmarshal(listRR.Body.Bytes(), &listResult)
	fqdns := listResult["fqdns"].([]interface{})
	if len(fqdns) != 1 {
		t.Errorf("expected 1 FQDN in list, got %d", len(fqdns))
	}

	// Step 4: Delete
	delReq := httptest.NewRequest("DELETE", "/api/v1/fqdns/myapp", nil)
	delRR := httptest.NewRecorder()
	router.ServeHTTP(delRR, delReq)

	if delRR.Code != http.StatusOK {
		t.Fatalf("Delete status = %d, want %d", delRR.Code, http.StatusOK)
	}

	// Step 5: Verify gone
	getReq2 := httptest.NewRequest("GET", "/api/v1/fqdns/myapp", nil)
	getRR2 := httptest.NewRecorder()
	router.ServeHTTP(getRR2, getReq2)

	if getRR2.Code != http.StatusNotFound {
		t.Errorf("after delete, Get status = %d, want %d", getRR2.Code, http.StatusNotFound)
	}
}
