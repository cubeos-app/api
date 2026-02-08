package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// =============================================================================
// Test Helpers
// =============================================================================

// newAppStoreRouter creates a chi router with appstore routes for testing.
func newAppStoreRouter(h *AppStoreHandler) http.Handler {
	r := chi.NewRouter()
	r.Mount("/api/v1/appstore", h.Routes())
	return r
}

// =============================================================================
// RegisterStore Validation Tests
// =============================================================================

func TestRegisterStoreValidation(t *testing.T) {
	handler := NewAppStoreHandler(nil, nil)
	router := newAppStoreRouter(handler)

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
	}{
		{
			name:       "invalid JSON",
			body:       `{broken`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid request",
		},
		{
			name:       "empty body",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "url is required",
		},
		{
			name:       "missing URL field",
			body:       `{"name": "My Store"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "url is required",
		},
		{
			name:       "empty URL",
			body:       `{"url": ""}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "url is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/appstore/stores", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d. Body: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}

			if tt.wantError != "" {
				var resp map[string]interface{}
				if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if errMsg, _ := resp["error"].(string); errMsg != tt.wantError {
					t.Errorf("error = %q, want %q", errMsg, tt.wantError)
				}
			}
		})
	}
}

// =============================================================================
// InstallApp (AppStore) Validation Tests
// =============================================================================

func TestAppStoreInstallAppValidation(t *testing.T) {
	handler := NewAppStoreHandler(nil, nil)
	router := newAppStoreRouter(handler)

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
	}{
		{
			name:       "invalid JSON",
			body:       `not json`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid request",
		},
		{
			name:       "empty body",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "store_id and app_name are required",
		},
		{
			name:       "missing app_name",
			body:       `{"store_id": "casaos"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "store_id and app_name are required",
		},
		{
			name:       "missing store_id",
			body:       `{"app_name": "filebrowser"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "store_id and app_name are required",
		},
		{
			name:       "invalid app name with spaces",
			body:       `{"store_id": "casaos", "app_name": "bad app name!"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid app name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/appstore/installed", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d. Body: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}

			if tt.wantError != "" {
				var resp map[string]interface{}
				if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if errMsg, _ := resp["error"].(string); errMsg != tt.wantError {
					t.Errorf("error = %q, want %q", errMsg, tt.wantError)
				}
			}
		})
	}
}

// =============================================================================
// AppAction Validation Tests
// =============================================================================

func TestAppActionValidation(t *testing.T) {
	handler := NewAppStoreHandler(nil, nil)
	router := newAppStoreRouter(handler)

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
	}{
		{
			name:       "invalid JSON",
			body:       `{bad`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid request",
		},
		{
			name:       "invalid action",
			body:       `{"action": "explode"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid action",
		},
		{
			name:       "empty action",
			body:       `{"action": ""}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid action",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/appstore/installed/test-app/action", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d. Body: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}

			if tt.wantError != "" {
				var resp map[string]interface{}
				json.Unmarshal(rr.Body.Bytes(), &resp)
				if errMsg, _ := resp["error"].(string); errMsg != tt.wantError {
					t.Errorf("error = %q, want %q", errMsg, tt.wantError)
				}
			}
		})
	}
}

// =============================================================================
// UpdateAppConfig Validation Tests
// =============================================================================

func TestUpdateAppConfigValidation(t *testing.T) {
	handler := NewAppStoreHandler(nil, nil)
	router := newAppStoreRouter(handler)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "invalid JSON",
			body:       `not valid json`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/api/v1/appstore/installed/test-app/config", bytes.NewBufferString(tt.body))
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
// UpdateCoreAppConfig Validation Tests
// =============================================================================

func TestUpdateCoreAppConfigValidation(t *testing.T) {
	handler := NewAppStoreHandler(nil, nil)
	router := newAppStoreRouter(handler)

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
	}{
		{
			name:       "invalid JSON",
			body:       `broken`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid request",
		},
		{
			name:       "missing confirm_dangerous",
			body:       `{"compose_yaml": "version: '3'"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "You must set confirm_dangerous=true to modify core app config",
		},
		{
			name:       "confirm_dangerous false",
			body:       `{"compose_yaml": "version: '3'", "confirm_dangerous": false}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "You must set confirm_dangerous=true to modify core app config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/api/v1/appstore/coreapps/pihole/config", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d. Body: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}

			if tt.wantError != "" {
				var resp map[string]interface{}
				json.Unmarshal(rr.Body.Bytes(), &resp)
				if errMsg, _ := resp["error"].(string); errMsg != tt.wantError {
					t.Errorf("error = %q, want %q", errMsg, tt.wantError)
				}
			}
		})
	}
}

// =============================================================================
// ApplyCoreAppConfig Validation Tests
// =============================================================================

func TestApplyCoreAppConfigValidation(t *testing.T) {
	handler := NewAppStoreHandler(nil, nil)
	router := newAppStoreRouter(handler)

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
	}{
		{
			name:       "invalid JSON",
			body:       `{bad`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid request body",
		},
		{
			name:       "missing confirm_dangerous",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "You must set confirm_dangerous=true to restart a core app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/appstore/coreapps/pihole/config/apply", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d. Body: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}

			if tt.wantError != "" {
				var resp map[string]interface{}
				json.Unmarshal(rr.Body.Bytes(), &resp)
				if errMsg, _ := resp["error"].(string); errMsg != tt.wantError {
					t.Errorf("error = %q, want %q", errMsg, tt.wantError)
				}
			}
		})
	}
}

// =============================================================================
// NPM Proxy Hosts - Service Unavailable when nil
// =============================================================================

func TestGetProxyHostsNilNPM(t *testing.T) {
	handler := NewAppStoreHandler(nil, nil)
	router := newAppStoreRouter(handler)

	req := httptest.NewRequest("GET", "/api/v1/appstore/proxy-hosts", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

// =============================================================================
// Route Registration Tests
// =============================================================================

func TestAppStoreRoutes(t *testing.T) {
	handler := NewAppStoreHandler(nil, nil)
	routes := handler.Routes()

	if routes == nil {
		t.Fatal("Routes() returned nil")
	}
}

// TestAppStoreRouteMethods verifies all expected endpoints are registered.
// Handlers with nil managers will panic — we recover gracefully since
// we're testing route registration, not handler logic.
func TestAppStoreRouteMethods(t *testing.T) {
	handler := NewAppStoreHandler(nil, nil)
	router := newAppStoreRouter(handler)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"GET stores", "GET", "/api/v1/appstore/stores"},
		{"POST stores", "POST", "/api/v1/appstore/stores"},
		{"GET store by ID", "GET", "/api/v1/appstore/stores/test-store"},
		{"DELETE store", "DELETE", "/api/v1/appstore/stores/test-store"},
		{"POST sync store", "POST", "/api/v1/appstore/stores/test-store/sync"},
		{"POST sync all", "POST", "/api/v1/appstore/stores/sync"},
		{"GET catalog apps", "GET", "/api/v1/appstore/apps"},
		{"GET categories", "GET", "/api/v1/appstore/categories"},
		{"GET catalog app", "GET", "/api/v1/appstore/stores/test/apps/testapp"},
		{"GET app manifest", "GET", "/api/v1/appstore/stores/test/apps/testapp/manifest"},
		{"GET app icon", "GET", "/api/v1/appstore/stores/test/apps/testapp/icon"},
		{"GET screenshot", "GET", "/api/v1/appstore/stores/test/apps/testapp/screenshot/1"},
		{"GET installed", "GET", "/api/v1/appstore/installed"},
		{"POST install", "POST", "/api/v1/appstore/installed"},
		{"GET installed app", "GET", "/api/v1/appstore/installed/test-app"},
		{"DELETE installed", "DELETE", "/api/v1/appstore/installed/test-app"},
		{"POST start", "POST", "/api/v1/appstore/installed/test-app/start"},
		{"POST stop", "POST", "/api/v1/appstore/installed/test-app/stop"},
		{"POST restart", "POST", "/api/v1/appstore/installed/test-app/restart"},
		{"POST action", "POST", "/api/v1/appstore/installed/test-app/action"},
		{"GET config", "GET", "/api/v1/appstore/installed/test-app/config"},
		{"PUT config", "PUT", "/api/v1/appstore/installed/test-app/config"},
		{"POST apply config", "POST", "/api/v1/appstore/installed/test-app/config/apply"},
		{"GET config backups", "GET", "/api/v1/appstore/installed/test-app/config/backups"},
		{"POST restore config", "POST", "/api/v1/appstore/installed/test-app/config/restore/backup1"},
		{"GET coreapps", "GET", "/api/v1/appstore/coreapps"},
		{"GET coreapp config", "GET", "/api/v1/appstore/coreapps/pihole/config"},
		{"PUT coreapp config", "PUT", "/api/v1/appstore/coreapps/pihole/config"},
		{"POST apply coreapp", "POST", "/api/v1/appstore/coreapps/pihole/config/apply"},
		{"GET coreapp backups", "GET", "/api/v1/appstore/coreapps/pihole/config/backups"},
		{"POST restore coreapp", "POST", "/api/v1/appstore/coreapps/pihole/config/restore/backup1"},
		{"GET proxy hosts", "GET", "/api/v1/appstore/proxy-hosts"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, bytes.NewBufferString("{}"))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			// Recover from nil manager panics — we're testing route registration, not logic.
			func() {
				defer func() { recover() }()
				router.ServeHTTP(rr, req)
			}()

			if rr.Code == http.StatusNotFound {
				t.Errorf("route returned 404 — route not registered for %s %s", tt.method, tt.path)
			}
			if rr.Code == http.StatusMethodNotAllowed {
				t.Errorf("route returned 405 — method not registered for %s %s", tt.method, tt.path)
			}
		})
	}
}
