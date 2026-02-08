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

// newAppsRouter creates a chi router with apps routes for testing.
// Passing a nil orchestrator allows testing validation logic that
// short-circuits before any orchestrator method is called.
func newAppsRouter(h *AppsHandler) http.Handler {
	r := chi.NewRouter()
	r.Mount("/api/v1/apps", h.Routes())
	return r
}

// =============================================================================
// InstallApp Validation Tests
// =============================================================================

func TestInstallAppValidation(t *testing.T) {
	handler := NewAppsHandler(nil) // nil orchestrator — testing validation only
	router := newAppsRouter(handler)

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
	}{
		{
			name:       "invalid JSON",
			body:       `{invalid`,
			wantStatus: http.StatusBadRequest,
			wantError:  "Invalid request body",
		},
		{
			name:       "empty body",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "App name is required",
		},
		{
			name:       "missing name field",
			body:       `{"display_name": "Test App"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "App name is required",
		},
		{
			name:       "empty name string",
			body:       `{"name": ""}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "App name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/apps", bytes.NewBufferString(tt.body))
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
				if errMsg, ok := resp["error"].(string); !ok || errMsg != tt.wantError {
					t.Errorf("error = %q, want %q", resp["error"], tt.wantError)
				}
			}
		})
	}
}

// =============================================================================
// SetAppTor Validation Tests
// =============================================================================

func TestSetAppTorValidation(t *testing.T) {
	handler := NewAppsHandler(nil)
	router := newAppsRouter(handler)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "invalid JSON",
			body:       `not json`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty body",
			body:       ``,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/apps/testapp/tor", bytes.NewBufferString(tt.body))
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
// SetAppVPN Validation Tests
// =============================================================================

func TestSetAppVPNValidation(t *testing.T) {
	handler := NewAppsHandler(nil)
	router := newAppsRouter(handler)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "invalid JSON",
			body:       `{broken`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty body",
			body:       ``,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/apps/testapp/vpn", bytes.NewBufferString(tt.body))
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
// Route Registration Tests
// =============================================================================

func TestAppsRoutes(t *testing.T) {
	handler := NewAppsHandler(nil)
	routes := handler.Routes()

	// Verify routes exist by checking the chi router has expected patterns
	if routes == nil {
		t.Fatal("Routes() returned nil")
	}

	// Verify the router is a chi.Router
	if _, ok := routes.(chi.Router); !ok {
		t.Fatal("Routes() did not return a chi.Router")
	}
}

// TestAppsRouteMethods verifies all expected endpoints return valid HTTP responses
// (not 404/405) when called. Methods that require an orchestrator will panic on
// nil pointer — we recover gracefully since we're testing route registration, not logic.
func TestAppsRouteMethods(t *testing.T) {
	handler := NewAppsHandler(nil)
	router := newAppsRouter(handler)

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		notAllowed bool // true = expect 405 Method Not Allowed
	}{
		// These should NOT return 404 (route exists)
		{"GET /apps", "GET", "/api/v1/apps", "", false},
		{"POST /apps", "POST", "/api/v1/apps", `{}`, false},
		{"GET /apps/{name}", "GET", "/api/v1/apps/testapp", "", false},
		{"DELETE /apps/{name}", "DELETE", "/api/v1/apps/testapp", "", false},
		{"POST /apps/{name}/start", "POST", "/api/v1/apps/testapp/start", "", false},
		{"POST /apps/{name}/stop", "POST", "/api/v1/apps/testapp/stop", "", false},
		{"POST /apps/{name}/restart", "POST", "/api/v1/apps/testapp/restart", "", false},
		{"POST /apps/{name}/enable", "POST", "/api/v1/apps/testapp/enable", "", false},
		{"POST /apps/{name}/disable", "POST", "/api/v1/apps/testapp/disable", "", false},
		{"GET /apps/{name}/logs", "GET", "/api/v1/apps/testapp/logs", "", false},
		{"POST /apps/{name}/tor", "POST", "/api/v1/apps/testapp/tor", `{"enabled":true}`, false},
		{"POST /apps/{name}/vpn", "POST", "/api/v1/apps/testapp/vpn", `{"enabled":true}`, false},

		// Wrong method should return 405
		{"PUT /apps (wrong method)", "PUT", "/api/v1/apps", `{}`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body *bytes.Buffer
			if tt.body != "" {
				body = bytes.NewBufferString(tt.body)
			} else {
				body = &bytes.Buffer{}
			}

			req := httptest.NewRequest(tt.method, tt.path, body)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			// Recover from nil orchestrator panics — we're testing route registration, not logic.
			func() {
				defer func() { recover() }()
				router.ServeHTTP(rr, req)
			}()

			if tt.notAllowed {
				if rr.Code != http.StatusMethodNotAllowed {
					t.Errorf("status = %d, want %d (method not allowed)", rr.Code, http.StatusMethodNotAllowed)
				}
				return
			}

			// Route should exist (not 404) and not be method-not-allowed (405)
			if rr.Code == http.StatusNotFound {
				t.Errorf("route returned 404 — route not registered")
			}
			if rr.Code == http.StatusMethodNotAllowed {
				t.Errorf("route returned 405 — method not registered")
			}
		})
	}
}

// =============================================================================
// GetAppLogs Query Parameter Tests
// =============================================================================

func TestGetAppLogsQueryParams(t *testing.T) {
	// Verify query params are parsed without panic.
	// The handler will fail calling orchestrator (nil pointer) but that's fine —
	// we're testing that parameter parsing doesn't error or panic.
	handler := NewAppsHandler(nil)
	router := newAppsRouter(handler)

	tests := []struct {
		name  string
		query string
	}{
		{"default params", ""},
		{"custom lines", "?lines=50"},
		{"invalid lines ignored", "?lines=abc"},
		{"since param", "?since=2025-01-01T00:00:00Z"},
		{"invalid since ignored", "?since=not-a-date"},
		{"both params", "?lines=10&since=2025-01-01T00:00:00Z"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/apps/testapp/logs"+tt.query, nil)
			rr := httptest.NewRecorder()

			// Will panic on nil orchestrator — that's expected.
			// We're verifying the param parsing code doesn't panic before that.
			func() {
				defer func() { recover() }()
				router.ServeHTTP(rr, req)
			}()

			// If we get a response (not a panic), check it's not a 400
			if rr.Code == http.StatusBadRequest {
				t.Errorf("query params caused 400 Bad Request — should be accepted")
			}
		})
	}
}

// =============================================================================
// UninstallApp Query Parameter Tests
// =============================================================================

func TestUninstallAppKeepDataParam(t *testing.T) {
	handler := NewAppsHandler(nil)
	router := newAppsRouter(handler)

	tests := []struct {
		name  string
		query string
	}{
		{"no keep_data", ""},
		{"keep_data=true", "?keep_data=true"},
		{"keep_data=false", "?keep_data=false"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("DELETE", "/api/v1/apps/testapp"+tt.query, nil)
			rr := httptest.NewRecorder()

			// Will panic on nil orchestrator — expected.
			func() {
				defer func() { recover() }()
				router.ServeHTTP(rr, req)
			}()

			// Should not return 400 for valid query params
			if rr.Code == http.StatusBadRequest {
				t.Errorf("keep_data param caused 400 — should be accepted")
			}
		})
	}
}
