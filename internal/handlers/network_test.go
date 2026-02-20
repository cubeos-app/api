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

// newNetworkRouter creates a chi router with network routes for testing.
func newNetworkRouter(h *NetworkHandler) http.Handler {
	r := chi.NewRouter()
	r.Mount("/api/v1/network", h.Routes())
	return r
}

// =============================================================================
// SetNetworkMode Validation Tests
// =============================================================================

func TestSetNetworkModeValidation(t *testing.T) {
	handler := NewNetworkHandler(nil, nil)
	router := newNetworkRouter(handler)

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
			wantError:  "Invalid request body",
		},
		{
			name:       "empty body",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "Network mode is required",
		},
		{
			name:       "empty mode string",
			body:       `{"mode": ""}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "Network mode is required",
		},
		{
			name:       "invalid mode",
			body:       `{"mode": "turbo"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "Invalid network mode. Valid modes: offline, online_eth, online_wifi, online_tether, server_eth, server_wifi",
		},
		{
			name:       "online_wifi without SSID",
			body:       `{"mode": "online_wifi"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "SSID is required for WiFi modes",
		},
		{
			name:       "server_wifi without SSID",
			body:       `{"mode": "server_wifi"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "SSID is required for WiFi modes",
		},
		{
			name:       "online_wifi with empty SSID",
			body:       `{"mode": "online_wifi", "ssid": ""}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "SSID is required for WiFi modes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/network/mode", bytes.NewBufferString(tt.body))
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
// GetAvailableModes (Static — no manager dependency)
// =============================================================================

func TestGetAvailableModes(t *testing.T) {
	handler := NewNetworkHandler(nil, nil)
	router := newNetworkRouter(handler)

	req := httptest.NewRequest("GET", "/api/v1/network/modes", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	modes, ok := result["modes"].([]interface{})
	if !ok {
		t.Fatal("response missing 'modes' array")
	}

	if len(modes) != 6 {
		t.Errorf("expected 6 modes, got %d", len(modes))
	}

	count, ok := result["count"].(float64)
	if !ok || int(count) != 6 {
		t.Errorf("count = %v, want 6", result["count"])
	}

	// Verify all expected mode IDs are present
	expectedIDs := map[string]bool{
		"offline":       false,
		"online_eth":    false,
		"online_wifi":   false,
		"online_tether": false,
		"server_eth":    false,
		"server_wifi":   false,
	}

	for _, m := range modes {
		mode, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		if id, ok := mode["id"].(string); ok {
			expectedIDs[id] = true
		}
	}

	for id, found := range expectedIDs {
		if !found {
			t.Errorf("missing mode: %s", id)
		}
	}
}

// =============================================================================
// ConnectToWiFi Validation Tests
// =============================================================================

func TestConnectToWiFiValidation(t *testing.T) {
	handler := NewNetworkHandler(nil, nil)
	router := newNetworkRouter(handler)

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
			wantError:  "Invalid request body",
		},
		{
			name:       "missing SSID",
			body:       `{"password": "secret"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "SSID is required",
		},
		{
			name:       "empty SSID",
			body:       `{"ssid": "", "password": "secret"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "SSID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/network/wifi/connect", bytes.NewBufferString(tt.body))
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
// UpdateAPConfig Validation Tests
// =============================================================================

func TestUpdateAPConfigValidation(t *testing.T) {
	handler := NewNetworkHandler(nil, nil)
	router := newNetworkRouter(handler)

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
			wantError:  "Invalid request body",
		},
		{
			name:       "missing SSID",
			body:       `{"password": "longpassword"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "SSID is required",
		},
		{
			name:       "empty SSID",
			body:       `{"ssid": ""}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "SSID is required",
		},
		{
			name:       "password too short",
			body:       `{"ssid": "CubeOS", "password": "short"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "Password must be at least 8 characters",
		},
		{
			name:       "password exactly 7 chars",
			body:       `{"ssid": "CubeOS", "password": "1234567"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "Password must be at least 8 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/api/v1/network/ap/config", bytes.NewBufferString(tt.body))
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
// KickAPClient / BlockAPClient MAC Validation Tests
// =============================================================================

func TestAPClientMACValidation(t *testing.T) {
	handler := NewNetworkHandler(nil, nil)
	router := newNetworkRouter(handler)

	tests := []struct {
		name       string
		endpoint   string
		mac        string
		wantStatus int
	}{
		{"kick - invalid MAC", "/api/v1/network/wifi/ap/clients/ZZZZ/kick", "ZZZZ", http.StatusBadRequest},
		{"kick - empty string MAC", "/api/v1/network/wifi/ap/clients//kick", "", http.StatusBadRequest}, // chi won't match empty param
		{"block - invalid MAC", "/api/v1/network/wifi/ap/clients/not-a-mac/block", "not-a-mac", http.StatusBadRequest},
		{"block - partial MAC", "/api/v1/network/wifi/ap/clients/AA:BB:CC/block", "AA:BB:CC", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", tt.endpoint, nil)
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
		})
	}
}

// =============================================================================
// HAL Service Unavailable Tests (nil halClient)
// =============================================================================

func TestHALServiceUnavailable(t *testing.T) {
	handler := NewNetworkHandler(nil, nil) // nil halClient
	router := newNetworkRouter(handler)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"start AP", "POST", "/api/v1/network/ap/start"},
		{"stop AP", "POST", "/api/v1/network/ap/stop"},
		{"restart AP", "POST", "/api/v1/network/wifi/ap/restart"},
		{"get interfaces", "GET", "/api/v1/network/interfaces"},
		{"get interfaces detailed", "GET", "/api/v1/network/interfaces/detailed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want %d (service unavailable)", rr.Code, http.StatusServiceUnavailable)
			}
		})
	}
}

// =============================================================================
// SetVPNMode Validation Tests
// =============================================================================

func TestSetVPNModeValidation(t *testing.T) {
	handler := NewNetworkHandler(nil, nil)
	router := newNetworkRouter(handler)

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
			name:       "invalid VPN mode",
			body:       `{"mode": "ipsec"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid VPN mode: must be none, wireguard, openvpn, or tor",
		},
		{
			name:       "wireguard without config_id",
			body:       `{"mode": "wireguard"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "config_id required for wireguard/openvpn modes",
		},
		{
			name:       "openvpn without config_id",
			body:       `{"mode": "openvpn"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "config_id required for wireguard/openvpn modes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/network/vpn/mode", bytes.NewBufferString(tt.body))
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
// SetDNSConfig Validation Tests
// =============================================================================

func TestSetDNSConfigValidation(t *testing.T) {
	handler := NewNetworkHandler(nil, nil)
	router := newNetworkRouter(handler)

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
			wantError:  "Invalid request body",
		},
		{
			name:       "no DNS servers provided",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "At least one DNS server is required (primary_dns or dns_servers)",
		},
		{
			name:       "empty primary and servers",
			body:       `{"primary_dns": "", "dns_servers": []}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "At least one DNS server is required (primary_dns or dns_servers)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/network/dns", bytes.NewBufferString(tt.body))
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
// Network Settings Validation
// =============================================================================

func TestUpdateNetworkSettingsValidation(t *testing.T) {
	handler := NewNetworkHandler(nil, nil)
	router := newNetworkRouter(handler)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "invalid JSON",
			body:       `{not-json`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/api/v1/network/settings", bytes.NewBufferString(tt.body))
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

func TestNetworkRoutes(t *testing.T) {
	handler := NewNetworkHandler(nil, nil)
	routes := handler.Routes()

	if routes == nil {
		t.Fatal("Routes() returned nil")
	}
}

// TestNetworkRouteMethods verifies all expected network endpoints are registered.
// Handlers with nil managers will panic — we recover gracefully since
// we're testing route registration, not handler logic.
func TestNetworkRouteMethods(t *testing.T) {
	handler := NewNetworkHandler(nil, nil)
	router := newNetworkRouter(handler)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"GET status", "GET", "/api/v1/network/status"},
		{"GET mode", "GET", "/api/v1/network/mode"},
		{"POST mode", "POST", "/api/v1/network/mode"},
		{"GET modes", "GET", "/api/v1/network/modes"},
		{"GET internet", "GET", "/api/v1/network/internet"},
		{"GET connectivity", "GET", "/api/v1/network/connectivity"},
		{"GET interfaces", "GET", "/api/v1/network/interfaces"},
		{"GET interfaces detailed", "GET", "/api/v1/network/interfaces/detailed"},
		{"GET wifi scan", "GET", "/api/v1/network/wifi/scan"},
		{"GET wifi status", "GET", "/api/v1/network/wifi/status"},
		{"POST wifi connect", "POST", "/api/v1/network/wifi/connect"},
		{"POST wifi disconnect", "POST", "/api/v1/network/wifi/disconnect"},
		{"GET wifi saved", "GET", "/api/v1/network/wifi/saved"},
		{"DELETE wifi saved SSID", "DELETE", "/api/v1/network/wifi/saved/TestNet"},
		{"GET AP status", "GET", "/api/v1/network/wifi/ap/status"},
		{"POST AP restart", "POST", "/api/v1/network/wifi/ap/restart"},
		{"GET AP clients", "GET", "/api/v1/network/wifi/ap/clients"},
		{"POST kick client", "POST", "/api/v1/network/wifi/ap/clients/AA:BB:CC:DD:EE:FF/kick"},
		{"POST block client", "POST", "/api/v1/network/wifi/ap/clients/AA:BB:CC:DD:EE:FF/block"},
		{"GET AP config", "GET", "/api/v1/network/ap/config"},
		{"PUT AP config", "PUT", "/api/v1/network/ap/config"},
		{"POST AP start", "POST", "/api/v1/network/ap/start"},
		{"POST AP stop", "POST", "/api/v1/network/ap/stop"},
		{"GET traffic", "GET", "/api/v1/network/traffic"},
		{"GET traffic history", "GET", "/api/v1/network/traffic/eth0/history"},
		{"GET settings", "GET", "/api/v1/network/settings"},
		{"PUT settings", "PUT", "/api/v1/network/settings"},
		{"GET VPN mode", "GET", "/api/v1/network/vpn/mode"},
		{"POST VPN mode", "POST", "/api/v1/network/vpn/mode"},
		{"POST dismiss warning", "POST", "/api/v1/network/warning/dismiss"},
		{"GET DNS", "GET", "/api/v1/network/dns"},
		{"POST DNS", "POST", "/api/v1/network/dns"},
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
				t.Errorf("route returned 404 — not registered: %s %s", tt.method, tt.path)
			}
			if rr.Code == http.StatusMethodNotAllowed {
				t.Errorf("route returned 405 — method not registered: %s %s", tt.method, tt.path)
			}
		})
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestIsValidMAC(t *testing.T) {
	tests := []struct {
		mac   string
		valid bool
	}{
		{"AA:BB:CC:DD:EE:FF", true},
		{"aa:bb:cc:dd:ee:ff", true},
		{"00:11:22:33:44:55", true},
		{"AA-BB-CC-DD-EE-FF", true}, // Dash format
		{"ZZZZ", false},
		{"AA:BB:CC", false},
		{"AA:BB:CC:DD:EE:GG", false}, // 'G' is invalid hex
		{"", false},
		{"00:00:00:00:00:00:00", false}, // Too many octets
		{"AA:BB:CC:DD:EE:F", false},     // Short octet
	}

	for _, tt := range tests {
		t.Run(tt.mac, func(t *testing.T) {
			result := isValidMAC(tt.mac)
			if result != tt.valid {
				t.Errorf("isValidMAC(%q) = %v, want %v", tt.mac, result, tt.valid)
			}
		})
	}
}

func TestGetModeDescription(t *testing.T) {
	tests := []struct {
		mode string
		want string
	}{
		{"offline", "Air-gapped access point mode"},
		{"online_eth", "AP + NAT via Ethernet uplink"},
		{"online_wifi", "AP + NAT via USB WiFi dongle"},
		{"server_eth", "No AP, direct Ethernet connection"},
		{"server_wifi", "No AP, direct WiFi connection"},
		{"unknown", "Unknown mode"},
		{"", "Unknown mode"},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			got := getModeDescription(tt.mode)
			if got != tt.want {
				t.Errorf("getModeDescription(%q) = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}
