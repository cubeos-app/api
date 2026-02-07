// Package integration provides end-to-end API integration tests for CubeOS.
// These tests require a running CubeOS API instance.
//
// Run with:
//
//	CUBEOS_API_URL=http://10.42.24.1:6010 go test -v ./tests/integration/...
//
// Or to run locally with mock server:
//
//	go test -v ./tests/integration/... -short
//
//go:build !integration
// +build !integration

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestConfig holds configuration for integration tests
type TestConfig struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

var testConfig *TestConfig

func TestMain(m *testing.M) {
	// Setup
	baseURL := os.Getenv("CUBEOS_API_URL")
	if baseURL == "" {
		baseURL = "http://localhost:6010"
	}

	testConfig = &TestConfig{
		BaseURL: baseURL,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Run tests
	code := m.Run()
	os.Exit(code)
}

// Helper functions

func (tc *TestConfig) doRequest(t *testing.T, method, path string, body interface{}) (*http.Response, []byte) {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Failed to marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, tc.BaseURL+path, bodyReader)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if tc.Token != "" {
		req.Header.Set("Authorization", "Bearer "+tc.Token)
	}

	resp, err := tc.Client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	return resp, respBody
}

func (tc *TestConfig) get(t *testing.T, path string) (*http.Response, []byte) {
	return tc.doRequest(t, http.MethodGet, path, nil)
}

func (tc *TestConfig) post(t *testing.T, path string, body interface{}) (*http.Response, []byte) {
	return tc.doRequest(t, http.MethodPost, path, body)
}

func (tc *TestConfig) put(t *testing.T, path string, body interface{}) (*http.Response, []byte) {
	return tc.doRequest(t, http.MethodPut, path, body)
}

func (tc *TestConfig) delete(t *testing.T, path string) (*http.Response, []byte) {
	return tc.doRequest(t, http.MethodDelete, path, nil)
}

// =============================================================================
// Health Tests
// =============================================================================

func TestHealth(t *testing.T) {
	resp, body := testConfig.get(t, "/health")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if result["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got %v", result["status"])
	}

	if _, ok := result["version"]; !ok {
		t.Error("Response missing 'version' field")
	}

	if _, ok := result["uptime_seconds"]; !ok {
		t.Error("Response missing 'uptime_seconds' field")
	}
}

// =============================================================================
// Apps Tests
// =============================================================================

func TestListApps(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/apps")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Apps []map[string]interface{} `json:"apps"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should have at least the system apps
	if len(result.Apps) == 0 {
		t.Log("Warning: No apps returned, system may not be fully initialized")
	}

	// Verify app structure
	for _, app := range result.Apps {
		requiredFields := []string{"name", "type", "enabled"}
		for _, field := range requiredFields {
			if _, ok := app[field]; !ok {
				t.Errorf("App missing required field '%s': %v", field, app)
			}
		}
	}
}

func TestListAppsWithFilter(t *testing.T) {
	tests := []struct {
		name   string
		filter string
	}{
		{"Filter by type=system", "?type=system"},
		{"Filter by type=platform", "?type=platform"},
		{"Filter by type=user", "?type=user"},
		{"Filter by enabled=true", "?enabled=true"},
		{"Filter by enabled=false", "?enabled=false"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := testConfig.get(t, "/api/v1/apps"+tt.filter)

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d: %s", resp.StatusCode, body)
			}

			var result struct {
				Apps []map[string]interface{} `json:"apps"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				t.Fatalf("Failed to parse response: %v", err)
			}
		})
	}
}

func TestGetAppNotFound(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/apps/nonexistent-app-xyz")

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}

	if _, ok := result["error"]; !ok {
		t.Error("Error response missing 'error' field")
	}
}

func TestGetSystemApp(t *testing.T) {
	// Try to get pihole (should always exist as system app)
	resp, body := testConfig.get(t, "/api/v1/apps/pihole")

	// Could be 200 or 404 depending on system state
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 200 or 404, got %d: %s", resp.StatusCode, body)
	}

	if resp.StatusCode == http.StatusOK {
		var app map[string]interface{}
		if err := json.Unmarshal(body, &app); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if app["name"] != "pihole" {
			t.Errorf("Expected app name 'pihole', got %v", app["name"])
		}

		if app["type"] != "system" {
			t.Errorf("Expected app type 'system', got %v", app["type"])
		}
	}
}

func TestGetAppLogs(t *testing.T) {
	// Try to get logs for API itself (should always be running)
	resp, body := testConfig.get(t, "/api/v1/apps/cubeos-api/logs?lines=10")

	// Could be 200 or 404 depending on system state
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 200 or 404, got %d: %s", resp.StatusCode, body)
	}
}

func TestAppLifecycleOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping lifecycle tests in short mode")
	}

	// These tests require a non-system app to be installed
	// Skip if running against production

	t.Run("Start app returns appropriate response", func(t *testing.T) {
		resp, _ := testConfig.post(t, "/api/v1/apps/test-app/start", nil)
		// Expect 404 (app not found) or 200 (success) or 403 (system app)
		validCodes := []int{http.StatusOK, http.StatusNotFound, http.StatusForbidden}
		found := false
		for _, code := range validCodes {
			if resp.StatusCode == code {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected status in %v, got %d", validCodes, resp.StatusCode)
		}
	})

	t.Run("Stop app returns appropriate response", func(t *testing.T) {
		resp, _ := testConfig.post(t, "/api/v1/apps/test-app/stop", nil)
		validCodes := []int{http.StatusOK, http.StatusNotFound, http.StatusForbidden}
		found := false
		for _, code := range validCodes {
			if resp.StatusCode == code {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected status in %v, got %d", validCodes, resp.StatusCode)
		}
	})

	t.Run("Restart app returns appropriate response", func(t *testing.T) {
		resp, _ := testConfig.post(t, "/api/v1/apps/test-app/restart", nil)
		validCodes := []int{http.StatusOK, http.StatusNotFound, http.StatusForbidden}
		found := false
		for _, code := range validCodes {
			if resp.StatusCode == code {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected status in %v, got %d", validCodes, resp.StatusCode)
		}
	})
}

func TestAppTorRouting(t *testing.T) {
	body := map[string]bool{"enabled": true}
	resp, respBody := testConfig.post(t, "/api/v1/apps/test-app/tor", body)

	// Expect 404 (app not found) or 200 (success)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 200 or 404, got %d: %s", resp.StatusCode, respBody)
	}
}

// =============================================================================
// Network Tests
// =============================================================================

func TestGetNetworkStatus(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/network/status")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify required fields
	requiredFields := []string{"mode", "subnet", "gateway_ip"}
	for _, field := range requiredFields {
		if _, ok := result[field]; !ok {
			t.Errorf("Response missing required field '%s'", field)
		}
	}

	// Verify mode is valid
	validModes := []string{"offline", "online_eth", "online_wifi"}
	mode, ok := result["mode"].(string)
	if !ok {
		t.Error("Mode field is not a string")
	} else {
		found := false
		for _, m := range validModes {
			if mode == m {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Invalid mode '%s', expected one of %v", mode, validModes)
		}
	}
}

func TestWiFiScan(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/network/wifi/scan")

	// WiFi scan may fail if no WiFi interface available
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("Expected status 200 or 503, got %d: %s", resp.StatusCode, body)
	}

	if resp.StatusCode == http.StatusOK {
		var result struct {
			Networks []map[string]interface{} `json:"networks"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		// Verify network structure if any found
		for _, network := range result.Networks {
			requiredFields := []string{"ssid", "signal"}
			for _, field := range requiredFields {
				if _, ok := network[field]; !ok {
					t.Errorf("Network missing required field '%s': %v", field, network)
				}
			}
		}
	}
}

func TestGetAPConfig(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/network/ap/config")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should have SSID at minimum
	if _, ok := result["ssid"]; !ok {
		t.Error("AP config missing 'ssid' field")
	}
}

func TestGetAPClients(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/network/ap/clients")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Clients []map[string]interface{} `json:"clients"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Clients list may be empty
	t.Logf("Found %d connected clients", len(result.Clients))
}

func TestSetNetworkModeValidation(t *testing.T) {
	tests := []struct {
		name         string
		body         map[string]interface{}
		expectStatus int
	}{
		{
			name:         "Invalid mode",
			body:         map[string]interface{}{"mode": "invalid_mode"},
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Missing mode",
			body:         map[string]interface{}{},
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Online WiFi without credentials",
			body:         map[string]interface{}{"mode": "online_wifi"},
			expectStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := testConfig.post(t, "/api/v1/network/mode", tt.body)

			if resp.StatusCode != tt.expectStatus {
				t.Errorf("Expected status %d, got %d: %s", tt.expectStatus, resp.StatusCode, body)
			}
		})
	}
}

// =============================================================================
// VPN Tests
// =============================================================================

func TestGetVPNStatus(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/vpn/status")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should have connected field
	if _, ok := result["connected"]; !ok {
		t.Error("VPN status missing 'connected' field")
	}
}

func TestListVPNConfigs(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/vpn/configs")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Configs []map[string]interface{} `json:"configs"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Configs list may be empty
	t.Logf("Found %d VPN configs", len(result.Configs))

	// Verify config structure if any exist
	for _, config := range result.Configs {
		requiredFields := []string{"name", "type"}
		for _, field := range requiredFields {
			if _, ok := config[field]; !ok {
				t.Errorf("VPN config missing required field '%s': %v", field, config)
			}
		}
	}
}

func TestGetVPNConfigNotFound(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/vpn/configs/nonexistent-vpn")

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d: %s", resp.StatusCode, body)
	}
}

func TestAddVPNConfigValidation(t *testing.T) {
	tests := []struct {
		name         string
		body         map[string]interface{}
		expectStatus int
	}{
		{
			name:         "Missing name",
			body:         map[string]interface{}{"type": "wireguard", "config": "base64data"},
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Missing type",
			body:         map[string]interface{}{"name": "test-vpn", "config": "base64data"},
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Invalid type",
			body:         map[string]interface{}{"name": "test-vpn", "type": "invalid", "config": "data"},
			expectStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := testConfig.post(t, "/api/v1/vpn/configs", tt.body)

			if resp.StatusCode != tt.expectStatus {
				t.Errorf("Expected status %d, got %d: %s", tt.expectStatus, resp.StatusCode, body)
			}
		})
	}
}

func TestGetPublicIP(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/vpn/public-ip")

	// May fail if no internet connection
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("Expected status 200 or 503, got %d: %s", resp.StatusCode, body)
	}

	if resp.StatusCode == http.StatusOK {
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if _, ok := result["ip"]; !ok {
			t.Error("Response missing 'ip' field")
		}
	}
}

// =============================================================================
// Mounts Tests
// =============================================================================

func TestListMounts(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/mounts")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Mounts []map[string]interface{} `json:"mounts"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Mounts list may be empty
	t.Logf("Found %d mounts", len(result.Mounts))

	// Verify mount structure if any exist
	for _, mount := range result.Mounts {
		requiredFields := []string{"name", "type", "remote_path", "local_path"}
		for _, field := range requiredFields {
			if _, ok := mount[field]; !ok {
				t.Errorf("Mount missing required field '%s': %v", field, mount)
			}
		}
	}
}

func TestGetMountNotFound(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/mounts/nonexistent-mount")

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d: %s", resp.StatusCode, body)
	}
}

func TestCreateMountValidation(t *testing.T) {
	tests := []struct {
		name         string
		body         map[string]interface{}
		expectStatus int
	}{
		{
			name:         "Missing name",
			body:         map[string]interface{}{"type": "smb", "remote_path": "//server/share"},
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Missing type",
			body:         map[string]interface{}{"name": "test-mount", "remote_path": "//server/share"},
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Missing remote_path",
			body:         map[string]interface{}{"name": "test-mount", "type": "smb"},
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Invalid type",
			body:         map[string]interface{}{"name": "test-mount", "type": "invalid", "remote_path": "//server/share"},
			expectStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := testConfig.post(t, "/api/v1/mounts", tt.body)

			if resp.StatusCode != tt.expectStatus {
				t.Errorf("Expected status %d, got %d: %s", tt.expectStatus, resp.StatusCode, body)
			}
		})
	}
}

func TestMountTestConnection(t *testing.T) {
	// Test connection validation
	body := map[string]interface{}{
		"name":        "test-connection",
		"type":        "smb",
		"remote_path": "//invalid-server/share",
	}

	resp, respBody := testConfig.post(t, "/api/v1/mounts/test", body)

	// Should return 200 with success=false or 500 for connection failure
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 200 or 500, got %d: %s", resp.StatusCode, respBody)
	}
}

// =============================================================================
// Profiles Tests
// =============================================================================

func TestListProfiles(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/profiles")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Profiles      []map[string]interface{} `json:"profiles"`
		ActiveProfile string                   `json:"active_profile"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should have at least system profiles (full, minimal, offline)
	if len(result.Profiles) == 0 {
		t.Log("Warning: No profiles returned")
	}

	// Verify profile structure
	for _, profile := range result.Profiles {
		requiredFields := []string{"name", "display_name"}
		for _, field := range requiredFields {
			if _, ok := profile[field]; !ok {
				t.Errorf("Profile missing required field '%s': %v", field, profile)
			}
		}
	}
}

func TestGetProfileNotFound(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/profiles/nonexistent-profile")

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d: %s", resp.StatusCode, body)
	}
}

func TestCreateProfileValidation(t *testing.T) {
	tests := []struct {
		name         string
		body         map[string]interface{}
		expectStatus int
	}{
		{
			name:         "Missing name",
			body:         map[string]interface{}{"display_name": "Test Profile"},
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Missing display_name",
			body:         map[string]interface{}{"name": "test-profile"},
			expectStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := testConfig.post(t, "/api/v1/profiles", tt.body)

			if resp.StatusCode != tt.expectStatus {
				t.Errorf("Expected status %d, got %d: %s", tt.expectStatus, resp.StatusCode, body)
			}
		})
	}
}

func TestApplyProfileNotFound(t *testing.T) {
	resp, body := testConfig.post(t, "/api/v1/profiles/nonexistent-profile/apply", nil)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d: %s", resp.StatusCode, body)
	}
}

// =============================================================================
// System Tests
// =============================================================================

func TestGetSystemInfo(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/system/info")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify required fields
	requiredFields := []string{"hostname", "platform", "architecture"}
	for _, field := range requiredFields {
		if _, ok := result[field]; !ok {
			t.Errorf("Response missing required field '%s'", field)
		}
	}
}

func TestGetSystemStats(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/system/stats")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify has cpu, memory, disk sections
	sections := []string{"cpu", "memory", "disk"}
	for _, section := range sections {
		if _, ok := result[section]; !ok {
			t.Errorf("Response missing '%s' section", section)
		}
	}
}

func TestGetTemperature(t *testing.T) {
	resp, body := testConfig.get(t, "/api/v1/system/temperature")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should have celsius or fahrenheit
	if _, ok := result["celsius"]; !ok {
		t.Error("Response missing 'celsius' field")
	}
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestNotFoundEndpoint(t *testing.T) {
	resp, _ := testConfig.get(t, "/api/v1/nonexistent")

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

func TestInvalidJSON(t *testing.T) {
	// Create a raw request with invalid JSON
	req, err := http.NewRequest(http.MethodPost, testConfig.BaseURL+"/api/v1/apps", bytes.NewReader([]byte("{invalid json")))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := testConfig.Client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

// =============================================================================
// Concurrency Tests
// =============================================================================

func TestConcurrentRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrency test in short mode")
	}

	const numRequests = 10
	type result struct {
		statusCode int
		err        error
	}
	results := make(chan result, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			client := &http.Client{Timeout: 30 * time.Second}
			resp, err := client.Get(testConfig.BaseURL + "/health")
			if err != nil {
				results <- result{0, err}
				return
			}
			resp.Body.Close()
			results <- result{resp.StatusCode, nil}
		}()
	}

	// Wait for all requests to complete
	timeout := time.After(30 * time.Second)
	for i := 0; i < numRequests; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Errorf("Concurrent request failed: %v", r.err)
			} else if r.statusCode != http.StatusOK {
				t.Errorf("Concurrent request returned status %d", r.statusCode)
			}
		case <-timeout:
			t.Fatal("Timeout waiting for concurrent requests")
		}
	}
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkHealthEndpoint(b *testing.B) {
	client := &http.Client{Timeout: 10 * time.Second}
	url := testConfig.BaseURL + "/health"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(url)
		if err != nil {
			b.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()
	}
}

func BenchmarkListApps(b *testing.B) {
	client := &http.Client{Timeout: 10 * time.Second}
	url := testConfig.BaseURL + "/api/v1/apps"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(url)
		if err != nil {
			b.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()
	}
}

func BenchmarkNetworkStatus(b *testing.B) {
	client := &http.Client{Timeout: 10 * time.Second}
	url := testConfig.BaseURL + "/api/v1/network/status"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(url)
		if err != nil {
			b.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()
	}
}
