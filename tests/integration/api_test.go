// Package integration provides API integration tests for CubeOS.
// Run with: go test -tags=integration ./tests/integration/...
//
//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

var (
	baseURL  = getEnv("CUBEOS_API_URL", "http://10.42.24.1:6010")
	username = getEnv("CUBEOS_USERNAME", "admin")
	password = getEnv("CUBEOS_PASSWORD", "cubeos")
	token    string
)

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// TestMain authenticates before running tests
func TestMain(m *testing.M) {
	// Authenticate
	var err error
	token, err = authenticate()
	if err != nil {
		fmt.Printf("Failed to authenticate: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Authenticated successfully, token obtained\n")

	// Run tests
	code := m.Run()
	os.Exit(code)
}

func authenticate() (string, error) {
	body := map[string]string{
		"username": username,
		"password": password,
	}
	jsonBody, _ := json.Marshal(body)

	resp, err := http.Post(baseURL+"/api/v1/auth/login", "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login failed with status %d", resp.StatusCode)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Token, nil
}

func authRequest(method, path string, body interface{}) (*http.Response, error) {
	var reqBody *bytes.Reader
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		reqBody = bytes.NewReader(jsonBody)
	} else {
		reqBody = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, baseURL+path, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

// ============================================================
// Health Tests
// ============================================================

func TestHealth(t *testing.T) {
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if result["status"] != "ok" {
		t.Errorf("Expected status 'ok', got '%v'", result["status"])
	}
}

// ============================================================
// Apps API Tests
// ============================================================

func TestListApps(t *testing.T) {
	resp, err := authRequest("GET", "/api/v1/apps", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result struct {
		Apps []map[string]interface{} `json:"apps"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	t.Logf("Found %d apps", len(result.Apps))
}

func TestListAppsWithFilter(t *testing.T) {
	// Test type filter
	resp, err := authRequest("GET", "/api/v1/apps?type=system", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result struct {
		Apps []map[string]interface{} `json:"apps"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	// All returned apps should be system type
	for _, app := range result.Apps {
		if app["type"] != "system" {
			t.Errorf("Expected type 'system', got '%v'", app["type"])
		}
	}
}

func TestGetAppNotFound(t *testing.T) {
	resp, err := authRequest("GET", "/api/v1/apps/nonexistent-app-xyz", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

// ============================================================
// Network API Tests
// ============================================================

func TestGetNetworkStatus(t *testing.T) {
	resp, err := authRequest("GET", "/api/v1/network/status", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result struct {
		Mode      string `json:"mode"`
		Internet  bool   `json:"internet"`
		Subnet    string `json:"subnet"`
		GatewayIP string `json:"gateway_ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Validate mode is one of expected values
	validModes := map[string]bool{"offline": true, "online_eth": true, "online_wifi": true}
	if !validModes[result.Mode] {
		t.Errorf("Invalid network mode: %s", result.Mode)
	}

	// Validate subnet format
	if result.Subnet == "" {
		t.Error("Subnet should not be empty")
	}

	t.Logf("Network mode: %s, Internet: %v, Subnet: %s", result.Mode, result.Internet, result.Subnet)
}

func TestScanWiFiNetworks(t *testing.T) {
	resp, err := authRequest("GET", "/api/v1/network/wifi/scan", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// May return 200 with empty list or error if no WiFi hardware
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 200 or 500, got %d", resp.StatusCode)
	}

	if resp.StatusCode == http.StatusOK {
		var result struct {
			Networks []map[string]interface{} `json:"networks"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		t.Logf("Found %d WiFi networks", len(result.Networks))
	}
}

// ============================================================
// VPN API Tests
// ============================================================

func TestGetVPNStatus(t *testing.T) {
	resp, err := authRequest("GET", "/api/v1/vpn/status", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result struct {
		Connected bool `json:"connected"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	t.Logf("VPN connected: %v", result.Connected)
}

func TestListVPNConfigs(t *testing.T) {
	resp, err := authRequest("GET", "/api/v1/vpn/configs", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result struct {
		Configs []map[string]interface{} `json:"configs"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	t.Logf("Found %d VPN configs", len(result.Configs))
}

func TestAddVPNConfigValidation(t *testing.T) {
	// Test with missing required fields
	resp, err := authRequest("POST", "/api/v1/vpn/configs", map[string]string{
		"name": "test-vpn",
		// Missing type and config
	})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing fields, got %d", resp.StatusCode)
	}
}

func TestVPNConfigLifecycle(t *testing.T) {
	// Skip if running in CI without VPN support
	if os.Getenv("SKIP_VPN_TESTS") != "" {
		t.Skip("Skipping VPN tests")
	}

	configName := fmt.Sprintf("test-vpn-%d", time.Now().Unix())

	// Create a minimal WireGuard config for testing
	wgConfig := `[Interface]
PrivateKey = cGFzc3dvcmQ=
Address = 10.0.0.2/24

[Peer]
PublicKey = cHVibGljLWtleQ==
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0`

	// Add config
	resp, err := authRequest("POST", "/api/v1/vpn/configs", map[string]string{
		"name":   configName,
		"type":   "wireguard",
		"config": base64.StdEncoding.EncodeToString([]byte(wgConfig)),
	})
	if err != nil {
		t.Fatalf("Failed to add VPN config: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d", resp.StatusCode)
	}

	// Verify it exists
	resp, err = authRequest("GET", "/api/v1/vpn/configs/"+configName, nil)
	if err != nil {
		t.Fatalf("Failed to get VPN config: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Delete config
	resp, err = authRequest("DELETE", "/api/v1/vpn/configs/"+configName, nil)
	if err != nil {
		t.Fatalf("Failed to delete VPN config: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify it's deleted
	resp, err = authRequest("GET", "/api/v1/vpn/configs/"+configName, nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404 after deletion, got %d", resp.StatusCode)
	}
}

func TestGetPublicIP(t *testing.T) {
	resp, err := authRequest("GET", "/api/v1/vpn/public-ip", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// May fail if no internet connection
	if resp.StatusCode == http.StatusOK {
		var result struct {
			PublicIP string `json:"public_ip"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		t.Logf("Public IP: %s", result.PublicIP)
	} else {
		t.Logf("Could not get public IP (status %d) - may be offline", resp.StatusCode)
	}
}

// ============================================================
// Mounts API Tests
// ============================================================

func TestListMounts(t *testing.T) {
	resp, err := authRequest("GET", "/api/v1/mounts", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result struct {
		Mounts []map[string]interface{} `json:"mounts"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	t.Logf("Found %d mounts", len(result.Mounts))
}

func TestAddMountValidation(t *testing.T) {
	// Test with missing required fields
	resp, err := authRequest("POST", "/api/v1/mounts", map[string]string{
		"name": "test-mount",
		// Missing type and remote_path
	})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing fields, got %d", resp.StatusCode)
	}
}

func TestAddMountInvalidSMBPath(t *testing.T) {
	resp, err := authRequest("POST", "/api/v1/mounts", map[string]interface{}{
		"name":        "test-smb",
		"type":        "smb",
		"remote_path": "invalid-path", // Should start with //
	})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid SMB path, got %d", resp.StatusCode)
	}
}

func TestAddMountInvalidNFSPath(t *testing.T) {
	resp, err := authRequest("POST", "/api/v1/mounts", map[string]interface{}{
		"name":        "test-nfs",
		"type":        "nfs",
		"remote_path": "invalid-path", // Should contain :
	})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid NFS path, got %d", resp.StatusCode)
	}
}

func TestMountNotFound(t *testing.T) {
	resp, err := authRequest("GET", "/api/v1/mounts/nonexistent-mount-xyz", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

func TestTestMountConnection(t *testing.T) {
	// Test with invalid host - should fail but not crash
	resp, err := authRequest("POST", "/api/v1/mounts/test", map[string]interface{}{
		"type":        "smb",
		"remote_path": "//192.0.2.1/share", // TEST-NET-1, won't exist
	})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	// Connection should fail but API should return properly
	if result.Success {
		t.Error("Expected connection to fail for non-existent host")
	}
}

// ============================================================
// Profiles API Tests
// ============================================================

func TestListProfiles(t *testing.T) {
	resp, err := authRequest("GET", "/api/v1/profiles", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result struct {
		Profiles      []map[string]interface{} `json:"profiles"`
		ActiveProfile string                   `json:"active_profile"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	t.Logf("Found %d profiles, active: %s", len(result.Profiles), result.ActiveProfile)
}

func TestGetProfileNotFound(t *testing.T) {
	resp, err := authRequest("GET", "/api/v1/profiles/nonexistent-profile-xyz", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

// ============================================================
// System API Tests
// ============================================================

func TestGetSystemInfo(t *testing.T) {
	resp, err := authRequest("GET", "/api/v1/system/info", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// Check required fields
	requiredFields := []string{"hostname", "os", "kernel", "architecture"}
	for _, field := range requiredFields {
		if _, ok := result[field]; !ok {
			t.Errorf("Missing required field: %s", field)
		}
	}

	t.Logf("System: %s, Kernel: %s, Arch: %s",
		result["os"], result["kernel"], result["architecture"])
}

func TestGetSystemStats(t *testing.T) {
	resp, err := authRequest("GET", "/api/v1/system/stats", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	t.Logf("System stats: %+v", result)
}

// ============================================================
// Auth Tests
// ============================================================

func TestAuthRequired(t *testing.T) {
	// Request without token should fail
	req, _ := http.NewRequest("GET", baseURL+"/api/v1/apps", nil)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 without auth, got %d", resp.StatusCode)
	}
}

func TestInvalidToken(t *testing.T) {
	req, _ := http.NewRequest("GET", baseURL+"/api/v1/apps", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-xyz")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for invalid token, got %d", resp.StatusCode)
	}
}

func TestRefreshToken(t *testing.T) {
	resp, err := authRequest("POST", "/api/v1/auth/refresh", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if result.Token == "" {
		t.Error("Expected non-empty refreshed token")
	}
}

func TestGetMe(t *testing.T) {
	resp, err := authRequest("GET", "/api/v1/auth/me", nil)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if result.Username != username {
		t.Errorf("Expected username '%s', got '%s'", username, result.Username)
	}
}
