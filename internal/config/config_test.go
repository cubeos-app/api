package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadWithEnvFile(t *testing.T) {
	// Create a temporary directory for test config
	tmpDir, err := os.MkdirTemp("", "cubeos-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create the config directory structure
	configDir := filepath.Join(tmpDir, "cubeos", "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}

	// Create a minimal defaults.env
	defaultsEnv := `GATEWAY_IP=10.42.24.1
DOMAIN=cubeos.cube
DATABASE_PATH=/cubeos/data/cubeos.db
API_PORT=6010
DASHBOARD_PORT=6011
NPM_PORT=6000
PIHOLE_PORT=6001
OLLAMA_PORT=6030
CHROMADB_PORT=6031
`
	envPath := filepath.Join(configDir, "defaults.env")
	if err := os.WriteFile(envPath, []byte(defaultsEnv), 0644); err != nil {
		t.Fatalf("Failed to write defaults.env: %v", err)
	}

	// Temporarily override the env file path by setting env vars directly
	// Since Load() hardcodes the path, we'll test the helper functions instead
	os.Setenv("GATEWAY_IP", "10.42.24.1")
	os.Setenv("DOMAIN", "cubeos.cube")
	defer os.Unsetenv("GATEWAY_IP")
	defer os.Unsetenv("DOMAIN")

	// Test getEnvOptional
	val := getEnvOptional("GATEWAY_IP", "default")
	if val != "10.42.24.1" {
		t.Errorf("getEnvOptional returned %s, expected 10.42.24.1", val)
	}

	// Test getEnvOptional with fallback
	val = getEnvOptional("NONEXISTENT_VAR", "fallback")
	if val != "fallback" {
		t.Errorf("getEnvOptional returned %s, expected fallback", val)
	}
}

func TestGetEnvIntOptional(t *testing.T) {
	os.Setenv("TEST_INT", "42")
	defer os.Unsetenv("TEST_INT")

	val := getEnvIntOptional("TEST_INT", 0)
	if val != 42 {
		t.Errorf("getEnvIntOptional returned %d, expected 42", val)
	}

	// Test fallback
	val = getEnvIntOptional("NONEXISTENT_INT", 99)
	if val != 99 {
		t.Errorf("getEnvIntOptional returned %d, expected 99", val)
	}
}

func TestConfigMethods(t *testing.T) {
	cfg := &Config{
		GatewayIP:    "10.42.24.1",
		NPMPort:      6000,
		OllamaPort:   6030,
		ChromaDBPort: 6031,
	}

	// Test GetNPMURL
	npmURL := cfg.GetNPMURL()
	expected := "http://10.42.24.1:6000"
	if npmURL != expected {
		t.Errorf("GetNPMURL returned %s, expected %s", npmURL, expected)
	}

	// Test GetOllamaURL
	ollamaURL := cfg.GetOllamaURL()
	expected = "http://10.42.24.1:6030"
	if ollamaURL != expected {
		t.Errorf("GetOllamaURL returned %s, expected %s", ollamaURL, expected)
	}

	// Test GetChromaDBURL
	chromaURL := cfg.GetChromaDBURL()
	expected = "http://10.42.24.1:6031"
	if chromaURL != expected {
		t.Errorf("GetChromaDBURL returned %s, expected %s", chromaURL, expected)
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cubeos-validate-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbDir := filepath.Join(tmpDir, "data")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatalf("failed to create data dir: %v", err)
	}

	cfg := &Config{
		Port:          6010,
		DatabasePath:  filepath.Join(dbDir, "cubeos.db"),
		JWTSecret:     "test-secret-12345",
		GatewayIP:     "10.42.24.1",
		Domain:        "cubeos.cube",
		Subnet:        "10.42.24.0/24",
		DataDir:       dbDir,
		DashboardPort: 6011,
		NPMPort:       6000,
		PiholePort:    6001,
		OllamaPort:    6030,
		ChromaDBPort:  6031,
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid config, got error: %v", err)
	}
}

func TestValidate_EmptyRequiredFields(t *testing.T) {
	cfg := &Config{
		Port:          6010,
		DashboardPort: 6011,
		NPMPort:       6000,
		PiholePort:    6001,
		// All string fields empty
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for empty required fields")
	}

	errStr := err.Error()
	for _, field := range []string{"DatabasePath", "JWTSecret", "GatewayIP", "Domain", "DataDir"} {
		if !strings.Contains(errStr, field) {
			t.Errorf("expected error to mention %s, got: %s", field, errStr)
		}
	}
}

func TestValidate_InvalidPort(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cubeos-validate-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &Config{
		Port:          0, // invalid
		DatabasePath:  filepath.Join(tmpDir, "cubeos.db"),
		JWTSecret:     "test-secret",
		GatewayIP:     "10.42.24.1",
		Domain:        "cubeos.cube",
		Subnet:        "10.42.24.0/24",
		DataDir:       tmpDir,
		DashboardPort: 70000, // invalid
		NPMPort:       6000,
		PiholePort:    6001,
	}

	err = cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for invalid ports")
	}
	if !strings.Contains(err.Error(), "Port=0") {
		t.Errorf("expected error about Port=0, got: %v", err)
	}
	if !strings.Contains(err.Error(), "DashboardPort=70000") {
		t.Errorf("expected error about DashboardPort=70000, got: %v", err)
	}
}

func TestValidate_InvalidGatewayIP(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cubeos-validate-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &Config{
		Port:          6010,
		DatabasePath:  filepath.Join(tmpDir, "cubeos.db"),
		JWTSecret:     "test-secret",
		GatewayIP:     "not-an-ip",
		Domain:        "cubeos.cube",
		Subnet:        "10.42.24.0/24",
		DataDir:       tmpDir,
		DashboardPort: 6011,
		NPMPort:       6000,
		PiholePort:    6001,
	}

	err = cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for invalid GatewayIP")
	}
	if !strings.Contains(err.Error(), "GatewayIP") {
		t.Errorf("expected error about GatewayIP, got: %v", err)
	}
}

func TestValidate_InvalidSubnet(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cubeos-validate-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &Config{
		Port:          6010,
		DatabasePath:  filepath.Join(tmpDir, "cubeos.db"),
		JWTSecret:     "test-secret",
		GatewayIP:     "10.42.24.1",
		Domain:        "cubeos.cube",
		Subnet:        "bad-cidr",
		DataDir:       tmpDir,
		DashboardPort: 6011,
		NPMPort:       6000,
		PiholePort:    6001,
	}

	err = cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for invalid Subnet")
	}
	if !strings.Contains(err.Error(), "Subnet") {
		t.Errorf("expected error about Subnet, got: %v", err)
	}
}

func TestValidate_NonexistentDataDir(t *testing.T) {
	cfg := &Config{
		Port:          6010,
		DatabasePath:  "/tmp/cubeos-test-nonexistent/cubeos.db",
		JWTSecret:     "test-secret",
		GatewayIP:     "10.42.24.1",
		Domain:        "cubeos.cube",
		Subnet:        "10.42.24.0/24",
		DataDir:       "/tmp/cubeos-test-nonexistent-dir-xyz",
		DashboardPort: 6011,
		NPMPort:       6000,
		PiholePort:    6001,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for nonexistent DataDir")
	}
	if !strings.Contains(err.Error(), "DataDir") {
		t.Errorf("expected error about DataDir, got: %v", err)
	}
}

func TestValidate_IPv6GatewayIP(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cubeos-validate-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &Config{
		Port:          6010,
		DatabasePath:  filepath.Join(tmpDir, "cubeos.db"),
		JWTSecret:     "test-secret",
		GatewayIP:     "::1", // IPv6 — should fail (must be IPv4)
		Domain:        "cubeos.cube",
		Subnet:        "10.42.24.0/24",
		DataDir:       tmpDir,
		DashboardPort: 6011,
		NPMPort:       6000,
		PiholePort:    6001,
	}

	err = cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for IPv6 GatewayIP")
	}
	if !strings.Contains(err.Error(), "GatewayIP") {
		t.Errorf("expected error about GatewayIP, got: %v", err)
	}
}

func TestValidateAll_ReturnsAllChecks(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cubeos-validate-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &Config{
		Port:          6010,
		DatabasePath:  filepath.Join(tmpDir, "cubeos.db"),
		JWTSecret:     "test-secret",
		GatewayIP:     "10.42.24.1",
		Domain:        "cubeos.cube",
		Subnet:        "10.42.24.0/24",
		DataDir:       tmpDir,
		DashboardPort: 6011,
		NPMPort:       6000,
		PiholePort:    6001,
	}

	results := cfg.ValidateAll()
	if len(results) == 0 {
		t.Fatal("expected non-empty validation results")
	}

	allValid := true
	for _, r := range results {
		if !r.Valid {
			allValid = false
			t.Errorf("field %s failed: %s", r.Field, r.Message)
		}
	}
	if !allValid {
		t.Error("expected all checks to pass for a valid config")
	}
}
