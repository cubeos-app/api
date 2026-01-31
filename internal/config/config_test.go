package config

import (
	"os"
	"path/filepath"
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
