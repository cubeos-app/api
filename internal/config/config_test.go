package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Clear any env vars that might interfere
	os.Unsetenv("API_PORT")
	os.Unsetenv("JWT_SECRET")

	cfg := Load()

	if cfg.Port != 9009 {
		t.Errorf("Load() default port = %v, want 9009", cfg.Port)
	}

	if cfg.JWTExpirationHours != 24 {
		t.Errorf("Load() default JWT expiration = %v, want 24", cfg.JWTExpirationHours)
	}

	if cfg.Version != "2.0.0" {
		t.Errorf("Load() default version = %v, want 2.0.0", cfg.Version)
	}
}

func TestLoadFromEnv(t *testing.T) {
	os.Setenv("API_PORT", "8080")
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("VERSION", "3.0.0")
	defer os.Unsetenv("API_PORT")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("VERSION")

	cfg := Load()

	if cfg.Port != 8080 {
		t.Errorf("Load() port from env = %v, want 8080", cfg.Port)
	}

	if cfg.JWTSecret != "test-secret" {
		t.Errorf("Load() JWT secret from env = %v, want test-secret", cfg.JWTSecret)
	}

	if cfg.Version != "3.0.0" {
		t.Errorf("Load() version from env = %v, want 3.0.0", cfg.Version)
	}
}

func TestIsCoreService(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		wantCore bool
	}{
		{"cubeos-api is core", "cubeos-api", true},
		{"pihole is core", "pihole", true},
		{"nginx-proxy is core", "nginx-proxy", true},
		{"watchtower pattern", "watchtower", true},
		{"postgres pattern", "postgres-main", true},
		{"random service not core", "my-custom-app", false},
		{"kiwix not core", "kiwix", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsCoreService(tt.service)
			if got != tt.wantCore {
				t.Errorf("IsCoreService(%q) = %v, want %v", tt.service, got, tt.wantCore)
			}
		})
	}
}

func TestInferCategory(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		wantCat  string
	}{
		{"ollama is ai", "ollama", "ai"},
		{"kiwix is knowledge", "kiwix", "knowledge"},
		{"wiki is knowledge", "wikipedia-offline", "knowledge"},
		{"element is communication", "element", "communication"},
		{"filebrowser is files", "filebrowser", "files"},
		{"cryptpad is productivity", "cryptpad", "productivity"},
		{"nginx is infrastructure", "nginx-custom", "infrastructure"},
		{"admin dashboard", "admin-portal", "admin"},
		{"unknown defaults to tools", "random-service", "tools"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InferCategory(tt.service)
			if got != tt.wantCat {
				t.Errorf("InferCategory(%q) = %v, want %v", tt.service, got, tt.wantCat)
			}
		})
	}
}
