package managers

import (
	"testing"

	"cubeos-api/internal/models"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// Equal versions
		{"0.2.0", "0.2.0", 0},
		{"1.0.0", "1.0.0", 0},
		{"0.2.0-alpha.01", "0.2.0-alpha.01", 0},

		// Major/minor/patch ordering
		{"0.1.0", "0.2.0", -1},
		{"0.2.0", "0.1.0", 1},
		{"1.0.0", "0.9.9", 1},
		{"0.2.0", "0.2.1", -1},
		{"0.2.1", "0.2.0", 1},

		// Pre-release < release
		{"0.2.0-alpha.01", "0.2.0", -1},
		{"0.2.0", "0.2.0-alpha.01", 1},
		{"0.2.0-beta.01", "0.2.0", -1},

		// Pre-release ordering: alpha < beta < rc
		{"0.2.0-alpha.01", "0.2.0-beta.01", -1},
		{"0.2.0-beta.01", "0.2.0-alpha.01", 1},
		{"0.2.0-alpha.01", "0.2.0-rc.01", -1},
		{"0.2.0-beta.01", "0.2.0-rc.01", -1},

		// Numeric pre-release parts
		{"0.2.0-alpha.01", "0.2.0-alpha.02", -1},
		{"0.2.0-alpha.02", "0.2.0-alpha.01", 1},
		{"0.2.0-alpha.10", "0.2.0-alpha.2", 1},

		// v-prefix handling
		{"v0.2.0", "0.2.0", 0},
		{"v0.2.0-alpha.01", "0.2.0-alpha.02", -1},

		// More complex pre-release
		{"0.2.0-alpha", "0.2.0-alpha.1", -1},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestDetectChannel(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"0.2.0-alpha.01", "alpha"},
		{"0.2.0-beta.01", "beta"},
		{"0.2.0-rc.01", "rc"},
		{"0.2.0", "stable"},
		{"1.0.0", "stable"},
		{"v0.2.0-alpha.02", "alpha"},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := detectChannel(tt.version)
			if got != tt.want {
				t.Errorf("detectChannel(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestChannelCompatible(t *testing.T) {
	tests := []struct {
		current, rel string
		want         bool
	}{
		{"alpha", "alpha", true},
		{"alpha", "beta", true},
		{"alpha", "stable", true},
		{"beta", "alpha", false},
		{"beta", "beta", true},
		{"beta", "stable", true},
		{"stable", "alpha", false},
		{"stable", "beta", false},
		{"stable", "stable", true},
		{"rc", "alpha", false},
		{"rc", "beta", false},
		{"rc", "rc", true},
		{"rc", "stable", true},
	}

	for _, tt := range tests {
		t.Run(tt.current+"_sees_"+tt.rel, func(t *testing.T) {
			got := channelCompatible(tt.current, tt.rel)
			if got != tt.want {
				t.Errorf("channelCompatible(%q, %q) = %v, want %v", tt.current, tt.rel, got, tt.want)
			}
		})
	}
}

func TestParseReleaseBody(t *testing.T) {
	body := `## Release Notes
This is a test release with various improvements.
Fixed several bugs.

## Breaking Changes
- Changed API endpoint /foo to /bar
- Removed deprecated field "baz"

## Images
api=0.2.0-alpha.02
dashboard=0.2.0-alpha.02
hal=latest
pihole=latest
`
	notes, breaking, images := parseReleaseBody(body)

	if !containsSubstring(notes, "test release") {
		t.Errorf("expected notes to contain 'test release', got: %q", notes)
	}

	if len(breaking) != 2 {
		t.Fatalf("expected 2 breaking changes, got %d", len(breaking))
	}
	if breaking[0] != "Changed API endpoint /foo to /bar" {
		t.Errorf("unexpected breaking[0]: %q", breaking[0])
	}

	if len(images) != 4 {
		t.Fatalf("expected 4 images, got %d: %v", len(images), images)
	}
	if images["api"] != "0.2.0-alpha.02" {
		t.Errorf("expected api image '0.2.0-alpha.02', got %q", images["api"])
	}
}

func TestParseReleaseBodyNoSections(t *testing.T) {
	body := "Just some plain release notes with no structured sections."
	notes, breaking, images := parseReleaseBody(body)

	if notes != body {
		t.Errorf("expected full body as notes, got: %q", notes)
	}
	if len(breaking) != 0 {
		t.Errorf("expected no breaking changes, got %d", len(breaking))
	}
	if len(images) != 0 {
		t.Errorf("expected no images, got %d", len(images))
	}
}

func TestParseReleaseBodyEmpty(t *testing.T) {
	notes, breaking, images := parseReleaseBody("")
	if notes != "" || len(breaking) != 0 || len(images) != 0 {
		t.Errorf("expected empty results for empty body")
	}
}

func TestValidateUpdate(t *testing.T) {
	m := &UpdateManager{currentVer: "0.2.0-alpha.01"}

	t.Run("nil manifest", func(t *testing.T) {
		err := m.ValidateUpdate(nil)
		if err == nil {
			t.Error("expected error for nil manifest")
		}
	})

	t.Run("min version met", func(t *testing.T) {
		err := m.ValidateUpdate(&models.ReleaseManifest{
			Version:    "0.2.0-alpha.02",
			MinVersion: "0.1.0",
		})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("min version not met", func(t *testing.T) {
		err := m.ValidateUpdate(&models.ReleaseManifest{
			Version:    "0.3.0",
			MinVersion: "0.2.1",
		})
		if err == nil {
			t.Error("expected error for min version gate")
		}
	})
}

func TestParseSemver(t *testing.T) {
	tests := []struct {
		input               string
		major, minor, patch int
		pre                 string
	}{
		{"0.2.0-alpha.01", 0, 2, 0, "alpha.01"},
		{"1.0.0", 1, 0, 0, ""},
		{"v0.2.0-beta.1", 0, 2, 0, "beta.1"},
		{"0.2.0", 0, 2, 0, ""},
		{"3.14.159", 3, 14, 159, ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			major, minor, patch, pre := parseSemver(tt.input)
			if major != tt.major || minor != tt.minor || patch != tt.patch || pre != tt.pre {
				t.Errorf("parseSemver(%q) = (%d, %d, %d, %q), want (%d, %d, %d, %q)",
					tt.input, major, minor, patch, pre, tt.major, tt.minor, tt.patch, tt.pre)
			}
		})
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && contains(s, sub))
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
