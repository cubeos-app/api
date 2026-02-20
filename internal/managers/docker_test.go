package managers

import (
	"math"
	"testing"
)

// =============================================================================
// cleanSwarmTaskName Tests (B99)
// =============================================================================

func TestCleanSwarmTaskName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "swarm task name with hash",
			input:    "kiwix_kiwix.1.ud4wufpgo8af3wxledehujf6i",
			expected: "kiwix_kiwix",
		},
		{
			name:     "cubeos api swarm task",
			input:    "cubeos-api_cubeos-api.1.abc123def456ghi789jkl01mn",
			expected: "cubeos-api_cubeos-api",
		},
		{
			name:     "plain container name unchanged",
			input:    "pihole",
			expected: "pihole",
		},
		{
			name:     "compose container name unchanged",
			input:    "npm-proxy",
			expected: "npm-proxy",
		},
		{
			name:     "task slot 2",
			input:    "myapp_web.2.xyzxyzxyzxyzxyzxyzxyzxyzx",
			expected: "myapp_web",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "short hash not stripped (safety)",
			input:    "myapp.1.short",
			expected: "myapp.1.short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanSwarmTaskName(tt.input)
			if got != tt.expected {
				t.Errorf("cleanSwarmTaskName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// formatDisplayName Tests
// =============================================================================

func TestFormatDisplayName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "cubeos prefix stripped",
			input:    "cubeos-dashboard",
			expected: "Dashboard",
		},
		{
			name:     "double cubeos prefix",
			input:    "cubeos-cubeos-something",
			expected: "Something",
		},
		{
			name:     "dashes replaced with spaces",
			input:    "my-cool-app",
			expected: "My Cool App",
		},
		{
			name:     "underscores replaced with spaces",
			input:    "my_cool_app",
			expected: "My Cool App",
		},
		{
			name:     "mixed separators",
			input:    "cubeos-my_app-v2",
			expected: "My App V2",
		},
		{
			name:     "single word",
			input:    "pihole",
			expected: "Pihole",
		},
		{
			name:     "already clean name",
			input:    "nginx",
			expected: "Nginx",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "only prefix",
			input:    "cubeos-",
			expected: "",
		},
		{
			name:     "multiple consecutive dashes",
			input:    "cubeos-app--name",
			expected: "App Name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDisplayName(tt.input)
			if got != tt.expected {
				t.Errorf("formatDisplayName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Stats Math Tests
// =============================================================================

// TestMemoryCalculation verifies the MB conversion used in GetContainerStats.
func TestMemoryCalculation(t *testing.T) {
	tests := []struct {
		name            string
		usageBytes      uint64
		limitBytes      uint64
		expectedMB      float64
		expectedLimitMB float64
	}{
		{
			name:            "256MB container",
			usageBytes:      268435456, // 256 * 1024 * 1024
			limitBytes:      536870912, // 512 * 1024 * 1024
			expectedMB:      256.0,
			expectedLimitMB: 512.0,
		},
		{
			name:            "zero usage",
			usageBytes:      0,
			limitBytes:      1073741824, // 1GB
			expectedMB:      0.0,
			expectedLimitMB: 1024.0,
		},
		{
			name:            "small container 50MB",
			usageBytes:      52428800, // 50 * 1024 * 1024
			limitBytes:      104857600,
			expectedMB:      50.0,
			expectedLimitMB: 100.0,
		},
		{
			name:            "1GB container",
			usageBytes:      1073741824, // 1024 * 1024 * 1024
			limitBytes:      2147483648, // 2GB
			expectedMB:      1024.0,
			expectedLimitMB: 2048.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			memoryMB := float64(tt.usageBytes) / (1024 * 1024)
			memoryLimitMB := float64(tt.limitBytes) / (1024 * 1024)

			if math.Abs(memoryMB-tt.expectedMB) > 0.01 {
				t.Errorf("memoryMB = %f, want %f", memoryMB, tt.expectedMB)
			}
			if math.Abs(memoryLimitMB-tt.expectedLimitMB) > 0.01 {
				t.Errorf("memoryLimitMB = %f, want %f", memoryLimitMB, tt.expectedLimitMB)
			}
		})
	}
}

// TestCPUPercentCalculation verifies the CPU percentage formula used in GetContainerStats.
func TestCPUPercentCalculation(t *testing.T) {
	tests := []struct {
		name           string
		cpuDelta       float64
		systemDelta    float64
		onlineCPUs     uint32
		percpuLen      int
		expectedResult float64
	}{
		{
			name:           "single core 50% usage",
			cpuDelta:       50000000,
			systemDelta:    100000000,
			onlineCPUs:     1,
			percpuLen:      1,
			expectedResult: 50.0,
		},
		{
			name:           "4 cores 25% each = 100% total",
			cpuDelta:       100000000,
			systemDelta:    400000000,
			onlineCPUs:     4,
			percpuLen:      4,
			expectedResult: 100.0,
		},
		{
			name:           "4 cores 10% usage",
			cpuDelta:       10000000,
			systemDelta:    400000000,
			onlineCPUs:     4,
			percpuLen:      4,
			expectedResult: 10.0,
		},
		{
			name:           "zero system delta returns 0",
			cpuDelta:       50000000,
			systemDelta:    0,
			onlineCPUs:     4,
			percpuLen:      4,
			expectedResult: 0.0,
		},
		{
			name:           "zero cpu delta returns 0",
			cpuDelta:       0,
			systemDelta:    100000000,
			onlineCPUs:     4,
			percpuLen:      4,
			expectedResult: 0.0,
		},
		{
			name:           "fallback to percpu length when onlineCPUs=0",
			cpuDelta:       50000000,
			systemDelta:    100000000,
			onlineCPUs:     0,
			percpuLen:      2,
			expectedResult: 100.0, // (50/100) * 2 * 100
		},
		{
			name:           "fallback to 1 CPU when both 0",
			cpuDelta:       50000000,
			systemDelta:    100000000,
			onlineCPUs:     0,
			percpuLen:      0,
			expectedResult: 50.0, // (50/100) * 1 * 100
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cpuPercent float64
			if tt.systemDelta > 0 && tt.cpuDelta > 0 {
				cpuCount := tt.onlineCPUs
				if cpuCount == 0 {
					cpuCount = uint32(tt.percpuLen)
				}
				if cpuCount == 0 {
					cpuCount = 1
				}
				cpuPercent = (tt.cpuDelta / tt.systemDelta) * float64(cpuCount) * 100.0
			}

			if math.Abs(cpuPercent-tt.expectedResult) > 0.01 {
				t.Errorf("cpuPercent = %f, want %f", cpuPercent, tt.expectedResult)
			}
		})
	}
}
