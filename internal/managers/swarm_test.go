package managers

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/docker/docker/api/types/swarm"
)

// skipIfNoDocker skips the test if Docker is not available
func skipIfNoDocker(t *testing.T) *SwarmManager {
	t.Helper()
	sm, err := NewSwarmManager()
	if err != nil {
		t.Skipf("Docker not available: %v", err)
	}
	return sm
}

// skipIfNoSwarm skips the test if Swarm is not active
func skipIfNoSwarm(t *testing.T, sm *SwarmManager) {
	t.Helper()
	active, err := sm.IsSwarmActive()
	if err != nil || !active {
		t.Skip("Swarm not active")
	}
}

func TestParseReplicas(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantRunning int
		wantDesired int
	}{
		{
			name:        "normal case",
			input:       "1/1",
			wantRunning: 1,
			wantDesired: 1,
		},
		{
			name:        "scaling up",
			input:       "2/3",
			wantRunning: 2,
			wantDesired: 3,
		},
		{
			name:        "stopped",
			input:       "0/1",
			wantRunning: 0,
			wantDesired: 1,
		},
		{
			name:        "scaled to zero",
			input:       "0/0",
			wantRunning: 0,
			wantDesired: 0,
		},
		{
			name:        "empty",
			input:       "",
			wantRunning: 0,
			wantDesired: 0,
		},
		{
			name:        "invalid format",
			input:       "1",
			wantRunning: 0,
			wantDesired: 0,
		},
		{
			name:        "large numbers",
			input:       "10/10",
			wantRunning: 10,
			wantDesired: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			running, desired := parseReplicas(tt.input)
			if running != tt.wantRunning {
				t.Errorf("parseReplicas() running = %d, want %d", running, tt.wantRunning)
			}
			if desired != tt.wantDesired {
				t.Errorf("parseReplicas() desired = %d, want %d", desired, tt.wantDesired)
			}
		})
	}
}

func TestIntPtr(t *testing.T) {
	tests := []struct {
		input int
	}{
		{0},
		{1},
		{5},
		{100},
		{-1},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			val := intPtr(tt.input)
			if val == nil {
				t.Error("intPtr() returned nil")
			}
			if *val != int64(tt.input) {
				t.Errorf("intPtr() = %d, want %d", *val, tt.input)
			}
		})
	}
}

func TestDefaultSwarmConfig(t *testing.T) {
	cfg := DefaultSwarmConfig()

	if cfg.AdvertiseAddr != "10.42.24.1" {
		t.Errorf("AdvertiseAddr = %s, want 10.42.24.1", cfg.AdvertiseAddr)
	}
	if cfg.TaskHistoryLimit != 1 {
		t.Errorf("TaskHistoryLimit = %d, want 1", cfg.TaskHistoryLimit)
	}
	if cfg.ListenAddr != "0.0.0.0:2377" {
		t.Errorf("ListenAddr = %s, want 0.0.0.0:2377", cfg.ListenAddr)
	}
}

func TestNewSwarmManager(t *testing.T) {
	sm := skipIfNoDocker(t)
	defer sm.Close()

	if sm.client == nil {
		t.Error("SwarmManager client is nil")
	}
	if sm.ctx == nil {
		t.Error("SwarmManager context is nil")
	}
}

func TestNewSwarmManagerWithContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sm, err := NewSwarmManagerWithContext(ctx)
	if err != nil {
		t.Skipf("Docker not available: %v", err)
	}
	defer sm.Close()

	if sm.ctx != ctx {
		t.Error("SwarmManager context not set correctly")
	}
}

func TestIsSwarmActive(t *testing.T) {
	sm := skipIfNoDocker(t)
	defer sm.Close()

	// Just test that it doesn't error - result depends on Docker state
	active, err := sm.IsSwarmActive()
	if err != nil {
		t.Errorf("IsSwarmActive() error = %v", err)
	}

	t.Logf("Swarm active: %v", active)
}

func TestListStacks(t *testing.T) {
	sm := skipIfNoDocker(t)
	defer sm.Close()
	skipIfNoSwarm(t, sm)

	// Should not error, even if no stacks deployed
	stacks, err := sm.ListStacks()
	if err != nil {
		t.Errorf("ListStacks() error = %v", err)
	}

	t.Logf("Found %d stacks", len(stacks))
	for _, s := range stacks {
		t.Logf("  - %s (%d services)", s.Name, s.Services)
	}
}

func TestStackExists(t *testing.T) {
	sm := skipIfNoDocker(t)
	defer sm.Close()
	skipIfNoSwarm(t, sm)

	// Test non-existent stack
	exists, err := sm.StackExists("nonexistent-stack-12345")
	if err != nil {
		t.Errorf("StackExists() error = %v", err)
	}
	if exists {
		t.Error("StackExists() returned true for non-existent stack")
	}
}

// Validation tests

func TestDeployStackValidation(t *testing.T) {
	sm := skipIfNoDocker(t)
	defer sm.Close()

	tests := []struct {
		name        string
		stackName   string
		composePath string
		wantErr     bool
	}{
		{
			name:        "empty stack name",
			stackName:   "",
			composePath: "/some/path",
			wantErr:     true,
		},
		{
			name:        "empty compose path",
			stackName:   "test",
			composePath: "",
			wantErr:     true,
		},
		{
			name:        "both empty",
			stackName:   "",
			composePath: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sm.DeployStack(tt.stackName, tt.composePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeployStack() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRemoveStackValidation(t *testing.T) {
	sm := skipIfNoDocker(t)
	defer sm.Close()

	err := sm.RemoveStack("")
	if err == nil {
		t.Error("RemoveStack() should error on empty name")
	}
}

func TestGetServiceStatusValidation(t *testing.T) {
	sm := skipIfNoDocker(t)
	defer sm.Close()

	_, err := sm.GetServiceStatus("")
	if err == nil {
		t.Error("GetServiceStatus() should error on empty name")
	}
}

func TestGetServiceLogsValidation(t *testing.T) {
	sm := skipIfNoDocker(t)
	defer sm.Close()

	_, err := sm.GetServiceLogs("", 100)
	if err == nil {
		t.Error("GetServiceLogs() should error on empty name")
	}
}

func TestScaleServiceValidation(t *testing.T) {
	sm := skipIfNoDocker(t)
	defer sm.Close()

	err := sm.ScaleService("", 1)
	if err == nil {
		t.Error("ScaleService() should error on empty name")
	}
}

func TestRestartServiceValidation(t *testing.T) {
	sm := skipIfNoDocker(t)
	defer sm.Close()

	err := sm.RestartService("")
	if err == nil {
		t.Error("RestartService() should error on empty name")
	}
}

func TestGetStackServicesValidation(t *testing.T) {
	sm := skipIfNoDocker(t)
	defer sm.Close()

	_, err := sm.GetStackServices("")
	if err == nil {
		t.Error("GetStackServices() should error on empty name")
	}
}

// =============================================================================
// determineHealth Tests
// =============================================================================

func TestDetermineHealth(t *testing.T) {
	// Create a minimal SwarmManager - determineHealth doesn't use any struct fields
	sm := &SwarmManager{}

	tests := []struct {
		name     string
		running  int
		desired  int
		expected string
	}{
		{
			name:     "all replicas running",
			running:  1,
			desired:  1,
			expected: "running",
		},
		{
			name:     "3/3 replicas running",
			running:  3,
			desired:  3,
			expected: "running",
		},
		{
			name:     "scaled to zero desired",
			running:  0,
			desired:  0,
			expected: "stopped",
		},
		{
			name:     "no replicas running (desired > 0)",
			running:  0,
			desired:  1,
			expected: "stopped",
		},
		{
			name:     "partially started (1/3)",
			running:  1,
			desired:  3,
			expected: "starting",
		},
		{
			name:     "partially started (2/3)",
			running:  2,
			desired:  3,
			expected: "starting",
		},
		{
			name:     "more running than desired returns unknown",
			running:  3,
			desired:  1,
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal swarm.Service - determineHealth only uses running/desired params
			var svc swarm.Service
			got := sm.determineHealth(svc, tt.running, tt.desired)
			if got != tt.expected {
				t.Errorf("determineHealth(running=%d, desired=%d) = %q, want %q",
					tt.running, tt.desired, got, tt.expected)
			}
		})
	}
}

// Integration test for full workflow (only runs if CUBEOS_INTEGRATION_TEST=1)
func TestSwarmIntegration(t *testing.T) {
	if os.Getenv("CUBEOS_INTEGRATION_TEST") != "1" {
		t.Skip("Integration tests disabled. Set CUBEOS_INTEGRATION_TEST=1 to enable.")
	}

	sm := skipIfNoDocker(t)
	defer sm.Close()
	skipIfNoSwarm(t, sm)

	// This test would deploy a test stack, verify it, then clean up
	// Left as a placeholder for CI/CD integration
	t.Log("Integration test placeholder - implement with test compose file")
}
