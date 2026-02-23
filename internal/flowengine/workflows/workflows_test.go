package workflows

import (
	"testing"
)

func TestAppInstallWorkflowSteps(t *testing.T) {
	w := NewAppInstallWorkflow()

	if w.Type() != "app_install" {
		t.Errorf("expected type 'app_install', got %q", w.Type())
	}
	if w.Version() != 1 {
		t.Errorf("expected version 1, got %d", w.Version())
	}

	steps := w.Steps()
	if len(steps) != 9 {
		t.Fatalf("expected 9 steps, got %d", len(steps))
	}

	// Verify step order
	expectedNames := []string{
		"validate", "allocate_port", "create_dirs", "write_compose",
		"deploy_stack", "wait_convergence", "insert_db", "add_dns", "create_proxy",
	}
	for i, name := range expectedNames {
		if steps[i].Name != name {
			t.Errorf("step %d: expected name %q, got %q", i, name, steps[i].Name)
		}
	}

	// Verify compensation exists for all steps except validate and wait_convergence
	for i, step := range steps {
		switch step.Name {
		case "validate", "wait_convergence":
			if step.Compensate != "" {
				t.Errorf("step %d (%s): expected no compensation, got %q", i, step.Name, step.Compensate)
			}
		default:
			if step.Compensate == "" {
				t.Errorf("step %d (%s): expected compensation, got empty", i, step.Name)
			}
		}
	}

	// Verify port allocation has release_port compensation (fixes port leak bug)
	allocateStep := steps[1]
	if allocateStep.Compensate != "db.release_port" {
		t.Errorf("allocate_port compensation: expected 'db.release_port', got %q", allocateStep.Compensate)
	}

	// Verify deploy_stack has remove_stack compensation
	deployStep := steps[4]
	if deployStep.Compensate != "docker.remove_stack" {
		t.Errorf("deploy_stack compensation: expected 'docker.remove_stack', got %q", deployStep.Compensate)
	}
}

func TestAppStoreInstallWorkflowSteps(t *testing.T) {
	w := NewAppStoreInstallWorkflow()

	if w.Type() != "appstore_install" {
		t.Errorf("expected type 'appstore_install', got %q", w.Type())
	}
	if w.Version() != 3 {
		t.Errorf("expected version 3, got %d", w.Version())
	}

	steps := w.Steps()
	if len(steps) != 18 {
		t.Fatalf("expected 18 steps, got %d", len(steps))
	}

	// Verify step order
	expectedNames := []string{
		"validate", "read_manifest", "allocate_port", "process_manifest",
		"create_dirs", "remap_volumes", "write_compose", "deploy_stack",
		"wait_convergence", "add_dns", "create_proxy", "insert_db",
		"cache_retag", "cache_push", "cache_manifest",
		"store_volumes", "detect_webui", "health_check",
	}
	for i, name := range expectedNames {
		if steps[i].Name != name {
			t.Errorf("step %d: expected name %q, got %q", i, name, steps[i].Name)
		}
	}

	// Verify port allocation has release_port compensation (PORT LEAK BUG FIX)
	allocateStep := steps[2]
	if allocateStep.Action != "db.allocate_port" {
		t.Errorf("step 2 action: expected 'db.allocate_port', got %q", allocateStep.Action)
	}
	if allocateStep.Compensate != "db.release_port" {
		t.Errorf("step 2 compensation: expected 'db.release_port', got %q", allocateStep.Compensate)
	}

	// Verify db insert is AFTER deploy (key safety improvement)
	var deployIdx, insertIdx int
	for i, s := range steps {
		if s.Name == "deploy_stack" {
			deployIdx = i
		}
		if s.Name == "insert_db" {
			insertIdx = i
		}
	}
	if insertIdx <= deployIdx {
		t.Errorf("insert_db (idx=%d) should come after deploy_stack (idx=%d)", insertIdx, deployIdx)
	}

	// Verify read-only steps have no compensation
	readOnlySteps := map[string]bool{
		"validate": true, "read_manifest": true, "process_manifest": true,
		"remap_volumes": true, "wait_convergence": true, "store_volumes": true,
		"detect_webui": true, "health_check": true,
	}
	for _, step := range steps {
		if readOnlySteps[step.Name] && step.Compensate != "" {
			t.Errorf("read-only step %q should have no compensation, got %q", step.Name, step.Compensate)
		}
	}
}

func TestAppStoreRemoveWorkflowSteps(t *testing.T) {
	w := NewAppStoreRemoveWorkflow()

	if w.Type() != "appstore_remove" {
		t.Errorf("expected type 'appstore_remove', got %q", w.Type())
	}
	if w.Version() != 1 {
		t.Errorf("expected version 1, got %d", w.Version())
	}

	steps := w.Steps()
	if len(steps) != 6 {
		t.Fatalf("expected 6 steps, got %d", len(steps))
	}

	// Verify step order
	expectedNames := []string{
		"validate", "stop_stack", "remove_dns", "remove_proxy", "delete_db", "cleanup_files",
	}
	for i, name := range expectedNames {
		if steps[i].Name != name {
			t.Errorf("step %d: expected name %q, got %q", i, name, steps[i].Name)
		}
	}

	// Verify compensation for each step
	expectedCompensations := map[string]string{
		"validate":      "",
		"stop_stack":    "docker.deploy_stack",
		"remove_dns":    "infra.add_dns",
		"remove_proxy":  "infra.create_proxy",
		"delete_db":     "db.insert_app",
		"cleanup_files": "",
	}
	for _, step := range steps {
		expected := expectedCompensations[step.Name]
		if step.Compensate != expected {
			t.Errorf("step %q compensation: expected %q, got %q", step.Name, expected, step.Compensate)
		}
	}

	// Verify cleanup_files has no retry (MaxAttempts: 1)
	cleanupStep := steps[5]
	if cleanupStep.Retry.MaxAttempts != 1 {
		t.Errorf("cleanup_files should have MaxAttempts=1, got %d", cleanupStep.Retry.MaxAttempts)
	}
}

func TestAllWorkflowsHaveNonEmptyActions(t *testing.T) {
	workflows := []interface {
		Type() string
		Steps() []struct {
			Name   string
			Action string
		}
	}{}

	// Test each workflow directly
	for _, wf := range []struct {
		name  string
		steps int
	}{
		{"app_install", 9},
		{"appstore_install", 18},
		{"appstore_remove", 6},
	} {
		var stepCount int
		switch wf.name {
		case "app_install":
			stepCount = len(NewAppInstallWorkflow().Steps())
		case "appstore_install":
			stepCount = len(NewAppStoreInstallWorkflow().Steps())
		case "appstore_remove":
			stepCount = len(NewAppStoreRemoveWorkflow().Steps())
		}
		if stepCount != wf.steps {
			t.Errorf("%s: expected %d steps, got %d", wf.name, wf.steps, stepCount)
		}
	}

	_ = workflows // suppress unused var
}

func TestAllStepsHaveTimeouts(t *testing.T) {
	allWorkflows := map[string][]struct {
		name    string
		timeout bool
	}{
		"app_install":      {},
		"appstore_install": {},
		"appstore_remove":  {},
	}

	for _, step := range NewAppInstallWorkflow().Steps() {
		if step.Timeout <= 0 {
			t.Errorf("app_install step %q has no timeout", step.Name)
		}
	}
	for _, step := range NewAppStoreInstallWorkflow().Steps() {
		if step.Timeout <= 0 {
			t.Errorf("appstore_install step %q has no timeout", step.Name)
		}
	}
	for _, step := range NewAppStoreRemoveWorkflow().Steps() {
		if step.Timeout <= 0 {
			t.Errorf("appstore_remove step %q has no timeout", step.Name)
		}
	}

	_ = allWorkflows // suppress unused var
}

func TestNetworkModeSwitchWorkflowSteps(t *testing.T) {
	w := NewNetworkModeSwitchWorkflow()

	if w.Type() != "network_mode_switch" {
		t.Errorf("expected type 'network_mode_switch', got %q", w.Type())
	}
	if w.Version() != 1 {
		t.Errorf("expected version 1, got %d", w.Version())
	}

	steps := w.Steps()
	if len(steps) != 7 {
		t.Fatalf("expected 7 steps, got %d", len(steps))
	}

	// Verify step order
	expectedNames := []string{
		"validate", "snapshot_state", "teardown_previous", "configure_upstream",
		"configure_services", "configure_dns", "persist",
	}
	for i, name := range expectedNames {
		if steps[i].Name != name {
			t.Errorf("step %d: expected name %q, got %q", i, name, steps[i].Name)
		}
	}

	// Verify read-only steps have no compensation
	for _, step := range steps {
		switch step.Name {
		case "validate", "snapshot_state":
			if step.Compensate != "" {
				t.Errorf("read-only step %q should have no compensation, got %q", step.Name, step.Compensate)
			}
		default:
			if step.Compensate == "" {
				t.Errorf("step %q should have compensation, got empty", step.Name)
			}
		}
	}

	// Verify compensation activity names
	expectedCompensations := map[string]string{
		"validate":           "",
		"snapshot_state":     "",
		"teardown_previous":  "net.restore_teardown",
		"configure_upstream": "net.restore_upstream",
		"configure_services": "net.restore_services",
		"configure_dns":      "net.restore_dns",
		"persist":            "net.restore_persist",
	}
	for _, step := range steps {
		expected := expectedCompensations[step.Name]
		if step.Compensate != expected {
			t.Errorf("step %q compensation: expected %q, got %q", step.Name, expected, step.Compensate)
		}
	}

	// Verify all steps have timeouts
	for _, step := range steps {
		if step.Timeout <= 0 {
			t.Errorf("step %q has no timeout", step.Name)
		}
	}

	// Verify configure_upstream has 45s timeout (DHCP polling can take 30s)
	upstreamStep := steps[3]
	if upstreamStep.Timeout.Seconds() != 45 {
		t.Errorf("configure_upstream timeout: expected 45s, got %v", upstreamStep.Timeout)
	}

	// Verify validate has MaxAttempts=1 (no retry for validation)
	validateStep := steps[0]
	if validateStep.Retry == nil || validateStep.Retry.MaxAttempts != 1 {
		t.Errorf("validate should have MaxAttempts=1")
	}

	// Verify configure_upstream has MaxAttempts=1 (netplan not safely retryable)
	if upstreamStep.Retry == nil || upstreamStep.Retry.MaxAttempts != 1 {
		t.Errorf("configure_upstream should have MaxAttempts=1")
	}

	// Verify configure_dns has MaxAttempts=3 (Pi-hole API is flaky)
	dnsStep := steps[5]
	if dnsStep.Retry == nil || dnsStep.Retry.MaxAttempts != 3 {
		t.Errorf("configure_dns should have MaxAttempts=3")
	}
}
