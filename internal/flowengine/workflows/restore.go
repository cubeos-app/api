package workflows

import (
	"time"

	"cubeos-api/internal/flowengine"
)

const (
	// RestoreWorkflowType is the registered type string for restore workflows.
	RestoreWorkflowType = "restore"
	// RestoreWorkflowVersion is the current version of the workflow definition.
	RestoreWorkflowVersion = 1
)

// RestoreWorkflow defines the step sequence for restoring from a backup.
// Aligns with Resilience Layers P3 (W8).
//
// Step order:
//
//  0. restore.validate_backup     — Read manifest, check version compatibility
//  1. restore.verify_checksums    — Spot-check file integrity
//  2. restore.import_config       — P0 future hook: restore DB + env files
//  3. restore.stop_services       — Stop coreapp stacks for safe data overwrite
//  4. restore.restore_coreapp_data — Extract coreapp appdata/ to original paths
//  5. restore.restore_app_data    — Extract user app appdata/ to original paths
//  6. restore.restart_services    — Restart all stacks
//  7. restore.verify_health       — Health check all services
//
// Phase 6 replaces step 2 with ConfigImportWorkflow (W14) submission.
type RestoreWorkflow struct{}

func (w *RestoreWorkflow) Type() string { return RestoreWorkflowType }
func (w *RestoreWorkflow) Version() int { return RestoreWorkflowVersion }

func (w *RestoreWorkflow) Steps() []flowengine.StepDefinition {
	return []flowengine.StepDefinition{
		{
			// Step 0: Validate backup — read manifest, check CubeOS version compat
			Name:       "validate_backup",
			Action:     "restore.validate_backup",
			Compensate: "", // read-only
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    15 * time.Second,
		},
		{
			// Step 1: Verify checksums — spot-check file integrity
			Name:       "verify_checksums",
			Action:     "restore.verify_checksums",
			Compensate: "", // read-only
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    60 * time.Second,
		},
		{
			// Step 2: Import config — direct DB replace + env file restore (Phase 4)
			// Phase 6 replaces this with ConfigImportWorkflow (W14) submission.
			Name:       "import_config",
			Action:     "restore.import_config",
			Compensate: "", // DB is replaced — compensation would need a pre-restore snapshot
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    30 * time.Second,
		},
		{
			// Step 3: Stop services for safe data overwrite
			Name:       "stop_services",
			Action:     "restore.stop_services",
			Compensate: "restore.start_services",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 2 * time.Second},
			Timeout:    60 * time.Second,
		},
		{
			// Step 4: Restore coreapp data from archive
			Name:       "restore_coreapp_data",
			Action:     "restore.restore_coreapp_data",
			Compensate: "", // overwritten data cannot be recovered
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    120 * time.Second,
		},
		{
			// Step 5: Restore user app data from archive
			Name:       "restore_app_data",
			Action:     "restore.restore_app_data",
			Compensate: "", // overwritten data cannot be recovered
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    120 * time.Second,
		},
		{
			// Step 6: Restart all stacks
			Name:       "restart_services",
			Action:     "restore.restart_services",
			Compensate: "", // services should be running
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 2 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    120 * time.Second,
		},
		{
			// Step 7: Health check — verify services are responding
			Name:       "verify_health",
			Action:     "restore.verify_health",
			Compensate: "", // observation-only
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     3,
				InitialInterval: 5 * time.Second,
				MaxInterval:     15 * time.Second,
			},
			Timeout: 60 * time.Second,
		},
	}
}

// RestoreInput is the JSON input for the restore workflow.
type RestoreInput struct {
	BackupID   string `json:"backup_id"`
	BackupPath string `json:"backup_path"` // full path to .tar.gz
	Confirm    bool   `json:"confirm"`
}
