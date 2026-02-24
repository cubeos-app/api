// Package workflows defines workflow types for the FlowEngine.
package workflows

import (
	"time"

	"cubeos-api/internal/flowengine"
)

const (
	// BackupWorkflowType is the registered type string for backup workflows.
	BackupWorkflowType = "backup"
	// BackupWorkflowVersion is the current version of the workflow definition.
	BackupWorkflowVersion = 1
)

// BackupWorkflow defines the step sequence for creating a system backup.
// Aligns with Resilience Layers P3 (W7).
//
// Step order:
//
//  0. backup.validate_target  — Verify destination writable + has space
//  1. backup.snapshot_config  — P0 seed: serialize DB + env files → cubeos-config.json
//  2. backup.stop_apps_if_needed — Optional: stop apps for Tier 3 consistency
//  3. backup.snapshot_database — VACUUM INTO temp path
//  4. backup.collect_app_data — Enumerate app data files by category
//  5. backup.create_archive   — tar.gz creation with all files
//  6. backup.write_manifest   — Generate + embed manifest.json with per-file categories
//  7. backup.compute_checksum — SHA256 of final archive
//  8. backup.move_to_destination — Move archive to final destination
//  9. backup.record_in_db     — INSERT/UPDATE backups table + config_snapshots table
type BackupWorkflow struct{}

func (w *BackupWorkflow) Type() string { return BackupWorkflowType }
func (w *BackupWorkflow) Version() int { return BackupWorkflowVersion }

func (w *BackupWorkflow) Steps() []flowengine.StepDefinition {
	return []flowengine.StepDefinition{
		{
			// Step 0: Validate destination is writable and has enough space
			Name:       "validate_target",
			Action:     "backup.validate_target",
			Compensate: "", // read-only
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    10 * time.Second,
		},
		{
			// Step 1: P0 seed — serialize system config into cubeos-config.json
			Name:       "snapshot_config",
			Action:     "backup.snapshot_config",
			Compensate: "", // read-only
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 1 * time.Second},
			Timeout:    15 * time.Second,
		},
		{
			// Step 2: Optional — stop apps for Tier 3 data consistency
			Name:       "stop_apps_if_needed",
			Action:     "backup.stop_apps_if_needed",
			Compensate: "backup.restart_stopped_apps",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    60 * time.Second,
		},
		{
			// Step 3: Hot backup — VACUUM INTO creates consistent DB snapshot
			Name:       "snapshot_database",
			Action:     "backup.snapshot_database",
			Compensate: "backup.cleanup_temp",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 1 * time.Second},
			Timeout:    30 * time.Second,
		},
		{
			// Step 4: Enumerate files to include based on scope tier
			Name:       "collect_app_data",
			Action:     "backup.collect_app_data",
			Compensate: "", // read-only
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    15 * time.Second,
		},
		{
			// Step 5: Create tar.gz archive with all files
			Name:       "create_archive",
			Action:     "backup.create_archive",
			Compensate: "backup.cleanup_temp",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    300 * time.Second, // Tier 3 can be large
		},
		{
			// Step 6: Generate and embed manifest.json
			Name:       "write_manifest",
			Action:     "backup.write_manifest",
			Compensate: "", // manifest is part of archive, cleaned up with it
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    30 * time.Second,
		},
		{
			// Step 7: SHA256 of final archive
			Name:       "compute_checksum",
			Action:     "backup.compute_checksum",
			Compensate: "", // read-only
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    60 * time.Second,
		},
		{
			// Step 8: Move archive from temp to final destination
			Name:       "move_to_destination",
			Action:     "backup.move_to_destination",
			Compensate: "backup.cleanup_dest",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 1 * time.Second},
			Timeout:    30 * time.Second,
		},
		{
			// Step 9: Record backup in database
			Name:       "record_in_db",
			Action:     "backup.record_in_db",
			Compensate: "", // DB record is harmless on failure
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 5 * time.Second},
			Timeout:    10 * time.Second,
		},
	}
}

// BackupInput is the JSON input for the backup workflow.
type BackupInput struct {
	Scope       string `json:"scope"`       // tier1, tier2, tier3
	Destination string `json:"destination"` // local, usb, nfs, smb
	DestPath    string `json:"dest_path"`   // override destination path
	Encrypt     bool   `json:"encrypt"`
	Description string `json:"description"`
	StopApps    bool   `json:"stop_apps"` // explicitly stop apps for consistency
}
