package workflows

import (
	"time"

	"cubeos-api/internal/flowengine"
)

const (
	// SystemUpdateType is the workflow type for system OTA updates.
	SystemUpdateType = "system_update"
	// SystemUpdateVersion is the current version of the workflow definition.
	SystemUpdateVersion = 1
)

// SystemUpdateWorkflow defines the step sequence for applying a CubeOS system update.
// It pulls new images, writes version pins, redeploys stacks, and waits for convergence.
// On failure, compensation restores original image tags and redeploys with the old versions.
//
// Step order:
//
//	validate          → check version compatible, no in-flight updates
//	snapshot_config   → P0 auto-snapshot: GenerateConfigSnapshot() → config_snapshots table
//	snapshot_state    → record current image tags + schema version for rollback
//	record_start      → insert update_history row (status=applying)
//	pull_images       → pull new images from upstream to localhost:5000
//	write_versions    → write new tags to image-versions.env
//	redeploy_stacks   → docker stack deploy for each changed service
//	wait_healthy      → wait for all services to converge (90s timeout)
//	record_complete   → update update_history (status=completed)
//
// Compensation (rollback) flow on failure:
//   - rollback_stacks:   re-deploy with original image tags
//   - restore_versions:  write original tags back to image-versions.env
//   - record_failed:     update update_history (status=rolled_back, error_message)
type SystemUpdateWorkflow struct{}

func (w *SystemUpdateWorkflow) Type() string { return SystemUpdateType }
func (w *SystemUpdateWorkflow) Version() int { return SystemUpdateVersion }

func (w *SystemUpdateWorkflow) Steps() []flowengine.StepDefinition {
	return []flowengine.StepDefinition{
		{
			// Step 0: Validate target version, check no in-flight updates
			Name:       "validate",
			Action:     "update.validate",
			Compensate: "",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    10 * time.Second,
		},
		{
			// Step 1: P0 auto-snapshot — capture config state before update
			Name:       "snapshot_config",
			Action:     "update.snapshot_config",
			Compensate: "",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 1 * time.Second},
			Timeout:    30 * time.Second,
		},
		{
			// Step 2: Record current image tags + schema version for rollback
			Name:       "snapshot_state",
			Action:     "update.snapshot_state",
			Compensate: "",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    10 * time.Second,
		},
		{
			// Step 3: Insert update_history row (status=applying)
			Name:       "record_start",
			Action:     "update.record_start",
			Compensate: "",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 500 * time.Millisecond},
			Timeout:    10 * time.Second,
		},
		{
			// Step 4: Pull new images from upstream to localhost:5000
			Name:       "pull_images",
			Action:     "update.pull_images",
			Compensate: "",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 5 * time.Second, MaxInterval: 30 * time.Second},
			Timeout:    10 * time.Minute,
		},
		{
			// Step 5: Write new tags to image-versions.env
			Name:       "write_versions",
			Action:     "update.write_versions",
			Compensate: "update.restore_versions",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    10 * time.Second,
		},
		{
			// Step 6: Redeploy Swarm stacks for each changed service
			Name:       "redeploy_stacks",
			Action:     "update.redeploy_stacks",
			Compensate: "update.rollback_stacks",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 5 * time.Second},
			Timeout:    5 * time.Minute,
		},
		{
			// Step 7: Wait for all services to converge (90s timeout)
			Name:       "wait_healthy",
			Action:     "update.wait_healthy",
			Compensate: "",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 10 * time.Second},
			Timeout:    120 * time.Second,
		},
		{
			// Step 8: Update update_history (status=completed)
			Name:       "record_complete",
			Action:     "update.record_complete",
			Compensate: "update.record_failed",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second},
			Timeout:    10 * time.Second,
		},
	}
}
