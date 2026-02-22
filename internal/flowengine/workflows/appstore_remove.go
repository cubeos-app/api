package workflows

import (
	"time"

	"cubeos-api/internal/flowengine"
)

const (
	// AppStoreRemoveType is the workflow type for app store removal.
	AppStoreRemoveType = "appstore_remove"
	// AppStoreRemoveVersion is the current version of the workflow definition.
	AppStoreRemoveVersion = 1
)

// AppStoreRemoveWorkflow defines the step sequence for removing an app installed from the store.
// Replaces AppStoreManager.RemoveAppWithProgress() with tracked, compensating steps.
//
// Step order:
//  0. validate — check app exists, not protected
//  1. stop_stack — graceful shutdown (removes stack)
//  2. remove_dns — remove Pi-hole DNS entry
//  3. remove_proxy — remove NPM reverse proxy host
//  4. delete_db — delete app record from database (cascades to ports/fqdns)
//  5. cleanup_files — remove app directories (best-effort, no retry)
//
// Differences from AppRemoveWorkflow (app_remove.go):
// - No separate "remove_stack" after "stop_stack" — for store apps, stop IS remove
// - File cleanup uses keep_data from input (user preference)
// - Validation checks store-specific properties
//
// Compensation strategy:
// - stop_stack → deploy_stack (re-deploy from stored compose)
// - remove_dns → add_dns (re-add DNS entry)
// - remove_proxy → create_proxy (re-create proxy host)
// - delete_db → insert_app (re-insert app record)
// - cleanup_files → none (irreversible, last step, best-effort)
type AppStoreRemoveWorkflow struct{}

func (w *AppStoreRemoveWorkflow) Type() string { return AppStoreRemoveType }
func (w *AppStoreRemoveWorkflow) Version() int { return AppStoreRemoveVersion }

func (w *AppStoreRemoveWorkflow) Steps() []flowengine.StepDefinition {
	return []flowengine.StepDefinition{
		{
			// Step 0: Validate app exists and is not a protected system app
			Name:       "validate",
			Action:     "app_remove.validate", // reuse from AppRemoveWorkflow
			Compensate: "",                    // read-only
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    10 * time.Second,
		},
		{
			// Step 1: Stop the stack (removes all Swarm services)
			Name:       "stop_stack",
			Action:     "docker.stop_stack",
			Compensate: "docker.deploy_stack",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    30 * time.Second,
		},
		{
			// Step 2: Remove DNS entry from Pi-hole
			Name:       "remove_dns",
			Action:     "infra.remove_dns",
			Compensate: "infra.add_dns",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    15 * time.Second,
		},
		{
			// Step 3: Remove NPM reverse proxy host
			Name:       "remove_proxy",
			Action:     "infra.remove_proxy",
			Compensate: "infra.create_proxy",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    15 * time.Second,
		},
		{
			// Step 4: Delete app from database (FK cascades delete port_allocations + fqdns)
			Name:       "delete_db",
			Action:     "db.delete_app",
			Compensate: "db.insert_app",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    10 * time.Second,
		},
		{
			// Step 5: Clean up files on disk (best-effort, no retry, no compensation)
			Name:       "cleanup_files",
			Action:     "db.cleanup_files",
			Compensate: "",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1}, // no retry for file ops
			Timeout:    15 * time.Second,
		},
	}
}

// NewAppStoreRemoveWorkflow creates a new AppStoreRemoveWorkflow definition.
func NewAppStoreRemoveWorkflow() *AppStoreRemoveWorkflow {
	return &AppStoreRemoveWorkflow{}
}
