// Package workflows defines workflow types for the FlowEngine.
// Each workflow is a sequence of steps with forward and compensation activities.
package workflows

import (
	"time"

	"cubeos-api/internal/flowengine"
)

// AppRemoveWorkflowType is the registered type string for app removal workflows.
const AppRemoveWorkflowType = "app_remove"

// AppRemoveWorkflow defines the steps for uninstalling an application.
//
// Step sequence:
//  1. validate     — Check app exists, not protected (no compensation)
//  2. stop_stack   — Scale service to 0 replicas (compensate: re-deploy)
//  3. remove_stack — Remove the Docker stack entirely (compensate: re-deploy)
//  4. remove_dns   — Remove Pi-hole DNS entry (compensate: re-add DNS)
//  5. remove_proxy — Remove NPM proxy host (compensate: re-create proxy)
//  6. delete_db    — Delete app row from database with cascade (compensate: re-insert)
//  7. cleanup_files — Remove compose config + optional data dirs (no compensation)
//
// Why this order:
//   - Stop before remove: graceful shutdown before stack deletion
//   - Remove stack before DNS/proxy: prevents routing to dead container
//   - Delete DB after infra teardown: if we crash between stack remove and DB delete,
//     recovery can re-run the delete safely (cascade cleans up ports/fqdns)
//   - File cleanup last: lowest priority, best-effort
//
// Compensation strategy:
//   - If stop_stack or remove_stack fails, we abort and try to re-deploy
//   - After remove_stack succeeds, compensation becomes the reverse: re-deploy stack
//   - After delete_db succeeds, compensation is complex (re-insert row) — deferred to Batch 2.4
//   - cleanup_files has no compensation (files are gone)
type AppRemoveWorkflow struct{}

// Type returns the workflow type identifier.
func (w AppRemoveWorkflow) Type() string {
	return AppRemoveWorkflowType
}

// Version returns the workflow definition version. Bump when step sequence changes.
func (w AppRemoveWorkflow) Version() int {
	return 1
}

// Steps returns the ordered step definitions for app removal.
func (w AppRemoveWorkflow) Steps() []flowengine.StepDefinition {
	return []flowengine.StepDefinition{
		{
			Name:   "validate",
			Action: "app_remove.validate",
			// No compensation — validation is read-only
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     1,
				InitialInterval: 0,
				MaxInterval:     0,
			},
			Timeout: 10 * time.Second,
		},
		{
			Name:       "stop_stack",
			Action:     "docker.stop_stack",
			Compensate: "docker.deploy_stack", // Re-deploy if we need to rollback
			Timeout:    30 * time.Second,
		},
		{
			Name:       "remove_stack",
			Action:     "docker.remove_stack",
			Compensate: "docker.deploy_stack", // Re-deploy if we need to rollback
			Timeout:    30 * time.Second,
		},
		{
			Name:       "remove_dns",
			Action:     "infra.remove_dns",
			Compensate: "infra.add_dns", // Re-add DNS entry on rollback
			Timeout:    15 * time.Second,
		},
		{
			Name:       "remove_proxy",
			Action:     "infra.remove_proxy",
			Compensate: "infra.create_proxy", // Re-create proxy on rollback
			Timeout:    15 * time.Second,
		},
		{
			Name:       "delete_db",
			Action:     "db.delete_app",
			Compensate: "db.insert_app", // Re-insert app row on rollback (stub until Batch 2.4)
			Timeout:    10 * time.Second,
		},
		{
			Name:   "cleanup_files",
			Action: "db.cleanup_files",
			// No compensation — file removal is best-effort and not reversible
			Retry: &flowengine.RetryPolicy{
				MaxAttempts:     1, // Don't retry file ops
				InitialInterval: 0,
				MaxInterval:     0,
			},
			Timeout: 15 * time.Second,
		},
	}
}

// AppRemoveInput is the JSON input for the app_remove workflow.
// Passed as the workflow's Input field and forwarded to the validate step.
type AppRemoveInput struct {
	AppID       int64  `json:"app_id"`
	AppName     string `json:"app_name"`
	FQDN        string `json:"fqdn"`
	ComposePath string `json:"compose_path,omitempty"`
	DataPath    string `json:"data_path,omitempty"`
	KeepData    bool   `json:"keep_data"`
	UsesSwarm   bool   `json:"uses_swarm"`
}
